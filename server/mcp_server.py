"""
MCP Server using FastMCP with Generic OAuth 2.1 Provider
Works with: Asgardeo, Auth0, Keycloak, Okta, AWS Cognito, etc.
"""

import os
from dotenv import load_dotenv
from pydantic import AnyHttpUrl
import logging
import jwt
from jwt import PyJWKClient
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware

from mcp.server.auth.provider import AccessToken, TokenVerifier
from mcp.server.auth.settings import AuthSettings
from mcp.server.fastmcp import FastMCP

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GenericOAuthTokenVerifier(TokenVerifier):
    """
    Generic JWT token verifier that works with any OAuth 2.1 / OIDC provider
    Supports both RS256 (JWKS) and HS256 (shared secret) algorithms
    """

    def __init__(
        self,
        jwks_url: Optional[str] = None,
        issuer: Optional[str] = None,
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        algorithm: str = "RS256",
        validate_audience: bool = True,
        validate_issuer: bool = True,
        ssl_verify: bool = True
    ):
        """
        Initialize the token verifier

        Args:
            jwks_url: JWKS endpoint URL (required for RS256)
            issuer: Token issuer URL (e.g., https://auth.provider.com)
            client_id: OAuth client ID (used for audience validation)
            client_secret: Client secret (required for HS256)
            algorithm: JWT algorithm (RS256 or HS256)
            validate_audience: Whether to validate audience claim
            validate_issuer: Whether to validate issuer claim
            ssl_verify: Whether to verify SSL certificates
        """
        self.jwks_url = jwks_url
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.algorithm = algorithm
        self.validate_audience = validate_audience
        self.validate_issuer = validate_issuer
        self.ssl_verify = ssl_verify

        # Initialize JWKS client for RS256
        if self.algorithm == "RS256":
            if not self.jwks_url:
                raise ValueError("jwks_url is required for RS256 algorithm")
            self.jwks_client = PyJWKClient(
                self.jwks_url,
                cache_keys=True,
                max_cached_keys=10,
                cache_jwk_set=True
            )
        elif self.algorithm == "HS256":
            if not self.client_secret:
                raise ValueError("client_secret is required for HS256 algorithm")
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        logger.info(f"Token verifier initialized with algorithm: {algorithm}")
        logger.info(f"Issuer: {issuer}")
        logger.info(f"Audience validation: {validate_audience}")

    async def verify_token(self, token: str) -> AccessToken | None:
        """
        Verify JWT token and return AccessToken if valid
        """
        try:
            # Decode token based on algorithm
            if self.algorithm == "RS256":
                payload = await self._verify_rs256(token)
            else:
                payload = self._verify_hs256(token)

            # Extract token information
            expires_at = payload.get("exp")
            subject = payload.get("sub")
            audience = payload.get("aud")

            # Extract scopes from different possible claim names
            scopes = self._extract_scopes(payload)

            # Determine client_id (from audience or use configured)
            if isinstance(audience, str):
                client_id = audience
            elif isinstance(audience, list) and audience:
                client_id = audience[0]
            else:
                client_id = self.client_id or "unknown"

            logger.info(f"✅ Token validated for subject: {subject}")
            logger.info(f"   Scopes: {scopes}")

            return AccessToken(
                token=token,
                client_id=client_id,
                scopes=scopes,
                expires_at=str(expires_at) if expires_at else None
            )

        except jwt.ExpiredSignatureError:
            logger.warning("❌ Token expired")
            return None
        except jwt.InvalidAudienceError:
            logger.warning("❌ Invalid audience")
            return None
        except jwt.InvalidIssuerError:
            logger.warning("❌ Invalid issuer")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"❌ Invalid token: {e}")
            return None
        except Exception as e:
            logger.error(f"❌ Token validation error: {e}")
            return None

    async def _verify_rs256(self, token: str) -> dict:
        """Verify token using RS256 (public key from JWKS)"""
        # Get signing key from JWKS
        signing_key = self.jwks_client.get_signing_key_from_jwt(token)

        # Build decode options
        decode_options = {
            "verify_exp": True,
            "verify_iat": True,
            "verify_aud": self.validate_audience,
            "verify_iss": self.validate_issuer
        }

        # Decode parameters
        decode_params = {
            "jwt": token,
            "key": signing_key.key,
            "algorithms": ["RS256"],
            "options": decode_options
        }

        # Add audience if validating
        if self.validate_audience and self.client_id:
            decode_params["audience"] = self.client_id

        # Add issuer if validating
        if self.validate_issuer and self.issuer:
            decode_params["issuer"] = self.issuer

        return jwt.decode(**decode_params)

    def _verify_hs256(self, token: str) -> dict:
        """Verify token using HS256 (shared secret)"""
        decode_options = {
            "verify_exp": True,
            "verify_iat": True,
            "verify_aud": self.validate_audience,
            "verify_iss": self.validate_issuer
        }

        decode_params = {
            "jwt": token,
            "key": self.client_secret,
            "algorithms": ["HS256"],
            "options": decode_options
        }

        if self.validate_audience and self.client_id:
            decode_params["audience"] = self.client_id

        if self.validate_issuer and self.issuer:
            decode_params["issuer"] = self.issuer

        return jwt.decode(**decode_params)

    def _extract_scopes(self, payload: dict) -> list[str]:
        """
        Extract scopes from token payload
        Different providers use different claim names
        """
        # Try common scope claim names
        for claim in ["scope", "scp", "scopes", "permissions"]:
            if claim in payload:
                value = payload[claim]

                # Handle space-separated string
                if isinstance(value, str):
                    return value.split()

                # Handle list
                elif isinstance(value, list):
                    return value

        return []


# ======================
# Environment Configuration
# ======================

# Authentication toggle
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "true").lower() == "true"

# Required settings (only if auth is enabled)
AUTH_ISSUER = os.getenv("AUTH_ISSUER")
CLIENT_ID = os.getenv("CLIENT_ID")
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8000")

# Algorithm selection (RS256 or HS256)
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "RS256")

# For RS256 (most common)
JWKS_URL = os.getenv("JWKS_URL")

# For HS256 (if needed)
CLIENT_SECRET = os.getenv("CLIENT_SECRET")

# Optional validation settings
VALIDATE_AUDIENCE = os.getenv("VALIDATE_AUDIENCE", "true").lower() == "true"
VALIDATE_ISSUER = os.getenv("VALIDATE_ISSUER", "true").lower() == "true"
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").lower() == "true"

# Required scopes (optional)
REQUIRED_SCOPES_STR = os.getenv("REQUIRED_SCOPES", "")
REQUIRED_SCOPES = REQUIRED_SCOPES_STR.split() if REQUIRED_SCOPES_STR else []

# Validate required environment variables only if auth is enabled
if ENABLE_AUTH:
    if not AUTH_ISSUER:
        raise ValueError("AUTH_ISSUER environment variable is required when auth is enabled")
    if not CLIENT_ID:
        raise ValueError("CLIENT_ID environment variable is required when auth is enabled")
    if JWT_ALGORITHM == "RS256" and not JWKS_URL:
        raise ValueError("JWKS_URL is required when using RS256 algorithm")
    if JWT_ALGORITHM == "HS256" and not CLIENT_SECRET:
        raise ValueError("CLIENT_SECRET is required when using HS256 algorithm")

logger.info("=" * 60)
logger.info("MCP Server Configuration")
logger.info("=" * 60)
logger.info(f"Authentication: {'ENABLED' if ENABLE_AUTH else 'DISABLED'}")
logger.info(f"Server URL: {MCP_SERVER_URL}")
if ENABLE_AUTH:
    logger.info(f"Auth Issuer: {AUTH_ISSUER}")
    logger.info(f"Client ID: {CLIENT_ID}")
    logger.info(f"Algorithm: {JWT_ALGORITHM}")
    logger.info(f"Required Scopes: {REQUIRED_SCOPES if REQUIRED_SCOPES else 'None'}")
logger.info("=" * 60)

# ======================
# Create FastMCP Instance
# ======================

if ENABLE_AUTH:
    # Create MCP server with authentication
    mcp = FastMCP(
        "Generic OAuth MCP Server",
        # Token verifier for JWT validation
        token_verifier=GenericOAuthTokenVerifier(
            jwks_url=JWKS_URL,
            issuer=AUTH_ISSUER,
            client_id=CLIENT_ID,
            client_secret=CLIENT_SECRET,
            algorithm=JWT_ALGORITHM,
            validate_audience=VALIDATE_AUDIENCE,
            validate_issuer=VALIDATE_ISSUER,
            ssl_verify=SSL_VERIFY
        ),
        # Auth settings for RFC 9728 Protected Resource Metadata
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(AUTH_ISSUER),
            resource_server_url=AnyHttpUrl(MCP_SERVER_URL),
            required_scopes=REQUIRED_SCOPES if REQUIRED_SCOPES else None
        )
    )
else:
    # Create MCP server without authentication
    mcp = FastMCP("Generic OAuth MCP Server")

# ======================
# Configure CORS
# ======================

# Add CORS middleware to handle OPTIONS requests from browser clients
# Get the Starlette app instance
streamable_app = mcp.streamable_http_app()
streamable_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify your client domain
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info("✅ CORS middleware configured")

# ======================
# Define MCP Tools
# ======================

@mcp.tool()
async def get_weather(city: str = "London") -> dict[str, str]:
    """Get weather data for a city"""
    logger.info(f"🌤️  Getting weather for: {city}")
    return {
        "city": city,
        "temperature": "22°C",
        "condition": "Partly cloudy",
        "humidity": "65%",
        "wind": "12 km/h"
    }


@mcp.tool()
async def calculate(expression: str) -> dict[str, str]:
    """Perform a mathematical calculation"""
    logger.info(f"🔢 Calculating: {expression}")
    try:
        result = eval(expression, {"__builtins__": {}}, {})
        return {
            "expression": expression,
            "result": str(result)
        }
    except Exception as e:
        return {
            "expression": expression,
            "error": str(e)
        }


@mcp.tool()
async def echo(message: str) -> dict[str, str]:
    """Echo back a message"""
    logger.info(f"📢 Echoing: {message}")
    return {
        "original": message,
        "echo": message
    }


# Add more tools as needed
@mcp.tool()
async def get_time() -> dict[str, str]:
    """Get current server time"""
    from datetime import datetime
    now = datetime.now()
    return {
        "timestamp": now.isoformat(),
        "time": now.strftime("%H:%M:%S"),
        "date": now.strftime("%Y-%m-%d")
    }


# ======================
# Run Server
# ======================

if __name__ == "__main__":
    logger.info("🚀 Starting MCP Server with OAuth 2.1 authentication")
    logger.info(f"   Transport: streamable-http")
    logger.info(f"   Port: 8000")
    logger.info("=" * 60)

    # Run with streamable HTTP transport
    # This automatically creates the .well-known endpoints
    mcp.run(transport="streamable-http")
