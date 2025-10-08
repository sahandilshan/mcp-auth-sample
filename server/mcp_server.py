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
    Always returns None for invalid/missing tokens to allow unauthenticated access
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

            # Configure SSL context for JWKS client
            import ssl
            if not self.ssl_verify:
                # Disable SSL verification (not recommended for production)
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                logger.warning("⚠️  SSL verification disabled for JWKS endpoint")
            else:
                ssl_context = None  # Use default SSL verification

            self.jwks_client = PyJWKClient(
                self.jwks_url,
                cache_keys=True,
                max_cached_keys=10,
                cache_jwk_set=True,
                ssl_context=ssl_context
            )
        elif self.algorithm == "HS256":
            if not self.client_secret:
                raise ValueError("client_secret is required for HS256 algorithm")
        else:
            raise ValueError(f"Unsupported algorithm: {algorithm}")

        logger.info(f"Token verifier initialized with algorithm: {algorithm}")
        logger.info(f"Issuer: {issuer}")
        logger.info(f"Optional authentication: enabled (tokens verified but not required)")

    async def verify_token(self, token: str) -> AccessToken | None:
        """
        Verify JWT token and return AccessToken if valid
        Returns None for invalid/missing tokens to allow unauthenticated access
        """
        # Allow missing or empty tokens
        if not token or token.strip() == "":
            logger.info("ℹ️  No token provided - allowing unauthenticated access")
            return None

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
            logger.warning("❌ Token expired - allowing unauthenticated access")
            return None
        except jwt.InvalidAudienceError:
            logger.warning("❌ Invalid audience - allowing unauthenticated access")
            return None
        except jwt.InvalidIssuerError:
            logger.warning("❌ Invalid issuer - allowing unauthenticated access")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"❌ Invalid token: {e} - allowing unauthenticated access")
            return None
        except Exception as e:
            logger.error(f"❌ Token validation error: {e} - allowing unauthenticated access")
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
# If no scopes are specified, default to openid and email for OIDC user info
if not REQUIRED_SCOPES_STR and ENABLE_AUTH:
    REQUIRED_SCOPES = ["openid", "email", "profile"]
else:
    REQUIRED_SCOPES = REQUIRED_SCOPES_STR.split() if REQUIRED_SCOPES_STR else []
    # Ensure openid and email are always included when auth is enabled
    if ENABLE_AUTH:
        if "openid" not in REQUIRED_SCOPES:
            REQUIRED_SCOPES.insert(0, "openid")
        if "email" not in REQUIRED_SCOPES:
            REQUIRED_SCOPES.append("email")

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
    allow_origins=["*"],
    allow_credentials = False,  # Must be False with wildcard
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info("✅ CORS middleware configured")

# ======================
# Helper Functions
# ======================

def get_current_user_token():
    """Get the current user's access token from request context"""
    try:
        context = mcp.get_context()
        if not context or not context.request_context or not context.request_context.request:
            return None

        user = context.request_context.request.user
        if not user or not user.access_token:
            return None

        return user.access_token
    except Exception as e:
        logger.error(f"Error getting user token: {e}")
        return None


def check_scope(required_scope: str) -> tuple[bool, Optional[str], Optional[list[str]]]:
    """
    Check if the current user has the required scope
    Returns: (has_scope, error_message, user_scopes)

    Note: Since MCP auth spec doesn't support per-tool authentication,
    this is used for informational responses only.
    """
    if not ENABLE_AUTH:
        return False, "Authentication is not enabled on this server", None

    access_token = get_current_user_token()
    if not access_token:
        return False, f"This tool requires authentication with '{required_scope}' scope", None

    user_scopes = access_token.scopes or []

    if required_scope not in user_scopes:
        return False, f"Missing required scope: '{required_scope}'. Your scopes: {user_scopes}", user_scopes

    return True, None, user_scopes


# ======================
# Define MCP Tools
# ======================

# ------------------
# PUBLIC TOOLS (No authentication required)
# ------------------

@mcp.tool()
async def get_server_info() -> dict[str, str]:
    """
    Get information about the MCP server
    This tool works without authentication.
    """
    logger.info("ℹ️  Getting server information (public)")

    # Check if user is authenticated (optional)
    access_token = get_current_user_token()
    is_authenticated = access_token is not None

    return {
        "server_name": "Generic OAuth MCP Server",
        "version": "1.0.0",
        "authentication": "enabled" if ENABLE_AUTH else "disabled",
        "transport": "streamable-http",
        "description": "MCP server with OAuth 2.1 authentication support",
        "your_status": "authenticated" if is_authenticated else "unauthenticated",
        "note": "Some tools provide additional information when authenticated"
    }


@mcp.tool()
async def calculate(expression: str) -> dict[str, str]:
    """
    Perform a mathematical calculation
    This tool works without authentication.

    Args:
        expression: Mathematical expression to evaluate (e.g., "2 + 2", "10 * 5")
    """
    logger.info(f"🔢 Calculating: {expression} (public)")
    try:
        # Safe evaluation with limited builtins
        result = eval(expression, {"__builtins__": {}}, {})
        return {
            "expression": expression,
            "result": str(result),
            "status": "success"
        }
    except Exception as e:
        return {
            "expression": expression,
            "error": str(e),
            "status": "error"
        }


# ------------------
# AUTHENTICATED TOOLS (Provide enhanced responses with authentication)
# ------------------

@mcp.tool()
async def get_email() -> dict[str, str]:
    """
    Get the email address of the authenticated user

    This tool demonstrates scope-based access:
    - Without authentication: Returns an informational message
    - With authentication but missing 'email' scope: Returns scope requirement message
    - With authentication and 'email' scope: Returns the user's email

    Note: MCP spec doesn't enforce tool-level auth, so this is informational only.
    """
    logger.info("📧 Getting user email (prefers 'email' scope)")

    # Check for email scope
    has_scope, error_msg, user_scopes = check_scope("email")
    if not has_scope:
        logger.warning(f"⚠️  {error_msg}")
        return {
            "status": "error",
            "error": error_msg,
            "note": "This tool works best with an access token containing the 'email' scope"
        }

    # Get the access token
    access_token = get_current_user_token()
    if not access_token:
        return {
            "status": "error",
            "error": "Failed to retrieve access token"
        }

    try:
        # Decode the JWT to extract email
        decoded = jwt.decode(access_token.token, options={"verify_signature": False})

        email = decoded.get("email")
        email_verified = decoded.get("email_verified", False)

        if not email:
            return {
                "status": "error",
                "error": "Email not found in token claims"
            }

        logger.info(f"✅ Email retrieved: {email}")

        return {
            "status": "success",
            "email": email,
            "email_verified": str(email_verified),
        }

    except Exception as e:
        logger.error(f"❌ Error extracting email: {e}")
        return {
            "status": "error",
            "error": f"Failed to extract email from token: {str(e)}"
        }


@mcp.tool()
async def get_name() -> dict[str, str]:
    """
    Get the name of the authenticated user

    This tool demonstrates scope-based access:
    - Without authentication: Returns an informational message
    - With authentication but missing 'profile' scope: Returns scope requirement message
    - With authentication and 'profile' scope: Returns the user's name information

    Note: MCP spec doesn't enforce tool-level auth, so this is informational only.
    """
    logger.info("👤 Getting user name (prefers 'profile' scope)")

    # Check for profile scope
    has_scope, error_msg, user_scopes = check_scope("profile")
    if not has_scope:
        logger.warning(f"⚠️  {error_msg}")
        return {
            "status": "error",
            "error": error_msg,
            "note": "This tool works best with an access token containing the 'profile' scope"
        }

    # Get the access token
    access_token = get_current_user_token()
    if not access_token:
        return {
            "status": "error",
            "error": "Failed to retrieve access token"
        }

    try:
        # Decode the JWT to extract name information
        decoded = jwt.decode(access_token.token, options={"verify_signature": False})

        name = decoded.get("name")
        given_name = decoded.get("given_name")
        family_name = decoded.get("family_name")
        preferred_username = decoded.get("preferred_username")

        # Build response with available name fields
        response = {
            "status": "success"
        }

        if name:
            response["name"] = name
        if given_name:
            response["given_name"] = given_name
        if family_name:
            response["family_name"] = family_name
        if preferred_username:
            response["preferred_username"] = preferred_username

        if not any([name, given_name, family_name, preferred_username]):
            return {
                "status": "error",
                "error": "No name information found in token claims"
            }

        logger.info(f"✅ Name retrieved: {name or given_name or preferred_username}")

        return response

    except Exception as e:
        logger.error(f"❌ Error extracting name: {e}")
        return {
            "status": "error",
            "error": f"Failed to extract name from token: {str(e)}"
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
