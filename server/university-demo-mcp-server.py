import os, ssl, logging, json
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, AnyHttpUrl
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware

import aiohttp
import jwt
from jwt import PyJWKClient
import certifi

from mcp.server.fastmcp import FastMCP
from mcp.server.auth.settings import AuthSettings
from mcp.server.auth.provider import AccessToken, TokenVerifier

# -------------------- Logging --------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-uni")

# -------------------- Env --------------------
load_dotenv()

# Authentication toggle (align with mcp_server.py)
ENABLE_AUTH = os.getenv("ENABLE_AUTH", "true").lower() == "true"

# Required settings
AUTH_ISSUER = os.getenv("AUTH_ISSUER")  # e.g. https://api.asgardeo.io/t/<tenant>/oauth2/token
CLIENT_ID = os.getenv("CLIENT_ID")      # SPA app client_id for PKCE
MCP_SERVER_URL = os.getenv("MCP_SERVER_URL", "http://localhost:8000")

# For RS256 (most common with OIDC providers)
JWKS_URL = os.getenv("JWKS_URL")  # e.g. https://api.asgardeo.io/t/<tenant>/oauth2/jwks

# Optional validation settings
VALIDATE_AUDIENCE = os.getenv("VALIDATE_AUDIENCE", "true").lower() == "true"
VALIDATE_ISSUER = os.getenv("VALIDATE_ISSUER", "true").lower() == "true"
SSL_VERIFY = os.getenv("SSL_VERIFY", "true").lower() == "true"
CA_BUNDLE = os.getenv("CA_BUNDLE")

# Required scopes
REQUIRED_SCOPES_STR = os.getenv("REQUIRED_SCOPES", "")
if not REQUIRED_SCOPES_STR and ENABLE_AUTH:
    REQUIRED_SCOPES = ["openid", "email", "profile", "roles"]
else:
    REQUIRED_SCOPES = REQUIRED_SCOPES_STR.split() if REQUIRED_SCOPES_STR else []
    # Ensure openid and email are always included when auth is enabled
    if ENABLE_AUTH:
        if "openid" not in REQUIRED_SCOPES:
            REQUIRED_SCOPES.insert(0, "openid")
        if "email" not in REQUIRED_SCOPES:
            REQUIRED_SCOPES.append("email")

# Database settings
MONGO_URI = os.getenv("MONGO_URI") or os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME = (os.getenv("DB_NAME") or "university_demo").strip().strip("/")

# Validate required environment variables only if auth is enabled
if ENABLE_AUTH:
    if not AUTH_ISSUER:
        raise ValueError("AUTH_ISSUER environment variable is required when auth is enabled")
    if not CLIENT_ID:
        raise ValueError("CLIENT_ID environment variable is required when auth is enabled")
    if not JWKS_URL:
        raise ValueError("JWKS_URL is required for RS256 algorithm")

# Legacy variable support (for backward compatibility)
TENANT = os.getenv("TENANT")  # Optional: e.g. metropolis

RAW_ISSUER = (AUTH_ISSUER or "").rstrip("/")

def to_discovery(url: str) -> str:
    if not url:
        return url
    u = url.rstrip('/')
    # If it's already a discovery URL, use as-is
    if u.endswith("/.well-known/openid-configuration"):
        return u
    # If it's exactly the issuer endpoint
    if u.endswith("/oauth2/token"):
        return u + "/.well-known/openid-configuration"
    # If it's the tenant base (no /oauth2/ segment), build the full discovery path
    if u.startswith("https://api.asgardeo.io/t/") and "/oauth2/" not in u:
        return u + "/oauth2/token/.well-known/openid-configuration"
    # Generic fallback
    return u + "/.well-known/openid-configuration"

AUTH_METADATA = to_discovery(RAW_ISSUER)

def build_ssl_context() -> ssl.SSLContext | bool:
    if not SSL_VERIFY:
        return False
    ctx = ssl.create_default_context()
    if CA_BUNDLE and os.path.exists(CA_BUNDLE):
        ctx.load_verify_locations(CA_BUNDLE)
    else:
        ctx.load_default_certs()
    return ctx

# -------------------- Mongo --------------------
client = AsyncIOMotorClient(MONGO_URI)
db = client[DB_NAME]

# -------------------- JWKS validator --------------------
class JWKSValidator:
    def __init__(self, jwks_url: str, issuer: str, audience: str):
        self.jwks_url = jwks_url
        self.issuer   = issuer
        self.audience = audience
        self._jwks: Optional[Dict[str, Any]] = None

    async def _fetch_jwks(self) -> Dict[str, Any]:
        if self._jwks:
            return self._jwks
        connector = aiohttp.TCPConnector(ssl=build_ssl_context())
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.get(self.jwks_url, timeout=15) as r:
                r.raise_for_status()
                self._jwks = await r.json()
                return self._jwks

    async def validate(self, token: str) -> Dict[str, Any]:
        logger.info(f"🔍 Starting token validation...")
        logger.info(f"🔍 Token (first 20 chars): {token[:20]}...")
        logger.info(f"🔍 Expected issuer: {self.issuer}")
        logger.info(f"🔍 Expected audience: {self.audience}")

        try:
            jwks = await self._fetch_jwks()
            logger.info(f"✅ JWKS fetched successfully, {len(jwks.get('keys', []))} keys available")

            header = jwt.get_unverified_header(token)
            logger.info(f"🔍 Token header: {header}")

            kid = header.get("kid")
            logger.info(f"🔍 Looking for key with kid: {kid}")

            key = next((k for k in jwks.get("keys", []) if k.get("kid") == kid), None)
            if not key:
                logger.error(f"❌ No key found matching kid: {kid}")
                logger.error(f"❌ Available kids: {[k.get('kid') for k in jwks.get('keys', [])]}")
                raise ValueError("jwks_key_not_found_for_kid")

            logger.info(f"✅ Found matching key for kid: {kid}")

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(key))
            logger.info(f"✅ Public key extracted")

            # Decode and validate
            decoded = jwt.decode(
                token,
                public_key,
                algorithms=[header.get("alg", "RS256")],
                audience=self.audience,
                issuer=self.issuer,
            )

            logger.info(f"✅ Token validated successfully!")
            logger.info(f"✅ Token claims: sub={decoded.get('sub')}, aud={decoded.get('aud')}, iss={decoded.get('iss')}")

            return decoded

        except jwt.ExpiredSignatureError as e:
            logger.error(f"❌ Token expired: {e}")
            raise
        except jwt.InvalidAudienceError as e:
            logger.error(f"❌ Invalid audience in token")
            logger.error(f"❌ Expected: {self.audience}")
            logger.error(f"❌ Got: {jwt.decode(token, options={'verify_signature': False}).get('aud')}")
            raise
        except jwt.InvalidIssuerError as e:
            logger.error(f"❌ Invalid issuer in token")
            logger.error(f"❌ Expected: {self.issuer}")
            logger.error(f"❌ Got: {jwt.decode(token, options={'verify_signature': False}).get('iss')}")
            raise
        except Exception as e:
            logger.error(f"❌ Token validation failed: {type(e).__name__}: {e}")
            import traceback
            logger.error(f"❌ Traceback: {traceback.format_exc()}")
            raise

VALIDATOR = JWKSValidator(JWKS_URL or "", AUTH_ISSUER or "", CLIENT_ID or "")

def roles_from_claims(claims: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    for k in ("roles", "groups", "application_roles", "app_roles"):
        v = claims.get(k)
        if not v: continue
        if isinstance(v, str):
            out.extend([x.strip() for x in v.split(",") if x.strip()])
        elif isinstance(v, list):
            out.extend([str(x) for x in v])
    return sorted(set(out))

def require_role(roles: List[str], *allowed: str):
    for a in allowed:
        if a in roles:
            return
    raise PermissionError(f"no_permission (requires one of: {allowed})")

async def userinfo(token: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
    issuer = (AUTH_ISSUER or "").rstrip("/")
    if not issuer:
        return None, "issuer_not_configured"
    if issuer.endswith("/token"):
        well_known = issuer[: -len("/token")] + "/.well-known/openid-configuration"
    else:
        well_known = issuer + "/.well-known/openid-configuration"
    connector = aiohttp.TCPConnector(ssl=build_ssl_context())
    try:
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.get(well_known, timeout=10) as r:
                r.raise_for_status()
                data = await r.json()
        ep = data.get("userinfo_endpoint")
        if not ep:
            return None, "userinfo_endpoint_not_configured"
        async with aiohttp.ClientSession(connector=connector) as s:
            async with s.get(ep, headers={"Authorization": f"Bearer {token}"}, timeout=15) as r:
                if r.status == 200:
                    return await r.json(), None
                return None, f"userinfo_http_{r.status}"
    except Exception as e:
        return None, f"userinfo_error_{type(e).__name__}"

async def student_id_from_token(access_token: str) -> Optional[str]:
    try:
        claims = jwt.decode(access_token, options={"verify_signature": False})
    except Exception:
        claims = {}
    email = claims.get("email") or claims.get("preferred_username") or claims.get("username")
    if not email:
        ui, err = await userinfo(access_token)
        if ui and not err:
            email = ui.get("email") or ui.get("preferred_username") or ui.get("username")
    if not email:
        return None
    s = await db.students.find_one({"email": email})
    return s["studentId"] if s else None

# -------------------- Transport token verifier (for FastMCP auth) --------------------
class AsgardeoTransportVerifier(TokenVerifier):
    """
    Token verifier for Asgardeo OAuth provider
    Returns None for invalid/missing tokens to allow optional authentication
    """

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        # Allow missing or empty tokens
        if not token or token.strip() == "":
            logger.info("ℹ️  No token provided - allowing unauthenticated access")
            return None

        try:
            claims = await VALIDATOR.validate(token)
            scopes = claims.get("scope", "")

            logger.info(f"✅ Token validated for subject: {claims.get('sub')}")

            return AccessToken(
                token=token,
                client_id=claims.get("aud"),
                scopes=scopes.split() if isinstance(scopes, str) else [],
                expires_at=str(claims.get("exp")) if claims.get("exp") else None,
            )
        except jwt.ExpiredSignatureError:
            logger.warning("❌ Token expired - allowing unauthenticated access")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"❌ Invalid token: {e} - allowing unauthenticated access")
            return None
        except Exception as e:
            logger.error(f"❌ Token validation error: {e} - allowing unauthenticated access")
            return None

# -------------------- MCP server --------------------
logger.info("=" * 60)
logger.info("MCP University Demo Server Configuration")
logger.info("=" * 60)
logger.info(f"Authentication: {'ENABLED' if ENABLE_AUTH else 'DISABLED'}")
logger.info(f"Server URL: {MCP_SERVER_URL}")
if ENABLE_AUTH:
    logger.info(f"Auth Issuer: {AUTH_ISSUER}")
    logger.info(f"Client ID: {CLIENT_ID}")
    logger.info(f"JWKS URL: {JWKS_URL}")
    logger.info(f"Required Scopes: {', '.join(REQUIRED_SCOPES)}")
logger.info(f"Database: {DB_NAME}")
logger.info("=" * 60)

if ENABLE_AUTH:
    mcp = FastMCP(
        "University Demo",
        token_verifier=AsgardeoTransportVerifier(),
        auth=AuthSettings(
            issuer_url=AnyHttpUrl(AUTH_ISSUER.rstrip("/")),
            resource_server_url=AnyHttpUrl(MCP_SERVER_URL),
            required_scopes=REQUIRED_SCOPES,
        ),
    )
else:
    mcp = FastMCP("University Demo")

# -------------------- Configure CORS --------------------
# Add CORS middleware to handle OPTIONS requests from browser clients
streamable_app = mcp.streamable_http_app()
streamable_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,  # Must be False with wildcard
    allow_methods=["*"],
    allow_headers=["*"],
)

logger.info("✅ CORS middleware configured")

# -------------------- Helper Functions --------------------
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


async def get_user_roles() -> tuple[Optional[List[str]], Optional[str]]:
    """
    Extract roles from the current user's token
    Returns: (roles_list, error_message)
    """
    access_token = get_current_user_token()
    if not access_token:
        return None, "not_authenticated"

    try:
        # Decode token without verification to extract claims
        claims = jwt.decode(access_token.token, options={"verify_signature": False})
        roles = roles_from_claims(claims)
        return roles, None
    except Exception as e:
        logger.error(f"Error extracting roles from token: {e}")
        return None, str(e)


# -------------------- Schemas --------------------
# All schemas use MCP context for authentication - no access_token parameter needed!

class CreateCourseArgs(BaseModel):
    courseCode: str
    title: str
    semester: str
    year: int
    price: float

    def model_post_init(self, __context):
        # Convert semester to lowercase and validate
        self.semester = self.semester.lower()
        if self.semester not in ["fall", "spring", "summer", "winter"]:
            raise ValueError(f"semester must be one of: fall, spring, summer, winter (got: {self.semester})")

class ChangePriceArgs(BaseModel):
    courseCode: str
    price: float

class EnrollArgs(BaseModel):
    courseCode: str
    studentId: Optional[str] = None  # Optional: will be derived from token if not provided

class StudentsDueArgs(BaseModel):
    semester: str
    year: int

    def model_post_init(self, __context):
        # Convert semester to lowercase and validate
        self.semester = self.semester.lower()
        if self.semester not in ["fall", "spring", "summer", "winter"]:
            raise ValueError(f"semester must be one of: fall, spring, summer, winter (got: {self.semester})")

class MarkPaidArgs(BaseModel):
    studentId: str
    courseCode: str

class MyBalanceArgs(BaseModel):
    studentId: Optional[str] = None  # Optional: will be derived from token if not provided
    semester: Optional[str] = None
    year: Optional[int] = None

    def model_post_init(self, __context):
        # Convert semester to lowercase and validate if provided
        if self.semester:
            self.semester = self.semester.lower()
            if self.semester not in ["fall", "spring", "summer", "winter"]:
                raise ValueError(f"semester must be one of: fall, spring, summer, winter (got: {self.semester})")

# -------------------- Tools --------------------
@mcp.tool()
async def ping() -> Dict[str, str]:
    return {"ok": "pong"}

@mcp.tool()
async def list_courses() -> List[Dict[str, Any]]:
    cur = db.courses.find({}, {"_id": 0})
    return [c async for c in cur]

@mcp.tool()
async def db_counts() -> dict:
    students = await db.students.count_documents({})
    courses = await db.courses.count_documents({})
    enrolls = await db.enrollments.count_documents({})
    return {"students": students, "courses": courses, "enrollments": enrolls}

@mcp.tool()
async def whoami_token(access_token: str) -> Dict[str, Any]:
    """Validate a token and show claims/roles (useful in Claude to capture the bearer)."""
    if not ENABLE_AUTH:
        return {"valid": False, "error": "auth_disabled"}
    try:
        claims = await VALIDATOR.validate(access_token)
        return {"valid": True, "claims": claims, "roles": roles_from_claims(claims)}
    except Exception as e:
        return {"valid": False, "error": str(e)}

@mcp.tool()
async def create_course(args: CreateCourseArgs) -> Dict[str, Any]:
    """
    Create a new course
    Requires authentication with 'academic' role
    """
    if ENABLE_AUTH:
        # Get roles from MCP context (token automatically verified by FastMCP)
        roles, error = await get_user_roles()
        if error == "not_authenticated":
            return {
                "error": "authentication_required",
                "message": "This tool requires authentication with 'academic' role"
            }
        if error:
            return {"error": "invalid_token", "detail": error}

        # Check for required role
        try:
            require_role(roles, "academic")
        except PermissionError as e:
            return {
                "error": "forbidden",
                "message": str(e),
                "your_roles": roles
            }

    # Create course
    if await db.courses.find_one({"courseCode": args.courseCode}):
        return {"error": "course_exists"}

    await db.courses.insert_one({
        "courseCode": args.courseCode,
        "title": args.title,
        "semester": args.semester,
        "year": args.year,
        "price": args.price,
    })
    return {"ok": True}

@mcp.tool()
async def change_course_price(args: ChangePriceArgs) -> Dict[str, Any]:
    """
    Change the price of a course
    Requires authentication with 'finance' role
    """
    if ENABLE_AUTH:
        # Get roles from MCP context
        roles, error = await get_user_roles()
        if error == "not_authenticated":
            return {
                "error": "authentication_required",
                "message": "This tool requires authentication with 'finance' role"
            }
        if error:
            return {"error": "invalid_token", "detail": error}

        # Check for required role
        try:
            require_role(roles, "finance")
        except PermissionError as e:
            return {
                "error": "forbidden",
                "message": str(e),
                "your_roles": roles
            }

    r = await db.courses.update_one({"courseCode": args.courseCode}, {"$set": {"price": args.price}})
    return {"ok": r.matched_count > 0}

@mcp.tool()
async def enroll(args: EnrollArgs) -> Dict[str, Any]:
    """
    Enroll a student in a course
    Requires authentication with 'student' role
    """
    if ENABLE_AUTH:
        # Get roles from MCP context
        roles, error = await get_user_roles()
        if error == "not_authenticated":
            return {
                "error": "authentication_required",
                "message": "This tool requires authentication with 'student' role"
            }
        if error:
            return {"error": "invalid_token", "detail": error}

        # Check for required role
        try:
            require_role(roles, "student")
        except PermissionError as e:
            return {
                "error": "forbidden",
                "message": str(e),
                "your_roles": roles
            }

        # Get student ID from token
        access_token = get_current_user_token()
        sid = args.studentId or await student_id_from_token(access_token.token)
    else:
        sid = args.studentId

    if not sid:
        return {"error": "student_not_linked"}

    course = await db.courses.find_one({"courseCode": args.courseCode})
    if not course:
        return {"error": "course_not_found"}

    sem, yr = course["semester"], course["year"]
    unpaid_prev = await db.enrollments.count_documents({
        "studentId": sid, "isPaid": False,
        "$or": [{"year": {"$lt": yr}}, {"year": yr, "semester": {"$ne": sem}}],
    })
    if unpaid_prev > 0:
        return {"error": "has_unpaid_balance_previous_semesters"}

    current = await db.enrollments.count_documents({
        "studentId": sid, "semester": sem, "year": yr, "status": "enrolled"
    })
    if current >= 5:
        return {"error": "max_courses_reached"}

    await db.enrollments.insert_one({
        "studentId": sid,
        "courseId": course["courseCode"],
        "semester": sem,
        "year": yr,
        "status": "enrolled",
        "isPaid": False,
        "amountDue": float(course["price"]),
        "createdAt": datetime.utcnow(),
    })
    return {"ok": True, "studentId": sid}

@mcp.tool()
async def students_due(args: StudentsDueArgs) -> List[Dict[str, Any]]:
    """
    Get list of students with outstanding payments for a semester
    Requires authentication with 'finance' role
    """
    if ENABLE_AUTH:
        # Get roles from MCP context
        roles, error = await get_user_roles()
        if error == "not_authenticated":
            return [{"error": "authentication_required", "message": "This tool requires authentication with 'finance' role"}]
        if error:
            return [{"error": "invalid_token", "detail": error}]

        # Check for required role
        try:
            require_role(roles, "finance")
        except PermissionError as e:
            return [{"error": "forbidden", "message": str(e), "your_roles": roles}]

    cur = db.enrollments.aggregate([
        {"$match": {"semester": args.semester, "year": args.year, "isPaid": False}},
        {"$lookup": {"from": "courses", "localField": "courseId", "foreignField": "courseCode", "as": "course"}},
        {"$unwind": "$course"},
        {"$lookup": {"from": "students", "localField": "studentId", "foreignField": "studentId", "as": "student"}},
        {"$unwind": "$student"},
        {"$project": {
            "_id": 0,
            "courseCode": "$course.courseCode", "title": "$course.title",
            "studentId": 1, "studentName": "$student.name", "studentEmail": "$student.email",
            "amountDue": 1
        }},
        {"$sort": {"courseCode": 1, "studentId": 1}},
    ])
    return [d async for d in cur]

@mcp.tool()
async def mark_paid(args: MarkPaidArgs) -> Dict[str, Any]:
    """
    Mark a student's course payment as paid
    Requires authentication with 'finance' role
    """
    if ENABLE_AUTH:
        # Get roles from MCP context
        roles, error = await get_user_roles()
        if error == "not_authenticated":
            return {
                "error": "authentication_required",
                "message": "This tool requires authentication with 'finance' role"
            }
        if error:
            return {"error": "invalid_token", "detail": error}

        # Check for required role
        try:
            require_role(roles, "finance")
        except PermissionError as e:
            return {
                "error": "forbidden",
                "message": str(e),
                "your_roles": roles
            }

    r = await db.enrollments.update_one(
        {"studentId": args.studentId, "courseId": args.courseCode, "status": "enrolled"},
        {"$set": {"isPaid": True, "amountDue": 0.0}},
    )
    if r.matched_count == 0:
        return {"error": "enrollment_not_found"}
    return {"ok": True}

@mcp.tool()
async def my_balance(args: MyBalanceArgs) -> Dict[str, Any]:
    """
    Get your current balance and enrollment details
    Requires authentication with 'student' role
    """
    if ENABLE_AUTH:
        # Get roles from MCP context
        roles, error = await get_user_roles()
        if error == "not_authenticated":
            return {
                "error": "authentication_required",
                "message": "This tool requires authentication with 'student' role"
            }
        if error:
            return {"error": "invalid_token", "detail": error}

        # Check for required role
        try:
            require_role(roles, "student")
        except PermissionError as e:
            return {
                "error": "forbidden",
                "message": str(e),
                "your_roles": roles
            }

        # Get student ID from token
        access_token = get_current_user_token()
        sid = args.studentId or await student_id_from_token(access_token.token)
    else:
        sid = args.studentId

    if not sid:
        return {"error": "student_not_linked"}

    match: Dict[str, Any] = {"studentId": sid, "status": "enrolled"}
    if args.semester: match["semester"] = args.semester
    if args.year is not None: match["year"] = args.year

    pipeline = [
        {"$match": match},
        {"$lookup": {"from": "courses", "localField": "courseId", "foreignField": "courseCode", "as": "course"}},
        {"$unwind": "$course"},
        {"$project": {
            "_id": 0,
            "semester": 1, "year": 1,
            "courseCode": "$course.courseCode", "title": "$course.title",
            "amountDue": 1, "isPaid": 1
        }},
        {"$sort": {"year": 1, "semester": 1, "courseCode": 1}},
    ]
    items = [x async for x in db.enrollments.aggregate(pipeline)]
    total_due  = float(sum(x["amountDue"] for x in items if not x["isPaid"]))
    total_paid = float(sum(x["amountDue"] for x in items if x["isPaid"]))

    return {
        "studentId": sid,
        "summary": {"total_due": total_due, "total_paid": total_paid},
        "lines": items,
    }

# -------------------- NEW: Example tool using MCP context (standard approach) --------------------
@mcp.tool()
async def create_course_v2(args: CreateCourseArgs) -> Dict[str, Any]:
    """
    Create a new course (V2 - uses MCP context for authentication)
    This is the RECOMMENDED approach - token comes from HTTP Authorization header
    """
    if ENABLE_AUTH:
        # Get roles from MCP context (token automatically verified by FastMCP)
        roles, error = await get_user_roles()
        if error == "not_authenticated":
            return {
                "error": "authentication_required",
                "message": "This tool requires authentication with 'academic' role"
            }
        if error:
            return {"error": "invalid_token", "detail": error}

        # Check for required role
        try:
            require_role(roles, "academic")
        except PermissionError as e:
            return {
                "error": "forbidden",
                "message": str(e),
                "your_roles": roles
            }

    # Create course
    if await db.courses.find_one({"courseCode": args.courseCode}):
        return {"error": "course_exists"}

    await db.courses.insert_one({
        "courseCode": args.courseCode,
        "title": args.title,
        "semester": args.semester,
        "year": args.year,
        "price": args.price,
    })

    return {
        "ok": True,
        "message": f"Course {args.courseCode} created successfully"
    }


@mcp.tool()
async def whoami() -> Dict[str, Any]:
    """
    Get information about the current authenticated user
    Uses MCP context - no token parameter needed!
    """
    if not ENABLE_AUTH:
        return {"error": "authentication_disabled"}

    access_token = get_current_user_token()
    if not access_token:
        return {
            "authenticated": False,
            "message": "No authentication token provided"
        }

    try:
        # Decode token to get claims
        claims = jwt.decode(access_token.token, options={"verify_signature": False})
        roles = roles_from_claims(claims)

        return {
            "authenticated": True,
            "subject": claims.get("sub"),
            "email": claims.get("email"),
            "name": claims.get("name"),
            "username": claims.get("preferred_username") or claims.get("username"),
            "roles": roles,
            "scopes": access_token.scopes,
            "token_expires_at": access_token.expires_at
        }
    except Exception as e:
        return {"error": "failed_to_decode_token", "detail": str(e)}


# -------------------- Run --------------------
if __name__ == "__main__":
    mcp.run(transport="streamable-http")

#if __name__ == "__main__":
#    mcp.run(transport="stdio")