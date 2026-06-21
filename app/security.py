from datetime import datetime, timedelta, timezone
from jose import jwt, JWTError
from passlib.context import CryptContext
import secrets

# ---------- Password hashing ----------

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


# ---------- JWT settings ----------
# NOTE: In a real production app, SECRET_KEY comes from an environment variable,
# never hardcoded. We'll move this to .env shortly.
import os
from dotenv import load_dotenv

load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")

ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 15))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.getenv("REFRESH_TOKEN_EXPIRE_DAYS", 7))

if not SECRET_KEY:
    raise RuntimeError("SECRET_KEY not set in .env file")


# ---------- Token creation ----------

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access", "jti": secrets.token_urlsafe(8)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh", "jti": secrets.token_urlsafe(8)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def generate_verification_token() -> str:
    """Generates a random token for email verification."""
    return secrets.token_urlsafe(32)

# ---------- Token verification ----------

def decode_token(token: str) -> dict:
    """
    Decodes and validates a JWT.
    Raises JWTError if the token is invalid, malformed, or expired.
    python-jose checks expiry ('exp' claim) automatically.
    """
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    return payload