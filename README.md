# JWT Auth Service

A JWT-based authentication API built with **FastAPI**, **SQLAlchemy**, and **SQLite**. Provides user registration, email verification, login, token refresh (with rotation), and logout (with server-side token revocation).

## Tech Stack

| Component | Choice |
|---|---|
| Framework | FastAPI |
| Database | SQLite (via SQLAlchemy ORM) |
| Password hashing | bcrypt (via passlib) |
| Tokens | JWT (via python-jose), HS256 |
| Validation | Pydantic v2 |
| Testing | pytest + httpx |

## Setup

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```
SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=15
REFRESH_TOKEN_EXPIRE_DAYS=7
```

Run the server:

```bash
uvicorn app.main:app --reload
```

Interactive API docs available at `http://127.0.0.1:8000/docs`.

Run tests:

```bash
pytest -v
```

## Architecture Notes

- **Stateless access tokens, revocable refresh tokens.** Access tokens are short-lived (15 min) and self-contained JWTs. Refresh tokens are also JWTs, but the current valid refresh token is additionally stored on the `User` record in the database. This hybrid approach is what makes logout actually work — a JWT alone can't be "revoked" before its natural expiry, but checking it against a server-side value can.
- **Refresh token rotation.** Every call to `/auth/refresh` issues a brand new access/refresh pair and invalidates the old refresh token. This limits the window in which a leaked refresh token can be reused.
- **Token type claims.** Every JWT carries a `"type"` claim (`access` or `refresh`). Endpoints that expect a refresh token explicitly reject access tokens presented in their place, and vice versa.
- **`jti` claim.** Each token includes a unique random `jti` (JWT ID) so that two tokens issued within the same second are never identical.
- **Email verification gate.** `is_verified` must be `true` before login succeeds, regardless of whether the password is correct.

## Endpoints

### `POST /auth/register`

Creates a new, unverified user account.

**Request body**
```json
{
  "email": "user@example.com",
  "password": "Password123"
}
```

**Validation rules**
- `email` must be a valid email format (Pydantic `EmailStr`)
- `password` must be 8–128 characters, and contain at least one uppercase letter, one lowercase letter, and one digit

**Responses**

| Status | Condition |
|---|---|
| `201 Created` | User created. Response includes a verification token (in production this would be emailed, not returned in the response). |
| `400 Bad Request` | Email already registered |
| `422 Unprocessable Entity` | Invalid email format or password doesn't meet strength rules |

```json
// 201 response
{ "message": "User registered. Verification token (dev only): <token>" }
```

---

### `POST /auth/verify-email`

Marks a user's email as verified using the one-time token issued at registration.

**Request body**
```json
{ "token": "<verification_token>" }
```

**Responses**

| Status | Condition |
|---|---|
| `200 OK` | Email verified successfully; token is cleared and cannot be reused |
| `400 Bad Request` | Token is invalid or does not match any user |

---

### `POST /auth/login`

Authenticates a user and issues an access/refresh token pair.

**Request body**
```json
{
  "email": "user@example.com",
  "password": "Password123"
}
```

**Validation rules**
- Credentials must match a registered user (password checked via bcrypt comparison, never plain text)
- `is_verified` must be `true`

**Responses**

| Status | Condition |
|---|---|
| `200 OK` | Returns `access_token`, `refresh_token`, `token_type` |
| `401 Unauthorized` | Email not found, or password incorrect |
| `403 Forbidden` | Credentials correct, but email not yet verified |

```json
// 200 response
{
  "access_token": "<jwt>",
  "refresh_token": "<jwt>",
  "token_type": "bearer"
}
```

---

### `POST /auth/refresh`

Exchanges a valid refresh token for a new access/refresh token pair. Old refresh token is invalidated (rotation).

**Request body**
```json
{ "refresh_token": "<refresh_token>" }
```

**Validation rules**
- Token must be a structurally valid, non-expired JWT
- Token's `type` claim must be `"refresh"` (an access token will be rejected here)
- Token must match the value currently stored for that user (i.e. not already logged out / rotated away)

**Responses**

| Status | Condition |
|---|---|
| `200 OK` | Returns a new `access_token` and `refresh_token` |
| `401 Unauthorized` | Token expired, malformed, wrong type, or no longer recognized (e.g. already used after rotation, or invalidated by logout) |

---

### `POST /auth/logout`

Invalidates a refresh token server-side, ending the session.

**Request body**
```json
{ "refresh_token": "<refresh_token>" }
```

**Responses**

| Status | Condition |
|---|---|
| `200 OK` | Logged out; the stored refresh token is cleared, so this token can no longer be used at `/auth/refresh` |
| `401 Unauthorized` | Token invalid, expired, or doesn't match the stored token |

## Test Coverage

15 automated tests in `tests/test_auth.py`, run against an isolated test database (separate from the dev database, created/destroyed per test):

- Registration: success, duplicate email, invalid email, weak/short password
- Login: success after verification, blocked before verification, wrong password, nonexistent user
- Email verification: success, invalid token
- Refresh: success with rotation, invalid token rejected, access token rejected as refresh token
- Logout: success and subsequent reuse rejected, invalid token rejected
