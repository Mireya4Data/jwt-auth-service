from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from jose import JWTError

from app.database import get_db
from app import models, schemas, security

router = APIRouter(prefix="/auth", tags=["auth"])


# ---------- POST /auth/register ----------
@router.post("/register", response_model=schemas.MessageResponse, status_code=status.HTTP_201_CREATED)
def register(payload: schemas.UserRegister, db: Session = Depends(get_db)):
    existing_user = db.query(models.User).filter(models.User.email == payload.email).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Email already registered")

    hashed_pw = security.hash_password(payload.password)
    verification_token = security.generate_verification_token()

    new_user = models.User(
        email=payload.email,
        hashed_password=hashed_pw,
        is_verified=False,
        verification_token=verification_token,
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # In production: send `verification_token` via email instead of logging it.
    print(f"[DEV ONLY] Verification token for {payload.email}: {verification_token}")

    return {"message": f"User registered. Verification token (dev only): {verification_token}"}


# ---------- POST /auth/verify-email ----------
@router.post("/verify-email", response_model=schemas.MessageResponse)
def verify_email(payload: schemas.EmailVerifyRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.verification_token == payload.token).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid or expired verification token")

    user.is_verified = True
    user.verification_token = None  # token is single-use
    db.commit()

    return {"message": "Email successfully verified"}


# ---------- POST /auth/login ----------
@router.post("/login", response_model=schemas.TokenResponse)
def login(payload: schemas.UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == payload.email).first()

    if not user or not security.verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password")

    if not user.is_verified:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Email not verified")

    access_token = security.create_access_token(data={"sub": str(user.id)})
    refresh_token = security.create_refresh_token(data={"sub": str(user.id)})

    # Store refresh token server-side so we can invalidate it on logout
    user.refresh_token = refresh_token
    db.commit()

    return {"access_token": access_token, "refresh_token": refresh_token, "token_type": "bearer"}


# ---------- POST /auth/refresh ----------
@router.post("/refresh", response_model=schemas.TokenResponse)
def refresh(payload: schemas.RefreshRequest, db: Session = Depends(get_db)):
    try:
        token_data = security.decode_token(payload.refresh_token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    if token_data.get("type") != "refresh":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token type")

    user_id = token_data.get("sub")
    user = db.query(models.User).filter(models.User.id == int(user_id)).first()

    if not user or user.refresh_token != payload.refresh_token:
        # Covers: user doesn't exist, OR token was already invalidated (e.g. by logout)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not recognized")

    new_access_token = security.create_access_token(data={"sub": str(user.id)})
    new_refresh_token = security.create_refresh_token(data={"sub": str(user.id)})

    # Rotate refresh token - old one becomes invalid
    user.refresh_token = new_refresh_token
    db.commit()

    return {"access_token": new_access_token, "refresh_token": new_refresh_token, "token_type": "bearer"}


# ---------- POST /auth/logout ----------
@router.post("/logout", response_model=schemas.MessageResponse)
def logout(payload: schemas.LogoutRequest, db: Session = Depends(get_db)):
    try:
        token_data = security.decode_token(payload.refresh_token)
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    user_id = token_data.get("sub")
    user = db.query(models.User).filter(models.User.id == int(user_id)).first()

    if not user or user.refresh_token != payload.refresh_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token not recognized")

    user.refresh_token = None  # invalidate it
    db.commit()

    return {"message": "Successfully logged out"}