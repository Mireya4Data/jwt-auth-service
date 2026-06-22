from fastapi import FastAPI
from app.database import Base, engine
from app import models
from app.auth import router as auth_router

# Creates all tables defined in models.py (if they don't already exist)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="JWT Auth Service",
    description="A JWT-based authentication API with register, email verification, login, refresh, and logout.",
    version="1.0.0",
)

app.include_router(auth_router)


@app.get("/")
def root():
    return {"message": "JWT Auth Service is running"}