from fastapi import FastAPI
from app.database import Base, engine, SQLALCHEMY_DATABASE_URL
from app import models
from app.auth import router as auth_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="JWT Auth Service",
    description="A JWT-based authentication API with register, email verification, login, refresh, and logout.",
    version="1.0.0",
)

app.include_router(auth_router)


@app.get("/")
def root():
    # Shows which database is actually being used (remove in production)
    db_type = "PostgreSQL" if "postgresql" in SQLALCHEMY_DATABASE_URL else "SQLite"
    return {"message": "JWT Auth Service is running", "database": db_type}