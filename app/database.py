from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

# SQLite database file - will be created automatically in the project folder
SQLALCHEMY_DATABASE_URL = "sqlite:///./auth_service.db"

# connect_args is needed only for SQLite (allows multiple threads to use the same connection)
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)

# Each instance of SessionLocal is a database session
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class our models will inherit from
Base = declarative_base()


# Dependency - gives each request its own DB session, closes it when done
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()