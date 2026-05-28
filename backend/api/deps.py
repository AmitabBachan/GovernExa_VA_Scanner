from typing import Generator
from db.session import SessionLocal

def get_db() -> Generator:
    """
    Dependency to yield a SQLAlchemy session for a request and close it afterwards.
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
