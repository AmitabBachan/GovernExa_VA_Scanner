import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Default to the docker compose DB URL if not set
SQLALCHEMY_DATABASE_URL = os.getenv(
    "DATABASE_URL", 
    "postgresql://vulnscope:supersecretpassword@localhost:5432/vulnscope"
)

# Connect to the DB
engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
