import os

from sqlalchemy import create_engine
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./governance.db")


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def ensure_schema_compatibility() -> None:
    if not DATABASE_URL.startswith("sqlite"):
        return

    with engine.begin() as conn:
        existing_columns = {
            row[1] for row in conn.execute(text("PRAGMA table_info(use_cases)"))
        }
        if "self_reported_risk_level" not in existing_columns:
            conn.execute(
                text(
                    "ALTER TABLE use_cases "
                    "ADD COLUMN self_reported_risk_level VARCHAR(20) NOT NULL DEFAULT 'unknown'"
                )
            )
        if "active" not in existing_columns:
            conn.execute(
                text(
                    "ALTER TABLE use_cases "
                    "ADD COLUMN active BOOLEAN NOT NULL DEFAULT 0"
                )
            )
        if "ai_vendor" not in existing_columns:
            conn.execute(
                text(
                    "ALTER TABLE use_cases "
                    "ADD COLUMN ai_vendor VARCHAR(120) NOT NULL DEFAULT ''"
                )
            )
        if "model_name" not in existing_columns:
            conn.execute(
                text(
                    "ALTER TABLE use_cases "
                    "ADD COLUMN model_name VARCHAR(120) NOT NULL DEFAULT ''"
                )
            )
        if "deployment_type" not in existing_columns:
            conn.execute(
                text(
                    "ALTER TABLE use_cases "
                    "ADD COLUMN deployment_type VARCHAR(60) NOT NULL DEFAULT ''"
                )
            )
        if "api_or_ui" not in existing_columns:
            conn.execute(
                text(
                    "ALTER TABLE use_cases "
                    "ADD COLUMN api_or_ui VARCHAR(20) NOT NULL DEFAULT ''"
                )
            )
        if "data_retained_by_vendor" not in existing_columns:
            conn.execute(
                text(
                    "ALTER TABLE use_cases "
                    "ADD COLUMN data_retained_by_vendor BOOLEAN NOT NULL DEFAULT 0"
                )
            )
        if "contract_approved" not in existing_columns:
            conn.execute(
                text(
                    "ALTER TABLE use_cases "
                    "ADD COLUMN contract_approved BOOLEAN NOT NULL DEFAULT 0"
                )
            )
        if "registration_payload" not in existing_columns:
            conn.execute(
                text(
                    "ALTER TABLE use_cases "
                    "ADD COLUMN registration_payload TEXT NOT NULL DEFAULT '{}'"
                )
            )


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
