from datetime import datetime
from enum import Enum
from zoneinfo import ZoneInfo

from sqlalchemy import Boolean, DateTime, Enum as SqlEnum, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from .database import Base


US_EASTERN_TZ = ZoneInfo("America/New_York")


def utc_now() -> datetime:
    return datetime.now(US_EASTERN_TZ)


class RiskLevel(str, Enum):
    low = "Low"
    medium = "Medium"
    high = "High"
    regulated = "Regulated"


class UseCaseStatus(str, Enum):
    draft = "Draft"
    pending_review = "Pending Review"
    submitted = "Submitted"
    approved = "Approved"
    active = "Active"
    rejected = "Rejected"
    deleted = "Deleted"


class SelfReportedRiskLevel(str, Enum):
    unknown = "Don't know"
    low = "Low"
    medium = "Medium"
    high = "High"


class UseCase(Base):
    __tablename__ = "use_cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    business_unit: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    owner_name: Mapped[str] = mapped_column(String(120), nullable=False, index=True)
    owner_email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    system_name: Mapped[str] = mapped_column(String(200), nullable=False, index=True)
    ai_vendor: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    model_name: Mapped[str] = mapped_column(String(120), nullable=False, default="")
    deployment_type: Mapped[str] = mapped_column(String(60), nullable=False, default="")
    api_or_ui: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    data_retained_by_vendor: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    contract_approved: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    registration_payload: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    purpose: Mapped[str] = mapped_column(Text, nullable=False)
    data_categories: Mapped[str] = mapped_column(String(400), nullable=False, default="none")
    uses_external_model: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    has_human_impact: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    automated_decision: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    federal_client: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    self_reported_risk_level: Mapped[SelfReportedRiskLevel] = mapped_column(
        SqlEnum(SelfReportedRiskLevel), nullable=False, default=SelfReportedRiskLevel.unknown
    )

    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    risk_level: Mapped[RiskLevel] = mapped_column(SqlEnum(RiskLevel), nullable=False, default=RiskLevel.low)
    status: Mapped[UseCaseStatus] = mapped_column(
        SqlEnum(UseCaseStatus), nullable=False, default=UseCaseStatus.submitted
    )

    approver_name: Mapped[str | None] = mapped_column(String(120), nullable=True)
    approval_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now, onupdate=utc_now
    )


class AuditEvent(Base):
    __tablename__ = "audit_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    use_case_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    actor: Mapped[str] = mapped_column(String(120), nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=utc_now)
