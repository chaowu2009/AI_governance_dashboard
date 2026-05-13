from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .models import RiskLevel, SelfReportedRiskLevel, UseCaseStatus


class UseCaseCreate(BaseModel):
    title: str = Field(min_length=5, max_length=200)
    business_unit: str = Field(min_length=2, max_length=120)
    owner_name: str = Field(min_length=2, max_length=120)
    owner_email: EmailStr
    system_name: str = Field(min_length=2, max_length=200)
    ai_vendor: str = Field(default="", max_length=120)
    model_name: str = Field(default="", max_length=120)
    deployment_type: str = Field(default="", max_length=60)
    api_or_ui: str = Field(default="", max_length=20)
    data_retained_by_vendor: bool = False
    contract_approved: bool = False
    purpose: str = Field(min_length=10, max_length=2000)
    data_categories: str = Field(default="none", max_length=400)
    uses_external_model: bool = False
    has_human_impact: bool = False
    automated_decision: bool = False
    federal_client: bool = False
    active: bool = False
    self_reported_risk_level: SelfReportedRiskLevel = SelfReportedRiskLevel.unknown

    @field_validator("self_reported_risk_level", mode="before")
    @classmethod
    def normalize_self_reported_risk_level(cls, value):
        if isinstance(value, str):
            normalized = value.strip().lower()
            aliases = {
                "unknown": SelfReportedRiskLevel.unknown,
                "low": SelfReportedRiskLevel.low,
                "medium": SelfReportedRiskLevel.medium,
                "high": SelfReportedRiskLevel.high,
                "don't know": SelfReportedRiskLevel.unknown,
            }
            if normalized in aliases:
                return aliases[normalized]
        return value


class UseCaseOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    business_unit: str
    owner_name: str
    owner_email: str
    system_name: str
    ai_vendor: str
    model_name: str
    deployment_type: str
    api_or_ui: str
    data_retained_by_vendor: bool
    contract_approved: bool
    purpose: str
    data_categories: str
    uses_external_model: bool
    has_human_impact: bool
    automated_decision: bool
    federal_client: bool
    active: bool
    self_reported_risk_level: SelfReportedRiskLevel
    risk_score: int
    risk_level: RiskLevel
    status: UseCaseStatus
    approver_name: str | None
    approval_notes: str | None
    approved_at: datetime | None
    created_at: datetime
    updated_at: datetime


class UseCaseApprovalIn(BaseModel):
    approver_name: str = Field(min_length=2, max_length=120)
    approval_notes: str = Field(min_length=3, max_length=1000)


class StatusUpdateOut(BaseModel):
    id: int
    status: UseCaseStatus
    message: str


class AuditEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    use_case_id: int
    action: str
    actor: str
    details: str
    created_at: datetime
