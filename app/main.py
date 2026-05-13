import hashlib
import hmac
import json
import os
import random
import secrets
import sys
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.database import Base, SessionLocal, engine, ensure_schema_compatibility, get_db
from app.models import AuditEvent, RiskLevel, SelfReportedRiskLevel, UseCase, UseCaseStatus, utc_now
from app.risk import classify_risk
from app.schemas import AuditEventOut, StatusUpdateOut, UseCaseApprovalIn, UseCaseCreate, UseCaseOut

# ---------------------------------------------------------------------------
# Security helpers
# ---------------------------------------------------------------------------

# Secret for HMAC-signing math-challenge answers. Set CAPTCHA_SECRET in env
# for production; falls back to a per-process random secret in development.
_CAPTCHA_SECRET: bytes = os.getenv("CAPTCHA_SECRET", secrets.token_hex(32)).encode()

# Governance reviewer token – required on moderation endpoints.
# Set GOVERNANCE_TOKEN in env. No default so the endpoint rejects all requests
# unless the operator explicitly configures a token.
_GOVERNANCE_TOKEN: str = os.getenv("GOVERNANCE_TOKEN", "")


def _make_captcha_challenge() -> dict[str, str]:
    """Return a new math challenge with a signed token."""
    a = random.randint(1, 12)
    b = random.randint(1, 12)
    expected = str(a + b)
    token = hmac.new(_CAPTCHA_SECRET, expected.encode(), hashlib.sha256).hexdigest()
    return {"question": f"What is {a} + {b}?", "token": token}


def _verify_captcha(answer: str, token: str) -> bool:
    """Return True when the answer matches the signed token."""
    expected_token = hmac.new(_CAPTCHA_SECRET, answer.strip().encode(), hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_token, token)


def _require_governance_token(request: Request) -> None:
    """Raise 403 when caller does not supply the governance reviewer token."""
    if not _GOVERNANCE_TOKEN:
        raise HTTPException(status_code=503, detail="Governance token not configured on this server")
    supplied = request.headers.get("X-Governance-Token", "")
    if not hmac.compare_digest(supplied, _GOVERNANCE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid or missing governance reviewer token")


def _require_governance_form_token(token: str) -> None:
    """Raise 403 when a moderation form does not include the governance token."""
    if not _GOVERNANCE_TOKEN:
        raise HTTPException(status_code=503, detail="Governance token not configured on this server")
    if not hmac.compare_digest((token or "").strip(), _GOVERNANCE_TOKEN):
        raise HTTPException(status_code=403, detail="Invalid or missing governance reviewer token")

@asynccontextmanager
async def lifespan(_: FastAPI):
    _seed_sample_use_cases()
    yield


app = FastAPI(title="AI Governance MVP", version="0.1.0", lifespan=lifespan)
templates = Jinja2Templates(directory="app/templates")

DATA_CATEGORY_OPTIONS = [
    "Public",
    "Internal",
    "Client Confidential",
    "Source Code",
    "PII",
    "PHI",
    "Financial",
    "Export-Controlled",
    "Federal Data",
    "Regulated Research Data",
]

DEPLOYMENT_TYPE_OPTIONS = ["SaaS", "Azure Gov", "Self-hosted"]
API_OR_UI_OPTIONS = ["API", "UI"]

AI_FUNCTION_TYPES = [
    "Text generation",
    "Code generation",
    "Search / RAG",
    "Summarization",
    "Classification",
    "Prediction",
    "Recommendation",
    "OCR / document extraction",
    "Translation",
    "Computer vision",
    "Speech / audio",
    "Agent / workflow automation",
    "Other",
]

BUSINESS_CRITICALITY_LEVELS = ["Low", "Moderate", "High", "Mission critical"]
HUMAN_REVIEW_OPTIONS = ["Always", "Sometimes", "No", "Not applicable"]
COMMON_CONNECTED_SYSTEMS = [
    "Jira",
    "GitHub",
    "SharePoint",
    "Google Drive",
    "AWS S3",
    "SQL Database",
    "Email",
    "CRM",
    "EHR / clinical system",
    "Federal client system",
    "None",
    "Other",
]
SECURITY_REVIEW_STATUS_OPTIONS = [
    "Not started",
    "In review",
    "Approved",
    "Approved with conditions",
    "Rejected",
    "Exception granted",
]
AUDIT_RETENTION_OPTIONS = ["None", "30 days", "90 days", "1 year", "Custom"]
APPROVAL_STATUS_OPTIONS = [
    "Draft",
    "Pending review",
    "Approved",
    "Approved with restrictions",
    "Rejected",
    "Retired",
]

SAMPLE_USE_CASE_DEFINITIONS = [
    {
        "title": "Knowledge Base Summarizer",
        "business_unit": "Operations",
        "owner_name": "Avery Chen",
        "owner_email": "avery.chen@example.com",
        "system_name": "KB Copilot",
        "ai_vendor": "OpenAI",
        "model_name": "gpt-4.1-mini",
        "deployment_type": "SaaS",
        "api_or_ui": "UI",
        "data_retained_by_vendor": False,
        "contract_approved": True,
        "purpose": "Summarizes internal knowledge articles to speed up support response drafting.",
        "data_categories": "Internal",
        "uses_external_model": True,
        "has_human_impact": False,
        "automated_decision": False,
        "federal_client": False,
        "active": True,
        "self_reported_risk_level": SelfReportedRiskLevel.low,
        "initial_status": UseCaseStatus.active,
    },
    {
        "title": "Benefits Eligibility Recommender",
        "business_unit": "People Operations",
        "owner_name": "Morgan Patel",
        "owner_email": "morgan.patel@example.com",
        "system_name": "Eligibility Advisor",
        "ai_vendor": "Anthropic",
        "model_name": "claude-3.5-sonnet",
        "deployment_type": "SaaS",
        "api_or_ui": "API",
        "data_retained_by_vendor": True,
        "contract_approved": False,
        "purpose": "Recommends likely benefits eligibility outcomes before human HR review.",
        "data_categories": "PII, Financial",
        "uses_external_model": True,
        "has_human_impact": True,
        "automated_decision": True,
        "federal_client": False,
        "active": False,
        "self_reported_risk_level": SelfReportedRiskLevel.high,
        "initial_status": UseCaseStatus.submitted,
    },
    {
        "title": "Contract Risk Classifier Pilot",
        "business_unit": "Legal",
        "owner_name": "Jordan Rivera",
        "owner_email": "jordan.rivera@example.com",
        "system_name": "Clause Insight Pilot",
        "ai_vendor": "OpenAI",
        "model_name": "gpt-4.1",
        "deployment_type": "Azure Gov",
        "api_or_ui": "UI",
        "data_retained_by_vendor": False,
        "contract_approved": True,
        "purpose": "Flags risky clauses in draft contracts for attorney review.",
        "data_categories": "Client Confidential, Internal",
        "uses_external_model": True,
        "has_human_impact": True,
        "automated_decision": False,
        "federal_client": True,
        "active": False,
        "self_reported_risk_level": SelfReportedRiskLevel.medium,
        "initial_status": UseCaseStatus.pending_review,
    },
]

Base.metadata.create_all(bind=engine)
ensure_schema_compatibility()


def _emit_audit_event(db: Session, use_case_id: int, action: str, actor: str, details: str) -> None:
    event = AuditEvent(
        use_case_id=use_case_id,
        action=action,
        actor=actor,
        details=details,
    )
    db.add(event)


def _render_template(request: Request, name: str, context: dict | None = None, status_code: int = 200):
    template_context: dict[str, object] = {}
    if context:
        template_context.update(context)
    return templates.TemplateResponse(request=request, name=name, context=template_context, status_code=status_code)


def _normalize_data_categories(data_categories: list[str]) -> str:
    cleaned = [item.strip() for item in data_categories if item and item.strip()]
    if not cleaned:
        return "none"

    seen: set[str] = set()
    ordered: list[str] = []

    for option in DATA_CATEGORY_OPTIONS:
        if option in cleaned and option not in seen:
            ordered.append(option)
            seen.add(option)

    for item in cleaned:
        if item not in seen:
            ordered.append(item)
            seen.add(item)

    return ", ".join(ordered)


def _normalize_list_values(values: list[str]) -> list[str]:
    cleaned = [item.strip() for item in values if item and item.strip()]
    seen: set[str] = set()
    ordered: list[str] = []
    for item in cleaned:
        if item not in seen:
            ordered.append(item)
            seen.add(item)
    return ordered


def _parse_bool_form_value(value: str | None) -> bool:
    if value is None:
        return False
    return value.strip().lower() in {"true", "1", "yes", "on"}


def _parse_data_categories(data_categories: str) -> set[str]:
    if not data_categories or data_categories.strip().lower() == "none":
        return set()
    return {item.strip() for item in data_categories.split(",") if item.strip()}


def _format_registration_value(value: object) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else "None"
    if value is None:
        return ""
    return str(value)


def _build_registration_view(use_case: UseCase) -> dict[str, list[tuple[str, str]]]:
    default_payload = {
        "use_case_title": use_case.title,
        "ai_system_name": use_case.system_name,
        "business_unit": use_case.business_unit,
        "owner_name": use_case.owner_name,
        "owner_email": use_case.owner_email,
        "business_purpose": use_case.purpose,
        "ai_function_type": [],
        "data_categories": [] if use_case.data_categories.lower() == "none" else [
            item.strip() for item in use_case.data_categories.split(",") if item.strip()
        ],
        "uses_external_model_provider": use_case.uses_external_model,
        "ai_vendor_name": use_case.ai_vendor,
        "model_name": use_case.model_name,
        "deployment_type": use_case.deployment_type,
        "api_or_ui_usage": use_case.api_or_ui,
        "data_retention_by_vendor": use_case.data_retained_by_vendor,
        "contract_approved": use_case.contract_approved,
        "risk_level": use_case.self_reported_risk_level.value,
        "business_criticality": "",
        "human_impacting_output": use_case.has_human_impact,
        "automated_decision_making": use_case.automated_decision,
        "human_review_required": "",
        "human_override_available": False,
        "federal_client_context": use_case.federal_client,
        "connected_systems": [],
        "production_access": use_case.active,
        "client_facing": False,
        "writes_to_systems": False,
        "reads_from_sensitive_systems": False,
        "security_review_required": False,
        "security_review_status": "",
        "logging_enabled": False,
        "audit_trail_retention": "",
        "access_control_defined": False,
        "data_encryption_required": False,
        "approval_status": use_case.status.value,
        "review_owner": use_case.approver_name or "",
        "approval_date": "",
        "next_review_date": "",
        "expiration_date": "",
        "policy_exception_needed": False,
        "notes": use_case.approval_notes or "",
    }

    if use_case.registration_payload:
        try:
            parsed_payload = json.loads(use_case.registration_payload)
            if isinstance(parsed_payload, dict):
                default_payload.update(parsed_payload)
        except json.JSONDecodeError:
            pass

    return {
        "Basic Information": [
            ("use_case_title", _format_registration_value(default_payload.get("use_case_title"))),
            ("ai_system_name", _format_registration_value(default_payload.get("ai_system_name"))),
            ("business_unit", _format_registration_value(default_payload.get("business_unit"))),
            ("owner_name", _format_registration_value(default_payload.get("owner_name"))),
            ("owner_email", _format_registration_value(default_payload.get("owner_email"))),
            ("business_purpose", _format_registration_value(default_payload.get("business_purpose"))),
        ],
        "AI Function / Use Type": [
            ("ai_function_type", _format_registration_value(default_payload.get("ai_function_type"))),
        ],
        "Data Classification": [
            ("data_categories", _format_registration_value(default_payload.get("data_categories"))),
        ],
        "Model / Vendor Information": [
            ("uses_external_model_provider", _format_registration_value(default_payload.get("uses_external_model_provider"))),
            ("ai_vendor_name", _format_registration_value(default_payload.get("ai_vendor_name"))),
            ("model_name", _format_registration_value(default_payload.get("model_name"))),
            ("deployment_type", _format_registration_value(default_payload.get("deployment_type"))),
            ("api_or_ui_usage", _format_registration_value(default_payload.get("api_or_ui_usage"))),
            ("data_retention_by_vendor", _format_registration_value(default_payload.get("data_retention_by_vendor"))),
            ("contract_approved", _format_registration_value(default_payload.get("contract_approved"))),
        ],
        "Risk and Impact": [
            ("risk_level", _format_registration_value(default_payload.get("risk_level"))),
            ("business_criticality", _format_registration_value(default_payload.get("business_criticality"))),
            ("human_impacting_output", _format_registration_value(default_payload.get("human_impacting_output"))),
            ("automated_decision_making", _format_registration_value(default_payload.get("automated_decision_making"))),
            ("human_review_required", _format_registration_value(default_payload.get("human_review_required"))),
            ("human_override_available", _format_registration_value(default_payload.get("human_override_available"))),
            ("federal_client_context", _format_registration_value(default_payload.get("federal_client_context"))),
        ],
        "System Integration": [
            ("connected_systems", _format_registration_value(default_payload.get("connected_systems"))),
            ("production_access", _format_registration_value(default_payload.get("production_access"))),
            ("client_facing", _format_registration_value(default_payload.get("client_facing"))),
            ("writes_to_systems", _format_registration_value(default_payload.get("writes_to_systems"))),
            ("reads_from_sensitive_systems", _format_registration_value(default_payload.get("reads_from_sensitive_systems"))),
        ],
        "Security and Audit": [
            ("security_review_required", _format_registration_value(default_payload.get("security_review_required"))),
            ("security_review_status", _format_registration_value(default_payload.get("security_review_status"))),
            ("logging_enabled", _format_registration_value(default_payload.get("logging_enabled"))),
            ("audit_trail_retention", _format_registration_value(default_payload.get("audit_trail_retention"))),
            ("access_control_defined", _format_registration_value(default_payload.get("access_control_defined"))),
            ("data_encryption_required", _format_registration_value(default_payload.get("data_encryption_required"))),
        ],
        "Governance Workflow": [
            ("approval_status", _format_registration_value(default_payload.get("approval_status"))),
            ("review_owner", _format_registration_value(default_payload.get("review_owner"))),
            ("approval_date", _format_registration_value(default_payload.get("approval_date"))),
            ("next_review_date", _format_registration_value(default_payload.get("next_review_date"))),
            ("expiration_date", _format_registration_value(default_payload.get("expiration_date"))),
            ("policy_exception_needed", _format_registration_value(default_payload.get("policy_exception_needed"))),
            ("notes", _format_registration_value(default_payload.get("notes"))),
        ],
    }


def _use_case_snapshot(use_case: UseCase) -> dict[str, object]:
    return {
        "title": use_case.title,
        "business_unit": use_case.business_unit,
        "owner_name": use_case.owner_name,
        "owner_email": use_case.owner_email,
        "system_name": use_case.system_name,
        "ai_vendor": use_case.ai_vendor,
        "model_name": use_case.model_name,
        "deployment_type": use_case.deployment_type,
        "api_or_ui": use_case.api_or_ui,
        "data_retained_by_vendor": use_case.data_retained_by_vendor,
        "contract_approved": use_case.contract_approved,
        "purpose": use_case.purpose,
        "data_categories": use_case.data_categories,
        "uses_external_model": use_case.uses_external_model,
        "has_human_impact": use_case.has_human_impact,
        "automated_decision": use_case.automated_decision,
        "federal_client": use_case.federal_client,
        "active": use_case.active,
        "self_reported_risk_level": use_case.self_reported_risk_level.value,
        "risk_score": use_case.risk_score,
        "risk_level": use_case.risk_level.value,
        "status": use_case.status.value,
    }


def _display_value(value: object) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if value is None:
        return "None"
    return str(value)


def _summarize_changes(before: dict[str, object], after: dict[str, object]) -> str:
    labels = {
        "title": "Title",
        "business_unit": "Business unit",
        "owner_name": "Owner name",
        "owner_email": "Owner email",
        "system_name": "System name",
        "ai_vendor": "AI vendor",
        "model_name": "Model name",
        "deployment_type": "Deployment type",
        "api_or_ui": "API or UI",
        "data_retained_by_vendor": "Data retained by vendor",
        "contract_approved": "Contract approved",
        "purpose": "Purpose",
        "data_categories": "Data categories",
        "uses_external_model": "External model",
        "has_human_impact": "Human impact",
        "automated_decision": "Automated decision",
        "federal_client": "Federal client",
        "active": "Active",
        "self_reported_risk_level": "Self-reported risk level",
        "risk_score": "Risk score",
        "risk_level": "Risk level",
        "status": "Status",
    }
    changes = []
    for field, label in labels.items():
        if before.get(field) != after.get(field):
            changes.append(f"{label}: {_display_value(before.get(field))} -> {_display_value(after.get(field))}")
    return "; ".join(changes) if changes else "No field changes recorded"


def _build_use_case_payload_from_form(
    title: str,
    business_unit: str,
    owner_name: str,
    owner_email: str,
    system_name: str,
    ai_vendor: str,
    model_name: str,
    deployment_type: str,
    api_or_ui: str,
    data_retained_by_vendor: bool,
    contract_approved: bool,
    purpose: str,
    data_categories: str,
    uses_external_model: bool,
    has_human_impact: bool,
    automated_decision: bool,
    federal_client: bool,
    active: bool,
    self_reported_risk_level: str,
) -> UseCaseCreate:
    return UseCaseCreate(
        title=title,
        business_unit=business_unit,
        owner_name=owner_name,
        owner_email=owner_email,
        system_name=system_name,
        ai_vendor=ai_vendor,
        model_name=model_name,
        deployment_type=deployment_type,
        api_or_ui=api_or_ui,
        data_retained_by_vendor=data_retained_by_vendor,
        contract_approved=contract_approved,
        purpose=purpose,
        data_categories=data_categories,
        uses_external_model=uses_external_model,
        has_human_impact=has_human_impact,
        automated_decision=automated_decision,
        federal_client=federal_client,
        active=active,
        self_reported_risk_level=self_reported_risk_level,
    )


def _apply_use_case_payload(use_case: UseCase, payload: UseCaseCreate) -> None:
    risk = classify_risk(
        data_categories=payload.data_categories,
        uses_external_model=payload.uses_external_model,
        has_human_impact=payload.has_human_impact,
        automated_decision=payload.automated_decision,
        federal_client=payload.federal_client,
    )

    use_case.title = payload.title
    use_case.business_unit = payload.business_unit
    use_case.owner_name = payload.owner_name
    use_case.owner_email = payload.owner_email
    use_case.system_name = payload.system_name
    use_case.ai_vendor = payload.ai_vendor
    use_case.model_name = payload.model_name
    use_case.deployment_type = payload.deployment_type
    use_case.api_or_ui = payload.api_or_ui
    use_case.data_retained_by_vendor = payload.data_retained_by_vendor
    use_case.contract_approved = payload.contract_approved
    use_case.purpose = payload.purpose
    use_case.data_categories = payload.data_categories
    use_case.uses_external_model = payload.uses_external_model
    use_case.has_human_impact = payload.has_human_impact
    use_case.automated_decision = payload.automated_decision
    use_case.federal_client = payload.federal_client
    use_case.active = payload.active
    use_case.self_reported_risk_level = payload.self_reported_risk_level
    use_case.risk_score = risk["score"]
    use_case.risk_level = risk["level"]


def _get_use_case_or_404(db: Session, use_case_id: int) -> UseCase:
    use_case = db.get(UseCase, use_case_id)
    if not use_case:
        raise HTTPException(status_code=404, detail="Use case not found")
    return use_case


def _sort_use_cases(use_cases: list[UseCase], sort_by: str) -> list[UseCase]:
    risk_priority = {
        RiskLevel.regulated: 4,
        RiskLevel.high: 3,
        RiskLevel.medium: 2,
        RiskLevel.low: 1,
    }

    if sort_by == "updated_at":
        return sorted(use_cases, key=lambda item: item.updated_at, reverse=True)
    if sort_by == "created_at":
        return sorted(use_cases, key=lambda item: item.created_at, reverse=True)
    if sort_by == "risk_level":
        return sorted(use_cases, key=lambda item: risk_priority.get(item.risk_level, 0), reverse=True)
    if sort_by == "owner_name":
        return sorted(use_cases, key=lambda item: item.owner_name.lower())
    if sort_by == "data_categories":
        return sorted(use_cases, key=lambda item: item.data_categories.lower())
    if sort_by == "active":
        return sorted(use_cases, key=lambda item: (item.active, item.updated_at), reverse=True)

    return sorted(use_cases, key=lambda item: item.updated_at, reverse=True)


def _get_use_case_history_items(db: Session, sort_by: str) -> list[dict[str, object]]:
    use_cases = list(db.scalars(select(UseCase)).all())
    use_cases = _sort_use_cases(use_cases, sort_by)
    use_case_ids = [use_case.id for use_case in use_cases]
    events_by_use_case_id: dict[int, list[AuditEvent]] = defaultdict(list)

    if use_case_ids:
        events = list(
            db.scalars(
                select(AuditEvent)
                .where(AuditEvent.use_case_id.in_(use_case_ids))
                .order_by(AuditEvent.created_at.desc())
            ).all()
        )
        for event in events:
            events_by_use_case_id[event.use_case_id].append(event)

    return [
        {
            "use_case": use_case,
            "events": events_by_use_case_id.get(use_case.id, []),
            "registration_view": _build_registration_view(use_case),
        }
        for use_case in use_cases
    ]


def _seed_sample_use_cases() -> None:
    with SessionLocal() as db:
        existing_use_case = db.scalar(select(UseCase.id).limit(1))
        if existing_use_case:
            return

        for item in SAMPLE_USE_CASE_DEFINITIONS:
            payload = UseCaseCreate(
                title=item["title"],
                business_unit=item["business_unit"],
                owner_name=item["owner_name"],
                owner_email=item["owner_email"],
                system_name=item["system_name"],
                ai_vendor=item["ai_vendor"],
                model_name=item["model_name"],
                deployment_type=item["deployment_type"],
                api_or_ui=item["api_or_ui"],
                data_retained_by_vendor=item["data_retained_by_vendor"],
                contract_approved=item["contract_approved"],
                purpose=item["purpose"],
                data_categories=item["data_categories"],
                uses_external_model=item["uses_external_model"],
                has_human_impact=item["has_human_impact"],
                automated_decision=item["automated_decision"],
                federal_client=item["federal_client"],
                active=item["active"],
                self_reported_risk_level=item["self_reported_risk_level"],
            )

            use_case = UseCase(status=item["initial_status"])
            _apply_use_case_payload(use_case, payload)
            use_case.registration_payload = json.dumps(
                {
                    "use_case_title": payload.title,
                    "ai_system_name": payload.system_name,
                    "business_unit": payload.business_unit,
                    "owner_name": payload.owner_name,
                    "owner_email": payload.owner_email,
                    "business_purpose": payload.purpose,
                    "data_categories": [category.strip() for category in payload.data_categories.split(",")],
                    "risk_level": payload.self_reported_risk_level.value,
                    "approval_status": use_case.status.value,
                    "notes": "Automatically seeded sample record.",
                }
            )

            db.add(use_case)
            db.flush()
            _emit_audit_event(
                db,
                use_case.id,
                action="use_case_seeded",
                actor="system",
                details=f"Seeded sample use case: {use_case.title}",
            )

        db.commit()
@app.get("/")
def home():
    return RedirectResponse(url="/register", status_code=303)


@app.get("/ai-policy")
def ai_policy_page(request: Request):
    return _render_template(request, "ai_policy.html")


@app.get("/register")
def register_page(request: Request):
    return _render_template(
        request,
        "register.html",
        {
            "data_category_options": DATA_CATEGORY_OPTIONS,
            "ai_function_types": AI_FUNCTION_TYPES,
            "deployment_type_options": DEPLOYMENT_TYPE_OPTIONS,
            "api_or_ui_options": API_OR_UI_OPTIONS,
            "business_criticality_levels": BUSINESS_CRITICALITY_LEVELS,
            "human_review_options": HUMAN_REVIEW_OPTIONS,
            "common_connected_systems": COMMON_CONNECTED_SYSTEMS,
            "security_review_status_options": SECURITY_REVIEW_STATUS_OPTIONS,
            "audit_retention_options": AUDIT_RETENTION_OPTIONS,
            "approval_status_options": APPROVAL_STATUS_OPTIONS,
            "captcha": _make_captcha_challenge(),
        },
    )


@app.get("/registered-use-cases")
def registered_use_cases_page(
    request: Request,
    sort_by: str = Query(default="updated_at"),
    db: Session = Depends(get_db),
):
    sort_options = {
        "updated_at": "updated_at (last updated)",
        "created_at": "created_at (last added)",
        "risk_level": "risk_level",
        "owner_name": "owner_name",
        "data_categories": "data_categories",
        "active": "active",
    }
    selected_sort = sort_by if sort_by in sort_options else "updated_at"
    all_use_cases = list(db.scalars(select(UseCase)).all())
    summary_items = _sort_use_cases(all_use_cases, "updated_at")

    return _render_template(
        request,
        "registered_use_cases.html",
        {
            "items": _get_use_case_history_items(db, selected_sort),
            "summary_items": summary_items,
            "sort_options": sort_options,
            "selected_sort": selected_sort,
        },
    )


@app.post("/use-cases/{use_case_id}/approve-pending")
def approve_pending_from_page(
    use_case_id: int,
    reviewer: str = Form(default="Governance Reviewer"),
    governance_token: str = Form(default=""),
    sort_by: str = Form(default="updated_at"),
    db: Session = Depends(get_db),
):
    """Approve a pending item from the web page and move it into Submitted."""
    _require_governance_form_token(governance_token)
    use_case = _get_use_case_or_404(db, use_case_id)

    if use_case.status != UseCaseStatus.pending_review:
        raise HTTPException(
            status_code=400,
            detail=f"Use case is not in Pending Review (current status: {use_case.status.value})",
        )

    use_case.status = UseCaseStatus.submitted
    _emit_audit_event(
        db,
        use_case.id,
        action="review_started",
        actor=reviewer.strip() or "Governance Reviewer",
        details="Governance reviewer approved pending submission from the web page",
    )
    db.commit()

    return RedirectResponse(url=f"/registered-use-cases?sort_by={sort_by}", status_code=303)


@app.post("/submit")
async def submit_from_form(request: Request, db: Session = Depends(get_db)):
    form_data = await request.form()

    data_categories_selected = _normalize_list_values(list(form_data.getlist("data_categories")))
    ai_function_type_selected = _normalize_list_values(list(form_data.getlist("ai_function_type")))
    connected_systems_selected = _normalize_list_values(list(form_data.getlist("connected_systems")))

    use_case_title = str(form_data.get("use_case_title", "")).strip()
    business_unit = str(form_data.get("business_unit", "")).strip()
    owner_name = str(form_data.get("owner_name", "")).strip()
    owner_email = str(form_data.get("owner_email", "")).strip()
    ai_system_name = str(form_data.get("ai_system_name", "")).strip()
    business_purpose = str(form_data.get("business_purpose", "")).strip()
    ai_vendor_name = str(form_data.get("ai_vendor_name", "")).strip()
    model_name = str(form_data.get("model_name", "")).strip()
    deployment_type = str(form_data.get("deployment_type", "")).strip()
    api_or_ui_usage = str(form_data.get("api_or_ui_usage", "")).strip()
    risk_level = str(form_data.get("risk_level", "Don't know")).strip()

    uses_external_model_provider = _parse_bool_form_value(form_data.get("uses_external_model_provider"))
    data_retention_by_vendor = _parse_bool_form_value(form_data.get("data_retention_by_vendor"))
    contract_approved = _parse_bool_form_value(form_data.get("contract_approved"))
    human_impacting_output = _parse_bool_form_value(form_data.get("human_impacting_output"))
    automated_decision_making = _parse_bool_form_value(form_data.get("automated_decision_making"))
    federal_client_context = _parse_bool_form_value(form_data.get("federal_client_context"))
    production_access = _parse_bool_form_value(form_data.get("production_access"))
    active = production_access

    normalized_data_categories = _normalize_data_categories(data_categories_selected)

    registration_payload = {
        "use_case_title": use_case_title,
        "ai_system_name": ai_system_name,
        "business_unit": business_unit,
        "owner_name": owner_name,
        "owner_email": owner_email,
        "business_purpose": business_purpose,
        "ai_function_type": ai_function_type_selected,
        "data_categories": data_categories_selected,
        "uses_external_model_provider": uses_external_model_provider,
        "ai_vendor_name": ai_vendor_name,
        "model_name": model_name,
        "deployment_type": deployment_type,
        "api_or_ui_usage": api_or_ui_usage,
        "data_retention_by_vendor": data_retention_by_vendor,
        "contract_approved": contract_approved,
        "risk_level": risk_level,
        "business_criticality": str(form_data.get("business_criticality", "Low")).strip(),
        "human_impacting_output": human_impacting_output,
        "automated_decision_making": automated_decision_making,
        "human_review_required": str(form_data.get("human_review_required", "Not applicable")).strip(),
        "human_override_available": _parse_bool_form_value(form_data.get("human_override_available")),
        "federal_client_context": federal_client_context,
        "connected_systems": connected_systems_selected,
        "production_access": production_access,
        "client_facing": _parse_bool_form_value(form_data.get("client_facing")),
        "writes_to_systems": _parse_bool_form_value(form_data.get("writes_to_systems")),
        "reads_from_sensitive_systems": _parse_bool_form_value(form_data.get("reads_from_sensitive_systems")),
        "security_review_required": _parse_bool_form_value(form_data.get("security_review_required")),
        "security_review_status": str(form_data.get("security_review_status", "Not started")).strip(),
        "logging_enabled": _parse_bool_form_value(form_data.get("logging_enabled")),
        "audit_trail_retention": str(form_data.get("audit_trail_retention", "90 days")).strip(),
        "access_control_defined": _parse_bool_form_value(form_data.get("access_control_defined")),
        "data_encryption_required": _parse_bool_form_value(form_data.get("data_encryption_required")),
        "approval_status": str(form_data.get("approval_status", "Draft")).strip(),
        "review_owner": str(form_data.get("review_owner", "")).strip(),
        "approval_date": str(form_data.get("approval_date", "")).strip(),
        "next_review_date": str(form_data.get("next_review_date", "")).strip(),
        "expiration_date": str(form_data.get("expiration_date", "")).strip(),
        "policy_exception_needed": _parse_bool_form_value(form_data.get("policy_exception_needed")),
        "notes": str(form_data.get("notes", "")).strip(),
    }

    # --- Honeypot check: bots fill hidden fields humans never see ---
    honeypot = str(form_data.get("website", "")).strip()
    if honeypot:
        # Silent redirect – don't reveal the rejection to bots
        return RedirectResponse(url="/registered-use-cases", status_code=303)

    # --- Math CAPTCHA verification ---
    captcha_answer = str(form_data.get("captcha_answer", "")).strip()
    captcha_token = str(form_data.get("captcha_token", "")).strip()
    if not captcha_answer or not _verify_captcha(captcha_answer, captcha_token):
        captcha = _make_captcha_challenge()
        return _render_template(
            request,
            "register.html",
            {
                "data_category_options": DATA_CATEGORY_OPTIONS,
                "ai_function_types": AI_FUNCTION_TYPES,
                "deployment_type_options": DEPLOYMENT_TYPE_OPTIONS,
                "api_or_ui_options": API_OR_UI_OPTIONS,
                "business_criticality_levels": BUSINESS_CRITICALITY_LEVELS,
                "human_review_options": HUMAN_REVIEW_OPTIONS,
                "common_connected_systems": COMMON_CONNECTED_SYSTEMS,
                "security_review_status_options": SECURITY_REVIEW_STATUS_OPTIONS,
                "audit_retention_options": AUDIT_RETENTION_OPTIONS,
                "approval_status_options": APPROVAL_STATUS_OPTIONS,
                "captcha": captcha,
                "captcha_error": "Incorrect answer — please try the new question below.",
            },
            status_code=422,
        )

    payload = _build_use_case_payload_from_form(
        use_case_title,
        business_unit,
        owner_name,
        owner_email,
        ai_system_name,
        ai_vendor_name,
        model_name,
        deployment_type,
        api_or_ui_usage,
        data_retention_by_vendor,
        contract_approved,
        business_purpose,
        normalized_data_categories,
        uses_external_model_provider,
        human_impacting_output,
        automated_decision_making,
        federal_client_context,
        active,
        risk_level,
    )
    use_case = _create_use_case(payload, db, actor=payload.owner_email, initial_status=UseCaseStatus.pending_review)
    use_case.registration_payload = json.dumps(registration_payload)
    db.commit()
    return RedirectResponse(url="/registered-use-cases", status_code=303)


@app.post("/use-cases", response_model=UseCaseOut, status_code=201)
def create_use_case(payload: UseCaseCreate, db: Session = Depends(get_db)):
    return _create_use_case(payload, db, actor=payload.owner_email)


def _create_use_case(
    payload: UseCaseCreate,
    db: Session,
    actor: str,
    initial_status: UseCaseStatus = UseCaseStatus.submitted,
) -> UseCase:
    use_case = UseCase(
        status=initial_status,
    )
    _apply_use_case_payload(use_case, payload)
    db.add(use_case)
    db.flush()

    _emit_audit_event(
        db,
        use_case.id,
        action="use_case_submitted",
        actor=actor,
        details=f"Use case submitted with risk={use_case.risk_level.value} score={use_case.risk_score}",
    )

    db.commit()
    db.refresh(use_case)
    return use_case


@app.put("/use-cases/{use_case_id}", response_model=UseCaseOut)
def update_use_case(
    use_case_id: int,
    payload: UseCaseCreate,
    db: Session = Depends(get_db),
    actor: str = Query(default="system"),
):
    use_case = _get_use_case_or_404(db, use_case_id)

    before = _use_case_snapshot(use_case)
    _apply_use_case_payload(use_case, payload)
    use_case.status = UseCaseStatus.submitted
    use_case.approver_name = None
    use_case.approval_notes = None
    use_case.approved_at = None
    after = _use_case_snapshot(use_case)
    details = _summarize_changes(before, after)

    _emit_audit_event(db, use_case.id, action="use_case_updated", actor=actor, details=details)
    db.commit()
    db.refresh(use_case)
    return use_case


@app.get("/use-cases/{use_case_id}/edit")
def edit_use_case_page(use_case_id: int, request: Request, db: Session = Depends(get_db)):
    use_case = _get_use_case_or_404(db, use_case_id)
    return _render_template(
        request,
        "edit_use_case.html",
        {
            "use_case": use_case,
            "data_category_options": DATA_CATEGORY_OPTIONS,
            "selected_data_categories": _parse_data_categories(use_case.data_categories),
            "deployment_type_options": DEPLOYMENT_TYPE_OPTIONS,
            "api_or_ui_options": API_OR_UI_OPTIONS,
        },
    )


@app.post("/use-cases/{use_case_id}/edit")
def edit_use_case_from_form(
    use_case_id: int,
    title: str = Form(...),
    business_unit: str = Form(...),
    owner_name: str = Form(...),
    owner_email: str = Form(...),
    system_name: str = Form(...),
    ai_vendor: str = Form(""),
    model_name: str = Form(""),
    deployment_type: str = Form(""),
    api_or_ui: str = Form(""),
    data_retained_by_vendor: bool = Form(False),
    contract_approved: bool = Form(False),
    purpose: str = Form(...),
    data_categories: list[str] = Form(default=[]),
    uses_external_model: bool = Form(False),
    has_human_impact: bool = Form(False),
    automated_decision: bool = Form(False),
    federal_client: bool = Form(False),
    active: bool = Form(False),
    self_reported_risk_level: str = Form("unknown"),
    db: Session = Depends(get_db),
):
    normalized_data_categories = _normalize_data_categories(data_categories)
    payload = _build_use_case_payload_from_form(
        title,
        business_unit,
        owner_name,
        owner_email,
        system_name,
        ai_vendor,
        model_name,
        deployment_type,
        api_or_ui,
        data_retained_by_vendor,
        contract_approved,
        purpose,
        normalized_data_categories,
        uses_external_model,
        has_human_impact,
        automated_decision,
        federal_client,
        active,
        self_reported_risk_level,
    )
    update_use_case(use_case_id, payload, db, actor=owner_email)
    return RedirectResponse(url="/registered-use-cases", status_code=303)


@app.get("/use-cases", response_model=list[UseCaseOut])
def list_use_cases(db: Session = Depends(get_db)):
    query = select(UseCase).order_by(UseCase.created_at.desc())
    return list(db.scalars(query).all())


@app.get("/inventory", response_model=list[UseCaseOut])
def get_inventory(
    owner_email: str | None = Query(default=None),
    business_unit: str | None = Query(default=None),
    risk_level: RiskLevel | None = Query(default=None),
    data_category: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    query = select(UseCase)

    if owner_email:
        query = query.where(UseCase.owner_email == owner_email)
    if business_unit:
        query = query.where(UseCase.business_unit == business_unit)
    if risk_level:
        query = query.where(UseCase.risk_level == risk_level)
    if data_category:
        query = query.where(UseCase.data_categories.ilike(f"%{data_category}%"))

    query = query.order_by(UseCase.created_at.desc())
    return list(db.scalars(query).all())


@app.post("/use-cases/{use_case_id}/start-review", response_model=StatusUpdateOut)
def start_review(use_case_id: int, request: Request, reviewer: str = Query(...), db: Session = Depends(get_db)):
    """Governance reviewer promotes a Pending Review submission to Submitted so it
    can proceed through the normal approval/activation flow."""
    _require_governance_token(request)
    use_case = _get_use_case_or_404(db, use_case_id)

    if use_case.status != UseCaseStatus.pending_review:
        raise HTTPException(
            status_code=400,
            detail=f"Use case is not in Pending Review (current status: {use_case.status.value})",
        )

    use_case.status = UseCaseStatus.submitted
    _emit_audit_event(
        db,
        use_case.id,
        action="review_started",
        actor=reviewer,
        details="Governance reviewer accepted submission; status moved to Submitted",
    )
    db.commit()
    return StatusUpdateOut(id=use_case.id, status=use_case.status, message="Submission accepted for review")


@app.post("/use-cases/{use_case_id}/reject", response_model=StatusUpdateOut)
def reject_use_case(use_case_id: int, request: Request, reviewer: str = Query(...), reason: str = Query(default=""), db: Session = Depends(get_db)):
    """Governance reviewer rejects a Pending Review or Submitted use case."""
    _require_governance_token(request)
    use_case = _get_use_case_or_404(db, use_case_id)

    if use_case.status not in (UseCaseStatus.pending_review, UseCaseStatus.submitted):
        raise HTTPException(
            status_code=400,
            detail=f"Can only reject Pending Review or Submitted cases (current: {use_case.status.value})",
        )

    use_case.status = UseCaseStatus.rejected
    _emit_audit_event(
        db,
        use_case.id,
        action="use_case_rejected",
        actor=reviewer,
        details=reason or "Rejected by governance reviewer",
    )
    db.commit()
    return StatusUpdateOut(id=use_case.id, status=use_case.status, message="Use case rejected")


@app.post("/use-cases/{use_case_id}/approve", response_model=StatusUpdateOut)
def approve_use_case(use_case_id: int, request: Request, payload: UseCaseApprovalIn, db: Session = Depends(get_db)):
    _require_governance_token(request)
    use_case = _get_use_case_or_404(db, use_case_id)

    if use_case.risk_level not in (RiskLevel.high, RiskLevel.regulated):
        raise HTTPException(status_code=400, detail="Approval endpoint is only required for high or regulated use cases")

    use_case.status = UseCaseStatus.approved
    use_case.approver_name = payload.approver_name
    use_case.approval_notes = payload.approval_notes
    use_case.approved_at = utc_now()

    _emit_audit_event(
        db,
        use_case.id,
        action="use_case_approved",
        actor=payload.approver_name,
        details=payload.approval_notes,
    )
    db.commit()

    return StatusUpdateOut(id=use_case.id, status=use_case.status, message="Use case approved")


@app.post("/use-cases/{use_case_id}/activate", response_model=StatusUpdateOut)
def activate_use_case(use_case_id: int, request: Request, actor: str = Query(default="system"), db: Session = Depends(get_db)):
    _require_governance_token(request)
    use_case = _get_use_case_or_404(db, use_case_id)

    if use_case.risk_level in (RiskLevel.high, RiskLevel.regulated) and use_case.status != UseCaseStatus.approved:
        raise HTTPException(
            status_code=400,
            detail="High and regulated use cases must be approved before activation",
        )

    use_case.status = UseCaseStatus.active
    _emit_audit_event(
        db,
        use_case.id,
        action="use_case_activated",
        actor=actor,
        details=f"Activated from status transition to {use_case.status.value}",
    )
    db.commit()

    return StatusUpdateOut(id=use_case.id, status=use_case.status, message="Use case activated")


@app.get("/audit-events", response_model=list[AuditEventOut])
def list_audit_events(use_case_id: int | None = Query(default=None), db: Session = Depends(get_db)):
    query = select(AuditEvent)
    if use_case_id:
        query = query.where(AuditEvent.use_case_id == use_case_id)
    query = query.order_by(AuditEvent.created_at.desc())
    return list(db.scalars(query).all())
