from __future__ import annotations

import hmac
import json
import os

import streamlit as st
from dotenv import load_dotenv

from app.database import Base, SessionLocal, engine, ensure_schema_compatibility
from app.main import (
    AI_FUNCTION_TYPES,
    APPROVAL_STATUS_OPTIONS,
    AUDIT_RETENTION_OPTIONS,
    BUSINESS_CRITICALITY_LEVELS,
    COMMON_CONNECTED_SYSTEMS,
    DATA_CATEGORY_OPTIONS,
    DEPLOYMENT_TYPE_OPTIONS,
    HUMAN_REVIEW_OPTIONS,
    API_OR_UI_OPTIONS,
    SECURITY_REVIEW_STATUS_OPTIONS,
    _create_use_case,
    _get_use_case_history_items,
    _seed_sample_use_cases,
    update_use_case,
)
from app.models import SelfReportedRiskLevel, UseCase, UseCaseStatus
from app.schemas import UseCaseCreate


st.set_page_config(page_title="AI Governance Dashboard", page_icon="🛡️", layout="wide")

load_dotenv()
_GOVERNANCE_TOKEN = os.getenv("GOVERNANCE_TOKEN", "")

Base.metadata.create_all(bind=engine)
ensure_schema_compatibility()
_seed_sample_use_cases()


def _inject_base_theme() -> None:
        st.markdown(
                """
                <style>
                @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;700&display=swap');

                :root {
                    --bg-1: #f2f5f3;
                    --bg-2: #d7efe4;
                    --bg-3: #f7e2c9;
                    --ink: #0b1811;
                    --muted: #2f4a3e;
                    --accent: #115a43;
                    --accent-2: #249c83;
                    --border: #8eb7a6;
                    --card: rgba(255, 255, 255, 0.94);
                }

                .stApp {
                    font-family: "Plus Jakarta Sans", "Segoe UI", sans-serif;
                    color: var(--ink);
                    background: radial-gradient(circle at 10% 12%, var(--bg-2), transparent 52%),
                                            radial-gradient(circle at 88% 75%, var(--bg-3), transparent 42%),
                                            linear-gradient(180deg, rgba(255, 255, 255, 0.35), rgba(255, 255, 255, 0)),
                                            var(--bg-1);
                }

                .stApp [data-testid="stAppViewContainer"] > .main .block-container {
                    max-width: 1240px;
                    padding-top: 0.9rem;
                    padding-bottom: 1.0rem;
                }

                .stMarkdown, .stText, p, label, div, span {
                    color: var(--ink);
                }

                [data-testid="stCaptionContainer"], [data-testid="stCaptionContainer"] p {
                    color: var(--muted) !important;
                }

                h1, h2, h3, [data-testid="stMarkdownContainer"] h1,
                [data-testid="stMarkdownContainer"] h2,
                [data-testid="stMarkdownContainer"] h3 {
                    font-family: "Space Grotesk", "Plus Jakarta Sans", sans-serif;
                    letter-spacing: 0.01em;
                    color: var(--ink);
                }

                .app-shell {
                    border: 1px solid var(--border);
                    background: var(--card);
                    border-radius: 16px;
                    padding: 10px 12px;
                    margin-bottom: 10px;
                    box-shadow: 0 12px 26px rgba(17, 33, 23, 0.11);
                }

                .hero-bar {
                    background: linear-gradient(120deg, var(--accent), var(--accent-2));
                    color: white;
                    border-radius: 12px;
                    padding: 9px 12px;
                    margin-bottom: 8px;
                    font-family: "Space Grotesk", "Plus Jakarta Sans", sans-serif;
                    font-weight: 700;
                    letter-spacing: 0.02em;
                }

                .stTabs [data-baseweb="tab-list"] {
                    gap: 6px;
                    margin-bottom: 8px;
                }

                .stTabs [data-baseweb="tab"] {
                    border: 1px solid var(--border);
                    border-radius: 10px;
                    background: #ffffff;
                    padding: 6px 10px;
                    color: var(--ink);
                }

                .stTabs [aria-selected="true"] {
                    background: linear-gradient(120deg, var(--accent), var(--accent-2));
                    color: #ffffff !important;
                    border-color: transparent;
                }

                .stButton > button,
                .stDownloadButton > button,
                .stFormSubmitButton > button {
                    border: 0;
                    border-radius: 10px;
                    color: #ffffff;
                    font-weight: 600;
                    background: linear-gradient(120deg, var(--accent), var(--accent-2));
                    box-shadow: 0 6px 16px rgba(17, 90, 67, 0.24);
                    min-height: 34px;
                }

                .stTextInput input,
                .stTextArea textarea,
                .stSelectbox div[data-baseweb="select"] > div,
                .stMultiSelect div[data-baseweb="select"] > div {
                    border-radius: 8px;
                    border: 1px solid var(--border);
                    background: #ffffff;
                    color: var(--ink);
                }

                .stTextInput input,
                .stTextArea textarea {
                    padding-top: 0.35rem;
                    padding-bottom: 0.35rem;
                }

                .stDataFrame, .stTable {
                    border: 1px solid var(--border);
                    border-radius: 10px;
                    overflow: hidden;
                    background: #fff;
                }

                [data-testid="stVerticalBlock"] > div {
                    margin-bottom: 0.35rem;
                }
                </style>
                """,
                unsafe_allow_html=True,
        )


def _load_use_cases(sort_by: str = "updated_at"):
    with SessionLocal() as db:
        return _get_use_case_history_items(db, sort_by)


def _create_from_form(form_values: dict[str, object], registration_payload: dict[str, object] | None = None) -> int:
    payload = UseCaseCreate(**form_values)
    with SessionLocal() as db:
        use_case = _create_use_case(payload, db, actor=payload.owner_email, initial_status=UseCaseStatus.pending_review)
        if registration_payload is not None:
            use_case.registration_payload = json.dumps(registration_payload)
            db.commit()
        return use_case.id


def _split_data_categories(raw: str) -> list[str]:
    if not raw or raw.strip().lower() == "none":
        return []
    return [item.strip() for item in raw.split(",") if item.strip()]


def _update_from_form(use_case_id: int, actor: str, form_values: dict[str, object]) -> None:
    payload = UseCaseCreate(**form_values)
    with SessionLocal() as db:
        use_case = update_use_case(use_case_id, payload, db, actor=actor)
        use_case.registration_payload = json.dumps(form_values.get("registration_payload", {}))
        db.commit()


def _load_registration_payload(use_case: UseCase) -> dict[str, object]:
    default_payload = {
        "use_case_title": use_case.title,
        "ai_system_name": use_case.system_name,
        "business_unit": use_case.business_unit,
        "owner_name": use_case.owner_name,
        "owner_email": use_case.owner_email,
        "business_purpose": use_case.purpose,
        "ai_function_type": [],
        "data_categories": _split_data_categories(use_case.data_categories),
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
        "human_review_required": "Not applicable",
        "human_override_available": False,
        "federal_client_context": use_case.federal_client,
        "connected_systems": [],
        "production_access": use_case.active,
        "client_facing": False,
        "writes_to_systems": False,
        "reads_from_sensitive_systems": False,
        "security_review_required": False,
        "security_review_status": "Not started",
        "logging_enabled": False,
        "audit_trail_retention": "90 days",
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
            payload = json.loads(use_case.registration_payload)
            if isinstance(payload, dict):
                default_payload.update(payload)
        except json.JSONDecodeError:
            pass

    if isinstance(default_payload.get("data_categories"), str):
        default_payload["data_categories"] = _split_data_categories(str(default_payload["data_categories"]))
    if isinstance(default_payload.get("ai_function_type"), str):
        default_payload["ai_function_type"] = [default_payload["ai_function_type"]]
    if isinstance(default_payload.get("connected_systems"), str):
        default_payload["connected_systems"] = [default_payload["connected_systems"]]
    return default_payload


def _status_counts():
    with SessionLocal() as db:
        items = list(db.query(UseCase.status).all())
    counts: dict[str, int] = {}
    for (status,) in items:
        counts[status.value] = counts.get(status.value, 0) + 1
    return [{"Status": key, "Count": value} for key, value in sorted(counts.items())]


st.title("AI Governance Dashboard")
st.caption("Streamlit Cloud launcher for the AI governance MVP.")
_inject_base_theme()
st.markdown('<div class="hero-bar">Enterprise AI Governance Workspace</div>', unsafe_allow_html=True)
st.markdown('<div class="app-shell">', unsafe_allow_html=True)

tab_intake, tab_cases, tab_policy = st.tabs(["AI Usage Registration", "Registered Use Cases", "AI Policy"])

with tab_policy:
    st.subheader("AI Policy")
    st.write(
        "This is the AI Policy page. You can add links to AI Policy and AI Policy implementation files here when they are ready."
    )
    st.info("Placeholder section for future policy file links.")

with tab_intake:
    st.subheader("AI Usage Registration")
    st.caption("Register AI usage using the governance schema layout.")
    with st.form("new_use_case"):
        st.markdown("#### Basic Information")
        core_col1, core_col2 = st.columns(2)
        title = core_col1.text_input("Use Case Title")
        system_name = core_col2.text_input("AI System Name")
        unit_col, owner_col = st.columns(2)
        business_unit = unit_col.text_input("Business Unit")
        owner_name = owner_col.text_input("Owner Name")
        owner_email = st.text_input("Owner Email")
        purpose = st.text_area("Business Purpose", height=110)

        st.markdown("#### AI Function / Use Type")
        function_col1, function_col2 = st.columns(2)
        selected_function_types: list[str] = []
        split_index = (len(AI_FUNCTION_TYPES) + 1) // 2
        for index, function_name in enumerate(AI_FUNCTION_TYPES[:split_index]):
            if function_col1.checkbox(function_name, key=f"intake_fn_left_{index}"):
                selected_function_types.append(function_name)
        for index, function_name in enumerate(AI_FUNCTION_TYPES[split_index:]):
            if function_col2.checkbox(function_name, key=f"intake_fn_right_{index}"):
                selected_function_types.append(function_name)

        st.markdown("#### Data / Model / Risk")
        data_categories = st.multiselect("Data categories", DATA_CATEGORY_OPTIONS)
        model_col1, model_col2 = st.columns(2)
        ai_vendor = model_col1.text_input("AI Vendor")
        model_name = model_col2.text_input("Model Name")
        deploy_col1, deploy_col2 = st.columns(2)
        deployment_type = deploy_col1.selectbox("Deployment type", [""] + DEPLOYMENT_TYPE_OPTIONS)
        api_or_ui = deploy_col2.selectbox("API or UI", [""] + API_OR_UI_OPTIONS)

        flag_col1, flag_col2, flag_col3 = st.columns(3)
        uses_external_model = flag_col1.checkbox("External model/provider")
        has_human_impact = flag_col2.checkbox("Human impact")
        automated_decision = flag_col3.checkbox("Automated decision")

        flag_col4, flag_col5, flag_col6 = st.columns(3)
        federal_client = flag_col4.checkbox("Federal client")
        production_access = flag_col5.checkbox("Production access")
        data_retained_by_vendor = flag_col6.checkbox("Vendor retains data")

        contract_approved = st.checkbox("Contract approved")
        self_reported_risk_level = st.selectbox(
            "Self-reported risk level",
            [item for item in SelfReportedRiskLevel],
            format_func=lambda item: item.value,
        )
        business_criticality = st.selectbox("Business criticality", BUSINESS_CRITICALITY_LEVELS)

        st.markdown("#### Human Review")
        human_review_required = st.selectbox("Human review required", HUMAN_REVIEW_OPTIONS)
        human_override_available = st.checkbox("Human override available")

        st.markdown("#### System Integration")
        connected_systems = st.multiselect("Connected systems", COMMON_CONNECTED_SYSTEMS)
        integration_col1, integration_col2, integration_col3 = st.columns(3)
        client_facing = integration_col1.checkbox("Client facing")
        writes_to_systems = integration_col2.checkbox("Writes to systems")
        reads_from_sensitive_systems = integration_col3.checkbox("Reads from sensitive systems")

        st.markdown("#### Security and Audit")
        security_col1, security_col2 = st.columns(2)
        security_review_required = security_col1.checkbox("Security review required")
        logging_enabled = security_col2.checkbox("Logging enabled")
        security_review_status = st.selectbox("Security review status", SECURITY_REVIEW_STATUS_OPTIONS)
        audit_trail_retention = st.selectbox("Audit trail retention", AUDIT_RETENTION_OPTIONS)
        security_col3, security_col4 = st.columns(2)
        access_control_defined = security_col3.checkbox("Access control defined")
        data_encryption_required = security_col4.checkbox("Data encryption required")

        st.markdown("#### Governance Workflow")
        approval_status = st.selectbox("Approval status", APPROVAL_STATUS_OPTIONS)
        review_owner = st.text_input("Review owner")
        governance_col1, governance_col2, governance_col3 = st.columns(3)
        approval_date = governance_col1.text_input("Approval date")
        next_review_date = governance_col2.text_input("Next review date")
        expiration_date = governance_col3.text_input("Expiration date")
        policy_exception_needed = st.checkbox("Policy exception needed")
        notes = st.text_area("Notes", height=90)

        submitted = st.form_submit_button("Submit for review")

    if submitted:
        try:
            normalized_data_categories = ", ".join(data_categories) if data_categories else "none"
            use_case_id = _create_from_form(
                {
                    "title": title,
                    "business_unit": business_unit,
                    "owner_name": owner_name,
                    "owner_email": owner_email,
                    "system_name": system_name,
                    "ai_vendor": ai_vendor,
                    "model_name": model_name,
                    "deployment_type": deployment_type,
                    "api_or_ui": api_or_ui,
                    "data_retained_by_vendor": data_retained_by_vendor,
                    "contract_approved": contract_approved,
                    "purpose": purpose,
                    "data_categories": normalized_data_categories,
                    "uses_external_model": uses_external_model,
                    "has_human_impact": has_human_impact,
                    "automated_decision": automated_decision,
                    "federal_client": federal_client,
                    "active": production_access,
                    "self_reported_risk_level": self_reported_risk_level,
                },
                registration_payload={
                    "use_case_title": title,
                    "ai_system_name": system_name,
                    "business_unit": business_unit,
                    "owner_name": owner_name,
                    "owner_email": owner_email,
                    "business_purpose": purpose,
                    "ai_function_type": selected_function_types,
                    "data_categories": data_categories,
                    "uses_external_model_provider": uses_external_model,
                    "ai_vendor_name": ai_vendor,
                    "model_name": model_name,
                    "deployment_type": deployment_type,
                    "api_or_ui_usage": api_or_ui,
                    "data_retention_by_vendor": data_retained_by_vendor,
                    "contract_approved": contract_approved,
                    "risk_level": self_reported_risk_level.value,
                    "business_criticality": business_criticality,
                    "human_impacting_output": has_human_impact,
                    "automated_decision_making": automated_decision,
                    "human_review_required": human_review_required,
                    "human_override_available": human_override_available,
                    "federal_client_context": federal_client,
                    "connected_systems": connected_systems,
                    "production_access": production_access,
                    "client_facing": client_facing,
                    "writes_to_systems": writes_to_systems,
                    "reads_from_sensitive_systems": reads_from_sensitive_systems,
                    "security_review_required": security_review_required,
                    "security_review_status": security_review_status,
                    "logging_enabled": logging_enabled,
                    "audit_trail_retention": audit_trail_retention,
                    "access_control_defined": access_control_defined,
                    "data_encryption_required": data_encryption_required,
                    "approval_status": approval_status,
                    "review_owner": review_owner,
                    "approval_date": approval_date,
                    "next_review_date": next_review_date,
                    "expiration_date": expiration_date,
                    "policy_exception_needed": policy_exception_needed,
                    "notes": notes,
                },
            )
            st.success(f"Use case #{use_case_id} submitted and queued for review.")
        except Exception as exc:  # pragma: no cover - Streamlit UI feedback
            st.error(f"Could not submit use case: {exc}")

with tab_cases:
    sort_by = st.selectbox(
        "Sort by",
        ["updated_at", "created_at", "risk_level", "owner_name", "data_categories", "active"],
        format_func=lambda item: item if item != "updated_at" else "updated_at (last updated)",
    )
    items = _load_use_cases(sort_by)
    if "selected_case_id" not in st.session_state:
        st.session_state["selected_case_id"] = None

    header_cols = st.columns([2.6, 1.6, 1.6, 1.5, 1.2, 2.0])
    header_cols[0].markdown("**Title**")
    header_cols[1].markdown("**Owner**")
    header_cols[2].markdown("**Business Unit**")
    header_cols[3].markdown("**Risk**")
    header_cols[4].markdown("**Status**")
    header_cols[5].markdown("**Updated**")

    for item in items:
        use_case = item["use_case"]
        row_cols = st.columns([2.6, 1.6, 1.6, 1.5, 1.2, 2.0])
        with row_cols[0]:
            if st.button(use_case.title, key=f"select_case_{use_case.id}", use_container_width=True, type="tertiary"):
                st.session_state["selected_case_id"] = use_case.id
        row_cols[1].write(use_case.owner_name)
        row_cols[2].write(use_case.business_unit)
        row_cols[3].write(use_case.risk_level.value)
        row_cols[4].write(use_case.status.value)
        row_cols[5].write(str(use_case.updated_at))

    selected_case = next(
        (item for item in items if item["use_case"].id == st.session_state["selected_case_id"]),
        None,
    )

    if selected_case:
        use_case = selected_case["use_case"]
        st.subheader(f"Case Details: {use_case.title}")

        with st.container(border=True):
            st.markdown("### Update Case")
            registration_payload = _load_registration_payload(use_case)
            with st.form(f"update_case_{use_case.id}"):
                st.markdown("#### Basic Information")
                col1, col2 = st.columns(2)
                title_edit = col1.text_input("Title", value=use_case.title)
                system_name_edit = col2.text_input("System Name", value=use_case.system_name)
                col3, col4 = st.columns(2)
                business_unit_edit = col3.text_input("Business Unit", value=use_case.business_unit)
                owner_name_edit = col4.text_input("Owner Name", value=use_case.owner_name)
                owner_email_edit = st.text_input("Owner Email", value=use_case.owner_email)
                purpose_edit = st.text_area("Purpose", value=use_case.purpose)

                st.markdown("#### AI Function / Use Type")
                ai_function_type_edit = st.multiselect(
                    "AI Function Type",
                    AI_FUNCTION_TYPES,
                    default=[v for v in registration_payload.get("ai_function_type", []) if v in AI_FUNCTION_TYPES],
                )

                st.markdown("#### Model / Vendor Information")
                col5, col6 = st.columns(2)
                ai_vendor_edit = col5.text_input("AI Vendor", value=use_case.ai_vendor)
                model_name_edit = col6.text_input("Model Name", value=use_case.model_name)
                col7, col8 = st.columns(2)
                deployment_type_edit = col7.selectbox(
                    "Deployment Type",
                    [""] + DEPLOYMENT_TYPE_OPTIONS,
                    index=([""] + DEPLOYMENT_TYPE_OPTIONS).index(use_case.deployment_type)
                    if use_case.deployment_type in DEPLOYMENT_TYPE_OPTIONS
                    else 0,
                )
                api_or_ui_edit = col8.selectbox(
                    "API or UI",
                    [""] + API_OR_UI_OPTIONS,
                    index=([""] + API_OR_UI_OPTIONS).index(use_case.api_or_ui)
                    if use_case.api_or_ui in API_OR_UI_OPTIONS
                    else 0,
                )

                st.markdown("#### Data / Risk / Workflow")
                selected_data_categories = st.multiselect(
                    "Data Categories",
                    DATA_CATEGORY_OPTIONS,
                    default=[v for v in registration_payload.get("data_categories", []) if v in DATA_CATEGORY_OPTIONS],
                )
                col9, col10, col11 = st.columns(3)
                uses_external_model_edit = col9.checkbox("Uses External Model", value=use_case.uses_external_model)
                has_human_impact_edit = col10.checkbox("Human Impact", value=use_case.has_human_impact)
                automated_decision_edit = col11.checkbox("Automated Decision", value=use_case.automated_decision)
                col12, col13, col14 = st.columns(3)
                federal_client_edit = col12.checkbox("Federal Client", value=use_case.federal_client)
                active_edit = col13.checkbox("Active", value=use_case.active)
                data_retained_by_vendor_edit = col14.checkbox("Data Retained by Vendor", value=use_case.data_retained_by_vendor)
                contract_approved_edit = st.checkbox("Contract Approved", value=use_case.contract_approved)
                self_reported_risk_level_edit = st.selectbox(
                    "Self-Reported Risk Level",
                    [item for item in SelfReportedRiskLevel],
                    index=[item for item in SelfReportedRiskLevel].index(use_case.self_reported_risk_level),
                    format_func=lambda item: item.value,
                )

                business_criticality_edit = st.selectbox(
                    "Business Criticality",
                    BUSINESS_CRITICALITY_LEVELS,
                    index=BUSINESS_CRITICALITY_LEVELS.index(registration_payload.get("business_criticality", "Low"))
                    if registration_payload.get("business_criticality", "Low") in BUSINESS_CRITICALITY_LEVELS
                    else 0,
                )
                human_review_required_edit = st.selectbox(
                    "Human Review Required",
                    HUMAN_REVIEW_OPTIONS,
                    index=HUMAN_REVIEW_OPTIONS.index(registration_payload.get("human_review_required", "Not applicable"))
                    if registration_payload.get("human_review_required", "Not applicable") in HUMAN_REVIEW_OPTIONS
                    else 0,
                )
                human_override_available_edit = st.checkbox(
                    "Human Override Available",
                    value=bool(registration_payload.get("human_override_available", False)),
                )

                st.markdown("#### System Integration")
                connected_systems_edit = st.multiselect(
                    "Connected Systems",
                    COMMON_CONNECTED_SYSTEMS,
                    default=[v for v in registration_payload.get("connected_systems", []) if v in COMMON_CONNECTED_SYSTEMS],
                )
                production_access_edit = st.checkbox(
                    "Production Access",
                    value=bool(registration_payload.get("production_access", use_case.active)),
                )
                client_facing_edit = st.checkbox("Client Facing", value=bool(registration_payload.get("client_facing", False)))
                writes_to_systems_edit = st.checkbox(
                    "Writes To Systems",
                    value=bool(registration_payload.get("writes_to_systems", False)),
                )
                reads_from_sensitive_systems_edit = st.checkbox(
                    "Reads From Sensitive Systems",
                    value=bool(registration_payload.get("reads_from_sensitive_systems", False)),
                )

                st.markdown("#### Security and Audit")
                security_review_required_edit = st.checkbox(
                    "Security Review Required",
                    value=bool(registration_payload.get("security_review_required", False)),
                )
                security_review_status_edit = st.selectbox(
                    "Security Review Status",
                    SECURITY_REVIEW_STATUS_OPTIONS,
                    index=SECURITY_REVIEW_STATUS_OPTIONS.index(registration_payload.get("security_review_status", "Not started"))
                    if registration_payload.get("security_review_status", "Not started") in SECURITY_REVIEW_STATUS_OPTIONS
                    else 0,
                )
                logging_enabled_edit = st.checkbox("Logging Enabled", value=bool(registration_payload.get("logging_enabled", False)))
                audit_trail_retention_edit = st.selectbox(
                    "Audit Trail Retention",
                    AUDIT_RETENTION_OPTIONS,
                    index=AUDIT_RETENTION_OPTIONS.index(registration_payload.get("audit_trail_retention", "90 days"))
                    if registration_payload.get("audit_trail_retention", "90 days") in AUDIT_RETENTION_OPTIONS
                    else 0,
                )
                access_control_defined_edit = st.checkbox(
                    "Access Control Defined",
                    value=bool(registration_payload.get("access_control_defined", False)),
                )
                data_encryption_required_edit = st.checkbox(
                    "Data Encryption Required",
                    value=bool(registration_payload.get("data_encryption_required", False)),
                )

                st.markdown("#### Governance Workflow")
                approval_status_edit = st.selectbox(
                    "Approval Status",
                    APPROVAL_STATUS_OPTIONS,
                    index=APPROVAL_STATUS_OPTIONS.index(registration_payload.get("approval_status", "Draft"))
                    if registration_payload.get("approval_status", "Draft") in APPROVAL_STATUS_OPTIONS
                    else 0,
                )
                review_owner_edit = st.text_input("Review Owner", value=str(registration_payload.get("review_owner", "")))
                approval_date_edit = st.text_input("Approval Date", value=str(registration_payload.get("approval_date", "")))
                next_review_date_edit = st.text_input("Next Review Date", value=str(registration_payload.get("next_review_date", "")))
                expiration_date_edit = st.text_input("Expiration Date", value=str(registration_payload.get("expiration_date", "")))
                policy_exception_needed_edit = st.checkbox(
                    "Policy Exception Needed",
                    value=bool(registration_payload.get("policy_exception_needed", False)),
                )
                notes_edit = st.text_area("Notes", value=str(registration_payload.get("notes", "")))

                actor_edit = st.text_input("Updated By (actor)", value="streamlit-user")
                auth_code_edit = st.text_input("Authentication Code", type="password")
                updated = st.form_submit_button("Update")

            if updated:
                try:
                    if not _GOVERNANCE_TOKEN:
                        st.error("GOVERNANCE_TOKEN is not configured in environment.")
                        st.stop()
                    if not hmac.compare_digest(auth_code_edit.strip(), _GOVERNANCE_TOKEN):
                        st.error("Invalid authentication code.")
                        st.stop()

                    normalized_data_categories = ", ".join(selected_data_categories) if selected_data_categories else "none"
                    _update_from_form(
                        use_case.id,
                        actor_edit,
                        {
                            "title": title_edit,
                            "business_unit": business_unit_edit,
                            "owner_name": owner_name_edit,
                            "owner_email": owner_email_edit,
                            "system_name": system_name_edit,
                            "ai_vendor": ai_vendor_edit,
                            "model_name": model_name_edit,
                            "deployment_type": deployment_type_edit,
                            "api_or_ui": api_or_ui_edit,
                            "data_retained_by_vendor": data_retained_by_vendor_edit,
                            "contract_approved": contract_approved_edit,
                            "purpose": purpose_edit,
                            "data_categories": normalized_data_categories,
                            "uses_external_model": uses_external_model_edit,
                            "has_human_impact": has_human_impact_edit,
                            "automated_decision": automated_decision_edit,
                            "federal_client": federal_client_edit,
                            "active": production_access_edit,
                            "self_reported_risk_level": self_reported_risk_level_edit,
                            "registration_payload": {
                                "use_case_title": title_edit,
                                "ai_system_name": system_name_edit,
                                "business_unit": business_unit_edit,
                                "owner_name": owner_name_edit,
                                "owner_email": owner_email_edit,
                                "business_purpose": purpose_edit,
                                "ai_function_type": ai_function_type_edit,
                                "data_categories": selected_data_categories,
                                "uses_external_model_provider": uses_external_model_edit,
                                "ai_vendor_name": ai_vendor_edit,
                                "model_name": model_name_edit,
                                "deployment_type": deployment_type_edit,
                                "api_or_ui_usage": api_or_ui_edit,
                                "data_retention_by_vendor": data_retained_by_vendor_edit,
                                "contract_approved": contract_approved_edit,
                                "risk_level": self_reported_risk_level_edit.value,
                                "business_criticality": business_criticality_edit,
                                "human_impacting_output": has_human_impact_edit,
                                "automated_decision_making": automated_decision_edit,
                                "human_review_required": human_review_required_edit,
                                "human_override_available": human_override_available_edit,
                                "federal_client_context": federal_client_edit,
                                "connected_systems": connected_systems_edit,
                                "production_access": production_access_edit,
                                "client_facing": client_facing_edit,
                                "writes_to_systems": writes_to_systems_edit,
                                "reads_from_sensitive_systems": reads_from_sensitive_systems_edit,
                                "security_review_required": security_review_required_edit,
                                "security_review_status": security_review_status_edit,
                                "logging_enabled": logging_enabled_edit,
                                "audit_trail_retention": audit_trail_retention_edit,
                                "access_control_defined": access_control_defined_edit,
                                "data_encryption_required": data_encryption_required_edit,
                                "approval_status": approval_status_edit,
                                "review_owner": review_owner_edit,
                                "approval_date": approval_date_edit,
                                "next_review_date": next_review_date_edit,
                                "expiration_date": expiration_date_edit,
                                "policy_exception_needed": policy_exception_needed_edit,
                                "notes": notes_edit,
                            },
                        },
                    )
                    st.success("Case updated successfully.")
                    st.rerun()
                except Exception as exc:  # pragma: no cover - Streamlit UI feedback
                    st.error(f"Could not update case: {exc}")

            st.markdown("### History")
            if selected_case["events"]:
                st.table(
                    [
                        {
                            "Action": event.action.replace("_", " ").title(),
                            "Actor": event.actor,
                            "Details": event.details,
                            "At": str(event.created_at),
                        }
                        for event in selected_case["events"]
                    ]
                )
            else:
                st.info("No history recorded for this case.")
    elif items:
        st.info("Click any title to show that case profile below.")

st.markdown("</div>", unsafe_allow_html=True)
