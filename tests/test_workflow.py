import hashlib
import hmac
import os

os.environ.setdefault("GOVERNANCE_TOKEN", "test-governance-token")
os.environ.setdefault("CAPTCHA_SECRET", "test-captcha-secret")

from fastapi.testclient import TestClient

from app.main import app, _CAPTCHA_SECRET


client = TestClient(app)
_GOV_HEADERS = {"X-Governance-Token": "test-governance-token"}


def _make_valid_captcha_fields(answer: str = "7") -> dict:
    """Return captcha_answer + captcha_token fields that will pass verification."""
    token = hmac.new(_CAPTCHA_SECRET, answer.encode(), hashlib.sha256).hexdigest()
    return {"captcha_answer": answer, "captcha_token": token}


def _payload(**overrides):
    data = {
        "title": "AI assistant for support operations",
        "business_unit": "Operations",
        "owner_name": "Jane Doe",
        "owner_email": "jane@example.com",
        "system_name": "Support Copilot",
        "purpose": "Drafts responses to routine support inquiries.",
        "data_categories": "none",
        "uses_external_model": False,
        "has_human_impact": False,
        "automated_decision": False,
        "federal_client": False,
        "active": False,
    }
    data.update(overrides)
    return data


def test_register_page_renders_menu():
    response = client.get("/register")

    assert response.status_code == 200
    assert "AI Usage Registration" in response.text
    assert "Registered Use Cases" in response.text
    assert "Login" not in response.text


def test_can_create_use_case_without_login():
    create = client.post("/use-cases", json=_payload(title="Open Access Example"))

    assert create.status_code == 201


def test_registered_use_cases_page_lists_history():
    create = client.post("/use-cases", json=_payload(title="Registry Panel Example", active=True))
    assert create.status_code == 201
    use_case_id = create.json()["id"]

    update = client.put(
        f"/use-cases/{use_case_id}",
        json=_payload(title="Registry Panel Example Updated", purpose="Updated purpose for audit history.", active=False),
    )
    assert update.status_code == 200

    response = client.get("/registered-use-cases")

    assert response.status_code == 200
    assert "Registry Panel Example Updated" in response.text
    assert "jane@example.com" in response.text
    assert "Use Case Submitted" in response.text
    assert "Use Case Updated" in response.text
    assert "Update" in response.text
    assert ">Delete<" not in response.text
    assert "Active" in response.text
    assert "No" in response.text
    assert "Sort by" in response.text
    assert "updated_at (last updated)" in response.text
    assert "active" in response.text
    assert "#1" in response.text
    assert "Full Registration Fields" in response.text
    assert "security_review_status" in response.text


def test_edit_form_accepts_unknown_risk_level_value():
    create = client.post("/use-cases", json=_payload(title="Edit Form Risk Mapping"))
    assert create.status_code == 201
    use_case_id = create.json()["id"]

    response = client.post(
        f"/use-cases/{use_case_id}/edit",
        data={
            "title": "Edit Form Risk Mapping Updated",
            "business_unit": "Operations",
            "owner_name": "Jane Doe",
            "owner_email": "jane@example.com",
            "system_name": "Support Copilot",
            "purpose": "Updated purpose after edit submission.",
            "data_categories": "none",
            "self_reported_risk_level": "unknown",
            "active": "false",
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/registered-use-cases"


def test_submit_form_accepts_checkbox_data_categories():
    response = client.post(
        "/submit",
        data={
            "use_case_title": "Checkbox Data Category Case",
            "ai_system_name": "Support Copilot",
            "business_unit": "Operations",
            "owner_name": "Jane Doe",
            "owner_email": "jane@example.com",
            "business_purpose": "Captures category selections using checkbox inputs.",
            "data_categories": ["Public", "PII", "Financial"],
            "risk_level": "low",
            "active": "false",
            **_make_valid_captcha_fields(),
        },
        follow_redirects=False,
    )

    assert response.status_code == 303
    assert response.headers["location"] == "/registered-use-cases"

    listed = client.get("/use-cases")
    assert listed.status_code == 200
    assert any(item["data_categories"] == "Public, PII, Financial" for item in listed.json())


def test_submit_and_edit_model_vendor_fields():
    submit = client.post(
        "/submit",
        data={
            "use_case_title": "Vendor Metadata Case",
            "ai_system_name": "Support Copilot",
            "business_unit": "Operations",
            "owner_name": "Jane Doe",
            "owner_email": "jane@example.com",
            "ai_vendor_name": "OpenAI",
            "model_name": "GPT-4.1",
            "deployment_type": "SaaS",
            "api_or_ui_usage": "API",
            "data_retention_by_vendor": "true",
            "contract_approved": "false",
            "business_purpose": "Captures model vendor metadata in use case intake.",
            "data_categories": ["Internal"],
            "risk_level": "medium",
            "active": "true",
            **_make_valid_captcha_fields(),
        },
        follow_redirects=False,
    )

    assert submit.status_code == 303

    use_cases = client.get("/use-cases")
    assert use_cases.status_code == 200
    created = next(item for item in use_cases.json() if item["title"] == "Vendor Metadata Case")

    assert created["ai_vendor"] == "OpenAI"
    assert created["model_name"] == "GPT-4.1"
    assert created["deployment_type"] == "SaaS"
    assert created["api_or_ui"] == "API"
    assert created["data_retained_by_vendor"] is True
    assert created["contract_approved"] is False

    edited = client.post(
        f"/use-cases/{created['id']}/edit",
        data={
            "title": "Vendor Metadata Case",
            "business_unit": "Operations",
            "owner_name": "Jane Doe",
            "owner_email": "jane@example.com",
            "system_name": "Support Copilot",
            "ai_vendor": "OpenAI",
            "model_name": "GPT-4.1",
            "deployment_type": "Azure Gov",
            "api_or_ui": "UI",
            "data_retained_by_vendor": "false",
            "contract_approved": "true",
            "purpose": "Captures model vendor metadata in use case intake.",
            "data_categories": ["Internal"],
            "self_reported_risk_level": "medium",
            "active": "true",
        },
        follow_redirects=False,
    )

    assert edited.status_code == 303

    updated = client.get("/use-cases").json()
    revised = next(item for item in updated if item["id"] == created["id"])
    assert revised["deployment_type"] == "Azure Gov"
    assert revised["api_or_ui"] == "UI"
    assert revised["data_retained_by_vendor"] is False
    assert revised["contract_approved"] is True


def test_high_risk_requires_approval_before_activation():
    create = client.post(
        "/use-cases",
        json=_payload(data_categories="pii", uses_external_model=True, automated_decision=True),
    )
    assert create.status_code == 201
    use_case_id = create.json()["id"]

    activate = client.post(f"/use-cases/{use_case_id}/activate", headers=_GOV_HEADERS)
    assert activate.status_code == 400
    assert "must be approved" in activate.json()["detail"]

    approve = client.post(
        f"/use-cases/{use_case_id}/approve",
        json={"approver_name": "Governance Lead", "approval_notes": "Risk controls verified"},
        headers=_GOV_HEADERS,
    )
    assert approve.status_code == 200

    activate_after = client.post(f"/use-cases/{use_case_id}/activate", headers=_GOV_HEADERS)
    assert activate_after.status_code == 200
    assert activate_after.json()["status"] == "Active"


def test_low_risk_can_activate_without_approval():
    create = client.post("/use-cases", json=_payload(title="FAQ summarizer"))
    assert create.status_code == 201
    use_case_id = create.json()["id"]

    activate = client.post(f"/use-cases/{use_case_id}/activate", headers=_GOV_HEADERS)
    assert activate.status_code == 200
    assert activate.json()["status"] == "Active"
