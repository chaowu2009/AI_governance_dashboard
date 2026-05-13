# AI Governance MVP

A lightweight Enterprise AI Governance Platform built with Python and FastAPI.

## What this implements

- Mandatory AI Use Case Registry
- Deterministic risk classification (`Low`, `Medium`, `High`, `Regulated`)
- AI system inventory and audit-friendly filters
- Approval workflow gating for high-risk systems
- Immutable audit event trail for key workflow changes

## Quick start

1. Create and activate a virtual environment.
2. Install dependencies:
   `pip install -r requirements.txt`
3. Run the app:
   `uvicorn app.main:app --reload`
4. Open:
   - API docs: `http://127.0.0.1:8000/docs`
   - Intake UI: `http://127.0.0.1:8000/`

## Streamlit Cloud

If you deploy on Streamlit Cloud, set the app entry file to `streamlit_app.py`.
That file is the Streamlit-native launcher for this repository.

## Navigation and workflow

1. The top menu separates `AI Usage Registration` and `Registered Use Cases`.
2. The Registered Use Cases page lists each record with complete history entries and timestamps.
3. Each active record has `Update` and `Delete` actions.

## Docker

1. Build and start the app:
   `docker compose up --build`
2. Open:
   - API docs: `http://127.0.0.1:8000/docs`
   - Intake UI: `http://127.0.0.1:8000/`

SQLite data is persisted to the local `data/` directory through the compose volume mount.

### Secure Token Setup (before pushing to GitHub)

1. Copy `.env.example` to `.env`.
2. Set local secret values in `.env`:
   - `CAPTCHA_SECRET` (random hex)
   - `GOVERNANCE_TOKEN` (reviewer token)
3. Start with Docker Compose as usual.

`.env` is git-ignored and will not be committed.

## Core API endpoints

- `POST /use-cases` submit use case (mandatory fields, auto risk classification)
- `GET /use-cases` list all use cases
- `GET /inventory` query inventory by owner, business unit, risk, data category
- `POST /use-cases/{id}/approve` approve high or regulated use cases
- `POST /use-cases/{id}/activate` activate use case (blocked for high/regulated unless approved)
- `GET /audit-events` list audit events

## Risk rubric (MVP)

Score is computed from weighted controls:

- Sensitive data category present: +30
- External model/provider: +20
- Human impact stated: +20
- Automated decision making: +30
- Federal client context: +20

Classification thresholds:

- `Regulated`: `federal_client` and (`automated_decision` or sensitive data)
- `High`: score >= 70
- `Medium`: score >= 35
- `Low`: score < 35

## Notes

- MVP stores metadata only (no client data content).
- SQLite is used for speed of adoption.
- The architecture is intentionally simple and extensible.
"# AI_governance_dashboard" 
