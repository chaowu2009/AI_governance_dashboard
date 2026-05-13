from .models import RiskLevel

SENSITIVE_CATEGORIES = {
    "pii",
    "phi",
    "financial",
    "biometric",
    "children",
    "government_id",
}


class RiskResult(dict):
    score: int
    level: RiskLevel


def _normalize_categories(raw: str) -> set[str]:
    if not raw:
        return set()
    return {item.strip().lower() for item in raw.split(",") if item.strip()}


def classify_risk(
    data_categories: str,
    uses_external_model: bool,
    has_human_impact: bool,
    automated_decision: bool,
    federal_client: bool,
) -> RiskResult:
    categories = _normalize_categories(data_categories)

    has_sensitive_data = len(categories.intersection(SENSITIVE_CATEGORIES)) > 0

    score = 0
    if has_sensitive_data:
        score += 30
    if uses_external_model:
        score += 20
    if has_human_impact:
        score += 20
    if automated_decision:
        score += 30
    if federal_client:
        score += 20

    if federal_client and (automated_decision or has_sensitive_data):
        level = RiskLevel.regulated
    elif score >= 70:
        level = RiskLevel.high
    elif score >= 35:
        level = RiskLevel.medium
    else:
        level = RiskLevel.low

    return RiskResult(score=score, level=level)
