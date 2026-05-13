from app.models import RiskLevel
from app.risk import classify_risk


def test_regulated_when_federal_and_automated():
    result = classify_risk(
        data_categories="none",
        uses_external_model=False,
        has_human_impact=False,
        automated_decision=True,
        federal_client=True,
    )
    assert result["level"] == RiskLevel.regulated


def test_medium_threshold():
    result = classify_risk(
        data_categories="pii",
        uses_external_model=False,
        has_human_impact=True,
        automated_decision=False,
        federal_client=False,
    )
    assert result["score"] == 50
    assert result["level"] == RiskLevel.medium


def test_low_threshold():
    result = classify_risk(
        data_categories="none",
        uses_external_model=False,
        has_human_impact=False,
        automated_decision=False,
        federal_client=False,
    )
    assert result["score"] == 0
    assert result["level"] == RiskLevel.low
