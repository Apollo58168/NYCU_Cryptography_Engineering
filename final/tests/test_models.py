from pathlib import Path

from pqc_audit.models import (
    AuditReport,
    CryptoEvidence,
    Finding,
    MigrationRecommendation,
    RiskAssessment,
    SemanticAnalysis,
    SourceFile,
    StaticMatch,
)


def test_models_can_be_created() -> None:
    source = SourceFile(Path("app.py"), "app.py", "print('ok')\n", 1)
    match = StaticMatch("app.py", 1, "rule", "RSA", "RSA", None, "high", "RSA")
    evidence = CryptoEvidence(
        "app.py:1-1",
        "app.py",
        1,
        1,
        "RSA",
        "RSA",
        None,
        "unknown",
        "static",
        [match],
    )
    analysis = SemanticAnalysis(
        evidence.evidence_id,
        True,
        True,
        "RSA",
        "key_generation",
        False,
        "real crypto usage",
        0.9,
        "{}",
    )
    risk = RiskAssessment(evidence.evidence_id, "quantum_vulnerable", 95, ["RSA"], "RSA risk")
    recommendation = MigrationRecommendation(
        evidence.evidence_id,
        "RSA detected",
        "Review protocol and migrate.",
        ["ML-KEM"],
        ["Protocol support may be required."],
        ["Identify actual usage."],
    )
    finding = Finding(evidence, analysis, risk, recommendation)
    report = AuditReport("target", "now", {"total_findings": 1}, [finding], [])

    assert source.line_count == 1
    assert report.findings[0].evidence.static_matches[0].algorithm_hint == "RSA"


def test_nested_model_lists_are_mutable_per_instance() -> None:
    first = AuditReport("a", "now", {}, [], [])
    second = AuditReport("b", "now", {}, [], [])

    first.errors.append("error")

    assert first.errors == ["error"]
    assert second.errors == []

