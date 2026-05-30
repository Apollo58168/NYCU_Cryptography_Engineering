from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from pqc_audit.models import (
    CryptoEvidence,
    Finding,
    MigrationRecommendation,
    RiskAssessment,
    SemanticAnalysis,
)
from pqc_audit.report_generator import ReportGenerator


def make_finding(evidence_id: str, risk_level: str, risk_score: int = 80) -> Finding:
    evidence = CryptoEvidence(
        evidence_id=evidence_id,
        file_path="app.py",
        start_line=10,
        end_line=12,
        snippet="private_key = rsa.generate_private_key()",
        algorithm="RSA",
        library="cryptography",
        usage_type="key_generation",
        source="static",
    )
    analysis = SemanticAnalysis(
        evidence_id=evidence_id,
        is_real_crypto_usage=True,
        is_security_sensitive=True,
        algorithm="RSA",
        usage_type="key_generation",
        is_test_or_example=False,
        explanation="RSA key generation was detected.",
        confidence=0.95,
        raw_model_output="{}",
    )
    risk = RiskAssessment(
        evidence_id=evidence_id,
        risk_level=risk_level,  # type: ignore[arg-type]
        risk_score=risk_score,
        risk_factors=["RSA"],
        reason="RSA is vulnerable to Shor's Algorithm.",
    )
    recommendation = MigrationRecommendation(
        evidence_id=evidence_id,
        summary="Migrate RSA key establishment.",
        recommended_action="Review the protocol and plan a PQC migration.",
        candidate_pqc_algorithms=["ML-KEM"],
        compatibility_notes=["Protocol support may be required."],
        developer_steps=["Identify the production usage."],
    )

    return Finding(evidence, analysis, risk, recommendation)


def test_generate_builds_summary_counts(tmp_path: Path) -> None:
    findings = [
        make_finding("app.py:10-12", "quantum_vulnerable"),
        make_finding("tls.py:3-4", "partially_vulnerable"),
        make_finding("aes.py:7-7", "quantum_safe"),
        make_finding("unknown.py:1-1", "unknown"),
    ]

    report = ReportGenerator().generate(tmp_path, findings, ["skipped binary file"])

    assert report.target_path == str(tmp_path)
    assert datetime.fromisoformat(report.generated_at)
    assert report.summary == {
        "total_findings": 4,
        "quantum_safe": 1,
        "partially_vulnerable": 1,
        "quantum_vulnerable": 1,
        "unknown": 1,
    }
    assert report.findings == findings
    assert report.errors == ["skipped binary file"]


def test_write_markdown_contains_report_sections(tmp_path: Path) -> None:
    report = ReportGenerator().generate(
        "example_project",
        [make_finding("app.py:10-12", "quantum_vulnerable", 95)],
        ["failed to read ignored.py"],
    )
    output_path = tmp_path / "nested" / "security-report.md"

    ReportGenerator().write_markdown(report, output_path)

    content = output_path.read_text(encoding="utf-8")
    assert "# PQC Audit Security Report" in content
    assert "## Scan Summary" in content
    assert "## Risk Summary" in content
    assert "## Findings Table" in content
    assert "## Detailed Findings" in content
    assert "## Errors and Skipped Files" in content
    assert "## Migration Summary" in content
    assert "| app.py:10-12 | app.py | 10-12 | RSA | key_generation | quantum_vulnerable | 95 |" in content
    assert "RSA is vulnerable to Shor's Algorithm." in content
    assert "failed to read ignored.py" in content
    assert "ML-KEM" in content


def test_write_json_outputs_valid_report(tmp_path: Path) -> None:
    report = ReportGenerator().generate(
        "example_project",
        [make_finding("app.py:10-12", "quantum_vulnerable")],
        ["skipped vendor.zip"],
    )
    output_path = tmp_path / "nested" / "security-report.json"

    ReportGenerator().write_json(report, output_path)

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["target_path"] == "example_project"
    assert data["generated_at"] == report.generated_at
    assert data["summary"]["total_findings"] == 1
    assert data["summary"]["quantum_vulnerable"] == 1
    assert data["findings"][0]["evidence"]["algorithm"] == "RSA"
    assert data["errors"] == ["skipped vendor.zip"]


def test_empty_report_output(tmp_path: Path) -> None:
    generator = ReportGenerator()
    report = generator.generate("empty_project", [], [])
    markdown_path = tmp_path / "security-report.md"
    json_path = tmp_path / "security-report.json"

    generator.write_markdown(report, markdown_path)
    generator.write_json(report, json_path)

    assert report.summary == {
        "total_findings": 0,
        "quantum_safe": 0,
        "partially_vulnerable": 0,
        "quantum_vulnerable": 0,
        "unknown": 0,
    }
    assert "No findings detected." in markdown_path.read_text(encoding="utf-8")
    assert json.loads(json_path.read_text(encoding="utf-8"))["findings"] == []


def test_report_generation_does_not_require_gemini(monkeypatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    report = ReportGenerator().generate("target", [], [])

    assert report.summary["total_findings"] == 0
