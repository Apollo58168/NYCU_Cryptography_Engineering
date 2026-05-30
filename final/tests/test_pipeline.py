from pathlib import Path

from pqc_audit.config import AppConfig
from pqc_audit.models import (
    CryptoEvidence,
    MigrationRecommendation,
    RiskAssessment,
    SemanticAnalysis,
    SourceFile,
    StaticMatch,
)
from pqc_audit.pipeline import AuditPipeline, static_fallback_analysis
from pqc_audit.repository import RepositoryScanResult


class FakeScanner:
    def __init__(self, calls: list[str]) -> None:
        self.calls = calls

    def scan(self, source_files: list[SourceFile]) -> list[StaticMatch]:
        self.calls.append("scan")
        return [
            StaticMatch("app.py", 1, "rule", "RSA", "RSA", "cryptography", "high", "RSA")
        ]


class FakeExtractor:
    def __init__(self, calls: list[str], evidence: CryptoEvidence) -> None:
        self.calls = calls
        self.evidence = evidence

    def extract(
        self,
        source_files: list[SourceFile],
        matches: list[StaticMatch],
    ) -> list[CryptoEvidence]:
        self.calls.append("extract")
        return [self.evidence]


class FakeAnalyzer:
    def __init__(self, calls: list[str], evidence: CryptoEvidence) -> None:
        self.calls = calls
        self.evidence = evidence

    def analyze(self, evidence_items: list[CryptoEvidence]) -> list[SemanticAnalysis]:
        self.calls.append("analyze")
        return [
            SemanticAnalysis(
                self.evidence.evidence_id,
                True,
                True,
                "RSA",
                "key_generation",
                False,
                "analysis",
                0.9,
                "{}",
            )
        ]


class FakeAssessor:
    def __init__(self, calls: list[str], evidence: CryptoEvidence) -> None:
        self.calls = calls
        self.evidence = evidence

    def assess(
        self,
        evidence_items: list[CryptoEvidence],
        analyses: list[SemanticAnalysis],
    ) -> list[RiskAssessment]:
        self.calls.append("assess")
        return [RiskAssessment(self.evidence.evidence_id, "quantum_vulnerable", 95, ["RSA"], "risk")]


class FakeRecommender:
    def __init__(self, calls: list[str], evidence: CryptoEvidence) -> None:
        self.calls = calls
        self.evidence = evidence

    def recommend(
        self,
        evidence_items: list[CryptoEvidence],
        analyses: list[SemanticAnalysis],
        risks: list[RiskAssessment],
    ) -> list[MigrationRecommendation]:
        self.calls.append("recommend")
        return [
            MigrationRecommendation(
                self.evidence.evidence_id,
                "summary",
                "action",
                ["ML-KEM"],
                ["note"],
                ["step"],
            )
        ]


def make_evidence() -> CryptoEvidence:
    return CryptoEvidence(
        "e1",
        "app.py",
        1,
        1,
        "RSA",
        "RSA",
        "cryptography",
        "key_generation",
        "static",
        [],
    )


def make_config(tmp_path: Path, *, skip_ai: bool = False, report_format: str = "both") -> AppConfig:
    return AppConfig(
        target_path=tmp_path,
        output_dir=tmp_path / "reports",
        report_format=report_format,  # type: ignore[arg-type]
        gemini_api_key=None if skip_ai else "key",
        skip_ai=skip_ai,
    )


def test_pipeline_execution_order_and_report_files(tmp_path: Path) -> None:
    source = SourceFile(tmp_path / "app.py", "app.py", "RSA\n", 1)
    calls: list[str] = []
    evidence = make_evidence()

    def load_repository(target_path: Path) -> RepositoryScanResult:
        calls.append("repository")
        return RepositoryScanResult([source], ["recoverable"])

    pipeline = AuditPipeline(
        repository_loader=load_repository,
        scanner=FakeScanner(calls),
        extractor=FakeExtractor(calls, evidence),
        analyzer=FakeAnalyzer(calls, evidence),
        assessor=FakeAssessor(calls, evidence),
        recommender=FakeRecommender(calls, evidence),
    )

    report = pipeline.run(make_config(tmp_path))

    assert calls == ["repository", "scan", "extract", "analyze", "assess", "recommend"]
    assert report.summary["total_findings"] == 1
    assert report.errors == ["recoverable"]
    assert (tmp_path / "reports" / "security-report.md").exists()
    assert (tmp_path / "reports" / "security-report.json").exists()


def test_skip_ai_bypasses_analyzer(tmp_path: Path) -> None:
    source = SourceFile(tmp_path / "app.py", "app.py", "RSA\n", 1)
    calls: list[str] = []
    evidence = make_evidence()

    def load_repository(target_path: Path) -> RepositoryScanResult:
        calls.append("repository")
        return RepositoryScanResult([source], [])

    pipeline = AuditPipeline(
        repository_loader=load_repository,
        scanner=FakeScanner(calls),
        extractor=FakeExtractor(calls, evidence),
        analyzer=FakeAnalyzer(calls, evidence),
        assessor=FakeAssessor(calls, evidence),
        recommender=FakeRecommender(calls, evidence),
    )

    report = pipeline.run(make_config(tmp_path, skip_ai=True, report_format="json"))

    assert "analyze" not in calls
    assert report.findings[0].semantic_analysis.explanation.startswith("AI analysis skipped")
    assert (tmp_path / "reports" / "security-report.json").exists()
    assert not (tmp_path / "reports" / "security-report.md").exists()


def test_static_fallback_analysis_uses_evidence_fields() -> None:
    evidence = make_evidence()

    analysis = static_fallback_analysis(evidence)

    assert analysis.evidence_id == evidence.evidence_id
    assert analysis.algorithm == "RSA"
    assert analysis.usage_type == "key_generation"
    assert analysis.confidence == 0.5
