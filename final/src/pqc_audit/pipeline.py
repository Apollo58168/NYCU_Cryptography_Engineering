from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from pqc_audit.config import AppConfig
from pqc_audit.gemini_analyzer import SemanticAnalyzer
from pqc_audit.migration_recommender import MigrationRecommender
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
from pqc_audit.pattern_extractor import PatternExtractor
from pqc_audit.report_generator import ReportGenerator
from pqc_audit.repository import RepositoryScanResult, scan_repository
from pqc_audit.risk_assessor import RiskAssessor
from pqc_audit.static_scanner import StaticScanner


class RepositoryLoader(Protocol):
    def __call__(self, target_path: Path) -> RepositoryScanResult:
        ...


class Scanner(Protocol):
    def scan(self, source_files: list[SourceFile]) -> list[StaticMatch]:
        ...


class Extractor(Protocol):
    def extract(
        self,
        source_files: list[SourceFile],
        matches: list[StaticMatch],
    ) -> list[CryptoEvidence]:
        ...


class Analyzer(Protocol):
    def analyze(self, evidence_items: list[CryptoEvidence]) -> list[SemanticAnalysis]:
        ...


class Assessor(Protocol):
    def assess(
        self,
        evidence_items: list[CryptoEvidence],
        analyses: list[SemanticAnalysis],
    ) -> list[RiskAssessment]:
        ...


class Recommender(Protocol):
    def recommend(
        self,
        evidence_items: list[CryptoEvidence],
        analyses: list[SemanticAnalysis],
        risks: list[RiskAssessment],
    ) -> list[MigrationRecommendation]:
        ...


@dataclass(slots=True)
class AuditPipeline:
    repository_loader: RepositoryLoader = scan_repository
    scanner: Scanner | None = None
    extractor: Extractor | None = None
    analyzer: Analyzer | None = None
    assessor: Assessor | None = None
    recommender: Recommender | None = None
    reporter: ReportGenerator | None = None

    def run(self, config: AppConfig) -> AuditReport:
        config.validate()
        reporter = self.reporter or ReportGenerator()
        repository_result = self.repository_loader(config.target_path)
        source_files = repository_result.source_files
        errors = list(repository_result.errors)

        scanner = self.scanner or StaticScanner()
        extractor = self.extractor or PatternExtractor(max_snippet_lines=config.max_snippet_lines)
        assessor = self.assessor or RiskAssessor()
        recommender = self.recommender or MigrationRecommender()

        matches = scanner.scan(source_files)
        evidence_items = extractor.extract(source_files, matches)
        analyses = self._analyze(config, evidence_items)
        risks = assessor.assess(evidence_items, analyses)
        recommendations = recommender.recommend(evidence_items, analyses, risks)
        findings = build_findings(evidence_items, analyses, risks, recommendations)

        report = reporter.generate(config.target_path, findings, errors)
        self._write_reports(config, reporter, report)
        return report

    def _analyze(
        self,
        config: AppConfig,
        evidence_items: list[CryptoEvidence],
    ) -> list[SemanticAnalysis]:
        if config.skip_ai:
            return [static_fallback_analysis(evidence) for evidence in evidence_items]

        analyzer = self.analyzer or SemanticAnalyzer(config)
        return analyzer.analyze(evidence_items)

    def _write_reports(
        self,
        config: AppConfig,
        reporter: ReportGenerator,
        report: AuditReport,
    ) -> None:
        if config.report_format in {"markdown", "both"}:
            reporter.write_markdown(report, config.output_dir / "security-report.md")
        if config.report_format in {"json", "both"}:
            reporter.write_json(report, config.output_dir / "security-report.json")


def static_fallback_analysis(evidence: CryptoEvidence) -> SemanticAnalysis:
    confidence_by_level = {"high": 0.9, "medium": 0.65, "low": 0.35}
    return SemanticAnalysis(
        evidence_id=evidence.evidence_id,
        is_real_crypto_usage=True,
        is_security_sensitive=True,
        algorithm=evidence.algorithm,
        usage_type=evidence.usage_type,
        is_test_or_example=False,
        explanation="AI analysis skipped; result based on static scanner evidence.",
        confidence=confidence_by_level[evidence.confidence],
        raw_model_output="",
    )


def build_findings(
    evidence_items: list[CryptoEvidence],
    analyses: list[SemanticAnalysis],
    risks: list[RiskAssessment],
    recommendations: list[MigrationRecommendation],
) -> list[Finding]:
    analyses_by_id = {analysis.evidence_id: analysis for analysis in analyses}
    risks_by_id = {risk.evidence_id: risk for risk in risks}
    recommendations_by_id = {
        recommendation.evidence_id: recommendation for recommendation in recommendations
    }
    findings: list[Finding] = []

    for evidence in evidence_items:
        analysis = analyses_by_id.get(evidence.evidence_id)
        risk = risks_by_id.get(evidence.evidence_id)
        recommendation = recommendations_by_id.get(evidence.evidence_id)
        if analysis is None or risk is None or recommendation is None:
            continue
        findings.append(Finding(evidence, analysis, risk, recommendation))

    return findings
