from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal


RiskLevel = Literal[
    "quantum_safe",
    "partially_vulnerable",
    "quantum_vulnerable",
    "unknown",
]

UsageType = Literal[
    "encryption",
    "signature",
    "key_exchange",
    "key_generation",
    "certificate_handling",
    "tls_configuration",
    "unknown",
]

ReportFormat = Literal["markdown", "json", "both"]

RISK_LEVELS: tuple[str, ...] = (
    "quantum_safe",
    "partially_vulnerable",
    "quantum_vulnerable",
    "unknown",
)

USAGE_TYPES: tuple[str, ...] = (
    "encryption",
    "signature",
    "key_exchange",
    "key_generation",
    "certificate_handling",
    "tls_configuration",
    "unknown",
)

REPORT_FORMATS: tuple[str, ...] = ("markdown", "json", "both")


@dataclass(slots=True)
class SourceFile:
    path: Path
    relative_path: str
    content: str
    line_count: int


@dataclass(slots=True)
class StaticMatch:
    file_path: str
    line_number: int
    rule_id: str
    matched_text: str
    algorithm_hint: str | None
    library_hint: str | None
    severity_hint: str
    line_text: str


@dataclass(slots=True)
class CryptoEvidence:
    evidence_id: str
    file_path: str
    start_line: int
    end_line: int
    snippet: str
    algorithm: str | None
    library: str | None
    usage_type: UsageType
    source: str
    static_matches: list[StaticMatch] = field(default_factory=list)


@dataclass(slots=True)
class SemanticAnalysis:
    evidence_id: str
    is_real_crypto_usage: bool
    is_security_sensitive: bool
    algorithm: str | None
    usage_type: UsageType | None
    is_test_or_example: bool
    explanation: str
    confidence: float
    raw_model_output: str


@dataclass(slots=True)
class RiskAssessment:
    evidence_id: str
    risk_level: RiskLevel
    risk_score: int
    risk_factors: list[str]
    reason: str


@dataclass(slots=True)
class MigrationRecommendation:
    evidence_id: str
    summary: str
    recommended_action: str
    candidate_pqc_algorithms: list[str]
    compatibility_notes: list[str]
    developer_steps: list[str]


@dataclass(slots=True)
class Finding:
    evidence: CryptoEvidence
    semantic_analysis: SemanticAnalysis
    risk_assessment: RiskAssessment
    recommendation: MigrationRecommendation


@dataclass(slots=True)
class AuditReport:
    target_path: str
    generated_at: str
    summary: dict[str, Any]
    findings: list[Finding]
    errors: list[str]

