from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from pqc_audit.models import AuditReport, Finding, RISK_LEVELS


class ReportGenerator:
    def generate(self, target_path: str | Path, findings: list[Finding], errors: list[str]) -> AuditReport:
        summary = self._build_summary(findings)
        generated_at = datetime.now(timezone.utc).isoformat()

        return AuditReport(
            target_path=str(target_path),
            generated_at=generated_at,
            summary=summary,
            findings=findings,
            errors=errors,
        )

    def write_markdown(self, report: AuditReport, output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self._to_markdown(report), encoding="utf-8")

    def write_json(self, report: AuditReport, output_path: str | Path) -> None:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(asdict(report), ensure_ascii=False, indent=2),
            encoding="utf-8",
        )

    def _build_summary(self, findings: list[Finding]) -> dict[str, Any]:
        summary: dict[str, Any] = {"total_findings": len(findings)}
        for risk_level in RISK_LEVELS:
            summary[risk_level] = 0

        for finding in findings:
            summary[finding.risk_assessment.risk_level] += 1

        return summary

    def _to_markdown(self, report: AuditReport) -> str:
        lines = [
            "# PQC Audit Security Report",
            "",
            "## Scan Summary",
            "",
            f"- Target path: `{report.target_path}`",
            f"- Generated at: `{report.generated_at}`",
            f"- Total findings: {report.summary['total_findings']}",
            "",
            "## Risk Summary",
            "",
            "| Risk level | Count |",
            "| --- | ---: |",
        ]

        for risk_level in RISK_LEVELS:
            lines.append(f"| {risk_level} | {report.summary[risk_level]} |")

        lines.extend(
            [
                "",
                "## Findings Table",
                "",
                "| Evidence ID | File | Lines | Algorithm | Usage | Risk | Score |",
                "| --- | --- | --- | --- | --- | --- | ---: |",
            ]
        )

        if report.findings:
            for finding in report.findings:
                evidence = finding.evidence
                analysis = finding.semantic_analysis
                risk = finding.risk_assessment
                algorithm = evidence.algorithm or analysis.algorithm or "unknown"
                usage_type = evidence.usage_type or analysis.usage_type or "unknown"
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            self._escape_table(evidence.evidence_id),
                            self._escape_table(evidence.file_path),
                            f"{evidence.start_line}-{evidence.end_line}",
                            self._escape_table(algorithm),
                            self._escape_table(usage_type),
                            risk.risk_level,
                            str(risk.risk_score),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("| No findings | - | - | - | - | - | - |")

        lines.extend(["", "## Detailed Findings", ""])
        if report.findings:
            for index, finding in enumerate(report.findings, start=1):
                lines.extend(self._finding_detail(index, finding))
        else:
            lines.append("No findings detected.")

        lines.extend(["", "## Errors and Skipped Files", ""])
        if report.errors:
            for error in report.errors:
                lines.append(f"- {error}")
        else:
            lines.append("No errors or skipped files.")

        lines.extend(["", "## Migration Summary", ""])
        if report.findings:
            for finding in report.findings:
                recommendation = finding.recommendation
                lines.append(f"- `{recommendation.evidence_id}`: {recommendation.summary}")
        else:
            lines.append("No migration actions are required based on current findings.")

        lines.append("")
        return "\n".join(lines)

    def _finding_detail(self, index: int, finding: Finding) -> list[str]:
        evidence = finding.evidence
        analysis = finding.semantic_analysis
        risk = finding.risk_assessment
        recommendation = finding.recommendation

        lines = [
            f"### Finding {index}: {evidence.evidence_id}",
            "",
            f"- File: `{evidence.file_path}`",
            f"- Lines: {evidence.start_line}-{evidence.end_line}",
            f"- Algorithm: {evidence.algorithm or analysis.algorithm or 'unknown'}",
            f"- Library: {evidence.library or 'unknown'}",
            f"- Usage type: {evidence.usage_type or analysis.usage_type or 'unknown'}",
            f"- Risk level: {risk.risk_level}",
            f"- Risk score: {risk.risk_score}",
            f"- Risk reason: {risk.reason}",
            f"- Semantic analysis: {analysis.explanation}",
            f"- Recommended action: {recommendation.recommended_action}",
        ]

        if recommendation.candidate_pqc_algorithms:
            lines.append(
                "- Candidate PQC algorithms: "
                + ", ".join(recommendation.candidate_pqc_algorithms)
            )

        if recommendation.compatibility_notes:
            lines.append("- Compatibility notes:")
            for note in recommendation.compatibility_notes:
                lines.append(f"  - {note}")

        if recommendation.developer_steps:
            lines.append("- Developer steps:")
            for step in recommendation.developer_steps:
                lines.append(f"  - {step}")

        if evidence.snippet:
            lines.extend(["", "```text", evidence.snippet, "```"])

        lines.append("")
        return lines

    def _escape_table(self, value: str) -> str:
        return value.replace("|", "\\|").replace("\n", " ")
