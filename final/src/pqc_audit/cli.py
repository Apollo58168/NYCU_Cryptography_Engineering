from __future__ import annotations

import argparse
from pathlib import Path
from typing import Sequence

from pqc_audit.config import DEFAULT_GEMINI_MODEL, ConfigError, build_config
from pqc_audit.pipeline import AuditPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pqc-audit",
        description="Audit Python projects for quantum-vulnerable cryptographic usage.",
    )
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--format", default="both", choices=("markdown", "json", "both"))
    parser.add_argument("--max-snippet-lines", default=40, type=int)
    parser.add_argument("--gemini-model", default=DEFAULT_GEMINI_MODEL)
    parser.add_argument("--skip-ai", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        config = build_config(
            target_path=args.target,
            output_dir=args.output,
            report_format=args.format,
            max_snippet_lines=args.max_snippet_lines,
            skip_ai=args.skip_ai,
            gemini_model=args.gemini_model,
        )
        report = AuditPipeline().run(config)
    except (ConfigError, ValueError, OSError, RuntimeError) as exc:
        print(f"error: {exc}")
        return 1

    print(f"Audit complete. Findings: {report.summary['total_findings']}")
    if config.report_format in {"markdown", "both"}:
        print(f"Markdown report: {config.output_dir / 'security-report.md'}")
    if config.report_format in {"json", "both"}:
        print(f"JSON report: {config.output_dir / 'security-report.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
