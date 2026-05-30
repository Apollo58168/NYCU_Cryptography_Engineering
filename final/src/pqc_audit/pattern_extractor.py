from __future__ import annotations

from collections.abc import Iterable
from hashlib import sha256

from pqc_audit.models import (
    ConfidenceLevel,
    CryptoEvidence,
    EvidenceType,
    SourceFile,
    SourceKind,
    StaticMatch,
    UsageType,
)


class PatternExtractor:
    ALGORITHM_PRIORITY: tuple[str, ...] = (
        "RSA",
        "ECDSA",
        "ECDH",
        "ECC",
        "DH",
        "DSA",
        "HMAC",
        "AES",
        "SHA-3",
        "SHA-2",
        "SHA-512",
        "SHA-384",
        "SHA-256",
    )

    def __init__(self, max_snippet_lines: int = 7, context_lines: int = 2) -> None:
        if max_snippet_lines < 1:
            raise ValueError("max_snippet_lines must be positive")
        if context_lines < 0:
            raise ValueError("context_lines must not be negative")

        self.max_snippet_lines = max_snippet_lines
        self.context_lines = context_lines

    def extract(
        self,
        source_files: Iterable[SourceFile],
        matches: Iterable[StaticMatch],
    ) -> list[CryptoEvidence]:
        sources = self._index_sources(source_files)
        matches_by_file: dict[str, list[StaticMatch]] = {}

        for match in matches:
            if self._find_source(sources, match.file_path) is None:
                continue
            matches_by_file.setdefault(match.file_path, []).append(match)

        evidence: list[CryptoEvidence] = []
        for file_path in sorted(matches_by_file):
            source = self._find_source(sources, file_path)
            if source is None:
                continue

            file_matches = sorted(matches_by_file[file_path], key=self._match_sort_key)
            for group in self._group_matches(file_matches):
                start_line, end_line = self._snippet_bounds(source, group)
                snippet = self._snippet(source, start_line, end_line)
                evidence.append(
                    CryptoEvidence(
                        evidence_id=self._evidence_id(file_path, start_line, end_line, group),
                        file_path=file_path,
                        start_line=start_line,
                        end_line=end_line,
                        snippet=snippet,
                        algorithm=self._infer_algorithm(group),
                        library=self._infer_library(group),
                        usage_type=self._infer_usage_type(group),
                        source="static",
                        static_matches=list(group),
                        evidence_type=self._infer_evidence_type(group),
                        source_kind=self._infer_source_kind(group),
                        confidence=self._infer_confidence(group),
                    )
                )

        return evidence

    def _index_sources(self, source_files: Iterable[SourceFile]) -> dict[str, SourceFile]:
        sources: dict[str, SourceFile] = {}
        for source in source_files:
            sources[source.relative_path] = source
            sources[str(source.path)] = source
        return sources

    def _find_source(self, sources: dict[str, SourceFile], file_path: str) -> SourceFile | None:
        return sources.get(file_path)

    def _group_matches(self, matches: list[StaticMatch]) -> list[list[StaticMatch]]:
        groups: list[list[StaticMatch]] = []
        current: list[StaticMatch] = []

        for match in matches:
            if not current:
                current.append(match)
                continue

            candidate = [*current, match]
            first_line = min(item.line_number for item in candidate)
            last_line = max(item.line_number for item in candidate)
            if last_line - first_line + 1 <= self.max_snippet_lines:
                current.append(match)
            else:
                groups.append(current)
                current = [match]

        if current:
            groups.append(current)

        return groups

    def _snippet_bounds(self, source: SourceFile, matches: list[StaticMatch]) -> tuple[int, int]:
        first_line = max(1, min(match.line_number for match in matches))
        last_line = min(source.line_count, max(match.line_number for match in matches))

        start_line = max(1, first_line - self.context_lines)
        end_line = min(source.line_count, last_line + self.context_lines)

        if end_line - start_line + 1 <= self.max_snippet_lines:
            return start_line, end_line

        extra = self.max_snippet_lines - (last_line - first_line + 1)
        before = min(first_line - 1, max(0, extra // 2))
        after = max(0, extra - before)

        start_line = first_line - before
        end_line = min(source.line_count, last_line + after)

        if end_line - start_line + 1 < self.max_snippet_lines:
            start_line = max(1, end_line - self.max_snippet_lines + 1)

        return start_line, end_line

    def _snippet(self, source: SourceFile, start_line: int, end_line: int) -> str:
        lines = source.content.splitlines()
        return "\n".join(lines[start_line - 1 : end_line])

    def _evidence_id(
        self,
        file_path: str,
        start_line: int,
        end_line: int,
        matches: list[StaticMatch],
    ) -> str:
        parts = [file_path, str(start_line), str(end_line)]
        parts.extend(
            f"{match.line_number}:{match.rule_id}:{match.matched_text}" for match in matches
        )
        digest = sha256("|".join(parts).encode("utf-8")).hexdigest()[:12]
        return f"static:{digest}"

    def _infer_algorithm(self, matches: list[StaticMatch]) -> str | None:
        hints = " ".join(match.algorithm_hint or "" for match in matches)
        normalized_hints = hints.replace("Diffie-Hellman", "DH").replace("Diffie Hellman", "DH")
        normalized = normalized_hints.upper().replace("_", "-")
        tokens = {token.upper() for token in normalized.replace("/", " ").split()}

        for algorithm in self.ALGORITHM_PRIORITY:
            if algorithm in tokens or algorithm in normalized:
                return algorithm
        return None

    def _infer_library(self, matches: list[StaticMatch]) -> str | None:
        for match in matches:
            if match.library_hint:
                return match.library_hint
        return None

    def _infer_usage_type(self, matches: list[StaticMatch]) -> UsageType:
        text = " ".join(
            [
                *(match.rule_id for match in matches),
                *(match.matched_text for match in matches),
                *(match.line_text for match in matches),
            ]
        ).lower()

        if (
            "sslcontext" in text
            or "create_default_context" in text
            or "httpsurlconnection" in text
            or "sslsocketfactory" in text
            or "sslparameters" in text
            or "tlsv1." in text
        ):
            return "tls_configuration"
        if (
            "keystore" in text
            or "pemparser" in text
            or "jcapemkeyconverter" in text
            or "certificate" in text
            or "x509" in text
        ):
            return "certificate_handling"
        if (
            "generate_private_key" in text
            or "generatekeypair" in text
            or "keypairgenerator" in text
            or "generate_key" in text
            or "rsa_generate_key" in text
            or "dh_generate_parameters" in text
            or "evp_pkey_keygen" in text
            or "keygen" in text
        ):
            return "key_generation"
        if (
            "exchange" in text
            or "ecdh" in text
            or "keyagreement" in text
            or "dh_compute_key" in text
            or "diffiehellman" in text
            or "evp_pkey_derive" in text
            or "derive" in text
        ):
            return "key_exchange"
        if (
            "sign" in text
            or "verify" in text
            or "signature" in text
            or "digestsign" in text
            or "digestverify" in text
            or "signer" in text
        ):
            return "signature"
        if "hmac" in text or "mac.getinstance" in text or "createhmac" in text:
            return "mac"
        if (
            "aes" in text
            or "symmetric" in text
            or "evp_aes" in text
            or "keygenerator.getinstance" in text
        ):
            return "symmetric_encryption"
        if (
            "sha-256" in text
            or "sha-384" in text
            or "sha-512" in text
            or "sha2" in text
            or "sha3" in text
            or "sha256" in text
            or "sha384" in text
            or "sha512" in text
            or "messagedigest" in text
            or "evp_sha" in text
            or "digest(" in text
        ):
            return "hashing"
        if "cipher" in text or "encrypt" in text or "decrypt" in text:
            return "encryption"
        return "unknown"

    def _infer_evidence_type(self, matches: list[StaticMatch]) -> EvidenceType:
        priority: tuple[EvidenceType, ...] = (
            "api_call",
            "config",
            "import",
            "keyword",
            "comment_or_string",
            "unknown",
        )
        evidence_types = {match.evidence_type for match in matches}
        for evidence_type in priority:
            if evidence_type in evidence_types:
                return evidence_type
        return "unknown"

    def _infer_source_kind(self, matches: list[StaticMatch]) -> SourceKind:
        source_kinds = {match.source_kind for match in matches}
        if "code" in source_kinds:
            return "code"
        if "comment" in source_kinds:
            return "comment"
        if "string" in source_kinds:
            return "string"
        return "unknown"

    def _infer_confidence(self, matches: list[StaticMatch]) -> ConfidenceLevel:
        confidences = {match.confidence for match in matches}
        if "high" in confidences:
            return "high"
        if "medium" in confidences:
            return "medium"
        return "low"

    def _match_sort_key(self, match: StaticMatch) -> tuple[int, str, str]:
        return (match.line_number, match.rule_id, match.matched_text)
