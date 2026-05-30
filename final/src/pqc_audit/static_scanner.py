from __future__ import annotations

import ast
import re
from collections.abc import Iterable
from dataclasses import dataclass

from pqc_audit.models import SourceFile, StaticMatch


@dataclass(frozen=True, slots=True)
class _Rule:
    rule_id: str
    pattern: re.Pattern[str]
    algorithm_hint: str
    library_hint: str | None


_TEXT_RULES: tuple[_Rule, ...] = (
    _Rule(
        "pycryptodome_crypto_rsa",
        re.compile(r"\bCrypto\.PublicKey\.RSA\b"),
        "RSA",
        "PyCryptodome",
    ),
    _Rule(
        "pycryptodome_cryptodome_rsa",
        re.compile(r"\bCryptodome\.PublicKey\.RSA\b"),
        "RSA",
        "PyCryptodome",
    ),
    _Rule("keyword_diffie_hellman", re.compile(r"\bDiffie-Hellman\b"), "Diffie-Hellman", None),
    _Rule("keyword_ecdsa", re.compile(r"\bECDSA\b"), "ECDSA", None),
    _Rule("keyword_ecdh", re.compile(r"\bECDH\b"), "ECDH", None),
    _Rule("keyword_rsa", re.compile(r"\bRSA\b"), "RSA", None),
    _Rule("keyword_ecc", re.compile(r"\bECC\b"), "ECC", None),
    _Rule("keyword_dh", re.compile(r"\bDH\b"), "DH", None),
)

_CRYPTOGRAPHY_IMPORTS = {
    "rsa": ("cryptography_import_rsa", "RSA"),
    "ec": ("cryptography_import_ec", "ECC"),
    "dh": ("cryptography_import_dh", "Diffie-Hellman"),
}

_CALL_RULES = {
    ("rsa", "generate_private_key"): ("cryptography_rsa_generate_private_key", "RSA", "cryptography"),
    ("ec", "generate_private_key"): ("cryptography_ec_generate_private_key", "ECC", "cryptography"),
    ("dh", "generate_parameters"): ("cryptography_dh_generate_parameters", "Diffie-Hellman", "cryptography"),
    ("ssl", "SSLContext"): ("ssl_context", "TLS", "ssl"),
    ("ssl", "create_default_context"): ("ssl_create_default_context", "TLS", "ssl"),
}


class StaticScanner:
    def scan(self, source_files: Iterable[SourceFile]) -> list[StaticMatch]:
        matches: list[StaticMatch] = []

        for source_file in source_files:
            file_matches: list[StaticMatch] = []
            try:
                tree = ast.parse(source_file.content, filename=source_file.relative_path)
            except SyntaxError:
                tree = None

            if tree is not None:
                file_matches.extend(self._scan_ast(source_file, tree))

            file_matches.extend(self._scan_text(source_file))
            matches.extend(self._dedupe(file_matches))

        return matches

    def _scan_ast(self, source_file: SourceFile, tree: ast.AST) -> list[StaticMatch]:
        matches: list[StaticMatch] = []
        lines = source_file.content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                matches.extend(self._match_import_from(source_file, lines, node))
            elif isinstance(node, ast.Import):
                matches.extend(self._match_import(source_file, lines, node))
            elif isinstance(node, ast.Call):
                match = self._match_call(source_file, lines, node)
                if match is not None:
                    matches.append(match)

        return matches

    def _match_import_from(
        self,
        source_file: SourceFile,
        lines: list[str],
        node: ast.ImportFrom,
    ) -> list[StaticMatch]:
        matches: list[StaticMatch] = []

        if node.module == "cryptography.hazmat.primitives.asymmetric":
            for alias in node.names:
                rule = _CRYPTOGRAPHY_IMPORTS.get(alias.name)
                if rule is None:
                    continue
                rule_id, algorithm_hint = rule
                matches.append(
                    self._build_match(
                        source_file,
                        node.lineno,
                        rule_id,
                        alias.name,
                        algorithm_hint,
                        "cryptography",
                        lines,
                    )
                )

        if node.module in {"Crypto.PublicKey", "Cryptodome.PublicKey"}:
            for alias in node.names:
                if alias.name == "RSA":
                    matches.append(
                        self._build_match(
                            source_file,
                            node.lineno,
                            "pycryptodome_import_rsa",
                            alias.name,
                            "RSA",
                            "PyCryptodome",
                            lines,
                        )
                    )

        return matches

    def _match_import(
        self,
        source_file: SourceFile,
        lines: list[str],
        node: ast.Import,
    ) -> list[StaticMatch]:
        matches: list[StaticMatch] = []

        for alias in node.names:
            if alias.name in {"Crypto.PublicKey.RSA", "Cryptodome.PublicKey.RSA"}:
                matches.append(
                    self._build_match(
                        source_file,
                        node.lineno,
                        "pycryptodome_import_rsa",
                        alias.name,
                        "RSA",
                        "PyCryptodome",
                        lines,
                    )
                )

        return matches

    def _match_call(
        self,
        source_file: SourceFile,
        lines: list[str],
        node: ast.Call,
    ) -> StaticMatch | None:
        call_name = self._attribute_parts(node.func)
        if len(call_name) < 2:
            return None

        rule = _CALL_RULES.get((call_name[-2], call_name[-1]))
        if rule is None:
            return None

        rule_id, algorithm_hint, library_hint = rule
        return self._build_match(
            source_file,
            node.lineno,
            rule_id,
            ".".join(call_name[-2:]),
            algorithm_hint,
            library_hint,
            lines,
        )

    def _scan_text(self, source_file: SourceFile) -> list[StaticMatch]:
        matches: list[StaticMatch] = []
        lines = source_file.content.splitlines()

        for line_number, line in enumerate(lines, start=1):
            for rule in _TEXT_RULES:
                for match in rule.pattern.finditer(line):
                    matches.append(
                        self._build_match(
                            source_file,
                            line_number,
                            rule.rule_id,
                            match.group(0),
                            rule.algorithm_hint,
                            rule.library_hint,
                            lines,
                        )
                    )

        return matches

    def _attribute_parts(self, node: ast.AST) -> tuple[str, ...]:
        if isinstance(node, ast.Name):
            return (node.id,)
        if isinstance(node, ast.Attribute):
            return (*self._attribute_parts(node.value), node.attr)
        return ()

    def _build_match(
        self,
        source_file: SourceFile,
        line_number: int,
        rule_id: str,
        matched_text: str,
        algorithm_hint: str | None,
        library_hint: str | None,
        lines: list[str],
    ) -> StaticMatch:
        line_text = lines[line_number - 1].strip() if 0 < line_number <= len(lines) else ""
        return StaticMatch(
            source_file.relative_path,
            line_number,
            rule_id,
            matched_text,
            algorithm_hint,
            library_hint,
            "high",
            line_text,
        )

    def _dedupe(self, matches: list[StaticMatch]) -> list[StaticMatch]:
        seen: set[tuple[str, int, str, str]] = set()
        deduped: list[StaticMatch] = []

        for match in matches:
            key = (match.file_path, match.line_number, match.rule_id, match.matched_text)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(match)

        return deduped
