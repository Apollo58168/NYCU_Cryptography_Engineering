from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Callable, Protocol

from pqc_audit.config import AppConfig
from pqc_audit.models import CryptoEvidence, SemanticAnalysis


class GeminiTransport(Protocol):
    def generate(self, prompt: str) -> str:
        ...


@dataclass(slots=True)
class GeminiRestTransport:
    api_key: str
    model: str
    max_retries: int = 3
    initial_retry_delay: float = 2.0
    backoff_factor: float = 2.0
    sleep: Callable[[float], None] = time.sleep
    urlopen: Callable[..., object] = field(default=urllib.request.urlopen)

    def generate(self, prompt: str) -> str:
        response_body = self._request_with_retry(prompt)

        try:
            return response_body["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError) as exc:
            raise RuntimeError("Gemini response did not contain generated text") from exc

    def _request_with_retry(self, prompt: str) -> dict[str, object]:
        url = (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.model}:generateContent?key={self.api_key}"
        )
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": prompt,
                        }
                    ]
                }
            ],
            "generationConfig": {
                "temperature": 0,
                "responseMimeType": "application/json",
            },
        }
        request = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        last_error: Exception | None = None
        for attempt in range(self.max_retries + 1):
            try:
                with self.urlopen(request, timeout=30) as response:
                    return json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", errors="replace")
                error = GeminiHTTPError(exc.code, body)
                if not should_retry_http_error(error) or attempt >= self.max_retries:
                    raise RuntimeError(f"Gemini request failed: {error}") from exc
                last_error = error
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt >= self.max_retries:
                    raise RuntimeError(f"Gemini request failed: {exc}") from exc
                last_error = exc
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"Gemini request failed: {exc}") from exc

            self.sleep(self._retry_delay(attempt))

        raise RuntimeError(f"Gemini request failed: {last_error}")

    def _retry_delay(self, attempt: int) -> float:
        return self.initial_retry_delay * (self.backoff_factor**attempt)


@dataclass(slots=True)
class GeminiHTTPError(Exception):
    status_code: int
    body: str

    def __str__(self) -> str:
        summary = extract_gemini_error_message(self.body)
        if summary:
            return f"HTTP {self.status_code}: {summary}"
        return f"HTTP {self.status_code}"


def should_retry_http_error(error: GeminiHTTPError) -> bool:
    if error.status_code in {401, 403}:
        return False
    if error.status_code == 429 and "prepayment credits are depleted" in error.body.lower():
        return False
    return error.status_code == 429 or 500 <= error.status_code <= 599


def extract_gemini_error_message(body: str) -> str | None:
    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return body[:300] if body else None

    error = data.get("error")
    if isinstance(error, dict):
        message = error.get("message")
        status = error.get("status")
        if isinstance(message, str) and isinstance(status, str):
            return f"{status}: {message}"
        if isinstance(message, str):
            return message
    return None


class SemanticAnalyzer:
    def __init__(self, config: AppConfig, transport: GeminiTransport | None = None) -> None:
        if transport is None:
            if not config.gemini_api_key:
                raise ValueError("Gemini API key is required")
            transport = GeminiRestTransport(config.gemini_api_key, config.gemini_model)
        self.transport = transport

    def analyze(self, evidence_items: list[CryptoEvidence]) -> list[SemanticAnalysis]:
        return [self._analyze_one(evidence) for evidence in evidence_items]

    def _analyze_one(self, evidence: CryptoEvidence) -> SemanticAnalysis:
        prompt = build_prompt(evidence)
        try:
            raw_output = self.transport.generate(prompt)
            data = parse_json_object(raw_output)
            return SemanticAnalysis(
                evidence_id=evidence.evidence_id,
                is_real_crypto_usage=bool(data["is_real_crypto_usage"]),
                is_security_sensitive=bool(data["is_security_sensitive"]),
                algorithm=data.get("algorithm"),
                usage_type=data.get("usage_type"),
                is_test_or_example=bool(data["is_test_or_example"]),
                explanation=str(data["explanation"]),
                confidence=float(data["confidence"]),
                raw_model_output=raw_output,
            )
        except Exception as exc:
            return fallback_analysis(evidence, f"Gemini analysis failed: {exc}")


def build_prompt(evidence: CryptoEvidence) -> str:
    algorithm_hint = evidence.algorithm or "null"
    library_hint = evidence.library or "null"
    return f"""You are auditing Python source code for cryptographic usage and post-quantum migration risk.

Return JSON only with these fields:
- is_real_crypto_usage: boolean
- is_security_sensitive: boolean
- algorithm: string or null
- usage_type: string or null
- is_test_or_example: boolean
- explanation: string
- confidence: number between 0 and 1

Evidence metadata:
- evidence_id: {evidence.evidence_id}
- file_path: {evidence.file_path}
- start_line: {evidence.start_line}
- end_line: {evidence.end_line}
- static_algorithm_hint: {algorithm_hint}
- static_library_hint: {library_hint}

Code snippet:
```python
{evidence.snippet}
```
"""


def parse_json_object(raw_output: str) -> dict[str, object]:
    text = raw_output.strip()
    if text.startswith("```"):
        lines = text.splitlines()
        if lines and lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()

    data = json.loads(text)
    required = {
        "is_real_crypto_usage",
        "is_security_sensitive",
        "algorithm",
        "usage_type",
        "is_test_or_example",
        "explanation",
        "confidence",
    }
    missing = required.difference(data)
    if missing:
        raise ValueError(f"Missing Gemini fields: {sorted(missing)}")
    return data


def fallback_analysis(evidence: CryptoEvidence, explanation: str) -> SemanticAnalysis:
    return SemanticAnalysis(
        evidence_id=evidence.evidence_id,
        is_real_crypto_usage=True,
        is_security_sensitive=True,
        algorithm=evidence.algorithm,
        usage_type=evidence.usage_type,
        is_test_or_example=False,
        explanation=explanation,
        confidence=0.0,
        raw_model_output="",
    )
