"""Secrets redaction utility (Spec P10)."""

from __future__ import annotations

import re

_REDACTION_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "REDACTED_AWS_KEY"),
    (
        re.compile(r"(?i)(aws_secret(?:_access)?_key\s*[:=]\s*[\"']?)([A-Za-z0-9/+=]{20,})([\"']?)"),
        r"\1REDACTED_AWS_SECRET\3",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "REDACTED_API_KEY"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "REDACTED_GH_TOKEN"),
    (
        re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
        "REDACTED_PRIVATE_KEY",
    ),
    (re.compile(r"(?i)(Bearer\s+)[A-Za-z0-9._-]{16,}"), r"\1REDACTED_TOKEN"),
    (
        re.compile(
            r"(?i)(\b(?:db_password|password|passwd|pwd|secret|api_key|azure_openai_key|access_token|auth_token|token)\b\s*[:=]\s*[\"'])([^\"'\r\n]{4,})([\"'])"
        ),
        r"\1REDACTED_SECRET\3",
    ),
    (re.compile(r"(?i)(://[^:/\s]+:)([^@/\s]+)(@)"), r"\1REDACTED_PASSWORD\3"),
]


def redact_secrets(text: str) -> str:
    if not text:
        return text
    out = text
    for pattern, replacement in _REDACTION_RULES:
        out = pattern.sub(replacement, out)
    return out


def contains_secret(text: str) -> bool:
    if not text:
        return False
    return redact_secrets(text) != text
