"""Redaction utilities for sensitive data and PII masking."""

import re
from typing import Any, Dict, Optional

_PATTERNS = [
    (re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}", re.IGNORECASE), "[REDACTED_API_KEY]"),
    (re.compile(r"ghp_[a-zA-Z0-9]{36}", re.IGNORECASE), "[REDACTED_GITHUB_TOKEN]"),
    (re.compile(r"AKIA[0-9A-Z]{16}", re.IGNORECASE), "[REDACTED_AWS_KEY]"),
    (re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{16,}", re.IGNORECASE), "Bearer [REDACTED_TOKEN]"),
    (re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6011[0-9]{12})\b"), "[REDACTED_CREDIT_CARD]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
]


def redact_sensitive_data(text: str) -> str:
    """Masks sensitive API keys, tokens, and PII in text strings."""
    if not text:
        return ""
    for pattern, replacement in _PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_sensitive_text(text: str, max_length: Optional[int] = None) -> str:
    """Redact sensitive data and optionally truncate (used by the evidence collector)."""
    out = redact_sensitive_data(text)
    if max_length is not None and len(out) > max_length:
        out = out[:max_length]
    return out


def redact_dictionary(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redacts sensitive values inside a dictionary."""
    if not isinstance(data, dict):
        return data

    redacted = {}
    for k, v in data.items():
        if isinstance(v, str):
            redacted[k] = redact_sensitive_data(v)
        elif isinstance(v, dict):
            redacted[k] = redact_dictionary(v)
        elif isinstance(v, list):
            redacted[k] = [
                redact_dictionary(item) if isinstance(item, dict) else (redact_sensitive_data(item) if isinstance(item, str) else item)
                for item in v
            ]
        else:
            redacted[k] = v
    return redacted