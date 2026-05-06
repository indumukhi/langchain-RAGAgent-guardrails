"""
Output Guardrails — filters and validates the LLM response before it reaches the user.

Checks (applied sequentially, each may mutate the response text):
  1. response_length      — truncate if over MAX_RESPONSE_LENGTH
  2. refusal_bypass       — block if the model tried to sidestep its own safety
  3. output_pii_masking   — redact any PII in the response text
  4. sensitive_info_filter— redact API keys, passwords, connection strings
  5. hallucination_check  — warn if response has low overlap with retrieved context
  6. response_quality     — warn if response is too short / empty
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional

from .input_guardrails import GuardrailStatus, GuardrailResult, PII_PATTERNS

logger = logging.getLogger(__name__)

MAX_RESPONSE_LENGTH = 5000

# ── Patterns ──────────────────────────────────────────────────────────────────

SENSITIVE_OUTPUT_PATTERNS: dict[str, str] = {
    "openai_key":       r"\bsk-[A-Za-z0-9]{32,}\b",
    "generic_api_key":  r"\b(?:pk|api|key|token)-[A-Za-z0-9]{20,}\b",
    "password_literal": r"(?i)(password|passwd|pwd)\s*[:=]\s*\S+",
    "secret_literal":   r"(?i)(secret|token|credential)\s*[:=]\s*[A-Za-z0-9+/]{10,}",
    "private_key_pem":  r"-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----",
    "connection_string": r"(?i)(mongodb|postgresql|mysql|redis|mssql)://[^\s]+",
    "aws_access_key":   r"\bAKIA[0-9A-Z]{16}\b",
    "bearer_token":     r"(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*",
}

PII_REPLACEMENT: dict[str, str] = {
    "email":       "[EMAIL REDACTED]",
    "phone":       "[PHONE REDACTED]",
    "ssn":         "[SSN REDACTED]",
    "credit_card": "[CARD REDACTED]",
    "passport":    "[PASSPORT REDACTED]",
    "ip_address":  "[IP REDACTED]",
    "api_key":     "[API KEY REDACTED]",
}

REFUSAL_BYPASS_PATTERNS: list[str] = [
    r"as an ai without (any\s+)?(restrictions?|ethics|guidelines?)",
    r"pretending to be (a\s+)?(different|uncensored|unrestricted)",
    r"in this hypothetical (scenario|context) where I have no",
    r"ignoring my (previous\s+)?training",
    r"as a dan",
    r"without (ethical|safety|content) (guidelines?|restrictions?|filters?)",
    r"since you (asked|told) me to ignore",
]


# ── Individual checks ─────────────────────────────────────────────────────────

def check_response_length(text: str) -> tuple[str, GuardrailResult]:
    if len(text) > MAX_RESPONSE_LENGTH:
        truncated = text[:MAX_RESPONSE_LENGTH] + "... [Response truncated for safety]"
        return truncated, GuardrailResult(
            status=GuardrailStatus.WARNING,
            message="Response was truncated to the maximum allowed length.",
            check_name="response_length",
            details={"original_length": len(text), "max": MAX_RESPONSE_LENGTH},
        )
    return text, GuardrailResult(status=GuardrailStatus.PASSED, message="Response length OK", check_name="response_length")


def check_refusal_bypass(text: str) -> GuardrailResult:
    for pattern in REFUSAL_BYPASS_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning("Refusal bypass detected in LLM output.")
            return GuardrailResult(
                status=GuardrailStatus.BLOCKED,
                message="Response blocked due to safety policy violation in LLM output.",
                check_name="refusal_bypass",
            )
    return GuardrailResult(status=GuardrailStatus.PASSED, message="No refusal bypass", check_name="refusal_bypass")


def mask_pii_in_response(text: str) -> tuple[str, GuardrailResult]:
    masked = text
    found: list[str] = []
    for pii_type, pattern in PII_PATTERNS.items():
        replacement = PII_REPLACEMENT.get(pii_type, f"[{pii_type.upper()} REDACTED]")
        new_text = re.sub(pattern, replacement, masked, flags=re.IGNORECASE)
        if new_text != masked:
            found.append(pii_type)
            masked = new_text

    if found:
        return masked, GuardrailResult(
            status=GuardrailStatus.WARNING,
            message=f"PII was automatically masked in the response ({', '.join(found)}).",
            check_name="output_pii_masking",
            details={"masked_types": found},
        )
    return masked, GuardrailResult(status=GuardrailStatus.PASSED, message="No PII in output", check_name="output_pii_masking")


def filter_sensitive_info(text: str) -> tuple[str, GuardrailResult]:
    filtered = text
    found: list[str] = []
    for info_type, pattern in SENSITIVE_OUTPUT_PATTERNS.items():
        new_text = re.sub(pattern, f"[{info_type.upper()} FILTERED]", filtered, flags=re.IGNORECASE)
        if new_text != filtered:
            found.append(info_type)
            filtered = new_text

    if found:
        logger.warning(f"Sensitive info filtered from output: {found}")
        return filtered, GuardrailResult(
            status=GuardrailStatus.WARNING,
            message="Sensitive technical information was removed from the response.",
            check_name="sensitive_info_filter",
            details={"filtered_types": found},
        )
    return filtered, GuardrailResult(status=GuardrailStatus.PASSED, message="No sensitive info", check_name="sensitive_info_filter")


def check_hallucination_risk(response: str, context_docs: list[str]) -> GuardrailResult:
    """
    Heuristic: computes word-level overlap between the response and the
    retrieved source documents.  Low overlap suggests the model may have
    fabricated content not grounded in the knowledge base.
    """
    if not context_docs:
        return GuardrailResult(
            status=GuardrailStatus.WARNING,
            message="Response generated without retrieved context — potential hallucination risk.",
            check_name="hallucination_check",
            details={"context_docs_count": 0},
        )

    combined_context = " ".join(context_docs).lower()
    context_words = set(combined_context.split())

    response_words = {
        w.lower().strip(".,!?;:()'\"")
        for w in response.split()
        if len(w) > 3
    }

    if response_words:
        overlap = len(response_words & context_words) / len(response_words)
        if overlap < 0.15:
            return GuardrailResult(
                status=GuardrailStatus.WARNING,
                message="Response may contain information not found in the source documents.",
                check_name="hallucination_check",
                details={"context_overlap_ratio": round(overlap, 2), "context_docs_count": len(context_docs)},
            )

    return GuardrailResult(
        status=GuardrailStatus.PASSED,
        message="Response appears grounded in retrieved context.",
        check_name="hallucination_check",
        details={"context_docs_count": len(context_docs)},
    )


def check_response_quality(text: str) -> GuardrailResult:
    """Ensure the response is non-trivially useful."""
    stripped = text.strip()
    if not stripped or len(stripped) < 10:
        return GuardrailResult(
            status=GuardrailStatus.WARNING,
            message="Response is too short or empty.",
            check_name="response_quality",
        )
    return GuardrailResult(status=GuardrailStatus.PASSED, message="Response quality OK", check_name="response_quality")


# ── Orchestrator ──────────────────────────────────────────────────────────────

def process_output(response: str, context_docs: Optional[list[str]] = None) -> dict:
    """
    Run all output guardrails on the LLM response.

    Returns a dict with:
      - response (str)         : final (possibly mutated) response text
      - blocked (bool)         : True if the response was hard-blocked
      - guardrail_results (list): serialised GuardrailResult objects
      - warnings (list[str])   : user-visible warning messages
    """
    results: list[GuardrailResult] = []
    text = response

    # 1. Length
    text, length_res = check_response_length(text)
    results.append(length_res)

    # 2. Refusal bypass (hard block)
    bypass_res = check_refusal_bypass(text)
    results.append(bypass_res)
    if bypass_res.status == GuardrailStatus.BLOCKED:
        return {
            "response": "I'm unable to provide that response due to safety policy guidelines.",
            "blocked": True,
            "guardrail_results": [_serialize(r) for r in results],
            "warnings": [],
        }

    # 3. PII masking
    text, pii_res = mask_pii_in_response(text)
    results.append(pii_res)

    # 4. Sensitive info filtering
    text, sens_res = filter_sensitive_info(text)
    results.append(sens_res)

    # 5. Hallucination risk
    hall_res = check_hallucination_risk(text, context_docs or [])
    results.append(hall_res)

    # 6. Response quality
    quality_res = check_response_quality(text)
    results.append(quality_res)

    warnings = [r.message for r in results if r.status == GuardrailStatus.WARNING]

    return {
        "response": text,
        "blocked": False,
        "guardrail_results": [_serialize(r) for r in results],
        "warnings": warnings,
    }


def _serialize(result: GuardrailResult) -> dict:
    return {
        "check_name": result.check_name,
        "status": result.status.value,
        "message": result.message,
        "details": result.details,
    }
