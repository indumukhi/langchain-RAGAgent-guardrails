"""
Input Guardrails — screens every user query before it reaches the LLM.

Checks (in order, short-circuits on first BLOCKED result):
  1. input_length          — min/max character limits
  2. pii_detection         — email, phone, SSN, credit card, passport, IP, API keys
  3. prompt_injection      — attempts to override system instructions
  4. jailbreak_detection   — attempts to bypass safety guidelines
  5. toxic_content         — hate speech, self-harm, explicit violence
  6. script_injection      — HTML/JS/Python code injection
  7. repetition_attack     — token-flooding / denial-of-service patterns
  8. openai_moderation     — OpenAI Moderation API (when client provided)
"""

import re
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)

# ── Constants ────────────────────────────────────────────────────────────────
MAX_INPUT_LENGTH = 2000
MIN_INPUT_LENGTH = 3


class GuardrailStatus(str, Enum):
    PASSED = "passed"
    BLOCKED = "blocked"
    WARNING = "warning"


@dataclass
class GuardrailResult:
    status: GuardrailStatus
    message: str
    check_name: str
    details: Optional[dict] = field(default=None)


# ── PII patterns ─────────────────────────────────────────────────────────────
PII_PATTERNS: dict[str, str] = {
    "email":       r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
    "phone":       r"\b(\+\d{1,3}[\s.\-]?)?\(?\d{3}\)?[\s.\-]?\d{3}[\s.\-]?\d{4}\b",
    "ssn":         r"\b(?!000|666|9\d{2})\d{3}[\-\s]?(?!00)\d{2}[\-\s]?(?!0000)\d{4}\b",
    "credit_card": r"\b(?:4\d{12}(?:\d{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12})\b",
    "passport":    r"\b[A-Z]{1,2}\d{6,9}\b",
    "ip_address":  r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
    "api_key":     r"\b(?:sk-|pk-|api-|key-)[A-Za-z0-9]{20,}\b",
}

# ── Prompt injection patterns ─────────────────────────────────────────────────
PROMPT_INJECTION_PATTERNS: list[str] = [
    r"ignore\s+(previous|all|prior|above)\s+(instructions?|prompt|context|rules?)",
    r"forget\s+(everything|all|previous|prior|above)",
    r"(you\s+are|you're|act\s+as|pretend\s+to\s+be|roleplay\s+as)\s+(a\s+)?(?:different|new|other)",
    r"(new|updated|revised)\s+(instructions?|prompt|rules?|directives?)",
    r"override\s+(your|the|all)\s+(safety|restrictions?|guidelines?|rules?)",
    r"(disregard|bypass|circumvent|skip)\s+(your|all|the)\s+(safety|restrictions?|guidelines?)",
    r"system\s*:\s*you\s+(are|must|should)",
    r"\[\[instructions?\]\]",
    r"\bjailbreak\b",
    r"\bDAN\s+(mode|prompt)\b",
    r"do\s+anything\s+now",
    r"escape\s+(your|the|all)\s+(constraints?|restrictions?|rules?|safety)",
    r"(unlock|enable|activate)\s+(developer|debug|admin|unrestricted)\s+mode",
    r"<system\b",
    r"<\|im_start\|>",
    r"#{2,}\s*(instruction|system|human|assistant)",
]

# ── Jailbreak patterns ────────────────────────────────────────────────────────
JAILBREAK_PATTERNS: list[str] = [
    r"simulate\s+(being|a|an)\s+(evil|uncensored|unfiltered|dangerous)",
    r"write\s+(from|as)\s+(a|an)\s+(evil|malicious|harmful)",
    r"(tell|show|teach)\s+me\s+(how|ways?)\s+to\s+(hack|attack|exploit|harm|kill|hurt)",
    r"(make|create|build|write)\s+(malware|virus|ransomware|exploit|bomb|weapon)",
    r"(illegal|unethical|harmful)\s+(instructions?|guide|tutorial|steps?)",
    r"without\s+(any\s+)?(restrictions?|limitations?|safety|filters?)",
    r"(pretend|imagine)\s+(there\s+are\s+no|without)\s+(rules?|guidelines?|restrictions?|limitations?)",
    r"as\s+an\s+AI\s+without\s+(any\s+)?(ethics|restrictions?|safety)",
]

# ── Toxic content patterns ────────────────────────────────────────────────────
TOXIC_PATTERNS: list[str] = [
    r"\b(kill|murder|rape|torture|abuse)\s+(yourself|him|her|them|people)\b",
    r"\b(hate|despise)\s+(jews?|blacks?|whites?|muslims?|christians?|gays?|women|men)\b",
    r"\b(n[i1]gg[ae]r|f[a@]gg[o0]t|k[i1]ke|sp[i1]c)\b",
    r"\b(suicide|self[\-\s]harm|cutting|overdose)\s+(method|how|ways?|steps?|instructions?)\b",
    r"\b(child|minor)\s+(porn|sex|abuse|exploitation)\b",
]

# ── Script / code injection patterns ─────────────────────────────────────────
SCRIPT_INJECTION_PATTERNS: list[str] = [
    r"<script\b",
    r"javascript\s*:",
    r"on\w+\s*=\s*[\"']?[^\"']*[\"']?",
    r"\beval\s*\(",
    r"\bexec\s*\(",
    r"__import__\s*\(",
    r"\bsubprocess\.",
    r"\bos\.system\s*\(",
    r"\bimport\s+os\b",
    r"\bimport\s+subprocess\b",
    r"\bopen\s*\(\s*[\"'][/\\]",
]


# ── Individual checks ─────────────────────────────────────────────────────────

def check_input_length(text: str) -> GuardrailResult:
    length = len(text)
    if length < MIN_INPUT_LENGTH:
        return GuardrailResult(
            status=GuardrailStatus.BLOCKED,
            message="Input is too short. Please provide a meaningful question.",
            check_name="input_length",
        )
    if length > MAX_INPUT_LENGTH:
        return GuardrailResult(
            status=GuardrailStatus.BLOCKED,
            message=f"Input exceeds the {MAX_INPUT_LENGTH}-character limit. Please shorten your question.",
            check_name="input_length",
            details={"length": length, "max": MAX_INPUT_LENGTH},
        )
    return GuardrailResult(status=GuardrailStatus.PASSED, message="Length OK", check_name="input_length")


def detect_pii(text: str) -> GuardrailResult:
    found: dict[str, int] = {}
    for pii_type, pattern in PII_PATTERNS.items():
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            found[pii_type] = len(matches)

    if found:
        types = list(found.keys())
        return GuardrailResult(
            status=GuardrailStatus.WARNING,
            message=(
                f"Your input may contain sensitive personal information "
                f"({', '.join(types)}). Please avoid sharing PII."
            ),
            check_name="pii_detection",
            details={"detected_types": types},
        )
    return GuardrailResult(status=GuardrailStatus.PASSED, message="No PII detected", check_name="pii_detection")


def detect_prompt_injection(text: str) -> GuardrailResult:
    for pattern in PROMPT_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning("Prompt injection attempt detected.")
            return GuardrailResult(
                status=GuardrailStatus.BLOCKED,
                message="Your input appears to attempt manipulation of the AI system. Request blocked.",
                check_name="prompt_injection",
            )
    return GuardrailResult(status=GuardrailStatus.PASSED, message="No prompt injection", check_name="prompt_injection")


def detect_jailbreak(text: str) -> GuardrailResult:
    for pattern in JAILBREAK_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning("Jailbreak attempt detected.")
            return GuardrailResult(
                status=GuardrailStatus.BLOCKED,
                message="Your request appears to attempt bypassing AI safety guidelines. Request blocked.",
                check_name="jailbreak_detection",
            )
    return GuardrailResult(status=GuardrailStatus.PASSED, message="No jailbreak detected", check_name="jailbreak_detection")


def detect_toxic_content(text: str) -> GuardrailResult:
    for pattern in TOXIC_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning("Toxic content detected in input.")
            return GuardrailResult(
                status=GuardrailStatus.BLOCKED,
                message="Your input contains harmful or inappropriate content. Request blocked.",
                check_name="toxic_content",
            )
    return GuardrailResult(status=GuardrailStatus.PASSED, message="No toxic content", check_name="toxic_content")


def check_script_injection(text: str) -> GuardrailResult:
    for pattern in SCRIPT_INJECTION_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            logger.warning("Script/code injection detected.")
            return GuardrailResult(
                status=GuardrailStatus.BLOCKED,
                message="Your input contains potentially malicious code. Request blocked.",
                check_name="script_injection",
            )
    return GuardrailResult(status=GuardrailStatus.PASSED, message="No script injection", check_name="script_injection")


def check_repetition_attack(text: str) -> GuardrailResult:
    """Detect token-flooding / repetition-based DoS attempts."""
    words = text.split()
    if len(words) <= 10:
        return GuardrailResult(status=GuardrailStatus.PASSED, message="No repetition attack", check_name="repetition_attack")

    freq: dict[str, int] = {}
    for w in words:
        w = w.lower().strip(".,!?;:")
        freq[w] = freq.get(w, 0) + 1

    max_freq = max(freq.values())
    ratio = max_freq / len(words)
    if ratio > 0.5:
        return GuardrailResult(
            status=GuardrailStatus.BLOCKED,
            message="Input contains excessive repetition which is not permitted.",
            check_name="repetition_attack",
            details={"top_word_frequency": max_freq, "repetition_ratio": round(ratio, 2)},
        )
    return GuardrailResult(status=GuardrailStatus.PASSED, message="No repetition attack", check_name="repetition_attack")


def check_openai_moderation(text: str, openai_client) -> GuardrailResult:
    """
    Use OpenAI's free Moderation API as an additional content safety layer.
    Pass None for openai_client to skip this check.
    """
    if openai_client is None:
        return GuardrailResult(status=GuardrailStatus.PASSED, message="Moderation skipped (no client)", check_name="openai_moderation")

    try:
        response = openai_client.moderations.create(input=text)
        result = response.results[0]
        if result.flagged:
            flagged = [cat for cat, val in result.categories.__dict__.items() if val]
            logger.warning(f"OpenAI moderation flagged input: {flagged}")
            return GuardrailResult(
                status=GuardrailStatus.BLOCKED,
                message=f"Content flagged by safety system: {', '.join(flagged)}.",
                check_name="openai_moderation",
                details={"flagged_categories": flagged},
            )
    except Exception as exc:
        logger.warning(f"OpenAI moderation API error (skipping): {exc}")

    return GuardrailResult(status=GuardrailStatus.PASSED, message="OpenAI moderation passed", check_name="openai_moderation")


# ── Orchestrator ──────────────────────────────────────────────────────────────

def validate_input(text: str, openai_client=None) -> list[GuardrailResult]:
    """
    Run all input guardrails in order.
    Short-circuits and stops at the first BLOCKED result.
    Returns the full list of results (including the blocking one).
    """
    checks = [
        lambda t: check_input_length(t),
        lambda t: detect_pii(t),
        lambda t: detect_prompt_injection(t),
        lambda t: detect_jailbreak(t),
        lambda t: detect_toxic_content(t),
        lambda t: check_script_injection(t),
        lambda t: check_repetition_attack(t),
        lambda t: check_openai_moderation(t, openai_client),
    ]

    results: list[GuardrailResult] = []
    for check in checks:
        result = check(text)
        results.append(result)
        if result.status == GuardrailStatus.BLOCKED:
            break

    return results