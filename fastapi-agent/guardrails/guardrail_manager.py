"""
Guardrail Manager — central orchestrator for the full request/response lifecycle.

Usage (in main.py):
    manager = get_guardrail_manager()

    # Before calling the agent
    result = manager.check_input(question, client_ip, user_agent, openai_client)
    if not result["allowed"]:
        raise HTTPException(...)

    # After the agent responds
    output = manager.process_response(raw_answer, context_docs)
    if output["blocked"]:
        raise HTTPException(...)
    final_answer = output["response"]
"""

import logging
from typing import Any, Callable, Optional

from .input_guardrails import validate_input, GuardrailStatus
from .output_guardrails import process_output
from .security_guardrails import (
    InMemoryRateLimiter,
    CircuitBreaker,
    get_client_id,
    sanitize_for_logging,
)

logger = logging.getLogger(__name__)


class GuardrailManager:
    """
    Wraps all guardrail subsystems into a single, stateful object.
    Instantiate once at application startup (singleton via get_guardrail_manager()).
    """

    def __init__(self) -> None:
        self.rate_limiter = InMemoryRateLimiter()
        self.circuit_breaker = CircuitBreaker(failure_threshold=5, recovery_timeout=60)
        logger.info("GuardrailManager initialised.")

    # ── Input pipeline ────────────────────────────────────────────────────────

    def check_input(
        self,
        question: str,
        client_ip: str,
        user_agent: str = "",
        openai_client=None,
    ) -> dict:
        """
        Run the full input guardrail pipeline.

        Returns:
          {
            "allowed": bool,
            "blocked_reason": str | None,  # set when allowed=False
            "check_name": str | None,      # which check triggered the block
            "warnings": list[str],         # non-blocking PII / advisory messages
            "results": list[dict],         # serialised GuardrailResult list
          }
        """
        client_id = get_client_id(client_ip, user_agent)

        # 1. Rate limiting (security layer — checked before anything else)
        allowed, reason = self.rate_limiter.check_rate_limit(client_id)
        if not allowed:
            logger.warning(f"Rate limit hit for client {client_id}: {reason}")
            return {
                "allowed": False,
                "blocked_reason": reason,
                "check_name": "rate_limit",
                "warnings": [],
                "results": [],
            }

        # 2. Content checks
        results = validate_input(question, openai_client=openai_client)
        blocked = [r for r in results if r.status == GuardrailStatus.BLOCKED]
        warnings = [r for r in results if r.status == GuardrailStatus.WARNING]

        if blocked:
            logger.warning(
                f"Input blocked by '{blocked[0].check_name}' | "
                f"client={client_id} | "
                f"text='{sanitize_for_logging(question)}'"
            )
            return {
                "allowed": False,
                "blocked_reason": blocked[0].message,
                "check_name": blocked[0].check_name,
                "warnings": [],
                "results": [_serialize(r) for r in results],
            }

        if warnings:
            logger.info(f"Input warnings for client {client_id}: {[r.check_name for r in warnings]}")

        return {
            "allowed": True,
            "blocked_reason": None,
            "check_name": None,
            "warnings": [r.message for r in warnings],
            "results": [_serialize(r) for r in results],
        }

    # ── Output pipeline ───────────────────────────────────────────────────────

    def process_response(
        self,
        response: str,
        context_docs: Optional[list[str]] = None,
    ) -> dict:
        """
        Run the full output guardrail pipeline.

        Returns the same dict shape as output_guardrails.process_output:
          {
            "response": str,
            "blocked": bool,
            "guardrail_results": list[dict],
            "warnings": list[str],
          }
        """
        return process_output(response, context_docs or [])

    # ── Circuit-breaker wrapper ───────────────────────────────────────────────

    def run_with_circuit_breaker(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """Execute func(*args, **kwargs) protected by the circuit breaker."""
        return self.circuit_breaker.call(func, *args, **kwargs)

    # ── Observability ─────────────────────────────────────────────────────────

    def get_health_status(self) -> dict:
        return {
            "circuit_breaker": self.circuit_breaker.get_status(),
        }


# ── Module-level singleton ────────────────────────────────────────────────────

_manager: Optional[GuardrailManager] = None


def get_guardrail_manager() -> GuardrailManager:
    """Return the process-wide singleton GuardrailManager."""
    global _manager
    if _manager is None:
        _manager = GuardrailManager()
    return _manager


def _serialize(result) -> dict:
    return {
        "check_name": result.check_name,
        "status": result.status.value,
        "message": result.message,
        "details": result.details,
    }
