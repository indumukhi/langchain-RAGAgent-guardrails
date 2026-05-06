"""
FastAPI application — AI RAG Agent with comprehensive guardrails.

Guardrail layers applied per request:
  INPUT  : rate limit → length → PII → prompt injection → jailbreak →
           toxic content → script injection → repetition → OpenAI Moderation
  AGENT  : circuit breaker wraps every LLM call
  OUTPUT : length truncation → refusal bypass → PII masking →
           sensitive info filter → hallucination check → quality check
"""

import logging
import time
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

load_dotenv()

# Import after env vars are loaded
from agent import get_agent, run_agent
from guardrails.guardrail_manager import get_guardrail_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


# ── Startup / shutdown ────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Server starting — initialising singleton agent and guardrails…")
    get_agent()
    get_guardrail_manager()
    logger.info("Agent and guardrails ready. Accepting requests.")
    yield
    logger.info("Server shutting down.")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="AI RAG Agent with Guardrails",
    description=(
        "RAG-powered AI assistant (LangChain + OpenAI + Pinecone) "
        "with comprehensive input/output safety guardrails."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200", "http://localhost:8080"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Schemas ───────────────────────────────────────────────────────────────────

class QuestionRequest(BaseModel):
    question: str

    @field_validator("question")
    @classmethod
    def not_empty(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("question must not be empty")
        return stripped


class AnswerResponse(BaseModel):
    question: str
    answer: str
    guardrail_warnings: list[str] = []
    processing_time_ms: float = 0.0


# ── Middleware ────────────────────────────────────────────────────────────────

@app.middleware("http")
async def request_logger(request: Request, call_next):
    start = time.perf_counter()
    logger.info(f"→ {request.method} {request.url.path}  client={request.client.host if request.client else '?'}")
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    logger.info(f"← {response.status_code}  {elapsed_ms:.1f}ms")
    return response


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    manager = get_guardrail_manager()
    return {
        "status": "ok",
        "guardrails": "enabled",
        "version": "2.0.0",
        "circuit_breaker": manager.get_health_status()["circuit_breaker"],
    }


@app.post("/ask", response_model=AnswerResponse)
def ask(body: QuestionRequest, request: Request):
    t_start = time.perf_counter()
    manager = get_guardrail_manager()
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    # ── 1. Input guardrails ────────────────────────────────────────────────
    input_result = manager.check_input(
        question=body.question,
        client_ip=client_ip,
        user_agent=user_agent,
        openai_client=None,   # set to openai.OpenAI() instance to enable moderation API
    )

    if not input_result["allowed"]:
        check = input_result.get("check_name", "guardrail")
        detail = input_result.get("blocked_reason", "Request blocked by safety guardrails.")
        status_code = 429 if check == "rate_limit" else 400
        raise HTTPException(status_code=status_code, detail=detail)

    input_warnings: list[str] = input_result.get("warnings", [])

    # ── 2. Agent execution (circuit-breaker protected) ─────────────────────
    try:
        raw_answer, context_docs = manager.run_with_circuit_breaker(run_agent, body.question)
    except RuntimeError as exc:
        # Circuit breaker open
        if "Circuit breaker" in str(exc):
            raise HTTPException(status_code=503, detail=str(exc))
        logger.exception("Unexpected runtime error from agent")
        raise HTTPException(status_code=500, detail="An internal error occurred.")
    except Exception:
        logger.exception("Agent execution error")
        raise HTTPException(status_code=500, detail="An error occurred while processing your request.")

    # ── 3. Output guardrails ───────────────────────────────────────────────
    output_result = manager.process_response(raw_answer, context_docs=context_docs)

    if output_result.get("blocked"):
        raise HTTPException(status_code=400, detail=output_result["response"])

    final_answer = output_result["response"]
    output_warnings: list[str] = output_result.get("warnings", [])
    all_warnings = input_warnings + output_warnings

    elapsed_ms = round((time.perf_counter() - t_start) * 1000, 2)

    return AnswerResponse(
        question=body.question,
        answer=final_answer,
        guardrail_warnings=all_warnings,
        processing_time_ms=elapsed_ms,
    )


# ── Local dev entry point ─────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)