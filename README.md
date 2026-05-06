# AI RAG Project — with Comprehensive Guardrails

A production-ready RAG (Retrieval-Augmented Generation) AI assistant built with **LangChain + OpenAI + Pinecone**, enhanced with a full guardrail layer across all request/response stages.

---

## Architecture

```
User Browser (Angular · localhost:4200)
       │  HTTP POST /api/ask
       ▼
Spring Boot API Gateway (localhost:8080)
       │  HTTP POST /ask  (with error propagation)
       ▼
FastAPI Agent Server (localhost:8000)
       │
       ├── INPUT GUARDRAILS
       │     ├─ Rate Limit (burst / per-minute / per-hour)
       │     ├─ Input Length Check
       │     ├─ PII Detection (email, phone, SSN, credit card…)
       │     ├─ Prompt Injection Detection
       │     ├─ Jailbreak Detection
       │     ├─ Toxic Content Detection
       │     ├─ Script / Code Injection Detection
       │     ├─ Repetition Attack Detection
       │     └─ OpenAI Moderation API (optional)
       │
       ├── AGENT EXECUTION (Circuit Breaker protected)
       │     ├─ Calculator Tool  (safe AST eval — no eval())
       │     └─ Document Search Tool  (Pinecone + OpenAI Embeddings)
       │
       └── OUTPUT GUARDRAILS
             ├─ Response Length Truncation
             ├─ Refusal Bypass Detection
             ├─ PII Masking in Response
             ├─ Sensitive Info Filtering (API keys, passwords…)
             ├─ Hallucination Risk Check (context overlap)
             └─ Response Quality Check
```

---

## Guardrails — Full Reference

### Input Guardrails (`guardrails/input_guardrails.py`)

| Check | Type | Action |
|-------|------|--------|
| `input_length` | Structural | BLOCK if < 3 or > 2000 chars |
| `pii_detection` | Privacy | WARN for email, phone, SSN, credit card, passport, IP, API key |
| `prompt_injection` | Security | BLOCK attempts to override system prompt |
| `jailbreak_detection` | Security | BLOCK attempts to bypass safety guidelines |
| `toxic_content` | Safety | BLOCK hate speech, self-harm, explicit violence |
| `script_injection` | Security | BLOCK HTML/JS/Python code in input |
| `repetition_attack` | DoS | BLOCK token-flooding (> 50% word repetition) |
| `openai_moderation` | Safety | BLOCK if OpenAI Moderation API flags content |

### Output Guardrails (`guardrails/output_guardrails.py`)

| Check | Type | Action |
|-------|------|--------|
| `response_length` | Structural | TRUNCATE at 5000 chars, WARN user |
| `refusal_bypass` | Safety | BLOCK if LLM tried to sidestep its own safety |
| `output_pii_masking` | Privacy | REDACT PII found in response text |
| `sensitive_info_filter` | Security | FILTER API keys, passwords, connection strings |
| `hallucination_check` | Quality | WARN if response has < 15% overlap with context docs |
| `response_quality` | Quality | WARN if response < 10 chars |

### Security Guardrails (`guardrails/security_guardrails.py`)

| Feature | Details |
|---------|---------|
| **Rate Limiter** | 5 req/10s burst · 20 req/min · 200 req/hour (per client IP+UA) |
| **Circuit Breaker** | Opens after 5 consecutive LLM failures · 60s recovery window |
| **CORS** | Restricted to `localhost:4200` and `localhost:8080` |
| **Request Logging** | Every request/response logged with timing |

### Tool Security (`tools/calculator_tool.py`)

The calculator uses Python's `ast` module instead of `eval()`.  
Only numeric constants and arithmetic operators (`+ - * / // % **`) are parsed — no function calls, no variable names, no imports.

---

## Project Structure

```
ai-rag-project-guardrails/
├── fastapi-agent/
│   ├── main.py                     # FastAPI app with guardrail hooks
│   ├── agent.py                    # LangChain agent (returns context docs)
│   ├── upload_docs.py              # One-time Pinecone upload script
│   ├── requirements.txt
│   ├── .env.example
│   ├── docs/                       # Drop your PDF files here
│   ├── guardrails/
│   │   ├── __init__.py
│   │   ├── input_guardrails.py     # 8 input safety checks
│   │   ├── output_guardrails.py    # 6 output safety checks
│   │   ├── security_guardrails.py  # Rate limiter + Circuit breaker
│   │   └── guardrail_manager.py    # Central orchestrator
│   └── tools/
│       ├── calculator_tool.py      # AST-safe math evaluator
│       └── document_search_tool.py # Pinecone RAG + context tracking
├── spring-boot-api/
│   ├── pom.xml
│   └── src/main/java/com/example/api/
│       ├── AiGatewayApplication.java
│       ├── controller/QuestionController.java
│       ├── service/AgentService.java
│       └── dto/
│           ├── QuestionRequest.java  # @NotBlank + @Size validation
│           └── AgentResponse.java   # Includes guardrail_warnings field
└── angular-ui/
    ├── package.json
    ├── angular.json
    ├── tsconfig.json
    └── src/app/
        ├── services/chat.service.ts  # Handles guardrail error codes (400/429/503)
        └── chat/
            ├── chat.component.ts     # Shows guardrail warnings per message
            ├── chat.component.html   # Warning panel under assistant responses
            └── chat.component.scss   # Yellow warning badge styling
```

---

## Setup & Running

### 1. Environment Variables

```bash
cd fastapi-agent
cp .env.example .env
# Fill in your keys:
# OPENAI_API_KEY=sk-...
# PINECONE_API_KEY=...
# PINECONE_INDEX_NAME=your-index-name
```

### 2. FastAPI Agent

```bash
cd fastapi-agent
pip install -r requirements.txt

# Upload your documents (first time only — put PDFs in ./docs/)
python upload_docs.py

# Start the agent server
python main.py
# → http://localhost:8000
```

### 3. Spring Boot API Gateway

```bash
cd spring-boot-api
./mvnw spring-boot:run
# → http://localhost:8080
```

### 4. Angular UI

```bash
cd angular-ui
npm install
npm start
# → http://localhost:4200
```

---

## API Reference

### `POST /ask` (FastAPI · port 8000)

**Request:**
```json
{ "question": "What is the company refund policy?" }
```

**Response (200):**
```json
{
  "question": "What is the company refund policy?",
  "answer": "According to the policy documents...",
  "guardrail_warnings": ["Your input may contain an email address. Please avoid sharing PII."],
  "processing_time_ms": 1423.5
}
```

**Guardrail block (400):**
```json
{ "detail": "Your request appears to attempt manipulation of the AI system. Request blocked." }
```

**Rate limit (429):**
```json
{ "detail": "Too many requests. Maximum 20 requests per minute." }
```

**Circuit breaker (503):**
```json
{ "detail": "Circuit breaker is OPEN — service temporarily unavailable. Retry in 45s." }
```

### `GET /health` (FastAPI · port 8000)

```json
{
  "status": "ok",
  "guardrails": "enabled",
  "version": "2.0.0",
  "circuit_breaker": { "state": "CLOSED", "failure_count": 0, ... }
}
```

---

## Enabling OpenAI Moderation API

In `main.py`, replace `openai_client=None` with a real client:

```python
import openai

_openai_client = openai.OpenAI()  # reads OPENAI_API_KEY from env

# In the /ask route:
input_result = manager.check_input(
    question=body.question,
    client_ip=client_ip,
    user_agent=user_agent,
    openai_client=_openai_client,   # ← enable moderation
)
```

This adds a free, model-backed content classification layer on top of the regex-based checks.

---

## Key Differences from Original Project

| Feature | Original | With Guardrails |
|---------|----------|-----------------|
| Input length check | Basic empty check | Min 3 / Max 2000 chars |
| PII detection | None | 7 PII types detected & warned |
| Prompt injection | None | 14 patterns blocked |
| Jailbreak detection | None | 8 patterns blocked |
| Toxic content | None | 5 categories blocked |
| Script injection | None | 11 patterns blocked |
| Repetition attack | None | Token-flood detection |
| OpenAI Moderation | None | Optional API integration |
| Rate limiting | None | Burst + per-minute + per-hour |
| Circuit breaker | None | 5-failure threshold, 60s recovery |
| Calculator security | `eval()` | Safe AST parser — no code exec |
| Output PII masking | None | 7 PII types auto-redacted |
| Sensitive info filter | None | API keys, passwords, tokens filtered |
| Hallucination check | None | Context overlap heuristic |
| Response truncation | None | 5000 char limit |
| Refusal bypass | None | LLM safety bypass detection |
| Error handling | Basic | Guardrail-aware 400/429/503 |
| CORS | `*` (open) | Restricted to known origins |
| Response warnings | None | Displayed in UI per message |