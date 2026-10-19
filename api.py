"""FastAPI wrapper around sec_triage with AI summarization."""

import logging

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware

from sec_triage import analyze, parse_line
from summary import summarize_findings

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("ai-triage-api")

app = FastAPI(
    title="AI Triage API",
    version="1.0.0",
    description="Upload a web or SSH log file and get structured findings plus an AI incident summary.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten to your frontend URL after deploying
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    """Liveness check for the base URL. Also tells you where to go next."""
    return {
        "service": "ai-triage-api",
        "status": "ok",
        "endpoints": {
            "health": "/api/health",
            "triage": "POST /api/triage",
            "docs": "/docs",
        },
    }


@app.get("/api/health")
def health():
    """Readiness check. Does not call the LLM or touch the filesystem."""
    return {"status": "ok", "service": "ai-triage-api", "version": "1.0.0"}


@app.post("/api/triage")
async def triage(file: UploadFile = File(...)):
    """Run detection rules over an uploaded log and return findings + summary."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file provided")

    raw = await file.read()
    if not raw:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    try:
        content = raw.decode("utf-8", errors="replace")
    except Exception as exc:  # pragma: no cover — decode errors are rare
        raise HTTPException(status_code=400, detail=f"Could not read file: {exc}")

    lines = content.splitlines()
    logger.info("Received file=%s size=%d lines=%d", file.filename, len(raw), len(lines))

    events = [parse_line(line, i) for i, line in enumerate(lines, 1)]
    findings = analyze(events)
    findings_dicts = [f.__dict__ for f in findings]

    logger.info("Analysis complete: %d finding(s)", len(findings_dicts))

    try:
        summary = summarize_findings(findings_dicts, len(lines))
    except RuntimeError as exc:
        # Missing GROQ_API_KEY or similar config problem — still return findings.
        logger.warning("LLM summary unavailable: %s", exc)
        summary = f"(AI summary unavailable: {exc})"
    except Exception as exc:  # network, rate limit, provider outage
        logger.exception("LLM call failed")
        summary = f"(AI summary failed: {exc})"

    return {
        "line_count": len(lines),
        "findings": findings_dicts,
        "summary": summary,
    }


@app.on_event("startup")
async def log_routes():
    """Log every registered route so Render logs show what's actually served."""
    logger.info("Registered routes:")
    for route in app.routes:
        methods = getattr(route, "methods", None)
        path = getattr(route, "path", "?")
        if methods:
            logger.info("  %s %s", ",".join(sorted(methods)), path)