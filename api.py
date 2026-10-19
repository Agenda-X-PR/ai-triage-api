from fastapi import FastAPI, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from sec_triage import parse_line, analyze
import json

app = FastAPI(title="AI Triage Dashboard")
app.add_middleware(CORSMiddleware, allow_origins=["*"])

@app.post("/api/triage")
async def triage(file: UploadFile = File(...)):
    content = (await file.read()).decode("utf-8", errors="replace")
    lines = content.splitlines()
    events = [parse_line(line, i) for i, line in enumerate(lines, 1)]
    findings = analyze(events)
    return {
        "line_count": len(lines),
        "findings": [f.__dict__ for f in findings],
    }