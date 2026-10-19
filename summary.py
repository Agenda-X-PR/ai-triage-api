"""LLM summarization of triage findings. Supports Groq (cloud) and Ollama (local)."""
from dotenv import load_dotenv
load_dotenv()

import json
import os

from openai import OpenAI


def _get_client():
    """Return (client, model_name) based on LLM_PROVIDER env var."""
    provider = os.environ.get("LLM_PROVIDER", "groq").lower()

    if provider == "ollama":
        # Ollama exposes an OpenAI-compatible endpoint on localhost
        client = OpenAI(
            base_url="http://localhost:11434/v1",
            api_key="ollama",  # required but ignored
        )
        return client, "llama3.2"

    # Default: Groq. Uses the same OpenAI-compatible interface.
    api_key = os.environ.get("GROQ_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GROQ_API_KEY is not set. Get a free key at https://console.groq.com/keys"
        )
    client = OpenAI(
        base_url="https://api.groq.com/openai/v1",
        api_key=api_key,
    )
    return client, "llama-3.3-70b-versatile"


def summarize_findings(findings: list[dict], line_count: int) -> str:
    """Produce a plain-English incident summary from structured findings."""
    if not findings:
        return (
            "No suspicious patterns matched the configured detection rules. "
            "This does not prove the log is benign. Review it manually if you "
            "expected activity."
        )

    prompt = f"""You are a security analyst summarizing log triage results for a developer.

Log lines analyzed: {line_count}

Findings (JSON):
{json.dumps(findings, indent=2)}

Write a concise incident summary in plain English. Follow these rules:

1. Lead with the highest-severity finding.
2. Explain what the pattern suggests, not just what was detected. For example,
   "5 failed logins from one IP in one second" suggests credential guessing.
3. Give one concrete next step per finding.
4. Do not invent findings that are not in the data.
5. Do not repeat raw JSON. Write prose.
6. Keep it under 150 words total.
7. If multiple findings relate to the same source IP, connect them.
"""

    client, model = _get_client()
    response = client.chat.completions.create(
        model=model,
        messages=[{"role": "user", "content": prompt}],
        temperature=0.2,
        max_tokens=400,
    )
    return response.choices[0].message.content.strip()