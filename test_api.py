"""Send sample-access.log to the triage API and print the response."""

import json
import sys

import httpx

URL = "http://127.0.0.1:8000/api/triage"


def main():
    try:
        with open("sample-access.log", "rb") as f:
            response = httpx.post(
                URL,
                files={"file": ("sample-access.log", f, "text/plain")},
                timeout=30,
            )
    except httpx.ConnectError:
        print("❌ Server not running. Start it first:")
        print("   uvicorn api:app --reload")
        sys.exit(1)

    print(f"Status: {response.status_code}\n")
    try:
        print(json.dumps(response.json(), indent=2))
    except json.JSONDecodeError:
        print(response.text)


if __name__ == "__main__":
    main()