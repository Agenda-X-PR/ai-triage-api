# sec-triage

[![CI](https://github.com/Agenda-X-PR/sec-triage/actions/workflows/ci.yml/badge.svg)](https://github.com/Agenda-X-PR/sec-triage/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.9+](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/tests-25-brightgreen.svg)](#tests)

A small, offline command-line helper for **defensive first-pass log triage**. Parses common Apache/Nginx combined access log lines, JSON-lines records, and SSH `Failed password` messages, then flags the patterns an analyst would look for first: repeated authentication denials, SSH password guessing, requests for commonly exposed paths, 404 bursts, and unusual request concentration.

Uses only Python's standard library. No network calls. No external dependencies.

## Why This Exists

A SOC analyst or on-call engineer staring at a fresh log file needs a fast, trustworthy first pass — before opening a SIEM, before escalating, before doing anything expensive. `sec-triage` is that first pass: one command, one file, one readable summary, one exit code that a script can branch on.

It is not a replacement for a SIEM or a real detection pipeline. It is a triage tool for the first 30 seconds.

## Quick Start

```bash
# Basic text output
python3 sec_triage.py examples/sample-access.log

# Write structured findings for downstream automation
python3 sec_triage.py /var/log/nginx/access.log --format json --output findings.json

# Pipe from another command, tighter threshold, spreadsheet-friendly output
cat auth.log | python3 sec_triage.py - --threshold 8 --format csv
```

Run `python3 sec_triage.py --help` for all options.

## What It Detects

| Rule | Severity | Trigger | What it means |
| :--- | :--- | :--- | :--- |
| `repeated_auth_or_access_denials` | High | ≥ N HTTP 401/403 responses from one IP | Credential guessing, broken auth, or unauthorized access attempts |
| `ssh_password_guessing` | High | ≥ N SSH `Failed password` events from one IP | Password spray or brute-force against SSH |
| `sensitive_path_probe` | Medium | Any request for `.env`, `wp-admin`, `phpmyadmin`, `.git`, `actuator`, etc. | Common scanning / reconnaissance behavior |
| `http_404_burst` | Medium | ≥ N 404s from one IP within a line window | Path enumeration or a broken application |
| `request_burst` | Low | ≥ 4×N requests from one IP within a line window | Possibly elevated traffic — validate against expectations |

**Thresholds are configurable.** Default is `--threshold 5`. `--window-lines` controls the line span used for burst detection (default `100`).

## Output Formats

### Text (default)

```
Analyzed 7 lines; 2 finding(s).
[HIGH  ] repeated_auth_or_access_denials | source=192.0.2.77 | count=5 | lines=3,4,5,6,7
  5 HTTP 401/403 responses; review for credential guessing or unauthorized access.
[MEDIUM] sensitive_path_probe | source=198.51.100.44 | count=1 | lines=2
  Request for commonly exposed or administrative path: /.env
```

### JSON

```json
{
  "input_lines": 7,
  "findings_count": 2,
  "findings": [
    {
      "severity": "high",
      "rule": "repeated_auth_or_access_denials",
      "source": "192.0.2.77",
      "count": 5,
      "summary": "5 HTTP 401/403 responses; review for credential guessing or unauthorized access.",
      "lines": [3, 4, 5, 6, 7]
    }
  ]
}
```

### CSV

```
severity,rule,source,count,summary,lines
high,repeated_auth_or_access_denials,192.0.2.77,5,"5 HTTP 401/403 responses...","3;4;5;6;7"
```

## Exit Codes

| Code | Meaning |
| :--- | :--- |
| `0` | No high-severity rule fired |
| `1` | At least one high-severity finding |
| `2` | Input or usage error (file not found, invalid arguments) |

Medium and low findings do **not** change the exit code. This lets shell scripts escalate on high-confidence signals only.

## Project Structure

```
.
├── sec_triage.py              # CLI entry point — all parsing and analysis
├── sample-access.log          # Example log for demos and tests
├── tests/
│   ├── __init__.py
│   ├── test_parsing.py        # Log line parsing (Apache, JSON, SSH, unknown)
│   ├── test_analysis.py       # Rule logic for each detection
│   └── test_cli.py            # Exit codes, output formats, stdin input
├── .github/workflows/ci.yml   # CI on Python 3.9, 3.10, 3.11, 3.12
├── LICENSE                    # MIT
└── README.md
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

**25 tests** covering:

- **Parsing** — Apache/Nginx combined lines, JSON-lines records, SSH `Failed password` (including `invalid user` variants), and unknown/garbage lines (must not crash)
- **Analysis rules** — Each detection fires on its happy path and stays quiet when it should:
  - `repeated_auth_or_access_denials` — fires at threshold, quiet below
  - `ssh_password_guessing` — fires at threshold
  - `sensitive_path_probe` — **aggregates per (IP, path)** so 500 hits produce one finding, not 500
  - `http_404_burst` — fires on a burst within the window, stays quiet when 404s are spread beyond it
  - `request_burst` — fires on concentrated volume
- **Regression cases** — Two specific bugs were found and fixed during development, each now locked down by a test:
  - Sliding-window 404 detection (was counting total 404s instead of a burst)
  - Sensitive-path aggregation (was producing one finding per request)
- **CLI behavior** — Exit codes `0`/`1`/`2`, text/JSON/CSV output formats, stdin input via `-`

All tests use only the standard library (`unittest`, `subprocess`, `tempfile`). No external dependencies, no network calls.

## Adding a New Detection Rule

The `analyze()` function groups events into dictionaries keyed by `(ip)` or `(ip, path)`, then emits findings per group. To add a rule:

1. Add the field you want to key on to `Event` (if not already parsed)
2. Populate it in `parse_line()` for the relevant log format
3. Add a dict in `analyze()` for it
4. In the loop, append matching line numbers
5. After the loop, emit a `Finding` when the group meets your threshold

Follow the existing patterns — the aggregation and threshold logic is consistent across all five rules.

## Scope and Safety

This utility reads logs you provide and performs **no** scanning, exploitation, blocking, or external threat-intelligence lookups. It makes no network requests. It only reads files you pass on the command line (or on stdin) and writes findings to stdout or a file you specify.

**Detections are heuristics, not proof of compromise.** Tune thresholds for your environment's traffic patterns and validate findings against surrounding events before acting on them. An absent finding is not proof that a log is benign — the tool only reports what its configured rules matched.

**Treat logs and exported findings as sensitive.** They can contain client IPs, URLs, usernames, and operational details. Do not commit real logs to repositories and do not upload findings to third parties without a data-handling decision.

## Parsing Notes

Parsing is best-effort. Unrecognized lines are retained as unclassified records (with `ip="unknown"`) rather than causing the run to fail. This means a truncated or malformed log produces a useful result instead of a stack trace.

Supported formats:

- **Apache / Nginx combined** — standard access log format
- **JSON-lines** — any object with `ip`/`client_ip`/`remote_addr`/`src_ip` and `method`/`path`/`url`/`status`/`status_code` fields (case-sensitive)
- **SSH auth logs** — `Failed password for [invalid user] <user> from <ip>` patterns
- **Syslog / auth** — falls back to extracting any IPv4 or IPv6 address from the line

## License

MIT — see [LICENSE](LICENSE) for details.