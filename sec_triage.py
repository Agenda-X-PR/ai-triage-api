#!/usr/bin/env python3
"""Defensive, offline log triage for common web and SSH security signals."""
from __future__ import annotations
import argparse
import csv
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

APACHE_RE = re.compile(r'^(?P<ip>\S+)\s+\S+\s+\S+\s+\[(?P<time>[^]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<size>\S+)')
SSH_FAIL_RE = re.compile(r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)')
SUSPICIOUS_PATHS = ("/.env", "/wp-login", "/wp-admin", "/phpmyadmin", "/.git", "/cgi-bin/", "/actuator", "/server-status", "/config.php", "/vendor/phpunit")

@dataclass
class Event:
    line: int
    source: str
    ip: Optional[str] = None
    timestamp: Optional[str] = None
    method: Optional[str] = None
    path: Optional[str] = None
    status: Optional[int] = None
    message: Optional[str] = None

@dataclass
class Finding:
    severity: str
    rule: str
    source: str
    count: int
    summary: str
    lines: list[int]


def parse_line(raw: str, line_no: int) -> Event:
    """Parse common access log, SSH auth, or JSON object lines; preserve unknown lines."""
    text = raw.rstrip("\r\n")
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            ip = obj.get("ip") or obj.get("client_ip") or obj.get("remote_addr") or obj.get("src_ip")
            method, path = obj.get("method"), obj.get("path") or obj.get("url")
            status = obj.get("status") or obj.get("status_code")
            try: status = int(status) if status is not None else None
            except (TypeError, ValueError): status = None
            return Event(line_no, str(ip) if ip else "unknown", str(ip) if ip else "unknown", str(obj.get("timestamp") or obj.get("time") or "") or None,
                         str(method).upper() if method else None, str(path) if path else None, status, text)
    except (json.JSONDecodeError, TypeError):
        pass
    m = APACHE_RE.match(text)
    if m:
        parts = m.group("request").split()
        return Event(line_no, m.group("ip"), m.group("ip"), m.group("time"), parts[0].upper() if len(parts)>0 else None,
                     parts[1] if len(parts)>1 else None, int(m.group("status")), text)
    m = SSH_FAIL_RE.search(text)
    if m:
        return Event(line_no, m.group("ip"), m.group("ip"), message=text, path="ssh-auth-failure")
    # Extract a useful source address from unstructured auth/syslog records.
    m = re.search(r'\b(?:from\s+)?(?P<ip>(?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]{3,})\b', text)
    return Event(line_no, m.group("ip") if m else "unknown", m.group("ip") if m else "unknown", message=text)


def analyze(events: Iterable[Event], threshold: int = 5, window_lines: int = 100) -> list[Finding]:
    events = list(events)
    findings: list[Finding] = []

    def add(severity, rule, source, lines, summary):
        findings.append(Finding(severity, rule, source, len(lines), summary, list(lines)))

    failures: dict[str, list[int]] = defaultdict(list)
    sshfails: dict[str, list[int]] = defaultdict(list)
    scans: dict[str, list[int]] = defaultdict(list)
    probes: dict[tuple[str, str], list[int]] = defaultdict(list)
    by_ip: dict[str, list[int]] = defaultdict(list)

    for e in events:
        ip = e.ip or "unknown"
        if e.status in (401, 403):
            failures[ip].append(e.line)
        if e.path and any(p in e.path.lower() for p in SUSPICIOUS_PATHS):
            probes[(ip, e.path)].append(e.line)
        if e.path == "ssh-auth-failure":
            sshfails[ip].append(e.line)
        if e.status == 404:
            scans[ip].append(e.line)
        if e.path and e.path != "ssh-auth-failure":
            by_ip[ip].append(e.line)

    # Rule: repeated auth/access denials
    for ip, lines in failures.items():
        if len(lines) >= threshold:
            add("high", "repeated_auth_or_access_denials", ip, lines,
                f"{len(lines)} HTTP 401/403 responses; review for credential guessing or unauthorized access.")

    # Rule: SSH password guessing
    for ip, lines in sshfails.items():
        if len(lines) >= threshold:
            add("high", "ssh_password_guessing", ip, lines,
                f"{len(lines)} failed SSH password attempts.")

    # Rule: sensitive path probe (aggregated per ip+path — bug fix)
    for (ip, path), lines in probes.items():
        add("medium", "sensitive_path_probe", ip, lines,
            f"{len(lines)} request(s) for commonly exposed path: {path[:180]}")

    # Rule: 404 burst within a sliding window (bug fix — uses `run`)
    for ip, lines in scans.items():
        if len(lines) < threshold:
            continue
        run: list[int] = []
        for n in lines:
            run = [x for x in run if n - x < window_lines]
            run.append(n)
            if len(run) >= threshold:
                add("medium", "http_404_burst", ip, run,
                    f"{len(run)} HTTP 404 responses within {window_lines} log lines; "
                    f"may indicate path enumeration or broken links.")
                break

    # Rule: request burst from one source
    for ip, lines in by_ip.items():
        if len(lines) >= threshold * 4 and lines[-1] - lines[0] <= window_lines:
            add("low", "request_burst", ip, lines,
                f"{len(lines)} requests within {window_lines} log lines; validate against expected traffic.")

    return sorted(findings, key=lambda f: (
        {"high": 0, "medium": 1, "low": 2}.get(f.severity, 3),
        f.lines[0] if f.lines else 0,
        f.rule,
    ))

def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="sec-triage", description="Offline triage of web access and SSH authentication logs.")
    p.add_argument("file", nargs="?", help="Log file; omit or use - to read stdin")
    p.add_argument("--threshold", type=int, default=5, help="minimum events for burst rules (default: 5)")
    p.add_argument("--window-lines", type=int, default=100, help="line span for request-burst rules (default: 100)")
    p.add_argument("--format", choices=("text", "json", "csv"), default="text", help="output format")
    p.add_argument("--output", help="write output to this file instead of stdout")
    args = p.parse_args(argv)
    if args.threshold < 1 or args.window_lines < 1: p.error("--threshold and --window-lines must be positive")
    try:
        if args.file and args.file != "-":
            with open(args.file, encoding="utf-8", errors="replace") as f: rows = list(f)
        else: rows = list(sys.stdin)
    except OSError as exc:
        print(f"sec-triage: {exc}", file=sys.stderr); return 2
    events = [parse_line(row, i) for i, row in enumerate(rows, 1)]
    findings = analyze(events, args.threshold, args.window_lines)
    out = open(args.output, "w", newline="", encoding="utf-8") if args.output else sys.stdout
    try:
        if args.format == "json":
            json.dump({"input_lines": len(rows), "findings_count": len(findings), "findings": [asdict(x) for x in findings]}, out, indent=2)
            out.write("\n")
        elif args.format == "csv":
            w = csv.DictWriter(out, fieldnames=["severity", "rule", "source", "count", "summary", "lines"])
            w.writeheader()
            for f in findings:
                d = asdict(f); d["lines"] = ";".join(map(str, f.lines)); w.writerow(d)
        else:
            print(f"Analyzed {len(rows)} lines; {len(findings)} finding(s).", file=out)
            for f in findings:
                loc = ",".join(map(str, f.lines[:8])) + ("…" if len(f.lines)>8 else "")
                print(f"[{f.severity.upper():6}] {f.rule} | source={f.source} | count={f.count} | lines={loc}\n  {f.summary}", file=out)
            if not findings: print("No configured patterns matched. This is not proof that the log is benign.", file=out)
    finally:
        if args.output: out.close()
    return 1 if any(f.severity == "high" for f in findings) else 0

if __name__ == "__main__":
    raise SystemExit(main())
