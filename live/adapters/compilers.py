#!/usr/bin/env python3
"""Offline runner compilers: recorded tool output -> adapter input contracts."""
from __future__ import annotations

import json
import re

_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
_METHOD = r"GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|TRACE"


def schemathesis_compile(cli_text):
    """Extract normalized failures from Schemathesis' pytest-style CLI report.

    The parser intentionally relies only on stable semantic labels (HTTP method/path,
    ``Check failed``, ``FALSIFIED`` and ``FAILED``), not box-drawing characters.
    """
    lines = _ANSI.sub("", str(cli_text or "")).splitlines()
    endpoint = method = check = ""
    example = ""
    failures = []

    def emit():
        if endpoint and method and check:
            value = {"endpoint": endpoint, "method": method, "check": check,
                     "example": example[:500]}
            if value not in failures:
                failures.append(value)

    for index, raw in enumerate(lines):
        line = raw.strip().strip("_=- ")
        ep_match = re.search(rf"\b({_METHOD})\s+(/\S+)", line, re.I)
        if ep_match:
            if check:
                emit()
                check = example = ""
            method, endpoint = ep_match.group(1).upper(), ep_match.group(2).rstrip(":")
        check_match = re.search(
            r"(?:check\s+failed|falsified|failed(?:\s+check)?)\s*[:\-]?\s*"
            r"([A-Za-z][A-Za-z0-9_. -]+)", line, re.I)
        if check_match and not line.upper().startswith("FAILED TEST"):
            candidate = check_match.group(1).strip().replace(" ", "_").lower()
            # Summary rows often include the endpoint before the final reason.
            candidate = candidate.split(" - ")[-1]
            if candidate not in ("failures", "failure"):
                if check and candidate != check:
                    emit()
                    example = ""
                check = candidate
        if re.search(r"falsifying\s+example", line, re.I):
            for following in lines[index + 1:index + 5]:
                candidate = following.strip()
                if candidate and not set(candidate) <= set("_=- "):
                    example = candidate
                    break
    emit()
    return {"failures": failures}


def zap_report_compile(report):
    """Validate and pass through ZAP traditional-json, already the adapter's shape."""
    value = json.loads(report) if isinstance(report, str) else report
    if not isinstance(value, dict) or not isinstance(value.get("site", []), list):
        raise ValueError("not a ZAP traditional-json report")
    return value


def playwright_capture_recipe(url_patterns):
    """JS runner snippet producing the list consumed by adapters.playwright."""
    patterns = json.dumps([str(pattern) for pattern in (url_patterns or [])])
    return f"""const bs2Patterns = {patterns};
const bs2Captures = [];
page.on('response', async (response) => {{
  const request = response.request();
  const url = response.url();
  if (bs2Patterns.some((pattern) => url.includes(pattern))) {{
    bs2Captures.push({{
      url,
      method: request.method(),
      status: response.status(),
      principal,
      context: contextName
    }});
  }}
}});
// After the governed browser steps complete:
await fs.promises.writeFile(capturePath, JSON.stringify(bs2Captures, null, 2));"""


__all__ = ["schemathesis_compile", "zap_report_compile", "playwright_capture_recipe"]
