#!/usr/bin/env python3
"""
redos-guardrail-demo

Illustrative reproduction of the VULNERABILITY CLASS behind two real,
high-severity advisories disclosed 2026-11-17 against pydantic-ai-harness
0.70.0 (used by pydantic-ai v2.70.0+):

  - GHSA-m4cr-m4qc-9hh3: ToolOutputLimits' strip_ansi used a pattern that
    took time quadratic in input length when stripping ANSI escape
    sequences from tool output.
  - GHSA-5m5q-5qj4-gx9h: the default `jwt` pattern in redact_secrets /
    secret_data() backtracked in time quadratic in input length when
    scanning text for JWTs to redact.

Both advisories describe quadratic-time regex backtracking triggered by
attacker-influenced text passed through a SAFETY feature (output
sanitization, secret redaction) -- the guardrail was the attack surface.

This script does NOT contain pydantic-ai's source. The exact vulnerable
patterns were not published. What's reproduced here is the general shape
of bug the advisories describe: a regex with nested/overlapping
quantifiers that backtracks catastrophically on crafted input, applied to
the same two jobs (stripping escape-like noise, matching token-like
strings) the advisories were about. The "fixed" side shows the standard
mitigation: rewrite the pattern so each character is consumed exactly
once, with no overlap between quantifiers.

Each match attempt runs in its own subprocess (_match_worker.py) so a
runaway regex can be killed outright on timeout -- a Python thread can't
be cancelled once it's inside the C regex engine, but a process can.

Usage:
    python3 demo.py
"""

import json
import subprocess
import sys
import time

LINE = "-" * 70
WORKER = str((__file__.rsplit("/", 1)[0] if "/" in __file__ else ".") + "/_match_worker.py")


def timed_match(pattern, text, replacement="", timeout_s=3.0):
    """Run one re.sub in a subprocess; return (elapsed_s, timed_out)."""
    payload = json.dumps({"pattern": pattern, "text": text, "replacement": replacement})
    start = time.monotonic()
    try:
        proc = subprocess.run(
            [sys.executable, WORKER],
            input=payload,
            capture_output=True,
            text=True,
            timeout=timeout_s,
        )
        elapsed = time.monotonic() - start
        if proc.returncode != 0:
            raise RuntimeError(f"worker failed: {proc.stderr}")
        return elapsed, False
    except subprocess.TimeoutExpired:
        return time.monotonic() - start, True


# ---------------------------------------------------------------------------
# Scenario 1: ANSI-escape-like stripping (shape of GHSA-m4cr-m4qc-9hh3)
# ---------------------------------------------------------------------------

# Vulnerable: nested quantifier over an optional-looking escape body lets the
# engine try exponentially many ways to partition a run of unterminated
# escape-starts before failing to match "m".
ANSI_VULNERABLE = r"(?:\x1b\[(?:[0-9;]*)*)+m"

# Fixed: no nested star, single pass -- each escape start is consumed once
# and never re-partitioned.
ANSI_FIXED = r"\x1b\[[0-9;]*m"


def make_ansi_payload(n):
    # n unterminated escape starts, then no final "m" -- forces the engine
    # to exhaust backtracking before giving up.
    return "\x1b[3;" * n


# ---------------------------------------------------------------------------
# Scenario 2: token-like redaction (shape of GHSA-5m5q-5qj4-gx9h)
# ---------------------------------------------------------------------------

# Vulnerable: a quantifier nested inside another quantifier over the same
# character class gives the engine exponentially many ways to group a long
# run into chunks when the required trailing anchor never shows up.
JWT_VULNERABLE = r"eyJ(?:[A-Za-z0-9_-]+)+\.SIGNATURE"

# Fixed: match the three dot-separated segments directly, each consumed in
# one linear pass with no overlap between groups.
JWT_FIXED = r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"


def make_jwt_payload(n):
    # A long base64-looking run that starts right but never reaches the
    # literal tail the pattern requires.
    return "eyJ" + ("A" * n)


# ---------------------------------------------------------------------------


def run_scenario(name, make_payload, vulnerable, fixed, sizes, timeout_s=3.0):
    print(LINE)
    print(name)
    print(LINE)
    print(f"{'input size':>12} | {'vulnerable':>14} | {'fixed':>10}")
    for n in sizes:
        payload = make_payload(n)
        v_elapsed, v_timed_out = timed_match(vulnerable, payload, timeout_s=timeout_s)
        f_elapsed, f_timed_out = timed_match(fixed, payload, timeout_s=timeout_s)
        v_str = f"TIMEOUT>{timeout_s:.0f}s" if v_timed_out else f"{v_elapsed * 1000:.1f}ms"
        f_str = f"TIMEOUT>{timeout_s:.0f}s" if f_timed_out else f"{f_elapsed * 1000:.2f}ms"
        print(f"{n:>12} | {v_str:>14} | {f_str:>10}")
        if v_timed_out:
            print(f"  -> vulnerable pattern did not finish within {timeout_s:.0f}s on a {n}-byte input.")
            print("     A single request of a few hundred KB (per the real advisories) occupies")
            print("     the event loop for tens of seconds to minutes.")
            break


def main():
    print("ReDoS-in-a-guardrail demo")
    print("Reproducing the VULNERABILITY CLASS behind GHSA-m4cr-m4qc-9hh3 and")
    print("GHSA-5m5q-5qj4-gx9h (pydantic-ai-harness 0.70.0, disclosed 2026-11-17).")
    print("See README.md for what this is and is not.\n")

    run_scenario(
        "Scenario 1: ANSI-escape stripping (ToolOutputLimits.strip_ansi shape)",
        make_ansi_payload,
        ANSI_VULNERABLE,
        ANSI_FIXED,
        sizes=[10, 20, 25, 30],
    )
    print()
    run_scenario(
        "Scenario 2: token redaction (redact_secrets jwt pattern shape)",
        make_jwt_payload,
        JWT_VULNERABLE,
        JWT_FIXED,
        sizes=[15, 20, 25, 30],
    )

    print(LINE)
    print("Both 'fixed' columns stay flat because the input is consumed once,")
    print("linearly, regardless of size. Both 'vulnerable' columns blow up because")
    print("the engine backtracks over every way to split the input between two")
    print("quantifiers that match the same characters.")


if __name__ == "__main__":
    sys.exit(main())
