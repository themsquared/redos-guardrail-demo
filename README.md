# redos-guardrail-demo

A stdlib-only, 60-second reproduction of why a regex-based safety feature
can itself be a denial-of-service vector — the shape of bug behind two
real, high-severity advisories disclosed 2026-11-17 against
[`pydantic-ai-harness`](https://github.com/pydantic/pydantic-ai) 0.70.0
(shipped in `pydantic-ai` v2.70.0, part of the popular
[Pydantic AI](https://ai.pydantic.dev/) agent framework):

- [GHSA-m4cr-m4qc-9hh3](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-m4cr-m4qc-9hh3)
  (high): with `strip_ansi=True`, the harness's `ToolOutputLimits`
  capability stripped ANSI escape sequences from tool output with a
  pattern that took time **quadratic** in the length of a line. A tool
  result of a few hundred kilobytes with many unterminated escape
  sequences could occupy the event loop for tens of seconds to minutes.
- [GHSA-5m5q-5qj4-gx9h](https://github.com/pydantic/pydantic-ai/security/advisories/GHSA-5m5q-5qj4-gx9h)
  (high): the default `jwt` pattern in `redact_secrets` / `secret_data()`
  backtracked in time **quadratic** in the length of the text it scanned.
  Anyone using `redact_secrets` with the default `jwt` pattern (included
  by default) on attacker-influenced text was affected.

Both were fixed in `pydantic-ai-harness` 0.70.0. `pydantic-ai` v2.71.0
(2026-11-18, the day before this repo was built) ships no further fix or
regression on either advisory — confirming they're current, not stale.

**The angle:** the vulnerable code in both cases was itself a *safety*
feature — output sanitization and secret redaction, the exact things you'd
reach for to make an agent's tool output safer to display or log. The
guardrail was the attack surface.

## What this is, and is not

This repo does **not** contain pydantic-ai's source and does not claim to
reproduce the literal vulnerable patterns — GitHub's advisories describe
the behavior, not the regex. What's reproduced here is the general
**vulnerability class** both advisories describe: a regex with
nested or overlapping quantifiers that backtracks catastrophically on
crafted input, applied to the same two jobs (stripping escape-like noise,
matching token-like strings) the advisories were about. This is a
standalone, illustrative demo of regex denial-of-service (ReDoS), built to
make the mechanism visible and timeable on a laptop in under a minute —
not a proof-of-concept against the real library.

## Quickstart

```bash
python3 demo.py
```

No dependencies beyond the Python 3 standard library. Tested on Python
3.9.6. Takes about 10 seconds to run (each "vulnerable" case is capped at
a 3-second timeout, enforced by killing a subprocess — a Python thread
can't be cancelled once it's inside the C regex engine, but a process
can).

Expected output shape (your exact milliseconds will vary):

```
Scenario 1: ANSI-escape stripping (ToolOutputLimits.strip_ansi shape)
  input size |     vulnerable |      fixed
          10 |        116.0ms |    28.68ms
          20 |     TIMEOUT>3s |    33.99ms
  -> vulnerable pattern did not finish within 3s on a 20-byte input.

Scenario 2: token redaction (redact_secrets jwt pattern shape)
  input size |     vulnerable |      fixed
          15 |         28.8ms |    25.73ms
          20 |         43.1ms |    42.19ms
          25 |        523.0ms |    30.15ms
          30 |     TIMEOUT>3s |    39.48ms
```

The "fixed" column stays flat (low single-digit to double-digit
milliseconds) regardless of input size, because the pattern consumes each
character once, linearly. The "vulnerable" column blows up — in scenario
1 within a 20-character input, in scenario 2 within 30 — because the
engine backtracks over every way to split the input between two
quantifiers that can match the same characters. On a real tool-output
path, "input size" is attacker-controlled: anything an agent reads from a
shell, a file, or an API response and hands to the sanitizer.

## Architecture

- `demo.py` — drives both scenarios, prints the comparison table.
- `_match_worker.py` — runs exactly one `re.sub()` call, invoked as its
  own subprocess by `demo.py` via `subprocess.run(..., timeout=...)` so a
  runaway match can be killed outright instead of hanging the whole
  script. (`_`-prefixed: not meant to be run directly.)

Two scenarios, matching the two advisories:

1. **ANSI-escape stripping** — vulnerable pattern nests one quantifier
   inside another over the escape sequence's body (`(?:\x1b\[(?:[0-9;]*)*)+m`);
   fixed pattern consumes it in one pass (`\x1b\[[0-9;]*m`).
2. **Token redaction** — vulnerable pattern nests a quantifier inside
   another over the token body (`eyJ(?:[A-Za-z0-9_-]+)+\.SIGNATURE`);
   fixed pattern matches the three segments directly, one pass, no
   backtracking (`eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`).

## The general lesson

Nested or overlapping quantifiers (`(a+)+`, `(x+)(x+)`, anything where two
parts of a pattern can match the same characters) are the classic
catastrophic-backtracking shape. They're especially easy to introduce in
code whose whole job is "scan this text for something that looks like
X" — exactly what a sanitizer or redactor does. If your agent framework,
gateway, or guardrail runs a regex against text an attacker can influence
(tool output, HTTP headers, file contents, anything round-tripped through
a model), that regex is worth the same scrutiny you'd give a SQL query
built from user input: check it for nested quantifiers, test it against
pathological input, and prefer linear-time constructs (negated character
classes, atomic groups, or a hand-written scanner) over greedy nesting.

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Topics

`redos` `regex-denial-of-service` `security` `ai-agents` `mcp` `agent-security` `python` `vulnerability-demo`
