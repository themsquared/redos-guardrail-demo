#!/usr/bin/env python3
"""Standalone worker: read pattern + text from stdin (JSON), run re.sub, print elapsed ms.
Invoked as its own process so a runaway match can be killed by the caller's
subprocess timeout -- not importable, not meant to be run directly."""
import json
import re
import sys
import time


def main():
    payload = json.loads(sys.stdin.read())
    pattern = re.compile(payload["pattern"])
    text = payload["text"]
    replacement = payload["replacement"]
    start = time.monotonic()
    pattern.sub(replacement, text)
    elapsed_ms = (time.monotonic() - start) * 1000
    print(f"{elapsed_ms:.3f}")


if __name__ == "__main__":
    main()
