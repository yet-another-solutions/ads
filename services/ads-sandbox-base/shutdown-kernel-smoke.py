"""CI-only PID-1 shutdown proof; run in a disposable private Docker PID namespace."""

from __future__ import annotations

import os
import select
import subprocess
from pathlib import Path

assert os.getpid() == 1 and os.geteuid() == 0
Path("/run/ads-sandbox-ready").touch(mode=0o600)
# The writer cannot be stopped by SIGTERM, and runs with a different UID.
writer = subprocess.Popen(
    [
        "/usr/bin/python3",
        "-I",
        "-c",
        """
import os, signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
os.setgid(1000)
os.setuid(1000)
with open('/session/shutdown-marker', 'w') as stream:
    stream.write('persistent shutdown proof\\n')
print('writer-ready', flush=True)
while True:
    time.sleep(1)
""",
    ],
    stdout=subprocess.PIPE,
    text=True,
)
assert writer.stdout is not None
assert select.select([writer.stdout], [], [], 5)[0], "writer did not start"
assert writer.stdout.readline().strip() == "writer-ready"
subprocess.Popen(
    [
        "/usr/bin/python3",
        "-I",
        "-c",
        "import os,signal,time; time.sleep(1); os.kill(1, signal.SIGTERM)",
    ]
)
os.execv("/usr/local/sbin/pause", ["pause"])
