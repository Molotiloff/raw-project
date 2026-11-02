"""Wait for the isolated gateway and execute the checks over loopback."""
import os
import sys
import time
import urllib.error
import urllib.request

for attempt in range(60):
    try:
        with urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=2) as response:
            if response.status == 200:
                break
    except (OSError, urllib.error.URLError):
        pass
    time.sleep(1)
else:
    print('Gateway did not become ready within 60 seconds', file=sys.stderr)
    sys.exit(2)
os.execv(sys.executable, [sys.executable, '/scenarios/cia.py', '--output', '/results/report.json'])
