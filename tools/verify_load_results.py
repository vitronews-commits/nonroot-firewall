"""Require actual load/soak metrics, so a missing instrumentation argument cannot pass silently."""
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])
soak = "--soak" in sys.argv[2:]
marker = "TUN_SOAK" if soak else "TUN_STRESS"
records = []
for path in root.rglob("logcat-*.txt"):
    records.extend(line for line in path.read_text(errors="replace").splitlines() if marker in line)
if len(records) != 1:
    raise SystemExit(f"Expected exactly one {marker} record, got {len(records)}")
record = records[0]
if "status=OK" not in record:
    raise SystemExit("No successful probe result")
if soak:
    match = re.search(r"mode=soak bytes=(\d+) concurrentConnections=1 halfCloseRequired=true elapsedMs=(\d+)", record)
    if not match or int(match[1]) <= 0 or int(match[2]) < 3600000:
        raise SystemExit("Soak did not execute transfers for at least 60 minutes")
else:
    for mib in (1, 10, 100):
        if not re.search(rf"measurement={mib}MiB bytes={mib*1024*1024} elapsedMs=\d+", record):
            raise SystemExit(f"Missing {mib} MiB transfer evidence")
    if "concurrentConnections=4" not in record:
        raise SystemExit("Missing concurrent transfer evidence")
for field in ("engineCpuMs", "enginePssBeforeKiB", "enginePssAfterKiB"):
    if not re.search(rf"{field}=\d+", record):
        raise SystemExit(f"Missing {field}")
print(f"Verified: {marker} actually executed; metrics: {record}")
