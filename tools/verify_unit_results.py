"""Reject removed, skipped or failing baseline tests; report all executed JVM results."""
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

baseline = set(json.loads(Path(__file__).with_name("baseline-tests.json").read_text()))
assert len(baseline) == 125, "Baseline must contain the verified 125 distinct tests"
cases = {}
for path in Path(sys.argv[1]).rglob("TEST-*.xml"):
    for case in ET.parse(path).iter("testcase"):
        name = case.get("classname","") + "." + case.get("name","")
        if name in cases:
            raise SystemExit("Duplicate JVM result: " + name)
        cases[name] = case
missing = baseline - cases.keys()
if missing:
    raise SystemExit("Missing regression baseline: " + repr(sorted(missing)))
counts = {"tests": len(cases), "failures": 0, "errors": 0, "skipped": 0, "baseline_preserved": 125}
for case in cases.values():
    for tag, key in (("failure","failures"),("error","errors"),("skipped","skipped")):
        counts[key] += case.find(tag) is not None
if counts["failures"] or counts["errors"] or counts["skipped"]:
    raise SystemExit("JVM verification failed: " + json.dumps(counts))
print("Verified JVM results: " + json.dumps(counts))
destination = Path("app/build/reports/verification-summary.json")
destination.parent.mkdir(parents=True, exist_ok=True)
destination.write_text(json.dumps(counts,indent=2))
