"""Reject a green Android job if explicit VPN acceptance was skipped or absent."""
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

root = Path(sys.argv[1])
cases = []
for path in root.rglob("TEST-*.xml"):
    for case in ET.parse(path).iter("testcase"):
        if "VpnAcceptanceTest" in case.get("classname", "") and "tunTcpUdpAttributionAndRuleRevocation" in case.get("name", ""):
            cases.append(case)
if len(cases) != 1:
    raise SystemExit(f"Expected exactly one explicit VPN acceptance result; found {len(cases)}")
case = cases[0]
for tag in ("skipped", "failure", "error"):
    if case.find(tag) is not None:
        raise SystemExit(f"Real VPN acceptance did not pass: {tag}")
print("Verified: explicit separate-UID TUN acceptance executed and passed (not skipped).")
