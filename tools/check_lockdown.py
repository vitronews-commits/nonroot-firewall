"""Emulator-only process-death/lockdown acceptance; no device wipe or user-data operations.
Uses a removable test-only DPC in the separate probe APK, not in the firewall APK.
"""
import json
from pathlib import Path
import re
import subprocess
import time
import uuid
import threading

ADMIN = "com.nonroot.firewall.probe/.ProbeAdmin"
PROBE = "com.nonroot.firewall.probe/.ProbeInstrumentation"
FIREWALL = "com.nonroot.firewall"


def adb(*args, timeout=30):
    result = subprocess.run(["adb", *args], text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"adb {' '.join(args)}: {result.stdout} {result.stderr}")
    return result.stdout.strip()


def probe(mode, token=None):
    result = adb("shell", "am", "instrument", "-w", "-e", "mode", mode, "-e", "token", token or uuid.uuid4().hex, PROBE)
    if "status=ERROR" in result or "INSTRUMENTATION_CODE: -1" not in result:
        raise RuntimeError(result)
    return result


def wait_vpn():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        status = probe("vpn_status")
        if "status=VPN" in status and "lockdown=true" in status:
            return
        time.sleep(1)
    raise RuntimeError("Always-on VPN did not establish with lockdown")


if adb("shell", "getprop", "ro.hardware") not in ("ranchu", "goldfish"):
    raise SystemExit("Refusing device policy changes outside a disposable emulator")
root_result = adb("root")
if "cannot run as root" in root_result:
    raise SystemExit("Rootable emulator required to inject process death, test not executed")
adb("wait-for-device")
if "package:" + FIREWALL in adb("shell", "pm", "list", "packages", FIREWALL).splitlines():
    raise SystemExit("Refusing to overwrite existing firewall installation/data; use a fresh emulator")
adb("install", "-t", "app/build/outputs/apk/debug/app-debug.apk")  # UTP removes the tested target APK.
owner = False
process = None
try:
    before = uuid.uuid4().hex
    if "status=ESCAPED" not in probe("lockdown_control", before):
        raise RuntimeError("No-VPN positive control cannot reach the external sink")
    if "LOCKDOWN_LEAK " + before not in Path("/tmp/firewall-echo.log").read_text():
        raise RuntimeError("Missing external positive-control evidence")
    result = adb("shell", "dpm", "set-device-owner", ADMIN)
    if "Success" not in result:
        raise RuntimeError(result)
    owner = True
    adb("shell", "appops", "set", FIREWALL, "ACTIVATE_VPN", "allow")
    if "status=OK" not in probe("lockdown_on"):
        raise RuntimeError("Lockdown configuration failed")
    wait_vpn()
    original_pid = adb("shell", "pidof", FIREWALL)
    if not original_pid.isdigit():
        raise RuntimeError("Expected exactly one firewall process")
    token = uuid.uuid4().hex
    process = subprocess.Popen(["adb", "shell", "am", "instrument", "-w", "-e", "mode", "lockdown_probe", "-e", "token", token, PROBE], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    watchdog = threading.Timer(45, process.kill)
    watchdog.start()
    lines = []
    killed = False
    for line in process.stdout:
        lines.append(line)
        if "phase=READY" in line:
            time.sleep(1)  # Observe default-deny before process death, then across restart.
            adb("shell", "kill", "-9", original_pid)
            killed = True
    process.wait(timeout=30)
    watchdog.cancel()
    output = "".join(lines)
    if process.returncode or not killed or "status=BLOCKED" not in output or not re.search(r"attempts=[1-9]\d{2,}", output):
        raise RuntimeError("Process-death probe failed: " + output)
    log = Path("/tmp/firewall-echo.log").read_text()
    if "LOCKDOWN_LEAK " + token in log:
        raise RuntimeError("Default-denied UDP reached the external sink while VPN process died")
    wait_vpn()
    recovered_pid = adb("shell", "pidof", FIREWALL)
    if not recovered_pid.isdigit() or recovered_pid == original_pid:
        raise RuntimeError("VPN did not recover as a new process")
    if "status=OK" not in probe("lockdown_off"):
        raise RuntimeError("Unable to remove lockdown for positive control")
    adb("shell", "am", "force-stop", FIREWALL)
    after = uuid.uuid4().hex
    if "status=ESCAPED" not in probe("lockdown_control", after):
        raise RuntimeError("Post-test no-VPN control cannot reach sink")
    if "LOCKDOWN_LEAK " + after not in Path("/tmp/firewall-echo.log").read_text():
        raise RuntimeError("Missing post-test external positive-control evidence")
    report = {"result": "PASS", "test": "Always-on lockdown / process death / separate UID UDP", "old_pid": original_pid, "new_pid": recovered_pid, "external_sink_packets": 0, "probe": output}
    destination = Path("app/build/acceptance-reports/lockdown.json")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report, indent=2))
    print("Verified: Android Always-on lockdown blocked separate-UID UDP across VPN process death and recovered.")
finally:
    if process is not None and process.poll() is None:
        process.terminate()
    if owner:
        try:
            if "status=OK" not in probe("lockdown_off"):
                raise RuntimeError("Unable to remove test lockdown")
        finally:
            result = adb("shell", "dpm", "remove-active-admin", ADMIN)
            if "Success" not in result:
                raise RuntimeError("Unable to remove temporary test administrator: " + result)
    adb("shell", "am", "force-stop", FIREWALL)
    adb("shell", "appops", "set", FIREWALL, "ACTIVATE_VPN", "default")
