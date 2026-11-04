# NonRoot Firewall — 0.3.0-dev candidate

Android 10+ local firewall using VpnService with the existing five-tab interface.
The development engine forwards IPv4/IPv6 TCP and UDP through protected sockets,
attributes traffic to Android UIDs, applies app/network/IP/CIDR/port rules, and
populates Pending/Logs with real packet decisions. Unknown traffic is blocked.

**Development build, not yet production-verified.** A protected TCP/UDP loopback
preflight must pass before a TUN interface is established. The TCP endpoint is
conservative and limited; fragments and IPv6 extension headers are dropped.
Read [VALIDATION.md](VALIDATION.md) for transport limits, exact checks and remaining
device acceptance requirements. Do not equate passing loopback tests with leak
protection on every Android device.

## Acceptance status

Development continues in `development/daily-use` / PR #3; main retains 0.2.1-dev.
The candidate is **not yet accepted for daily use**. The tested Android 10 resolver
can expose system DNS as package-less UID 1051. Those requests remain blocked;
there is no blanket DNS exception. Android 15 mobile DNS/handover acceptance also
has unresolved failures. See [TEST_RESULTS.md](TEST_RESULTS.md) for evidence by source.

The existing five tabs now include live connection metadata, log search/filtering
and validated rules import/export. The bounded TCP window replaces stop-and-wait;
UDP/TCP forwarding retains fresh UID authorization at actual I/O. Unsupported
fragments/extensions are dropped, not silently routed outside the VPN.

Always-on VPN and “Block connections without VPN” are Android settings, not an
in-app guarantee. Process-death/lockdown and physical Redmi 13C acceptance must be
verified separately. No physical-device VPN is activated by the test workflow.

## Build and test

Use JDK 17, Gradle 8.9, Android SDK platform 35 and build-tools 35.0.0:

```sh
./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease :app:assembleAndroidTest
./gradlew :app:connectedDebugAndroidTest
```

The default Android test suite does not activate VPN. CI runs an additional,
explicitly gated emulator-only real-TUN acceptance test after the no-VPN suite.
The debug APK is signed for development. The release APK is intentionally unsigned;
a persistent private release key is required before distribution.

See [PROGRESS.md](PROGRESS.md) for dated milestones and actual validation results.
No third-party firewall engine has been copied into this implementation.

Pinned build and delivery instructions: [BUILDING.md](BUILDING.md).
