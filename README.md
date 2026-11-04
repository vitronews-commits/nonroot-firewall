# NonRoot Firewall

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

## Build and test

Use JDK 17, Gradle 8.9, Android SDK platform 35 and build-tools 35.0.0:

```sh
gradle :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease :app:assembleAndroidTest
gradle :app:connectedDebugAndroidTest
```

The default Android test suite does not activate VPN. CI runs an additional,
explicitly gated emulator-only real-TUN acceptance test after the no-VPN suite.
The debug APK is signed for development. The release APK is intentionally unsigned;
a persistent private release key is required before distribution.

See [PROGRESS.md](PROGRESS.md) for dated milestones and actual validation results.
No third-party firewall engine has been copied into this implementation.
