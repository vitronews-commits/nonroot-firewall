# NonRoot Firewall — progress

## Locked requirements
- Classic NoRoot Firewall-inspired five-tab UI: Home, Pending, Apps, Filters, Log.
- Default decision: **PENDING** (ask); unknown connections must not be forwarded.
- Allow/block by app, IPv4/IPv6 IP/CIDR and Wi-Fi/mobile.
- No root, no remote VPN server, minimal settings.
- Android 15 target device: Redmi 13C.

## Implemented (source only; not yet built or device-tested)
- [x] Android Kotlin project skeleton.
- [x] Five-tab placeholder UI.
- [x] Pure Kotlin rule decision model with default PENDING.
- [x] VpnService declaration, deliberately inactive.
- [x] Filters UI: add/remove IP/CIDR allow/block rules with optional package and network.
- [x] Local rule persistence using SharedPreferences (synchronous commit).
- [x] Numeric IPv4/IPv6 CIDR validation; no hostname lookup for entered rules.
- [x] GitHub Actions debug build workflow and policy tests (not verified).
- [x] Regression tests for Wi-Fi/mobile app rule precedence and invalid CIDR input.
- [x] CI now runs unit tests before assembling the debug APK.
- [x] Bounded, deduplicated PendingQueue policy model with four tests (not connected to live traffic).

## Not implemented
- [ ] Integrate and license-audit NetGuard native forwarding engine.
- [ ] Packet-to-UID attribution, live connection interception, pending approvals and timeouts.
- [ ] Connect PendingQueue to packet engine; current queue is a pure in-memory model, not a traffic buffer.
- [ ] Real VPN start/stop and foreground notification.
- [ ] Per-app rules editing, rule conflict resolution, and production-ready persistence.
- [ ] Validate build and unit tests on CI.
- [ ] IPv4/IPv6 DNS and QUIC leak tests, network switching and Xiaomi-specific tests.
- [ ] Gradle build and signed APK.

## Security invariants
- Never claim traffic is protected until VPN establishment and forwarding are verified.
- Pending must block/hold, not automatically allow.
- No hostname DNS resolution on the packet processing thread.
- CIDR and package attribution require tests before enforcement.
- NetGuard GPL-3.0 obligations must be met if its code is incorporated.
