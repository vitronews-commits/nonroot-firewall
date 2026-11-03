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

## Not implemented
- [ ] Integrate and license-audit NetGuard native forwarding engine.
- [ ] Packet-to-UID attribution, connection queue, pending approvals and timeouts.
- [ ] Real VPN start/stop and foreground notification.
- [ ] Rule persistence and editing screens.
- [ ] IPv4/IPv6 DNS and QUIC leak tests, network switching and Xiaomi-specific tests.
- [ ] Gradle build and signed APK.

## Security invariants
- Never claim traffic is protected until VPN establishment and forwarding are verified.
- Pending must block/hold, not automatically allow.
- No hostname DNS resolution on the packet processing thread.
- CIDR and package attribution require tests before enforcement.
- NetGuard GPL-3.0 obligations must be met if its code is incorporated.
