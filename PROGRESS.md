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
- [x] Apps tab can add/remove local per-package allow/block rules for Wi-Fi/mobile/all networks.
- [x] App rules persist in SharedPreferences and overwrite previous same package+network decisions.
- [x] FirewallEngine interface and explicitly unavailable implementation (no false protection status).
- [x] ConnectionGate records PENDING metadata, clears resolved requests, and enforces ALLOW-only decision semantics.
- [x] Rule precedence aligned: app+IP > app rule > global IP > pending; regression tests added.

## Not implemented
- [ ] Integrate and license-audit NetGuard native forwarding engine; no NetGuard code is present yet.
- [ ] Packet-to-UID attribution, live connection interception, pending approvals and timeouts.
- [ ] Connect PendingQueue to packet engine; current queue is a pure in-memory model, not a traffic buffer.
- [ ] Real VPN start/stop and foreground notification.
- [ ] Real installed-app picker, rule conflict resolution, and production-ready persistence.
- [ ] Validate build and unit tests on CI.
- [ ] IPv4/IPv6 DNS and QUIC leak tests, network switching and Xiaomi-specific tests.
- [ ] Gradle build and signed APK.

## Security invariants
- Never claim traffic is protected until VPN establishment and forwarding are verified.
- Pending must block/hold, not automatically allow.
- No hostname DNS resolution on the packet processing thread.
- CIDR and package attribution require tests before enforcement.
- NetGuard GPL-3.0 obligations must be met if its code is incorporated.

## Classic UI reference implementation (2026-11-03)
- [x] Five-tab blue navigation and pale-blue toolbar based on user-provided screenshots.
- [x] Classic-style Apps list with Wi-Fi/mobile indicators and App Detail navigation.
- [x] Custom per-app IP filter list with delete and add actions.
- [x] Global Pre-Filters rows with Wi-Fi/mobile markers and delete actions.
- [ ] Pixel-perfect screenshot comparison on target device; icons, spacing and font are approximations.
- [ ] Populate Apps with actual installed-app names/icons (currently shows saved package rules only).
- [ ] Pending and Logs need real packet engine data; no fake activity should be displayed.
- [ ] Build/CI verification remains outstanding.

## Custom Filter dialog milestone
- [x] IPv4 wildcard input normalization (e.g. 172.217.114.* → /24), plus address suggestions.
- [x] Destination port matching (specific port or any) and backward-compatible local storage.
- [x] Separate Wi-Fi/Mobile decisions within the editor, saved as per-network rules.
- [x] Five additional unit tests for wildcard, ports and network-specific policy.
- [ ] Match the original dialog's exact spacing, dropdown appearance and icons on a physical Android 15 device.
- [ ] The `*` address currently maps to IPv4 only; IPv6-any requires separate support.
- [ ] Real VPN enforcement and successful CI build remain unverified.

## Video-based UI/policy refinement
- [x] Custom IP filters now use first matching rule in stored order, consistent with classic App Detail wording.
- [x] Global IP filters now check destination port as well as IP and network.
- [x] Regression tests for first-match ordering and global port filtering added.
- [x] New Custom Filter editor uses compact inline Address/Port rows and dropdown arrows.
- [ ] Replace Wi-Fi/Mobile spinners with the exact compact three-state controls from the reference video.
- [ ] CI build and visual screenshot comparison on Android 15 are not yet verified.
- [ ] VPN packet forwarding and live Pending/Logs remain unimplemented.
