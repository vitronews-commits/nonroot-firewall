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

## Compact controls and navigation milestone
- [x] Replaced Wi-Fi/Mobile dropdown spinners in New Custom Filter with compact three-state tap controls (Pending/Allow/Block).
- [x] Fixed bottom tab active-state highlighting after navigation.
- [x] App Detail now uses the main toolbar title/back navigation rather than a duplicate in-content heading.
- [ ] Replace provisional text symbols with faithful vector icons.
- [ ] Run CI build and inspect APK on Android 15; compilation not verified in this update.

## App identity milestone
- [x] App rows and App Detail use PackageManager labels/icons when package is visible and installed.
- [x] Android manifest declares narrow launcher-app visibility via queries instead of broad QUERY_ALL_PACKAGES.
- [x] Missing/uninstalled/invisible packages show package name and fallback icon.
- [x] Bottom navigation height uses dp rather than raw pixels.
- [ ] Full installed-app listing is not implemented; Apps currently lists saved app rules only.
- [ ] System/non-launcher packages may not resolve under package visibility restrictions.
- [ ] Android CI build and device screenshot validation still unverified.

## Installed-app discovery milestone
- [x] Apps screen now enumerates visible launchable installed packages via PackageManager queryIntentActivities.
- [x] Also includes packages referenced by saved AppRules and custom IpRules, including uninstalled apps.
- [x] App rows sorted by display label, with package fallback where unavailable.
- [x] Added missing android.view.View import used by list dividers.
- [ ] Non-launcher system components are not exhaustively enumerated; Android package visibility is deliberately scoped.
- [ ] Build status not verified; device testing still required.

## App quick-toggle milestone
- [x] Wi-Fi/Mobile icons in Apps now cycle Pending -> Allow -> Block -> Pending on tap.
- [x] Changes persist to AppRuleStore, preserving the other network when a generic app rule existed.
- [x] CI uploads JUnit HTML reports even if build/test job fails.
- [ ] Verify actual build result and on-device app-list UI; no successful APK is claimed.
- [ ] VPN engine is still unavailable; app-rule toggles do not block traffic yet.

## Rule evaluation hardening
- [x] Reject hostname and malformed IPv4 packet destination strings before calling InetAddress in CIDR matching.
- [x] Added regression tests for hostname and malformed IPv4 with global catch-all allow.
- [ ] No verified successful GitHub Actions run available through current checks; combined commit statuses returned empty.
- [ ] Android SDK/Gradle are unavailable in the current local execution environment; no APK build was performed here.

## App Detail access controls
- [x] App Detail Wi-Fi and Mobile indicators are interactive, sharing the same persisted three-state app access controls as Apps.
- [x] App Detail indicators show current effective app-rule state with allow/block/pending colors.
- [ ] CI build and Android 15 device verification still pending. Commit combined status endpoint returned no statuses, which does not prove Actions success or failure.

## Build integrity and package visibility hardening
- [x] PackageManager app label/icon discovery and launcher enumeration now handle SecurityException gracefully.
- [x] CI verifies APK file exists, has nonzero size, and passes unzip archive integrity check before artifact upload.
- [x] CI treats missing APK artifact as an error.
- [ ] A passing GitHub Actions run has not been observed in this session; the APK remains unverified on device.

## Apps permissions list polish
- [x] Added explicit Wi-Fi, Mobile, and Application column headers.
- [x] Colored app permissions green/allow, red/block, gray/pending.
- [x] Added screen-reader content descriptions for tappable permission indicators.
- [ ] No successful CI run could be verified: commit-workflow lookup returned no runs (it only exposes pull-request runs); GitHub Actions page was not accessible from this environment.
- [ ] Real-device screenshot comparison and VPN engine remain pending.

## Codemagic CI
- [x] Added codemagic.yaml with linux_x2, Java 17, Gradle 8.9 bootstrap, unit tests, debug APK assembly, ZIP integrity check, and downloadable APK/test reports.
- [ ] Connect GitHub repository in Codemagic and run the first build.
- [ ] Verify actual Codemagic build result; no success is claimed yet.

## Development checkpoint — 2026-11-04 (source-level; CI not verified)
**Priority:** complete and validate the packet-processing architecture before further UI polish.

### Implemented since previous progress update
- [x] Installed-app catalog caching, background refresh, RecyclerView/DiffUtil and targeted row refresh to avoid scroll jumps.
- [x] Wi-Fi/mobile three-state app controls, colored full-width rows, app icons and compact Apps refresh action.
- [x] AndroidX configuration correction added in `gradle.properties` after a failed CI run.
- [x] `PacketParser`: basic IPv4/IPv6 header, protocol, address and port parsing, bounded IPv6 extension traversal.
- [x] `PacketPolicy`: packet metadata mapped to the pure `RuleEngine`, with explicit UNATTRIBUTED/UNSUPPORTED outcomes.
- [x] `ConnectionOwnerResolver`: Android 10+ `ConnectivityManager.getConnectionOwnerUid` lookup scaffold; shared UID ambiguity is not silently resolved.
- [x] `ForwardingGate`: fail-closed decision layer; ALLOW alone is insufficient without ready transport.
- [x] `FlowKey`/`FlowTable`: bounded, expiring flow metadata bookkeeping; not yet integrated with a persistent relay.
- [x] `UdpDatagram`: basic strict IPv4 UDP payload extraction.
- [x] `UdpResponsePacket`: IPv4 UDP response serialization and checksum generation.
- [x] `ProtectedUdpSocketFactory`: protects sockets before binding, closes on failure.
- [x] `UdpExchange`: experimental one-shot UDP request/reply with policy check and timeout.
- [x] `UdpRelay`: bounded asynchronous worker queue, using one socket per exchange.
- [x] `UdpPacketPipeline`: connects packet parsing, attributed package decisions, forwarding gate and relay.
- [x] Added unit-test source files for parsers, policy, flow bookkeeping, UDP replies, exchange, relay and pipeline.

### Verification and important limitations
- [ ] **Run a current successful GitHub Actions build and all unit tests.** No successful run for the latest commits has been verified.
- [x] Added IPv4 header and UDP pseudo-header checksum validation at the UDP pipeline boundary (IPv4 zero UDP checksum is permitted). Five regression tests added; execution not yet verified.
- [ ] Extend checksum validation coverage to all relevant packet ingress paths; the standalone UDP parser still only validates lengths.
- [ ] Ensure IPv6 extension/fragment semantics, malformed packets and IPv4/IPv6 parity are thoroughly tested.
- [ ] Resolve per-UID ownership accurately in an actual active VPN context, including shared UID, unknown UID, timing and socket tuple limitations.
- [ ] Replace one-shot UDP sockets with bounded, persistent per-flow UDP sessions, idle expiry, reply validation, concurrency controls and teardown.
- [ ] Wire reply packets to a synchronized TUN writer, with explicit lifetime and error handling.
- [ ] Add TCP forwarding, DNS/QUIC and IPv6 handling, network-switch behavior and leak tests.
- [ ] Connect Pending approvals and Logs to real traffic; do not display fabricated protection state.
- [ ] Test on Xiaomi Redmi 13C / Android 15 before enabling VPN.

**Security gate:** `FirewallVpnService` remains an inactive placeholder. Do not establish TUN, advertise protection or route device traffic until a complete, verified forwarding/return path exists. `UdpRelay` and `UdpPacketPipeline` are experimental and not connected to live traffic.

**CI evidence:** An inspected older Actions run (`41727178458`) failed because `android.useAndroidX=true` was missing. A later source fix exists, but that old failure is not evidence about current CI status.

### Documentation discipline
Update this `PROGRESS.md` whenever a meaningful implementation, test, build result, blocker or architectural decision changes. Distinguish source committed, tests written, tests passed, device-tested and production-ready.

## UDP integrity checkpoint — 2026-11-04
- [x] Added `UdpChecksums.kt` with IPv4 header and UDP checksum verification, including fragment rejection.
- [x] `UdpPacketPipeline` now rejects packets failing integrity checks before rule evaluation/relay admission.
- [x] Updated pipeline fixtures to generate valid checksummed packets; added `UdpChecksumsTest.kt` with five test cases.
- [x] Removed unused imports from `UdpRelay.kt`.
- [ ] Execute CI unit tests and debug APK build for these commits; no successful run verified.
- [ ] Persistent UDP sessions, TUN reply writer, TCP/IPv6 forwarding and real-device validation remain outstanding.
- [ ] VPN service remains intentionally inactive.

## CI compilation fix — 2026-11-04
- [x] Inspected failed GitHub Actions run 41735904929: `:app:compileDebugKotlin` failed at `UdpRelay.kt:30:9` (`Unresolved reference 'Executors'`).
- [x] Restored `java.util.concurrent.Executors` import in `UdpRelay.kt` (commit `8402e0bd`).
- [ ] Verify a new GitHub Actions run passes compilation, unit tests and APK assembly. Fix is committed but not yet verified.

## Persistent flow resource groundwork — 2026-11-04
- [x] Added generic `FlowResourceTable<T : Closeable>` for bounded per-flow resource reuse, idle expiry and deterministic cleanup.
- [x] Added four unit tests for reuse, capacity, expiry, shutdown and backwards-clock handling.
- [ ] CI compilation and test execution for these commits still need confirmation.
- [ ] This table does not yet create sockets, send datagrams or manage receive workers; rejected registrations remain caller-owned and must be closed by their caller.
- [ ] Integrate protected UDP sockets with the table, implement per-flow receive loops, serialized TUN output and safe shutdown.
- [ ] Keep `FirewallVpnService` inactive until complete transport and return-path verification.

## UDP socket pooling checkpoint — 2026-11-04
- [x] Added `UdpSocketPool.kt` backed by `FlowResourceTable`, keyed by `FlowKey` for UDP-only socket reuse, capacity limits and idle expiry.
- [x] Pool accepts a caller-provided socket factory; the caller MUST use `ProtectedUdpSocketFactory` in VPN context.
- [ ] Socket pool is not yet wired into `UdpRelay`, connected to remote endpoints, or equipped with receive workers; this is resource management only.
- [ ] Unit-test creation was attempted but blocked by the repository tool; no new pool tests were committed.
- [ ] Verify compilation and tests in CI; no successful build claimed for this change.
- [ ] VPN/TUN remains inactive.

## UDP socket lifecycle hardening — 2026-11-04
- [x] `FlowResourceTable.remove()` now explicitly closes and unregisters failed resources; added idempotent cleanup regression test.
- [x] `UdpSocketPool` detects closed cached sockets, removes them and can create replacements; exposes `remove()` for error cleanup.
- [ ] Socket pooling is still not integrated into the active `UdpRelay`; receive workers, packet delivery, and thread-safe TUN writes remain outstanding.
- [ ] CI execution of these changes not yet independently verified. VPN remains inactive.

## UDP pool tests — 2026-11-04
- [x] Added socket pool reuse, expiry, capacity and shutdown tests (50a26ada).
- [x] Reject unbound socket factory results (25a80141).
- [x] Updated test fixtures to bind sockets (1c529249).
- [ ] Confirm CI build and unit tests.
- [ ] Integrate per-flow receive worker before using pooled sockets in relay.

## UDP pool API — 2026-11-04
- [x] Added `activeSocket()` for non-allocating lookup and synchronized failed-flow eviction (096242b8).
- [ ] New regression test write was blocked by tooling; test not committed.
- [ ] CI verification and persistent relay integration remain pending.

## Persistent UDP receive worker — 2026-11-04
- [x] Added `UdpFlowSession` with one receive loop per socket, numeric IPv4 endpoint, synchronized sends, idle timeout and close cleanup.
- [x] Added three lifecycle and input-validation tests.
- [ ] Not integrated with `UdpRelay`, `UdpSocketPool` or TUN; caller must supply a protected socket.
- [ ] Verify new CI build and tests before integration. VPN remains inactive.

## Optional persistent UDP pipeline — 2026-11-04
- [x] Added optional UdpSessionManager injection into UdpPacketPipeline; policy and transport gate remain mandatory.
- [x] Authorized UDP packets use persistent sessions when injected, otherwise existing one-shot relay.
- [x] UDP reply callback exceptions no longer terminate the session receive loop.
- [ ] Verify CI and integration tests; no VPN/TUN activation.

## UDP pipeline compatibility — 2026-11-04
- [x] Restored trailing-lambda constructor compatibility after optional manager injection (11c6fc6c).
- [x] Added regression test ensuring manager cannot bypass the transport-ready gate (499ab7ba).
- [ ] CI verification pending; VPN remains inactive.

## UDP loopback integration test — 2026-11-04
- [x] Added local IPv4 UDP responder integration test checking authorized send, received reply and IPv4/UDP checksums (111708f7, 3c906e9f).
- [ ] CI execution not yet confirmed. This is a test, not evidence of a passing build.
- [ ] VPN/TUN remains inactive; protected-socket device integration still pending.

## UDP session capacity tests — 2026-11-04
- [x] Added capacity-limit and socket-cleanup test (2f60bc61).
- [x] Added same-flow socket reuse test (faedc2cf).
- [ ] Verify tests in CI; VPN remains inactive.

## UDP concurrency and policy revocation — 2026-11-04
- [x] Added concurrent same-flow socket allocation regression test (bb418bc1).
- [x] Added blocked-session reuse test (1b0e1107).
- [x] Revoke existing UDP session on non-ALLOW policy (6f26eae8).
- [ ] CI execution and Android device verification pending; VPN inactive.

## UDP rule-change invalidation — 2026-11-04
- [x] Added onRulesChanged() to close all active UDP sessions (68274d98).
- [x] Added regression test for session and socket cleanup (4e17ee2a).
- [ ] Wire hook to actual rule persistence/UI events and verify CI; VPN remains inactive.

## Rule change event bridge — 2026-11-04
- [x] Added process-local RuleChangeBus with listener registration and isolation (f5c5a98d).
- [x] MainActivity emits events after successful app/IP rule saves (69d18c03).
- [x] Added listener delivery and failure isolation tests (c72d5b46).
- [ ] Attach active engine session manager listener when engine exists; CI unverified, VPN inactive.

## UDP manager rule-event lifecycle — 2026-11-04
- [x] UDP manager registers a rule-change listener and unregisters on close (e072b395).
- [x] Rule-change event regression test verifies session/socket revocation (b70c8d85).
- [ ] Verify CI, concurrent event behavior and real forwarding before VPN activation.
