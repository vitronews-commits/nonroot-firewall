## 2026-11-04 — TCP incarnation and FIN persistence hardening (verification pending)

- Retain the existing engine and all 125 baseline tests.
- Per-flow atomic leases revoke stale workers before tuple reuse; response delivery verifies the exact incarnation under the flow monitor.
- FIN persistence no longer emits the previous payload byte at the FIN sequence. Keepalive probes are acknowledged without forwarding probe data. Idle expiry emits a reset and upstream sockets enable keepalive.
- Corrupt-policy acceptance now waits for an actually established closed TUN, not merely an early error status.
- Added three regression tests; not yet declared passing. Local wrapper execution failed because the Gradle distribution network endpoint is unreachable. CI is the validation authority for this milestone.
- Previous head 72b4f55 built successfully, but API 35 acceptance failed on mobile system DNS; the 60-minute job failed on its subsequent DNS Pending assertion. API 29 aborted with an emulator system crash. These are not overall PASS results.

# NonRoot Firewall — progress

## Current status — 2026-11-04 / 0.3.0-dev acceptance in progress

- Development branch: `development/daily-use`, [PR #3](https://github.com/vitronews-commits/nonroot-firewall/pull/3). Main remains the verified 0.2.1 baseline.
- Current source before this fixture milestone: `38d5319baec5bfc6d2a584013e66d77bafd51f2e`, [CI 41814964645](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41814964645), still running.
- Local 153 JVM tests passed with zero failures/skips, retaining all original 125. Full Android build/lint for that source passed. Actual load/soak/network/lifecycle acceptance is not yet final.
- Previous API 35 source passed 1/10/100 MiB + 4 concurrent separate-UID TUN transfers. API 29 returned all 1 MiB bytes then reset on EOF: remains a failure until clean half-close passes. Tests were not weakened to accept reset.
- Bounded NIO TCP/UDP, fresh UID checks at actual I/O, strict persisted policy, safe backups/imports, live monitoring, MTU errors and atomic route/DNS replacement implemented; see dated milestones below.
- Local execution environment became unavailable during host-fixture verification. Work continues via GitHub; no unexecuted local check is counted as passed.
- Remaining physical acceptance: Redmi/HyperOS, real IPv6-only/DNS64/NAT64, Doze/reboot and external leak capture. Emulator findings are reported separately. Release signing key remains external; no production certification.

## Verified 0.2.1 baseline (historical) — 2026-11-04 / 0.2.1-dev

- Installable debug APK produced; release APK built unsigned. Five-tab UI and existing preferences retained.
- Final CI [41801468947](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41801468947), source `22e74810ee6669402550062489a8c8d1e55de5db`: **125 JVM tests, zero failures/errors/skips**, lint, debug/release/test/probe builds and debug signature/ZIP checks all passed.
- **API 29 and API 35 actual TUN acceptance passed, explicitly not skipped.** Each API also passed three no-VPN tests. Separate-UID probe verifies 64 KiB TCP echo, UDP echo, attribution, active TCP revocation and exact blocked UDP Pending. Transport-specific QUEUED and payload-bearing TCP REPLY assertions prevent bypass-only false positives.
- Added bounded SYN MSS negotiation: response segments honor peer MSS and tunnel MTU (1460 IPv4 / 1440 IPv6; absent-option defaults 536/1220). Runtime protected preflight verifies negotiation before TUN establishment.
- Fixed cumulative ACK processing during full-duplex uploads; ordered payload and ACK progression are independent, with future ACK rejection and uint32 wrap checks. Two new socket regressions fail against preceding code and pass with the fix. All 20 local transport tests pass.
- Download links, exact hashes and installation/data-preservation instructions: [TEST_RESULTS.md](TEST_RESULTS.md). Extracted debug APK hash matches CI.
- Remaining: physical Redmi 13C network switching/Doze/reboot/lockdown, external DNS/IPv6 leak capture, sustained throughput and private persistent release signing key. Stop-and-wait TCP and unsupported fragment/extension limits remain explicit in VALIDATION.md. No production-certification claim; no user-device VPN activated.

## Historical scaffold record (superseded by current status)

## Locked requirements
- Classic NoRoot Firewall-inspired five-tab UI: Home, Pending, Apps, Filters, Log.
- Default decision: **PENDING** (ask); unknown connections must not be forwarded.
- Allow/block by app, IPv4/IPv6 IP/CIDR and Wi-Fi/mobile.
- No root, no remote VPN server, minimal settings.
- Android 15 target device: Redmi 13C.

## Historical implementation snapshot (2026-11-03)
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

## Historical remaining work at scaffold stage
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

## UDP socket failure cleanup — 2026-11-04
- [x] Existing UDP flow send failure now closes and removes the session without retry (84b964f9).
- [x] Added closed-socket reuse regression test (2f6dbf0d); timing robustness requires review.
- [ ] Confirm CI, rule-event race behavior, and real TUN return path before VPN activation.

## CI verification expansion — 2026-11-04
- [x] Updated GitHub Actions to compile Android instrumentation-test APK via `:app:assembleAndroidTest` and assemble an unsigned release APK, in addition to unit tests and debug APK (commit ab1382c9).
- [x] Added nonempty ZIP integrity check for the unsigned release APK.
- [ ] **Not verified:** workflow execution, compilation, test success, or APK availability. An assembled AndroidTest APK is NOT an executed instrumentation test; an emulator/device test runner must be added.
- [ ] Unsigned release APK is not installable as-is; signing and release readiness remain pending.
- [ ] Critical gate unchanged: FirewallVpnService remains inactive until bidirectional TCP/UDP forwarding, loop prevention, attribution and leak tests pass.

## Engine integration milestone — 2026-11-04 (implementation, validation in progress)
- Repository baseline inspected at 6f6dfd0. VPN was a placeholder; no TCP transport existed.
- Added bounded TCP stop-and-wait proxy and IPv4/IPv6 UDP sessions, strict checksums/length validation, protected socket factories, monotonic timeouts and generation-based invalidation.
- Added real-socket loopback preflight that must pass BEFORE Builder.establish(); every production socket also requires successful VpnService.protect(). No VPN was activated in the development environment.
- Connected VpnService, rules, bounded metadata Logs and Pending allow/block actions; retained five tabs and existing SharedPreferences keys.
- Added unit/integration and Android instrumentation sources. Compilation and execution pending; not a claim of a working firewall.
- Unsupported fragments, IP options and IPv6 extensions fail closed. TCP performance/compatibility needs further validation; release is not yet ready.

## Transport validation and baseline CI diagnosis — 2026-11-04
- Executed first integrated JVM suite: all 14 new TCP/UDP tests passed, including real IPv4 TCP/UDP and IPv6 UDP loopback, TCP retry, duplicate/out-of-order data, half-close and reset.
- Reproduced baseline CI failures in UdpSessionManagerTest (GitHub run 41743946050). Fixtures sent to unbound localhost:53; ICMP port-unreachable raced the assertions. Tests now bind an ephemeral destination socket and close it after each test. Existing failed-socket test synchronizes intentional close/submission to test the intended path deterministically.
- A subsequent JVM run passed 109 tests. Later policy/pre-filter changes require final rerun.
- Corrected Global Pre-Filters precedence: first matching global filter now precedes app filters/app access. This prevents app Allow bypassing a global Block; persisted formats/keys remain unchanged.
- Updated instrumentation setup to AndroidX runner after catching missing legacy android.test classes at compilation. Emulator installation complete; execution still pending.
- Added CI jobs for JVM/integration tests, lint, debug/release/test APK builds and actual emulator instrumentation. CI execution for this implementation pending.

## APK/build milestone — 2026-11-04
- Verified local full build (build6): 109 JVM tests, `lintDebug`, debug APK, unsigned release APK and AndroidTest APK all succeeded. No tests skipped in JVM reports.
- Fixed foreground notification update to use startForeground (no unchecked notification-post call). Retained package visibility permission with a narrow lint annotation because listing/filtering all installed apps is a core firewall requirement. Switched cleanup scheduling to fixed delay.
- Added live Home status updates and VALIDATION.md with exact limits and device acceptance steps; rebuilding after the UI change.
- Published implementation branch `engine/vpn-transport` and draft PR #1 through authenticated GitHub API after plain git push lacked credentials. Main remains at the inspected baseline while validation continues.
- Software-emulated Android 29 boot in progress. No physical-device or real TUN activation has been performed. Do not interpret assembled APKs as device acceptance evidence.

## Emulator acceptance harness and CI setup fix — 2026-11-04
- Added an explicitly gated emulator-only VpnAcceptanceTest and loopback host echo fixture. It first verifies off-TUN forwarding, then relies on the service's protected preflight before TUN creation; checks actual TCP/UDP return traffic, UID attribution, active-flow revocation and unknown-app Pending. Execution pending.
- CI setup action failed while accepting unrelated SDK licenses before compilation (runs 41746348544/41746341066). Replaced it with the repository's previously working preinstalled-sdkmanager package-install approach.
- CI now runs no-VPN Android tests first, then the explicitly enabled emulator TUN acceptance stage. No physical device is automatically activated.
- Removed duplicate branch-push/PR builds to avoid spending two CI runs per update.

## Android instrumentation milestone — 2026-11-04
- Executed the three no-VPN Android instrumentation tests on a software-emulated API 29 device: 3 passed, 0 failed, 0 skipped. Verified real Android TCP/UDP packet pipeline, malformed-traffic rejection, and five-tab launch without altering stored firewall rules.
- GitHub run 41746647739 build job passed unit/integration tests, lint, all APK builds, ZIP checks and debug signature verification. Emulator job is still running; no TUN result claimed yet.
- Hardened return-path authorization to re-resolve Android socket ownership; cached attribution alone cannot authorize replies after a tuple is reassigned. Attribution loss revokes the existing flow, and changed owner/network invalidates old sessions.
- Added a policy-revocation-without-event return-path test and an IPv6 TCP multi-segment integrity test. These latest additions require execution.

## Protected Android preflight failure investigation — 2026-11-04
- Latest local full non-device build passed with 111 JVM tests (including IPv6 TCP multi-segment and event-free policy revocation), lint and all APKs.
- GitHub no-VPN instrumentation passed (three tests; gated VPN test skipped as intended).
- Explicit VPN acceptance failed BEFORE TUN establishment: protected UDP preflight received no datagram and timed out (run 41746647739). Safety gate prevented activation; this is an unresolved Android integration failure, not a passing VPN result.
- Added transport error propagation into preflight diagnostics to expose the underlying Android socket failure instead of only the timeout. Investigation continuing.

## Android native socket descriptor correction — 2026-11-04
- AOSP Android 10 Socket implementation confirms that `Socket()` only sets its implementation; `getFileDescriptor$()` returns the implementation descriptor without allocating it. Calling VpnService.protect() before the native descriptor exists can fail.
- TCP factory now binds locally to an ephemeral port to allocate the descriptor, then requires protect() success BEFORE connect/send. Local bind transmits no packets. Protection failures still close the socket.
- Added TCP-specific preflight error reporting; the original generic timeout did not distinguish UDP receive from TCP accept, so the earlier UDP attribution was not established.
- JVM failure-path test now verifies the TCP socket is locally bound but unconnected at protection time. Android verification of the fix pending.

## Independent-UID VPN acceptance correction — 2026-11-04
- The TCP descriptor fix passed protected preflight locally and allowed TUN establishment. A clean full build passed 111 JVM tests, lint and all APK builds.
- The previous VPN test's TCP/UDP exchanges succeeded but its UID-attribution assertion failed: traffic from the VPN owner's own UID did not prove interception. This was a test design failure, not a passing firewall test; the assertion prevented a false success report.
- Added a minimal `:probe` APK with a distinct UID and self-targeting instrumentation. The revised acceptance test requires probe TCP/UDP echo traffic, logged probe ownership, revocation of a live probe TCP connection, and default-blocked UDP appearing in Pending.
- Probe/main/test APKs compile successfully. Actual separate-UID test execution pending.

## Real TUN acceptance milestone — 2026-11-04
- **Passed on local Android 29 emulator with a separate probe UID:** TCP echo payload integrity, UDP echo payload integrity, correct probe package attribution in the real engine, revocation of an established TCP flow by a global IP/port rule, and default-blocked unknown UDP recorded in Pending. Test completed `OK (1 test)` after the three no-VPN Android tests passed `OK (3 tests)`.
- Protected preflight passed before TUN establishment. The native TCP descriptor fix is confirmed on Android.
- GitHub run 41748206475 completed successfully (build plus Android instrumentation). Independent-probe revision is also running in CI; local independent-probe success is already established.
- Clarified logs: QUEUED means transport acceptance, REPLY means an actual TUN write, and transport exceptions are recorded. This avoids labeling an accepted queue item as delivered traffic. Final regression run after logging changes is in progress.
- Full local build including both app/probe lint, 111 JVM tests and all APK builds passed (161 tasks, verified-build.log).

## Android-version verification expansion — 2026-11-04
- Expanded CI instrumentation to Android API 29 and API 35 (Android 15), with independent report artifacts per API. Both run off-TUN tests before the explicitly gated separate-UID TUN acceptance test.
- This complements, but does not replace, physical Redmi 13C checks for network transitions, Doze, OEM process management, and leak capture.

## ACK-wait CPU regression — 2026-11-04
- Removed a busy loop while TCP awaited ACKs; the worker now blocks on its bounded input queue and wakes immediately when a packet arrives, with periodic retransmission timer checks.
- Added a regression that bounds policy/UID lookup calls during an unacknowledged interval. Full local build passed **112 tests**, both lint tasks and all APKs.
- API 29/API 35 CI passed on the preceding functional revision (41749462403). Final scheduling regression run is pending; actual local real-TUN rerun is in progress.

## Android 15 skip audit correction — 2026-11-04
- Detailed CI logs for 41750213492 revealed that API 35 explicit VPN acceptance was skipped. A green job alone was insufficient evidence; previous API 35 real-TUN success statements are superseded by this correction.
- Emulator identification is now case-insensitive and also recognizes ranchu/goldfish hardware. Explicit VPN mode fails rather than silently skipping on an unexpected device.
- Added verify_vpn_results.py: the second-stage CI must contain exactly one executed, passing VpnAcceptanceTest with no skip/failure/error. Missing or skipped tests fail the job.
- No production engine code changed. Corrected Android 10/15 CI execution pending.

## Long-running owner cache correction — 2026-11-04
- Source audit found that reaching 128 attribution-cache entries invalidated all active transports. Repeated short-lived connections could therefore interrupt unrelated long-lived transfers.
- Added an atomic active-flow snapshot and prune only stale owner metadata when the cache fills. Existing active sessions are retained; cache size remains bounded by pruning to the at-most-64 active flow keys.
- Existing real UDP integration now checks active-flow snapshot before/after invalidation. No test-success claim for this change until CI completes.

## Stable network callback handling — 2026-11-04
- Capability callbacks previously invalidated every session, even when only Wi-Fi signal strength changed. Network callbacks now invalidate only when the selected non-VPN network or transport classification changes; rule-save events still revoke immediately.
- Prefer validated physical networks, falling back to available non-VPN networks when none are validated. This permits switching to a working mobile path when Wi-Fi loses validation without treating RSSI refreshes as network handovers.
- Recheck closure/policy immediately after TCP/UDP socket factory returns, before connect/send, so a concurrent rule/network revocation cannot reuse a socket allocated across invalidation.
- Changes require CI verification; physical network transition/Doze acceptance remains pending.

## Android 15 permission-denial test semantics — 2026-11-04
- API 35 acceptance surfaced IOException/sendto EPERM. Probe diagnostics now include mode and phase so an allowed-flow failure is distinguishable from an expected deny/revoke outcome.
- Explicit EPERM/EACCES cause chains are accepted only in blocked UDP or post-established-TCP-revocation phases; other I/O errors remain errors.
- Unknown UDP success additionally requires the exact probe/IP/port (10.0.2.2:28081) in engine Pending, so an OS-only denial with no packet attribution cannot falsely pass.
- Established-flow revocation now explicitly requires the probe's READY marker after its first successful echo. Production engine behavior is unchanged by this fixture correction; CI execution pending.

## Final verification and handoff — 2026-11-04
- Run 41753223859 passed every job for the final implementation. Both Android logs explicitly state: `Verified: explicit separate-UID TUN acceptance executed and passed (not skipped).`
- API 35 fixture accepts only explicit EPERM/EACCES in expected denied phases; exact UDP Pending and established-connection READY assertions prevent an unrelated OS failure from falsely satisfying the test.
- Created TEST_RESULTS.md with artifact downloads, per-API evidence, checksums, install/data-preservation instructions and remaining physical-device criteria.
- Local execution environment disconnected after successful local testing. No unverified local file link is presented; installable APKs and reports are available from the verified GitHub Actions artifacts.

## Transport-specific Android evidence — 2026-11-04
- Strengthened actual TUN acceptance to require separate QUEUED records for TCP port 28080 and UDP port 28081, plus a TCP payload-bearing REPLY written to TUN. A UDP-only event cannot satisfy the large TCP transfer claim.
- New checks require execution on both API levels; no additional production engine change.

## Full-duplex cumulative ACK reliability — 2026-11-04
- The 64 KiB actual-TUN test exposed a valid-upload rejection: requiring every ACK to equal the newest send sequence discarded upload bytes carrying an older ACK. Checking receive order before ACK progress also ignored valid response ACKs that crossed earlier upload data.
- Track the oldest unacknowledged server sequence and process valid cumulative ACK progress independently from ordered payload consumption. Future ACKs remain rejected; old ACKs never clear new outstanding data; receive-window bounds and unsigned wrap checks are retained.
- Regression proof: the two targeted real-socket tests fail against the preceding TCP implementation, while all 20 local transport tests pass with the fix (13 TCP session / 7 MSS codec). Full project CI pending; expected total 125 JVM tests.
- Probe failures now include received-byte progress, and nested instrumentation text is flattened in assertion messages to avoid corrupting the outer instrumentation output parser.

## 0.2.1 final verification — 2026-11-04
- Supersedes pending CI notes above: run 41801468947 passed build and both Android jobs; 125 JVM tests verified directly from XML. Both Android logs contain the explicit executed/not-skipped TUN success marker.
- Standalone installable debug APK extracted from that run and SHA-256 checked; release remains unsigned.

## Daily-use audit milestone — 2026-11-04 (in progress)
- Separate branch development/daily-use starts from verified 0.2.1-dev.
- ARCHITECTURE_AUDIT.md records security/lifecycle findings and Kotlin vs native stack tradeoffs. Targeted bounded-window/NIO upgrade chosen; no replacement of the verified UID/rule/protection boundary.
- No physical-device VPN activation; no settings/data migration performed. New code remains unverified until regression/actual-TUN CI runs.

## Bounded sliding-window and lifecycle implementation — verification pending
- Protected SocketChannel upstream, selector wakeups, 32 KiB upload buffer, <=64 KiB downstream in flight with <=128 retransmission records, 256-packet bounded input queue. Cumulative ACK removal, retransmission backoff, half-close and zero-window probes added; RST sequence validated. Plain socket path retained for baseline tests only.
- Rule reload closes explicit policy gate; numeric UID retained and rechecked; package changes invalidate transports. No-network declaration uses empty network array and gate rejects missing underlying path.
- Added separate-UID 1/10/100 MiB and four concurrent TCP transfers with byte integrity/half-close checks and elapsed/CPU/PSS metrics. Dedicated API 35 60-minute TCP/UDP TUN soak workflow added; not yet executed.

## Monitoring, rules portability and expanded regression milestone — verification pending
- Local JVM: all 136 tests passed, including original 125, four NIO TCP state/window tests, three seeded fuzz/property tests (25,000 arbitrary packets + 3,000 generated/checksum mutations), and 1/10/100 MiB plus concurrency socket tests. JVM loopback is not Android throughput evidence.
- Live flow metadata/counters and searchable protocol/result-filtered Logs inside existing fifth tab. Counts explicitly represent TUN IP bytes including retransmissions.
- Bounded 128 KiB versioned rules backup via Android document picker, whole-file validation and one atomic commit for both original preference keys. Five Android backup tests added; no user data migration. Always-on/lockdown uses Android VPN settings.
- First expanded API 29 TUN load run exposed connection reset on 1 MiB; remains FAIL pending diagnosis. Added progress/error diagnostics, not a timeout relaxation or test skip. API 35/soak not yet established as passing.
- DNS servers taken from underlying LinkProperties at establishment rather than hardcoded public resolvers. DNS changes during handover still require explicit compatibility acceptance.

## Security and PMTU milestone — verification pending
- Corrupt stored policy now closes forwarding gate; raw preferences are not rewritten. Bounded JSON nesting/UTF-8/schema checks protect import before recursive Android parsing. Log sampling reduces per-packet UI metadata churn; flow byte counters retain all admitted IP bytes.
- Added checksum-tested ICMPv4 fragmentation-needed / ICMPv6 Packet Too Big for permitted oversized UDP relative to cached underlying MTU; denied packets cannot allocate sockets or receive this response. Upstream TCP PMTU remains kernel-managed. Unsupported fragment/extension data remains denied.
- First API 35 actual TUN 1/10/100 MiB + concurrency passed; API 29 reset remains under investigation. Backup rejection test fixture corrected to mutate structured JSON (Android escapes CIDR slash in serialized JSON); the prior string replacement did not mutate its input.

## I/O authorization, backpressure and compatibility milestone — verification pending
- Retain fresh UID/package validation at each actual upstream write/connect and TUN reply; cheap generation/rule checks replace redundant UID binder calls inside bookkeeping loops. No UID TTL cache introduced. Added deny-at-I/O regression.
- TunWriter retries EAGAIN via POLLOUT with a bounded deadline and revalidates authorization after every wait. No blind retry or busy loop; counters advance after successful output. Android 10 reset diagnosis remains subject to actual TUN rerun.
- Protected UDP DatagramChannel uses selector wakeups; unconnected send plus exact remote address/port receive filtering preserves valid zero-length datagrams (connected JDK channel optimized them away). Tests cover empty/1200/1472-byte UDP and counters.
- Separate-UID fixtures now exchange real DNS wire messages over UDP/TCP, and a 1200-byte UDP echo (QUIC-sized transport, not a QUIC/TLS handshake certification). Mandatory metric verifier rejects missing load or <60-minute soak evidence.
- Fixed JVM-only CPU metric reflection so Android unit-test compilation does not require unsupported management APIs.

## Android evidence correction and lockdown acceptance harness — verification pending
- Latest 150-test build passed, but all Android runs correctly failed when sampled SYN-ACK suppressed the first payload log. Distinct payload/control sample keys now preserve the mandatory actual-TCP-return assertion; assertion was not weakened.
- Added removable test-only DPC to probe APK and an emulator-only process-death test: supported DevicePolicyManager Always-on + lockdown, separate-UID denied UDP during kill/restart, independent host leak sink, recovery and cleanup checks. No admin component added to firewall APK; physical devices are refused.
- 60-minute soak now records minute heartbeats/PSS/active flow counts and starts with verified screen sleep. This is emulator screen-off evidence only, not physical Doze/battery certification.
- Removed hash-based RecyclerView stable IDs (distinct package names can have equal Java hashes); DiffUtil retains full package identity.

## DNS/network lifecycle and reproducible tooling milestone — verification pending
- Network/DNS changes now version the route configuration, invalidate old flows and close policy gate. Worker establishes replacement TUN before releasing the old descriptor; offline placeholders retain captured routes with a closed gate. Internal transport failure retains any established TUN while retrying, rather than deliberately restoring ordinary routing.
- Per-service START guard no longer depends on global UI status. Added emulator Wi-Fi loss/reconnect, optional actual cellular handover (otherwise explicitly NOT_TESTED), repeated START and two STOP/START roundtrips.
- Link-local IPv6 upstream addresses acquire the selected physical interface scope; policy still evaluates original numeric addresses. Missing scope fails closed. Three JVM tests added; real link-local/NAT64 remains unverified.
- API 29 diagnostics show all 1 MiB bytes arrived, then upstream reset at EOF. Explicit host fixture SHUT_WR and channel-native half-close added; reset is not accepted as a successful EOF.
- Gradle 8.9 wrapper generated with official pinned SHA-256. Release key remains external/private; no signing key created.

## Isolated system DNS and environment checkpoint — verification pending
- Add real Android system name resolution from the separate UID, not only manually constructed DNS packets. Emulator DNS uses an isolated host port-53 fixture; test requires correct A result and an attributed port-53 QUEUED event. Host UDP/TCP DNS fixtures self-check before emulator boot.
- DPM lockdown coordinator reinstalls the firewall APK after Gradle UTP uninstalls its tested target; previous failure happened before lockdown was configured and is not a protection result.
- Source edits continued through GitHub after local runtime became unavailable. No physical VPN activation or user-data migration.

## Numeric/IP family audit and independent half-close controls — CI pending
- Restrict IPv4 rule digits to ASCII; Unicode digit-like hostnames must not reach InetAddress/DNS lookup. Short hex-only hostnames rejected before resolution.
- Reject mapped IPv6 wire addresses which Java normalizes to IPv4; do not silently change response IP family. Three targeted tests added, not locally executed while runtime is unavailable.
- API 29 returned every 1 MiB byte then upstream response-read reset before EOF. Added no-VPN Socket and bound-SocketChannel controls against the same host fixture, explicit graceful linger and preserved host logs. Reset remains a failure.

## Android system DNS identity investigation — CI pending
- Real system DNS failed on API 29 before load. Preserve/log unknown numeric UID, package count and transport tuple without payload or DNS content; no permission is granted to package-less/shared identities.
- AOSP resolver source explicitly uses AID_DNS on Q in affected modules because per-app fchown conflicts with Q VPN isolation: https://android.googlesource.com/platform/packages/modules/DnsResolver/+/refs/tags/android-vts-12.1_r4/resolv_private.h . Whether this explains our emulator is not assumed without UID evidence.
- Host DNS fixture now accepts EDNS additional records and returns only the question plus its controlled answer. No-VPN Android name-resolution controls must pass before drawing conclusions about the firewall.

## Independent failure diagnostics while runtime is unavailable
- CI prints direct Socket/SocketChannel controls and preserves synthetic host logs. Temporary read-only artifact diagnostic workflow inspects prior controls through GitHub while local execution is disconnected.
- Disposable emulator disables captive-portal probing (isolated DNS cannot validate Internet domains) and Private DNS auto-probes to make plaintext system DNS attribution deterministic. Test-lab configuration only; no production change or claim about DoT.

## IPv6 NIO and diagnostic attribution regression — CI pending
- Added 1 MiB real-socket IPv6 NIO TCP half-close coverage, and both-family UDP tests at zero/1200/MTU-limit payloads with foreign-sender rejection.
- Transport errors now retain the original connection/protocol for filtered Logs; an asynchronous failure regression checks attribution.
- Expected full JVM total: 158 including the unchanged 125 baseline. This is an expectation until CI XML is inspected, not a success claim.

## Sleep-aware timeouts and independent-control findings — CI pending
- Production flow/idle/RTO clocks now receive Android elapsedRealtimeNanos (includes deep sleep); JVM default stays monotonic. A simulated-suspend socket test verifies immediate stale-flow expiry after wake. Expected JVM total 159, pending CI.
- Screen-off soak uses a bounded instrumentation-only partial wakelock and elapsed realtime. Release APK has no new wakelock permission/acquisition. This maintains test traffic generation, not a claim about idle physical-device battery.
- Independent no-VPN API 29 Socket returned all 1 MiB then reset too (artifact diagnostic run 41817455053): TUN is not required to reproduce that EOF problem. No reset is accepted by actual TUN half-close assertions.
- Replaced invalid multi-threaded blocking SocketChannel-adapter control (could serialize reader/writer) with single-owner NIO control. Host fixture keeps FIN-bearing descriptor briefly alive for NAT drain. Direct-control failures are printed as failures without preventing remaining diagnostics; actual TUN acceptance remains strict.
- Clock reference: https://developer.android.com/reference/android/os/SystemClock .

## Baseline contract and DNS deny acceptance — CI pending
- Committed exact 125 baseline test IDs extracted from verified run 41801468947. CI rejects missing/skipped/failing cases and reports actual total in verification-summary.json.
- Unique-name system DNS default-deny probe must fail resolution and create per-app port-53 Pending on supporting OS builds. No generic resolver exception.
- Lab starts with cellular disabled to prevent default-network switches invalidating isolated DNS control. Handover explicitly enables cellular; mobile DNS requires MOBILE-attributed DNS event, then cellular disables to test Wi-Fi return.
- Rule evaluation stops at first matching global/application filter without intermediate matching-list allocations; precedence and mutable-list baseline tests retained.

## Confirmed Android 10 external compatibility limits / diagnostic isolation
- Source f278ced, run 41818439830 API 29: system DNS packets explicitly report UID 1051, zero packages, UDP destination 10.0.2.3:53, and are correctly denied. Attribution to requesting app is unavailable in this resolver build; no global DNS bypass is introduced.
- Independent Socket AND NIO controls without VPN both received all 1 MiB then reset instead of EOF. This is an emulator/underlying-path compatibility failure independently of our TUN endpoint; clean EOF is still not accepted as passing.
- Acceptance records system-DNS and client-first-half-close results separately and keeps their final assertions. Numeric 1/10/100 MiB payload tests can run on API 29 without claiming clean EOF, while a separate actual-TUN half-close test remains strict. API 29 overall acceptance still FAILs if either required capability fails.
- The per-app DNS default-deny case is explicitly NOT_TESTED when framework identity is unavailable; this is not a passing skip. Other transport/lifecycle work continues.

## Persisted-data recovery and service restart hardening — CI pending
- Ordinary RuleStore/AppRuleStore saves now refuse to overwrite malformed current records; tolerant display loading cannot accidentally discard a corrupt block during an unrelated edit. Export reads strict validated snapshots; only explicit validated import replaces corrupt keys.
- After protected preflight, a malformed-policy bootstrap retains a closed TUN instead of deliberately releasing routing. Added actual-TUN corruption/blocked-I/O/explicit-repair acceptance and Android storage-preservation checks.
- Successful/duplicate START returns START_STICKY to aid OS process recovery. STOP/revoke explicitly terminate; sticky restart alone is not a lockdown guarantee. Home status distinguishes OFF after a terminal error.
- Added a single-APK debug artifact to reduce confusion with instrumentation/probe APKs. Release remains unsigned.

## Emulator association and verification resource control
- API 35 completed load and reached Wi-Fi return, but merely enabling the radio did not reassociate the emulator SSID. Explicit test-only AndroidWifi reassociation added; no production network preference override.
- Superseded intermediate emulator workflows are cancelled to free CI slots. Keep the latest source and the already-running sleep-aware 60-minute engine sample (41818439830); no unfinished soak is counted as passing.
- Maintenance workflow is temporary development scaffolding, not an app feature.

## 2026-11-04 — independent lockdown evidence

- Run lockdown acceptance independently from network compatibility assertions; otherwise an unrelated mobile DNS failure prevents process-death testing entirely.
- Create a new probe UDP socket for every attempt across process death. A socket retained from the old VPN is insufficient evidence for lockdown of newly opened connections.
- Require external-sink positive controls before and after the test. Refuse installation over existing firewall app data even on an emulator.
- Exact retained soak evidence from source 72b4f55: 3,605,281 ms, 42,532,864 TCP bytes plus UDP echoes, engine CPU 49,528 ms, PSS before/after 120,327/48,537 KiB. Screen off with a test-only partial wake lock. The encompassing JUnit test FAILED later on DNS Pending; this is not a complete soak acceptance PASS or a battery/Doze result.

## 2026-11-04 — broaden diagnostics without masking failures

- Keep DNS compatibility failures until the final assertion so reconnect, repeated START/STOP and corrupt-policy repair are still exercised. The test still fails when any recorded requirement fails.
- Add 32 round-trip latency samples (median/p95) and one persistent TCP stream throughout the 60-minute screen-off transfer loop, alongside fresh TCP/UDP sessions. The metrics validator requires those observations; pending execution.

## 2026-11-04 — transparent route status and crash diagnostics

- Home status distinguishes captured VPN routes from an inactive app; it no longer claims traffic blocking while the VPN is off.
- Preserve full emulator logcat independently of UTP: API 29 system crashes left no per-test logcat. Crashes remain failures.
- Downloaded candidate 16d9448 APK matches CI SHA-256 b2e54bae18d506688db6f9b1d523232f1c04363b659a3e543a5835d4eb67328b; development candidate, not daily-use acceptance.

- Lockdown harness initially failed before VPN activation because `pm path` returns nonzero for an absent package. Use exact `pm list packages` membership for the fresh-install guard; no existing data is overwritten. Verification rerun required.

## 2026-11-04 — explicit VPN STOP lifecycle fix

- Actual API 35 acceptance at 16d9448 failed `expected OFF but was RUNNING` after STOP. UI used stopService while descriptor closure was deferred until onDestroy.
- A live VPN is platform-bound: now the STOP action closes transports/original TUN and interrupts the worker (which closes duplicated descriptors in finally) before stopSelf. UI and instrumentation invoke the same STOP action. Revoke and destroy share cleanup.
- Test retains the OFF assertion and repeated real TCP/UDP reconnect; verification pending. No failure is converted into a timeout allowance or skip.
