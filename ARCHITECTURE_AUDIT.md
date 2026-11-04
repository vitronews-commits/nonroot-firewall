# Architecture/security audit — 2026-11-04

Baseline: 0.2.1-dev, commit 0887b1c. Preserve 125 JVM tests and separate-UID Android TUN acceptance.

## Decision: retain the policy boundary and incrementally improve TCP

| Approach | Benefit | Cost/risk | Decision |
|---|---|---|---|
| Existing Kotlin proxy + bounded window/NIO | Keeps protected socket factories, UID lookup, live rules, preflight and regression harness | TCP state correctness remains our responsibility; needs loss/window/half-close/load tests | Implement and measure; development status until acceptance |
| lwIP integration | Mature TCP/IP algorithms, permissive BSD license | JNI/NDK/ABI builds, callbacks and buffer ownership, policy/UID hooks, fragmentation attack surface; must port all acceptance evidence | Candidate if measured custom endpoint cannot meet requirements |
| hev tun2socks | Existing Android/dual-stack adapter | SOCKS server/adapter plus native dependencies; app-rule checks must remain before every forwarded packet and reply | Do not replace verified boundary without prototype comparison |

References: RFC 9293 https://www.rfc-editor.org/rfc/rfc9293.html ; lwIP upstream https://github.com/lwip-tcpip/lwip ; Android VpnService https://developer.android.com/reference/android/net/VpnService .

## Findings / required corrections

- HIGH: reload invalidates before replacing rules, allowing new sessions to observe old policy under the new generation. Add explicit closed policy gate across reload and install new rules before invalidation.
- HIGH: attribution cache retains package only. Retain numeric UID too; reject ownership change on live flow. Package replacement/removal must revoke live transports.
- MEDIUM: no-network underlying declaration uses null (system default). Use empty array and require a selected non-VPN network at the policy boundary.
- MEDIUM: any RST terminates TCP without sequence validation. Validate RST sequence and challenge in-window non-exact RSTs.
- MEDIUM: upstream blocking write can stall a TCP worker indefinitely; protected SocketChannel and bounded nonblocking upload buffer prevent this.
- PERFORMANCE: stop-and-wait response and 50 ms socket reads serialize progress. Bounded send window, cumulative ACK queue and selector wakeups avoid per-segment sleeps.
- COMPATIBILITY: static public DNS is not a DNS64 strategy. Use numeric DNS from selected network when establishing TUN, preserving rule/UID enforcement; network DNS changes require reconnect/revalidation.
- RESOURCE: bounded 64 sessions / 32 incoming packets / 500 logs already limit metadata. Need snapshot counters without payload retention and long-running evidence.
- PROCESS DEATH: system-wide fail-closed requires user-enabled Android Always-on + lockdown; no app-only guarantee.

## Boundaries retained

Protected sockets before connect/send; upstream network bind; deny unknown/shared UID; strict checksums and MTU; unsupported fragments/options/extensions dropped; default pending never forwarded. DNS/DoT/DoH/QUIC receive ordinary application rules, never a privileged bypass. No new boot broadcast workaround: expose supported Android Always-on settings.

## Acceptance gaps

Physical Redmi/HyperOS, IPv6-only/DNS64/NAT64 real networks, external DNS/IPv6 leak capture, lockdown under process kill and long-duration battery behavior require measured evidence. Emulator and JVM results must not be substituted for these.
