# 0.3.0-dev candidate validation addendum

This addendum supersedes historical stop-and-wait descriptions below. The engine
now has bounded sliding-window response forwarding (up to 64 KiB / 128 records),
32 KiB upload buffering and 64 total flows. It negotiates neither window scaling
nor SACK. It is a constrained proxy endpoint, not a complete production TCP/IP stack.

Per-flow atomic leases close the late-response/tuple-reuse race. Authorization
is rechecked at actual upstream I/O and return delivery; no UID TTL cache grants
access. Rule changes invalidate active sessions. Bytes already accepted into OS
network buffers cannot be recalled. Unknown/shared/package-less ownership remains
denied, including the observed API 29 system DNS UID 1051.

Both IP default routes remain captured during underlying-network changes; an
unavailable network closes the forwarding gate. Replacement TUN establishment
precedes old descriptor release. This does not substitute for Android Always-on
and lockdown when the process dies. Tests must verify those platform mechanisms.

IPv4 fragments, IPv6 extension headers and unsupported transport traffic are
dropped. Oversized permitted UDP can receive synthesized ICMP fragmentation-needed
or ICMPv6 Packet Too Big; this is not general ICMP forwarding, complete end-to-end
PMTU discovery or NAT64 validation. DoT/DoH/QUIC use the same app policy as other
TCP/UDP, but complete TLS/HTTP3 protocol compatibility has not been demonstrated.

Strict rule loading fails closed on corrupt data. Ordinary saves refuse to replace
corrupt policy; validated explicit import can repair it atomically. UI preferences
and five tabs remain. A routing-established flag distinguishes a captured closed
TUN from an early bootstrap error.

See TEST_RESULTS.md for PASS / FAIL / NOT TESTED evidence. Physical Xiaomi/HyperOS,
real IPv6-only/DNS64/NAT64, external leak capture and battery behavior remain required.

---

## Historical validation record

# NonRoot Firewall 0.2.1-dev — verification and limits

This is a development build, not a verified production firewall. The engine is
connected to VpnService; Android device-level TUN, routing and leak validation
must be distinguished from passing off-tunnel socket tests.

## Architecture

- The TUN reader accepts only complete, checksum-valid TCP/UDP packets with
  trustworthy Android UID attribution. Missing/ambiguous shared-UID ownership,
  unsupported packets, BLOCK and PENDING all fail closed.
- Global pre-filters run first (first match), followed by application IP/port
  filters (first match), network-specific app access, generic app access,
  then PENDING. This corrects the previous mismatch with the Pre-Filters UI.
- Every upstream TCP/UDP socket must pass VpnService.protect() before connect
  or send. A local TCP bind first allocates Android's lazy native descriptor;
  this does not transmit traffic. Production sockets additionally bind to the selected non-VPN Android
  Network; the policy network classification refers to that same network.
- Before Builder.establish(), a protected loopback preflight sends synthetic
  IP packets through the actual TCP/UDP forwarder, receives replies and checks
  the returned packet addresses, ports, payload and checksums. Failure prevents
  TUN creation. Actual TUN delivery still needs Android end-to-end testing.
- IPv4 and IPv6 use default routes; unsupported traffic is dropped inside the
  tunnel. There is no bypass list and no automatic DNS exemption. DNS UDP/TCP,
  DoT and DoH are subject to the originating application's connection policy.
- Flow tables, workers, queues, attribution cache and logs are bounded. Rule or
  network changes invalidate flows; generation numbers suppress late replies.
- Logs distinguish QUEUED (accepted for transport), REPLY (written to TUN), and
  transport failures; queue acceptance alone is not a delivery guarantee.
- No packet payloads are logged. Pending/Logs are process-local bounded metadata,
  not durable traffic history. Pending approval applies to subsequent retries.

## Implemented transport limits

- MTU 1500. IPv4 options, fragmentation and IPv6 extension headers/jumbograms
  are not implemented and are dropped. Large fragmented DNS replies can fail;
  there is no synthesized ICMP/ICMPv6 Packet Too Big or DNS truncation response.
- TCP uses a conservative stop-and-wait endpoint with negotiated MSS,
  bounded by the TUN MTU (1460 bytes IPv4 / 1440 IPv6). If the client omits
  MSS, default send limits are 536 bytes IPv4 / 1220 IPv6. It supports duplicate/out-of-order rejection, retransmission, half-close/reset,
  and sequence wrap arithmetic. It does not negotiate SACK/window scaling,
  implement full congestion control or implement zero-window persistence probes.
  Throughput and compatibility are limited. This is not a mature full TCP stack.
- At most 64 active transport workers/flows, 32 queued packets per flow;
  overload drops requests. UDP idle expiry is 30 seconds; TCP 120 seconds.
  An independent sweeper closes idle resources, including blocked socket I/O.
- UDP response oversize is detected rather than silently truncated. Connected
  UDP sockets accept replies only from the authorized destination tuple.
- On service/process death Android can remove the VPN and restore ordinary
  routing. Device-wide fail-closed behavior across process death requires
  Android's Always-on VPN + Block connections without VPN (lockdown). This is
  not guaranteed by the app alone. Lockdown/device reboot tests remain required.

## Reproduce local checks

Use JDK 17, Gradle 8.9, Android platform 35 and build-tools 35.0.0:

```sh
gradle :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease :app:assembleAndroidTest
```

The workflow also runs `:app:connectedDebugAndroidTest` on API 29 and API 35 emulators.
The gated second stage installs the `:probe` test application under a separate
Android UID and runs its instrumentation through a local host TCP/UDP echo server.
Traffic generated by the VPN's own UID is insufficient proof of interception;
the acceptance test requires a logged, attributed connection from the probe UID.
The default instrumentation suite does not activate a VPN and does not change
saved rules. It executes TCP/UDP packet transport on Android, verifies that the
five-tab activity launches without changing rules, and rejects malformed input.

## Device acceptance still required

1. Install a build signed with the same key to retain existing settings. A debug
   APK from a different build machine may have a different debug signer. Do not
   uninstall the current app without exporting/backing up its app data first.
2. On Android 10 and Android 15, run instrumentation first. Then tap START and
   grant Android's VPN permission. Confirm a preflight-passed event precedes
   RUNNING; any preflight error must leave VPN inactive.
3. From a separate app, confirm default PENDING blocks TCP, UDP/QUIC and DNS;
   approving a request permits its next retry. Verify another app remains blocked.
4. Test IPv4/IPv6 TCP request/response and UDP request/response, DNS UDP and TCP,
   HTTPS downloads/uploads, TCP half-close, retransmission under loss, simultaneous
   connections, idle expiry and capacity pressure. Confirm payload integrity.
5. Apply global/app CIDR+port blocks during active transfers; no later payload
   should pass. Check Wi-Fi/mobile rules while switching networks and disconnecting
   the selected network. Confirm protected upstream packets do not recur in TUN.
6. Check VPN revoke, STOP, repeated START/STOP, screen-off/Doze, force-stop,
   reboot, and lockdown. Use external packet capture to test DNS/IPv6 leaks.
7. Record device/OS/build identity and actual results before promoting release.

## Release preparation

`app-release-unsigned.apk` is intentionally unsigned. A persistent private release
key and a chosen distribution/update strategy are required before release signing.
Do not use an ephemeral debug key for a published release. No private release key
is generated or committed by this change.
