# Changelog

## 0.3.0-dev — unreleased acceptance candidate

- Bounded NIO TCP sliding window, cumulative ACKs, retransmission, half-close,
  MSS handling and zero-window persistence; keepalive and tuple-incarnation fixes.
- Protected UDP sessions, fresh I/O UID authorization, closed network-loss gate,
  atomic DNS/TUN replacement and strict persisted-policy validation.
- Five-tab interface retained; live flows, searchable logs and validated JSON
  rule import/export without changing the existing preference keys.
- Packet fuzzing, IPv6 socket regressions, MTU error generation, throughput and
  emulator lifecycle/soak/lockdown tests. Detailed evidence is in TEST_RESULTS.md.
- Known unresolved Android system DNS / emulator compatibility failures prevent
  a production-ready designation. No private release signing keys added.

## 0.2.1-dev — baseline

125 JVM tests and separate-UID actual TCP/UDP TUN acceptance on API 29/35;
conservative stop-and-wait TCP, app/network/IP/CIDR/port policy and five-tab UI.
Historical results remain in TEST_RESULTS.md.
