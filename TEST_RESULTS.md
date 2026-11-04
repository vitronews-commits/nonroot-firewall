# 0.3.0-dev acceptance ledger — 4 November 2026

**Not accepted for daily use.** Main remains 0.2.1-dev. Candidate changes are on
`development/daily-use` ([PR #3](https://github.com/vitronews-commits/nonroot-firewall/pull/3)).
Latest source is `7fd4a62f60bbd1c15ab974c2a6058a91fc440954`, [CI run 41865446592](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41865446592).
A passing sub-check does not make its enclosing failed JUnit suite pass.

| Capability | Status | Evidence / limitation |
|---|---|---|
| Original 125 JVM regression IDs | PASS | Latest run: 162 tests, zero failures/errors/skips; all 125 baseline IDs preserved |
| Candidate build/lint/debug and unsigned release | PASS | Latest run 41865446592, build job 126698366073 |
| New FIN/keepalive/flow-incarnation regressions | PASS | Latest run: 162 JVM tests, zero failures/errors/skips |
| Separate-UID IPv4 TCP 1/10/100 MiB + four concurrent | PASS | API 35 c0fa47e, run 41813702595; 100 MiB 130173 ms (~6.44 Mbit/s) |
| CPU / memory load measurements | PASS | Same run: engine CPU 92256 ms / 153090 ms elapsed, PSS 106117 to 47341 KiB; emulator only |
| API 35 complete separate-UID real-TUN network/lifecycle acceptance | PASS | Latest explicit test: 1 executed / 0 skipped; TCP/UDP/DNS, rule revocation, handover, reconnect, STOP/START and closed-policy repair |
| API 35 1/10/100 MiB, concurrency and latency | PASS | 837/6,804/70,632 ms; four concurrent streams; median 1,265 µs / p95 1,802 µs |
| API 29 system DNS compatibility | FAIL | f278 source: resolver UID 1051 has zero packages and is denied; no DNS exemption |
| API 29 clean client-first EOF | FAIL | Independent no-VPN Socket and NIO controls also reset after all 1 MiB; not proven firewall-caused |
| API 29 latest entire test | FAIL | DNS UID 1051 has no packages and is denied; client-first EOF resets in no-VPN controls; emulator then crashes with EMFILE / INSTRUMENTATION_ABORTED |
| 60-minute screen-off transport interval | MEASURED | 3,601,482 ms; 42,467,328 TCP bytes; 648 persistent echoes; test-only partial wake lock |
| Entire 60-minute acceptance test | FAIL | After the transfer, new UDP ownership returned UID 0/no packages; exact app-specific Pending assertion did not pass safely |
| Always-on lockdown across process death | FAIL | No UDP escape observed and probe remained blocked, but Android did not restore an active VPN within 60 seconds; post-test positive control not reached |
| Physical Redmi 13C / Android 15 / HyperOS | NOT TESTED | User-operated physical validation required |
| Doze / battery / reboot protection | NOT TESTED | Screen-off with test wake lock is not Doze or battery certification |
| Real IPv6-only, DNS64/NAT64, external IPv6/DNS leak capture | NOT TESTED | Requires suitable network and independent capture |
| Full DoT / DoH / QUIC protocol handshakes | NOT TESTED | Generic TCP/UDP transport is not equivalent protocol acceptance |
| Fragment reassembly / general ICMP forwarding | NOT TESTED | Unsupported; fail-closed dropping is intentional |

Latest completed run: https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41865446592
Latest source: https://github.com/vitronews-commits/nonroot-firewall/commit/7fd4a62f60bbd1c15ab974c2a6058a91fc440954

Local Gradle invocation after environment recovery failed before build because the
Gradle distribution endpoint was unreachable. It is not counted as a test result.
Pinned build and artifact extraction instructions: BUILDING.md. APK installation
alone does not prove forwarding safety. No physical VPN was enabled automatically.

---

## Historical 0.2.1-dev evidence and downloads

# NonRoot Firewall 0.2.1-dev — επαλήθευση

Ημερομηνία: 4 Νοεμβρίου 2026.

## Λήψεις

- [APKs (ZIP)](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41801468947/artifacts/13307608899)
- [JVM/lint reports](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41801468947/artifacts/13308037129)
- [Android 10 reports](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41801468947/artifacts/13307883521)
- [Android 15 reports](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41801468947/artifacts/13308097555)
- [Πλήρες CI run](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41801468947)

Μέσα στο APK ZIP, η εγκαταστάσιμη εφαρμογή είναι:
`app/build/outputs/apk/debug/app-debug.apk`.
Το `app/build/outputs/apk/release/app-release-unsigned.apk` είναι unsigned.
Τα AndroidTest/probe APKs είναι μόνο fixtures για επανάληψη δοκιμών.

## Αποτελέσματα

| Έλεγχος | Αποτέλεσμα |
|---|---|
| JVM unit/integration | 125 επιτυχίες, 0 αποτυχίες/παραλείψεις |
| App lint και όλα τα APK builds στο CI | Επιτυχία |
| Debug signature και APK ZIP integrity | Επιτυχία |
| Android 10 / API 29 | 3 tests χωρίς VPN + 1 εκτελεσμένο πραγματικό TUN test |
| Android 15 / API 35 | 3 tests χωρίς VPN + 1 εκτελεσμένο πραγματικό TUN test |
| TCP/UDP TUN με ξεχωριστό UID | TCP echo 64 KiB, UDP echo, πραγματικό package attribution |
| Αλλαγή κανόνα σε ενεργό TCP flow | Η επόμενη μεταφορά αποκλείεται |
| Άγνωστο UDP flow | Αποκλεισμός και καταχώρηση στο Pending |
| IPv6 TCP/UDP | Πραγματικά JVM loopback integration tests |
| Αναμονή ACK | Regression test αποκλείει busy-wait / αδιάκοπα policy lookups |

Ελεγμένο commit: `22e74810ee6669402550062489a8c8d1e55de5db`.
Το explicit VPN test δεν θεωρείται επιτυχημένο αν παραλειφθεί: το CI ελέγχει
τα JUnit XML και απαιτεί ακριβώς ένα executed/passing result χωρίς skip/error.
Η παράλειψη στην προηγούμενη έκδοση του API 35 test διορθώθηκε και δεν αποτελεί
στοιχείο επιτυχούς επαλήθευσης.

Το preflight ελέγχει πραγματικά protected TCP/UDP sockets και επιστρεφόμενα
IP packets πριν το `Builder.establish()`. Αποτυχία αποτρέπει δημιουργία TUN.
Η πραγματική TUN δοκιμή χρησιμοποιεί χωριστή εφαρμογή probe με άλλο UID·
κίνηση του ίδιου του VPN app δεν αρκεί ως απόδειξη interception.
Δεν ενεργοποιήθηκε VPN σε φυσική συσκευή του χρήστη.

## Νέα επαλήθευση 0.2.1-dev

MSS negotiation και bounded TCP option parsing, με απόρριψη malformed options.
Διορθώθηκε cumulative ACK processing σε αμφίδρομη μεταφορά: παλαιότερα ACKs
δεν απορρίπτουν έγκυρο upload και ACKs μπορούν να προχωρούν ανεξάρτητα από
την παραλαβή ordered payload. Δύο regression tests αποτυγχάνουν στον προηγούμενο
κώδικα και περνούν στη διόρθωση. Τοπικά: 20 transport tests επιτυχία.
Το CI επιβεβαίωσε 64 KiB TCP echo και πραγματικό TCP REPLY στο TUN και στα δύο APIs.

## Υλοποιημένα

IPv4/IPv6 TCP/UDP forwarding, Android UID attribution, κανόνες ανά εφαρμογή,
Wi-Fi/mobile/άλλο δίκτυο, IP/CIDR και port, timeouts και cleanup, fail-closed για
άγνωστα/μη επιτρεπόμενα, πραγματικά Pending και Logs. Διατηρήθηκαν οι πέντε
καρτέλες και τα υπάρχοντα SharedPreferences keys. Global pre-filters τρέχουν
πριν από app rules, σύμφωνα με το UI. Logs: QUEUED = αποδοχή στην ουρά,
REPLY = πραγματική εγγραφή στο TUN, transport failure = αποτυχία socket/I/O.

## Εγκατάσταση και διατήρηση ρυθμίσεων

Για ενημέρωση χωρίς απώλεια δεδομένων χρειάζεται ίδιο signing key. Αν το Android
αρνηθεί εγκατάσταση λόγω διαφορετικής υπογραφής, μην απεγκαταστήσεις την παλιά
εφαρμογή χωρίς backup. Σε debuggable εγκατάσταση, με ADB και ξεκλείδωτη συσκευή:

```sh
adb exec-out run-as com.nonroot.firewall cat shared_prefs/firewall_rules.xml > firewall_rules.xml
```

Επιβεβαίωσε ότι το backup περιέχει τους κανόνες πριν από αντικατάσταση.
Μετά την εγκατάσταση νέου debuggable APK, η επαναφορά γίνεται με κλειστή εφαρμογή:

```sh
adb shell am force-stop com.nonroot.firewall
adb shell run-as com.nonroot.firewall mkdir -p shared_prefs
adb shell -T "run-as com.nonroot.firewall sh -c 'cat > shared_prefs/firewall_rules.xml'" < firewall_rules.xml
```

Οι εντολές φυσικής συσκευής παρατίθενται ως οδηγίες· δεν εκτελέστηκαν εδώ.
Το unsigned release απαιτεί μόνιμο ιδιωτικό signing key πριν από διανομή.

## Όρια και υπολειπόμενοι έλεγχοι

Development build, όχι ακόμη production certification σε φυσική συσκευή.
Ο TCP endpoint είναι συντηρητικός stop-and-wait με negotiated MSS έως 1460 bytes
IPv4 / 1440 IPv6 (defaults 536/1220 όταν απουσιάζει MSS). Το throughput παραμένει περιορισμένο. Δεν υλοποιούνται fragments, IPv4 options,
IPv6 extension headers/jumbograms, ICMP path-MTU synthesis ή zero-window
persistence probes· μη υποστηριζόμενη κίνηση απορρίπτεται. Μεγάλα fragmented
DNS replies μπορεί να αποτύχουν. DNS/DoT/DoH δεν αποκτούν αυτόματο bypass.
Ασαφή/shared UIDs μπλοκάρονται. Pending/Logs είναι bounded process-local metadata.

Στο Redmi 13C απομένουν:

1. Wi-Fi ↔ mobile αλλαγές κατά ενεργή μεταφορά και αποσύνδεση/επανασύνδεση.
2. Οθόνη κλειστή/Doze, πολλαπλά START/STOP, ανάκληση VPN και reboot.
3. Always-on VPN + Block connections without VPN/lockdown και θάνατος διεργασίας.
4. Εξωτερικό packet capture για DNS/IPv6 leaks και μεγαλύτερα downloads/uploads.

Ο engine απορρίπτει μη επιτρεπόμενη κίνηση. System-wide αποκλεισμός αν το Android
αφαιρέσει το VPN μετά από process death απαιτεί το Android lockdown· το app μόνο
του δεν τον εγγυάται. Πλήρεις τεχνικές λεπτομέρειες: [VALIDATION.md](VALIDATION.md).

Το τελικό debug APK λήφθηκε από το επιτυχές CI και επαληθεύτηκε το SHA-256 του.
Τα APKs και reports διατίθενται επίσης ως τα παραπάνω GitHub artifacts.

## SHA-256 των CI APKs

```text
e6dbff56dd20e6da3353dcad6af30f6f342a3fb27007f08e635f1166845e9cec  app/build/outputs/apk/debug/app-debug.apk
6dfe1af41c236104ed634d5536ec84a6dedf282c7906476b4e3128372799f2d7  app/build/outputs/apk/release/app-release-unsigned.apk
```
