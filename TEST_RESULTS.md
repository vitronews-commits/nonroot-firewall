# NonRoot Firewall 0.2.0-dev — επαλήθευση

Ημερομηνία: 4 Νοεμβρίου 2026.

## Λήψεις

- [APKs (ZIP)](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41753223859/artifacts/13286018519)
- [JVM/lint reports](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41753223859/artifacts/13287475815)
- [Android 10 reports](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41753223859/artifacts/13286969119)
- [Android 15 reports](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41753223859/artifacts/13286993921)
- [Πλήρες CI run](https://github.com/vitronews-commits/nonroot-firewall/actions/runs/41753223859)

Μέσα στο APK ZIP, η εγκαταστάσιμη εφαρμογή είναι:
`app/build/outputs/apk/debug/app-debug.apk`.
Το `app/build/outputs/apk/release/app-release-unsigned.apk` είναι unsigned.
Τα AndroidTest/probe APKs είναι μόνο fixtures για επανάληψη δοκιμών.

## Αποτελέσματα

| Έλεγχος | Αποτέλεσμα |
|---|---|
| JVM unit/integration | 112 επιτυχίες, 0 αποτυχίες/παραλείψεις |
| App lint και όλα τα APK builds στο CI | Επιτυχία |
| Debug signature και APK ZIP integrity | Επιτυχία |
| Android 10 / API 29 | 3 tests χωρίς VPN + 1 εκτελεσμένο πραγματικό TUN test |
| Android 15 / API 35 | 3 tests χωρίς VPN + 1 εκτελεσμένο πραγματικό TUN test |
| TCP/UDP TUN με ξεχωριστό UID | Σωστό payload, πραγματικό package attribution |
| Αλλαγή κανόνα σε ενεργό TCP flow | Η επόμενη μεταφορά αποκλείεται |
| Άγνωστο UDP flow | Αποκλεισμός και καταχώρηση στο Pending |
| IPv6 TCP/UDP | Πραγματικά JVM loopback integration tests |
| Αναμονή ACK | Regression test αποκλείει busy-wait / αδιάκοπα policy lookups |

Ελεγμένο commit: `d5aa925c97f4facffc73d75e5ba10809bcdaefd3`.
Το explicit VPN test δεν θεωρείται επιτυχημένο αν παραλειφθεί: το CI ελέγχει
τα JUnit XML και απαιτεί ακριβώς ένα executed/passing result χωρίς skip/error.
Η παράλειψη στην προηγούμενη έκδοση του API 35 test διορθώθηκε και δεν αποτελεί
στοιχείο επιτυχούς επαλήθευσης.

Το preflight ελέγχει πραγματικά protected TCP/UDP sockets και επιστρεφόμενα
IP packets πριν το `Builder.establish()`. Αποτυχία αποτρέπει δημιουργία TUN.
Η πραγματική TUN δοκιμή χρησιμοποιεί χωριστή εφαρμογή probe με άλλο UID·
κίνηση του ίδιου του VPN app δεν αρκεί ως απόδειξη interception.
Δεν ενεργοποιήθηκε VPN σε φυσική συσκευή του χρήστη.

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
Ο TCP endpoint είναι συντηρητικός stop-and-wait με response segments 536 bytes:
το throughput είναι περιορισμένο. Δεν υλοποιούνται fragments, IPv4 options,
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

Το τοπικό περιβάλλον αποσυνδέθηκε μετά την επιτυχή τοπική επαλήθευση. Τα τελικά
APKs και reports παραδόθηκαν από το CI ως τα παραπάνω GitHub artifacts.

## SHA-256 των CI APKs

```text
cd70004218ab177132b32a7de5160cb5e5556f682491c94a427e75bc10f8554e  app/build/outputs/apk/debug/app-debug.apk
f43471705173c438bbe8ccc9d5fefb6f1ea9580b95f270cf5f27b6c1bcbdb944  app/build/outputs/apk/release/app-release-unsigned.apk
```
