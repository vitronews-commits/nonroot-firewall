# Build and verification

Toolchain: JDK 17, Gradle 8.9 (checked-in wrapper with distribution SHA-256),
Android platform 35 / build-tools 35.0.0, AGP 8.7.3, Kotlin 2.0.21.
Install those SDK packages and set ANDROID_HOME. Dependency downloads require network access.

```sh
./gradlew :app:testDebugUnitTest :app:lintDebug :app:assembleDebug :app:assembleRelease :app:assembleAndroidTest :probe:assembleDebug
python3 tools/verify_unit_results.py app/build/test-results/testDebugUnitTest
```

The validator requires every original 125 test ID, zero failures/errors/skips and
actual test execution. See the CI report for the total for each source commit.
Outputs: `app/build/outputs/apk/debug/app-debug.apk` and
`app/build/outputs/apk/release/app-release-unsigned.apk`.
The latter cannot be installed until signed externally. No release private key is
created, committed or published. CI validates ZIP integrity and the debug signature.
Build inputs are pinned; byte-for-byte reproducibility across ephemeral debug
signers is not claimed.

The default `connectedDebugAndroidTest` suite does not enable VPN. Real TUN tests
require `vpnAcceptance=true`, an emulator, the separate probe APK and host echo/DNS
fixtures. Follow `.github/workflows/android.yml` exactly: run the protected
forwarding preflight/no-VPN suite first. Never run device-policy test scripts on a
physical device or an emulator containing personal data. The process-death test
uses removable test-only administration and root only to inject an emulator crash.

GitHub Actions artifacts contain the source run, tests, signed debug APK and
unsigned release. `NonRootFirewall-0.3.0-dev` is a ZIP containing one debug APK;
extract it before installation. Download may require GitHub sign-in. CI debug
signing certificates may differ between runs. Do not uninstall an existing app to
resolve a signature mismatch without exporting/backing up its rules and data.

Do not infer acceptance from a successful build alone: inspect API 29, API 35,
lockdown and 60-minute results separately. A skipped test is NOT TESTED.
