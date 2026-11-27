# Validation procedures and boundaries

All runtime acceptance in this implementation uses synthetic fixtures. Native API collectors are compiled and their transformations/status/error handling are exercised separately; actual Windows metadata collection on the user's machine has not been run. Personal browser databases, password stores and live system-audit output are not validation inputs. No traffic-test or OS-sandbox claim is made.

| Layer | Procedure | Evidence scope |
| --- | --- | --- |
| Native build and unit/component fixtures | `python "1. build.py" --candidate --tests --no-pause` | Release x64 compilation and CTest; separate candidate protects the running normal copy; source/output receipt |
| Collector transformations | `XASpyPrivacyTests` under CTest | Synthetic argument stripping, registry/path normalization, access/error/partial/cancel states, numeric endpoint/PID projection, bounds and WMI scalar conversion; no live enumeration |
| Parser/privacy | `XASpyPrivacyTests` under CTest | Filtered fields, malicious run ID rejection, malformed/duplicate/deep JSON and invalid scope checks |
| Browser reader | `XASpyBrowserTests` under CTest | Real synthetic SQLite/Bookmarks files; source grades, URL-secret removal, schema/view/corrupt/sidecar/locked cases, cancellation and row bounds |
| End-to-end engine/control | `python -B tools/test_native.py --exe out/candidate/Release/XASpy.exe --fixture ".\work\fixture-native"` | All modules via synthetic records, actual file hashing/structured bookmarks, per-check failures, local status/summary/cancel, privacy sentinels, fixture isolation and cancellation persistence |
| Native UI | `powershell -NoProfile -File tools/test_ui.ps1 -Executable out/candidate/Release/XASpy.exe -FixtureRoot ".\work\fixture-native" -Screenshot work/ui-fixture.png` | Exact owned fixture window only: idle/default scope, opt-in browser, Start, per-check rows, private viewer, targeted mode, Cancel, graceful close, nonblank rendered screenshot; user app untouched |
| Build recovery | `python -B -m build_support.test_native_workflow` | Synthetic content-addressed recovery reuse/change/deletion/restore, exclusions, corruption refusal, drift and receipt invalidation under process/network/outside-fixture write barrier |

The end-to-end fixture tool retains its fixture root for UI testing and diagnosis. It writes only synthetic data; its candidate's reports remain under that executable's findings folder. The UI test creates/removes only its own cancellation fixture and owns/closes only the new validation process. The build helper never launches the application or performs a live audit. Native source edits require a new build; native test success from an earlier executable cannot validate later source changes.

The original running application is not replaced by candidate validation. After accepting a candidate, the user may close their own normal copy and rebuild normally, or open the candidate explicitly. Real service/provider permissions, device/driver data, profile schemas and operating-system variations remain unverified until a separately authorized audit; the application must report gaps instead of calling those checks clean.
