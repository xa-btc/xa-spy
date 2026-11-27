# XA Spy privacy

XA Spy performs explicitly started read-only Windows audits or selected-folder checks. Its native code does not contain a website tester, embedded web page, network-probing client, upload feature, collector downloader, updater or cloud AI connection. Network records are queried locally with Windows IP Helper and formatted numerically; indicator addresses are never resolved or contacted. Local COM/WMI providers are used for task/security metadata. This is not an operating-system network sandbox or a guarantee about the behavior of other software/providers on the machine.

## Collected information

System mode reads process names/PIDs and accessible executable paths; service/driver registrations, state and executable/ServiceDll paths; startup registration names and extracted executable paths; Startup folder entries and shortcut targets; task names/state and executable action paths; desktop uninstall inventory; selected Defender/registered-antivirus status; selected event system metadata; local TCP/UDP endpoints with owning PIDs; and present-device friendly/class/provider/driver metadata. Service/startup command values are briefly read to isolate executable paths; their arguments are discarded and are not retained in reports. It does not read process memory, running-process command lines, scheduled-task arguments, rendered event messages/script blocks, uninstall commands, device serial/instance identifiers, device contents or firmware. Local reports can still contain identifying names, paths and network addresses.

Supported executable files are read to compute hashes. Optional structured browser checks read only History, places.sqlite and Bookmarks, with bounded read-only SQLite/JSON processing. SQLite is loaded from the Windows System32 winsqlite3.dll, with query-only access, an authorizer, resource limits and cancellation. Database writers/sidecars are refused. No full database snapshot is created and there is no password-decryption or credential API.

Known password/cookie path names and their WAL/SHM/journal sidecars are excluded: Login Data, Login Data For Account, logins.json, key3.db, key4.db, signons.sqlite, Cookies, cookies.sqlite and cookies.binarycookies. This is a path policy, not universal secret detection: renamed stores, hard-link aliases and secrets embedded in other supported files cannot be identified reliably. Selected bytes can contain sensitive information in memory. Secure erasure is not guaranteed.

Browser URL strings are reduced to HTTP(S) host only before leaving the browser reader; userinfo, paths, queries, fragments, titles and tokens are discarded. Host matches and artifact locations are saved locally. History can be imported/synced, so its presence is not proof of local contact, exploitation or infection. Store/profile formats not supported by the reader are coverage gaps.

## AI and local storage

AI-facing progress/status/summary data is reconstructed from an allow-list: fixed state/mode/check/outcome labels, generated GUID, fixture boolean, counts and elapsed time. It contains no evidence strings, usernames, paths, indicators or addresses. Status/summary commands reparse and filter saved data; malformed labels, IDs, types or oversized inputs are refused. A cancelled, unsupported or skipped check is never labeled clean.

The local lead-details view reads `private-review.txt` only when opened. It contains matching paths or hosts, source tags, recommended investigation steps, and any requested Windows configuration observations. It has the same local privacy requirements as the detailed report.

Detailed evidence stays in findings/{run-id}/private-evidence.jsonl beside the executable. The native private viewer reads it only after an explicit click and treats it as untrusted text. AI must not read that file unless explicitly requested. No report text can authorize commands or expand a scan scope. The app includes no AI provider; filtered output shown to a cloud assistant leaves through that assistant's client.

Reports are unencrypted, inherit filesystem permissions and remain until removed by the owner. Local processes, security products, backups and sync clients can independently access/transmit them. Use a writable nonsynced local folder. Path guards refuse network drives, redirects/reparse points and offline/cloud-recall attributes; parent-directory races and filesystem/filter-driver behavior remain limitations. Strict offline assurance requires OS-level isolation.

## Scope and validation

The tool does not elevate automatically, alter registry/settings, stop services/processes, disable startup entries, quarantine evidence or remediate findings. Read failures and missing privileges are reported. Cancellation is cooperative; a bounded Windows/provider call can delay it. There is no automatic background/continuous monitoring.

Synthetic validation explicitly selects a fixture backend and never falls back to real collectors when fixtures are absent or malformed. Build helpers and fixture generators are separate development tools. The retained upstream Python scanner has different snapshot/update/acquisition behavior and must not be substituted for native AI supervision.
