# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [3.0.0] - 2026-11-13

### Added
- **New WPF interface (now the default):** Light/Dark themes that switch instantly; themed menus, tabs, drop-downs, scroll bars and grids; windows sized to the screen and remembered; classic-style docking (bottom / left / right / undock) for the response and the sidebar. The previous WinForms window is still available with `-ClassicUi`.
- **Request editor:** syntax highlighting with line numbers for JSON/XML bodies and responses; `{{variables}}` highlighted in the URL, headers and body with the resolved value and its source on hover; Params tab synced with the URL; multipart grid where the Type decides the row (Text: value field, File: file picker with Browse, opened automatically when switching to File) plus drag-and-drop onto a key; an **Options** tab for *Save response to file*, the multipart file name / content-type options and the output format field; GraphQL; OAuth 2.0 (embedded browser sign-in) and client certificates.
- **Request tabs:** "+" button and a close button per tab, a request per tab with a running indicator, drag to reorder, *Open in new window*, warning before closing a busy tab.
- **Tests:** snippet library (status, 2xx, response time, JSON value equals/exists, header present/contains, body contains, save a value), `Assert-True` and `$responseTimeMs`.
- **Collections:** folder and collection settings (auth, headers, pre-request script, tests) inherited by requests whose auth is *Inherit*; export to Postman v2.1; import from Postman, Insomnia, HAR, OpenAPI (JSON/YAML) and API Tester files.
- **History:** stores status, headers and the body (up to 256 KB): *View saved response* and offline *Compare Responses*.
- **Collection runner:** parallel requests (1-10), retries for flaky requests (0-5), data files, HTML and CSV reports. Headless: `-OutputFormat Console|Json|JUnit|Html` and `-Retries N`.
- **Monitors:** background service (`-RunMonitors`) with a status tray icon, start at Windows sign-in or as a scheduled task (also while nobody is signed in), live browser dashboard (`http://127.0.0.1:8765/`, JSON at `/api/status`), retries before alerting, quiet hours, down/recovered alerts, Microsoft Teams / Slack / webhook alerts, p50/p95/p99 latency, email alerts sent in the background.
- **Secrets:** environment, collection and global variables can be marked secret - masked on screen, encrypted with DPAPI on disk and left out of every export.
- **Code snippets:** Go, Java and JavaScript (axios) in addition to cURL, PowerShell, Python, C# and JavaScript.
- **Updater:** daily background update check at start-up (can be switched off); downloads are verified against `API-Tester.ps1.sha256`.
- **User guide:** `docs/USER_GUIDE.md` covers installation, every feature, shortcuts and troubleshooting.
- **Release tooling:** `tools/Release.ps1` (changelog, version, release notes, build, tag, push, GitHub releases, verification) and GitHub Actions workflows `build.yml` and `release.yml`.

### Changed
- Headless runs use the same engine as the app (auth, all body types, pre-request scripts, PowerShell tests, collection and data-file variables).
- Every function uses an approved PowerShell verb (32 functions renamed) and naming is consistent across the code.
- `Build.ps1` stops with exit code 1 on syntax errors and writes `dist/API-Tester.ps1.sha256`.
- New windows start with one fresh request tab (Settings -> *Restore request tabs from the last session* restores the previous behaviour).
- `-NewUi` is accepted but no longer needed.

### Fixed
- Windows PowerShell 5.1: environments and global variables were never loaded or saved (`ConvertFrom-Json -AsHashtable` is PowerShell 7 only).
- Restricted headers (`Accept`, `User-Agent`, `Referer`, `Range`, ...) crashed requests.
- TLS 1.2 was not enabled on older .NET Framework versions.
- Headless `-RunCollection` did not find requests in folders; OpenAPI imports were invisible; YAML specs were rejected.
- Postman import dropped API-key auth, inherited collection/folder auth and the collection variables, and sent disabled headers.
- Collections nested deeper than about three folders were truncated when saved.
- The proxy password was not decrypted after a restart.
- `Write-Log -Level Error` threw and hid the real error behind "Cannot validate argument on parameter 'Level'".
- Logging was off on a fresh install; monitor email alerts used a non-existent parameter; monitors sent a bare GET; *Compare Responses* compared empty bodies; log-viewer search broke on quotes.
- Classic window: workspace import crashed (missing *Import History* checkbox).

### Security
- Workspace, collection and Postman exports never contain secrets.
- `dist/Configuration`, `History` and `Logs` (user data) are no longer part of the repository (`.gitignore`).

## [2.0.0] - 2026-07-09

### Added
- **Architectural Overhaul**: Split monolithic `API-Tester.ps1` into modular `src/` directory with `Build.ps1`.
- **OpenAPI Import**: Automatically parse and generate collections from OpenAPI/Swagger `.json` specs.
- **Data-Driven Testing**: Collection Runner now supports `CSV` and `JSON` files for iterative data testing.
- **CI/CD Headless CLI**: Bypass the GUI and run collections synchronously from the command line using the `-Headless` argument.
- **Response Body Diff Viewer**: Compare two historical request responses side-by-side to visually identify regression changes.
- **Performance Load Tester**: Dedicated UI to spin up asynchronous `RunspacePool` workers and bombard endpoints, plotting live RPS and Latency metrics.
- **Pre-Request Scripts**: Execute PowerShell script blocks *before* requests to generate dynamic signatures or payloads.
- **Multi-Language Snippet Generator**: Export your configured requests into copy-pasteable snippets for `cURL`, `PowerShell`, `Python`, `JavaScript`, and `C#`.
- **Dynamic Dark Mode**: Real-time theme toggle engine supporting Light and Dark modes.
- **Auto-Save & Crash Recovery**: Draft requests are periodically background-saved to `api_tester_drafts.json` and optionally recovered on launch.
- **Protobuf Import for gRPC**: Provide local `.proto` files to the gRPC client to query APIs that don't have reflection enabled.

### Changed
- Refactored all UI components (Forms, Panels, Controls) into individual module files.
- Moved `API-Tester-v1.ps1` to `v1-archive` branch.
- Replaced monolithic event handlers with state-managed routing.

### Fixed
- Fixed UI locking during long-running tasks.
- Resolved memory leaks in historical logging.

## [1.0.0] - Initial Release
- Basic API testing (GET, POST, PUT, DELETE).
- Collections, History, and Environment variables.
- Automated tests using PowerShell script blocks.
- Basic JSON and XML highlighting.
- Built strictly on `System.Windows.Forms` in a single file.

[Unreleased]: https://github.com/imumeshk/API-Tester/compare/v3.0.0...HEAD
[3.0.0]: https://github.com/imumeshk/API-Tester/releases/tag/v3.0.0
[2.0.0]: https://github.com/imumeshk/API-Tester/releases/tag/v2.0.0
