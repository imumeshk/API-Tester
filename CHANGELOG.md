# Changelog

All notable changes to **PowerShell API Tester** are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [2.0.0] — 2026-07-08 — V2 Release

### Added
- **Request Tabs** — open, manage, and switch between multiple requests simultaneously
- **Request Templates** — save and reuse request configurations across sessions
- **Tab State Persistence** — request tabs are saved and restored between app launches (`api_tester_request_tabs.json`)
- **Help Menu** — new top-level `&Help` menu in the menu bar containing:
  - `About PowerShell API Tester...` — styled About dialog with version, author, GitHub link
  - `Keyboard Shortcuts...` — quick reference dialog for all hotkeys
- **In-App Updater** (`Invoke-UpdateCheck` / `Invoke-DownloadUpdate`):
  - Queries GitHub Releases API for latest version tag
  - Semantic version comparison (`[System.Version]`)
  - One-click download of updated `.ps1` asset
  - Automatic `.bak.ps1` backup before replacement
  - Graceful browser fallback when no asset is attached to a release
- **App Version Constant** — `$script:AppVersion = "2.0.0"` at top of script
- **GitHub metadata constants** — `$script:AppGitHubRepo`, `$script:AppGitHubAsset`
- **Version in title bar** — window title now shows `"PowerShell API Tester v2.0.0"`
- **Log Viewer** (`Show-LogViewer`) — browse and filter application logs from within the UI
- **Show-ReportCustomizationDialog** — configurable report generation options
- **Duplicate Request Tab** button in the tab toolbar
- **Ensure-RequestTabDefaults** — guards against missing fields in tab state on load

### Fixed
- **Duplicate `RunspacePool` initialisation** — the short-alias `[runspacefactory]::CreateRunspacePool(1,5)` was creating a pool that was immediately discarded; removed the dead assignment
- **Dead `$req.Timeout = 30000`** in monitor job block — hardcoded timeout was immediately overwritten by the configured `$timeout * 1000`; dead line removed

### Changed
- Refactored `Save-Globals` — removed a duplicate definition that existed alongside `Load-Globals`
- Request tab state is now loaded during startup (`Load-RequestTabs`) and saved on every tab change (`Save-RequestTabs`)
- `New-APIForm` initialisation sequence extended to call `Load-RequestTemplates` and `Load-RequestTabs`

---

## [1.0.0] — 2026-07-08 — Initial Public Release

### Added
- **Help Menu** — `&Help` top-level menu with About and Keyboard Shortcuts (backported from V2)
- **In-App Updater** — GitHub Releases API check and one-click download (backported from V2)
- **App Version Constant** — `$script:AppVersion = "1.0.0"`, GitHub repo + asset metadata
- **Version in title bar** — window title shows `"PowerShell API Tester v1.0.0"`

### Core Features (V1 launch)
- Native Windows Forms GUI (no Electron, no Node.js)
- HTTP methods: GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS
- Request body types: JSON, XML, Multipart / Form-Data, URL-encoded, GraphQL, Raw
- Authentication: None, Bearer Token, API Key, Basic, OAuth 2.0 (Client Credentials, Auth Code), mTLS
- Environment manager with Dev / QA / UAT / Prod switching
- `{{variable}}` substitution in URLs, headers, and bodies
- Global and environment-scoped variables
- Collection manager — hierarchical collections → folders → requests
- Automatic request history with search, filter, and export
- Copy as cURL / Copy as PowerShell from history
- Built-in test assertions (`Assert-StatusIs`, `Assert-Equal`, `Assert-Contains`)
- JSONPath value extraction from responses
- RTF colour-coded test result rendering
- Collection Runner — sequential execution with CSV export
- API Monitor Manager — scheduled health checks with email alerting (SMTP Basic + OAuth 2.0)
- Real-time Monitoring Dashboard with uptime/latency charts
- Monitor analytics window
- WebSocket Client
- gRPC Client (via grpcurl binary)
- JWT Utility — decode and inspect JWT tokens
- HTML Report Generator
- Cookie Jar management
- Proxy configuration (system / custom)
- Global Variables editor
- Settings window (UI, Request, Logging, History, Console, Import)
- Log rotation (5 MB cap, keep last 5 backups)
- DPI awareness (`SetProcessDPIAware`)
- System tray icon for monitoring status
- Workspace import / export (`.apw` format)
- Postman collection import
- cURL command import
- Dockable response panel (Bottom / Left / Right / Undock)
- Reset Layout option

### Fixed
- GET method request handling
- Collection runner form closing behaviour
- Output format consistency

---

## [Unreleased]

> Planned / In progress

- Dark mode theme toggle
- Response body diff viewer (compare two requests)
- Import from OpenAPI / Swagger spec
- Plugin / extension system

---

[2.0.0]: https://github.com/imumeshk/API-Tester/compare/v1.0.0...v2.0.0
[1.0.0]: https://github.com/imumeshk/API-Tester/releases/tag/v1.0.0
[Unreleased]: https://github.com/imumeshk/API-Tester/compare/v2.0.0...HEAD