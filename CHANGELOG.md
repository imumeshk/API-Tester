# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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