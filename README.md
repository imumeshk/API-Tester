# 🧪 PowerShell API Tester (V3)

> A native, GUI-based API testing & monitoring tool built entirely in PowerShell — no Electron, no Node.js, no dependencies.

[![Version](https://img.shields.io/github/v/release/imumeshk/API-Tester?style=flat-square)](https://github.com/imumeshk/API-Tester/releases/latest)
[![Build](https://github.com/imumeshk/API-Tester/actions/workflows/build.yml/badge.svg)](https://github.com/imumeshk/API-Tester/actions/workflows/build.yml)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

PowerShell API Tester is a fully-featured, ultra-lightweight alternative to Postman/Insomnia. It runs entirely inside standard Windows PowerShell (5.1 or 7) with a native WPF interface - the previous WinForms window is still available with `-ClassicUi`.

## ✨ What's new in 3.1.0 - 2026-11-23

### Added
Theme button, custom keyboard shortcuts, response toolbar, faster start-up. See for full changes, and fixes [CHANGELOG.md](https://github.com/imumeshk/API-Tester/blob/main/CHANGELOG.md)

### Fixed
- Switching the theme froze the window and only took effect after restarting the app.
- The first window took long to appear (C# compiled at every start, large history file).


## ✨ What's new in V3
New interface with instant Light/Dark themes, syntax highlighting and variable hover, a Params tab, test snippets, folder/collection inheritance, Postman/Insomnia/HAR import and Postman export, history with saved responses, parallel runs with retries and HTML reports, background monitors with a status tray icon, a live browser dashboard, Teams/Slack/webhook alerts, secret variables and a built-in updater. See [docs/releases/v3.0.0.md](docs/releases/v3.0.0.md) and [CHANGELOG.md](CHANGELOG.md).

**3.1:** one-click light/dark switch, customisable keyboard shortcuts, redesigned Settings, Environments and Monitor Manager windows, and a faster start - see [docs/releases/v3.1.0.md](docs/releases/v3.1.0.md).

📖 **New to API Tester? Read the [User Guide](docs/USER_GUIDE.md)** - installation, every feature, shortcuts and troubleshooting.

## 🚀 Features (V2 Update)
Version 2 is a massive architectural overhaul that brings enterprise-grade API testing capabilities natively to Windows.

### Core Testing
- **HTTP Methods:** GET, POST, PUT, DELETE, PATCH, OPTIONS, HEAD.
- **Body Types:** Form-data, URL-Encoded, Raw JSON/XML, GraphQL, Binary Files.
- **Variables & Environments:** Full support for `{{variable}}` substitution via Globals, Environments, and Collections.
- **Automated Tests:** Post-request PowerShell scripts to assert status codes, response times, and parse JSON payloads.
- **Pre-Request Scripts:** Dynamically construct HMAC signatures or modify payloads before a request fires.

### Advanced Tooling
- **OpenAPI (Swagger) Import:** Parse `.json` OpenAPI specs into runnable collections.
- **Data-Driven Runner:** Run collections using variables imported from CSV or JSON files.
- **CI/CD Headless CLI:** Execute collections silently from your pipeline via `.\API-Tester.ps1 -Headless -RunCollection "My APIs" -DataFile "data.csv"`.
- **Response Diff Viewer:** Compare two historical responses side-by-side with visual text diffing.
- **Load Tester:** Asynchronous RunspacePool engine for stress testing APIs with live RPS/Latency charting.
- **gRPC & WebSockets:** Native gRPC Client (via `grpcurl` with `.proto` import) and live WebSocket client.

### Quality of Life
- **Dark Mode:** Gorgeous, dynamic Light/Dark theme engine.
- **Multi-Language Snippets:** Copy requests directly as cURL, PowerShell, Python, C#, or JavaScript.
- **Auto-Save & Crash Recovery:** Request drafts are auto-saved to prevent data loss.

---

## 📦 Project Architecture
The codebase has been refactored into a modular structure for easier maintenance and contribution.

```text
API-Tester/
├── src/                          ← Source Code Modules
│   ├── UI/                       ← Windows Forms definitions (MainForm, Dialogs)
│   ├── Core/                     ← Core engine (HttpClient, Auth, OpenApiParser)
│   ├── Utils/                    ← Helpers and formatting functions
│   ├── Main.ps1                  ← Entry point
│   └── Parameters.ps1            ← CLI Argument binding
├── Build.ps1                     ← Build script to compile into a single file
├── dist/
│   └── API-Tester.ps1            ← The final executable output
├── v1-archive/                   ← Legacy V1 codebase
├── CHANGELOG.md
└── README.md
```

## 🛠️ How to Build & Run
API-Tester is distributed as a single `.ps1` file, but developed modularly.

1. Clone the repository: `git clone https://github.com/imumeshk/API-Tester.git`
2. Run the build script to compile the `src/` directory:
   ```powershell
   .\Build.ps1
   ```
3. Run the compiled application:
   ```powershell
   .\dist\API-Tester.ps1
   ```

---

### Launch options
Full instructions: [User Guide](docs/USER_GUIDE.md).

- `.\dist\API-Tester.ps1` - opens the WPF interface (default).
- `.\dist\API-Tester.ps1 -ClassicUi` - opens the previous WinForms interface.
- `.\dist\API-Tester.ps1 -RunMonitors` - runs the monitors in the background (tray icon only).
- `.\dist\API-Tester.ps1 -Headless -RunCollection "My APIs" [-Environment "Dev"] [-DataFile data.csv] [-OutputFormat Console|Json|JUnit|Html] [-Retries 2]` - CI mode; exit code 1 when any request fails.

### Updating
- In the app: **Help -> About API Tester -> Check for updates** (the app also checks once a day at start-up).
- Or download `API-Tester.ps1` from the [latest release](https://github.com/imumeshk/API-Tester/releases/latest) and replace your copy - keep the `Configuration`, `History` and `Logs` folders next to it.
- New versions are published automatically by GitHub Actions when a version tag (for example `v3.1.0`) is pushed.

## ⚙️ Configuration & Data
All your collections, environments, and settings are saved automatically next to the script at runtime:

```text
Configuration/
├── api_tester_settings.json
├── api_tester_environments.json
├── api_tester_collections.json
├── api_tester_drafts.json
...
```

---

## 🤝 Contributing
1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Modify the modules in the `src/` directory.
4. Run `.\Build.ps1` to test your changes.
5. Open a Pull Request.

---

## 👤 Author
**Umesh Kashyap**
GitHub: [@imumeshk](https://github.com/imumeshk)

## 📄 License
MIT License — see [LICENSE](LICENSE) for details.

<p align="center">Built with ❤️ in PowerShell — no Electron harmed in the making of this tool.</p>