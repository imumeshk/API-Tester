# 🧪 PowerShell API Tester

> A native, GUI-based API testing & monitoring tool built entirely in PowerShell — no Electron, no Node.js, no dependencies.

[![Version](https://img.shields.io/badge/V2-2.0.0-blue?style=flat-square)](https://github.com/imumeshk/API-Tester/releases)
[![Version](https://img.shields.io/badge/V1-1.0.0-gray?style=flat-square)](https://github.com/imumeshk/API-Tester/releases)
[![Platform](https://img.shields.io/badge/platform-Windows-informational?style=flat-square&logo=windows)](https://github.com/imumeshk/API-Tester)
[![Language](https://img.shields.io/badge/PowerShell-5.1%2B-blue?style=flat-square&logo=powershell)](https://github.com/imumeshk/API-Tester)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)

**PowerShell API Tester** is a standalone, feature-rich HTTP client and API testing utility designed for engineers who want **Postman-level functionality without Electron, Node.js, or heavy dependencies**.

Built using **PowerShell + Windows Forms**, it runs natively on Windows and is ideal for enterprise, secure, or locked-down environments.

---

## 📦 Versions

| Version | File | Status | Highlights |
|---------|------|--------|-----------|
| **V2** `2.0.0` | `API-Tester-V2/API Tester.ps1` | ✅ Latest | Request Tabs, Templates, Tab State Persistence, About dialog, In-app Updater |
| **V1** `1.0.0` | `API Tester.ps1` | Stable | Full feature set — see below |

> **Recommended:** Use **V2** for all new work. V1 remains available for compatibility.

---

## 🚀 Quick Start

```powershell
# Clone the repository
git clone https://github.com/imumeshk/API-Tester.git
cd "API-Tester"

# Run V2 (recommended)
powershell -ExecutionPolicy Bypass -File "API-Tester-V2\API Tester.ps1"

# Run V1
powershell -ExecutionPolicy Bypass -File "API Tester.ps1"
```

> **Requirements:** Windows 7+, PowerShell 5.1+. No installation or internet access needed to run.

---

## ✨ Features

### 🖥️ User Interface
- Native Windows Forms GUI — no browser, no Electron
- Consistent colour palette with light theme
- DPI-aware rendering (`SetProcessDPIAware`)
- Resizable, dockable panels (Response, History) — dock Bottom / Left / Right / Undock
- Status bar showing request time and response size
- System tray integration for background monitoring

### 🌐 HTTP & Protocol Support

| Method | Body Types | Protocols |
|--------|-----------|-----------|
| GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS | JSON, XML, Form-Data (multipart), URL-encoded, GraphQL, Raw | HTTP/HTTPS, WebSocket, gRPC (via grpcurl) |

- Custom headers editor (key-value grid)
- Query parameter builder
- Cookie Jar management
- Proxy configuration (system / custom)

### 🔐 Authentication
- None / Bearer Token / API Key
- Basic Auth
- **OAuth 2.0** — Client Credentials, Authorization Code, Device Code
  - Auto token refresh
  - Browser-based redirect capture
- Client Certificates (mTLS / PKCS#12)

### 🌱 Environments & Variables
- Multiple named environments (Dev / QA / UAT / Prod)
- Global variables shared across all environments
- Collection-scoped variables
- `{{variable}}` substitution in URLs, headers, and request bodies
- JSON Path extraction from responses (`$.data.token`)

### 📂 Collections & History
- Hierarchical: Collection → Folder → Request
- Right-click context menu: New, Rename, Delete, Export, Run
- Automatic request history with search and filters
- Export history as JSON
- **Copy as cURL** / **Copy as PowerShell** from history

### ✅ Automated Testing
```powershell
# Built-in assertion functions
Assert-StatusIs 200
Assert-Equal $response.id 123
Assert-Contains $responseBody "success"

# JSONPath extraction from response
$token = Get-JsonPathValue $response "$.data.token"
```
- RTF colour-coded test results (PASS = green, FAIL = red)
- Per-collection test runner with CSV export

### 📊 Monitoring
- API Monitor Manager — scheduled HTTP health checks
- Configurable intervals (seconds to hours)
- Email alerting via SMTP (Basic + OAuth 2.0)
- Real-time monitoring dashboard with charts
- Monitor analytics with uptime / latency history
- Monitor log export (CSV)

### 🛠️ Tools Menu

| Tool | Description |
|------|------------|
| **Global Variables** | Edit shared key-value variables |
| **Proxy Configuration** | System or custom proxy settings |
| **Cookie Jar** | Manage persistent cookies |
| **JWT Utility** | Decode and inspect JWT tokens |
| **Generate Report** | HTML API test report |
| **WebSocket Client** | Real-time WebSocket testing |
| **gRPC Client** | gRPC testing via grpcurl binary |

---

## 🆕 V2 Exclusive Features

### 📑 Request Tabs
- Open multiple requests simultaneously in a tabbed interface
- Add, remove, rename, and duplicate tabs
- **Tab state is persisted** — reopen the app and your tabs restore exactly

### 📋 Request Templates
- Save frequently used request configurations as reusable templates
- Apply any template to a new tab instantly

### ℹ️ Help Menu

| Item | Description |
|------|------------|
| **About PowerShell API Tester...** | Version, author, GitHub link, update checker |
| **Keyboard Shortcuts...** | Quick reference dialog |

### ⬆️ In-App Updater

Access via **Help → About → Check for Updates**:

1. Queries the GitHub Releases API for the latest tag
2. Compares semantic versions — shows status instantly
3. If a newer version is available with a `.ps1` asset → **one-click download**
4. Backs up the current script as `.bak.ps1` before replacing
5. Falls back to opening the releases page in the browser if no asset is found

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `Ctrl + Enter` | Send Request |
| `Ctrl + F` | Find in Response |
| `Ctrl + Shift + Enter` | Run Console Command |
| `Alt + F4` | Close Application |

---

## 📁 File Structure

```
API-Tester/
├── API Tester.ps1                    ← V1 (1.0.0)
├── API-Tester-V2/
│   └── API Tester.ps1                ← V2 (2.0.0) — Recommended
├── CHANGELOG.md
└── README.md

# Auto-created at runtime (alongside the script):
Configuration/
├── api_tester_settings.json
├── api_tester_environments.json
├── api_tester_globals.json
├── api_tester_collections.json
├── api_tester_monitors.json
├── api_tester_request_tabs.json         ← V2 only
└── api_tester_request_templates.json    ← V2 only

History/
├── api_tester_history.json
└── api_tester_grpc_history.json

Logs/
└── api_tester.csv
```

---

## ⚙️ Settings

All settings are accessible via **Menu → Settings**:

| Category | Options |
|----------|---------|
| **UI & Panels** | Toggle History, Collections, Response panels |
| **Request** | Default timeout, follow redirects, SSL verification |
| **Logging** | Enable/disable logs, log level (Info / Debug), auto log rotation |
| **History** | Max entries, auto-save toggle |
| **Console** | Default language (PowerShell / Python / JS / PHP / Ruby / Go / Bash) |
| **Import** | cURL import toggle, Postman import toggle |

Settings are auto-saved to `Configuration/api_tester_settings.json`.

---

## 🔄 Releasing Updates (For Maintainers)

To enable the one-click in-app updater for users:

1. Create a **GitHub Release** with a semver tag (e.g. `v2.1.0`)
2. Attach the updated `.ps1` as a release asset with **exactly** these names:
   - V1 → **`API Tester.ps1`**
   - V2 → **`API Tester V2.ps1`**
3. Users can then: **Help → About → Check for Updates → Download & Update**

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Edit the appropriate version file
4. Test locally:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "API-Tester-V2\API Tester.ps1"
   ```
5. Syntax check before committing:
   ```powershell
   $e = $null
   [System.Management.Automation.Language.Parser]::ParseFile(".\API-Tester-V2\API Tester.ps1", [ref]$null, [ref]$e)
   $e | ForEach-Object { "Line $($_.Extent.StartLineNumber): $($_.Message)" }
   ```
6. Open a Pull Request

---

## 👤 Author

**Umesh Kashyap**
GitHub: [@imumeshk](https://github.com/imumeshk)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<p align="center">Built with ❤️ in PowerShell — no Electron harmed in the making of this tool.</p>