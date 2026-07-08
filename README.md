# 🧪 PowerShell API Tester

> A native, GUI-based API testing & monitoring tool built entirely in PowerShell — no Electron, no Node.js, no dependencies.

[![Version](https://img.shields.io/badge/V2-2.0.0-blue?style=flat-square)](https://github.com/imumeshk/API-Tester/
├── src/
│   └── API-Tester.ps1                ← V2 (2.0.0) — Recommended
├── assets/                           ← Images and icons
├── docs/                             ← Documentation
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
   - V1 → **`API-Tester-v1.ps1`**
   - V2 → **`API-Tester.ps1`**
3. Users can then: **Help → About → Check for Updates → Download & Update**

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Edit the appropriate version file
4. Test locally:
   ```powershell
   powershell -ExecutionPolicy Bypass -File "API-Tester-V2\API-Tester-v1.ps1"
   ```
5. Syntax check before committing:
   ```powershell
   $e = $null
   [System.Management.Automation.Language.Parser]::ParseFile(".\API-Tester-V2\API-Tester-v1.ps1", [ref]$null, [ref]$e)
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