# 🧪 PowerShell API Tester

> A native, GUI-based API testing & monitoring tool built entirely in PowerShell

**PowerShell API Tester** is a standalone, feature-rich HTTP client and API testing utility designed for engineers who want **Postman-level functionality without Electron, Node.js, or heavy dependencies**.

Built using **PowerShell + Windows Forms**, it runs natively on Windows and is ideal for enterprise, secure, or locked-down environments.

---

## 🚀 Overview

- 🪟 Native Windows application (no Electron)
- ⚡ Lightweight & fast
- 🧠 Fully scriptable using PowerShell
- 🔐 Enterprise-ready authentication & security
- 🧩 Extensible and transparent by design

---

## ✨ Key Features

### 🖥️ User Interface
- Native Windows Forms GUI
- Tab-based layout for Requests, Responses, Tests, and Tools
- No external runtimes required

### 🌐 HTTP & API Support
- HTTP Methods: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`
- Request body types:
  - JSON
  - XML
  - Multipart / Form-Data
  - GraphQL
- Headers, query parameters, and cookies support

### 🔐 Authentication
- Basic Authentication
- Bearer Token
- API Key
- OAuth 2.0
  - Client Credentials
  - Authorization Code
  - Auto token refresh
- Client Certificates (mTLS)

### 🌱 Environments & Variables
- Environment-based configurations (Dev / QA / UAT / Prod)
- Global and scoped variables
- Variable substitution in URLs, headers, and bodies

### 📂 Collections & History
- Organize requests into collections and folders
- Automatic execution history tracking
- Request/response persistence

### ✅ Automated Testing
- PowerShell-based assertions:
  ```powershell
  Assert-StatusIs 200
  Assert-Equal $response.id 123
