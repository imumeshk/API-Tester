# API Tester - User Guide

Version 3.0 · Windows · Windows PowerShell 5.1 or PowerShell 7

API Tester is a desktop tool for building, sending, testing and monitoring HTTP APIs. It is a single PowerShell
script - nothing to install, no account, and your data stays on your computer.

---

## Contents

1. [Getting started](#1-getting-started)
2. [The main window](#2-the-main-window)
3. [Building and sending a request](#3-building-and-sending-a-request)
4. [Variables, environments and secrets](#4-variables-environments-and-secrets)
5. [Pre-request scripts and tests](#5-pre-request-scripts-and-tests)
6. [Working with the response](#6-working-with-the-response)
7. [Collections](#7-collections)
8. [History](#8-history)
9. [Running collections](#9-running-collections)
10. [Monitors](#10-monitors)
11. [Tools](#11-tools)
12. [Settings](#12-settings)
13. [Keyboard and mouse shortcuts](#13-keyboard-and-mouse-shortcuts)
14. [Backup, moving to another PC and updating](#14-backup-moving-to-another-pc-and-updating)
15. [Troubleshooting](#15-troubleshooting)

---

## 1. Getting started

### Requirements
- Windows 10 or 11 (or Windows Server 2016 or later).
- Windows PowerShell 5.1 (built into Windows) or PowerShell 7.
- Optional: `grpcurl` for the gRPC client (it can be downloaded from inside the app), the `powershell-yaml` module
  for importing OpenAPI files in YAML.

### Install
1. Download **`API-Tester.ps1`** from the [latest release](https://github.com/imumeshk/API-Tester/releases/latest).
2. Put it in a folder of its own, for example `C:\Tools\API-Tester\`. The app stores its data next to the script.
3. Files downloaded from the internet are blocked by Windows. Unblock it once:

   ```powershell
   Unblock-File C:\Tools\API-Tester\API-Tester.ps1
   ```

### Start
Right-click the file and choose **Run with PowerShell**, or from a PowerShell window:

```powershell
cd C:\Tools\API-Tester
.\API-Tester.ps1
```

If PowerShell refuses to run scripts on your computer, start it like this instead:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\API-Tester.ps1
```

### Start options

| Command | What it does |
|---|---|
| `.\API-Tester.ps1` | Opens the app. |
| `.\API-Tester.ps1 -ClassicUi` | Opens the previous (version 2) window. |
| `.\API-Tester.ps1 -RunMonitors` | Runs your monitors in the background with only a tray icon - see [Monitors](#10-monitors). |
| `.\API-Tester.ps1 -Headless -RunCollection "My APIs"` | Runs a collection without a window, for scripts and CI - see [Command line](#command-line-ci). |

### Where your data is stored
Next to the script, in three folders:

| Folder | Contents |
|---|---|
| `Configuration\` | Settings, collections, environments, global variables, request tabs, templates, monitors. |
| `History\` | Request history, monitor log, gRPC history. |
| `Logs\` | The application log. |

Passwords, tokens and secret variables in these files are encrypted for your Windows account.

---

## 2. The main window

```
+--------------------------------------------------------------------------------------+
|  API Tester       [status messages]            Environment [ Dev       v] Manage  Settings |
|  Menu   Tools   Monitor   Help                                                          |
|  [ Request 1  x ] [ Orders  x ] [ + ]                                                   |
|  [GET v] [ https://api.example.com/orders?page=1          ]  Send  Cancel  Save  Templates |
| +------------------+ +---------------------------------+ +-----------------------------+ |
| | Collections |History| Params Headers Body Auth ...    | | RESPONSE  200 OK  120 ms     | |
| |  > My APIs        | |                                 | | Response | Headers | JSON ... | |
| |    > Orders       | |   (request editor)              | |   (response viewer)          | |
| +------------------+ +---------------------------------+ +-----------------------------+ |
+--------------------------------------------------------------------------------------+
```

| Area | What it is for |
|---|---|
| **Header** | Status messages and errors, the active **Environment**, **Manage...** (environments) and **Settings**. |
| **Menu bar** | **Menu** (import, export, layout, settings), **Tools**, **Monitor** and **Help**. |
| **Request tabs** | Several requests open at once. **+** opens a new tab; the **x** on a tab closes it. |
| **Request bar** | Method, URL, **Send**, **Cancel**, **Save** and **Templates...** (and **Repeat...** when enabled in Settings). |
| **Sidebar** | **Collections** and **History**. |
| **Request editor** | Tabs **Params**, **Headers**, **Body**, **Auth**, **Pre-request**, **Tests** and **Options**. |
| **Response panel** | The response and tools to inspect it. |

### Layout
- **Dock the response** to the bottom, left or right of the editor, or **undock** it into its own window: right-click
  the response toolbar (the row with **Prettify**, **Save...**, **Copy**) and choose **Docking Options**.
- **Undock the sidebar**: right-click the **Collections** / **History** tab headers and choose **Undock Panel**
  (choose **Dock Panel** or close the window to put it back).
- Drag the splitters between the panels to resize them.
- **Menu -> Reset Layout** puts everything back to the default for your screen.
- The window remembers its size and position. Tabs and panels you don't use can be hidden in
  [Settings](#12-settings).

### Light and dark theme
**Settings -> App theme**. The change applies immediately to every open window.

---

## 3. Building and sending a request

### Method and URL
Pick the method (**GET**, **POST**, **PUT**, **PATCH**, **DELETE**, **HEAD**, **OPTIONS**; more with *Allow all request
methods* in Settings) and type the URL. URLs can contain [variables](#4-variables-environments-and-secrets) such as
`{{baseUrl}}/orders`.

Press **Send** or **Ctrl+Enter**. While the request runs, its tab shows an orange dot and **Cancel** stops it. Each
tab runs its own request, so you can switch tabs and send others in the meantime.

### Params
The query string as a table: **+ Add parameter**, edit **Key** and **Value**, **Remove selected**. The URL and the
table always match - editing one updates the other. The tab header shows how many parameters there are.

### Headers
One header per line: `Name: value`, for example:

```
Accept: application/json
X-Request-Id: {{$guid}}
```

### Body
Choose the body type in the drop-down:

| Body type | Use it for |
|---|---|
| `application/json` | JSON. **Beautify** formats it. Syntax highlighting and line numbers are shown. |
| `application/xml` | XML. **Beautify** formats it. |
| `text/plain` | Any text. |
| `application/x-www-form-urlencoded` | HTML-form style `name=value` pairs, one per line. |
| `multipart/form-data` | Form fields and file uploads (see below). |
| `GraphQL` | A GraphQL query plus its variables (JSON). |

**Multipart form data (file uploads)** - every row is a form field:

- **+ Text field** adds a text field: type the **Key** and the **Value**.
- **+ Attach file(s)...** adds file rows (or fills the selected row first).
- Set a row's **Type** to **File** to turn it into an upload: the file picker opens straight away; **Browse...**
  changes the file later. **File name** and **Content type** are filled in automatically and can be changed.
- You can drop files from Explorer onto a row (that key gets the file) or onto the grid (new rows).
- **Remove selected** / **Clear all** delete rows.

Whether the file name and content type are sent with each file is set on the **Options** tab.

### Auth

| Type | Fields |
|---|---|
| **Inherit** | Uses the auth of the folder or collection the request is saved in ([see Collections](#settings-inherited-by-requests)). |
| **No Auth** | Nothing is added. |
| **API Key** | Key name, value, and whether it goes into a **header** or the **query string**. |
| **Bearer Token** | Token, sent as `Authorization: Bearer <token>`. |
| **Basic Auth** | User name and password. |
| **Auth2** (OAuth 2.0) | Token endpoint, client ID / secret, scope. **Get token (client credentials)**, **Get token (authorization code)...** (signs in through a browser window and catches the code automatically) and **Refresh token**. Expired tokens are refreshed when you send. |
| **Client Certificate** | A `.pfx` file and its password, or a certificate from your Windows certificate store. |

### Options tab
- **Save response to file** - binary and attachment responses (for example a generated document) are written to
  this path after each send. **Browse...** chooses it, **Clear** removes it.
- **Multipart / form-data** - send the file name and content type with each file, and an optional **output format
  field** (an extra form field such as `outputFormat=TrackChanges`). These are greyed out for other body types.

The tab title shows a dot (`Options •`) while something is set there.

### Request tabs

| To... | Do this |
|---|---|
| Open a new tab | **+** or **Ctrl+T** |
| Close a tab | its **x**, a middle-click, or **Ctrl+W** (you are asked first if a request is still running) |
| Rename | double-click the tab |
| Reorder | drag the tab |
| Duplicate, rename, close others, open in its own window | right-click the tab |

**Open in new window** opens the request in a second API Tester window - handy for comparing two requests side by
side. By default a new session starts with one empty tab; to reopen last session's tabs, switch on
*Restore request tabs from the last session* in Settings.

### Saving a request
- **Save** stores the request in a collection. For a request that came from a collection, **Save** updates it;
  otherwise you choose the collection or folder and give it a name.
- **Templates...** saves the current request as a reusable template, or starts a new request from one.

### Importing a cURL command
**Menu -> Import cURL...**, paste a command copied from a browser's developer tools or from API documentation, and
it becomes a request with method, URL, headers, body and auth.

### Repeating a request
Switch on *Enable repeat request* in Settings; **Repeat...** then sends the request several times in a row and
reports how many succeeded.

---

## 4. Variables, environments and secrets

### Using variables
Write `{{name}}` anywhere: URL, headers, body, auth fields, monitor requests. Before sending, API Tester replaces it
with the value.

- Known variables are highlighted in the editor; unknown ones are shown in **red**.
- **Hover** over a variable to see its value and where it comes from (secret values are masked).

### Where values come from
When the same name exists in several places, the first match wins:

1. **Data file** - the current row of a collection run with a CSV/JSON data file.
2. **Environment** - the environment selected in the header.
3. **Collection** - the collection the request belongs to.
4. **Global** - available everywhere.

Built-in dynamic variables:

| Variable | Value |
|---|---|
| `{{$guid}}` | A new GUID for every request |
| `{{$timestamp}}` | Current Unix time in seconds |
| `{{$randomInt}}` | A random number from 1 to 9999 |

### Environments
Use environments for the same API on different stages (Dev, Test, Prod).

- **Manage...** in the header (or **Tools -> Manage Environments...**) adds, edits and removes them.
- Each environment has **variables**, and can also have a **base URL**, **headers** and an **auth** setting. When you
  select the environment, these are applied to the current request.
- **Save current...** creates an environment from the current request.

### Global and collection variables
- **Tools -> Global Variables...** - values used by every request.
- Right-click a collection -> **Edit Variables...** - values for the requests in that collection.

### Secret variables
Tick **Secret** next to a variable (in the environment, global or collection variables editor):

- the value is masked on screen (tick **Show secret values** to see it),
- it is stored encrypted for your Windows account,
- it is never included in workspace, collection or Postman exports.

### Taking a value from a response
**Extract variable** in the response toolbar: choose **JSON Path** (for example `data.token`) or **Regex** (the first
capture group is used, or the whole match when there is none), the scope (**Global**, **Collection** or **Environment**) and the variable name, then **Extract**.

---

## 5. Pre-request scripts and tests

Both are PowerShell. They run inside API Tester - there is nothing to install.

### Pre-request script
Runs just before the request is sent. It can read and change `$ApiRequest` (`Method`, `Url`, `Headers`, `Body`) and
read the active environment in `$Environment`.

```powershell
# Add a signature header
$stamp = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$ApiRequest.Headers += "`r`nX-Timestamp: $stamp"
```

### Tests
Run after the response arrives. Available variables:

| Variable | Contains |
|---|---|
| `$statusCode` | HTTP status code, for example `200` |
| `$headers` | Response headers (`$headers['Content-Type']`) |
| `$body` | Response body as text |
| `$jsonBody` | The body parsed as JSON (when it is JSON) |
| `$responseTimeMs` | How long the request took |

Assertions:

| Function | Example |
|---|---|
| `Assert-StatusIs` | `Assert-StatusIs $statusCode 200` |
| `Assert-Equal` | `Assert-Equal (Get-JsonPathValue -JsonObject $jsonBody -Path 'data.id') 42 'id is 42'` |
| `Assert-Contains` | `Assert-Contains $body 'success'` |
| `Assert-True` | `Assert-True ($responseTimeMs -lt 500) 'Fast enough'` |

`Get-JsonPathValue -JsonObject $jsonBody -Path 'items[0].name'` reads a value from the JSON body.

**Insert snippet ▾** on the Tests tab adds ready-made checks: status is 200 / 2xx, response time, JSON value equals
or exists, JSON array not empty, header present / contains, body contains, and saving a value as a global variable.

Results appear in the **Test Results** tab (PASS / FAIL with the message).

Scripts and tests can also be set on a folder or collection so they run for every request inside it - see
[Collections](#settings-inherited-by-requests).

---

## 6. Working with the response

The response header shows the **status** (green 2xx, amber 3xx, red 4xx/5xx), the **time** and the **size**.

### Response tabs

| Tab | What it shows |
|---|---|
| **Response** | The body, formatted and syntax-highlighted for JSON/XML, with line numbers. |
| **Response Headers** | All response headers. |
| **JSON Tree** | The JSON as an expandable tree: search (**Find next**), **Expand all** / **Collapse all**, **Copy path** of the selected node. |
| **Code Snippets** | The request as code: cURL, PowerShell, Python, C#, JavaScript, JavaScript (axios), Go, Java. **Copy** puts it on the clipboard. |
| **Console** | Run a quick command - see below. |
| **Preview** | Rendered HTML or an image, when the response is one. |
| **Test Results** | The results of the Tests script. |

### Response toolbar
- **Prettify** - format the body again.
- **Save...** - save the body (or a binary file) to disk.
- **Copy** - copy the body.
- **Go to line...** - jump to a line number.
- **Find** (**Ctrl+F**) - search the body; **Enter** / **Shift+Enter** for next / previous, **Esc** to close.
- **Extract variable** - see [above](#taking-a-value-from-a-response).
- **Wrap** - wrap long lines.

### Console
Type a command and press **Ctrl+Enter** (or **Ctrl+Shift+Enter** from anywhere). Choose the language with a prefix:
`ps:` (PowerShell), `python:`, `js:`, `php:`, `ruby:`, `go:`, `bat:`, `bash:`. Without a prefix the *default console
language* from Settings is used. The matching interpreter must be installed.

### Downloading files
Responses that are files are shown as `[Binary content ...]`. Save them with **Save...**, or automatically:

- per request: **Options -> Save response to file**;
- for every download: **Settings -> Auto-save downloaded files to a folder** (optionally *Name saved files after the
  uploaded file(s)*, with a prefix). The file name comes from the server's `Content-Disposition` header.

---

## 7. Collections

Collections group requests in folders - like a project.

### Creating and organising
- **New** (in the Collections panel) or right-click -> **New Collection** / **New Folder**.
- **Save** in the request bar, or right-click a collection/folder -> **Save Current Request**.
- Double-click a request (or right-click -> **Open**) to open it; **Open in new tab** keeps the current tab.
- Right-click -> **Rename** / **Delete**.
- The filter box above the tree finds requests by name.

### Settings inherited by requests
Right-click a collection or folder -> **Settings (auth, headers, scripts)...**:

- **Auth** - used by every request inside whose Auth type is **Inherit**. The nearest folder wins.
- **Headers** - added to every request inside; a request's own header with the same name wins.
- **Pre-request** and **Tests** - run for every request inside, in the order collection -> folder -> request.

This also applies to collection runs and command-line runs.

### Import

**Menu -> Import Postman / Insomnia / HAR / OpenAPI...** or **Import...** in the Collections panel. The format is
detected automatically:

| Format | Notes |
|---|---|
| Postman collection (v2.0 / v2.1) | Folders, requests, auth (also inherited), variables, bodies. |
| Insomnia export | Workspaces become collections; `{{ _.name }}` becomes `{{name}}`; environment data becomes collection variables. |
| HAR (browser "Save all as HAR") | One request per entry. |
| OpenAPI / Swagger (JSON, YAML) | One request per operation. YAML needs the `powershell-yaml` module (`Install-Module powershell-yaml -Scope CurrentUser`). |
| API Tester export | Collections exported from API Tester. |

You can also right-click a collection -> **Import OpenAPI Spec...** to add an API to an existing collection.

### Export
- Right-click -> **Export...** - API Tester format.
- Right-click -> **Export as Postman collection...** - Postman v2.1. PowerShell scripts are not included (Postman
  runs JavaScript).
- **Export...** in the Collections panel - all collections.

Secret variables are never exported.

---

## 8. History

Every request you send is listed in **History** with its time, status and URL.

- **Search** and the **environment filter** narrow the list.
- Double-click (or **Open**) loads a request; with *Auto-run on history double-click* in Settings it is sent at once.
- **View saved response** - the response is stored with the entry (status, headers and the body up to 256 KB), so you
  can look at it offline.
- **Compare Responses** - select two entries; their saved responses are compared side by side (or both are sent
  again when no response was saved).
- **Copy as cURL / PowerShell / Python / C#**, **Delete**, and **Export...** / **Clear** at the bottom.

History keeps the last 50 requests. Switch saving responses off with *Save responses in history* in Settings.

---

## 9. Running collections

Right-click a collection or folder -> **Run...**

| Option | Meaning |
|---|---|
| Request list | Untick requests to skip them. **Select all** / **Clear**. |
| **Data file...** | A CSV or JSON file; the collection runs once per row, and each column is a variable (`{{column}}`). |
| **Delay (ms)** | Pause between starting requests. |
| **Parallel** | How many requests run at the same time (1-10). |
| **Retries** | How often a failing request is tried again before it counts as failed (0-5). |
| **Stop on failure** | Stop starting new requests after the first failure. |

**Start run** runs it; **Stop run** stops. Each request ends as **PASS**, **FAIL** (HTTP 4xx/5xx or a failed test) or
**ERROR** (no response). Afterwards: **Retry failed**, **Export CSV...** or **HTML report...** (a report with a
summary and p50/p95/p99 response times).

**Load Test...** on the same menu sends many requests in parallel to measure performance - see
[Load tester](#load-tester).

### Command line (CI)
Run a collection without opening a window - for example in a build pipeline:

```powershell
.\API-Tester.ps1 -Headless -RunCollection "My APIs" -Environment "Test" -DataFile .\users.csv -OutputFormat JUnit -Retries 2 > results.xml
```

| Parameter | Meaning |
|---|---|
| `-RunCollection` | Name of the collection. |
| `-Environment` | Environment to use (optional). |
| `-DataFile` | CSV or JSON data file (optional). |
| `-OutputFormat` | `Console` (default), `Json`, `JUnit` (for CI test reports) or `Html`. |
| `-Retries` | Retries for failing requests. |

The exit code is **0** when everything passed and **1** when any request failed - so a pipeline step fails
automatically.

---

## 10. Monitors

A monitor sends a request on a schedule, records the result and alerts you when the API fails or is slow.

### Creating a monitor
**Monitor -> Monitor Manager... -> Add monitor...**

- **Request** - method, URL, headers, body, auth. **Import from the current request** copies the open request;
  **Test request** tries it once.
- **Interval** - how often it runs (in seconds).
- **Alerts**:
  - *Alert on HTTP failure* - when the status is not 2xx or there is no response.
  - *Alert on slow response* with a threshold in milliseconds.
  - *Only alert when the monitor goes down or recovers* - one alert when it starts failing and one "recovered" alert,
    instead of an alert for every failed check.
  - *Retry before alerting* - failed checks are retried (5 seconds apart) this many times first.
  - *Quiet hours* (for example `22:00` to `07:00`) - no alerts in that time; results are still logged.
  - *Webhook* - **Teams** (incoming webhook), **Slack** (incoming webhook) or **Generic** (any URL that accepts JSON).
  - *Send email alert to* - uses the SMTP settings (**SMTP settings...** / **Email config**, with **Test connection**).

Select a monitor and use **Start / Stop**, **Edit** or **Delete**. Every result is written to the monitor log
(**Open log**, **Clear log**, **Archive log**).

### Seeing the results
- **Monitor Manager** - every monitor with its last run and result.
- **Monitor -> Monitoring Dashboard...** - uptime, average and p50/p95/p99 response time, totals and a chart for a
  date range. **Export data** and **Save chart**.
- **Monitor -> Open Monitors in Browser** - a live page at `http://127.0.0.1:8765/` that refreshes every 3 seconds:
  healthy / failing counts, 24-hour uptime, response times and a small chart per monitor. Only your own computer can
  open it.

### Keeping monitors running
Monitors run while API Tester is open. To keep them running after you close it:

- **When closing** the app with monitors running, choose **Yes** to keep them running in the background.
- **Run in background** in the Monitor Manager does the same at any time; **Stop background** stops it.
- **Start background monitors when I sign in to Windows** starts them automatically after you sign in.
- **Scheduled task...** runs them when Windows starts, even when nobody is signed in (needs API Tester to be started
  as administrator once to install, and the password of the account it should run as).

Only one copy ever runs your monitors, so alerts are never doubled. Changes you make in the Monitor Manager are
picked up by the background monitors within a second.

### The tray icon
While monitors run, an icon appears in the notification area:

| Colour | Meaning |
|---|---|
| Green | All running monitors are healthy |
| Red | At least one monitor is failing |
| Blue | Waiting for the first results |
| Grey | No monitor is running |

Hover for a summary. **Right-click** for each monitor's last result (click a monitor to start or stop it, plus
**Start all** / **Stop all**), the browser dashboard, the monitor log and **Stop background monitors**.
**Double-click** opens API Tester.

> Windows 11 may hide new icons behind the **^** arrow. Drag the icon onto the taskbar, or switch it on in
> **Settings -> Personalization -> Taskbar -> Other system tray icons**. Monitors started by the scheduled task while
> nobody is signed in have no tray icon.

---

## 11. Tools

All in the **Tools** menu.

| Tool | What it does |
|---|---|
| **Manage Environments...** | See [Environments](#environments). |
| **Global Variables...** | See [Global and collection variables](#global-and-collection-variables). |
| **Request Templates...** | Saved request templates: **Load**, **Delete**, **Save current as template...**. |
| **Proxy Configuration...** | Mode **None**, **System** (the default - the Windows proxy) or **Custom** (address, port and optional credentials); **Test connection** checks it. |
| **Cookie Jar...** | Cookies the app received and sends back; view, delete, import and export. |
| **JWT Utility...** | **Decode** a JSON Web Token, **Verify signature** (HS256) and **Generate JWT**. |
| **Generate Report...** | An HTML report of your monitors (summary cards, statistics table). |
| **WebSocket Client...** | **Connect** to a `ws://` / `wss://` URL, send messages and see what arrives. |
| **gRPC Client...** | Calls gRPC services through `grpcurl` (**Download grpcurl** if you don't have it); works with server reflection or a `.proto` file. |
| **Load Tester...** | See below. |

### Load tester
Choose the request (the current one, or a collection request via **Load Test...**), the number of parallel
**threads** and the **duration**, then **Start test**. The live chart shows requests per second and response times;
the summary shows totals, errors and latency. **Stop** ends the test after the requests in flight have finished.

---

## 12. Settings

**Settings** in the header (or **Menu -> Settings...**).

| Group | Options |
|---|---|
| **UI & panel visibility** | Show or hide the environment panel, history, and each request / response tab. |
| **Configuration** | Logging, history, auto-run on history double-click, all request methods, ignore SSL errors (for test servers with self-signed certificates), Postman and cURL import, repeat request, restore request tabs, save responses in history, check for updates at start-up. |
| **App theme**, **Response font size** | Light / Dark (applied immediately); font size of the response viewer (8-72). |
| **Timeout**, **Max repeats**, **Default console language** | Request timeout in seconds; how often **Repeat...** may send (1-100); the console language used without a prefix. |
| **Auto-save & renaming** | Auto-save downloaded files to a folder, name saved files after the uploaded file(s), file-name prefix. |
| **Log level** and logs | Info or Debug; **View logs**, **Open logs folder**, **Clear logs**. |

**Restore defaults** resets everything; **Save** applies the changes immediately.

---

## 13. Keyboard and mouse shortcuts

| Shortcut | Action |
|---|---|
| **Ctrl+Enter** | Send the request |
| **Ctrl+T** | New request tab |
| **Ctrl+W** | Close the request tab |
| **Ctrl+F** | Find in the response |
| **Enter** / **Shift+Enter** (in Find) | Next / previous match |
| **Esc** (in Find) | Close the find bar |
| **Ctrl+Shift+Enter** | Run the console command |
| **Alt+F4** | Exit |
| Double-click a tab | Rename it |
| Middle-click a tab | Close it |
| Drag a tab | Reorder tabs |
| Right-click the response toolbar | Docking options |
| Double-click the tray icon | Open API Tester |

**Help -> Keyboard Shortcuts...** shows the list in the app.

---

## 14. Backup, moving to another PC and updating

### Backup
- **Menu -> Export Workspace...** saves collections, environments, global variables, history, templates and settings
  in one file (choose what to include). **Menu -> Import Workspace...** restores it.
- Or copy the `Configuration` and `History` folders.

### Moving to another PC or Windows account
Passwords, tokens and secret variables are encrypted for your Windows account and cannot be read on another account
or computer - and workspace exports never contain secret variables. After moving, enter those values again.

### Updating
- **Help -> About API Tester -> Check for updates -> Download & update**, then restart the app. API Tester also checks
  once a day in the background and shows a message when a new version is available (switch this off with *Check for
  updates at start-up* in Settings).
- Or download the new `API-Tester.ps1` and replace the old one; keep the `Configuration`, `History` and `Logs` folders.

Downloads are checked against the published checksum before the old version is replaced; the previous version is
kept as `API-Tester.bak.ps1`.

---

## 15. Troubleshooting

| Problem | What to do |
|---|---|
| "Running scripts is disabled on this system" | Start with `powershell -NoProfile -ExecutionPolicy Bypass -File .\API-Tester.ps1`, or run `Unblock-File .\API-Tester.ps1` once. |
| The window does not open, or closes immediately | Start it from a PowerShell window to see the message; the details are also in `Logs\api_tester.csv`. |
| A message appears in the header | That is an error from the last action - the full text is in **Settings -> View logs**. |
| "Could not establish trust relationship" / certificate errors | The server uses a self-signed certificate: switch on *Ignore SSL errors* in Settings (only for test servers). |
| Requests time out behind a company proxy | **Tools -> Proxy Configuration...** -> system proxy or your proxy's address. |
| `{{variable}}` is red / not replaced | Not defined in the active environment, the collection or the globals - hover it to check, and check the environment selected in the header. |
| A downloaded file is not saved | Set **Options -> Save response to file**, or switch on auto-save in Settings (the server must send a file name for auto-save). |
| OpenAPI YAML import fails | `Install-Module powershell-yaml -Scope CurrentUser`, then import again. |
| The monitor tray icon is missing | Look behind the **^** arrow in the taskbar; see [The tray icon](#the-tray-icon). |
| The browser dashboard does not open | Another program uses port 8765 - change `MonitorDashboardPort` in `Configuration\api_tester_settings.json`. |
| Check for updates fails | Your network may block `api.github.com`; download the new version from the releases page instead. |
| I want the previous window | Start with `-ClassicUi`. |

Found a bug or have an idea? Open an issue at https://github.com/imumeshk/API-Tester/issues.
