# PS-ModuleManager -- Comprehensive Plan

## 1. Overview

**PS-ModuleManager** is a single-file PowerShell module (`PS-ModuleManager.psm1`) with a rich WPF GUI that lets administrators manage PowerShell modules across local and remote domain-joined computers. All XAML, logic, and services live inside one `.psm1` file -- no external dependencies beyond .NET Framework (WPF/PresentationFramework) and Windows PowerShell 5.1+.

> **Note:** The module requires Windows PowerShell 5.1. All code uses PS 5.1-compatible syntax only (no `??`, `?.`, ternary operators, or `ForEach-Object -Parallel`). The `.psm1` file is saved with a UTF-8 BOM to ensure correct encoding on all systems.

### 1.1 Goals

| # | Goal | Detail |
|---|------|--------|
| 1 | **Unified GUI** | WPF window (XAML defined inline as here-strings) for install / update / remove / inventory of PowerShell modules. |
| 2 | **AD Computer Discovery** | ADSI-based enumeration of domain-joined computers with OU filtering, name search, and enabled-only toggle. |
| 3 | **Parallel Remote Operations** | Runspace pool with configurable concurrency for `Invoke-Command` against multiple targets simultaneously. |
| 4 | **Central Module Repository** | Network share (`\\server\share\Modules\<Name>\<Version>\`) as the source of truth for module packages (ZIP). |
| 5 | **Version Comparison** | Compare installed module versions against the latest available on the share; color-code outdated / missing / up-to-date. |
| 6 | **Configuration** | Persistent `settings.json` for paths, concurrency, credential mode, logging, and retry policy. |
| 7 | **Logging** | Structured log output to both the UI log pane and a log file with timestamps and severity. |
| 8 | **Security** | Kerberos remoting, optional alternate credentials, Authenticode validation of module ZIPs. |

---

## 2. Architecture (Single-File Design)

```
PS-ModuleManager.psm1            <-- everything lives here
|-- #region Assembly Loading       (PresentationFramework, WindowsBase, etc.)
|-- #region Script-Scoped State    (module-wide variables: Settings, RunspacePool, Jobs, etc.)
|-- #region Configuration          (Get-PSMMDefaultSettings, Import/Export-PSMMSettings, Test-PSMMSettings)
|-- #region Logging                (Write-PSMMLog -- file + UI dispatcher)
|-- #region ADSI Service           (Get-PSMMComputers -- LDAP search via DirectorySearcher)
|-- #region Runspace Pool          (New-PSMMRunspacePool, Invoke-PSMMParallel, Receive/Stop-PSMMJobs, Close-PSMMRunspacePool)
|-- #region Module Inventory       (Get-PSMMRemoteModules, Get-PSMMShareModules, Compare-PSMMModuleVersions)
|-- #region Module Deployment      (Install-PSMMModule, Uninstall-PSMMModule)
|-- #region Credential Management  (Get-PSMMCredential -- Default/Prompt/Stored modes)
|-- #region WPF XAML Definition    (inline XAML here-strings for main window + settings dialog)
|-- #region WPF Helpers            (New-PSMMWindow, Find-PSMMControl, Update-PSMMDispatcher)
|-- #region WPF Event Handlers     (Register-PSMMMainWindowEvents -- all button/menu wiring)
|-- #region Job Poller             (Start-PSMMJobPoller -- DispatcherTimer for async result polling)
|-- #region Settings Dialog        (Show-PSMMSettingsDialog -- modal settings editor)
+-- #region Exported Function      (Show-ModuleManagerGUI -- single public entry-point)
```

### 2.1 Internal Functions

| Function | Region | Purpose |
|----------|--------|---------|
| `Get-PSMMDefaultSettings` | Configuration | Returns hashtable with all default settings |
| `Import-PSMMSettings` | Configuration | Loads settings.json, merges with defaults |
| `Export-PSMMSettings` | Configuration | Persists settings hashtable to JSON file |
| `Test-PSMMSettings` | Configuration | Validates settings, returns list of issues |
| `Write-PSMMLog` | Logging | Structured log to file + UI pane (dispatcher-safe) |
| `Get-PSMMComputers` | ADSI Service | Queries AD for computer objects via DirectorySearcher |
| `New-PSMMRunspacePool` | Runspace Pool | Creates and opens a bounded runspace pool |
| `Invoke-PSMMParallel` | Runspace Pool | Queues script blocks across computers in the pool |
| `Receive-PSMMJobs` | Runspace Pool | Polls and harvests completed job results |
| `Stop-PSMMAllJobs` | Runspace Pool | Cancels all running jobs |
| `Close-PSMMRunspacePool` | Runspace Pool | Closes and disposes the pool |
| `Get-PSMMRemoteModules` | Module Inventory | Runs Get-Module -ListAvailable on remote computers |
| `Get-PSMMShareModules` | Module Inventory | Lists modules/versions on the central share |
| `Compare-PSMMModuleVersions` | Module Inventory | Compares installed vs. share versions |
| `Install-PSMMModule` | Module Deployment | Installs module from share to remote computers |
| `Uninstall-PSMMModule` | Module Deployment | Removes module from remote computers |
| `Get-PSMMCredential` | Credential Mgmt | Obtains credentials per configured mode |
| `New-PSMMWindow` | WPF Helpers | Parses XAML string into WPF Window object |
| `Find-PSMMControl` | WPF Helpers | Finds named control inside a WPF window |
| `Update-PSMMDispatcher` | WPF Helpers | Thread-safe UI update via Dispatcher.Invoke |
| `Register-PSMMMainWindowEvents` | Event Handlers | Wires all button/menu event handlers |
| `Start-PSMMJobPoller` | Job Poller | DispatcherTimer to poll async job completion |
| `Show-PSMMSettingsDialog` | Settings Dialog | Opens modal settings editor window |

### 2.2 Data Models (PSCustomObject patterns)

| Model | Properties |
|-------|-----------|
| `ComputerInfo` | `Name`, `DNSHostName`, `OU`, `Enabled`, `OS`, `Reachable` |
| `ModuleInfo` | `ComputerName`, `ModuleName`, `InstalledVersion`, `TargetVersion`, `Status` (UpToDate / Outdated / Missing / Unknown) |
| `DeploymentJob` | `Id`, `ComputerName`, `ModuleName`, `Operation` (Install / Update / Remove), `Status` (Queued / Running / Completed / Failed), `Message`, `Timestamp` |
| `AppSettings` | `DomainLdapPath`, `OuFilter`, `ModuleSearchPaths`, `CentralSharePath`, `MaxConcurrency`, `CredentialMode`, `LogPath`, `RetryCount`, `ReachabilityCheck`, `LogLevel`, `JobTimeoutSeconds` |

---

## 3. Key Functional Areas

### 3.1 AD Computer Discovery (ADSI)

- Uses `[System.DirectoryServices.DirectorySearcher]` -- no RSAT / ActiveDirectory module required.
- Filters: `(&(objectCategory=computer)(objectClass=computer))` with optional OU scope.
- Returns `ComputerInfo` objects; optional WinRM reachability test (`Test-WSMan`).
- Search box supports wildcard (`*web*`) translated to LDAP `(cn=*web*)`.

### 3.2 Module Inventory

- Runs `Get-Module -ListAvailable` remotely via `Invoke-Command` inside runspace pool jobs.
- Groups results by computer -> module -> version.
- Compares against the latest version found on the central share.
- Grid coloring: **Green** = up-to-date, **Orange** = outdated, **Red** = missing, **Gray** = unreachable.

### 3.3 Module Deployment

| Operation | Steps |
|-----------|-------|
| **Install** | 1. Copy ZIP from share to remote temp. 2. Extract to `$env:ProgramFiles\WindowsPowerShell\Modules\<Name>\<Ver>`. 3. `Import-Module -Force` to validate. 4. Log result. |
| **Update** | 1. Back up current version folder. 2. Perform Install steps. 3. Remove backup on success (or rollback on failure). |
| **Remove** | 1. Confirm via dialog. 2. `Remove-Module -Force` if loaded. 3. Delete module folder. 4. Log result. |

### 3.4 Runspace Pool & Concurrency

- Pool size: `[Math]::Min(4, [Environment]::ProcessorCount)` -- overridable in settings.
- Each job: `[PowerShell]::Create()` bound to shared pool; async `BeginInvoke()`.
- Progress polling on UI timer (500 ms) dispatches status updates to WPF.
- Cancel support: `PowerShell.Stop()` + `Runspace.Close()` per job.
- Timeout support: configurable per-job timeout via `JobTimeoutSeconds` setting.

### 3.5 WPF GUI Layout (Inline XAML)

```
+------------------------------------------------------------------+
|  Menu Bar  [ File | Tools | Help ]                               |
+----------+---------------------------------------+---------------+
| Computer |  Module Grid                          | Actions       |
| List     |  +--------+--------+--------+-------+ | [> Install]   |
|          |  |Computer|Module  |Current |Target | | [~ Update]    |
| OU Tree  |  |        |        |Version |Version| | [x Remove]    |
| + Search |  |        |        |        |       | | [@ Refresh]   |
|          |  +--------+--------+--------+-------+ |               |
|          |                                       | [* Settings]  |
+----------+---------------------------------------+---------------+
|  Log Pane (scrollable, filterable by severity)                   |
|  [INFO] 14:32:01 -- Queried 12 computers ...                    |
|  [WARN] 14:32:05 -- SRV03 unreachable ...                       |
+------------------------------------------------------------------+
|  Status Bar: Jobs 3/10 | Pool 4 threads | Connected to CORP     |
+------------------------------------------------------------------+
```

### 3.6 Settings Dialog

- Modal WPF window (also inline XAML).
- Fields: LDAP path, OU filter, share path, concurrency, credential mode dropdown, log path, retry count, log level.
- **Test Share** and **Test AD** buttons for connectivity validation.
- Save writes `settings.json` next to the module; validates before persisting.

### 3.7 Logging

- `Write-PSMMLog` function: severity (INFO / WARN / ERROR / DEBUG), message, optional computer name.
- Appends to log file (`$LogPath\PS-ModuleManager_yyyy-MM-dd.log`).
- Dispatches to WPF `ListBox` on UI thread via `Dispatcher.Invoke`.
- Log level filtering: entries below the configured `LogLevel` are suppressed.

---

## 4. Security Considerations

| Area | Approach |
|------|----------|
| Remoting transport | Kerberos (default domain) or HTTPS; never plain HTTP with basic auth. |
| Credentials | `CredentialMode`: **Default** (current user), **Prompt** (`Get-Credential`), **Stored** (Windows Credential Manager via `cmdkey`). |
| Module signing | Optional Authenticode check on ZIP before extraction (`Get-AuthenticodeSignature`). |
| Least privilege | Remoting sessions use constrained endpoints where possible. |

---

## 5. File Deliverables

| File | Purpose |
|------|---------|
| `PS-ModuleManager.psd1` | Module manifest (version, GUID, exported functions, required assemblies). |
| `PS-ModuleManager.psm1` | **Single comprehensive module** -- all code, inline WPF XAML, and logic (~1900 lines). |
| `settings.json` | Sample / default configuration (created on first run if missing). |
| `docs/PLAN.md` | This plan document. |
| `README.md` | Quick-start, configuration reference, project structure. |
| `LICENSE` | License file. |

---

## 6. Usage

```powershell
# Import the module
Import-Module .\PS-ModuleManager.psd1

# Launch the GUI
Show-ModuleManagerGUI

# Or with a custom settings file
Show-ModuleManagerGUI -SettingsPath "C:\Config\settings.json"
```

---

## 7. Compatibility Notes

- **PowerShell 5.1 only** -- no PS 7+ operators (`??`, `?.`, ternary `? :`).
- **UTF-8 BOM** -- the `.psm1` file is saved with a byte-order mark so PS 5.1 reads it correctly (PS 5.1 defaults to ANSI otherwise).
- **ASCII-safe strings** -- no Unicode em dashes, bullets, or special characters in executable code paths.
- **.NET Framework 4.5+** -- required for WPF assemblies (`PresentationFramework`, `PresentationCore`, `WindowsBase`).

---

## 8. Future Enhancements

- PowerShell 7 / cross-platform support (replace WPF with Avalonia or terminal UI).
- PSGallery integration as an alternative module source.
- Scheduled task wrapper for unattended deployments.
- Export inventory to CSV / HTML report.
- Module dependency graph visualization.
- Authenticode signature enforcement policy toggle.
