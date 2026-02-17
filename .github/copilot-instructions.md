# PS-ModuleManager -- Copilot Instructions

## Project Identity

PS-ModuleManager is a **single-file PowerShell module** (`PS-ModuleManager.psm1`, ~2845 lines) with an inline WPF GUI for managing PowerShell modules across local and remote domain-joined computers. There are no external XAML files -- all UI is defined as inline here-strings.

---

## Hard Constraints

These rules are non-negotiable. Violations will break the module.

1. **PowerShell 5.1 only** -- never use PS 7+ syntax: `??`, `?.`, ternary `? :`, `ForEach-Object -Parallel`, null-coalescing assignment `??=`, pipeline chain operators `&&` / `||`, or `Clean` block.
2. **UTF-8 with BOM** -- the `.psm1` file must be saved with a byte-order mark. PS 5.1 defaults to ANSI without it.
3. **ASCII-safe executable code** -- no Unicode em dashes, smart quotes, bullets, or special characters in any code path. Markdown comments are fine.
4. **.NET Framework 4.5+ only** -- no .NET Core / .NET 5+ APIs. WPF assemblies: `PresentationFramework`, `PresentationCore`, `WindowsBase`.
5. **Single-file architecture** -- all logic, XAML, data classes, and services live inside `PS-ModuleManager.psm1`. Do not extract code into separate `.ps1` files loaded via dot-sourcing (helper scripts in `scripts/` are standalone utilities, not part of the module).
6. **`#requires -Version 5.1`** -- this directive must remain at the top of the `.psm1`.

---

## Coding Standards

### Naming

- Internal functions: `Verb-PSMM<Noun>` (e.g., `Get-PSMMComputers`, `Write-PSMMLog`).
- Exported functions: descriptive names without the `PSMM` prefix (e.g., `Show-ModuleManagerGUI`, `Get-ADSIInfo`).
- Script-scoped variables: `$script:PascalCase` (e.g., `$script:Settings`, `$script:RunspacePool`).
- WPF control names in XAML: `PascalCase` (e.g., `ComputerListBox`, `ModuleDataGrid`, `TxtOuFilter`).

### Structure

The `.psm1` is organized into `#region` / `#endregion` blocks in this order:

```
#region Assembly Loading
#region Script-Scoped State
#region Configuration          -- Get-PSMMDefaultSettings, Import/Export/Test-PSMMSettings
#region Logging                -- Write-PSMMLog, Invoke-PSMMLogRotation
#region ADSI Service           -- ConvertTo-PSMMLdapSafeString, Get-PSMMComputers
#region Runspace Pool          -- New-PSMMRunspacePool, Invoke-PSMMParallel, Receive/Stop/Close
#region Module Inventory       -- Get-PSMMRemoteModules, Get-PSMMShareModules, Compare-PSMMModuleVersions
#region Module Deployment      -- Get-PSMMModuleDependencies, Install-PSMMModule, Uninstall-PSMMModule
#region Credential Management  -- Get-PSMMCredential
#region WPF XAML Definition    -- inline XAML here-strings (main window + settings dialog)
#region WPF Helpers            -- New-PSMMWindow, Find-PSMMControl, Update-PSMMDispatcher, Invoke-PSMMSafeAction
#region WPF Event Handlers     -- Register-PSMMMainWindowEvents
#region Job Poller             -- Start-PSMMJobPoller (DispatcherTimer)
#region ADSI Helper            -- Get-ADSIInfo
#region Settings Dialog        -- Show-PSMMSettingsDialog
#region Exported Function      -- Show-ModuleManagerGUI
```

New code must be placed in the correct region. If a new region is needed, insert it in logical order and follow the existing comment-banner style.

### Functions

- Every function needs a `<# .SYNOPSIS #>` comment-based help block.
- Use `[CmdletBinding()]` and typed `param()` blocks on exported functions.
- Internal functions should validate parameters but can use simpler signatures.
- Always use `Write-PSMMLog` for user-facing messages -- never bare `Write-Host` inside the module (except in `Get-ADSIInfo` which is a console helper).

### WPF / XAML

- All XAML is stored in `$script:` here-string variables (e.g., `$script:MainWindowXaml`).
- Thread-safe UI updates must go through `Update-PSMMDispatcher` or `$window.Dispatcher.Invoke()`.
- Data binding uses `ObservableCollection[T]` with `INotifyPropertyChanged` C# classes (`ComputerItem`, `ModuleGridItem`) defined via `Add-Type`.
- The GUI uses a dark theme (VS Code-inspired). Maintain the existing color palette and style conventions.

### Error Handling

- Wrap remote operations in `try/catch` -- never let a single computer failure crash the entire batch.
- Use `Write-PSMMLog -Severity 'ERROR'` for caught exceptions.
- Retry logic: honor `$script:Settings.RetryCount` for transient failures (WinRM timeouts, network errors).
- Always clean up runspace pool resources in `finally` blocks or on window close.

### Settings

Any new setting must be added in **all** of these places:
1. `Get-PSMMDefaultSettings` -- provide a sensible default value.
2. `settings.json` -- add to the sample file.
3. `Test-PSMMSettings` -- add validation if the setting has constraints.
4. Settings dialog XAML and event handlers (if user-configurable).
5. Documentation: `README.md` settings table, `PLAN.md` AppSettings model, this file.

Current settings schema:

| Setting | Type | Default |
|---------|------|---------|
| `DomainLdapPath` | string | `''` (auto-detect) |
| `OuFilter` | string | `''` |
| `ModuleSearchPaths` | string[] | `['C:\Program Files\WindowsPowerShell\Modules']` |
| `CentralSharePath` | string | `''` |
| `MaxConcurrency` | int | `Min(4, ProcessorCount)` |
| `CredentialMode` | string | `'Default'` -- `Default` / `Prompt` / `Stored` |
| `LogPath` | string | `<ModuleRoot>\logs` |
| `LogLevel` | string | `'INFO'` -- `DEBUG` / `INFO` / `WARN` / `ERROR` |
| `RetryCount` | int | `2` |
| `ReachabilityCheck` | bool | `$true` |
| `JobTimeoutSeconds` | int | `300` |
| `ExcludeServers` | bool | `$false` |
| `ExcludeVirtual` | bool | `$false` |
| `GlobalExcludeList` | string[] | `@()` |

---

## Data Models

These C# classes are compiled via `Add-Type` at module load. They implement `INotifyPropertyChanged` for WPF binding.

| Class | Properties |
|-------|-----------|
| `ComputerItem` | `IsSelected` (bool), `Name` (string), `ConnectionStatus` (string: Local/WinRM/Unreachable) |
| `ModuleGridItem` | `ComputerName`, `ModuleName`, `InstalledVersion`, `TargetVersion`, `Status`, `Model`, `OS`, `PSModulePath` |

PSCustomObject patterns used internally:

| Model | Properties |
|-------|-----------|
| `ComputerInfo` | `Name`, `DNSHostName`, `OU`, `Enabled`, `OS`, `Reachable` |
| `ModuleInfo` | `ComputerName`, `ModuleName`, `InstalledVersion`, `TargetVersion`, `Status`, `PSModulePath` |
| `DeploymentJob` | `Id`, `ComputerName`, `ModuleName`, `Operation`, `Status`, `Message`, `Timestamp` |

---

## Exported API

Only two functions are exported (via both `Export-ModuleMember` and the `.psd1` manifest):

| Function | Purpose |
|----------|---------|
| `Show-ModuleManagerGUI` | Launch WPF GUI. Params: `-SettingsPath`, `-WindowStartupLocation`, `-WindowState`. |
| `Get-ADSIInfo` | Console helper to discover domain LDAP path and enumerate OUs. |

---

## File Layout

```
PS-ModuleManager/
  .github/copilot-instructions.md   # This file
  PS-ModuleManager.psd1              # Module manifest
  PS-ModuleManager.psm1              # The module (all code + inline XAML)
  PS-ModuleManager.ps1               # Self-elevating launcher
  settings.json                      # Configuration (auto-created on first run)
  CHANGELOG.md                       # Keep a Changelog format
  README.md                          # User-facing docs
  LICENSE
  docs/PLAN.md                       # Architecture & design plan
  scripts/Create-Shortcut.ps1        # Desktop shortcut creator
  scripts/Get-ADSIInfo.ps1           # Standalone ADSI discovery
  logs/                              # Log output directory
  test/                              # Test scripts
```

---

## Testing Guidance

- Test all changes in **Windows PowerShell 5.1** (`powershell.exe`), not `pwsh.exe`.
- Verify WPF window loads: `Import-Module .\PS-ModuleManager.psd1 -Force; Show-ModuleManagerGUI`
- After adding a setting, confirm round-trip: default → export → import → UI display.
- After changing XAML, verify the window parses without error (`[System.Windows.Markup.XamlReader]::Parse()`).
- Remote operations require WinRM; test with `Test-WSMan <computername>` first.

---

## Recommended Improvements

The following enhancements would improve reliability, maintainability, and user experience. Prioritized by impact.

### High Priority (all implemented)

1. **Pester test suite** -- DONE. `test/PS-ModuleManager.Tests.ps1` with unit tests for `Get-PSMMDefaultSettings`, `Import-PSMMSettings`, `Test-PSMMSettings`, `Compare-PSMMModuleVersions`, `Get-PSMMShareModules`, `ConvertTo-PSMMLdapSafeString`.

2. **Input validation and sanitization** -- DONE. `ConvertTo-PSMMLdapSafeString` escapes special LDAP characters in user-provided filters before building the `DirectorySearcher` filter.

3. **Graceful error recovery in UI** -- DONE. `Invoke-PSMMSafeAction` wraps event handlers with `try/catch` and shows a `MessageBox` on unhandled exceptions. Enhanced confirmation dialogs for all destructive actions.

4. **Progress indication** -- DONE. Indeterminate `ProgressBar` (`StatusProgress`) in the status bar, activated by `Start-PSMMJobPoller` and hidden when all jobs complete.

5. **Export inventory to CSV** -- DONE. `BtnExportCsv` button with `SaveFileDialog` exports `ModuleDataGrid` contents via `Export-Csv`.

### Medium Priority (all implemented)

6. **Module dependency awareness** -- DONE. `Get-PSMMModuleDependencies` reads `.psd1` manifests for `RequiredModules` and logs warnings before install.

7. **Bulk select/deselect computers** -- DONE. "Select All", "Deselect All", and "Invert Selection" buttons in the computer list panel.

8. **Confirmation dialogs for destructive actions** -- DONE. All Install/Update/Remove operations show confirmation dialogs listing affected computers and modules.

9. **Settings import/export** -- DONE. Import/Export buttons in the Settings dialog with `OpenFileDialog`/`SaveFileDialog` for external JSON files.

10. **Log rotation** -- DONE. `Invoke-PSMMLogRotation` removes files older than 30 days and enforces a 10 MB total size cap. Runs automatically on GUI startup.

11. **Keyboard shortcuts** -- DONE. `Ctrl+R` = Inventory refresh, `Ctrl+S` = Settings, `Ctrl+E` = Export CSV, `Escape` = Cancel running jobs. Implemented via `PreviewKeyDown` on the main window.

### Low Priority / Future

12. **PSGallery as a module source** -- Support `Install-Module` / `Find-Module` from the PowerShell Gallery as an alternative to the central share, with a toggle in settings.

13. **HTML report generation** -- Generate a styled HTML report of the inventory diff (installed vs. target versions) for email distribution or intranet publishing.

14. **Scheduled task integration** -- Add a function `Register-PSMMScheduledTask` that creates a Windows Scheduled Task to run unattended inventory scans and email reports.

15. **Module version pinning** -- Allow pinning specific module versions per computer group so that not all machines are upgraded to the latest share version simultaneously (staged rollout).

16. **Dark/Light theme toggle** -- Add a theme switcher in the UI. The current dark theme is hardcoded in XAML; extract color resources into a `ResourceDictionary` pattern for easy swapping.

17. **Authenticode enforcement toggle** -- Add a setting `RequireSignedModules` (bool) that validates `Get-AuthenticodeSignature` on module ZIPs before extraction, blocking unsigned packages.

18. **Connection status caching** -- Cache WinRM reachability results for a configurable TTL (e.g., 5 minutes) so that switching between operations doesn't re-test every computer.
