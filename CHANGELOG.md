# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

## [2.0.0] - 2026-02-18

### Added

- **SyncHash + Dispatcher architecture** -- centralized `[hashtable]::Synchronized(@{})` (`$script:SyncHash`) shared between all runspaces; all named WPF controls stored as `$syncHash.<ControlName>` for direct access from background threads
- `Initialize-PSMMSyncHash` -- populates the syncHash with all named controls after XAML parsing
- `Invoke-PSMMDispatcherUpdate` -- concise thread-safe UI mutation helper via `Dispatcher.Invoke()`
- `Invoke-PSMMBackgroundRunspace` -- spawns runspaces with automatic `$syncHash` injection; replaces manual runspace wiring
- `Invoke-PSMMSafeAction` -- wraps WPF event handlers in `try/catch` with `MessageBox` on unhandled exceptions; prevents silent GUI crashes
- `Show-PSMMCredentialDialog` -- pure WPF dark-themed credential dialog (username TextBox + PasswordBox + OK/Cancel); replaces `Get-Credential` which caused WinForms deadlock on the WPF dispatcher thread
- **In-place grid updates** -- `ModuleGridItem` properties are updated in-place via `INotifyPropertyChanged` (`Status = 'Scanning...'` → actual result); no `Clear()`/re-add on every inventory refresh; stale rows cleaned up after all jobs complete
- **CheckBox dark theme** -- `ControlTemplate`-based `CheckBox` style applied to all three XAML windows (main, settings, credential dialog): 16×16 custom bullet with teal checkmark, dark fill, blue accent on checked
- **Settings ↔ main window CheckBox sync** -- `ChkSkipServers` and `ChkSkipVirtual` are seeded from `$script:Settings` on window open; `Checked`/`Unchecked` handlers write back to `$script:Settings` and persist via `Export-PSMMSettings`; Settings dialog Save already synced the other direction
- `PSModulePath` property on `ModuleGridItem` for module path visibility in the inventory grid
- `ComputerItem` WPF data class with `INotifyPropertyChanged` for checkbox + connection status binding
- `ModuleGridItem` WPF data class with `INotifyPropertyChanged` for reactive inventory grid
- Job polling via `DispatcherTimer` (500 ms) with auto-refresh of inventory after Install/Update/Remove
- `ExcludeServers` and `ExcludeVirtual` settings to filter computers during ADSI discovery; exposed as toolbar CheckBoxes (`ChkSkipServers`, `ChkSkipVirtual`) with pill-toggle visual indicators
- `GlobalExcludeList` setting to permanently exclude specific computer names
- `ModuleSearchPaths` setting to configure local module search directories
- `OSFilter` setting for additional OS-based computer filtering
- `Get-ADSIInfo` exported function for domain LDAP path and OU discovery
- `PS-ModuleManager.ps1` self-elevating launcher script (auto-admin, console hiding)
- `scripts/Create-Shortcut.ps1` to create a desktop shortcut for launching the module
- `scripts/Get-ADSIInfo.ps1` standalone ADSI discovery script for populating settings
- `-WindowStartupLocation` and `-WindowState` parameters on `Show-ModuleManagerGUI`
- Pester v5 test suite (`test/PS-ModuleManager.Tests.ps1`) covering non-WPF business logic: `Get-PSMMDefaultSettings`, `Import-PSMMSettings`, `Test-PSMMSettings`, `Compare-PSMMModuleVersions`, `Get-PSMMShareModules`, `ConvertTo-PSMMLdapSafeString`
- `ConvertTo-PSMMLdapSafeString` -- LDAP injection protection; escapes special characters before building `DirectorySearcher` filters
- Indeterminate `ProgressBar` (`StatusProgress`) in the status bar; activated during long-running operations, hidden on completion
- Export inventory to CSV button (`BtnExportCsv`) with `SaveFileDialog`
- Export log to text file button (`BtnExportLog`) with `SaveFileDialog`
- `Get-PSMMModuleDependencies` -- reads `.psd1` `RequiredModules` before install; logs warnings when dependencies are detected
- "Select All", "Deselect All", and "Invert Selection" buttons for bulk computer list management
- Settings import/export buttons in the Settings dialog (load from / save to external JSON via `OpenFileDialog` / `SaveFileDialog`)
- `Invoke-PSMMLogRotation` -- automatic log cleanup: 30-day file retention, 10 MB total cap; runs on GUI startup
- Keyboard shortcuts: `Ctrl+R` (Inventory), `Ctrl+S` (Settings), `Ctrl+E` (Export CSV), `Escape` (Cancel jobs)
- Enhanced confirmation dialogs for Install/Update/Remove listing affected computers and modules
- `.github/copilot-instructions.md` with coding standards and improvement roadmap
- `LICENSE` file

### Changed

- **BREAKING** -- replaced all `$script:` UI state variables with `$script:SyncHash` hashtable; direct control references are now `$script:SyncHash.<ControlName>` instead of saved local variables
- Reorganized module into `SyncHash Helpers` region (new) between `WPF XAML Definition` and `WPF Helpers`
- `BtnCredentials.Add_Click` now calls `Show-PSMMCredentialDialog` instead of `Get-Credential` (fixes WPF dispatcher deadlock)
- `Uninstall-PSMMModule` accepts `ModulePath` parameter for improved path handling
- All module operations use `ObservableCollection` with in-place property updates (no grid clear/rebuild)
- `Get-ADSIInfo` error handling improved with fallback to local computer info when ADSI is unavailable
- Dark ScrollBar style applied globally (5 px thin scrollbars)
- Module expanded from ~1900 lines (1.0.0) to ~3585 lines (2.0.0)
- Comprehensive README and PLAN.md updates
- Module version bumped to 2.0.0 in manifest

## [1.0.0] - 2026-02-16

### Added

- Initial release of PS-ModuleManager
- WPF-based GUI with dark VS Code-inspired theme (all XAML defined inline)
- ADSI-based computer discovery with OU filtering, wildcard search, and enabled-only toggle
- Parallel remote module inventory via runspace pool with configurable concurrency
- Install / Update / Remove modules from a central network share (ZIP or folder-based)
- Version comparison with color-coded status grid (Green / Orange / Red / Gray)
- Persistent `settings.json` configuration with built-in validation and Settings dialog
- Structured logging to file and scrollable UI pane with severity filtering
- `Show-ModuleManagerGUI` exported function with `-SettingsPath` parameter
- Credential management with Default / Prompt / Stored modes
- Admin check on startup with warning when not elevated
- Module manifest (`PS-ModuleManager.psd1`)
- CHANGELOG.md
- .gitignore file
