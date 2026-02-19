# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [2.0.0] - 2026-02-17

### Changed

- **BREAKING: Complete architectural overhaul to SyncHash + Dispatcher pattern**
  - Replaced all `$script:` UI state with a centralized `[hashtable]::Synchronized(@{})` (`$script:SyncHash`)
  - All named WPF controls are stored in `$syncHash.<ControlName>` for direct access from any runspace
  - Background operations update the UI thread-safely via `$syncHash.Window.Dispatcher.Invoke([Action]{...})`
  - New `Initialize-PSMMSyncHash` function populates the syncHash with all named controls after XAML parsing
  - New `Invoke-PSMMDispatcherUpdate` helper for concise thread-safe UI mutations
  - New `Invoke-PSMMBackgroundRunspace` helper for spawning runspaces with automatic `$syncHash` injection
- Reorganized module regions to include new `SyncHash Helpers` region
- Bumped module version to 2.0.0 in manifest

### Preserved

- All 27 internal functions and 2 exported functions (`Show-ModuleManagerGUI`, `Get-ADSIInfo`)
- Complete dark-theme XAML (main window + settings dialog) with all styles and controls
- ADSI computer discovery, runspace pool, module inventory/deployment, settings, logging
- `INotifyPropertyChanged` C# classes (`ComputerItem`, `ModuleGridItem`)
- `ObservableCollection` data binding for computer list and module grid
- DispatcherTimer-based job poller with auto-refresh after Install/Update/Remove
- All keyboard shortcuts, confirmation dialogs, and CSV/log export functionality
- PowerShell 5.1 compatibility and UTF-8 with BOM encoding

## [Unreleased] - 2026-02-17

### Added

- `PSModulePath` property on `ModuleGridItem` for enhanced module path visibility in the UI
- `ComputerItem` WPF data class with `INotifyPropertyChanged` for checkbox + connection status binding
- `ModuleGridItem` WPF data class with `INotifyPropertyChanged` for reactive inventory grid
- Job polling via `DispatcherTimer` with auto-refresh of inventory after Install/Update/Remove operations
- `ExcludeServers` and `ExcludeVirtual` settings to filter computers during ADSI discovery
- `GlobalExcludeList` setting to permanently exclude specific computer names
- `ModuleSearchPaths` setting to configure local module search directories
- `Get-ADSIInfo` exported function for domain LDAP path and OU discovery
- `PS-ModuleManager.ps1` self-elevating launcher script (auto-admin, console hiding)
- `scripts/Create-Shortcut.ps1` to create a desktop shortcut for launching the module
- `scripts/Get-ADSIInfo.ps1` standalone ADSI discovery script for populating settings
- `-WindowStartupLocation` and `-WindowState` parameters on `Show-ModuleManagerGUI`
- LICENSE file
- VSCode settings for spell checking and terminal configuration
- `.editorconfig` for consistent coding styles
- `.gitattributes` for LF normalization
- Test scripts in `test/` directory
- Pester v5 test suite (`test/PS-ModuleManager.Tests.ps1`) covering non-WPF business logic
- `ConvertTo-PSMMLdapSafeString` for LDAP injection protection in search filters
- `Invoke-PSMMSafeAction` wrapper for graceful error recovery in WPF event handlers
- Indeterminate `ProgressBar` in status bar during long-running operations
- Export inventory to CSV button (`BtnExportCsv`) with `SaveFileDialog`
- `Get-PSMMModuleDependencies` for `.psd1` manifest `RequiredModules` checking before install
- Dependency warnings logged during `Install-PSMMModule` when `RequiredModules` are detected
- "Invert Selection" button for bulk computer selection toggling
- Settings import/export buttons in the Settings dialog (load from / save to external JSON)
- `Invoke-PSMMLogRotation` for automatic log file cleanup (30-day retention, 10 MB cap)
- Log rotation runs automatically on GUI startup
- Keyboard shortcuts: `Ctrl+R` (Inventory), `Ctrl+S` (Settings), `Ctrl+E` (Export CSV), `Escape` (Cancel jobs)
- Enhanced confirmation dialogs for Install/Update/Remove with detailed computer and module lists
- `.github/copilot-instructions.md` with coding standards and improvement roadmap

### Changed

- Enhance `Uninstall-PSMMModule` to accept `ModulePath` parameter and improve path handling
- Refactor code to use `ObservableCollection` for automatic WPF UI updates on computer and module lists
- Enhance UI layout with ScrollBar styles, dark theme refinements, and auto-refresh after operations
- Improve `Get-ADSIInfo` error handling with fallback to local computer info when ADSI is unavailable
- Expand module from ~1900 lines to ~2845 lines with additional features and UI enhancements
- Update `MaxConcurrency` default behavior
- Comprehensive README update with full settings reference and project structure
- Create PLAN.md with detailed architecture and functional specification

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
