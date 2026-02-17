# PS-ModuleManager

A **single-file PowerShell module** with a WPF GUI for managing PowerShell modules across local and remote domain-joined computers.

> **Requires Windows PowerShell 5.1** -- all code is PS 5.1-compatible. No PowerShell 7+ syntax.

## Features

- **AD Computer Discovery** -- ADSI-based enumeration with OU filtering, wildcard search, and enabled-only toggle (no RSAT required)
- **Parallel Remote Operations** -- Runspace pool with configurable concurrency for fast multi-target operations
- **Module Inventory** -- Query installed modules on remote computers; compare versions against a central share
- **Install / Update / Remove** -- Deploy modules from a central network share (ZIP or folder-based)
- **Version Status** -- Color-coded grid: green (up-to-date), orange (outdated), red (missing), gray (unreachable)
- **Settings UI** -- Built-in settings dialog with connectivity tests; persists to `settings.json`
- **Structured Logging** -- Timestamped log output to both the UI pane and log files
- **Dark-themed WPF GUI** -- Modern VS Code-inspired interface with all XAML defined inline

## Requirements

- Windows PowerShell 5.1+
- .NET Framework 4.5+ (for WPF)
- WinRM enabled on target computers (for remote operations)
- Domain-joined machine (for ADSI computer discovery)

## Quick Start

```powershell
# Import the module
Import-Module .\PS-ModuleManager.psd1

# Launch the GUI
Show-ModuleManagerGUI

# Or with a custom settings file
Show-ModuleManagerGUI -SettingsPath "C:\Config\settings.json"

# Launch maximized and centered on owner window
Show-ModuleManagerGUI -WindowStartupLocation CenterOwner -WindowState Maximized
```

Alternatively, use the self-elevating launcher script:

```powershell
# Automatically elevates to Administrator and hides the console window
.\PS-ModuleManager.ps1
```

Or create a desktop shortcut:

```powershell
.\scripts\Create-Shortcut.ps1
```

## Configuration

Edit `settings.json` (created automatically on first run) or use the built-in Settings dialog:

| Setting | Description | Default |
|---------|-------------|---------|
| `DomainLdapPath` | LDAP path to domain root | *(auto-detect)* |
| `OuFilter` | OU scope for computer search | *(all)* |
| `CentralSharePath` | UNC path to module repository | *(empty)* |
| `ModuleSearchPaths` | Local paths to search for installed modules | `C:\Program Files\WindowsPowerShell\Modules` |
| `MaxConcurrency` | Parallel runspace threads | `4` |
| `CredentialMode` | `Default` / `Prompt` / `Stored` | `Default` |
| `LogPath` | Directory for log files | `logs/` |
| `LogLevel` | `DEBUG` / `INFO` / `WARN` / `ERROR` | `INFO` |
| `RetryCount` | Retry attempts for failed operations | `2` |
| `ReachabilityCheck` | Test WinRM before operations | `true` |
| `JobTimeoutSeconds` | Per-job timeout for remote operations | `300` |
| `ExcludeServers` | Skip server OS computers during discovery | `false` |
| `ExcludeVirtual` | Skip virtual machines during discovery | `false` |
| `GlobalExcludeList` | Array of computer names to always exclude | `[]` |

## Central Share Layout

```
\\server\PSModules\
+-- ModuleA\
|   +-- 1.0.0\
|   |   +-- ModuleA.psm1 (or module.zip)
|   +-- 1.1.0\
|       +-- ModuleA.psm1
+-- ModuleB\
    +-- 2.0.0\
        +-- module.zip
```

## Project Structure

```
PS-ModuleManager/
+-- PS-ModuleManager.psd1    # Module manifest
+-- PS-ModuleManager.psm1    # Single comprehensive module (all code + inline WPF XAML)
+-- PS-ModuleManager.ps1     # Self-elevating launcher script (hides console, imports module, launches GUI)
+-- settings.json             # Configuration file (auto-created on first run)
+-- CHANGELOG.md              # Project changelog
+-- README.md
+-- LICENSE
+-- docs/
|   +-- PLAN.md               # Detailed project plan & architecture
+-- scripts/
|   +-- Create-Shortcut.ps1   # Creates a desktop shortcut to launch the module
|   +-- Get-ADSIInfo.ps1      # Standalone script to discover domain LDAP path and OUs
+-- logs/                     # Log file output directory
+-- test/
|   +-- test.ps1              # Test scripts
|   +-- test2.ps1
```

## Exported Commands

| Command | Description |
|---------|-------------|
| `Show-ModuleManagerGUI` | Opens the WPF Module Manager window. Accepts `-SettingsPath`, `-WindowStartupLocation`, and `-WindowState` parameters. |
| `Get-ADSIInfo` | Discovers the domain LDAP path and enumerates available OUs via ADSI. Useful for populating `settings.json`. |

## License

See [LICENSE](LICENSE) for details.

