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
```

## Configuration

Edit `settings.json` (created automatically on first run) or use the built-in Settings dialog:

| Setting | Description | Default |
|---------|-------------|---------|
| `DomainLdapPath` | LDAP path to domain root | *(auto-detect)* |
| `OuFilter` | OU scope for computer search | *(all)* |
| `CentralSharePath` | UNC path to module repository | *(empty)* |
| `MaxConcurrency` | Parallel runspace threads | `4` |
| `CredentialMode` | `Default` / `Prompt` / `Stored` | `Default` |
| `LogPath` | Directory for log files | `logs/` |
| `LogLevel` | `DEBUG` / `INFO` / `WARN` / `ERROR` | `INFO` |
| `RetryCount` | Retry attempts for failed operations | `2` |
| `ReachabilityCheck` | Test WinRM before operations | `true` |
| `JobTimeoutSeconds` | Per-job timeout for remote operations | `300` |

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
+-- PS-ModuleManager.psd1   # Module manifest
+-- PS-ModuleManager.psm1   # Single comprehensive module (all code + inline WPF XAML)
+-- settings.json            # Configuration file (auto-created on first run)
+-- docs/
|   +-- PLAN.md              # Detailed project plan & architecture
+-- README.md
+-- LICENSE
```

## Exported Command

| Command | Description |
|---------|-------------|
| `Show-ModuleManagerGUI` | Opens the WPF Module Manager window. Accepts optional `-SettingsPath` parameter. |

## License

See [LICENSE](LICENSE) for details.

