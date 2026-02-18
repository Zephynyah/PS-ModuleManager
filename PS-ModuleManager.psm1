<#
.SYNOPSIS
    PS-ModuleManager -- A WPF-based PowerShell Module Manager.

.DESCRIPTION
    Provides a rich graphical interface to discover domain-joined computers via ADSI,
    inventory installed PowerShell modules, and install / update / remove modules from
    a central network share.  All WPF XAML is defined inline -- no external files needed.

    Key capabilities:
      * ADSI computer discovery with OU filtering and wildcard search
      * Parallel remote module inventory via runspace pool
      * Install / Update / Remove modules from a central ZIP-based share
      * Version comparison with color-coded status (Green / Orange / Red / Gray)
      * Persistent settings (settings.json) with built-in validation
      * Structured logging to file and scrollable UI pane

.NOTES
    Requires: Windows PowerShell 5.1+, .NET Framework 4.5+ (WPF)
    Remoting:  WinRM must be enabled on target computers.
    Author:    PS-ModuleManager Contributors
    Version:   1.0.0
#>

#requires -Version 5.1

#region Assembly Loading
# ─────────────────────────────────────────────────────────────────────────────
# Load WPF assemblies.  PresentationFramework is typically auto-loaded but we
# make it explicit for clarity and to ensure availability in all hosts.
# ─────────────────────────────────────────────────────────────────────────────
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms   # for FolderBrowserDialog fallback

# ── Define WPF-friendly data classes with INotifyPropertyChanged ──────────────
if (-not ([System.Management.Automation.PSTypeName]'ComputerItem').Type) {
    Add-Type -TypeDefinition @"
using System.ComponentModel;
using System.Runtime.CompilerServices;

/// <summary>Data item for the Computer list (left panel) with checkbox + status.</summary>
public class ComputerItem : INotifyPropertyChanged {
    private bool   _isSelected;
    private string _name;
    private string _connectionStatus;   // "Local" | "WinRM" | "Unreachable"

    public bool IsSelected {
        get { return _isSelected; }
        set { _isSelected = value; OnPropertyChanged(); }
    }
    public string Name {
        get { return _name; }
        set { _name = value; OnPropertyChanged(); }
    }
    public string ConnectionStatus {
        get { return _connectionStatus; }
        set { _connectionStatus = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string name = null) {
        var handler = PropertyChanged;
        if (handler != null) handler(this, new PropertyChangedEventArgs(name));
    }
}
"@
}

if (-not ([System.Management.Automation.PSTypeName]'ModuleGridItem').Type) {
    Add-Type -TypeDefinition @"
using System.ComponentModel;
using System.Runtime.CompilerServices;

/// <summary>Data item for the Module Inventory grid (center panel).</summary>
public class ModuleGridItem : INotifyPropertyChanged {
    private string _computerName;
    private string _moduleName;
    private string _installedVersion;
    private string _targetVersion;
    private string _status;
    private string _model;
    private string _os;
    private string _psModulePath;

    public string ComputerName {
        get { return _computerName; }
        set { _computerName = value; OnPropertyChanged(); }
    }
    public string ModuleName {
        get { return _moduleName; }
        set { _moduleName = value; OnPropertyChanged(); }
    }
    public string InstalledVersion {
        get { return _installedVersion; }
        set { _installedVersion = value; OnPropertyChanged(); }
    }
    public string TargetVersion {
        get { return _targetVersion; }
        set { _targetVersion = value; OnPropertyChanged(); }
    }
    public string Status {
        get { return _status; }
        set { _status = value; OnPropertyChanged(); }
    }
    public string Model {
        get { return _model; }
        set { _model = value; OnPropertyChanged(); }
    }
    public string OS {
        get { return _os; }
        set { _os = value; OnPropertyChanged(); }
    }
    public string PSModulePath {
        get { return _psModulePath; }
        set { _psModulePath = value; OnPropertyChanged(); }
    }

    public event PropertyChangedEventHandler PropertyChanged;
    protected void OnPropertyChanged([CallerMemberName] string name = null) {
        var handler = PropertyChanged;
        if (handler != null) handler(this, new PropertyChangedEventArgs(name));
    }
}
"@
}
#endregion Assembly Loading




#region Script-Scoped State
# ─────────────────────────────────────────────────────────────────────────────
# Module-wide variables shared across functions.  Prefixed with $script: to
# keep them private to the module and avoid polluting the caller's scope.
# ─────────────────────────────────────────────────────────────────────────────

# Default settings path -- next to the module file
$script:ModuleRoot = $PSScriptRoot
$script:SettingsPath = Join-Path $script:ModuleRoot 'settings.json'

# Runtime state
$script:Settings = $null   # [hashtable]  loaded from settings.json
$script:RunspacePool = $null   # [RunspacePool]
$script:Jobs = [System.Collections.ArrayList]::new()   # active async jobs
$script:LogEntries = [System.Collections.ArrayList]::new()   # in-memory log buffer
$script:Credential = $null   # [PSCredential] when using Prompt/Stored mode
$script:MainWindow = $null   # WPF Window reference
$script:ComputerList = [System.Collections.ObjectModel.ObservableCollection[ComputerItem]]::new()
$script:ModuleGrid = [System.Collections.ObjectModel.ObservableCollection[ModuleGridItem]]::new()
$script:JobQueue = [System.Collections.ObjectModel.ObservableCollection[PSObject]]::new()
$script:JobPollerTimer = $null   # active DispatcherTimer for job polling
$script:CurrentPollerOperation = $null   # current poller operation label (Inventory/Install/Update/Remove)
#endregion Script-Scoped State

#region Configuration
# ─────────────────────────────────────────────────────────────────────────────
# Functions to load, save, validate, and provide defaults for settings.json.
# ─────────────────────────────────────────────────────────────────────────────

function Get-PSMMDefaultSettings {
    <#
    .SYNOPSIS
        Returns a hashtable with all default settings.
    .DESCRIPTION
        Provides sensible defaults so the application can start even without
        an existing settings.json.  Every key used elsewhere in the module
        must be represented here.
    .OUTPUTS
        [hashtable]
    #>
    return @{
        DomainLdapPath    = ''                          # e.g. 'LDAP://DC=corp,DC=local'
        OuFilter          = ''                          # e.g. 'OU=Servers,DC=corp,DC=local'
        ModuleSearchPaths = @('C:\Program Files\WindowsPowerShell\Modules')
        CentralSharePath  = ''                          # e.g. '\\fileserver\PSModules'
        MaxConcurrency    = [Math]::Min(4, [Environment]::ProcessorCount)
        CredentialMode    = 'Default'                   # Default | Prompt | Stored
        LogPath           = Join-Path $script:ModuleRoot 'logs'
        LogLevel          = 'INFO'                      # DEBUG | INFO | WARN | ERROR
        RetryCount        = 2
        ReachabilityCheck = $true
        JobTimeoutSeconds = 300
        ExcludeServers    = $false
        ExcludeVirtual    = $false
        OSFilter          = ''                          # e.g. '*Windows 10*' or '*Server 2019*' - wildcards supported
        GlobalExcludeList = @()                         # e.g. @('Server1','it*','test-*') - wildcards supported, may be $null in PS 5.1
    }
}

function Import-PSMMSettings {
    <#
    .SYNOPSIS
        Loads settings from the JSON file, merging with defaults.
    .PARAMETER Path
        Full path to the settings.json file.  Falls back to the module-root copy.
    .OUTPUTS
        [hashtable] -- the merged settings object.
    #>
    [CmdletBinding()]
    param(
        [string]$Path = $script:SettingsPath
    )

    $defaults = Get-PSMMDefaultSettings

    if (Test-Path -LiteralPath $Path) {
        try {
            $json = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
            # Merge: JSON values override defaults
            foreach ($key in @($defaults.Keys)) {
                if ($null -ne $json.$key) {
                    $defaults[$key] = $json.$key
                }
            }
            Write-PSMMLog -Severity 'INFO' -Message "Settings loaded from $Path"
        }
        catch {
            Write-PSMMLog -Severity 'ERROR' -Message "Failed to parse settings file: $_"
        }
    }
    else {
        Write-PSMMLog -Severity 'WARN' -Message "Settings file not found at $Path -- using defaults."
        # Create default file for the user
        Export-PSMMSettings -Settings $defaults -Path $Path
    }

    $script:Settings = $defaults
    return $defaults
}

function Export-PSMMSettings {
    <#
    .SYNOPSIS
        Persists the settings hashtable to a JSON file.
    .PARAMETER Settings
        The settings hashtable to save.
    .PARAMETER Path
        Destination file path.
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Settings,
        [string]$Path = $script:SettingsPath
    )

    try {
        $dir = Split-Path $Path -Parent
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        $Settings | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $Path -Encoding UTF8 -Force
        Write-PSMMLog -Severity 'INFO' -Message "Settings saved to $Path"
    }
    catch {
        Write-PSMMLog -Severity 'ERROR' -Message "Failed to save settings: $_"
    }
}

function Test-PSMMSettings {
    <#
    .SYNOPSIS
        Validates the current settings and returns a list of issues.
    .OUTPUTS
        [string[]] -- array of validation error messages (empty = valid).
    #>
    [CmdletBinding()]
    param(
        [hashtable]$Settings = $script:Settings
    )

    $issues = @()

    if ($Settings.MaxConcurrency -lt 1 -or $Settings.MaxConcurrency -gt 64) {
        $issues += "MaxConcurrency must be between 1 and 64."
    }

    if ($Settings.CentralSharePath -and -not (Test-Path -LiteralPath $Settings.CentralSharePath -ErrorAction SilentlyContinue)) {
        $issues += "CentralSharePath '$($Settings.CentralSharePath)' is not accessible."
    }

    if ($Settings.CredentialMode -notin @('Default', 'Prompt', 'Stored')) {
        $issues += "CredentialMode must be Default, Prompt, or Stored."
    }

    if ($Settings.RetryCount -lt 0 -or $Settings.RetryCount -gt 10) {
        $issues += "RetryCount must be between 0 and 10."
    }

    if ($Settings.LogLevel -notin @('DEBUG', 'INFO', 'WARN', 'ERROR')) {
        $issues += "LogLevel must be DEBUG, INFO, WARN, or ERROR."
    }

    return $issues
}
#endregion Configuration

#region Logging
# ─────────────────────────────────────────────────────────────────────────────
# Structured logging to file and (optionally) the WPF log pane.
# ─────────────────────────────────────────────────────────────────────────────

function Write-PSMMLog {
    <#
    .SYNOPSIS
        Writes a structured log entry to file and the UI log pane.
    .PARAMETER Severity
        Log level: DEBUG, INFO, WARN, or ERROR.
    .PARAMETER Message
        The log message text.
    .PARAMETER ComputerName
        Optional target computer associated with the entry.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Severity = 'INFO',

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$ComputerName = ''
    )

    # Determine configured minimum severity
    $levelMap = @{ 'DEBUG' = 0; 'INFO' = 1; 'WARN' = 2; 'ERROR' = 3 }
    $configuredLevel = if ($script:Settings.LogLevel) { $script:Settings.LogLevel } else { 'INFO' }
    $minLevel = $levelMap[$configuredLevel]
    $thisLevel = $levelMap[$Severity]

    if ($thisLevel -lt $minLevel) { return }

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $prefix = if ($ComputerName) { "[$Severity] $timestamp [$ComputerName]" } else { "[$Severity] $timestamp" }
    $line = "$prefix -- $Message"

    # In-memory buffer
    $null = $script:LogEntries.Add([PSCustomObject]@{
            Timestamp    = $timestamp
            Severity     = $Severity
            ComputerName = $ComputerName
            Message      = $Message
            FullLine     = $line
        })

    # File output
    try {
        $logDir = if ($script:Settings.LogPath) { $script:Settings.LogPath } else { Join-Path $script:ModuleRoot 'logs' }
        if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
        $logFile = Join-Path $logDir ("PS-ModuleManager_{0}.log" -f (Get-Date -Format 'yyyy-MM-dd'))
        Add-Content -LiteralPath $logFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    }
    catch { <# silently ignore file logging failures #> }

    # WPF pane update (dispatcher-safe)
    if ($script:MainWindow -and $script:MainWindow.Dispatcher) {
        try {
            $script:MainWindow.Dispatcher.Invoke([Action] {
                    $logBox = $script:MainWindow.FindName('LogListBox')
                    if ($logBox) {
                        $logBox.Items.Add($line)
                        $logBox.ScrollIntoView($logBox.Items[$logBox.Items.Count - 1])
                    }

                    # Also update status bar
                    $statusText = $script:MainWindow.FindName('StatusText')
                    if ($statusText) { $statusText.Text = $Message }
                }, [System.Windows.Threading.DispatcherPriority]::Background)
        }
        catch { <# dispatcher may not be ready yet #> }
    }
}

function Invoke-PSMMLogRotation {
    <#
    .SYNOPSIS
        Removes log files older than the specified retention period.
    .DESCRIPTION
        Scans the configured log directory for PS-ModuleManager_*.log files
        and deletes any older than RetentionDays (default 30).  Also enforces
        a maximum total log directory size (default 10 MB).
    .PARAMETER LogPath
        Path to the log directory.  If not specified, uses $script:Settings.LogPath.
    .PARAMETER RetentionDays
        Number of days to retain log files.  Files older than this are deleted.
    .PARAMETER MaxTotalSizeMB
        Maximum total size (in MB) of all log files.  Oldest files are removed
        first until the total is under the limit.
    #>
    [CmdletBinding()]
    param(
        [string]$LogPath,
        [int]$RetentionDays = 30,
        [int]$MaxTotalSizeMB = 10
    )

    $logDir = if ($LogPath) { $LogPath } elseif ($script:Settings.LogPath) { $script:Settings.LogPath } else { Join-Path $script:ModuleRoot 'logs' }
    if (-not (Test-Path -LiteralPath $logDir)) { return }

    $logFiles = Get-ChildItem -LiteralPath $logDir -Filter 'PS-ModuleManager_*.log' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime

    if (-not $logFiles -or $logFiles.Count -eq 0) { return }

    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    $removed = 0

    # Remove files older than retention period
    foreach ($f in $logFiles) {
        if ($f.LastWriteTime -lt $cutoff) {
            try {
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                $removed++
            }
            catch { <# ignore individual file deletion failures #> }
        }
    }

    # Re-enumerate after age-based cleanup
    $logFiles = Get-ChildItem -LiteralPath $logDir -Filter 'PS-ModuleManager_*.log' -File -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime

    # Enforce size limit (remove oldest first)
    if ($logFiles) {
        $totalBytes = ($logFiles | Measure-Object -Property Length -Sum).Sum
        $maxBytes = $MaxTotalSizeMB * 1MB
        $idx = 0
        while ($totalBytes -gt $maxBytes -and $idx -lt $logFiles.Count) {
            try {
                $totalBytes -= $logFiles[$idx].Length
                Remove-Item -LiteralPath $logFiles[$idx].FullName -Force -ErrorAction Stop
                $removed++
            }
            catch { <# ignore #> }
            $idx++
        }
    }

    if ($removed -gt 0) {
        Write-PSMMLog -Severity 'INFO' -Message "Log rotation: removed $removed old log file(s)."
    }
}
#endregion Logging

#region ADSI Service
# ─────────────────────────────────────────────────────────────────────────────
# Active Directory computer discovery using raw ADSI / DirectorySearcher.
# No RSAT or ActiveDirectory module required.
# ─────────────────────────────────────────────────────────────────────────────

function ConvertTo-PSMMLdapSafeString {
    <#
    .SYNOPSIS
        Escapes LDAP special characters in user-provided filter strings.
    .DESCRIPTION
        Sanitizes input to prevent LDAP injection by escaping RFC 4515 special
        characters: backslash, parentheses, NUL, and optionally asterisk.
        Wildcard asterisks used for LDAP name filters are preserved by default.
    .PARAMETER InputString
        The raw user input to sanitize.
    .PARAMETER EscapeWildcard
        If $true, also escapes the asterisk character. Default is $false to
        allow LDAP wildcard searches like '*web*'.
    .OUTPUTS
        [string] -- the escaped string safe for LDAP filter insertion.
    #>
    [CmdletBinding()]
    param(
        [string]$InputString,
        [bool]$EscapeWildcard = $false
    )

    if ([string]::IsNullOrEmpty($InputString)) { return $InputString }

    # Order matters: escape backslash first to avoid double-escaping
    $result = $InputString -replace '\\', '\5c'
    $result = $result -replace '\(', '\28'
    $result = $result -replace '\)', '\29'
    $result = $result -replace [char]0, '\00'

    if ($EscapeWildcard) {
        $result = $result -replace '\*', '\2a'
    }

    return $result
}

function Get-PSMMComputers {
    <#
    .SYNOPSIS
        Queries Active Directory for computer objects via ADSI.
    .DESCRIPTION
        Uses System.DirectoryServices.DirectorySearcher to find computer objects.
        Supports OU scoping, name wildcard filter, and enabled-only toggle.
    .PARAMETER LdapPath
        The LDAP path to search from. e.g. 'LDAP://OU=Servers,DC=corp,DC=local'
    .PARAMETER NameFilter
        Wildcard filter for computer names (e.g. 'WEB*').  Default: '*' (all).
    .PARAMETER EnabledOnly
        If $true, only returns enabled computer accounts.
    .PARAMETER TestReachability
        If $true, tests WinRM reachability on each discovered computer.
    .OUTPUTS
        [PSCustomObject[]] -- ComputerInfo objects.
    #>
    [CmdletBinding()]
    param(
        [string]$LdapPath = $script:Settings.DomainLdapPath,
        [string]$NameFilter = '*',
        [bool]$EnabledOnly = $true,
        [bool]$TestReachability = $script:Settings.ReachabilityCheck,

        [bool]$ExcludeServers = $script:Settings.ExcludeServers,

        [bool]$ExcludeVirtual = $script:Settings.ExcludeVirtual,

        [string]$OSFilter = $script:Settings.OSFilter
    )

    Write-PSMMLog -Severity 'INFO' -Message "Querying AD for computers (filter: $NameFilter) ..."

    $computers = [System.Collections.ArrayList]::new()

    try {
        # Build the ADSI searcher
        if ($LdapPath) {
            $root = [ADSI]$LdapPath
        }
        else {
            # Default: current domain root
            $root = [ADSI]''
        }

        $searcher = [System.DirectoryServices.DirectorySearcher]::new($root)
        $searcher.PageSize = 1000

        # Sanitize user-provided name filter to prevent LDAP injection
        $safeNameFilter = ConvertTo-PSMMLdapSafeString -InputString $NameFilter
        # LDAP filter
        $nameClause = "(cn=$safeNameFilter)"
        if ($EnabledOnly) {
            # userAccountControl bit 2 = ACCOUNTDISABLE
            $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)$nameClause(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }
        else {
            $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)$nameClause)"
        }

        $searcher.PropertiesToLoad.AddRange(@('cn', 'dnshostname', 'distinguishedname', 'operatingsystem', 'useraccountcontrol'))

        $results = $searcher.FindAll()
        Write-PSMMLog -Severity 'INFO' -Message "Found $($results.Count) computer(s) in AD."

        # Pre-build GlobalExcludeList for fast lookup inside the loop
        $excludeList = $script:Settings.GlobalExcludeList
        $hasExcludeList = $excludeList -and $excludeList.Count -gt 0
        $excludedCount = 0

        foreach ($entry in $results) {
            $props = $entry.Properties
            $name = ($props['cn']  | Select-Object -First 1) -as [string]
            $dns = ($props['dnshostname'] | Select-Object -First 1) -as [string]
            $dn = ($props['distinguishedname'] | Select-Object -First 1) -as [string]
            $os = ($props['operatingsystem'] | Select-Object -First 1) -as [string]
            $uac = ($props['useraccountcontrol'] | Select-Object -First 1) -as [int]

            # Skip GlobalExcludeList entries immediately (before reachability check)
            # Supports wildcards (e.g. "it*", "*vdi*") and exact names
            if ($hasExcludeList) {
                $excluded = $false
                foreach ($pattern in $excludeList) {
                    if ($name -like $pattern) { $excluded = $true; break }
                }
                if ($excluded) {
                    $excludedCount++
                    continue
                }
            }

            # Derive OU from DN
            $ou = if ($dn) {
                ($dn -split ',', 2)[1]
            }
            else { '' }

            $enabled = -not ($uac -band 2)

            # Optionally test reachability
            $reachable = $null
            if ($TestReachability -and $dns) {
                try {
                    $null = Test-WSMan -ComputerName $dns -ErrorAction Stop
                    $reachable = $true
                }
                catch {
                    $reachable = $false
                    Write-PSMMLog -Severity 'WARN' -Message "Computer $name ($dns) is unreachable." -ComputerName $name
                }
            }

            $null = $computers.Add([PSCustomObject]@{
                    Name        = $name
                    DNSHostName = $dns
                    OU          = $ou
                    Enabled     = $enabled
                    OS          = $os
                    Reachable   = $reachable
                })
        }

        if ($excludedCount -gt 0) {
            Write-PSMMLog -Severity 'INFO' -Message "Excluded $excludedCount computer(s) via GlobalExcludeList."
        }

        $results.Dispose()
        $searcher.Dispose()
    }
    catch {
        Write-PSMMLog -Severity 'WARN' -Message "AD query failed: $_  -- falling back to local computer."

        # Fallback: add the local computer so the tool remains usable off-domain
        $localName = $env:COMPUTERNAME
        $localDns  = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $localName }
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $localOS   = $ComputerSystem.Caption
        $localModel = $ComputerSystem.Model

        $reachable = $null
        if ($TestReachability) {
            try {
                $null = Test-WSMan -ComputerName $localDns -ErrorAction Stop
                $reachable = $true
            }
            catch { $reachable = $false }
        }

        $null = $computers.Add([PSCustomObject]@{
                Name        = $localName
                DNSHostName = $localDns
                OU          = ''
                Enabled     = $true
                OS          = $localOS
                Model       = $localModel
                Reachable   = $reachable
            })

        Write-PSMMLog -Severity 'INFO' -Message "Added local computer '$localName' as fallback."
    }

    # ── Post-filter: exclude servers and virtual devices ─────────────────
    $filtered = $computers.ToArray()

    if ($ExcludeServers) {
        $before = $filtered.Count
        $filtered = @($filtered | Where-Object { $_.OS -notmatch 'Server' })
        $skipped = $before - $filtered.Count
        if ($skipped -gt 0) { Write-PSMMLog -Severity 'INFO' -Message "Excluded $skipped server(s) from results." }
    }

    if ($ExcludeVirtual) {
        $before = $filtered.Count
        $filtered = @($filtered | Where-Object { $_.Name -notmatch 'VM-|YOURVM' -and $_.OS -notmatch 'Virtual' -and $_.OU -notmatch 'Virtual' })
        $skipped = $before - $filtered.Count
        if ($skipped -gt 0) { Write-PSMMLog -Severity 'INFO' -Message "Excluded $skipped virtual device(s) from results." }
    }

    # OS Filter -- include only computers whose OS matches the pattern
    if ($OSFilter -and $OSFilter -ne '') {
        $before = $filtered.Count
        $filtered = @($filtered | Where-Object { $_.OS -like $OSFilter })
        $kept = $filtered.Count
        $skipped = $before - $kept
        if ($skipped -gt 0) { Write-PSMMLog -Severity 'INFO' -Message "Filtered to $kept computer(s) matching OS pattern '$OSFilter' ($skipped excluded)." }
    }

    # GlobalExcludeList -- skip computers matching these patterns (supports wildcards)
    # $excludeList = $script:Settings.GlobalExcludeList
    # if ($excludeList -and $excludeList.Count -gt 0) {
    #     $before = $filtered.Count
    #     $filtered = @($filtered | Where-Object {
    #         $computerName = $_.Name
    #         $shouldExclude = $false
    #         foreach ($pattern in $excludeList) {
    #             if ($computerName -like $pattern) {
    #                 $shouldExclude = $true
    #                 break
    #             }
    #         }
    #         -not $shouldExclude
    #     })
    #     $skipped = $before - $filtered.Count
    #     if ($skipped -gt 0) { Write-PSMMLog -Severity 'INFO' -Message "Excluded $skipped computer(s) via GlobalExcludeList." }
    # }

    return $filtered
}
#endregion ADSI Service

#region Runspace Pool
# ─────────────────────────────────────────────────────────────────────────────
# Shared runspace pool for parallel remote operations.
# ─────────────────────────────────────────────────────────────────────────────

function New-PSMMRunspacePool {
    <#
    .SYNOPSIS
        Creates and opens a runspace pool with the configured concurrency.
    .PARAMETER MaxRunspaces
        Maximum number of concurrent runspaces.  Defaults to settings value.
    .OUTPUTS
        [System.Management.Automation.Runspaces.RunspacePool]
    #>
    [CmdletBinding()]
    param(
        [int]$MaxRunspaces = $(if ($script:Settings.MaxConcurrency) { $script:Settings.MaxConcurrency } else { 4 })
    )

    Write-PSMMLog -Severity 'INFO' -Message "Creating runspace pool (max $MaxRunspaces) ..."

    $iss = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $pool = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxRunspaces, $iss, [System.Management.Automation.Host.PSHost]$Host)
    $pool.ApartmentState = [System.Threading.ApartmentState]::STA
    $pool.Open()

    $script:RunspacePool = $pool
    Write-PSMMLog -Severity 'INFO' -Message "Runspace pool opened."
    return $pool
}

function Invoke-PSMMParallel {
    <#
    .SYNOPSIS
        Submits a script block to the runspace pool for a list of computers.
    .DESCRIPTION
        Queues one PowerShell instance per computer and returns job tracking
        objects that can be polled for completion.
    .PARAMETER ComputerNames
        Array of computer DNS names or NetBIOS names to target.
    .PARAMETER ScriptBlock
        The script to execute remotely.  Receives $ComputerName as argument.
    .PARAMETER ArgumentList
        Additional arguments passed to the script block.
    .OUTPUTS
        [PSCustomObject[]] -- Job descriptors with Handle, PowerShell, ComputerName.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [object[]]$ArgumentList = @()
    )

    if (-not $script:RunspacePool -or $script:RunspacePool.RunspacePoolStateInfo.State -ne 'Opened') {
        New-PSMMRunspacePool
    }

    $jobs = [System.Collections.ArrayList]::new()

    foreach ($computer in $ComputerNames) {
        $ps = [PowerShell]::Create()
        $ps.RunspacePool = $script:RunspacePool

        $null = $ps.AddScript($ScriptBlock.ToString())
        $null = $ps.AddArgument($computer)
        foreach ($arg in $ArgumentList) {
            $null = $ps.AddArgument($arg)
        }

        $handle = $ps.BeginInvoke()

        $job = [PSCustomObject]@{
            Id           = [Guid]::NewGuid().ToString('N').Substring(0, 8)
            ComputerName = $computer
            PowerShell   = $ps
            Handle       = $handle
            Status       = 'Running'
            Result       = $null
            Error        = $null
            StartTime    = Get-Date
        }

        $null = $jobs.Add($job)
        $null = $script:Jobs.Add($job)

        Write-PSMMLog -Severity 'DEBUG' -Message "Job $($job.Id) queued for $computer" -ComputerName $computer
    }

    return $jobs.ToArray()
}

function Receive-PSMMJobs {
    <#
    .SYNOPSIS
        Polls all active jobs and collects completed results.
    .DESCRIPTION
        Iterates over $script:Jobs, checks IsCompleted, and harvests results.
        Completed jobs are marked and their PowerShell instances disposed.
    .OUTPUTS
        [PSCustomObject[]] -- completed job objects with results populated.
    #>
    [CmdletBinding()]
    param()

    $completed = @()

    foreach ($job in $script:Jobs) {
        if ($job.Status -ne 'Running') { continue }

        # Check timeout
        $elapsed = (Get-Date) - $job.StartTime
        $timeout = if ($script:Settings.JobTimeoutSeconds) { $script:Settings.JobTimeoutSeconds } else { 300 }
        if ($elapsed.TotalSeconds -gt $timeout) {
            try { $job.PowerShell.Stop() } catch {}
            $job.Status = 'Failed'
            $job.Error = "Timed out after $timeout seconds."
            Write-PSMMLog -Severity 'ERROR' -Message "Job $($job.Id) timed out." -ComputerName $job.ComputerName
            $completed += $job
            continue
        }

        if ($job.Handle.IsCompleted) {
            try {
                $job.Result = $job.PowerShell.EndInvoke($job.Handle)
                if ($job.PowerShell.HadErrors) {
                    $errMsg = ($job.PowerShell.Streams.Error | ForEach-Object { $_.ToString() }) -join '; '
                    if (-not $errMsg) {
                        $errMsg = ($job.PowerShell.Streams.Warning | ForEach-Object { $_.ToString() }) -join '; '
                    }
                    if (-not $errMsg -and $job.Result) {
                        # Check if the result contains an _ERROR_ marker from the inventory script
                        $errorResult = $job.Result | Where-Object { $_.ModuleName -eq '_ERROR_' } | Select-Object -First 1
                        if ($errorResult) { $errMsg = $errorResult.ModuleBase }
                    }
                    if (-not $errMsg) { $errMsg = 'Unknown error (no details captured).' }
                    $job.Error  = $errMsg
                    $job.Status = 'Failed'
                    Write-PSMMLog -Severity 'ERROR' -Message "Job $($job.Id) failed: $($job.Error)" -ComputerName $job.ComputerName
                }
                else {
                    $job.Status = 'Completed'
                    Write-PSMMLog -Severity 'INFO' -Message "Job $($job.Id) completed successfully." -ComputerName $job.ComputerName
                }
            }
            catch {
                $job.Status = 'Failed'
                $job.Error = $_.ToString()
                Write-PSMMLog -Severity 'ERROR' -Message "Job $($job.Id) exception: $_" -ComputerName $job.ComputerName
            }
            finally {
                $job.PowerShell.Dispose()
            }

            $completed += $job
        }
    }

    return $completed
}

function Stop-PSMMAllJobs {
    <#
    .SYNOPSIS
        Cancels all running jobs and disposes resources.
    #>
    [CmdletBinding()]
    param()

    foreach ($job in $script:Jobs) {
        if ($job.Status -eq 'Running') {
            try {
                $job.PowerShell.Stop()
                $job.PowerShell.Dispose()
                $job.Status = 'Cancelled'
                Write-PSMMLog -Severity 'WARN' -Message "Job $($job.Id) cancelled." -ComputerName $job.ComputerName
            }
            catch {
                Write-PSMMLog -Severity 'ERROR' -Message "Error cancelling job $($job.Id): $_"
            }
        }
    }
}

function Close-PSMMRunspacePool {
    <#
    .SYNOPSIS
        Closes and disposes the runspace pool.
    #>
    [CmdletBinding()]
    param()

    if ($script:RunspacePool) {
        try {
            Stop-PSMMAllJobs
            $script:RunspacePool.Close()
            $script:RunspacePool.Dispose()
            $script:RunspacePool = $null
            Write-PSMMLog -Severity 'INFO' -Message 'Runspace pool closed.'
        }
        catch {
            Write-PSMMLog -Severity 'ERROR' -Message "Error closing runspace pool: $_"
        }
    }
}
#endregion Runspace Pool

#region Module Inventory
# ─────────────────────────────────────────────────────────────────────────────
# Query installed modules locally or remotely and compare against central share.
# ─────────────────────────────────────────────────────────────────────────────

function Get-PSMMRemoteModules {
    <#
    .SYNOPSIS
        Retrieves installed PowerShell modules from one or more remote computers.
    .DESCRIPTION
        Uses Invoke-Command (via the runspace pool) to run Get-Module -ListAvailable
        on each target.  When ModuleName is specified, only that module is queried;
        otherwise all modules are returned.
    .PARAMETER ComputerNames
        Array of computer names to query.
    .PARAMETER ModuleName
        Optional module name to filter on.  If specified, only that module is inventoried.
    .PARAMETER Credential
        Optional PSCredential for remoting.
    .OUTPUTS
        [PSCustomObject[]] -- ModuleInfo objects.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerNames,

        [string]$ModuleName,

        [PSCredential]$Credential = $script:Credential
    )

    if ($ModuleName) {
        Write-PSMMLog -Severity 'INFO' -Message "Inventorying module '$ModuleName' on $($ComputerNames.Count) computer(s) ..."
    } else {
        Write-PSMMLog -Severity 'INFO' -Message "Inventorying all modules on $($ComputerNames.Count) computer(s) ..."
    }

    $inventoryScript = {
        param($Computer, $Cred, $ModFilter)
        try {
            if ($ModFilter) {
                $sb = [scriptblock]::Create("Get-Module -ListAvailable -Name '$ModFilter' | Select-Object Name, @{N = 'Version'; E = { `$_.Version.ToString() } }, ModuleBase")
            } else {
                $sb = { Get-Module -ListAvailable | Select-Object Name, @{N = 'Version'; E = { $_.Version.ToString() } }, ModuleBase }
            }

            # Gather Model and OS info
            $sysInfoSb = {
                $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
                $os = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue
                [PSCustomObject]@{
                    Model = if ($cs) { $cs.Model } else { '' }
                    OS    = if ($os) { $os.Caption } else { '' }
                }
            }

            $isLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')
            if ($isLocal) {
                # Run locally -- no WinRM needed
                $modules  = & $sb
                $sysInfo  = & $sysInfoSb
            } else {
                $splat = @{ ComputerName = $Computer; ScriptBlock = $sb }
                if ($Cred) { $splat['Credential'] = $Cred }
                $modules = Invoke-Command @splat -ErrorAction Stop

                $splatSys = @{ ComputerName = $Computer; ScriptBlock = $sysInfoSb }
                if ($Cred) { $splatSys['Credential'] = $Cred }
                $sysInfo = Invoke-Command @splatSys -ErrorAction SilentlyContinue
            }

            $model = if ($sysInfo) { $sysInfo.Model } else { '' }
            $osCaption = if ($sysInfo) { $sysInfo.OS } else { '' }

            if ($ModFilter -and -not $modules) {
                # Module not found on remote computer -- return explicit 'Not Installed' entry
                [PSCustomObject]@{
                    ComputerName     = $Computer
                    ModuleName       = $ModFilter
                    InstalledVersion = ''
                    ModuleBase       = ''
                    Model            = $model
                    OS               = $osCaption
                }
            } else {
                foreach ($m in $modules) {
                    [PSCustomObject]@{
                        ComputerName     = $Computer
                        ModuleName       = $m.Name
                        InstalledVersion = $m.Version
                        ModuleBase       = $m.ModuleBase
                        Model            = $model
                        OS               = $osCaption
                    }
                }
            }
        }
        catch {
            [PSCustomObject]@{
                ComputerName     = $Computer
                ModuleName       = '_ERROR_'
                InstalledVersion = ''
                ModuleBase       = $_.ToString()
                Model            = ''
                OS               = ''
            }
        }
    }

    $jobs = Invoke-PSMMParallel -ComputerNames $ComputerNames -ScriptBlock $inventoryScript -ArgumentList @($Credential, $ModuleName)
    return $jobs
}

function Get-PSMMShareModules {
    <#
    .SYNOPSIS
        Lists modules and versions available on the central network share.
    .DESCRIPTION
        Expects share structure: <CentralSharePath>\<ModuleName>\<Version>\
        Each version folder should contain the module files (or a ZIP).
    .OUTPUTS
        [PSCustomObject[]] -- objects with ModuleName, Version, Path.
    #>
    [CmdletBinding()]
    param(
        [string]$SharePath = $script:Settings.CentralSharePath
    )

    $modules = [System.Collections.ArrayList]::new()

    if (-not $SharePath -or -not (Test-Path -LiteralPath $SharePath)) {
        Write-PSMMLog -Severity 'WARN' -Message "Central share path not configured or inaccessible: $SharePath"
        return @()
    }

    try {
        foreach ($modDir in (Get-ChildItem -LiteralPath $SharePath -Directory -ErrorAction Stop)) {
            foreach ($verDir in (Get-ChildItem -LiteralPath $modDir.FullName -Directory -ErrorAction SilentlyContinue)) {
                $null = $modules.Add([PSCustomObject]@{
                        ModuleName = $modDir.Name
                        Version    = $verDir.Name
                        Path       = $verDir.FullName
                    })
            }
        }
        Write-PSMMLog -Severity 'INFO' -Message "Found $($modules.Count) module version(s) on share."
    }
    catch {
        Write-PSMMLog -Severity 'ERROR' -Message "Error reading central share: $_"
    }

    return $modules.ToArray()
}

function Compare-PSMMModuleVersions {
    <#
    .SYNOPSIS
        Compares installed module versions against the latest available on the share.
    .PARAMETER InstalledModules
        Array of ModuleInfo objects from Get-PSMMRemoteModules.
    .PARAMETER ShareModules
        Array of share module objects from Get-PSMMShareModules.
    .OUTPUTS
        [PSCustomObject[]] -- enriched ModuleInfo objects with Status and TargetVersion.
    #>
    [CmdletBinding()]
    param(
        [PSCustomObject[]]$InstalledModules,
        [PSCustomObject[]]$ShareModules
    )

    # Build lookup: module name -> latest version on share
    $latestOnShare = @{}
    foreach ($sm in $ShareModules) {
        try {
            $ver = [Version]$sm.Version
            if (-not $latestOnShare.ContainsKey($sm.ModuleName) -or $ver -gt [Version]$latestOnShare[$sm.ModuleName]) {
                $latestOnShare[$sm.ModuleName] = $sm.Version
            }
        }
        catch {
            # Non-parseable version string -- skip
        }
    }

    $results = foreach ($mod in $InstalledModules) {
        $target = $latestOnShare[$mod.ModuleName]
        $status = if ($mod.ModuleName -eq '_ERROR_') {
            'Error'
        }
        elseif (-not $target) {
            'Unknown'
        }
        elseif (-not $mod.InstalledVersion) {
            'Missing'
        }
        else {
            try {
                $cmp = [Version]$mod.InstalledVersion
                $tgt = [Version]$target
                if ($cmp -ge $tgt) { 'UpToDate' } else { 'Outdated' }
            }
            catch { 'Unknown' }
        }

        [ModuleGridItem]@{
            ComputerName     = $mod.ComputerName
            ModuleName       = $mod.ModuleName
            InstalledVersion = $mod.InstalledVersion
            TargetVersion    = $target
            Status           = $status
            Model            = $mod.Model
            OS               = $mod.OS
            PSModulePath     = if ($mod.PSObject.Properties['PSModulePath']) { $mod.PSModulePath } else { $mod.ModuleBase }
        }
    }

    return $results
}
#endregion Module Inventory

#region Module Deployment
# ─────────────────────────────────────────────────────────────────────────────
# Install, update, and remove modules on remote computers.
# ─────────────────────────────────────────────────────────────────────────────

function Get-PSMMModuleDependencies {
    <#
    .SYNOPSIS
        Reads the .psd1 manifest from a share module folder and returns RequiredModules.
    .DESCRIPTION
        Looks for a .psd1 file in the specified module source path, parses it
        with Import-PowerShellDataFile, and returns any RequiredModules entries.
    .PARAMETER SourcePath
        The path to the module version folder on the central share.
    .PARAMETER ModuleName
        The name of the module (used to locate the .psd1 file).
    .OUTPUTS
        [PSCustomObject[]] with ModuleName and optionally ModuleVersion for each dependency.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$SourcePath,

        [Parameter(Mandatory)]
        [string]$ModuleName
    )

    $deps = @()
    $psd1 = Join-Path $SourcePath "$ModuleName.psd1"
    if (-not (Test-Path -LiteralPath $psd1)) {
        # Try finding any .psd1 in the folder
        $psd1File = Get-ChildItem -LiteralPath $SourcePath -Filter '*.psd1' -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($psd1File) { $psd1 = $psd1File.FullName } else { return $deps }
    }

    try {
        $manifest = Import-PowerShellDataFile -Path $psd1 -ErrorAction Stop
        if ($manifest.RequiredModules) {
            foreach ($req in $manifest.RequiredModules) {
                if ($req -is [string]) {
                    $deps += [PSCustomObject]@{ ModuleName = $req; ModuleVersion = $null }
                }
                elseif ($req -is [hashtable]) {
                    $deps += [PSCustomObject]@{
                        ModuleName    = $req['ModuleName']
                        ModuleVersion = if ($req.ContainsKey('ModuleVersion')) { $req['ModuleVersion'] } else { $null }
                    }
                }
            }
        }
    }
    catch {
        Write-PSMMLog -Severity 'WARN' -Message "Could not parse manifest for dependency check: $_"
    }

    return $deps
}

function Install-PSMMModule {
    <#
    .SYNOPSIS
        Installs a module from the central share to one or more remote computers.
    .DESCRIPTION
        Copies the module version folder (or extracts ZIP) to the target computer's
        PowerShell module path and validates with Import-Module.
    .PARAMETER ComputerNames
        Target computers.
    .PARAMETER ModuleName
        Name of the module to install.
    .PARAMETER Version
        Version to install.  If omitted, uses the latest on the share.
    .PARAMETER Credential
        Optional PSCredential for remoting.
    .OUTPUTS
        [PSCustomObject[]] -- Job descriptors from the runspace pool.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory)]
        [string]$ModuleName,

        [string]$Version,

        [PSCredential]$Credential = $script:Credential
    )

    $sharePath = $script:Settings.CentralSharePath
    if (-not $sharePath) {
        Write-PSMMLog -Severity 'ERROR' -Message 'Central share path not configured.'
        return
    }

    # Resolve latest version if not specified
    if (-not $Version) {
        $versions = Get-ChildItem -LiteralPath (Join-Path $sharePath $ModuleName) -Directory -ErrorAction SilentlyContinue |
        Sort-Object { try { [Version]$_.Name } catch { [Version]'0.0' } } -Descending
        if ($versions) {
            $Version = $versions[0].Name
        }
        else {
            Write-PSMMLog -Severity 'ERROR' -Message "No versions found for module '$ModuleName' on share."
            return
        }
    }

    $sourcePath = Join-Path $sharePath "$ModuleName\$Version"
    if (-not (Test-Path -LiteralPath $sourcePath)) {
        Write-PSMMLog -Severity 'ERROR' -Message "Source path does not exist: $sourcePath"
        return
    }

    # Check for module dependencies
    $dependencies = Get-PSMMModuleDependencies -SourcePath $sourcePath -ModuleName $ModuleName
    if ($dependencies.Count -gt 0) {
        $depNames = ($dependencies | ForEach-Object {
            if ($_.ModuleVersion) { "$($_.ModuleName) v$($_.ModuleVersion)+" } else { $_.ModuleName }
        }) -join ', '
        Write-PSMMLog -Severity 'WARN' -Message "Module '$ModuleName' requires: $depNames -- verify these are installed on target computers."
    }

    Write-PSMMLog -Severity 'INFO' -Message "Installing $ModuleName v$Version on $($ComputerNames.Count) computer(s) ..."

    $installScript = {
        param($Computer, $Cred, $ModName, $Ver, $Source)
        try {
            # Scriptblock that runs locally on the target machine using a local staging path
            $innerSb = {
                param($ModName, $Ver, $StagingPath)
                $destRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
                $destPath = Join-Path $destRoot "$ModName\$Ver"

                if (-not (Test-Path $destPath)) {
                    New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                }

                # Check for ZIP or folder in the local staging path
                $zipFile = Get-ChildItem -LiteralPath $StagingPath -Filter '*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($zipFile) {
                    # Extract to a temp directory first to handle ZIPs with a wrapper folder
                    $tempExtract = Join-Path $env:TEMP "PSMMExtract_$ModName_$Ver_$([guid]::NewGuid().ToString('N'))"
                    New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null
                    try {
                        Add-Type -AssemblyName System.IO.Compression.FileSystem
                        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile.FullName, $tempExtract)

                        # Detect wrapper folder: if extraction produced a single subfolder and no files at root, unwrap it
                        $extractedDirs  = Get-ChildItem -LiteralPath $tempExtract -Directory -ErrorAction SilentlyContinue
                        $extractedFiles = Get-ChildItem -LiteralPath $tempExtract -File -ErrorAction SilentlyContinue
                        if ($extractedDirs.Count -eq 1 -and $extractedFiles.Count -eq 0) {
                            # Single wrapper folder -- copy its contents directly into destination
                            Copy-Item -Path (Join-Path $extractedDirs[0].FullName '*') -Destination $destPath -Recurse -Force
                        }
                        else {
                            # No wrapper -- copy everything as-is
                            Copy-Item -Path "$tempExtract\*" -Destination $destPath -Recurse -Force
                        }
                    }
                    finally {
                        Remove-Item -LiteralPath $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    # Folder-based: copy loose module files directly
                    Copy-Item -Path "$StagingPath\*" -Destination $destPath -Recurse -Force
                }

                # Validate
                $loaded = Get-Module -ListAvailable -Name $ModName | Where-Object { $_.Version.ToString() -eq $Ver }
                if ($loaded) {
                    "SUCCESS: $ModName v$Ver installed on $env:COMPUTERNAME"
                }
                else {
                    "WARNING: Files copied but module not detected in Get-Module for $ModName v$Ver"
                }
            }

            $isLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')
            if ($isLocal) {
                # Local install -- source is directly accessible
                & $innerSb $ModName $Ver $Source
            }
            else {
                # Remote install -- stage source files onto the remote PC first to avoid double-hop
                $session = $null
                try {
                    $sessionSplat = @{ ComputerName = $Computer; ErrorAction = 'Stop' }
                    if ($Cred) { $sessionSplat['Credential'] = $Cred }
                    $session = New-PSSession @sessionSplat

                    # Create a temp staging directory on the remote machine
                    $remoteStagingPath = Invoke-Command -Session $session -ScriptBlock {
                        $p = Join-Path $env:TEMP "PSMMStaging_$([guid]::NewGuid().ToString('N'))"
                        New-Item -ItemType Directory -Path $p -Force | ForEach-Object { $_.FullName }
                    }

                    # Copy source files from the share to the remote staging directory
                    Copy-Item -Path "$Source\*" -Destination $remoteStagingPath -ToSession $session -Recurse -Force

                    # Run the install logic using the local staging path (no double-hop)
                    Invoke-Command -Session $session -ScriptBlock $innerSb -ArgumentList @($ModName, $Ver, $remoteStagingPath)

                    # Clean up staging directory on remote machine
                    Invoke-Command -Session $session -ScriptBlock {
                        param($p)
                        Remove-Item -LiteralPath $p -Recurse -Force -ErrorAction SilentlyContinue
                    } -ArgumentList @($remoteStagingPath)
                }
                finally {
                    if ($session) { Remove-PSSession -Session $session -ErrorAction SilentlyContinue }
                }
            }
        }
        catch {
            "ERROR on ${Computer}: $_"
        }
    }

    $jobs = Invoke-PSMMParallel -ComputerNames $ComputerNames -ScriptBlock $installScript -ArgumentList @($Credential, $ModuleName, $Version, $sourcePath)
    return $jobs
}

function Uninstall-PSMMModule {
    <#
    .SYNOPSIS
        Removes a module from one or more remote computers.
    .PARAMETER ComputerNames
        Target computers.
    .PARAMETER ModuleName
        Name of the module to remove.
    .PARAMETER Version
        Specific version to remove.  If omitted, removes all versions.
    .PARAMETER ModulePath
        The actual path (PSModulePath / ModuleBase) where the module is installed.
        When provided, this exact path is removed instead of guessing from the
        default ProgramFiles location.
    .PARAMETER Credential
        Optional PSCredential for remoting.
    .OUTPUTS
        [PSCustomObject[]] -- Job descriptors.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string[]]$ComputerNames,

        [Parameter(Mandatory)]
        [string]$ModuleName,

        [string]$Version,

        [string]$ModulePath,

        [PSCredential]$Credential = $script:Credential
    )

    Write-PSMMLog -Severity 'INFO' -Message "Removing $ModuleName $(if ($Version) {"v$Version "})from $($ComputerNames.Count) computer(s) ..."

    $removeScript = {
        param($Computer, $Cred, $ModName, $Ver, $KnownPath)
        try {
            $innerSb = {
                param($ModName, $Ver, $KnownPath)
                # Unload if loaded
                Remove-Module -Name $ModName -Force -ErrorAction SilentlyContinue

                # Use the known path from inventory if available
                if ($KnownPath -and (Test-Path $KnownPath)) {
                    $target = $KnownPath
                }
                else {
                    # Fallback: try standard ProgramFiles location
                    $destRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
                    if ($Ver) {
                        $target = Join-Path $destRoot "$ModName\$Ver"
                    }
                    else {
                        $target = Join-Path $destRoot $ModName
                    }
                }

                if (Test-Path $target) {
                    Remove-Item -LiteralPath $target -Recurse -Force
                    "SUCCESS: Removed $target on $env:COMPUTERNAME"
                }
                else {
                    "WARNING: Path not found: $target on $env:COMPUTERNAME"
                }
            }

            $isLocal = ($Computer -eq $env:COMPUTERNAME) -or ($Computer -eq 'localhost') -or ($Computer -eq '.')
            if ($isLocal) {
                & $innerSb $ModName $Ver $KnownPath
            } else {
                $splat = @{
                    ComputerName = $Computer
                    ErrorAction  = 'Stop'
                    ScriptBlock  = $innerSb
                    ArgumentList = @($ModName, $Ver, $KnownPath)
                }
                if ($Cred) { $splat['Credential'] = $Cred }
                Invoke-Command @splat
            }
        }
        catch {
            "ERROR on ${Computer}: $_"
        }
    }

    $jobs = Invoke-PSMMParallel -ComputerNames $ComputerNames -ScriptBlock $removeScript -ArgumentList @($Credential, $ModuleName, $Version, $ModulePath)
    return $jobs
}
#endregion Module Deployment

#region Credential Management
# ─────────────────────────────────────────────────────────────────────────────
# Credential handling based on configured CredentialMode.
# ─────────────────────────────────────────────────────────────────────────────

function Get-PSMMCredential {
    <#
    .SYNOPSIS
        Obtains credentials according to the configured CredentialMode.
    .OUTPUTS
        [PSCredential] or $null (for Default mode).
    #>
    [CmdletBinding()]
    param()

    switch ($script:Settings.CredentialMode) {
        'Prompt' {
            Write-PSMMLog -Severity 'INFO' -Message 'Prompting user for credentials ...'
            $script:Credential = Get-Credential -Message 'Enter credentials for remote operations'
        }
        'Stored' {
            Write-PSMMLog -Severity 'INFO' -Message 'Using stored credentials from Windows Credential Manager.'
            # Placeholder -- integrate with cmdkey / CredentialManager module as needed
            $script:Credential = $null
        }
        default {
            Write-PSMMLog -Severity 'INFO' -Message 'Using default (current user) credentials.'
            $script:Credential = $null
        }
    }

    return $script:Credential
}
#endregion Credential Management

#region WPF XAML Definition
# ─────────────────────────────────────────────────────────────────────────────
# The complete WPF UI is defined as an inline XAML here-string.
# No external .xaml files are needed.
# ─────────────────────────────────────────────────────────────────────────────

$script:MainWindowXaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="PS-ModuleManager"
    Width="1200" Height="800"
    MinWidth="900" MinHeight="600"
    WindowStartupLocation="CenterScreen"
    Background="#1E1E1E"
    Foreground="#D4D4D4"
    FontFamily="Segoe UI"
    FontSize="13">

    <Window.Resources>

        <!-- Define a style for all ScrollBar controls within this scope -->
        <Style TargetType="{x:Type ScrollBar}">
            <Style.Triggers>
                <!-- Apply properties only to the Vertical ScrollBar -->
                <Trigger Property="Orientation" Value="Vertical">
                    <Setter Property="MinWidth" Value="5" />
                    <Setter Property="Width" Value="5" />
                </Trigger>
                <!-- Apply properties only to the Horizontal ScrollBar -->
                <Trigger Property="Orientation" Value="Horizontal">
                    <Setter Property="MinHeight" Value="5" />
                    <Setter Property="Height" Value="5" />
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- ── Color Palette ───────────────────────────── -->
        <SolidColorBrush x:Key="PanelBg"       Color="#252526"/>
        <SolidColorBrush x:Key="BorderBrush"    Color="#3C3C3C"/>
        <SolidColorBrush x:Key="AccentBlue"     Color="#007ACC"/>
        <SolidColorBrush x:Key="TextPrimary"    Color="#D4D4D4"/>
        <SolidColorBrush x:Key="TextSecondary"  Color="#9E9E9E"/>
        <SolidColorBrush x:Key="GreenStatus"    Color="#4EC9B0"/>
        <SolidColorBrush x:Key="OrangeStatus"   Color="#CE9178"/>
        <SolidColorBrush x:Key="RedStatus"      Color="#F44747"/>
        <SolidColorBrush x:Key="GrayStatus"     Color="#6A6A6A"/>

        <!-- ── Button Style ────────────────────────────── -->
        <Style TargetType="Button">
            <Setter Property="Background"    Value="#0E639C"/>
            <Setter Property="Foreground"    Value="White"/>
            <Setter Property="BorderBrush"   Value="#1177BB"/>
            <Setter Property="Padding"       Value="14,7"/>
            <Setter Property="Margin"        Value="3"/>
            <Setter Property="Cursor"        Value="Hand"/>
            <Setter Property="FontSize"      Value="12"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="1"
                                CornerRadius="3"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#1177BB"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter Property="Background" Value="#094771"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Background" Value="#3C3C3C"/>
                                <Setter Property="Foreground" Value="#6A6A6A"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ── TextBox Style ───────────────────────────── -->
        <Style TargetType="TextBox">
            <Setter Property="Background"    Value="#3C3C3C"/>
            <Setter Property="Foreground"    Value="#D4D4D4"/>
            <Setter Property="BorderBrush"   Value="#555555"/>
            <Setter Property="Padding"       Value="5,3"/>
            <Setter Property="Margin"        Value="3"/>
        </Style>

        <!-- ── DataGrid Style ──────────────────────────── -->
        <Style TargetType="DataGrid">
            <Setter Property="Background"           Value="#1E1E1E"/>
            <Setter Property="Foreground"            Value="#D4D4D4"/>
            <Setter Property="BorderBrush"           Value="#3C3C3C"/>
            <Setter Property="RowBackground"         Value="#1E1E1E"/>
            <Setter Property="AlternatingRowBackground" Value="#252526"/>
            <Setter Property="GridLinesVisibility"   Value="None"/>
            <Setter Property="HeadersVisibility"     Value="Column"/>
        </Style>

        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background"  Value="#333333"/>
            <Setter Property="Foreground"  Value="#D4D4D4"/>
            <Setter Property="Padding"     Value="8,5"/>
            <Setter Property="BorderBrush" Value="#444444"/>
            <Setter Property="BorderThickness" Value="0,0,1,1"/>
            <Setter Property="FontWeight"  Value="SemiBold"/>
        </Style>

        <!-- ── ListBox Style ───────────────────────────── -->
        <Style TargetType="ListBox">
            <Setter Property="Background"  Value="#1E1E1E"/>
            <Setter Property="Foreground"  Value="#D4D4D4"/>
            <Setter Property="BorderBrush" Value="#3C3C3C"/>
        </Style>

        <!-- ── MenuItem Style (dark menu dropdowns) ──── -->
        <Style TargetType="MenuItem">
            <Setter Property="Background"  Value="#2D2D30"/>
            <Setter Property="Foreground"  Value="#D4D4D4"/>
            <Setter Property="BorderBrush" Value="#3C3C3C"/>
            <Setter Property="Padding"     Value="6,4"/>
            <Style.Triggers>
                <Trigger Property="IsHighlighted" Value="True">
                    <Setter Property="Background" Value="#3E3E42"/>
                </Trigger>
                <Trigger Property="IsEnabled" Value="False">
                    <Setter Property="Foreground" Value="#6A6A6A"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- ── Separator Style (in menus) ──────────── -->
        <Style TargetType="Separator">
            <Setter Property="Background" Value="#3C3C3C"/>
            <Setter Property="Margin"     Value="4,2"/>
        </Style>

        <!-- ── ComboBoxItem Style (dark dropdown items) ── -->
        <Style TargetType="ComboBoxItem">
            <Setter Property="Background"  Value="#2D2D30"/>
            <Setter Property="Foreground"  Value="#D4D4D4"/>
            <Setter Property="Padding"     Value="6,4"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Style.Triggers>
                <Trigger Property="IsHighlighted" Value="True">
                    <Setter Property="Background" Value="#3E3E42"/>
                </Trigger>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#094771"/>
                    <Setter Property="Foreground" Value="White"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- ── ComboBox ControlTemplate (dark dropdown popup) ── -->
        <ControlTemplate x:Key="ComboBoxToggleButton" TargetType="ToggleButton">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition />
                    <ColumnDefinition Width="20"/>
                </Grid.ColumnDefinitions>
                <Border x:Name="Border" Grid.ColumnSpan="2" Background="#3C3C3C" BorderBrush="#555555" BorderThickness="1" CornerRadius="2"/>
                <Border Grid.Column="0" Background="#3C3C3C" BorderBrush="#555555" BorderThickness="1,1,0,1" CornerRadius="2,0,0,2" Margin="1"/>
                <Path x:Name="Arrow" Grid.Column="1" Fill="#D4D4D4" HorizontalAlignment="Center" VerticalAlignment="Center" Data="M 0 0 L 4 4 L 8 0 Z"/>
            </Grid>
        </ControlTemplate>

        <Style TargetType="ComboBox">
            <Setter Property="Background"    Value="#3C3C3C"/>
            <Setter Property="Foreground"    Value="#D4D4D4"/>
            <Setter Property="BorderBrush"   Value="#555555"/>
            <Setter Property="Padding"       Value="5,3"/>
            <Setter Property="Margin"        Value="3"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton Name="ToggleButton" Template="{StaticResource ComboBoxToggleButton}"
                                          Focusable="false" IsChecked="{Binding Path=IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                                          ClickMode="Press"/>
                            <ContentPresenter Name="ContentSite" IsHitTestVisible="False"
                                              Content="{TemplateBinding SelectionBoxItem}"
                                              ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                              ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                              Margin="6,3,23,3" VerticalAlignment="Center" HorizontalAlignment="Left"/>
                            <Popup Name="Popup" Placement="Bottom" IsOpen="{TemplateBinding IsDropDownOpen}"
                                   AllowsTransparency="True" Focusable="False" PopupAnimation="Slide">
                                <Grid Name="DropDown" SnapsToDevicePixels="True"
                                      MinWidth="{TemplateBinding ActualWidth}" MaxHeight="{TemplateBinding MaxDropDownHeight}">
                                    <Border x:Name="DropDownBorder" Background="#2D2D30" BorderBrush="#555555" BorderThickness="1" CornerRadius="2"/>
                                    <ScrollViewer Margin="4,6,4,6" SnapsToDevicePixels="True">
                                        <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained"/>
                                    </ScrollViewer>
                                </Grid>
                            </Popup>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Style for the Border Background -->
        <Style x:Key="ServersPillBorderStyle" TargetType="Border">
            <Setter Property="Background" Value="#007ACC" />
            <Style.Triggers>
                <DataTrigger Binding="{Binding IsChecked, ElementName=ChkSkipServers}" Value="True">
                    <Setter Property="Background" Value="#444444" />
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <!-- Style for the TextBlock Content -->
        <Style x:Key="ServersPillTextStyle" TargetType="TextBlock">
            <Setter Property="Text" Value="Servers Included" />
            <Style.Triggers>
                <DataTrigger Binding="{Binding IsChecked, ElementName=ChkSkipServers}" Value="True">
                    <Setter Property="Text" Value="Servers Skipped" />
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <!-- Style for the Border Background -->
        <Style x:Key="VirtualPillBorderStyle" TargetType="Border">
            <Setter Property="Background" Value="#007ACC" />
            <Style.Triggers>
                <DataTrigger Binding="{Binding IsChecked, ElementName=ChkSkipVirtual}" Value="True">
                    <Setter Property="Background" Value="#444444" />
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <!-- Style for the TextBlock Content -->
        <Style x:Key="VirtualPillTextStyle" TargetType="TextBlock">
            <Setter Property="Text" Value="VMs Included" />
            <Style.Triggers>
                <DataTrigger Binding="{Binding IsChecked, ElementName=ChkSkipVirtual}" Value="True">
                    <Setter Property="Text" Value="VMs Skipped" />
                </DataTrigger>
            </Style.Triggers>
        </Style>


    </Window.Resources>

    <DockPanel>
        <!-- ══════════════════ MENU BAR ══════════════════ -->
        <Menu DockPanel.Dock="Top" Background="#333333" Foreground="#D4D4D4">
            <MenuItem Header="_File">
                <MenuItem Header="_Settings"    Name="MenuSettings"/>
                <Separator/>
                <MenuItem Header="E_xit"        Name="MenuExit"/>
            </MenuItem>
            <MenuItem Header="_Tools">
                <MenuItem Header="_Refresh Computers"  Name="MenuRefreshAD"/>
                <MenuItem Header="Test _Connectivity"  Name="MenuTestConn"/>
                <Separator/>
                <MenuItem Header="_Cancel All Jobs"    Name="MenuCancelJobs"/>
            </MenuItem>
            <MenuItem Header="_Help">
                <MenuItem Header="_About"  Name="MenuAbout"/>
            </MenuItem>
        </Menu>

        <!-- ══════════════════ TOOLBAR ═══════════════════ -->
        <Border DockPanel.Dock="Top" Background="#252526" Padding="5,4" BorderBrush="#3C3C3C" BorderThickness="0,0,0,1">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Orientation="Horizontal">
                    <TextBlock Text="OU Filter:" VerticalAlignment="Center" Margin="5,0"/>
                    <TextBox Name="TxtOuFilter" Width="250" ToolTip="LDAP path or OU filter (e.g. OU=Servers,DC=corp,DC=local)"/>
                    <TextBlock Text="Name:" VerticalAlignment="Center" Margin="10,0,5,0"/>
                    <TextBox Name="TxtNameFilter" Width="150" Text="*" ToolTip="Computer name wildcard (e.g. WEB*)"/>
                    <Button Name="BtnSearchAD" Content="&#x1F50D; Search AD" Margin="8,3"/>
                    <Separator Margin="10,2" Style="{x:Null}"/>
                    <Separator Margin="10,2" Style="{x:Null}"/>
                    <Button Name="BtnCredentials" Content="&#x1F511; Credentials" Background="#4A4A4A" BorderBrush="#5A5A5A"/>
                </StackPanel>

                <StackPanel Grid.Column="2" Orientation="Horizontal" Margin="20,0,5,0" >
                    <!-- Skip Servers CheckBox (hidden, drives pill state) -->
                    <CheckBox Name="ChkSkipServers" Visibility="Collapsed" />

                    <!-- Skip Servers Pill -->
                    <Border Margin="20,0,5,0" Height="30" CornerRadius="15" Padding="12,0" Cursor="Hand"
                            ToolTip="Include/Exclude computers with a Server OS in settings">
                        <Border.Style>
                            <Style TargetType="Border">
                                <Setter Property="Background" Value="#007ACC" />
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding ElementName=ChkSkipServers, Path=IsChecked}" Value="True">
                                        <Setter Property="Background" Value="#444444" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Border.Style>

        
                        <!-- Label text -->
                        <TextBlock VerticalAlignment="Center" Foreground="White" FontSize="12">
                            <TextBlock.Style>
                                <Style TargetType="TextBlock">
                                    <Setter Property="Text" Value="&#x2714; Servers" />
                                    <Style.Triggers>
                                        <DataTrigger Binding="{Binding ElementName=ChkSkipServers, Path=IsChecked}" Value="True">
                                            <Setter Property="Text" Value="&#x2718; Servers" />
                                        </DataTrigger>
                                    </Style.Triggers>
                                </Style>
                            </TextBlock.Style>
                        </TextBlock>
                
                    </Border>
                </StackPanel>

                <StackPanel Grid.Column="3" Orientation="Horizontal" Margin="0,0">
                    <!-- Skip Virtual CheckBox (hidden, drives pill state) -->
                    <CheckBox Name="ChkSkipVirtual" Visibility="Collapsed" />

                    <!-- Skip Virtual Pill -->
                    <Border Margin="20,0,5,0" Height="30" CornerRadius="15" Padding="12,0" Cursor="Hand" ToolTip="Include/Exclude virtual machines in settings">
                        <Border.Style>
                            <Style TargetType="Border">
                                <Setter Property="Background" Value="#007ACC" />
                                <Style.Triggers>
                                    <DataTrigger Binding="{Binding ElementName=ChkSkipVirtual, Path=IsChecked}" Value="True">
                                        <Setter Property="Background" Value="#444444" />
                                    </DataTrigger>
                                </Style.Triggers>
                            </Style>
                        </Border.Style>
             
                        <!-- Label text -->
                        <TextBlock VerticalAlignment="Center" Foreground="White" FontSize="12">
                            <TextBlock.Style>
                                <Style TargetType="TextBlock">
                                    <Setter Property="Text" Value="&#x2714; VMs" />
                                    <Style.Triggers>
                                        <DataTrigger Binding="{Binding ElementName=ChkSkipVirtual, Path=IsChecked}" Value="True">
                                            <Setter Property="Text" Value="&#x2718; VMs" />
                                        </DataTrigger>
                                    </Style.Triggers>
                                </Style>
                            </TextBlock.Style>
                        </TextBlock>
                    </Border>
                </StackPanel>

            </Grid>
        </Border>

        <!-- ══════════════════ STATUS BAR ════════════════ -->
        <Border DockPanel.Dock="Bottom" Background="#007ACC" Padding="8,3">
            <DockPanel>
                <TextBlock Name="StatusText" Text="Ready" Foreground="White" VerticalAlignment="Center"/>
                <ProgressBar Name="StatusProgress" Width="120" Height="12" IsIndeterminate="False"
                             Visibility="Collapsed" Margin="10,0" VerticalAlignment="Center"
                             Background="#005A9E" Foreground="#4EC9B0" BorderThickness="0"/>
                <TextBlock Name="StatusJobs" Text="" Foreground="White" HorizontalAlignment="Right" DockPanel.Dock="Right" VerticalAlignment="Center"/>
            </DockPanel>
        </Border>

        <!-- ══════════════════ MAIN CONTENT ══════════════ -->
        <Grid>
            <Grid.ColumnDefinitions>
                <ColumnDefinition Width="240" MinWidth="180"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="*"/>
                <ColumnDefinition Width="Auto"/>
                <ColumnDefinition Width="210" MinWidth="170"/>
            </Grid.ColumnDefinitions>
            <Grid.RowDefinitions>
                <RowDefinition Height="*"/>
                <RowDefinition Height="Auto"/>
                <RowDefinition Height="180" MinHeight="100"/>
            </Grid.RowDefinitions>

            <!-- ── LEFT: Computer List ───────────────────── -->
            <Border Grid.Column="0" Grid.Row="0" Grid.RowSpan="3"
                    Background="{StaticResource PanelBg}" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,0,1,0">
                <DockPanel>
                    <TextBlock DockPanel.Dock="Top" Text="Computers" FontWeight="Bold" FontSize="14" Margin="10,8" Foreground="{StaticResource AccentBlue}"/>
                    <StackPanel DockPanel.Dock="Bottom" Margin="5">
                        <TextBlock Name="TxtComputerCount" Text="0 computers" Foreground="{StaticResource TextSecondary}" Margin="5,3"/>
                        <Button Name="BtnSelectAll"     Content="Select All"       Background="#4A4A4A" BorderBrush="#5A5A5A"/>
                        <Button Name="BtnDeselectAll"   Content="Deselect All"     Background="#4A4A4A" BorderBrush="#5A5A5A"/>
                        <Button Name="BtnInvertSelect"  Content="Invert Selection" Background="#4A4A4A" BorderBrush="#5A5A5A"/>
                    </StackPanel>
                    <ListBox Name="ComputerListBox"
                             Margin="5"
                             Background="#1E1E1E"
                             BorderThickness="0"
                             ScrollViewer.HorizontalScrollBarVisibility="Disabled">
                        <ListBox.ItemTemplate>
                            <DataTemplate>
                                <DockPanel Margin="2,1">
                                    <CheckBox IsChecked="{Binding IsSelected, Mode=TwoWay, UpdateSourceTrigger=PropertyChanged}"
                                              VerticalAlignment="Center" Margin="0,0,6,0"/>
                                    <TextBlock Text="{Binding ConnectionStatus}" FontSize="10" Foreground="#888888"
                                               VerticalAlignment="Center" DockPanel.Dock="Right" Margin="6,0,2,0"
                                               MinWidth="42" TextAlignment="Right"/>
                                    <TextBlock Text="{Binding Name}" Foreground="#D4D4D4" VerticalAlignment="Center"
                                               TextTrimming="CharacterEllipsis"/>
                                </DockPanel>
                            </DataTemplate>
                        </ListBox.ItemTemplate>
                    </ListBox>
                </DockPanel>
            </Border>

            <!-- Splitter -->
            <GridSplitter Grid.Column="1" Grid.Row="0" Grid.RowSpan="3" Width="4" Background="#3C3C3C" HorizontalAlignment="Center" VerticalAlignment="Stretch"/>

            <!-- ── CENTER: Module Data Grid ──────────────── -->
            <DockPanel Grid.Column="2" Grid.Row="0" Margin="5,5,5,0">
                <DockPanel DockPanel.Dock="Top">
                    <TextBlock Text="Module Inventory" FontWeight="Bold" FontSize="14" Margin="5,5" Foreground="{StaticResource AccentBlue}"/>
                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                        <Button Name="BtnExportCsv" Content="Export CSV" Background="#4A4A4A" BorderBrush="#5A5A5A" Margin="5,3" Padding="10,4" FontSize="11"/>
                        <Button Name="BtnClearGrid" Content="Clear" Background="#4A4A4A" BorderBrush="#5A5A5A" Margin="5,3" Padding="10,4" FontSize="11"/>
                    </StackPanel>
                </DockPanel>
                <DataGrid Name="ModuleDataGrid"
                          AutoGenerateColumns="False"
                          IsReadOnly="True"
                          SelectionMode="Extended"
                          CanUserSortColumns="True"
                          Margin="0,5,0,0">
                    <DataGrid.Columns>
                        <DataGridTextColumn Header="Computer"          Binding="{Binding ComputerName}"     Width="2*"/>
                        <DataGridTextColumn Header="Model"             Binding="{Binding Model}"            Width="2*"/>
                        <DataGridTextColumn Header="OS"                Binding="{Binding OS}"               Width="4*"/>
                        <DataGridTextColumn Header="Module"            Binding="{Binding ModuleName}"       Width="3*"/>
                        <DataGridTextColumn Header="Installed"         Binding="{Binding InstalledVersion}" Width="2*"/>
                        <DataGridTextColumn Header="Available"         Binding="{Binding TargetVersion}"    Width="2*"/>
                        <DataGridTextColumn Header="Status"            Binding="{Binding Status}"           Width="2*"/>
                        <DataGridTextColumn Header="Path"              Binding="{Binding PSModulePath}"      Width="6*"/>
                    </DataGrid.Columns>
                </DataGrid>
            </DockPanel>

            <!-- ── Log pane splitter ─────────────────────── -->
            <GridSplitter Grid.Column="2" Grid.Row="1" Height="4" Background="#3C3C3C" HorizontalAlignment="Stretch" VerticalAlignment="Center"/>

            <!-- ── BOTTOM CENTER: Log Pane ───────────────── -->
            <Border Grid.Column="2" Grid.Row="2" Background="{StaticResource PanelBg}" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,1,0,0">
                <DockPanel>
                    <DockPanel DockPanel.Dock="Top">
                        <TextBlock Text="Log" FontWeight="Bold" FontSize="13" Margin="8,5" Foreground="{StaticResource AccentBlue}"/>
                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                            <Button Name="BtnExportLog" Content="Export" Background="#4A4A4A" BorderBrush="#5A5A5A" Margin="5,3" Padding="10,4" FontSize="11"/>
                            <Button Name="BtnClearLog" Content="Clear" Background="#4A4A4A" BorderBrush="#5A5A5A" Margin="5,3" Padding="10,4" FontSize="11"/>
                        </StackPanel>
                    </DockPanel>
                    <ListBox Name="LogListBox" Margin="5,0,5,5" FontFamily="Consolas" FontSize="11.5" Background="#1E1E1E" BorderThickness="0"/>
                </DockPanel>
            </Border>

            <!-- Splitter -->
            <GridSplitter Grid.Column="3" Grid.Row="0" Grid.RowSpan="3" Width="4" Background="#3C3C3C" HorizontalAlignment="Center" VerticalAlignment="Stretch"/>

            <!-- ── RIGHT: Actions Panel ──────────────────── -->
            <Border Grid.Column="4" Grid.Row="0" Grid.RowSpan="3" Background="{StaticResource PanelBg}" BorderBrush="{StaticResource BorderBrush}" BorderThickness="1,0,0,0">
                <StackPanel Margin="8">
                    <TextBlock Text="Actions" FontWeight="Bold" FontSize="14" Margin="0,5,0,10" Foreground="{StaticResource AccentBlue}"/>

                    <Button Name="BtnInventory" Content="&#x21BB; Inventory"  ToolTip="Query modules on selected computers"/>
                    <Button Name="BtnInstall"   Content="&#x25B6; Install"    ToolTip="Install module from central share"/>
                    <Button Name="BtnUpdate"    Content="&#x21C4; Update"     ToolTip="Update outdated modules"/>
                    <Button Name="BtnRemove"    Content="&#x2715; Remove"     ToolTip="Remove selected module"/>

                    <Separator Margin="0,12" Background="#3C3C3C"/>

                    <TextBlock Text="Module:" Foreground="{StaticResource TextSecondary}" Margin="0,3"/>
                    <ComboBox Name="CmbModule" ToolTip="Select module from central share"/>

                    <TextBlock Text="Version:" Foreground="{StaticResource TextSecondary}" Margin="0,6,0,3"/>
                    <ComboBox Name="CmbVersion" ToolTip="Select target version"/>

                    <Separator Margin="0,12" Background="#3C3C3C"/>

                    <Button Name="BtnCancelJobs" Content="&#x23F9; Cancel Jobs" Background="#6A3030" BorderBrush="#8A4040"/>
                    <Button Name="BtnSettings"   Content="&#x2699; Settings"    Background="#4A4A4A" BorderBrush="#5A5A5A" Margin="3,10,3,3"/>
                </StackPanel>
            </Border>
        </Grid>
    </DockPanel>
</Window>
'@

# ──────────────────────────────────────────────────────────────────────────────
# Settings Dialog XAML (also inline)
# ──────────────────────────────────────────────────────────────────────────────
$script:SettingsDialogXaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Settings -- PS-ModuleManager"
    Width="600" Height="700"
    WindowStartupLocation="CenterOwner"
    ResizeMode="NoResize"
    Background="#1E1E1E"
    Foreground="#D4D4D4"
    FontFamily="Segoe UI"
    FontSize="13">

    <Window.Resources>

        <!-- Define a style for all ScrollBar controls within this scope -->
        <Style TargetType="{x:Type ScrollBar}">
            <Style.Triggers>
                <!-- Apply properties only to the Vertical ScrollBar -->
                <Trigger Property="Orientation" Value="Vertical">
                    <Setter Property="MinWidth" Value="5" />
                    <Setter Property="Width" Value="5" />
                </Trigger>
                <!-- Apply properties only to the Horizontal ScrollBar -->
                <Trigger Property="Orientation" Value="Horizontal">
                    <Setter Property="MinHeight" Value="5" />
                    <Setter Property="Height" Value="5" />
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style TargetType="TextBox">
            <Setter Property="Background"  Value="#3C3C3C"/>
            <Setter Property="Foreground"  Value="#D4D4D4"/>
            <Setter Property="BorderBrush" Value="#555555"/>
            <Setter Property="Padding"     Value="5,3"/>
            <Setter Property="Margin"      Value="0,3,0,8"/>
        </Style>
        <Style TargetType="Button">
            <Setter Property="Background"  Value="#0E639C"/>
            <Setter Property="Foreground"  Value="White"/>
            <Setter Property="BorderBrush" Value="#1177BB"/>
            <Setter Property="Padding"     Value="14,7"/>
            <Setter Property="Margin"      Value="5"/>
            <Setter Property="Cursor"      Value="Hand"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border Background="{TemplateBinding Background}"
                                BorderBrush="{TemplateBinding BorderBrush}"
                                BorderThickness="1" CornerRadius="3"
                                Padding="{TemplateBinding Padding}">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter Property="Background" Value="#1177BB"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- ── ComboBoxItem Style (dark dropdown items) ── -->
        <Style TargetType="ComboBoxItem">
            <Setter Property="Background"  Value="#2D2D30"/>
            <Setter Property="Foreground"  Value="#D4D4D4"/>
            <Setter Property="Padding"     Value="6,4"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Style.Triggers>
                <Trigger Property="IsHighlighted" Value="True">
                    <Setter Property="Background" Value="#3E3E42"/>
                </Trigger>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#094771"/>
                    <Setter Property="Foreground" Value="White"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- ── ComboBox ControlTemplate (dark dropdown popup) ── -->
        <ControlTemplate x:Key="SettComboBoxToggleButton" TargetType="ToggleButton">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition />
                    <ColumnDefinition Width="20"/>
                </Grid.ColumnDefinitions>
                <Border x:Name="Border" Grid.ColumnSpan="2" Background="#3C3C3C" BorderBrush="#555555" BorderThickness="1" CornerRadius="2"/>
                <Border Grid.Column="0" Background="#3C3C3C" BorderBrush="#555555" BorderThickness="1,1,0,1" CornerRadius="2,0,0,2" Margin="1"/>
                <Path x:Name="Arrow" Grid.Column="1" Fill="#D4D4D4" HorizontalAlignment="Center" VerticalAlignment="Center" Data="M 0 0 L 4 4 L 8 0 Z"/>
            </Grid>
        </ControlTemplate>

        <Style TargetType="ComboBox">
            <Setter Property="Background"    Value="#3C3C3C"/>
            <Setter Property="Foreground"    Value="#D4D4D4"/>
            <Setter Property="BorderBrush"   Value="#555555"/>
            <Setter Property="Padding"       Value="5,3"/>
            <Setter Property="Margin"        Value="0,3,0,8"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton Name="ToggleButton" Template="{StaticResource SettComboBoxToggleButton}"
                                          Focusable="false" IsChecked="{Binding Path=IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"
                                          ClickMode="Press"/>
                            <ContentPresenter Name="ContentSite" IsHitTestVisible="False"
                                              Content="{TemplateBinding SelectionBoxItem}"
                                              ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}"
                                              ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}"
                                              Margin="6,3,23,3" VerticalAlignment="Center" HorizontalAlignment="Left"/>
                            <Popup Name="Popup" Placement="Bottom" IsOpen="{TemplateBinding IsDropDownOpen}"
                                   AllowsTransparency="True" Focusable="False" PopupAnimation="Slide">
                                <Grid Name="DropDown" SnapsToDevicePixels="True"
                                      MinWidth="{TemplateBinding ActualWidth}" MaxHeight="{TemplateBinding MaxDropDownHeight}">
                                    <Border x:Name="DropDownBorder" Background="#2D2D30" BorderBrush="#555555" BorderThickness="1" CornerRadius="2"/>
                                    <ScrollViewer Margin="4,6,4,6" SnapsToDevicePixels="True">
                                        <StackPanel IsItemsHost="True" KeyboardNavigation.DirectionalNavigation="Contained"/>
                                    </ScrollViewer>
                                </Grid>
                            </Popup>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid Margin="20">
        <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel>
                <TextBlock Text="Domain LDAP Path" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                <TextBox Name="TxtSettLdap" ToolTip="e.g. LDAP://DC=corp,DC=local"/>

                <TextBlock Text="OU Filter" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                <TextBox Name="TxtSettOu" ToolTip="e.g. OU=Servers,DC=corp,DC=local"/>

                <TextBlock Text="Module Search Paths" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                <TextBox Name="TxtSettSearchPaths" ToolTip="Comma-separated list of module search paths" AcceptsReturn="False"/>

                <TextBlock Text="Central Share Path" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                <TextBox Name="TxtSettShare" ToolTip="e.g. \\\\fileserver\\PSModules"/>

                <TextBlock Text="Log Path" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                <TextBox Name="TxtSettLogPath"/>

                <Grid>
                    <Grid.ColumnDefinitions>
                        <ColumnDefinition Width="*"/>
                        <ColumnDefinition Width="*"/>
                    </Grid.ColumnDefinitions>
                    <StackPanel Grid.Column="0" Margin="0,0,8,0">
                        <TextBlock Text="Max Concurrency" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                        <TextBox Name="TxtSettConcurrency"/>
                    </StackPanel>
                    <StackPanel Grid.Column="1">
                        <TextBlock Text="Retry Count" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                        <TextBox Name="TxtSettRetry"/>
                    </StackPanel>
                </Grid>

                <TextBlock Text="Job Timeout (seconds)" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                <TextBox Name="TxtSettTimeout"/>

                <TextBlock Text="Credential Mode" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                <ComboBox Name="CmbSettCredMode" Margin="0,3,0,8">
                    <ComboBoxItem Content="Default"  IsSelected="True"/>
                    <ComboBoxItem Content="Prompt"/>
                    <ComboBoxItem Content="Stored"/>
                </ComboBox>

                <TextBlock Text="Log Level" FontWeight="SemiBold" Foreground="#9CDCFE"/>
                <ComboBox Name="CmbSettLogLevel" Margin="0,3,0,8">
                    <ComboBoxItem Content="DEBUG"/>
                    <ComboBoxItem Content="INFO" IsSelected="True"/>
                    <ComboBoxItem Content="WARN"/>
                    <ComboBoxItem Content="ERROR"/>
                </ComboBox>

                <CheckBox Name="ChkReachability" Content="Test WinRM reachability before operations"
                          Foreground="#D4D4D4" IsChecked="True" Margin="0,8"/>
                <CheckBox Name="ChkExcludeServers" Content="Exclude Server OS computers by default"
                          Foreground="#D4D4D4" Margin="0,4"/>
                <CheckBox Name="ChkExcludeVirtual" Content="Exclude virtual machines by default"
                          Foreground="#D4D4D4" Margin="0,4"/>

                <TextBlock Text="OS Filter (wildcards supported, e.g. '*Windows 10*'):" Foreground="#CCCCCC" Margin="0,12,0,2"/>
                <TextBox Name="TxtOsFilter" Background="#3C3C3C" Foreground="#D4D4D4"
                         BorderBrush="#5A5A5A" Padding="4" ToolTip="Filter computers by OS (e.g. '*Windows 10*' or '*Server 2019*'). Leave empty for no filter."/>
            </StackPanel>
        </ScrollViewer>

        <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="0,10,0,0">
            <Button Name="BtnSettImport" Content="Import"      Background="#4A4A4A" BorderBrush="#5A5A5A"/>
            <Button Name="BtnSettExport" Content="Export"      Background="#4A4A4A" BorderBrush="#5A5A5A"/>
            <Button Name="BtnTestShare"  Content="Test Share"  Background="#4A4A4A" BorderBrush="#5A5A5A"/>
            <Button Name="BtnTestAD"     Content="Test AD"     Background="#4A4A4A" BorderBrush="#5A5A5A"/>
            <Button Name="BtnSettSave"   Content="Save"/>
            <Button Name="BtnSettCancel" Content="Cancel"      Background="#4A4A4A" BorderBrush="#5A5A5A"/>
        </StackPanel>
    </Grid>
</Window>
'@

#endregion WPF XAML Definition

#region WPF Helpers
# ─────────────────────────────────────────────────────────────────────────────
# Utility functions for creating and interacting with WPF windows.
# ─────────────────────────────────────────────────────────────────────────────

function New-PSMMWindow {
    <#
    .SYNOPSIS
        Parses a XAML string and returns the WPF Window object.
    .PARAMETER Xaml
        The XAML markup string.
    .OUTPUTS
        [System.Windows.Window]
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Xaml
    )

    # Remove x:Class if present (not needed outside Visual Studio)
    $cleanXaml = $Xaml -replace 'x:Class="[^"]*"', ''

    $reader = [System.Xml.XmlReader]::Create([System.IO.StringReader]::new($cleanXaml))
    $window = [System.Windows.Markup.XamlReader]::Load($reader)

    return $window
}

function Find-PSMMControl {
    <#
    .SYNOPSIS
        Finds a named control inside a WPF window.
    .PARAMETER Window
        The WPF Window object.
    .PARAMETER Name
        The x:Name of the control to find.
    .OUTPUTS
        The WPF control, or $null.
    #>
    [CmdletBinding()]
    param(
        [System.Windows.Window]$Window,
        [string]$Name
    )
    return $Window.FindName($Name)
}

function Update-PSMMDispatcher {
    <#
    .SYNOPSIS
        Invokes an action on the WPF dispatcher thread (thread-safe UI update).
    .PARAMETER Action
        The script block to run on the UI thread.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    if ($script:MainWindow -and $script:MainWindow.Dispatcher) {
        $script:MainWindow.Dispatcher.Invoke($Action, [System.Windows.Threading.DispatcherPriority]::Background)
    }
}
#endregion WPF Helpers

#region WPF Event Handlers
# ─────────────────────────────────────────────────────────────────────────────
# Event handler functions wired to WPF controls.
# All handlers are wrapped in try/catch to prevent silent crashes.
# ─────────────────────────────────────────────────────────────────────────────

function Invoke-PSMMSafeAction {
    <#
    .SYNOPSIS
        Wraps a script block in try/catch for safe UI event handling.
    .DESCRIPTION
        Executes the given action and catches any unhandled exception, showing
        it in a WPF MessageBox and logging it. Prevents UI freezes.
    .PARAMETER Action
        The script block to execute safely.
    .PARAMETER Context
        Optional label for the operation (used in error messages).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action,
        [string]$Context = 'Operation'
    )

    try {
        & $Action
    }
    catch {
        $errMsg = $_.Exception.Message
        if (-not $errMsg) { $errMsg = $_.ToString() }
        Write-PSMMLog -Severity 'ERROR' -Message "$Context failed: $errMsg"
        [System.Windows.MessageBox]::Show(
            "$Context failed:`n`n$errMsg",
            'Error', 'OK', 'Error') | Out-Null
    }
}

function Register-PSMMMainWindowEvents {
    <#
    .SYNOPSIS
        Wires up all event handlers for the main window controls.
    .PARAMETER Window
        The main WPF Window object.
    #>
    [CmdletBinding()]
    param(
        [System.Windows.Window]$Window
    )

    # ── Search AD ────────────────────────────────────────────────────────────
    $btnSearch = Find-PSMMControl -Window $Window -Name 'BtnSearchAD'
    $btnSearch.Add_Click({
            $ouFilter = (Find-PSMMControl -Window $script:MainWindow -Name 'TxtOuFilter').Text
            $nameFilter = (Find-PSMMControl -Window $script:MainWindow -Name 'TxtNameFilter').Text
            if (-not $nameFilter) { $nameFilter = '*' }

            $ldapPath = if ($ouFilter) { "LDAP://$ouFilter" } else { $script:Settings.DomainLdapPath }

            Write-PSMMLog -Severity 'INFO' -Message "Searching AD: OU=$ouFilter, Name=$nameFilter"

            try {
                $skipServers = (Find-PSMMControl -Window $script:MainWindow -Name 'ChkSkipServers').IsChecked -eq $true
                $skipVirtual = (Find-PSMMControl -Window $script:MainWindow -Name 'ChkSkipVirtual').IsChecked -eq $true
                $computers = Get-PSMMComputers -LdapPath $ldapPath -NameFilter $nameFilter -ExcludeServers $skipServers -ExcludeVirtual $skipVirtual

                # Determine local computer name for status detection
                $localName = $env:COMPUTERNAME

                $script:ComputerList.Clear()
                foreach ($c in $computers) {
                    # Determine connection status
                    $connStatus = if ($c.Name -eq $localName -or $c.Name -eq 'localhost') {
                        'Local'
                    } elseif ($c.Reachable -eq $true) {
                        'WinRM'
                    } elseif ($c.Reachable -eq $false) {
                        'Unreachable'
                    } else {
                        'Unknown'
                    }

                    # Auto-select if Local or WinRM reachable
                    $autoSelect = $connStatus -in @('Local', 'WinRM')

                    $script:ComputerList.Add([ComputerItem]@{
                        IsSelected       = $autoSelect
                        Name             = $c.Name
                        ConnectionStatus = $connStatus
                    })
                }

                $countText = Find-PSMMControl -Window $script:MainWindow -Name 'TxtComputerCount'
                $countText.Text = "$($computers.Count) computers"
            }
            catch {
                Write-PSMMLog -Severity 'ERROR' -Message "AD search failed: $_"
                [System.Windows.MessageBox]::Show("AD search failed:`n$_", 'Error', 'OK', 'Error')
            }
        })

    # ── Inventory ────────────────────────────────────────────────────────────
    $btnInventory = Find-PSMMControl -Window $Window -Name 'BtnInventory'
    $btnInventory.Add_Click({
        Invoke-PSMMSafeAction -Context 'Inventory' -Action {
            # Get computers checked via checkbox
            $selected = @($script:ComputerList | Where-Object { $_.IsSelected } | ForEach-Object { $_.Name })

            if ($selected.Count -eq 0) {
                [System.Windows.MessageBox]::Show('Check one or more computers first.', 'Info', 'OK', 'Information')
                return
            }

            # Check if a specific module is selected in the Module combobox
            $cmbMod = Find-PSMMControl -Window $script:MainWindow -Name 'CmbModule'
            $modFilter = if ($cmbMod.SelectedItem) { $cmbMod.SelectedItem.ToString() } else { $null }

            if ($modFilter) {
                Write-PSMMLog -Severity 'INFO' -Message "Starting inventory for '$modFilter' on $($selected.Count) computer(s) ..."
            } else {
                Write-PSMMLog -Severity 'INFO' -Message "Starting inventory (all modules) on $($selected.Count) computer(s) ..."
            }

            # Clear previous inventory rows for the selected computers to avoid duplicates
            $toRemove = @($script:ModuleGrid | Where-Object { $selected -contains $_.ComputerName })
            foreach ($item in $toRemove) { $script:ModuleGrid.Remove($item) }

            # Launch async inventory -- filtered to the selected module if one is chosen
            $null = Get-PSMMRemoteModules -ComputerNames $selected -ModuleName $modFilter

            # Start a dispatcher timer to poll results
            Start-PSMMJobPoller -Operation 'Inventory'
        }
        })

    # ── Install ──────────────────────────────────────────────────────────────
    $btnInstall = Find-PSMMControl -Window $Window -Name 'BtnInstall'
    $btnInstall.Add_Click({
        Invoke-PSMMSafeAction -Context 'Install' -Action {
            $cmbMod = Find-PSMMControl -Window $script:MainWindow -Name 'CmbModule'
            $cmbVer = Find-PSMMControl -Window $script:MainWindow -Name 'CmbVersion'

            # Get computers checked via checkbox
            $selected = @($script:ComputerList | Where-Object { $_.IsSelected } | ForEach-Object { $_.Name })

            if ($selected.Count -eq 0 -or -not $cmbMod.SelectedItem) {
                [System.Windows.MessageBox]::Show('Check computer(s) and select a module.', 'Info', 'OK', 'Information')
                return
            }

            $modName = $cmbMod.SelectedItem.ToString()
            $version = if ($cmbVer.SelectedItem) { $cmbVer.SelectedItem.ToString() } else { $null }

            # Build detailed confirmation with computer list
            $compList = ($selected | Select-Object -First 10) -join ", "
            if ($selected.Count -gt 10) { $compList += " ... and $($selected.Count - 10) more" }
            $confirm = [System.Windows.MessageBox]::Show(
                "Install $modName $(if ($version) {"v$version "})on $($selected.Count) computer(s)?`n`nComputers: $compList",
                'Confirm Install', 'YesNo', 'Question')

            if ($confirm -eq 'Yes') {
                $null = Install-PSMMModule -ComputerNames $selected -ModuleName $modName -Version $version
                Start-PSMMJobPoller -Operation 'Install'
            }
        }
        })

    # ── Update ───────────────────────────────────────────────────────────────
    $btnUpdate = Find-PSMMControl -Window $Window -Name 'BtnUpdate'
    $btnUpdate.Add_Click({
        Invoke-PSMMSafeAction -Context 'Update' -Action {
            $grid = Find-PSMMControl -Window $script:MainWindow -Name 'ModuleDataGrid'
            $outdated = @()
            foreach ($item in $grid.SelectedItems) {
                if ($item.Status -eq 'Outdated') { $outdated += $item }
            }

            if ($outdated.Count -eq 0) {
                [System.Windows.MessageBox]::Show('Select outdated module rows in the grid.', 'Info', 'OK', 'Information')
                return
            }

            # Build detailed confirmation with module/computer list
            $detailLines = @()
            foreach ($item in $outdated) {
                $detailLines += "  $($item.ComputerName): $($item.ModuleName) $($item.InstalledVersion) -> $($item.TargetVersion)"
            }
            $detailText = ($detailLines | Select-Object -First 15) -join "`n"
            if ($detailLines.Count -gt 15) { $detailText += "`n  ... and $($detailLines.Count - 15) more" }

            $confirm = [System.Windows.MessageBox]::Show(
                "Update $($outdated.Count) module(s)?`n`n$detailText",
                'Confirm Update', 'YesNo', 'Question')

            if ($confirm -eq 'Yes') {
                foreach ($item in $outdated) {
                    $null = Install-PSMMModule -ComputerNames @($item.ComputerName) -ModuleName $item.ModuleName -Version $item.TargetVersion
                }
                Start-PSMMJobPoller -Operation 'Update'
            }
        }
        })

    # ── Remove ───────────────────────────────────────────────────────────────
    $btnRemove = Find-PSMMControl -Window $Window -Name 'BtnRemove'
    $btnRemove.Add_Click({
        Invoke-PSMMSafeAction -Context 'Remove' -Action {
            $grid = Find-PSMMControl -Window $script:MainWindow -Name 'ModuleDataGrid'

            if ($grid.SelectedItems.Count -eq 0) {
                [System.Windows.MessageBox]::Show('Select module rows to remove.', 'Info', 'OK', 'Information')
                return
            }

            # Build detailed confirmation with module/computer list
            $detailLines = @()
            foreach ($item in $grid.SelectedItems) {
                $detailLines += "  $($item.ComputerName): $($item.ModuleName) v$($item.InstalledVersion)"
            }
            $detailText = ($detailLines | Select-Object -First 15) -join "`n"
            if ($detailLines.Count -gt 15) { $detailText += "`n  ... and $($detailLines.Count - 15) more" }

            $confirm = [System.Windows.MessageBox]::Show(
                "Remove $($grid.SelectedItems.Count) module(s) from target computers? This cannot be undone.`n`n$detailText",
                'Confirm Remove', 'YesNo', 'Warning')

            if ($confirm -eq 'Yes') {
                foreach ($item in $grid.SelectedItems) {
                    $null = Uninstall-PSMMModule -ComputerNames @($item.ComputerName) -ModuleName $item.ModuleName -Version $item.InstalledVersion -ModulePath $item.PSModulePath
                }
                Start-PSMMJobPoller -Operation 'Remove'
            }
        }
        })

    # ── Cancel Jobs ──────────────────────────────────────────────────────────
    $btnCancel = Find-PSMMControl -Window $Window -Name 'BtnCancelJobs'
    $btnCancel.Add_Click({
            Stop-PSMMAllJobs
            Write-PSMMLog -Severity 'WARN' -Message 'All jobs cancelled by user.'
        })

    # ── Select/Deselect All ──────────────────────────────────────────────────
    $btnSelectAll = Find-PSMMControl -Window $Window -Name 'BtnSelectAll'
    $btnSelectAll.Add_Click({
            foreach ($item in $script:ComputerList) { $item.IsSelected = $true }
        })

    $btnDeselectAll = Find-PSMMControl -Window $Window -Name 'BtnDeselectAll'
    $btnDeselectAll.Add_Click({
            foreach ($item in $script:ComputerList) { $item.IsSelected = $false }
        })

    $btnInvertSelect = Find-PSMMControl -Window $Window -Name 'BtnInvertSelect'
    $btnInvertSelect.Add_Click({
            foreach ($item in $script:ComputerList) { $item.IsSelected = -not $item.IsSelected }
        })

    # ── Clear Module Grid ────────────────────────────────────────────────────
    $btnClearGrid = Find-PSMMControl -Window $Window -Name 'BtnClearGrid'
    $btnClearGrid.Add_Click({
            $script:ModuleGrid.Clear()
        })

    # ── Export Inventory to CSV ──────────────────────────────────────────────
    $btnExportCsv = Find-PSMMControl -Window $Window -Name 'BtnExportCsv'
    $btnExportCsv.Add_Click({
            Invoke-PSMMSafeAction -Context $script:MainWindow -Action {
                if ($script:ModuleGrid.Count -eq 0) {
                    [System.Windows.MessageBox]::Show('No inventory data to export.', 'Info', 'OK', 'Information')
                    return
                }
                $dlg = [Microsoft.Win32.SaveFileDialog]::new()
                $dlg.Title = 'Export Module Inventory'
                $dlg.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
                $dlg.FileName = "ModuleInventory_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"
                if ($dlg.ShowDialog($script:MainWindow)) {
                    $rows = foreach ($item in $script:ModuleGrid) {
                        [PSCustomObject]@{
                            ComputerName     = $item.ComputerName
                            Model            = $item.Model
                            OS               = $item.OS
                            ModuleName       = $item.ModuleName
                            InstalledVersion = $item.InstalledVersion
                            TargetVersion    = $item.TargetVersion
                            Status           = $item.Status
                            PSModulePath     = $item.PSModulePath
                        }
                    }
                    $rows | Export-Csv -Path $dlg.FileName -NoTypeInformation -Encoding UTF8
                    Write-PSMMLog -Severity 'INFO' -Message "Inventory exported to $($dlg.FileName) ($($script:ModuleGrid.Count) rows)"
                }
            }
        })

    # ── Export Log ───────────────────────────────────────────────────────────
    $btnExportLog = Find-PSMMControl -Window $Window -Name 'BtnExportLog'
    $btnExportLog.Add_Click({
            $logBox = Find-PSMMControl -Window $script:MainWindow -Name 'LogListBox'
            if ($logBox.Items.Count -eq 0) {
                [System.Windows.MessageBox]::Show('No log entries to export.', 'Info', 'OK', 'Information')
                return
            }
            $dlg = [Microsoft.Win32.SaveFileDialog]::new()
            $dlg.Title = 'Export Log'
            $dlg.Filter = 'Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*'
            $dlg.FileName = "PS-ModuleManager_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').log"
            if ($dlg.ShowDialog($script:MainWindow)) {
                try {
                    $logBox.Items | Out-File -FilePath $dlg.FileName -Encoding UTF8
                    Write-PSMMLog -Severity 'INFO' -Message "Log exported to $($dlg.FileName)"
                }
                catch {
                    [System.Windows.MessageBox]::Show("Failed to export log:`n$_", 'Error', 'OK', 'Error')
                }
            }
        })

    # ── Clear Log ────────────────────────────────────────────────────────────
    $btnClearLog = Find-PSMMControl -Window $Window -Name 'BtnClearLog'
    $btnClearLog.Add_Click({
            $logBox = Find-PSMMControl -Window $script:MainWindow -Name 'LogListBox'
            $logBox.Items.Clear()
        })

    # ── Settings ─────────────────────────────────────────────────────────────
    $btnSettings = Find-PSMMControl -Window $Window -Name 'BtnSettings'
    $btnSettings.Add_Click({ Show-PSMMSettingsDialog })

    $menuSettings = Find-PSMMControl -Window $Window -Name 'MenuSettings'
    $menuSettings.Add_Click({ Show-PSMMSettingsDialog })

    # ── Credentials ──────────────────────────────────────────────────────────
    $btnCred = Find-PSMMControl -Window $Window -Name 'BtnCredentials'
    $btnCred.Add_Click({
            $script:Credential = Get-Credential -Message 'Enter credentials for remote operations'
            if ($script:Credential) {
                Write-PSMMLog -Severity 'INFO' -Message "Credentials set for user: $($script:Credential.UserName)"
            }
        })

    # ── Menu: Refresh AD ─────────────────────────────────────────────────────
    $menuRefresh = Find-PSMMControl -Window $Window -Name 'MenuRefreshAD'
    $menuRefresh.Add_Click({
            $btnSearch = Find-PSMMControl -Window $script:MainWindow -Name 'BtnSearchAD'
            $btnSearch.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
        })

    # ── Menu: Test Connectivity ──────────────────────────────────────────────
    $menuTestConn = Find-PSMMControl -Window $Window -Name 'MenuTestConn'
    $menuTestConn.Add_Click({
            $issues = Test-PSMMSettings
            if ($issues.Count -eq 0) {
                [System.Windows.MessageBox]::Show('All settings are valid and paths are accessible.', 'Connectivity OK', 'OK', 'Information')
            }
            else {
                [System.Windows.MessageBox]::Show(($issues -join "`n"), 'Settings Issues', 'OK', 'Warning')
            }
        })

    # ── Menu: Cancel All ─────────────────────────────────────────────────────
    $menuCancel = Find-PSMMControl -Window $Window -Name 'MenuCancelJobs'
    $menuCancel.Add_Click({
            Stop-PSMMAllJobs
            Write-PSMMLog -Severity 'WARN' -Message 'All jobs cancelled by user.'
        })

    # ── Menu: About ──────────────────────────────────────────────────────────
    $menuAbout = Find-PSMMControl -Window $Window -Name 'MenuAbout'
    $menuAbout.Add_Click({
            [System.Windows.MessageBox]::Show(
                "PS-ModuleManager v1.0.0`n`nA WPF-based PowerShell Module Manager for installing, updating, and removing modules on domain-joined computers.`n`nPowered by ADSI, WinRM, and Runspace Pools.",
                'About PS-ModuleManager', 'OK', 'Information')
        })

    # ── Menu: Exit ───────────────────────────────────────────────────────────
    $menuExit = Find-PSMMControl -Window $Window -Name 'MenuExit'
    $menuExit.Add_Click({
            $script:MainWindow.Close()
        })

    # ── Module ComboBox population ───────────────────────────────────────────
    $cmbModule = Find-PSMMControl -Window $Window -Name 'CmbModule'
    $cmbModule.Add_DropDownOpened({
            $cmb = Find-PSMMControl -Window $script:MainWindow -Name 'CmbModule'
            $cmb.Items.Clear()

            $shareModules = Get-PSMMShareModules
            $moduleNames = $shareModules | Select-Object -ExpandProperty ModuleName -Unique | Sort-Object
            foreach ($name in $moduleNames) {
                $cmb.Items.Add($name)
            }
        })

    # ── Version ComboBox population (changes when module is selected) ────────
    $cmbModule.Add_SelectionChanged({
            $cmbMod = Find-PSMMControl -Window $script:MainWindow -Name 'CmbModule'
            $cmbVer = Find-PSMMControl -Window $script:MainWindow -Name 'CmbVersion'
            $cmbVer.Items.Clear()

            if ($cmbMod.SelectedItem) {
                $modName = $cmbMod.SelectedItem.ToString()
                $shareModules = Get-PSMMShareModules
                $versions = $shareModules | Where-Object { $_.ModuleName -eq $modName } |
                Sort-Object { try { [Version]$_.Version } catch { [Version]'0.0' } } -Descending |
                Select-Object -ExpandProperty Version
                foreach ($v in $versions) {
                    $cmbVer.Items.Add($v)
                }
                if ($cmbVer.Items.Count -gt 0) { $cmbVer.SelectedIndex = 0 }
            }
        })

    # ── Keyboard shortcuts ──────────────────────────────────────────────────
    $Window.Add_PreviewKeyDown({
            param($sender, $e)
            $ctrl = [System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control
            if ($ctrl) {
                switch ($e.Key) {
                    'R' {
                        # Ctrl+R -- Refresh inventory (click the Inventory button)
                        $btn = $sender.FindName('BtnInventory')
                        if ($btn) {
                            $btn.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
                        }
                        $e.Handled = $true
                    }
                    'S' {
                        # Ctrl+S -- Open Settings dialog
                        Show-PSMMSettingsDialog
                        $e.Handled = $true
                    }
                    'E' {
                        # Ctrl+E -- Export inventory to CSV
                        $btn = $sender.FindName('BtnExportCsv')
                        if ($btn) {
                            $btn.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
                        }
                        $e.Handled = $true
                    }
                }
            }
            elseif ($e.Key -eq 'Escape') {
                # Escape -- Cancel running jobs
                Stop-PSMMAllJobs
                Write-PSMMLog -Severity 'WARN' -Message 'Jobs cancelled by user (Escape key).'
                $e.Handled = $true
            }
        })

    # ── Window Closing cleanup ───────────────────────────────────────────────
    $Window.Add_Closing({
            Write-PSMMLog -Severity 'INFO' -Message 'Application closing -- cleaning up ...'
            Close-PSMMRunspacePool
        })
}
#endregion WPF Event Handlers

#region Job Poller
# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher timer that polls runspace jobs and updates the UI.
# ─────────────────────────────────────────────────────────────────────────────

function Start-PSMMJobPoller {
    <#
    .SYNOPSIS
        Starts a WPF DispatcherTimer that polls job completion and updates the UI.
    .DESCRIPTION
        Uses $script:CurrentPollerOperation (not a local variable) so the tick
        handler can reliably read the operation label even after this function
        returns.  PowerShell .NET-event delegates do NOT capture function-local
        variables the way C# lambdas do -- using $script: scope is the fix.
    .PARAMETER Operation
        Label for the operation being polled (Inventory / Install / Update / Remove).
    #>
    [CmdletBinding()]
    param(
        [string]$Operation = 'Operation'
    )

    # ── Stop any previous poller ─────────────────────────────────────────────
    if ($script:JobPollerTimer) {
        try { $script:JobPollerTimer.Stop() } catch {}
        $script:JobPollerTimer = $null
    }

    # ── Store operation in script scope so the tick closure can read it ──────
    $script:CurrentPollerOperation = $Operation

    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:JobPollerTimer = $timer

    # ── Show progress bar ────────────────────────────────────────────────────
    $progressBar = Find-PSMMControl -Window $script:MainWindow -Name 'StatusProgress'
    if ($progressBar) {
        $progressBar.IsIndeterminate = $true
        $progressBar.Visibility = [System.Windows.Visibility]::Visible
    }

    $timer.Add_Tick({
            try {
                # ── 1. Harvest completed jobs ────────────────────────────────
                $completed = Receive-PSMMJobs
                $running   = @($script:Jobs | Where-Object { $_.Status -eq 'Running' }).Count

                # ── 2. Update status bar ─────────────────────────────────────
                $statusJobs = Find-PSMMControl -Window $script:MainWindow -Name 'StatusJobs'
                if ($statusJobs) {
                    $total = $script:Jobs.Count
                    $done  = @($script:Jobs | Where-Object { $_.Status -ne 'Running' }).Count
                    $statusJobs.Text = "Jobs: $done / $total  |  Running: $running  |  Pool: $($script:Settings.MaxConcurrency)"
                }

                # ── 3. Process completed results ─────────────────────────────
                $addedCount = 0
                foreach ($job in $completed) {
                    if (-not $job.Result) { continue }
                    foreach ($result in $job.Result) {
                        if ($result -is [PSCustomObject] -and $result.PSObject.Properties['ModuleName']) {
                            if ($result.ModuleName -eq '_ERROR_') { continue }

                            $script:ModuleGrid.Add([ModuleGridItem]@{
                                    ComputerName     = $result.ComputerName
                                    ModuleName       = $result.ModuleName
                                    InstalledVersion = $result.InstalledVersion
                                    TargetVersion    = ''
                                    Status           = 'Scanned'
                                    Model            = $result.Model
                                    OS               = $result.OS
                                    PSModulePath     = $result.ModuleBase
                                })
                            $addedCount++
                        }
                        elseif ($result -is [string]) {
                            Write-PSMMLog -Severity 'INFO' -Message $result -ComputerName $job.ComputerName
                        }
                    }
                }

                # ── 4. Force the DataGrid to repaint if rows were added ──────
                if ($addedCount -gt 0) {
                    $grid = Find-PSMMControl -Window $script:MainWindow -Name 'ModuleDataGrid'
                    if ($grid) {
                        $grid.Items.Refresh()
                        $grid.UpdateLayout()
                    }
                    Write-PSMMLog -Severity 'DEBUG' -Message "Poller: added $addedCount row(s) to grid (total: $($script:ModuleGrid.Count))."
                }

                # ── 5. All jobs finished? ────────────────────────────────────
                if ($running -eq 0 -and $script:Jobs.Count -gt 0) {
                    # Stop this timer
                    if ($script:JobPollerTimer) {
                        try { $script:JobPollerTimer.Stop() } catch {}
                        $script:JobPollerTimer = $null
                    }

                    # ── Hide progress bar ────────────────────────────────────
                    $progressBar = Find-PSMMControl -Window $script:MainWindow -Name 'StatusProgress'
                    if ($progressBar) {
                        $progressBar.IsIndeterminate = $false
                        $progressBar.Visibility = [System.Windows.Visibility]::Collapsed
                    }

                    Write-PSMMLog -Severity 'INFO' -Message "All jobs completed. Grid rows: $($script:ModuleGrid.Count)"

                    # ── 5a. Version comparison ───────────────────────────────
                    $shareModules = Get-PSMMShareModules
                    if ($shareModules.Count -gt 0 -and $script:ModuleGrid.Count -gt 0) {
                        $gridItems = @($script:ModuleGrid)
                        $compared  = Compare-PSMMModuleVersions -InstalledModules $gridItems -ShareModules $shareModules

                        $script:ModuleGrid.Clear()
                        foreach ($c in $compared) {
                            $script:ModuleGrid.Add($c)
                        }

                        # Force grid to show the enriched data
                        $grid = Find-PSMMControl -Window $script:MainWindow -Name 'ModuleDataGrid'
                        if ($grid) {
                            $grid.Items.Refresh()
                            $grid.UpdateLayout()
                        }
                        Write-PSMMLog -Severity 'DEBUG' -Message "Version comparison done. Grid rows: $($script:ModuleGrid.Count)"
                    }

                    # ── 5b. Auto-refresh after Install/Update/Remove ─────────
                    # NOTE: uses $script:CurrentPollerOperation -- NOT a local variable
                    $currentOp = $script:CurrentPollerOperation
                    if ($currentOp -in @('Install', 'Update', 'Remove')) {
                        $affectedComputers = @(
                            $script:Jobs |
                                Where-Object { $_.Status -ne 'Running' } |
                                ForEach-Object { $_.ComputerName } |
                                Select-Object -Unique
                        )
                        if ($affectedComputers.Count -gt 0) {
                            Write-PSMMLog -Severity 'INFO' -Message "Auto-refreshing inventory for $($affectedComputers.Count) computer(s) after $currentOp ..."

                            # Clear grid rows for affected computers
                            $toRemove = @($script:ModuleGrid | Where-Object { $affectedComputers -contains $_.ComputerName })
                            foreach ($item in $toRemove) { $script:ModuleGrid.Remove($item) }

                            # Module filter from combo box
                            $cmbMod    = Find-PSMMControl -Window $script:MainWindow -Name 'CmbModule'
                            $modFilter = if ($cmbMod -and $cmbMod.SelectedItem) { $cmbMod.SelectedItem.ToString() } else { $null }

                            # Reset jobs list so new poller starts clean
                            $script:Jobs.Clear()

                            # Launch inventory and start a fresh poller
                            $null = Get-PSMMRemoteModules -ComputerNames $affectedComputers -ModuleName $modFilter
                            Start-PSMMJobPoller -Operation 'Inventory'
                        }
                    }
                }
            }
            catch {
                Write-PSMMLog -Severity 'ERROR' -Message "Job poller tick error: $_"
                # Do NOT kill the timer on transient errors -- only stop if truly fatal
            }
        })

    Write-PSMMLog -Severity 'DEBUG' -Message "Job poller started (operation: $Operation, interval: 500ms)."
    $timer.Start()
}
#endregion Job Poller

#region ADSI Helper
# ─────────────────────────────────────────────────────────────────────────────
function Get-ADSIInfo {
    <#
    .SYNOPSIS
        Discovers DomainLdapPath and available OUs using ADSI.
    .DESCRIPTION
        Uses ADSI (no Active Directory module required) to determine the domain
        LDAP path and enumerate available OUs for use in settings.json.
    #>

    # ── Get Domain LDAP Path ────────────────────────────────────────────────────
    try {
        $rootDSE = [ADSI]"LDAP://RootDSE"
        $defaultNC = $rootDSE.defaultNamingContext.ToString()
        $domainLdapPath = "LDAP://$defaultNC"

        Write-Host "`n=== Domain Info ===" -ForegroundColor Cyan
        Write-Host "Domain LDAP Path : " -NoNewline; Write-Host $domainLdapPath -ForegroundColor Green
        Write-Host "Naming Context   : $defaultNC"
        Write-Host "DNS Host Name    : $($rootDSE.dnsHostName)"
    }
    catch {
        Write-Host "ADSI not available -- falling back to local computer." -ForegroundColor Yellow
        Write-Host $_.Exception.Message -ForegroundColor DarkYellow

        $localName = $env:COMPUTERNAME
        $localDns  = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $localName }
        $localOS   = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption

        Write-Host "`n=== Local Computer Info ===" -ForegroundColor Cyan
        Write-Host "Computer Name : " -NoNewline; Write-Host $localName -ForegroundColor Green
        Write-Host "DNS Host Name : $localDns"
        Write-Host "OS            : $localOS"
        Write-Host ""
        Write-Host "Tip: The tool will target this machine when ADSI is unavailable." -ForegroundColor Yellow
        return
    }

    # ── Enumerate OUs ───────────────────────────────────────────────────────────
    Write-Host "`n=== Available OUs ===" -ForegroundColor Cyan

    $searcher = [ADSISearcher]"(objectClass=organizationalUnit)"
    $searcher.SearchRoot = [ADSI]"LDAP://$defaultNC"
    $searcher.PageSize = 1000
    $searcher.PropertiesToLoad.AddRange(@("distinguishedName", "name", "description"))

    $ous = $searcher.FindAll() | ForEach-Object {
        [PSCustomObject]@{
            Name              = ($_.Properties["name"] | Select-Object -First 1)
            DistinguishedName = ($_.Properties["distinguishedname"] | Select-Object -First 1)
            Description       = ($_.Properties["description"] | Select-Object -First 1)
        }
    } | Sort-Object DistinguishedName

    if ($ous.Count -eq 0) {
        Write-Host "No OUs found." -ForegroundColor Yellow
    }
    else {
        Write-Host "Found $($ous.Count) OU(s):`n"
        $ous | Format-Table -Property Name, DistinguishedName, Description -AutoSize -Wrap

        # ── Suggested settings.json values ──────────────────────────────────────
        Write-Host "=== Suggested settings.json values ===" -ForegroundColor Cyan
        Write-Host '"DomainLdapPath": "' -NoNewline
        Write-Host $domainLdapPath -ForegroundColor Green -NoNewline
        Write-Host '"'
        Write-Host ""
        Write-Host "Pick an OuFilter from the list above, e.g.:" -ForegroundColor Yellow
        $ous | Select-Object -First 5 | ForEach-Object {
            Write-Host "  `"OuFilter`": `"$($_.DistinguishedName)`""
        }
    }
}
#endregion ADSI Helper

#region Settings Dialog
# ─────────────────────────────────────────────────────────────────────────────
# WPF settings editor modal dialog.
# ─────────────────────────────────────────────────────────────────────────────

function Show-PSMMSettingsDialog {
    <#
    .SYNOPSIS
        Opens the settings editor dialog.
    #>
    [CmdletBinding()]
    param()

    $settingsWin = New-PSMMWindow -Xaml $script:SettingsDialogXaml
    $settingsWin.Owner = $script:MainWindow

    # Cache references to avoid Find-PSMMControl inside closures (closure scope cannot resolve module-private functions)
    $txtLdap         = $settingsWin.FindName('TxtSettLdap')
    $txtOu           = $settingsWin.FindName('TxtSettOu')
    $txtSearchPaths  = $settingsWin.FindName('TxtSettSearchPaths')
    $txtShare        = $settingsWin.FindName('TxtSettShare')
    $txtLogPath      = $settingsWin.FindName('TxtSettLogPath')
    $txtConcurrency  = $settingsWin.FindName('TxtSettConcurrency')
    $txtRetry        = $settingsWin.FindName('TxtSettRetry')
    $txtTimeout      = $settingsWin.FindName('TxtSettTimeout')
    $credCombo       = $settingsWin.FindName('CmbSettCredMode')
    $logCombo        = $settingsWin.FindName('CmbSettLogLevel')
    $chkReachability   = $settingsWin.FindName('ChkReachability')
    $chkExclServers    = $settingsWin.FindName('ChkExcludeServers')
    $chkExclVirtual    = $settingsWin.FindName('ChkExcludeVirtual')
    $txtOsFilter       = $settingsWin.FindName('TxtOsFilter')
    $btnSave           = $settingsWin.FindName('BtnSettSave')
    $btnCancel       = $settingsWin.FindName('BtnSettCancel')
    $btnTestShare    = $settingsWin.FindName('BtnTestShare')
    $btnTestAD       = $settingsWin.FindName('BtnTestAD')
    $btnSettImport   = $settingsWin.FindName('BtnSettImport')
    $btnSettExport   = $settingsWin.FindName('BtnSettExport')

    # Populate fields
    $txtLdap.Text        = $script:Settings.DomainLdapPath
    $txtOu.Text          = $script:Settings.OuFilter
    $txtShare.Text       = $script:Settings.CentralSharePath
    $txtLogPath.Text     = $script:Settings.LogPath
    $txtConcurrency.Text = $script:Settings.MaxConcurrency.ToString()
    $txtRetry.Text       = $script:Settings.RetryCount.ToString()
    $txtTimeout.Text     = $script:Settings.JobTimeoutSeconds.ToString()

    # ModuleSearchPaths: join array to comma-separated string for display
    if ($script:Settings.ModuleSearchPaths -is [System.Collections.IEnumerable] -and $script:Settings.ModuleSearchPaths -isnot [string]) {
        $txtSearchPaths.Text = ($script:Settings.ModuleSearchPaths -join ', ')
    } else {
        $txtSearchPaths.Text = [string]$script:Settings.ModuleSearchPaths
    }

    # Set combo selections
    foreach ($item in $credCombo.Items) {
        if ($item.Content -eq $script:Settings.CredentialMode) {
            $credCombo.SelectedItem = $item
            break
        }
    }

    foreach ($item in $logCombo.Items) {
        if ($item.Content -eq $script:Settings.LogLevel) {
            $logCombo.SelectedItem = $item
            break
        }
    }

    $chkReachability.IsChecked = [bool]$script:Settings.ReachabilityCheck
    $chkExclServers.IsChecked    = [bool]$script:Settings.ExcludeServers
    $chkExclVirtual.IsChecked    = [bool]$script:Settings.ExcludeVirtual
    $txtOsFilter.Text            = $script:Settings.OSFilter

    # Capture module-scoped references as local variables so .GetNewClosure() can see them
    $settings        = $script:Settings          # hashtable reference -- mutations propagate
    $mainWin         = $script:MainWindow        # main window reference for syncing toolbar
    $fnTestSettings  = ${function:Test-PSMMSettings}
    $fnExportSettings = ${function:Export-PSMMSettings}
    $fnImportSettings = ${function:Import-PSMMSettings}
    $fnWriteLog      = ${function:Write-PSMMLog}

    # ── Save ─────────────────────────────────────────────────────────────────
    $btnSave.Add_Click({
            $settings['DomainLdapPath']    = $txtLdap.Text
            $settings['OuFilter']          = $txtOu.Text
            $settings['CentralSharePath']  = $txtShare.Text
            $settings['LogPath']           = $txtLogPath.Text
            $settings['MaxConcurrency']    = [int]($txtConcurrency.Text)
            $settings['RetryCount']        = [int]($txtRetry.Text)
            $settings['JobTimeoutSeconds'] = [int]($txtTimeout.Text)

            # Parse ModuleSearchPaths from comma-separated string back to array
            $settings['ModuleSearchPaths'] = @($txtSearchPaths.Text -split '\s*,\s*' | Where-Object { $_ -ne '' })

            $credSel = $credCombo.SelectedItem
            if ($credSel) { $settings['CredentialMode'] = $credSel.Content.ToString() }

            $logSel = $logCombo.SelectedItem
            if ($logSel) { $settings['LogLevel'] = $logSel.Content.ToString() }

            $settings['ReachabilityCheck'] = [bool]$chkReachability.IsChecked
            $settings['ExcludeServers']    = [bool]$chkExclServers.IsChecked
            $settings['ExcludeVirtual']    = [bool]$chkExclVirtual.IsChecked
            $settings['OSFilter']          = $txtOsFilter.Text

            # Validate
            $issues = & $fnTestSettings -Settings $settings
            if ($issues.Count -gt 0) {
                [System.Windows.MessageBox]::Show(($issues -join "`n"), 'Validation Issues', 'OK', 'Warning')
                return
            }

            & $fnExportSettings -Settings $settings
            & $fnWriteLog -Severity 'INFO' -Message 'Settings saved successfully.'

            # ── Sync main window toolbar controls with saved settings ────────
            if ($mainWin) {
                # Skip Servers / Skip Virtual checkboxes
                $chkSrv = $mainWin.FindName('ChkSkipServers')
                if ($chkSrv) { $chkSrv.IsChecked = [bool]$settings['ExcludeServers'] }

                $chkVm = $mainWin.FindName('ChkSkipVirtual')
                if ($chkVm) { $chkVm.IsChecked = [bool]$settings['ExcludeVirtual'] }

                # OU filter text box
                $ouBox = $mainWin.FindName('TxtOuFilter')
                if ($ouBox) { $ouBox.Text = [string]$settings['OuFilter'] }
            }

            $settingsWin.Close()
        }.GetNewClosure())

    # ── Cancel ───────────────────────────────────────────────────────────────
    $btnCancel.Add_Click({ $settingsWin.Close() }.GetNewClosure())

    # ── Import Settings ──────────────────────────────────────────────────────
    $btnSettImport.Add_Click({
            $dlg = [Microsoft.Win32.OpenFileDialog]::new()
            $dlg.Title  = 'Import Settings'
            $dlg.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
            if ($dlg.ShowDialog($settingsWin)) {
                try {
                    $imported = & $fnImportSettings -Path $dlg.FileName
                    if (-not $imported) {
                        [System.Windows.MessageBox]::Show('Failed to load settings from the selected file.', 'Import Error', 'OK', 'Error')
                        return
                    }
                    # Update UI fields from imported settings
                    $txtLdap.Text        = if ($imported.DomainLdapPath)    { $imported.DomainLdapPath }    else { '' }
                    $txtOu.Text          = if ($imported.OuFilter)          { $imported.OuFilter }          else { '' }
                    $txtShare.Text       = if ($imported.CentralSharePath)  { $imported.CentralSharePath }  else { '' }
                    $txtLogPath.Text     = if ($imported.LogPath)           { $imported.LogPath }           else { '' }
                    $txtConcurrency.Text = if ($imported.MaxConcurrency)    { $imported.MaxConcurrency.ToString() } else { '4' }
                    $txtRetry.Text       = if ($imported.RetryCount)        { $imported.RetryCount.ToString() }     else { '2' }
                    $txtTimeout.Text     = if ($imported.JobTimeoutSeconds) { $imported.JobTimeoutSeconds.ToString() } else { '300' }

                    if ($imported.ModuleSearchPaths -is [System.Collections.IEnumerable] -and $imported.ModuleSearchPaths -isnot [string]) {
                        $txtSearchPaths.Text = ($imported.ModuleSearchPaths -join ', ')
                    } elseif ($imported.ModuleSearchPaths) {
                        $txtSearchPaths.Text = [string]$imported.ModuleSearchPaths
                    }

                    if ($imported.CredentialMode) {
                        foreach ($ci in $credCombo.Items) {
                            if ($ci.Content -eq $imported.CredentialMode) { $credCombo.SelectedItem = $ci; break }
                        }
                    }
                    if ($imported.LogLevel) {
                        foreach ($li in $logCombo.Items) {
                            if ($li.Content -eq $imported.LogLevel) { $logCombo.SelectedItem = $li; break }
                        }
                    }

                    $chkReachability.IsChecked = if ($null -ne $imported.ReachabilityCheck) { [bool]$imported.ReachabilityCheck } else { $true }
                    $chkExclServers.IsChecked  = if ($null -ne $imported.ExcludeServers)    { [bool]$imported.ExcludeServers }    else { $false }
                    $chkExclVirtual.IsChecked  = if ($null -ne $imported.ExcludeVirtual)    { [bool]$imported.ExcludeVirtual }    else { $false }

                    & $fnWriteLog -Severity 'INFO' -Message "Settings imported from $($dlg.FileName) -- click Save to apply."
                    [System.Windows.MessageBox]::Show("Settings loaded from:`n$($dlg.FileName)`n`nReview values and click Save to apply.", 'Import Successful', 'OK', 'Information')
                }
                catch {
                    [System.Windows.MessageBox]::Show("Error importing settings:`n$_", 'Import Error', 'OK', 'Error')
                }
            }
        }.GetNewClosure())

    # ── Export Settings ──────────────────────────────────────────────────────
    $btnSettExport.Add_Click({
            $dlg = [Microsoft.Win32.SaveFileDialog]::new()
            $dlg.Title    = 'Export Settings'
            $dlg.Filter   = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
            $dlg.FileName = "PS-ModuleManager-Settings_$(Get-Date -Format 'yyyy-MM-dd').json"
            if ($dlg.ShowDialog($settingsWin)) {
                try {
                    & $fnExportSettings -Settings $settings -Path $dlg.FileName
                    & $fnWriteLog -Severity 'INFO' -Message "Settings exported to $($dlg.FileName)"
                    [System.Windows.MessageBox]::Show("Settings exported to:`n$($dlg.FileName)", 'Export Successful', 'OK', 'Information')
                }
                catch {
                    [System.Windows.MessageBox]::Show("Error exporting settings:`n$_", 'Export Error', 'OK', 'Error')
                }
            }
        }.GetNewClosure())

    # ── Test Share ───────────────────────────────────────────────────────────
    $btnTestShare.Add_Click({
            $sharePath = $txtShare.Text
            if ([string]::IsNullOrWhiteSpace($sharePath)) {
                [System.Windows.MessageBox]::Show('Central Share Path is empty.', 'Warning', 'OK', 'Warning')
            }
            elseif (Test-Path -LiteralPath $sharePath -ErrorAction SilentlyContinue) {
                [System.Windows.MessageBox]::Show("Share is accessible: $sharePath", 'Success', 'OK', 'Information')
            }
            else {
                [System.Windows.MessageBox]::Show("Share is NOT accessible: $sharePath", 'Failed', 'OK', 'Error')
            }
        }.GetNewClosure())

    # ── Test AD ──────────────────────────────────────────────────────────────
    $btnTestAD.Add_Click({
            try {
                $ldap = $txtLdap.Text
                $root = if ($ldap) { [ADSI]$ldap } else { [ADSI]'' }
                $name = $root.distinguishedName
                [System.Windows.MessageBox]::Show("AD connection successful.`nDomain: $name", 'Success', 'OK', 'Information')
            }
            catch {
                [System.Windows.MessageBox]::Show("AD connection failed:`n$_", 'Failed', 'OK', 'Error')
            }
        }.GetNewClosure())

    $settingsWin.ShowDialog() | Out-Null
}
#endregion Settings Dialog

#region Exported Function
# ─────────────────────────────────────────────────────────────────────────────
# The single public entry-point for the module.
# ─────────────────────────────────────────────────────────────────────────────

function Show-ModuleManagerGUI {
    <#
    .SYNOPSIS
        Launches the PS-ModuleManager WPF GUI.

    .DESCRIPTION
        Opens the PowerShell Module Manager graphical interface.  From the GUI you
        can discover domain-joined computers via ADSI, inventory installed PowerShell
        modules, and install / update / remove modules from a central network share.

        All operations are executed in parallel using a runspace pool, with real-time
        progress and logging visible in the application window.

    .PARAMETER SettingsPath
        Path to a custom settings.json file.  If not specified, the module looks for
        settings.json in the same directory as the module file.

    .PARAMETER WindowStartupLocation
        Specifies the initial position of the main window.  Default is 'CenterScreen'.
        Other options: 'Manual', 'WindowsDefaultLocation', 'WindowsDefaultBounds', 'CenterOwner'.

    .PARAMETER WindowState
        Specifies the initial window state.  Default is 'Normal'.  Other options: 'Minimized', 'Maximized'.

    .EXAMPLE
        Show-ModuleManagerGUI

        Opens the Module Manager GUI using default settings.

    .EXAMPLE
        Show-ModuleManagerGUI -SettingsPath 'C:\Config\settings.json'

        Opens the GUI with a custom configuration file.

    .EXAMPLE
        Show-ModuleManagerGUI -WindowStartupLocation CenterOwner -WindowState Maximized

        Opens the GUI centered on the owner window and maximized.

    .NOTES
        Requires Windows PowerShell 5.1+ with .NET Framework 4.5+ for WPF.
        WinRM must be enabled on target computers for remote operations.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Position = 0)]
        [string]$SettingsPath = $script:SettingsPath,

        [ValidateSet('Manual', 'CenterScreen', 'WindowsDefaultLocation', 'WindowsDefaultBounds', 'CenterOwner')]
        [string]$WindowStartupLocation = 'CenterScreen',

        [ValidateSet('Normal', 'Minimized', 'Maximized')]
        [string]$WindowState = 'Normal'
    )

    Write-Host 'Starting PS-ModuleManager ...' -ForegroundColor Cyan

    # ── Admin check ───────────────────────────────────────────────────────────
    $script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $script:IsAdmin) {
        Write-Host 'WARNING: Not running as Administrator. Install/Update/Remove operations will fail for system-wide module paths.' -ForegroundColor Yellow
    }

    # ── Load settings ────────────────────────────────────────────────────────
    $script:SettingsPath = $SettingsPath
    Import-PSMMSettings -Path $SettingsPath

    # ── Log rotation ─────────────────────────────────────────────────────────
    Invoke-PSMMLogRotation

    # ── Initialize runspace pool ─────────────────────────────────────────────
    New-PSMMRunspacePool

    # ── Handle credentials ───────────────────────────────────────────────────
    if ($script:Settings.CredentialMode -eq 'Prompt') {
        Get-PSMMCredential
    }

    # ── Build WPF window ────────────────────────────────────────────────────
    $script:MainWindow = New-PSMMWindow -Xaml $script:MainWindowXaml

    # Populate toolbar defaults from settings
    $ouBox = Find-PSMMControl -Window $script:MainWindow -Name 'TxtOuFilter'
    if ($ouBox -and $script:Settings.OuFilter) {
        $ouBox.Text = $script:Settings.OuFilter
    }

    # Set toolbar checkboxes from saved settings
    $chkSkipSrv = Find-PSMMControl -Window $script:MainWindow -Name 'ChkSkipServers'
    if ($chkSkipSrv) { $chkSkipSrv.IsChecked = [bool]$script:Settings.ExcludeServers }
    $chkSkipVm = Find-PSMMControl -Window $script:MainWindow -Name 'ChkSkipVirtual'
    if ($chkSkipVm) { $chkSkipVm.IsChecked = [bool]$script:Settings.ExcludeVirtual }

    # ── Wire event handlers ──────────────────────────────────────────────────
    Register-PSMMMainWindowEvents -Window $script:MainWindow

    # ── Bind the Computer list to its ObservableCollection ────────────────────
    $compListBox = Find-PSMMControl -Window $script:MainWindow -Name 'ComputerListBox'
    $script:ComputerList.Clear()
    $compListBox.ItemsSource = $script:ComputerList

    # ── Bind the Module Inventory grid to the ObservableCollection ────────────
    $grid = Find-PSMMControl -Window $script:MainWindow -Name 'ModuleDataGrid'
    $script:ModuleGrid.Clear()
    $grid.ItemsSource = $script:ModuleGrid

    # ── Initial log entry ────────────────────────────────────────────────────
    Write-PSMMLog -Severity 'INFO' -Message 'PS-ModuleManager v1.0.0 started.'
    Write-PSMMLog -Severity 'INFO' -Message "Settings loaded from: $SettingsPath"
    Write-PSMMLog -Severity 'INFO' -Message "Central share: $($script:Settings.CentralSharePath)"
    Write-PSMMLog -Severity 'INFO' -Message "Concurrency: $($script:Settings.MaxConcurrency) threads"

    if (-not $script:IsAdmin) {
        Write-PSMMLog -Severity 'WARN' -Message 'Not running as Administrator -- install/update/remove to system-wide module paths will require elevation.'
    }

    # ── Ensure window is topmost ───────────────────────────────────────────
    #$script:MainWindow.Topmost = $true

    # ── Set window properties ──────────────────────────────────────────────
    $script:MainWindow.WindowStartupLocation = $WindowStartupLocation
    $script:MainWindow.WindowState = $WindowState

    # ── Show the window (blocking) ───────────────────────────────────────────
    $script:MainWindow.ShowDialog() | Out-Null

    # ── Cleanup ──────────────────────────────────────────────────────────────
    Close-PSMMRunspacePool
    Write-Host 'PS-ModuleManager closed.' -ForegroundColor Cyan
}
#endregion Exported Function

# ─────────────────────────────────────────────────────────────────────────────
# Module auto-export
# ─────────────────────────────────────────────────────────────────────────────
Export-ModuleMember -Function 'Show-ModuleManagerGUI', 'Get-ADSIInfo'
