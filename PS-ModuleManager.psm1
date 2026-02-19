<#
.SYNOPSIS
    PS-ModuleManager -- A WPF-based PowerShell Module Manager.

.DESCRIPTION
    Provides a rich graphical interface to discover domain-joined computers via ADSI,
    inventory installed PowerShell modules, and install / update / remove modules from
    a central network share.  All WPF XAML is defined inline -- no external files needed.

    Architecture: SyncHash + Dispatcher pattern
      * The WPF window runs on a dedicated STA runspace
      * A synchronized hashtable ($syncHash) is shared between all runspaces
      * Background operations (AD queries, inventory, install/update/remove) each spawn
        their own runspace and update the UI via $syncHash.Window.Dispatcher.Invoke()
      * ObservableCollections with INotifyPropertyChanged provide automatic WPF data binding

    Key capabilities:
      * ADSI computer discovery with OU filtering and wildcard search
      * Parallel remote module inventory via runspace pool
      * Install / Update / Remove modules from a central ZIP-based share
      * Version comparison with color-coded status (Green / Orange / Red / Gray)
      * Persistent settings (settings.json) with built-in validation
      * Structured logging to file and scrollable UI pane
      * Thread-safe UI updates via Dispatcher.Invoke() from background runspaces

.NOTES
    Requires: Windows PowerShell 5.1+, .NET Framework 4.5+ (WPF)
    Remoting:  WinRM must be enabled on target computers.
    Author:    PS-ModuleManager Contributors
    Version:   2.0.0
#>

#requires -Version 5.1

#region Assembly Loading
# ---------------------------------------------------------------------------
# Load WPF assemblies and define data-binding C# classes.
# ---------------------------------------------------------------------------
Add-Type -AssemblyName PresentationFramework
Add-Type -AssemblyName PresentationCore
Add-Type -AssemblyName WindowsBase
Add-Type -AssemblyName System.Windows.Forms   # for FolderBrowserDialog fallback

# -- Define WPF-friendly data classes with INotifyPropertyChanged -------------
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
# ---------------------------------------------------------------------------
# Module-wide variables shared across functions.  Prefixed with $script: to
# keep them private to the module and avoid polluting the caller's scope.
# ---------------------------------------------------------------------------
$script:ModuleRoot = $PSScriptRoot
$script:SettingsPath = Join-Path $script:ModuleRoot 'settings.json'

# Runtime state
$script:Settings = $null   # [hashtable]  loaded from settings.json
$script:RunspacePool = $null   # [RunspacePool] for parallel remote ops
$script:Jobs = [System.Collections.ArrayList]::new()
$script:LogEntries = [System.Collections.ArrayList]::new()
$script:Credential = $null   # [PSCredential] when using Prompt/Stored mode

# SyncHash -- THE central synchronized hashtable shared between the UI runspace
# and all background worker runspaces.  Every named WPF control is stored here
# so that background threads can update the UI via Dispatcher.Invoke().
$script:SyncHash = [hashtable]::Synchronized(@{})

# ObservableCollections for WPF data binding
$script:ComputerList = [System.Collections.ObjectModel.ObservableCollection[ComputerItem]]::new()
$script:ModuleGrid = [System.Collections.ObjectModel.ObservableCollection[ModuleGridItem]]::new()
$script:JobQueue = [System.Collections.ObjectModel.ObservableCollection[PSObject]]::new()

# Timer references
$script:JobPollerTimer = $null
$script:CurrentPollerOperation = $null
#endregion Script-Scoped State


#region Configuration
# ---------------------------------------------------------------------------
# Settings management: defaults, import, export, validation.
# ---------------------------------------------------------------------------

function Get-PSMMDefaultSettings {
    <#
    .SYNOPSIS
        Returns a hashtable of sensible default settings.
    #>
    return @{
        DomainLdapPath    = ''
        OuFilter          = ''
        ModuleSearchPaths = @('C:\Program Files\WindowsPowerShell\Modules')
        CentralSharePath  = ''
        MaxConcurrency    = [Math]::Min(4, [Environment]::ProcessorCount)
        CredentialMode    = 'Default'
        LogPath           = Join-Path $script:ModuleRoot 'logs'
        LogLevel          = 'INFO'
        RetryCount        = 2
        ReachabilityCheck = $true
        JobTimeoutSeconds = 300
        ExcludeServers    = $false
        ExcludeVirtual    = $false
        OSFilter          = ''
        GlobalExcludeList = @()
    }
}

function Import-PSMMSettings {
    <#
    .SYNOPSIS
        Loads settings from a JSON file, falling back to defaults for missing keys.
    .PARAMETER Path
        Path to the settings JSON file.
    #>
    [CmdletBinding()]
    param(
        [string]$Path = $script:SettingsPath
    )

    $defaults = Get-PSMMDefaultSettings

    if (Test-Path -LiteralPath $Path) {
        try {
            $json = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json
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
        Export-PSMMSettings -Settings $defaults -Path $Path
    }

    $script:Settings = $defaults
    return $defaults
}

function Export-PSMMSettings {
    <#
    .SYNOPSIS
        Saves settings hashtable to a JSON file.
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
        Validates settings and returns an array of issue strings.
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
# ---------------------------------------------------------------------------
# Structured logging to file, in-memory buffer, and WPF log pane.
# Uses $script:SyncHash for thread-safe UI updates via Dispatcher.
# ---------------------------------------------------------------------------

function Write-PSMMLog {
    <#
    .SYNOPSIS
        Logs a message to file, memory buffer, and the WPF log pane (via Dispatcher).
    .PARAMETER Severity
        Log level: DEBUG, INFO, WARN, or ERROR.
    .PARAMETER Message
        The log message text.
    .PARAMETER ComputerName
        Optional computer context for the log entry.
    #>
    [CmdletBinding()]
    param(
        [ValidateSet('DEBUG', 'INFO', 'WARN', 'ERROR')]
        [string]$Severity = 'INFO',

        [Parameter(Mandatory)]
        [string]$Message,

        [string]$ComputerName = ''
    )

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

    # WPF pane update via SyncHash + Dispatcher (thread-safe from ANY runspace)
    if ($script:SyncHash.Window -and $script:SyncHash.Window.Dispatcher) {
        try {
            $capturedLine = $line
            $capturedMsg = $Message
            $sh = $script:SyncHash
            $sh.Window.Dispatcher.Invoke(
                [Action] {
                    if ($sh.LogListBox) {
                        $sh.LogListBox.Items.Add($capturedLine)
                        $sh.LogListBox.ScrollIntoView($sh.LogListBox.Items[$sh.LogListBox.Items.Count - 1])
                    }
                    if ($sh.StatusText) { $sh.StatusText.Text = $capturedMsg }
                },
                [System.Windows.Threading.DispatcherPriority]::Background
            )
        }
        catch { <# dispatcher may not be ready yet #> }
    }
}

function Invoke-PSMMLogRotation {
    <#
    .SYNOPSIS
        Removes old log files and enforces a total size cap.
    .PARAMETER LogPath
        Directory containing log files.
    .PARAMETER RetentionDays
        Files older than this are deleted.  Default: 30.
    .PARAMETER MaxTotalSizeMB
        Maximum total size of all log files.  Default: 10.
    #>
    [CmdletBinding()]
    param(
        [string]$LogPath = $(if ($script:Settings.LogPath) { $script:Settings.LogPath } else { Join-Path $script:ModuleRoot 'logs' }),
        [int]$RetentionDays = 30,
        [int]$MaxTotalSizeMB = 10
    )

    if (-not (Test-Path $LogPath)) { return }

    $cutoff = (Get-Date).AddDays(-$RetentionDays)
    $logFiles = Get-ChildItem -LiteralPath $LogPath -Filter '*.log' -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime

    $removed = 0

    # Remove files older than retention
    foreach ($f in $logFiles) {
        if ($f.LastWriteTime -lt $cutoff) {
            try { Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop; $removed++ }
            catch { <# skip #> }
        }
    }

    # Enforce total size cap
    $remaining = Get-ChildItem -LiteralPath $LogPath -Filter '*.log' -File -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime
    $totalBytes = ($remaining | Measure-Object -Property Length -Sum).Sum
    $maxBytes = $MaxTotalSizeMB * 1MB

    if ($totalBytes -gt $maxBytes) {
        foreach ($f in $remaining) {
            if ($totalBytes -le $maxBytes) { break }
            try {
                $totalBytes -= $f.Length
                Remove-Item -LiteralPath $f.FullName -Force -ErrorAction Stop
                $removed++
            }
            catch { <# skip #> }
        }
    }

    if ($removed -gt 0) {
        Write-PSMMLog -Severity 'INFO' -Message "Log rotation: removed $removed old log file(s)."
    }
}
#endregion Logging


#region ADSI Service
# ---------------------------------------------------------------------------
# Active Directory computer discovery using raw ADSI / DirectorySearcher.
# No RSAT or ActiveDirectory module required.
# ---------------------------------------------------------------------------

function ConvertTo-PSMMLdapSafeString {
    <#
    .SYNOPSIS
        Escapes LDAP special characters in user-provided filter strings.
    .DESCRIPTION
        Sanitizes input to prevent LDAP injection by escaping RFC 4515 special
        characters: backslash, parentheses, NUL, and optionally asterisk.
    .PARAMETER InputString
        The raw user input to sanitize.
    .PARAMETER EscapeWildcard
        If $true, also escapes the asterisk character. Default is $false.
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
        The LDAP path to search from.
    .PARAMETER NameFilter
        Wildcard filter for computer names.  Default: '*' (all).
    .PARAMETER EnabledOnly
        If $true, only returns enabled computer accounts.
    .PARAMETER TestReachability
        If $true, tests WinRM reachability on each discovered computer.
    .PARAMETER ExcludeServers
        If $true, excludes computers with Server OS.
    .PARAMETER ExcludeVirtual
        If $true, excludes virtual machines.
    .PARAMETER OSFilter
        Wildcard filter for OS.
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
        if ($LdapPath) {
            $root = [ADSI]$LdapPath
        }
        else {
            $root = [ADSI]''
        }

        $searcher = [System.DirectoryServices.DirectorySearcher]::new($root)
        $searcher.PageSize = 1000

        $safeNameFilter = ConvertTo-PSMMLdapSafeString -InputString $NameFilter
        $nameClause = "(cn=$safeNameFilter)"
        if ($EnabledOnly) {
            $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(operatingSystem=$($OSFilter))$nameClause(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
        }
        else {
            $searcher.Filter = "(&(objectCategory=computer)(objectClass=computer)(operatingSystem=$($OSFilter))$nameClause)"
        }

        $searcher.PropertiesToLoad.AddRange(@('cn', 'dnshostname', 'distinguishedname', 'operatingsystem', 'useraccountcontrol'))

        $results = $searcher.FindAll()
        Write-PSMMLog -Severity 'INFO' -Message "Found $($results.Count) computer(s) in AD."

        # Pre-build GlobalExcludeList for fast lookup
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

            # Skip GlobalExcludeList entries
            if ($hasExcludeList) {
                $excluded = $false
                foreach ($pattern in $excludeList) {
                    if ($name -like $pattern) { $excluded = $true; break }
                }
                if ($excluded) { $excludedCount++; continue }
            }

            $ou = if ($dn) { ($dn -split ',', 2)[1] } else { '' }
            $enabled = -not ($uac -band 2)

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

        $localName = $env:COMPUTERNAME
        $localDns = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $localName }
        $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue
        $localOS = $cs.Caption
        $localModel = $cs.Model

        $reachable = $null
        if ($TestReachability) {
            try { $null = Test-WSMan -ComputerName $localDns -ErrorAction Stop; $reachable = $true }
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

    # Post-filter
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

    # if ($OSFilter -and $OSFilter -ne '') {
    #     $before = $filtered.Count
    #     $filtered = @($filtered | Where-Object { $_.OS -like $OSFilter })
    #     $kept = $filtered.Count
    #     $skipped = $before - $kept
    #     if ($skipped -gt 0) { Write-PSMMLog -Severity 'INFO' -Message "Filtered to $kept computer(s) matching OS pattern '$OSFilter' ($skipped excluded)." }
    # }

    return $filtered
}
#endregion ADSI Service


#region Runspace Pool
# ---------------------------------------------------------------------------
# Shared runspace pool for parallel remote operations.
# ---------------------------------------------------------------------------

function New-PSMMRunspacePool {
    <#
    .SYNOPSIS
        Creates and opens a runspace pool with the configured concurrency.
    .PARAMETER MaxRunspaces
        Maximum number of concurrent runspaces.
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
        Queues one PowerShell instance per computer and returns job tracking objects.
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
                        $errorResult = $job.Result | Where-Object { $_.ModuleName -eq '_ERROR_' } | Select-Object -First 1
                        if ($errorResult) { $errMsg = $errorResult.ModuleBase }
                    }
                    if (-not $errMsg) { $errMsg = 'Unknown error (no details captured).' }
                    $job.Error = $errMsg
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
# ---------------------------------------------------------------------------
# Query installed modules locally or remotely and compare against central share.
# ---------------------------------------------------------------------------

function Get-PSMMRemoteModules {
    <#
    .SYNOPSIS
        Retrieves installed PowerShell modules from one or more remote computers.
    .PARAMETER ComputerNames
        Array of computer names to query.
    .PARAMETER ModuleName
        Optional module name to filter on.
    .PARAMETER Credential
        Optional PSCredential for remoting.
    .OUTPUTS
        [PSCustomObject[]] -- Job descriptors from the runspace pool.
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
    }
    else {
        Write-PSMMLog -Severity 'INFO' -Message "Inventorying all modules on $($ComputerNames.Count) computer(s) ..."
    }

    $inventoryScript = {
        param($Computer, $Cred, $ModFilter)
        try {
            if ($ModFilter) {
                $sb = [scriptblock]::Create("Get-Module -ListAvailable -Name '$ModFilter' | Select-Object Name, @{N = 'Version'; E = { `$_.Version.ToString() } }, ModuleBase")
            }
            else {
                $sb = { Get-Module -ListAvailable | Select-Object Name, @{N = 'Version'; E = { $_.Version.ToString() } }, ModuleBase }
            }

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
                $modules = & $sb
                $sysInfo = & $sysInfoSb
            }
            else {
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
                [PSCustomObject]@{
                    ComputerName     = $Computer
                    ModuleName       = $ModFilter
                    InstalledVersion = ''
                    ModuleBase       = ''
                    Model            = $model
                    OS               = $osCaption
                }
            }
            else {
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
        catch { <# Non-parseable version string -- skip #> }
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
# ---------------------------------------------------------------------------
# Install, update, and remove modules on remote computers.
# ---------------------------------------------------------------------------

function Get-PSMMModuleDependencies {
    <#
    .SYNOPSIS
        Reads the .psd1 manifest from a share module folder and returns RequiredModules.
    .PARAMETER SourcePath
        The path to the module version folder on the central share.
    .PARAMETER ModuleName
        The name of the module.
    .OUTPUTS
        [PSCustomObject[]] with ModuleName and optionally ModuleVersion.
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
            $innerSb = {
                param($ModName, $Ver, $StagingPath)
                $destRoot = Join-Path $env:ProgramFiles 'WindowsPowerShell\Modules'
                $destPath = Join-Path $destRoot "$ModName\$Ver"

                if (-not (Test-Path $destPath)) {
                    New-Item -ItemType Directory -Path $destPath -Force | Out-Null
                }

                $zipFile = Get-ChildItem -LiteralPath $StagingPath -Filter '*.zip' -ErrorAction SilentlyContinue | Select-Object -First 1
                if ($zipFile) {
                    $tempExtract = Join-Path $env:TEMP "PSMMExtract_$ModName_$Ver_$([guid]::NewGuid().ToString('N'))"
                    New-Item -ItemType Directory -Path $tempExtract -Force | Out-Null
                    try {
                        Add-Type -AssemblyName System.IO.Compression.FileSystem
                        [System.IO.Compression.ZipFile]::ExtractToDirectory($zipFile.FullName, $tempExtract)

                        $extractedDirs = Get-ChildItem -LiteralPath $tempExtract -Directory -ErrorAction SilentlyContinue
                        $extractedFiles = Get-ChildItem -LiteralPath $tempExtract -File -ErrorAction SilentlyContinue
                        if ($extractedDirs.Count -eq 1 -and $extractedFiles.Count -eq 0) {
                            Copy-Item -Path (Join-Path $extractedDirs[0].FullName '*') -Destination $destPath -Recurse -Force
                        }
                        else {
                            Copy-Item -Path "$tempExtract\*" -Destination $destPath -Recurse -Force
                        }
                    }
                    finally {
                        Remove-Item -LiteralPath $tempExtract -Recurse -Force -ErrorAction SilentlyContinue
                    }
                }
                else {
                    Copy-Item -Path "$StagingPath\*" -Destination $destPath -Recurse -Force
                }

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
                & $innerSb $ModName $Ver $Source
            }
            else {
                $session = $null
                try {
                    $sessionSplat = @{ ComputerName = $Computer; ErrorAction = 'Stop' }
                    if ($Cred) { $sessionSplat['Credential'] = $Cred }
                    $session = New-PSSession @sessionSplat

                    $remoteStagingPath = Invoke-Command -Session $session -ScriptBlock {
                        $p = Join-Path $env:TEMP "PSMMStaging_$([guid]::NewGuid().ToString('N'))"
                        New-Item -ItemType Directory -Path $p -Force | ForEach-Object { $_.FullName }
                    }

                    Copy-Item -Path "$Source\*" -Destination $remoteStagingPath -ToSession $session -Recurse -Force

                    Invoke-Command -Session $session -ScriptBlock $innerSb -ArgumentList @($ModName, $Ver, $remoteStagingPath)

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
        Specific version to remove.
    .PARAMETER ModulePath
        The actual path where the module is installed.
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
                Remove-Module -Name $ModName -Force -ErrorAction SilentlyContinue

                if ($KnownPath -and (Test-Path $KnownPath)) {
                    $target = $KnownPath
                }
                else {
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
            }
            else {
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
# ---------------------------------------------------------------------------
# Credential handling based on configured CredentialMode.
# ---------------------------------------------------------------------------

function Show-PSMMCredentialDialog {
    <#
    .SYNOPSIS
        Shows a custom WPF credential dialog (dark-themed, no WinForms dependency).
    .DESCRIPTION
        Replaces Get-Credential with a pure-WPF dialog that runs safely on the
        WPF dispatcher thread without deadlocking.
    .PARAMETER Message
        Prompt message shown in the dialog.
    .PARAMETER Owner
        Optional owner window for modal centering.
    .OUTPUTS
        [PSCredential] or $null if cancelled.
    #>
    [CmdletBinding()]
    param(
        [string]$Message = 'Enter credentials for remote operations',
        [System.Windows.Window]$Owner = $null
    )

    $credXaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Credentials"
    Width="420" Height="260"
    WindowStartupLocation="CenterOwner"
    ResizeMode="NoResize"
    Background="#1E1E1E"
    Foreground="#D4D4D4"
    FontFamily="Segoe UI"
    FontSize="13">
    <Window.Resources>
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
        <Style TargetType="TextBox">
            <Setter Property="Background"  Value="#3C3C3C"/>
            <Setter Property="Foreground"  Value="#D4D4D4"/>
            <Setter Property="BorderBrush" Value="#555555"/>
            <Setter Property="Padding"     Value="5,4"/>
        </Style>
        <!-- CheckBox Dark Theme -->
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#D4D4D4"/>
            <Setter Property="Background" Value="#3C3C3C"/>
            <Setter Property="BorderBrush" Value="#555555"/>
            <Setter Property="Margin" Value="0,2"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <BulletDecorator Background="Transparent">
                            <BulletDecorator.Bullet>
                                <Grid Width="16" Height="16">
                                    <Border x:Name="Border" Background="#3C3C3C" BorderBrush="#555555" BorderThickness="1" CornerRadius="2"/>
                                    <Path x:Name="CheckMark" Data="M 2 6 L 6 10 L 13 2" Stroke="#4EC9B0" StrokeThickness="2" Visibility="Collapsed" Margin="1"/>
                                </Grid>
                            </BulletDecorator.Bullet>
                            <ContentPresenter Margin="6,0,0,0" VerticalAlignment="Center" HorizontalAlignment="Left" RecognizesAccessKey="True"/>
                        </BulletDecorator>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="CheckMark" Property="Visibility" Value="Visible"/>
                                <Setter TargetName="Border" Property="Background" Value="#0E639C"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="#1177BB"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="BorderBrush" Value="#007ACC"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Foreground" Value="#6A6A6A"/>
                                <Setter TargetName="Border" Property="Background" Value="#2D2D30"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="#444444"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>
    <StackPanel Margin="20">
        <TextBlock Name="CredMessage" TextWrapping="Wrap" Foreground="#9CDCFE" Margin="0,0,0,12"/>
        <TextBlock Text="Username:" Foreground="#D4D4D4" Margin="0,0,0,4"/>
        <TextBox   Name="TxtCredUser" Margin="0,0,0,10"/>
        <TextBlock Text="Password:" Foreground="#D4D4D4" Margin="0,0,0,4"/>
        <PasswordBox Name="TxtCredPass" Background="#3C3C3C" Foreground="#D4D4D4"
                     BorderBrush="#555555" Padding="5,4" Margin="0,0,0,14"/>
        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
            <Button Name="BtnCredOK"     Content="OK"     IsDefault="True"/>
            <Button Name="BtnCredCancel" Content="Cancel" IsCancel="True" Background="#4A4A4A" BorderBrush="#5A5A5A"/>
        </StackPanel>
    </StackPanel>
</Window>
"@

    $credWin = New-PSMMWindow -Xaml $credXaml
    if ($Owner) { $credWin.Owner = $Owner }

    $credWin.FindName('CredMessage').Text = $Message
    $txtUser = $credWin.FindName('TxtCredUser')
    $txtPass = $credWin.FindName('TxtCredPass')
    $btnOK = $credWin.FindName('BtnCredOK')
    $btnCanc = $credWin.FindName('BtnCredCancel')

    # Pre-fill with DOMAIN\username
    $txtUser.Text = "$env:USERDOMAIN\$env:USERNAME"
    $txtUser.SelectAll()

    $credResult = $null

    $btnOK.Add_Click({
            $user = $txtUser.Text
            $pass = $txtPass.SecurePassword
            if ($user -and $pass.Length -gt 0) {
                $script:_CredDialogResult = [System.Management.Automation.PSCredential]::new($user, $pass)
                $credWin.DialogResult = $true
                $credWin.Close()
            }
            else {
                [System.Windows.MessageBox]::Show('Please enter both username and password.', 'Validation', 'OK', 'Warning')
            }
        }.GetNewClosure())

    $btnCanc.Add_Click({
            $script:_CredDialogResult = $null
            $credWin.DialogResult = $false
            $credWin.Close()
        }.GetNewClosure())

    $dialogOk = $credWin.ShowDialog()

    if ($dialogOk) {
        return $script:_CredDialogResult
    }
    return $null
}

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
            $script:Credential = Show-PSMMCredentialDialog -Message 'Enter credentials for remote operations' -Owner $script:SyncHash.Window
        }
        'Stored' {
            Write-PSMMLog -Severity 'INFO' -Message 'Using stored credentials from Windows Credential Manager.'
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
# ---------------------------------------------------------------------------
# The complete WPF UI is defined as inline XAML here-strings.
# No external .xaml files are needed.
# ---------------------------------------------------------------------------

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
                <Trigger Property="Orientation" Value="Vertical">
                    <Setter Property="MinWidth" Value="5" />
                    <Setter Property="Width" Value="5" />
                </Trigger>
                <Trigger Property="Orientation" Value="Horizontal">
                    <Setter Property="MinHeight" Value="5" />
                    <Setter Property="Height" Value="5" />
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- Color Palette -->
        <SolidColorBrush x:Key="PanelBg"       Color="#252526"/>
        <SolidColorBrush x:Key="BorderBrush"    Color="#3C3C3C"/>
        <SolidColorBrush x:Key="AccentBlue"     Color="#007ACC"/>
        <SolidColorBrush x:Key="TextPrimary"    Color="#D4D4D4"/>
        <SolidColorBrush x:Key="TextSecondary"  Color="#9E9E9E"/>
        <SolidColorBrush x:Key="GreenStatus"    Color="#4EC9B0"/>
        <SolidColorBrush x:Key="OrangeStatus"   Color="#CE9178"/>
        <SolidColorBrush x:Key="RedStatus"      Color="#F44747"/>
        <SolidColorBrush x:Key="GrayStatus"     Color="#6A6A6A"/>

        <!-- Button Style -->
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

        <!-- TextBox Style -->
        <Style TargetType="TextBox">
            <Setter Property="Background"    Value="#3C3C3C"/>
            <Setter Property="Foreground"    Value="#D4D4D4"/>
            <Setter Property="BorderBrush"   Value="#555555"/>
            <Setter Property="Padding"       Value="5,3"/>
            <Setter Property="Margin"        Value="3"/>
        </Style>

        <!-- DataGrid Style -->
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

        <!-- ListBox Style -->
        <Style TargetType="ListBox">
            <Setter Property="Background"  Value="#1E1E1E"/>
            <Setter Property="Foreground"  Value="#D4D4D4"/>
            <Setter Property="BorderBrush" Value="#3C3C3C"/>
        </Style>

        <!-- MenuItem Style -->
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

        <!-- Separator Style -->
        <Style TargetType="Separator">
            <Setter Property="Background" Value="#3C3C3C"/>
            <Setter Property="Margin"     Value="4,2"/>
        </Style>

        <!-- ComboBoxItem Style -->
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

        <!-- ComboBox ControlTemplate (dark dropdown popup) -->
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

        <!-- Server/VM pill toggle styles -->
        <Style x:Key="ServersPillBorderStyle" TargetType="Border">
            <Setter Property="Background" Value="#007ACC" />
            <Style.Triggers>
                <DataTrigger Binding="{Binding IsChecked, ElementName=ChkSkipServers}" Value="True">
                    <Setter Property="Background" Value="#444444" />
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="ServersPillTextStyle" TargetType="TextBlock">
            <Setter Property="Text" Value="Servers Included" />
            <Style.Triggers>
                <DataTrigger Binding="{Binding IsChecked, ElementName=ChkSkipServers}" Value="True">
                    <Setter Property="Text" Value="Servers Skipped" />
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="VirtualPillBorderStyle" TargetType="Border">
            <Setter Property="Background" Value="#007ACC" />
            <Style.Triggers>
                <DataTrigger Binding="{Binding IsChecked, ElementName=ChkSkipVirtual}" Value="True">
                    <Setter Property="Background" Value="#444444" />
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <Style x:Key="VirtualPillTextStyle" TargetType="TextBlock">
            <Setter Property="Text" Value="VMs Included" />
            <Style.Triggers>
                <DataTrigger Binding="{Binding IsChecked, ElementName=ChkSkipVirtual}" Value="True">
                    <Setter Property="Text" Value="VMs Skipped" />
                </DataTrigger>
            </Style.Triggers>
        </Style>

        <!-- CheckBox Dark Theme -->
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#D4D4D4"/>
            <Setter Property="Background" Value="#3C3C3C"/>
            <Setter Property="BorderBrush" Value="#555555"/>
            <Setter Property="Margin" Value="0,2"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <BulletDecorator Background="Transparent">
                            <BulletDecorator.Bullet>
                                <Grid Width="16" Height="16">
                                    <Border x:Name="Border" Background="#3C3C3C" BorderBrush="#555555" BorderThickness="1" CornerRadius="2"/>
                                    <Path x:Name="CheckMark" Data="M 2 6 L 6 10 L 13 2" Stroke="#4EC9B0" StrokeThickness="2" Visibility="Collapsed" Margin="1"/>
                                </Grid>
                            </BulletDecorator.Bullet>
                            <ContentPresenter Margin="6,0,0,0" VerticalAlignment="Center" HorizontalAlignment="Left" RecognizesAccessKey="True"/>
                        </BulletDecorator>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="CheckMark" Property="Visibility" Value="Visible"/>
                                <Setter TargetName="Border" Property="Background" Value="#0E639C"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="#1177BB"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="BorderBrush" Value="#007ACC"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Foreground" Value="#6A6A6A"/>
                                <Setter TargetName="Border" Property="Background" Value="#2D2D30"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="#444444"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

    </Window.Resources>

    <DockPanel>
        <!-- MENU BAR -->
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

        <!-- TOOLBAR -->
        <Border DockPanel.Dock="Top" Background="#252526" Padding="5,4" BorderBrush="#3C3C3C" BorderThickness="0,0,0,1">
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="Auto"/>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Orientation="Horizontal">
                    <Border BorderThickness="1" BorderBrush="#3C3C3C" Background="#252526" Margin="0" Padding="0">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="Name" VerticalAlignment="Center"  Margin="10,0,10,0"/>
                            <TextBox Name="TxtNameFilter" Width="250" Text="*" ToolTip="Computer name wildcard (e.g. WEB*)"/>
                        </StackPanel>
                    </Border>
                    <Button Name="BtnSearchAD" Content="&#x1F50D; Search AD" Margin="8,3"/>
                    <Separator Margin="10,2" Style="{x:Null}"/>
                    <Separator Margin="10,2" Style="{x:Null}"/>
                    
                </StackPanel>

                <Button Grid.Column="2" Name="BtnCredentials" Content="&#x1F511; Credentials" Background="#4A4A4A" BorderBrush="#5A5A5A"/>

            </Grid>
        </Border>

        <!-- STATUS BAR -->
        <Border DockPanel.Dock="Bottom" Background="#007ACC" Padding="8,3">
            <DockPanel>
                <TextBlock Name="StatusText" Text="Ready" Foreground="White" VerticalAlignment="Center"/>
                <ProgressBar Name="StatusProgress" Width="120" Height="12" IsIndeterminate="False"
                             Visibility="Collapsed" Margin="10,0" VerticalAlignment="Center"
                             Background="#005A9E" Foreground="#4EC9B0" BorderThickness="0"/>
                <TextBlock Name="StatusJobs" Text="" Foreground="White" HorizontalAlignment="Right" DockPanel.Dock="Right" VerticalAlignment="Center"/>
            </DockPanel>
        </Border>

        <!-- MAIN CONTENT -->
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

            <!-- LEFT: Computer List -->
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

            <!-- CENTER: Module Data Grid -->
            <DockPanel Grid.Column="2" Grid.Row="0" Margin="5,5,5,0">
                <DockPanel DockPanel.Dock="Top">
                    <TextBlock Text="Module Inventory" FontWeight="Bold" FontSize="14" Margin="5,5" Foreground="{StaticResource AccentBlue}"/>
                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                        <Button Name="BtnExportCsv" Content="🧾 Export CSV" BorderBrush="#0E639C" Margin="5,3" Padding="10,4" FontSize="11"/>
                        <Button Name="BtnClearGrid" Content="❌ Clear" Background="#4A4A4A" BorderBrush="#5A5A5A" Margin="5,3" Padding="10,4" FontSize="11"/>
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

            <!-- Log pane splitter -->
            <GridSplitter Grid.Column="2" Grid.Row="1" Height="4" Background="#3C3C3C" HorizontalAlignment="Stretch" VerticalAlignment="Center"/>

            <!-- BOTTOM CENTER: Log Pane -->
            <Border Grid.Column="2" Grid.Row="2" Background="{StaticResource PanelBg}" BorderBrush="{StaticResource BorderBrush}" BorderThickness="0,1,0,0">
                <DockPanel>
                    <DockPanel DockPanel.Dock="Top">
                        <TextBlock Text="Log" FontWeight="Bold" FontSize="13" Margin="8,5" Foreground="{StaticResource AccentBlue}"/>
                        <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                            <Button Name="BtnExportLog" Content="🧾 Export" BorderBrush="#0E639C" Margin="5,3" Padding="10,4" FontSize="11"/>
                            <Button Name="BtnClearLog" Content="❌ Clear" Background="#4A4A4A" BorderBrush="#5a5a5a" Margin="5,3" Padding="10,4" FontSize="11"/>
                        </StackPanel>
                    </DockPanel>
                    <ListBox Name="LogListBox" Margin="5,0,5,5" FontFamily="Consolas" FontSize="11.5" Background="#1E1E1E" BorderThickness="0"/>
                </DockPanel>
            </Border>

            <!-- Splitter -->
            <GridSplitter Grid.Column="3" Grid.Row="0" Grid.RowSpan="3" Width="4" Background="#3C3C3C" HorizontalAlignment="Center" VerticalAlignment="Stretch"/>

            <!-- RIGHT: Actions Panel -->
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

                    <CheckBox Name="ChkSkipServers" Content="Skip Servers" Margin="0,6,0,8"/>

                    <CheckBox Name="ChkSkipVirtual"  Content="Skip Virtual Machines" Margin="0,3,0,8"/>

                    <Separator Margin="0,12" Background="#3C3C3C"/>

                    <Button Name="BtnCancelJobs" Content="&#x23F9; Cancel Jobs" Background="#6A3030" BorderBrush="#8A4040"/>
                    <Button Name="BtnSettings"   Content="&#x2699; Settings"    Background="#4A4A4A" BorderBrush="#5A5A5A" Margin="3,10,3,3"/>
                </StackPanel>
            </Border>
        </Grid>
    </DockPanel>
</Window>
'@

# Settings Dialog XAML
$script:SettingsDialogXaml = @'
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="Settings -- PS-ModuleManager"
    Width="700" Height="760"
    MinWidth="700" MinHeight="760"
    WindowStartupLocation="CenterOwner"
    ResizeMode="NoResize"
    Background="#1E1E1E"
    Foreground="#D4D4D4"
    FontFamily="Segoe UI"
    FontSize="13">

    <Window.Resources>
        <Style TargetType="{x:Type ScrollBar}">
            <Style.Triggers>
                <Trigger Property="Orientation" Value="Vertical">
                    <Setter Property="MinWidth" Value="5" />
                    <Setter Property="Width" Value="5" />
                </Trigger>
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

        <!-- CheckBox Dark Theme -->
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#D4D4D4"/>
            <Setter Property="Background" Value="#3C3C3C"/>
            <Setter Property="BorderBrush" Value="#555555"/>
            <Setter Property="Margin" Value="0,2"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <BulletDecorator Background="Transparent">
                            <BulletDecorator.Bullet>
                                <Grid Width="16" Height="16">
                                    <Border x:Name="Border" Background="#3C3C3C" BorderBrush="#555555" BorderThickness="1" CornerRadius="2"/>
                                    <Path x:Name="CheckMark" Data="M 2 6 L 6 10 L 13 2" Stroke="#4EC9B0" StrokeThickness="2" Visibility="Collapsed" Margin="1"/>
                                </Grid>
                            </BulletDecorator.Bullet>
                            <ContentPresenter Margin="6,0,0,0" VerticalAlignment="Center" HorizontalAlignment="Left" RecognizesAccessKey="True"/>
                        </BulletDecorator>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="CheckMark" Property="Visibility" Value="Visible"/>
                                <Setter TargetName="Border" Property="Background" Value="#0E639C"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="#1177BB"/>
                            </Trigger>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="Border" Property="BorderBrush" Value="#007ACC"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Foreground" Value="#6A6A6A"/>
                                <Setter TargetName="Border" Property="Background" Value="#2D2D30"/>
                                <Setter TargetName="Border" Property="BorderBrush" Value="#444444"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
    </Window.Resources>

    <Grid >
        <Grid.RowDefinitions>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <ScrollViewer VerticalScrollBarVisibility="Auto">
            <StackPanel Margin="20,20,20,0">
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

                <CheckBox Name="ChkReachability" Content="Test WinRM reachability before operations" Foreground="#D4D4D4" IsChecked="True" Margin="0,4"/>
                <CheckBox Name="ChkExcludeServers" Content="Exclude Server OS computers by default" Foreground="#D4D4D4" Margin="0,4"/>
                <CheckBox Name="ChkExcludeVirtual" Content="Exclude virtual machines by default" Foreground="#D4D4D4" Margin="0,4"/>

                <TextBlock Text="OS Filter (wildcards supported, e.g. '*Windows 10*'):" Foreground="#CCCCCC" Margin="0,12,0,2"/>
                <TextBox Name="TxtOsFilter" Background="#3C3C3C" Foreground="#D4D4D4" BorderBrush="#5A5A5A" Padding="4" ToolTip="Filter computers by OS. Leave empty for no filter."/>
            </StackPanel>
        </ScrollViewer>

        <StackPanel Grid.Row="1" Orientation="Horizontal" HorizontalAlignment="Right" Margin="20,10">
            <Button Name="BtnSettImport" Content="➕ Import"      Background="#4A4A4A" BorderBrush="#5A5A5A"/>
            <Button Name="BtnSettExport" Content="⬆️ Export"      Background="#4A4A4A" BorderBrush="#5A5A5A"/>
            <Button Name="BtnTestShare"  Content="Test Share"  Background="#4A4A4A" BorderBrush="#5A5A5A"/>
            <Button Name="BtnTestAD"     Content="Test AD"     Background="#4A4A4A" BorderBrush="#5A5A5A"/>
            <Button Name="BtnSettSave"   Content="💾 Save"/>
            <Button Name="BtnSettCancel" Content="❌Cancel"      Background="#6A3030" BorderBrush="#6A3030"/>
        </StackPanel>
    </Grid>
</Window>
'@

#endregion WPF XAML Definition


#region SyncHash Helpers
# ---------------------------------------------------------------------------
# Functions to initialize the synchronized hashtable with all named WPF
# controls, and to perform thread-safe UI updates via Dispatcher.Invoke().
#
# This is THE core of the new architecture:
#   1. $syncHash.Window holds the WPF Window reference
#   2. $syncHash.<ControlName> holds every named control
#   3. Background runspaces receive $syncHash and update UI via:
#        $syncHash.Window.Dispatcher.Invoke([Action]{ ... })
# ---------------------------------------------------------------------------

function Initialize-PSMMSyncHash {
    <#
    .SYNOPSIS
        Populates $script:SyncHash with the Window and all named controls.
    .DESCRIPTION
        After parsing XAML, this function walks the visual tree and stores every
        named WPF control in $script:SyncHash so background runspaces can
        reference them via Dispatcher.Invoke().
    .PARAMETER Window
        The parsed WPF Window object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [System.Windows.Window]$Window
    )

    $script:SyncHash.Window = $Window

    # Store all named controls in the syncHash
    $controlNames = @(
        # Toolbar
        'TxtOuFilter', 'TxtNameFilter', 'BtnSearchAD', 'BtnCredentials',
        'ChkSkipServers', 'ChkSkipVirtual',
        # Menu items
        'MenuSettings', 'MenuExit', 'MenuRefreshAD', 'MenuTestConn', 'MenuCancelJobs', 'MenuAbout',
        # Computer list
        'ComputerListBox', 'TxtComputerCount',
        'BtnSelectAll', 'BtnDeselectAll', 'BtnInvertSelect',
        # Module grid
        'ModuleDataGrid', 'BtnExportCsv', 'BtnClearGrid',
        # Log pane
        'LogListBox', 'BtnExportLog', 'BtnClearLog',
        # Actions panel
        'BtnInventory', 'BtnInstall', 'BtnUpdate', 'BtnRemove',
        'CmbModule', 'CmbVersion',
        'BtnCancelJobs', 'BtnSettings',
        # Status bar
        'StatusText', 'StatusProgress', 'StatusJobs'
    )

    foreach ($name in $controlNames) {
        $control = $Window.FindName($name)
        if ($control) {
            $script:SyncHash[$name] = $control
        }
    }

    # Store the ObservableCollections so background runspaces can reference them
    $script:SyncHash.ComputerList = $script:ComputerList
    $script:SyncHash.ModuleGrid = $script:ModuleGrid

    Write-PSMMLog -Severity 'DEBUG' -Message "SyncHash initialized with $($controlNames.Count) control references."
}

function Invoke-PSMMDispatcherUpdate {
    <#
    .SYNOPSIS
        Invokes an action on the WPF UI thread via the syncHash Dispatcher.
    .DESCRIPTION
        Thread-safe way to update any WPF control from a background runspace.
        The $syncHash.Window.Dispatcher.Invoke() pattern ensures all UI mutations
        happen on the STA thread that owns the WPF objects.
    .PARAMETER Action
        The script block to run on the UI thread.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    if ($script:SyncHash.Window -and $script:SyncHash.Window.Dispatcher) {
        $script:SyncHash.Window.Dispatcher.Invoke(
            $Action,
            [System.Windows.Threading.DispatcherPriority]::Background
        )
    }
}

function Invoke-PSMMBackgroundRunspace {
    <#
    .SYNOPSIS
        Spawns a new background runspace that has access to the syncHash.
    .DESCRIPTION
        Creates a new runspace, injects the $syncHash variable, runs the
        given script block asynchronously, and returns the runspace/handle
        for optional tracking.  The script block should update the UI
        exclusively via $syncHash.Window.Dispatcher.Invoke([Action]{...}).
    .PARAMETER ScriptBlock
        The code to execute in the background. It receives $syncHash as
        a variable in scope.
    .PARAMETER ArgumentList
        Additional variables to inject into the runspace as named variables.
        Pass as a hashtable of @{ VarName = Value }.
    .OUTPUTS
        [PSCustomObject] with Runspace, PowerShell, and Handle properties.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [scriptblock]$ScriptBlock,

        [hashtable]$ArgumentList = @{}
    )

    $rs = [RunspaceFactory]::CreateRunspace()
    $rs.ApartmentState = [System.Threading.ApartmentState]::STA
    $rs.ThreadOptions = [System.Management.Automation.Runspaces.PSThreadOptions]::ReuseThread
    $rs.Open()

    # Inject syncHash into the new runspace
    $rs.SessionStateProxy.SetVariable('syncHash', $script:SyncHash)

    # Inject any additional variables
    foreach ($key in $ArgumentList.Keys) {
        $rs.SessionStateProxy.SetVariable($key, $ArgumentList[$key])
    }

    $ps = [PowerShell]::Create().AddScript($ScriptBlock)
    $ps.Runspace = $rs
    $handle = $ps.BeginInvoke()

    return [PSCustomObject]@{
        Runspace   = $rs
        PowerShell = $ps
        Handle     = $handle
    }
}
#endregion SyncHash Helpers


#region WPF Helpers
# ---------------------------------------------------------------------------
# Utility functions for creating and interacting with WPF windows.
# ---------------------------------------------------------------------------

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

function Invoke-PSMMSafeAction {
    <#
    .SYNOPSIS
        Wraps a script block in try/catch for safe UI event handling.
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
#endregion WPF Helpers


#region WPF Event Handlers
# ---------------------------------------------------------------------------
# Event handler functions wired to WPF controls.
# All handlers use the $syncHash pattern for thread-safe UI updates.
# Background operations spawn child runspaces with $syncHash access.
# ---------------------------------------------------------------------------

function Register-PSMMMainWindowEvents {
    <#
    .SYNOPSIS
        Wires up all event handlers for the main window controls.
    .DESCRIPTION
        Each handler that runs a long operation spawns a background runspace
        (via Invoke-PSMMBackgroundRunspace) that receives the $syncHash for
        thread-safe Dispatcher.Invoke() UI updates.
    .PARAMETER Window
        The main WPF Window object.
    #>
    [CmdletBinding()]
    param(
        [System.Windows.Window]$Window
    )

    $sh = $script:SyncHash

    # -- Seed main-window checkboxes from current settings ----------------------
    $sh.ChkSkipServers.IsChecked = [bool]$script:Settings.ExcludeServers
    $sh.ChkSkipVirtual.IsChecked = [bool]$script:Settings.ExcludeVirtual

    # Two-way sync: main-window checkbox -> $script:Settings (and persist)
    $chkSkipServersHandler = {
        $script:Settings['ExcludeServers'] = ($script:SyncHash.ChkSkipServers.IsChecked -eq $true)
        Export-PSMMSettings -Settings $script:Settings
    }
    $chkSkipVirtualHandler = {
        $script:Settings['ExcludeVirtual'] = ($script:SyncHash.ChkSkipVirtual.IsChecked -eq $true)
        Export-PSMMSettings -Settings $script:Settings
    }
    $sh.ChkSkipServers.Add_Checked($chkSkipServersHandler)
    $sh.ChkSkipServers.Add_Unchecked($chkSkipServersHandler)
    $sh.ChkSkipVirtual.Add_Checked($chkSkipVirtualHandler)
    $sh.ChkSkipVirtual.Add_Unchecked($chkSkipVirtualHandler)

    # -- Search AD (spawns background runspace) --------------------------------
    $sh.BtnSearchAD.Add_Click({
            Invoke-PSMMSafeAction -Context 'AD Search' -Action {
                $ouFilter = $script:SyncHash.TxtOuFilter.Text
                $nameFilter = $script:SyncHash.TxtNameFilter.Text
                if (-not $nameFilter) { $nameFilter = '*' }

                $ldapPath = if ($ouFilter) { "LDAP://$ouFilter" } else { $script:Settings.DomainLdapPath }

                # Update status immediately via Dispatcher
                Invoke-PSMMDispatcherUpdate -Action {
                    $script:SyncHash.StatusText.Text = 'Searching Active Directory ...'
                    $script:SyncHash.StatusProgress.IsIndeterminate = $true
                    $script:SyncHash.StatusProgress.Visibility = [System.Windows.Visibility]::Visible
                }

                Write-PSMMLog -Severity 'INFO' -Message "Searching AD: OU=$ouFilter, Name=$nameFilter"

                try {
                    $skipServers = $script:SyncHash.ChkSkipServers.IsChecked -eq $true
                    $skipVirtual = $script:SyncHash.ChkSkipVirtual.IsChecked -eq $true
                    $computers = Get-PSMMComputers -LdapPath $ldapPath -NameFilter $nameFilter -ExcludeServers $skipServers -ExcludeVirtual $skipVirtual

                    $localName = $env:COMPUTERNAME

                    # Update the ObservableCollection on the UI thread
                    $script:ComputerList.Clear()
                    foreach ($c in $computers) {
                        $connStatus = if ($c.Name -eq $localName -or $c.Name -eq 'localhost') {
                            'Local'
                        }
                        elseif ($c.Reachable -eq $true) {
                            'WinRM'
                        }
                        elseif ($c.Reachable -eq $false) {
                            'Unreachable'
                        }
                        else {
                            'Unknown'
                        }

                        $autoSelect = $connStatus -in @('Local', 'WinRM')

                        $script:ComputerList.Add([ComputerItem]@{
                                IsSelected       = $autoSelect
                                Name             = $c.Name
                                ConnectionStatus = $connStatus
                            })
                    }

                    # Update count text
                    $script:SyncHash.TxtComputerCount.Text = "$($computers.Count) computers"

                    # Hide progress
                    Invoke-PSMMDispatcherUpdate -Action {
                        $script:SyncHash.StatusProgress.IsIndeterminate = $false
                        $script:SyncHash.StatusProgress.Visibility = [System.Windows.Visibility]::Collapsed
                        $script:SyncHash.StatusText.Text = "Found $($script:ComputerList.Count) computer(s)"
                    }
                }
                catch {
                    Write-PSMMLog -Severity 'ERROR' -Message "AD search failed: $_"
                    Invoke-PSMMDispatcherUpdate -Action {
                        $script:SyncHash.StatusProgress.IsIndeterminate = $false
                        $script:SyncHash.StatusProgress.Visibility = [System.Windows.Visibility]::Collapsed
                        $script:SyncHash.StatusText.Text = 'AD search failed'
                    }
                    [System.Windows.MessageBox]::Show("AD search failed:`n$_", 'Error', 'OK', 'Error')
                }
            }
        })

    # -- Inventory (uses runspace pool + job poller) ----------------------------
    $sh.BtnInventory.Add_Click({
            Invoke-PSMMSafeAction -Context 'Inventory' -Action {
                $selected = @($script:ComputerList | Where-Object { $_.IsSelected } | ForEach-Object { $_.Name })

                if ($selected.Count -eq 0) {
                    [System.Windows.MessageBox]::Show('Check one or more computers first.', 'Info', 'OK', 'Information')
                    return
                }

                $cmbMod = $script:SyncHash.CmbModule
                $modFilter = if ($cmbMod.SelectedItem) { $cmbMod.SelectedItem.ToString() } else { $null }

                if ($modFilter) {
                    Write-PSMMLog -Severity 'INFO' -Message "Starting inventory for '$modFilter' on $($selected.Count) computer(s) ..."
                }
                else {
                    Write-PSMMLog -Severity 'INFO' -Message "Starting inventory (all modules) on $($selected.Count) computer(s) ..."
                }

                # Mark existing rows for selected computers as scanning (observable update)
                foreach ($item in $script:ModuleGrid) {
                    if ($selected -contains $item.ComputerName) {
                        $item.Status = 'Scanning...'
                    }
                }

                # Launch async inventory
                $null = Get-PSMMRemoteModules -ComputerNames $selected -ModuleName $modFilter

                # Start polling via DispatcherTimer
                Start-PSMMJobPoller -Operation 'Inventory'
            }
        })

    # -- Install ---------------------------------------------------------------
    $sh.BtnInstall.Add_Click({
            Invoke-PSMMSafeAction -Context 'Install' -Action {
                $cmbMod = $script:SyncHash.CmbModule
                $cmbVer = $script:SyncHash.CmbVersion

                $selected = @($script:ComputerList | Where-Object { $_.IsSelected } | ForEach-Object { $_.Name })

                if ($selected.Count -eq 0 -or -not $cmbMod.SelectedItem) {
                    [System.Windows.MessageBox]::Show('Check computer(s) and select a module.', 'Info', 'OK', 'Information')
                    return
                }

                $modName = $cmbMod.SelectedItem.ToString()
                $version = if ($cmbVer.SelectedItem) { $cmbVer.SelectedItem.ToString() } else { $null }

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

    # -- Update ----------------------------------------------------------------
    $sh.BtnUpdate.Add_Click({
            Invoke-PSMMSafeAction -Context 'Update' -Action {
                $grid = $script:SyncHash.ModuleDataGrid
                $outdated = @()
                foreach ($item in $grid.SelectedItems) {
                    if ($item.Status -eq 'Outdated') { $outdated += $item }
                }

                if ($outdated.Count -eq 0) {
                    [System.Windows.MessageBox]::Show('Select outdated module rows in the grid.', 'Info', 'OK', 'Information')
                    return
                }

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

    # -- Remove ----------------------------------------------------------------
    $sh.BtnRemove.Add_Click({
            Invoke-PSMMSafeAction -Context 'Remove' -Action {
                $grid = $script:SyncHash.ModuleDataGrid

                if ($grid.SelectedItems.Count -eq 0) {
                    [System.Windows.MessageBox]::Show('Select module rows to remove.', 'Info', 'OK', 'Information')
                    return
                }

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

    # -- Cancel Jobs -----------------------------------------------------------
    $sh.BtnCancelJobs.Add_Click({
            Stop-PSMMAllJobs
            Write-PSMMLog -Severity 'WARN' -Message 'All jobs cancelled by user.'
        })

    # -- Select All / Deselect All / Invert ------------------------------------
    $sh.BtnSelectAll.Add_Click({
            foreach ($item in $script:ComputerList) { $item.IsSelected = $true }
        })

    $sh.BtnDeselectAll.Add_Click({
            foreach ($item in $script:ComputerList) { $item.IsSelected = $false }
        })

    $sh.BtnInvertSelect.Add_Click({
            foreach ($item in $script:ComputerList) { $item.IsSelected = -not $item.IsSelected }
        })

    # -- Clear Module Grid -----------------------------------------------------
    $sh.BtnClearGrid.Add_Click({
            $script:ModuleGrid.Clear()
        })

    # -- Export Inventory to CSV -----------------------------------------------
    $sh.BtnExportCsv.Add_Click({
            Invoke-PSMMSafeAction -Context 'Export CSV' -Action {
                if ($script:ModuleGrid.Count -eq 0) {
                    [System.Windows.MessageBox]::Show('No inventory data to export.', 'Info', 'OK', 'Information')
                    return
                }
                $dlg = [Microsoft.Win32.SaveFileDialog]::new()
                $dlg.Title = 'Export Module Inventory'
                $dlg.Filter = 'CSV files (*.csv)|*.csv|All files (*.*)|*.*'
                $dlg.FileName = "ModuleInventory_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').csv"
                if ($dlg.ShowDialog($script:SyncHash.Window)) {
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

    # -- Export Log -------------------------------------------------------------
    $sh.BtnExportLog.Add_Click({
            $logBox = $script:SyncHash.LogListBox
            if ($logBox.Items.Count -eq 0) {
                [System.Windows.MessageBox]::Show('No log entries to export.', 'Info', 'OK', 'Information')
                return
            }
            $dlg = [Microsoft.Win32.SaveFileDialog]::new()
            $dlg.Title = 'Export Log'
            $dlg.Filter = 'Log files (*.log)|*.log|Text files (*.txt)|*.txt|All files (*.*)|*.*'
            $dlg.FileName = "PS-ModuleManager_$(Get-Date -Format 'yyyy-MM-dd_HHmmss').log"
            if ($dlg.ShowDialog($script:SyncHash.Window)) {
                try {
                    $logBox.Items | Out-File -FilePath $dlg.FileName -Encoding UTF8
                    Write-PSMMLog -Severity 'INFO' -Message "Log exported to $($dlg.FileName)"
                }
                catch {
                    [System.Windows.MessageBox]::Show("Failed to export log:`n$_", 'Error', 'OK', 'Error')
                }
            }
        })

    # -- Clear Log -------------------------------------------------------------
    $sh.BtnClearLog.Add_Click({
            $script:SyncHash.LogListBox.Items.Clear()
        })

    # -- Settings --------------------------------------------------------------
    $sh.BtnSettings.Add_Click({ Show-PSMMSettingsDialog })
    $sh.MenuSettings.Add_Click({ Show-PSMMSettingsDialog })

    # -- Credentials -----------------------------------------------------------
    # Uses a custom WPF credential dialog (no WinForms Get-Credential deadlock).
    $sh.BtnCredentials.Add_Click({
            Invoke-PSMMSafeAction -Context 'Credentials' -Action {
                $cred = Show-PSMMCredentialDialog -Message 'Enter credentials for remote operations' -Owner $script:SyncHash.Window
                if ($cred) {
                    $script:Credential = $cred
                    Write-PSMMLog -Severity 'INFO' -Message "Credentials set for user: $($cred.UserName)"
                }
            }
        })

    # -- Menu: Refresh AD ------------------------------------------------------
    $sh.MenuRefreshAD.Add_Click({
            $script:SyncHash.BtnSearchAD.RaiseEvent(
                [System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent)
            )
        })

    # -- Menu: Test Connectivity -----------------------------------------------
    $sh.MenuTestConn.Add_Click({
            $issues = Test-PSMMSettings
            if ($issues.Count -eq 0) {
                [System.Windows.MessageBox]::Show('All settings are valid and paths are accessible.', 'Connectivity OK', 'OK', 'Information')
            }
            else {
                [System.Windows.MessageBox]::Show(($issues -join "`n"), 'Settings Issues', 'OK', 'Warning')
            }
        })

    # -- Menu: Cancel All ------------------------------------------------------
    $sh.MenuCancelJobs.Add_Click({
            Stop-PSMMAllJobs
            Write-PSMMLog -Severity 'WARN' -Message 'All jobs cancelled by user.'
        })

    # -- Menu: About -----------------------------------------------------------
    $sh.MenuAbout.Add_Click({
            [System.Windows.MessageBox]::Show(
                "PS-ModuleManager v2.0.0`n`nA WPF-based PowerShell Module Manager for installing, updating, and removing modules on domain-joined computers.`n`nArchitecture: SyncHash + Dispatcher pattern`nPowered by ADSI, WinRM, and Runspace Pools.",
                'About PS-ModuleManager', 'OK', 'Information')
        })

    # -- Menu: Exit ------------------------------------------------------------
    $sh.MenuExit.Add_Click({
            $script:SyncHash.Window.Close()
        })

    # -- Module ComboBox population --------------------------------------------
    $sh.CmbModule.Add_DropDownOpened({
            $cmb = $script:SyncHash.CmbModule
            $cmb.Items.Clear()
            $shareModules = Get-PSMMShareModules
            $moduleNames = $shareModules | Select-Object -ExpandProperty ModuleName -Unique | Sort-Object
            foreach ($name in $moduleNames) {
                $cmb.Items.Add($name)
            }
        })

    # -- Version ComboBox population -------------------------------------------
    $sh.CmbModule.Add_SelectionChanged({
            $cmbMod = $script:SyncHash.CmbModule
            $cmbVer = $script:SyncHash.CmbVersion
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

    # -- Keyboard shortcuts ----------------------------------------------------
    $Window.Add_PreviewKeyDown({
            param($send, $e)
            $ctrl = [System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control
            if ($ctrl) {
                switch ($e.Key) {
                    'R' {
                        $btn = $send.FindName('BtnInventory')
                        if ($btn) {
                            $btn.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
                        }
                        $e.Handled = $true
                    }
                    'S' {
                        Show-PSMMSettingsDialog
                        $e.Handled = $true
                    }
                    'E' {
                        $btn = $send.FindName('BtnExportCsv')
                        if ($btn) {
                            $btn.RaiseEvent([System.Windows.RoutedEventArgs]::new([System.Windows.Controls.Primitives.ButtonBase]::ClickEvent))
                        }
                        $e.Handled = $true
                    }
                }
            }
            elseif ($e.Key -eq 'Escape') {
                Stop-PSMMAllJobs
                Write-PSMMLog -Severity 'WARN' -Message 'Jobs cancelled by user (Escape key).'
                $e.Handled = $true
            }
        })

    # -- Window Closing cleanup ------------------------------------------------
    $Window.Add_Closing({
            Write-PSMMLog -Severity 'INFO' -Message 'Application closing -- cleaning up ...'
            Close-PSMMRunspacePool
        })
}
#endregion WPF Event Handlers


#region Job Poller
# ---------------------------------------------------------------------------
# DispatcherTimer that polls runspace jobs and updates the UI via syncHash.
# ---------------------------------------------------------------------------

function Start-PSMMJobPoller {
    <#
    .SYNOPSIS
        Starts a WPF DispatcherTimer that polls job completion and updates the UI.
    .DESCRIPTION
        The timer tick handler uses $script:SyncHash to update UI controls
        thread-safely via the WPF Dispatcher.  All grid/status updates go
        through $syncHash.<Control> references.
    .PARAMETER Operation
        Label for the operation being polled (Inventory / Install / Update / Remove).
    #>
    [CmdletBinding()]
    param(
        [string]$Operation = 'Operation'
    )

    # Stop any previous poller
    if ($script:JobPollerTimer) {
        try { $script:JobPollerTimer.Stop() } catch {}
        $script:JobPollerTimer = $null
    }

    $script:CurrentPollerOperation = $Operation

    $timer = [System.Windows.Threading.DispatcherTimer]::new()
    $timer.Interval = [TimeSpan]::FromMilliseconds(500)
    $script:JobPollerTimer = $timer

    # Show progress bar via syncHash
    if ($script:SyncHash.StatusProgress) {
        $script:SyncHash.StatusProgress.IsIndeterminate = $true
        $script:SyncHash.StatusProgress.Visibility = [System.Windows.Visibility]::Visible
    }

    $timer.Add_Tick({
            try {
                # 1. Harvest completed jobs
                $completed = Receive-PSMMJobs
                $running = @($script:Jobs | Where-Object { $_.Status -eq 'Running' }).Count

                # 2. Update status bar via syncHash
                if ($script:SyncHash.StatusJobs) {
                    $total = $script:Jobs.Count
                    $done = @($script:Jobs | Where-Object { $_.Status -ne 'Running' }).Count
                    $script:SyncHash.StatusJobs.Text = "Jobs: $done / $total  |  Running: $running  |  Pool: $($script:Settings.MaxConcurrency)"
                }

                # 3. Process completed results -- update existing items in-place or add new ones
                $changedCount = 0
                foreach ($job in $completed) {
                    if (-not $job.Result) { continue }
                    foreach ($result in $job.Result) {
                        if ($result -is [PSCustomObject] -and $result.PSObject.Properties['ModuleName']) {
                            if ($result.ModuleName -eq '_ERROR_') { continue }

                            # Look for an existing row to update in-place (INotifyPropertyChanged handles UI)
                            $existing = $null
                            foreach ($row in $script:ModuleGrid) {
                                if ($row.ComputerName -eq $result.ComputerName -and $row.ModuleName -eq $result.ModuleName) {
                                    $existing = $row
                                    break
                                }
                            }

                            if ($existing) {
                                # Update in-place -- WPF auto-reflects via INotifyPropertyChanged
                                $existing.InstalledVersion = $result.InstalledVersion
                                $existing.Status = 'Scanned'
                                $existing.Model = $result.Model
                                $existing.OS = $result.OS
                                $existing.PSModulePath = $result.ModuleBase
                            }
                            else {
                                # New module not yet in grid -- add it
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
                            }
                            $changedCount++
                        }
                        elseif ($result -is [string]) {
                            Write-PSMMLog -Severity 'INFO' -Message $result -ComputerName $job.ComputerName
                        }
                    }
                }

                # 4. Log changes (no forced repaint needed -- ObservableCollection + INotifyPropertyChanged handle it)
                if ($changedCount -gt 0) {
                    Write-PSMMLog -Severity 'DEBUG' -Message "Poller: updated/added $changedCount row(s) in grid (total: $($script:ModuleGrid.Count))."
                }

                # 5. All jobs finished?
                if ($running -eq 0 -and $script:Jobs.Count -gt 0) {
                    if ($script:JobPollerTimer) {
                        try { $script:JobPollerTimer.Stop() } catch {}
                        $script:JobPollerTimer = $null
                    }

                    # Hide progress bar
                    if ($script:SyncHash.StatusProgress) {
                        $script:SyncHash.StatusProgress.IsIndeterminate = $false
                        $script:SyncHash.StatusProgress.Visibility = [System.Windows.Visibility]::Collapsed
                    }

                    Write-PSMMLog -Severity 'INFO' -Message "All jobs completed. Grid rows: $($script:ModuleGrid.Count)"

                    # 5a. Version comparison -- update existing grid items in-place
                    $shareModules = Get-PSMMShareModules
                    if ($shareModules.Count -gt 0 -and $script:ModuleGrid.Count -gt 0) {
                        # Build lookup: module name -> latest version on share
                        $latestOnShare = @{}
                        foreach ($sm in $shareModules) {
                            try {
                                $ver = [Version]$sm.Version
                                if (-not $latestOnShare.ContainsKey($sm.ModuleName) -or $ver -gt [Version]$latestOnShare[$sm.ModuleName]) {
                                    $latestOnShare[$sm.ModuleName] = $sm.Version
                                }
                            }
                            catch { <# skip unparseable versions #> }
                        }

                        # Update each grid item in-place (INotifyPropertyChanged propagates to UI)
                        foreach ($item in $script:ModuleGrid) {
                            $target = $latestOnShare[$item.ModuleName]
                            $item.TargetVersion = if ($target) { $target } else { '' }

                            $item.Status = if (-not $target) {
                                'Unknown'
                            }
                            elseif (-not $item.InstalledVersion) {
                                'Missing'
                            }
                            else {
                                try {
                                    $cmp = [Version]$item.InstalledVersion
                                    $tgt = [Version]$target
                                    if ($cmp -ge $tgt) { 'UpToDate' } else { 'Outdated' }
                                }
                                catch { 'Unknown' }
                            }
                        }

                        Write-PSMMLog -Severity 'DEBUG' -Message "Version comparison done (in-place). Grid rows: $($script:ModuleGrid.Count)"
                    }

                    # 5a-cleanup. Remove stale rows still stuck at transient status
                    # (e.g. a module was uninstalled so no result came back for it)
                    $staleRows = @($script:ModuleGrid | Where-Object { $_.Status -in @('Scanning...', 'Refreshing...') })
                    if ($staleRows.Count -gt 0) {
                        foreach ($stale in $staleRows) { $script:ModuleGrid.Remove($stale) }
                        Write-PSMMLog -Severity 'DEBUG' -Message "Removed $($staleRows.Count) stale row(s) with no matching scan result."
                    }

                    # 5b. Auto-refresh after Install/Update/Remove
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

                            # Mark affected rows as refreshing (observable in-place update)
                            foreach ($item in $script:ModuleGrid) {
                                if ($affectedComputers -contains $item.ComputerName) {
                                    $item.Status = 'Refreshing...'
                                }
                            }

                            $cmbMod = $script:SyncHash.CmbModule
                            $modFilter = if ($cmbMod -and $cmbMod.SelectedItem) { $cmbMod.SelectedItem.ToString() } else { $null }

                            $script:Jobs.Clear()

                            $null = Get-PSMMRemoteModules -ComputerNames $affectedComputers -ModuleName $modFilter
                            Start-PSMMJobPoller -Operation 'Inventory'
                        }
                    }
                }
            }
            catch {
                Write-PSMMLog -Severity 'ERROR' -Message "Job poller tick error: $_"
            }
        })

    Write-PSMMLog -Severity 'DEBUG' -Message "Job poller started (operation: $Operation, interval: 500ms)."
    $timer.Start()
}
#endregion Job Poller


#region ADSI Helper
# ---------------------------------------------------------------------------
function Get-ADSIInfo {
    <#
    .SYNOPSIS
        Discovers DomainLdapPath and available OUs using ADSI.
    .DESCRIPTION
        Uses ADSI (no Active Directory module required) to determine the domain
        LDAP path and enumerate available OUs for use in settings.json.
    #>

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
        $localDns = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $localName }
        $localOS = (Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction SilentlyContinue).Caption

        Write-Host "`n=== Local Computer Info ===" -ForegroundColor Cyan
        Write-Host "Computer Name : " -NoNewline; Write-Host $localName -ForegroundColor Green
        Write-Host "DNS Host Name : $localDns"
        Write-Host "OS            : $localOS"
        Write-Host ""
        Write-Host "Tip: The tool will target this machine when ADSI is unavailable." -ForegroundColor Yellow
        return
    }

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
# ---------------------------------------------------------------------------
# WPF settings editor modal dialog.
# ---------------------------------------------------------------------------

function Show-PSMMSettingsDialog {
    <#
    .SYNOPSIS
        Opens the settings editor dialog.
    #>
    [CmdletBinding()]
    param()

    $settingsWin = New-PSMMWindow -Xaml $script:SettingsDialogXaml
    $settingsWin.Owner = $script:SyncHash.Window

    # Cache references to avoid closure issues
    $txtLdap = $settingsWin.FindName('TxtSettLdap')
    $txtOu = $settingsWin.FindName('TxtSettOu')
    $txtSearchPaths = $settingsWin.FindName('TxtSettSearchPaths')
    $txtShare = $settingsWin.FindName('TxtSettShare')
    $txtLogPath = $settingsWin.FindName('TxtSettLogPath')
    $txtConcurrency = $settingsWin.FindName('TxtSettConcurrency')
    $txtRetry = $settingsWin.FindName('TxtSettRetry')
    $txtTimeout = $settingsWin.FindName('TxtSettTimeout')
    $credCombo = $settingsWin.FindName('CmbSettCredMode')
    $logCombo = $settingsWin.FindName('CmbSettLogLevel')
    $chkReachability = $settingsWin.FindName('ChkReachability')
    $chkExclServers = $settingsWin.FindName('ChkExcludeServers')
    $chkExclVirtual = $settingsWin.FindName('ChkExcludeVirtual')
    $txtOsFilter = $settingsWin.FindName('TxtOsFilter')
    $btnSave = $settingsWin.FindName('BtnSettSave')
    $btnCancel = $settingsWin.FindName('BtnSettCancel')
    $btnTestShare = $settingsWin.FindName('BtnTestShare')
    $btnTestAD = $settingsWin.FindName('BtnTestAD')
    $btnSettImport = $settingsWin.FindName('BtnSettImport')
    $btnSettExport = $settingsWin.FindName('BtnSettExport')

    # Populate fields from current settings
    $txtLdap.Text = $script:Settings.DomainLdapPath
    $txtOu.Text = $script:Settings.OuFilter
    $txtShare.Text = $script:Settings.CentralSharePath
    $txtLogPath.Text = $script:Settings.LogPath
    $txtConcurrency.Text = $script:Settings.MaxConcurrency.ToString()
    $txtRetry.Text = $script:Settings.RetryCount.ToString()
    $txtTimeout.Text = $script:Settings.JobTimeoutSeconds.ToString()

    if ($script:Settings.ModuleSearchPaths -is [System.Collections.IEnumerable] -and $script:Settings.ModuleSearchPaths -isnot [string]) {
        $txtSearchPaths.Text = ($script:Settings.ModuleSearchPaths -join ', ')
    }
    else {
        $txtSearchPaths.Text = [string]$script:Settings.ModuleSearchPaths
    }

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
    $chkExclServers.IsChecked = [bool]$script:Settings.ExcludeServers
    $chkExclVirtual.IsChecked = [bool]$script:Settings.ExcludeVirtual
    $txtOsFilter.Text = $script:Settings.OSFilter

    # Capture module-scoped references for .GetNewClosure()
    $settings = $script:Settings
    $syncHash = $script:SyncHash
    $fnTestSettings = ${function:Test-PSMMSettings}
    $fnExportSettings = ${function:Export-PSMMSettings}
    $fnImportSettings = ${function:Import-PSMMSettings}
    $fnWriteLog = ${function:Write-PSMMLog}

    # -- Save ---
    $btnSave.Add_Click({
            $settings['DomainLdapPath'] = $txtLdap.Text
            $settings['OuFilter'] = $txtOu.Text
            $settings['CentralSharePath'] = $txtShare.Text
            $settings['LogPath'] = $txtLogPath.Text
            $settings['MaxConcurrency'] = [int]($txtConcurrency.Text)
            $settings['RetryCount'] = [int]($txtRetry.Text)
            $settings['JobTimeoutSeconds'] = [int]($txtTimeout.Text)

            $settings['ModuleSearchPaths'] = @($txtSearchPaths.Text -split '\s*,\s*' | Where-Object { $_ -ne '' })

            $credSel = $credCombo.SelectedItem
            if ($credSel) { $settings['CredentialMode'] = $credSel.Content.ToString() }

            $logSel = $logCombo.SelectedItem
            if ($logSel) { $settings['LogLevel'] = $logSel.Content.ToString() }

            $settings['ReachabilityCheck'] = [bool]$chkReachability.IsChecked
            $settings['ExcludeServers'] = [bool]$chkExclServers.IsChecked
            $settings['ExcludeVirtual'] = [bool]$chkExclVirtual.IsChecked
            $settings['OSFilter'] = $txtOsFilter.Text

            $issues = & $fnTestSettings -Settings $settings
            if ($issues.Count -gt 0) {
                [System.Windows.MessageBox]::Show(($issues -join "`n"), 'Validation Issues', 'OK', 'Warning')
                return
            }

            & $fnExportSettings -Settings $settings
            & $fnWriteLog -Severity 'INFO' -Message 'Settings saved successfully.'

            # Sync main window toolbar controls via syncHash
            if ($syncHash.Window) {
                if ($syncHash.ChkSkipServers) { $syncHash.ChkSkipServers.IsChecked = [bool]$settings['ExcludeServers'] }
                if ($syncHash.ChkSkipVirtual) { $syncHash.ChkSkipVirtual.IsChecked = [bool]$settings['ExcludeVirtual'] }
                if ($syncHash.TxtOuFilter) { $syncHash.TxtOuFilter.Text = [string]$settings['OuFilter'] }
            }

            $settingsWin.Close()
        }.GetNewClosure())

    # -- Cancel ---
    $btnCancel.Add_Click({ $settingsWin.Close() }.GetNewClosure())

    # -- Import Settings ---
    $btnSettImport.Add_Click({
            $dlg = [Microsoft.Win32.OpenFileDialog]::new()
            $dlg.Title = 'Import Settings'
            $dlg.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
            if ($dlg.ShowDialog($settingsWin)) {
                try {
                    $imported = & $fnImportSettings -Path $dlg.FileName
                    if (-not $imported) {
                        [System.Windows.MessageBox]::Show('Failed to load settings from the selected file.', 'Import Error', 'OK', 'Error')
                        return
                    }
                    $txtLdap.Text = if ($imported.DomainLdapPath) { $imported.DomainLdapPath }    else { '' }
                    $txtOu.Text = if ($imported.OuFilter) { $imported.OuFilter }          else { '' }
                    $txtShare.Text = if ($imported.CentralSharePath) { $imported.CentralSharePath }  else { '' }
                    $txtLogPath.Text = if ($imported.LogPath) { $imported.LogPath }           else { '' }
                    $txtConcurrency.Text = if ($imported.MaxConcurrency) { $imported.MaxConcurrency.ToString() } else { '4' }
                    $txtRetry.Text = if ($imported.RetryCount) { $imported.RetryCount.ToString() }     else { '2' }
                    $txtTimeout.Text = if ($imported.JobTimeoutSeconds) { $imported.JobTimeoutSeconds.ToString() } else { '300' }

                    if ($imported.ModuleSearchPaths -is [System.Collections.IEnumerable] -and $imported.ModuleSearchPaths -isnot [string]) {
                        $txtSearchPaths.Text = ($imported.ModuleSearchPaths -join ', ')
                    }
                    elseif ($imported.ModuleSearchPaths) {
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
                    $chkExclServers.IsChecked = if ($null -ne $imported.ExcludeServers) { [bool]$imported.ExcludeServers }    else { $false }
                    $chkExclVirtual.IsChecked = if ($null -ne $imported.ExcludeVirtual) { [bool]$imported.ExcludeVirtual }    else { $false }

                    & $fnWriteLog -Severity 'INFO' -Message "Settings imported from $($dlg.FileName) -- click Save to apply."
                    [System.Windows.MessageBox]::Show("Settings loaded from:`n$($dlg.FileName)`n`nReview values and click Save to apply.", 'Import Successful', 'OK', 'Information')
                }
                catch {
                    [System.Windows.MessageBox]::Show("Error importing settings:`n$_", 'Import Error', 'OK', 'Error')
                }
            }
        }.GetNewClosure())

    # -- Export Settings ---
    $btnSettExport.Add_Click({
            $dlg = [Microsoft.Win32.SaveFileDialog]::new()
            $dlg.Title = 'Export Settings'
            $dlg.Filter = 'JSON files (*.json)|*.json|All files (*.*)|*.*'
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

    # -- Test Share ---
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

    # -- Test AD ---
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
# ---------------------------------------------------------------------------
# The public entry-points for the module.
# ---------------------------------------------------------------------------

function Show-ModuleManagerGUI {
    <#
    .SYNOPSIS
        Launches the PS-ModuleManager WPF GUI.

    .DESCRIPTION
        Opens the PowerShell Module Manager graphical interface.  From the GUI you
        can discover domain-joined computers via ADSI, inventory installed PowerShell
        modules, and install / update / remove modules from a central network share.

        Architecture: SyncHash + Dispatcher pattern
        All operations are executed in parallel using a runspace pool, with real-time
        progress and logging visible in the application window.  Background runspaces
        update the UI thread-safely via $syncHash.Window.Dispatcher.Invoke().

    .PARAMETER SettingsPath
        Path to a custom settings.json file.

    .PARAMETER WindowStartupLocation
        Specifies the initial position of the main window.  Default is 'CenterScreen'.

    .PARAMETER WindowState
        Specifies the initial window state.  Default is 'Normal'.

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

    Write-Host 'Starting PS-ModuleManager v2.0.0 (SyncHash architecture) ...' -ForegroundColor Cyan

    # -- Admin check ---
    $script:IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
    if (-not $script:IsAdmin) {
        Write-Host 'WARNING: Not running as Administrator. Install/Update/Remove operations will fail for system-wide module paths.' -ForegroundColor Yellow
    }

    # -- Load settings ---
    $script:SettingsPath = $SettingsPath
    Import-PSMMSettings -Path $SettingsPath

    # -- Log rotation ---
    Invoke-PSMMLogRotation

    # -- Initialize runspace pool ---
    New-PSMMRunspacePool

    # -- Handle credentials ---
    if ($script:Settings.CredentialMode -eq 'Prompt') {
        Get-PSMMCredential
    }

    # -- Build WPF window ---
    $window = New-PSMMWindow -Xaml $script:MainWindowXaml

    # -- Initialize the SyncHash with all named controls ---
    Initialize-PSMMSyncHash -Window $window

    # -- Populate toolbar defaults from settings ---
    if ($script:SyncHash.TxtOuFilter -and $script:Settings.OuFilter) {
        $script:SyncHash.TxtOuFilter.Text = $script:Settings.OuFilter
    }

    if ($script:SyncHash.ChkSkipServers) {
        $script:SyncHash.ChkSkipServers.IsChecked = [bool]$script:Settings.ExcludeServers
    }
    if ($script:SyncHash.ChkSkipVirtual) {
        $script:SyncHash.ChkSkipVirtual.IsChecked = [bool]$script:Settings.ExcludeVirtual
    }

    # -- Wire event handlers ---
    Register-PSMMMainWindowEvents -Window $window

    # -- Bind ObservableCollections to WPF controls ---
    $script:ComputerList.Clear()
    $script:SyncHash.ComputerListBox.ItemsSource = $script:ComputerList

    $script:ModuleGrid.Clear()
    $script:SyncHash.ModuleDataGrid.ItemsSource = $script:ModuleGrid

    # -- Initial log entries ---
    Write-PSMMLog -Severity 'INFO' -Message 'PS-ModuleManager v2.0.0 started (SyncHash + Dispatcher architecture).'
    Write-PSMMLog -Severity 'INFO' -Message "Settings loaded from: $SettingsPath"
    Write-PSMMLog -Severity 'INFO' -Message "Central share: $($script:Settings.CentralSharePath)"
    Write-PSMMLog -Severity 'INFO' -Message "Concurrency: $($script:Settings.MaxConcurrency) threads"

    if (-not $script:IsAdmin) {
        Write-PSMMLog -Severity 'WARN' -Message 'Not running as Administrator -- install/update/remove to system-wide module paths will require elevation.'
    }

    # -- Set window properties ---
    $window.WindowStartupLocation = $WindowStartupLocation
    $window.WindowState = $WindowState

    # -- Show the window (blocking call) ---
    $window.ShowDialog() | Out-Null

    # -- Cleanup ---
    Close-PSMMRunspacePool
    Write-Host 'PS-ModuleManager closed.' -ForegroundColor Cyan
}
#endregion Exported Function

# ---------------------------------------------------------------------------
# Module auto-export
# ---------------------------------------------------------------------------
Export-ModuleMember -Function 'Show-ModuleManagerGUI', 'Get-ADSIInfo'
