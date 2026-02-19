#requires -Module Pester
<#
.SYNOPSIS
    Pester test suite for PS-ModuleManager non-WPF functions.
.DESCRIPTION
    Unit tests for business logic functions: configuration, module inventory,
    version comparison, share modules, and logging.
    Run with: Invoke-Pester -Path .\test\PS-ModuleManager.Tests.ps1
.NOTES
    Requires Pester v5+.  Tests are designed for Windows PowerShell 5.1.
#>

# ── Setup: dot-source or import the module so internal functions are available ──
BeforeAll {
    # Import the module to make internal functions available for testing
    $modulePath = Join-Path $PSScriptRoot '..\PS-ModuleManager.psd1'
    if (Test-Path $modulePath) {
        Import-Module $modulePath -Force
    }

    # To test internal functions we need to import the .psm1 directly
    $psm1Path = Join-Path $PSScriptRoot '..\PS-ModuleManager.psm1'
    if (Test-Path $psm1Path) {
        # Use InternalCommand to get access to module-private functions
        $module = Import-Module $psm1Path -Force -PassThru
    }
}

AfterAll {
    if ($module) {
        Remove-Module $module.Name -Force -ErrorAction SilentlyContinue
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Get-PSMMDefaultSettings
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-PSMMDefaultSettings' {

    It 'Returns a hashtable' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result | Should -BeOfType [hashtable]
    }

    It 'Contains all required settings keys' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $expectedKeys = @(
            'DomainLdapPath', 'OuFilter', 'ModuleSearchPaths', 'CentralSharePath',
            'MaxConcurrency', 'CredentialMode', 'LogPath', 'LogLevel',
            'RetryCount', 'ReachabilityCheck', 'JobTimeoutSeconds',
            'ExcludeServers', 'ExcludeVirtual', 'OSFilter', 'GlobalExcludeList'
        )
        foreach ($key in $expectedKeys) {
            $result.ContainsKey($key) | Should -BeTrue -Because "Missing key: $key"
        }
    }

    It 'Has MaxConcurrency between 1 and processor count' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.MaxConcurrency | Should -BeGreaterOrEqual 1
        $result.MaxConcurrency | Should -BeLessOrEqual ([Environment]::ProcessorCount)
    }

    It 'Has CredentialMode set to Default' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.CredentialMode | Should -Be 'Default'
    }

    It 'Has LogLevel set to INFO' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.LogLevel | Should -Be 'INFO'
    }

    It 'Has RetryCount set to 2' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.RetryCount | Should -Be 2
    }

    It 'Has ReachabilityCheck set to true' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.ReachabilityCheck | Should -BeTrue
    }

    It 'Has ExcludeServers set to false' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.ExcludeServers | Should -BeFalse
    }

    It 'Has ExcludeVirtual set to false' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.ExcludeVirtual | Should -BeFalse
    }

    It 'Has GlobalExcludeList as empty array' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        # PS 5.1 quirk: empty arrays in hashtables may collapse to $null
        # Verify the key exists and is either null or an empty array
        $result.ContainsKey('GlobalExcludeList') | Should -BeTrue
        $list = @($result.GlobalExcludeList)  # Force array context
        $list.Count | Should -Be 0
   }

    It 'Has ModuleSearchPaths containing default path' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.ModuleSearchPaths | Should -Contain 'C:\Program Files\WindowsPowerShell\Modules'
    }

    It 'Has JobTimeoutSeconds set to 300' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.JobTimeoutSeconds | Should -Be 300
    }

    It 'Has OSFilter as empty string' {
        $result = InModuleScope PS-ModuleManager { Get-PSMMDefaultSettings }
        $result.ContainsKey('OSFilter') | Should -BeTrue
        $result.OSFilter | Should -Be ''
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Test-PSMMSettings
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Test-PSMMSettings' {

    It 'Returns no issues for valid default settings' {
        $issues = InModuleScope PS-ModuleManager {
            $s = Get-PSMMDefaultSettings
            $s.CentralSharePath = ''  # empty is OK (not validated if empty)
            Test-PSMMSettings -Settings $s
        }
        $issues.Count | Should -Be 0
    }

    It 'Flags MaxConcurrency below 1' {
        $issues = InModuleScope PS-ModuleManager {
            $s = Get-PSMMDefaultSettings
            $s.MaxConcurrency = 0
            Test-PSMMSettings -Settings $s
        }
        $issues | Should -Contain 'MaxConcurrency must be between 1 and 64.'
    }

    It 'Flags MaxConcurrency above 64' {
        $issues = InModuleScope PS-ModuleManager {
            $s = Get-PSMMDefaultSettings
            $s.MaxConcurrency = 100
            Test-PSMMSettings -Settings $s
        }
        $issues | Should -Contain 'MaxConcurrency must be between 1 and 64.'
    }

    It 'Flags invalid CredentialMode' {
        $issues = InModuleScope PS-ModuleManager {
            $s = Get-PSMMDefaultSettings
            $s.CredentialMode = 'InvalidMode'
            Test-PSMMSettings -Settings $s
        }
        $issues | Should -Contain 'CredentialMode must be Default, Prompt, or Stored.'
    }

    It 'Flags RetryCount below 0' {
        $issues = InModuleScope PS-ModuleManager {
            $s = Get-PSMMDefaultSettings
            $s.RetryCount = -1
            Test-PSMMSettings -Settings $s
        }
        $issues | Should -Contain 'RetryCount must be between 0 and 10.'
    }

    It 'Flags RetryCount above 10' {
        $issues = InModuleScope PS-ModuleManager {
            $s = Get-PSMMDefaultSettings
            $s.RetryCount = 20
            Test-PSMMSettings -Settings $s
        }
        $issues | Should -Contain 'RetryCount must be between 0 and 10.'
    }

    It 'Flags invalid LogLevel' {
        $issues = InModuleScope PS-ModuleManager {
            $s = Get-PSMMDefaultSettings
            $s.LogLevel = 'VERBOSE'
            Test-PSMMSettings -Settings $s
        }
        $issues | Should -Contain 'LogLevel must be DEBUG, INFO, WARN, or ERROR.'
    }

    It 'Accepts valid CredentialMode values' {
        foreach ($mode in @('Default', 'Prompt', 'Stored')) {
            $issues = InModuleScope PS-ModuleManager {
                param($m)
                $s = Get-PSMMDefaultSettings
                $s.CredentialMode = $m
                Test-PSMMSettings -Settings $s
            } -ArgumentList $mode
            ($issues | Where-Object { $_ -match 'CredentialMode' }).Count | Should -Be 0
        }
    }

    It 'Accepts valid LogLevel values' {
        foreach ($level in @('DEBUG', 'INFO', 'WARN', 'ERROR')) {
            $issues = InModuleScope PS-ModuleManager {
                param($l)
                $s = Get-PSMMDefaultSettings
                $s.LogLevel = $l
                Test-PSMMSettings -Settings $s
            } -ArgumentList $level
            ($issues | Where-Object { $_ -match 'LogLevel' }).Count | Should -Be 0
        }
    }

    It 'Reports multiple issues simultaneously' {
        $issues = InModuleScope PS-ModuleManager {
            $s = Get-PSMMDefaultSettings
            $s.MaxConcurrency = 0
            $s.RetryCount = -1
            $s.CredentialMode = 'Bad'
            $s.LogLevel = 'Bad'
            Test-PSMMSettings -Settings $s
        }
        $issues.Count | Should -BeGreaterOrEqual 4
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Import-PSMMSettings
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Import-PSMMSettings' {

    It 'Returns defaults when file does not exist' {
        $result = InModuleScope PS-ModuleManager {
            $tempPath = Join-Path $env:TEMP "PSMMTest_$(Get-Random).json"
            $settings = Import-PSMMSettings -Path $tempPath
            # Clean up the auto-created file
            if (Test-Path $tempPath) { Remove-Item $tempPath -Force }
            $settings
        }
        $result | Should -BeOfType [hashtable]
        $result.CredentialMode | Should -Be 'Default'
    }

    It 'Merges JSON values over defaults' {
        $result = InModuleScope PS-ModuleManager {
            $tempPath = Join-Path $env:TEMP "PSMMTest_$(Get-Random).json"
            $json = @{ MaxConcurrency = 8; LogLevel = 'DEBUG' } | ConvertTo-Json
            Set-Content -Path $tempPath -Value $json -Encoding UTF8
            $settings = Import-PSMMSettings -Path $tempPath
            Remove-Item $tempPath -Force
            $settings
        }
        $result.MaxConcurrency | Should -Be 8
        $result.LogLevel | Should -Be 'DEBUG'
        # Non-overridden values should still be defaults
        $result.RetryCount | Should -Be 2
    }

    It 'Handles malformed JSON gracefully' {
        $result = InModuleScope PS-ModuleManager {
            $tempPath = Join-Path $env:TEMP "PSMMTest_$(Get-Random).json"
            Set-Content -Path $tempPath -Value '{invalid json!!}' -Encoding UTF8
            $settings = Import-PSMMSettings -Path $tempPath
            Remove-Item $tempPath -Force
            $settings
        }
        # Should fall back to defaults without throwing
        $result | Should -BeOfType [hashtable]
        $result.CredentialMode | Should -Be 'Default'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Export-PSMMSettings
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Export-PSMMSettings' {

    It 'Writes settings to a JSON file' {
        InModuleScope PS-ModuleManager {
            $tempPath = Join-Path $env:TEMP "PSMMTest_$(Get-Random).json"
            $s = Get-PSMMDefaultSettings
            Export-PSMMSettings -Settings $s -Path $tempPath
            Test-Path $tempPath | Should -BeTrue
            $content = Get-Content $tempPath -Raw | ConvertFrom-Json
            $content.RetryCount | Should -Be 2
            Remove-Item $tempPath -Force
        }
    }

    It 'Creates parent directory if missing' {
        InModuleScope PS-ModuleManager {
            $tempDir = Join-Path $env:TEMP "PSMMTestDir_$(Get-Random)"
            $tempPath = Join-Path $tempDir 'settings.json'
            $s = Get-PSMMDefaultSettings
            Export-PSMMSettings -Settings $s -Path $tempPath
            Test-Path $tempPath | Should -BeTrue
            Remove-Item $tempDir -Recurse -Force
        }
    }

    It 'Round-trips settings correctly' {
        InModuleScope PS-ModuleManager {
            $tempPath = Join-Path $env:TEMP "PSMMTest_$(Get-Random).json"
            $original = Get-PSMMDefaultSettings
            $original.MaxConcurrency = 6
            $original.LogLevel = 'WARN'
            Export-PSMMSettings -Settings $original -Path $tempPath
            $loaded = Import-PSMMSettings -Path $tempPath
            $loaded.MaxConcurrency | Should -Be 6
            $loaded.LogLevel | Should -Be 'WARN'
            Remove-Item $tempPath -Force
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Compare-PSMMModuleVersions
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Compare-PSMMModuleVersions' {

    It 'Marks module as UpToDate when versions match' {
        $result = InModuleScope PS-ModuleManager {
            $installed = @([PSCustomObject]@{
                ComputerName     = 'PC1'
                ModuleName       = 'TestMod'
                InstalledVersion = '1.0.0'
                ModuleBase       = 'C:\Modules\TestMod'
                Model            = ''
                OS               = ''
            })
            $share = @([PSCustomObject]@{
                ModuleName = 'TestMod'
                Version    = '1.0.0'
                Path       = '\\share\TestMod\1.0.0'
            })
            Compare-PSMMModuleVersions -InstalledModules $installed -ShareModules $share
        }
        $result.Status | Should -Be 'UpToDate'
    }

    It 'Marks module as Outdated when installed < share version' {
        $result = InModuleScope PS-ModuleManager {
            $installed = @([PSCustomObject]@{
                ComputerName     = 'PC1'
                ModuleName       = 'TestMod'
                InstalledVersion = '1.0.0'
                ModuleBase       = 'C:\Modules\TestMod'
                Model            = ''
                OS               = ''
            })
            $share = @([PSCustomObject]@{
                ModuleName = 'TestMod'
                Version    = '2.0.0'
                Path       = '\\share\TestMod\2.0.0'
            })
            Compare-PSMMModuleVersions -InstalledModules $installed -ShareModules $share
        }
        $result.Status | Should -Be 'Outdated'
        $result.TargetVersion | Should -Be '2.0.0'
    }

    It 'Marks module as Missing when not installed' {
        $result = InModuleScope PS-ModuleManager {
            $installed = @([PSCustomObject]@{
                ComputerName     = 'PC1'
                ModuleName       = 'TestMod'
                InstalledVersion = ''
                ModuleBase       = ''
                Model            = ''
                OS               = ''
            })
            $share = @([PSCustomObject]@{
                ModuleName = 'TestMod'
                Version    = '1.0.0'
                Path       = '\\share\TestMod\1.0.0'
            })
            Compare-PSMMModuleVersions -InstalledModules $installed -ShareModules $share
        }
        $result.Status | Should -Be 'Missing'
    }

    It 'Marks module as Unknown when not on share' {
        $result = InModuleScope PS-ModuleManager {
            $installed = @([PSCustomObject]@{
                ComputerName     = 'PC1'
                ModuleName       = 'UnknownMod'
                InstalledVersion = '1.0.0'
                ModuleBase       = 'C:\Modules\UnknownMod'
                Model            = ''
                OS               = ''
            })
            $share = @()
            Compare-PSMMModuleVersions -InstalledModules $installed -ShareModules $share
        }
        $result.Status | Should -Be 'Unknown'
    }

    It 'Marks _ERROR_ entries as Error' {
        $result = InModuleScope PS-ModuleManager {
            $installed = @([PSCustomObject]@{
                ComputerName     = 'PC1'
                ModuleName       = '_ERROR_'
                InstalledVersion = ''
                ModuleBase       = 'WinRM failed'
                Model            = ''
                OS               = ''
            })
            $share = @()
            Compare-PSMMModuleVersions -InstalledModules $installed -ShareModules $share
        }
        $result.Status | Should -Be 'Error'
    }

    It 'Selects latest version from share when multiple exist' {
        $result = InModuleScope PS-ModuleManager {
            $installed = @([PSCustomObject]@{
                ComputerName     = 'PC1'
                ModuleName       = 'TestMod'
                InstalledVersion = '1.5.0'
                ModuleBase       = 'C:\Modules\TestMod'
                Model            = ''
                OS               = ''
            })
            $share = @(
                [PSCustomObject]@{ ModuleName = 'TestMod'; Version = '1.0.0'; Path = '\\share\TestMod\1.0.0' }
                [PSCustomObject]@{ ModuleName = 'TestMod'; Version = '2.0.0'; Path = '\\share\TestMod\2.0.0' }
                [PSCustomObject]@{ ModuleName = 'TestMod'; Version = '1.5.0'; Path = '\\share\TestMod\1.5.0' }
            )
            Compare-PSMMModuleVersions -InstalledModules $installed -ShareModules $share
        }
        $result.TargetVersion | Should -Be '2.0.0'
        $result.Status | Should -Be 'Outdated'
    }

    It 'Marks UpToDate when installed version is newer than share' {
        $result = InModuleScope PS-ModuleManager {
            $installed = @([PSCustomObject]@{
                ComputerName     = 'PC1'
                ModuleName       = 'TestMod'
                InstalledVersion = '3.0.0'
                ModuleBase       = 'C:\Modules\TestMod'
                Model            = ''
                OS               = ''
            })
            $share = @([PSCustomObject]@{
                ModuleName = 'TestMod'
                Version    = '2.0.0'
                Path       = '\\share\TestMod\2.0.0'
            })
            Compare-PSMMModuleVersions -InstalledModules $installed -ShareModules $share
        }
        $result.Status | Should -Be 'UpToDate'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Get-PSMMShareModules
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-PSMMShareModules' {

    It 'Returns empty array when share path is empty' {
        $result = InModuleScope PS-ModuleManager {
            Get-PSMMShareModules -SharePath ''
        }
        $result.Count | Should -Be 0
    }

    It 'Returns empty array when share path does not exist' {
        $result = InModuleScope PS-ModuleManager {
            Get-PSMMShareModules -SharePath 'C:\NonExistent_Path_PSMM_Test'
        }
        $result.Count | Should -Be 0
    }

    It 'Discovers modules from a valid share structure' {
        $result = InModuleScope PS-ModuleManager {
            $tempShare = Join-Path $env:TEMP "PSMMShareTest_$(Get-Random)"
            New-Item -Path "$tempShare\ModuleA\1.0.0" -ItemType Directory -Force | Out-Null
            New-Item -Path "$tempShare\ModuleA\2.0.0" -ItemType Directory -Force | Out-Null
            New-Item -Path "$tempShare\ModuleB\1.0.0" -ItemType Directory -Force | Out-Null
            $modules = Get-PSMMShareModules -SharePath $tempShare
            Remove-Item $tempShare -Recurse -Force
            $modules
        }
        $result.Count | Should -Be 3
        ($result | Where-Object { $_.ModuleName -eq 'ModuleA' }).Count | Should -Be 2
        ($result | Where-Object { $_.ModuleName -eq 'ModuleB' }).Count | Should -Be 1
    }

    It 'Returns correct properties for each module' {
        $result = InModuleScope PS-ModuleManager {
            $tempShare = Join-Path $env:TEMP "PSMMShareTest_$(Get-Random)"
            New-Item -Path "$tempShare\TestMod\1.2.3" -ItemType Directory -Force | Out-Null
            $modules = Get-PSMMShareModules -SharePath $tempShare
            Remove-Item $tempShare -Recurse -Force
            $modules
        }
        $result[0].ModuleName | Should -Be 'TestMod'
        $result[0].Version | Should -Be '1.2.3'
        $result[0].Path | Should -Not -BeNullOrEmpty
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# ConvertTo-PSMMLdapSafeString (LDAP sanitization)
# ─────────────────────────────────────────────────────────────────────────────
Describe 'ConvertTo-PSMMLdapSafeString' {

    It 'Passes through normal text unchanged' {
        $result = InModuleScope PS-ModuleManager {
            ConvertTo-PSMMLdapSafeString -InputString 'DESKTOP-PC01'
        }
        $result | Should -Be 'DESKTOP-PC01'
    }

    It 'Preserves wildcard asterisks by default' {
        $result = InModuleScope PS-ModuleManager {
            ConvertTo-PSMMLdapSafeString -InputString 'WEB*'
        }
        $result | Should -Be 'WEB*'
    }

    It 'Escapes parentheses' {
        $result = InModuleScope PS-ModuleManager {
            ConvertTo-PSMMLdapSafeString -InputString 'test(value)'
        }
        $result | Should -Be 'test\28value\29'
    }

    It 'Escapes backslash' {
        $result = InModuleScope PS-ModuleManager {
            ConvertTo-PSMMLdapSafeString -InputString 'test\value'
        }
        $result | Should -Be 'test\5cvalue'
    }

    It 'Escapes NUL character' {
        $result = InModuleScope PS-ModuleManager {
            ConvertTo-PSMMLdapSafeString -InputString "test$([char]0)value"
        }
        $result | Should -Be 'test\00value'
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Invoke-PSMMLogRotation
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Invoke-PSMMLogRotation' {

    It 'Removes log files older than retention days' {
        InModuleScope PS-ModuleManager {
            $tempLogDir = Join-Path $env:TEMP "PSMMLogTest_$(Get-Random)"
            New-Item -ItemType Directory -Path $tempLogDir -Force | Out-Null

            # Create old log file (40 days ago)
            $oldFile = Join-Path $tempLogDir 'PS-ModuleManager_old.log'
            Set-Content -Path $oldFile -Value 'old log'
            (Get-Item $oldFile).LastWriteTime = (Get-Date).AddDays(-40)

            # Create recent log file
            $newFile = Join-Path $tempLogDir 'PS-ModuleManager_new.log'
            Set-Content -Path $newFile -Value 'new log'

            Invoke-PSMMLogRotation -LogPath $tempLogDir -RetentionDays 30

            Test-Path $oldFile | Should -BeFalse
            Test-Path $newFile | Should -BeTrue

            Remove-Item $tempLogDir -Recurse -Force
        }
    }

    It 'Keeps files within retention period' {
        InModuleScope PS-ModuleManager {
            $tempLogDir = Join-Path $env:TEMP "PSMMLogTest_$(Get-Random)"
            New-Item -ItemType Directory -Path $tempLogDir -Force | Out-Null

            $recentFile = Join-Path $tempLogDir 'PS-ModuleManager_recent.log'
            Set-Content -Path $recentFile -Value 'recent log'
            (Get-Item $recentFile).LastWriteTime = (Get-Date).AddDays(-5)

            Invoke-PSMMLogRotation -LogPath $tempLogDir -RetentionDays 30

            Test-Path $recentFile | Should -BeTrue

            Remove-Item $tempLogDir -Recurse -Force
        }
    }
}

# ─────────────────────────────────────────────────────────────────────────────
# Get-PSMMComputers filtering tests
# ─────────────────────────────────────────────────────────────────────────────
Describe 'Get-PSMMComputers Filtering' {

    It 'Supports OSFilter with wildcards' {
        InModuleScope PS-ModuleManager {
            # Mock computer data
            $mockComputers = @(
                [PSCustomObject]@{Name='PC1'; OS='Windows 10 Pro'; Enabled=$true}
                [PSCustomObject]@{Name='PC2'; OS='Windows 11 Pro'; Enabled=$true}
                [PSCustomObject]@{Name='SRV1'; OS='Windows Server 2019'; Enabled=$true}
            )

            # Simulate OSFilter logic
            $OSFilter = '*Windows 10*'
            $filtered = @($mockComputers | Where-Object { $_.OS -like $OSFilter })

            $filtered.Count | Should -Be 1
            $filtered[0].Name | Should -Be 'PC1'
        }
    }

    It 'Supports GlobalExcludeList with wildcard patterns' {
        InModuleScope PS-ModuleManager {
            # Mock computer data
            $mockComputers = @(
                [PSCustomObject]@{Name='IT-SERVER-01'; OS='Windows Server 2019'}
                [PSCustomObject]@{Name='IT-DESKTOP-02'; OS='Windows 10'}
                [PSCustomObject]@{Name='WEB-SERVER-01'; OS='Windows Server 2019'}
                [PSCustomObject]@{Name='IT-LAPTOP-03'; OS='Windows 11'}
                [PSCustomObject]@{Name='SERVER2'; OS='Windows Server 2016'}
            )

            # Simulate GlobalExcludeList logic with wildcards
            $excludeList = @('it*', 'Server2')
            $filtered = @($mockComputers | Where-Object {
                $computerName = $_.Name
                $shouldExclude = $false
                foreach ($pattern in $excludeList) {
                    if ($computerName -like $pattern) {
                        $shouldExclude = $true
                        break
                    }
                }
                -not $shouldExclude
            })

            $filtered.Count | Should -Be 1
            $filtered[0].Name | Should -Be 'WEB-SERVER-01'
        }
    }

    It 'GlobalExcludeList supports exact names without wildcards' {
        InModuleScope PS-ModuleManager {
            $mockComputers = @(
                [PSCustomObject]@{Name='SERVER1'; OS='Windows Server 2019'}
                [PSCustomObject]@{Name='SERVER2'; OS='Windows Server 2016'}
                [PSCustomObject]@{Name='DESKTOP1'; OS='Windows 10'}
            )

            $excludeList = @('SERVER2')
            $filtered = @($mockComputers | Where-Object {
                $computerName = $_.Name
                $shouldExclude = $false
                foreach ($pattern in $excludeList) {
                    if ($computerName -like $pattern) {
                        $shouldExclude = $true
                        break
                    }
                }
                -not $shouldExclude
            })

            $filtered.Count | Should -Be 2
            $filtered.Name | Should -Contain 'SERVER1'
            $filtered.Name | Should -Contain 'DESKTOP1'
            $filtered.Name | Should -Not -Contain 'SERVER2'
        }
    }

    It 'GlobalExcludeList supports multiple wildcard patterns' {
        InModuleScope PS-ModuleManager {
            $mockComputers = @(
                [PSCustomObject]@{Name='DEV-SERVER-01'}
                [PSCustomObject]@{Name='TEST-DESKTOP-01'}
                [PSCustomObject]@{Name='PROD-SERVER-01'}
                [PSCustomObject]@{Name='QA-LAPTOP-01'}
            )

            $excludeList = @('dev-*', 'test-*', 'qa-*')
            $filtered = @($mockComputers | Where-Object {
                $computerName = $_.Name
                $shouldExclude = $false
                foreach ($pattern in $excludeList) {
                    if ($computerName -like $pattern) {
                        $shouldExclude = $true
                        break
                    }
                }
                -not $shouldExclude
            })

            $filtered.Count | Should -Be 1
            $filtered[0].Name | Should -Be 'PROD-SERVER-01'
        }
    }

    It 'OSFilter returns empty when no matches' {
        InModuleScope PS-ModuleManager {
            $mockComputers = @(
                [PSCustomObject]@{Name='PC1'; OS='Windows 10 Pro'}
                [PSCustomObject]@{Name='PC2'; OS='Windows 11 Pro'}
            )

            $OSFilter = '*Linux*'
            $filtered = @($mockComputers | Where-Object { $_.OS -like $OSFilter })

            $filtered.Count | Should -Be 0
        }
    }

    It 'Combines OSFilter and GlobalExcludeList correctly' {
        InModuleScope PS-ModuleManager {
            # Start with computers
            $mockComputers = @(
                [PSCustomObject]@{Name='IT-PC-01'; OS='Windows 10 Pro'}
                [PSCustomObject]@{Name='IT-PC-02'; OS='Windows 10 Pro'}
                [PSCustomObject]@{Name='WEB-SRV-01'; OS='Windows Server 2019'}
                [PSCustomObject]@{Name='DEV-PC-01'; OS='Windows 10 Pro'}
            )

            # Apply OSFilter first (Windows 10 only)
            $OSFilter = '*Windows 10*'
            $filtered = @($mockComputers | Where-Object { $_.OS -like $OSFilter })

            # Then apply GlobalExcludeList (exclude IT-*)
            $excludeList = @('it-*')
            $filtered = @($filtered | Where-Object {
                $computerName = $_.Name
                $shouldExclude = $false
                foreach ($pattern in $excludeList) {
                    if ($computerName -like $pattern) {
                        $shouldExclude = $true
                        break
                    }
                }
                -not $shouldExclude
            })

            $filtered.Count | Should -Be 1
            $filtered[0].Name | Should -Be 'DEV-PC-01'
        }
    }
}
