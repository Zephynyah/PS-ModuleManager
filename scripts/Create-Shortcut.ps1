<#
.SYNOPSIS
    Creates a desktop shortcut to launch PS-ModuleManager.
#>

$modulePath = $PSScriptRoot
$shortcutPath = Join-Path ([Environment]::GetFolderPath('Desktop')) 'PS-ModuleManager.lnk'

$shell = New-Object -ComObject WScript.Shell
$shortcut = $shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = 'powershell.exe'
$shortcut.Arguments = "-NoProfile -ExecutionPolicy Bypass -Command `"Import-Module '$modulePath\PS-ModuleManager.psd1' -Force; Show-ModuleManagerGUI -WindowStartupLocation CenterOwner -WindowState Maximized`""
$shortcut.WorkingDirectory = $modulePath
$shortcut.WindowStyle = 1  # Normal window
$shortcut.IconLocation = 'powershell.exe,0'
$shortcut.Description = 'PS-ModuleManager'
$shortcut.Save()

Write-Host "Shortcut created: $shortcutPath" -ForegroundColor Green
