@{

    # Script module file associated with this manifest
    RootModule        = 'PS-ModuleManager.psm1'

    # Version number of this module
    ModuleVersion     = '2.0.0'

    # Unique ID for this module
    GUID              = 'a3f7c8d2-1e4b-4f9a-b6c5-8d2e3f4a5b6c'

    # Author of this module
    Author            = 'PS-ModuleManager Contributors'

    # Company or vendor of this module
    CompanyName       = ''

    # Copyright statement for this module
    Copyright         = '(c) 2026. All rights reserved.'

    # Description of the functionality provided by this module
    Description       = 'A WPF-based PowerShell Module Manager for installing, updating, and removing PowerShell modules on local and remote domain-joined computers via ADSI and PowerShell Remoting.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '5.1'

    # Required .NET Framework version
    DotNetFrameworkVersion = '4.5'

    # Assemblies that must be loaded prior to importing this module
    RequiredAssemblies = @(
        'PresentationFramework'
        'PresentationCore'
        'WindowsBase'
        'System.Xaml'
    )

    # Functions to export from this module
    FunctionsToExport = @(
        'Show-ModuleManagerGUI',
        'Get-ADSIInfo'
    )

    # Cmdlets to export from this module
    CmdletsToExport   = @()

    # Variables to export from this module
    VariablesToExport  = @()

    # Aliases to export from this module
    AliasesToExport    = @()

    # Private data to pass to the module specified in RootModule
    PrivateData       = @{
        PSData = @{
            Tags       = @('WPF', 'GUI', 'ModuleManager', 'ActiveDirectory', 'ADSI', 'Remoting')
            LicenseUri = ''
            ProjectUri = ''
        }
    }

    # HelpInfo URI of this module
    # HelpInfoURI = ''
}
