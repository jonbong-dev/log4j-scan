@{
    RootModule        = 'Log4jScan.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b7f5a3e2-4c9d-4f0a-9e1b-4c5d6e7f8a9b'
    Author            = 'log4j-scan updated edition (PowerShell port)'
    CompanyName       = 'Community'
    Copyright         = 'MIT'
    Description       = 'Native PowerShell Log4Shell scanner with a user-initiated live CVE update engine and WPF/TUI GUI front-end.'
    PowerShellVersion = '5.1'
    FunctionsToExport = @(
        'Invoke-Log4jTargetScan',
        'Get-Log4jCveInfo',
        'Update-Log4jCveDatabase',
        'Get-Log4jCveDatabase',
        'Get-CallbackHost',
        'Expand-Log4jPayload'
    )
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
    PrivateData       = @{
        PSData = @{
            Tags       = @('security', 'log4j', 'log4shell', 'cve', 'scanner')
            LicenseUri = 'https://opensource.org/licenses/MIT'
            ProjectUri = 'https://github.com/fullhunt/log4j-scan'
        }
    }
}
