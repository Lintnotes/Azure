<#
.SYNOPSIS
    Detects and Reports Windows Azure VM Agent Version.
.DESCRIPTION
    This script will verify if the Windows Azure VM Agent Version is installed and report back the version.
.EXAMPLE
    Get-AzureVMAgentVersion
.NOTES
    FileName:   Get-AzureVMAgentVersion.ps1
    Author:     Brandon Linton
    Contact:    @Lintnotes
    Created:    2021-12-15
    Updated:    
    Version History:
        1.0.0 - (2021-12-15) - Script Created
        
    Links: https://github.com/Azure/WindowsVMAgent/blob/main/release-notes/2.7.md

Disclaimer. The sample scripts are not supported under any Microsoft standard support program or service. 
The sample scripts are provided AS IS without warranty of any kind. 
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#>

$Script:Model = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Model).Model
$Script:Manufacturer = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Manufacturer).Manufacturer
$Script:IsVirtual = ($Model -Match 'Virtual' -or $Model -Match 'VMware' -or $Manufacturer -Match 'Xen' -or $Manufacturer -Match 'QEUMU' -or $Manufacturer -Match 'Google' -or $Manufacturer -Match 'Amazon')
$Script:Is64Bit = [System.Environment]::Is64BitOperatingSystem
$Script:MinimumSupportedVersion = '2.7.1198.911'

If(!($IsVirtual)){
    Write-Host "Detected Physical System Aborting Script..."
    Break
}
ElseIf (!(Get-Service WindowsAzureGuestAgent -ErrorAction SilentlyContinue)) {
    Write-Host "Detected Non-Azure VM - $($Manufacturer) $($Model)"
    Break
}
Else{
    If ($Is64Bit -eq $True) {
        $Script:AgentInfo = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -match [regex]::Escape("Azure VM Agent") }
    }
    Else {
        $Script:AgentInfo = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*') |  Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Where-Object { $_.DisplayName -match [regex]::Escape("Azure VM Agent") }
    }
    If ($AgentInfo) {
        Write-Host "Detected Manual Install of Windows Azure VM Agent Version: $($AgentInfo.DisplayVersion)"
        If ($($AgentInfo.DisplayVersion -lt $MinimumSupportedVersion)) {
            Write-Host "Detected Unsupported Version please upgrade immediately." 
        }
        Break
    }
    Elseif (Test-Path $env:SystemDrive\WindowsAzure) {
        $Script:AgentInfo = (Get-ChildItem -Path $env:SystemDrive\WindowsAzure -Filter "WindowsAzureGuestAgent.exe" -Recurse)
        Write-Host "Detected Portal Install of Windows Azure VM Agent Version: $($AgentInfo.VersionInfo.ProductVersion)"
        If($($AgentInfo.VersionInfo.ProductVersion -lt $MinimumSupportedVersion)){
            Write-Host "Detected Unsupported Version please upgrade immediately."
        }
    }
    Else {
        Write-Host "Windows Azure VM Agent NOT Installed."
    }
}