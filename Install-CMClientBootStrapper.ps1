<#
.SYNOPSIS
    Installs the CM Agent and launches a predefined provisioning task sequence
.DESCRIPTION
    This script will launch the ccmsetup bootstrap agent and immedaitely kick off a provisioning task sequence to configure a system.
.PARAMETER MP
Specifies the Management Point in your MEMCM Site.
.PARAMETER FSP
Specifies the Fallback Status Point in your MEMCM Site to send status messages to.
.PARAMETER CMSiteCode
Specifies the Site Code for your MEMCM Site.
.PARAMETER DNSSuffix
Specifies the DNS Suffix that your clients should use during installation.
.PARAMETER ProvisionTSDeploymentID
Specifies the Deployment ID of your Providioning Task Sequence.
.PARAMETER Domain
Specifies the Domain to join the system to. - The default is DOMAIN.COM
.PARAMETER OUName
Specifies the Domain Organizational Unit to join the system to. - Default is Application if the chosen OU doesnt exist you will be redirected to Application.
.PARAMETER Description
Specifies the Description of the system to be applied to the AD Computer Object and Description field on the local system.
.PARAMETER Role
Specifies the Role the system will be deployed as ie a full build,limited application deployment or Domain Controller role. - The Default is Full Build.
.PARAMETER WorkgroupJoin
Specifies if the system should be joined to a workgroup or not. - Default is False only add this flag if you want to join a workgroup.
.EXAMPLE
    # Default - Joins systems to the DOMAIN.COM Domain and places them in the Application OU with no description.
    PS> .\Install-CMClientBootStrapper.ps1

    # Custom Domain and OU with Description.
    PS> .\Install-CMClientBootStrapper.ps1 -Domain "CORP.DOMAIN.COM" -OUName "Infrastructure" -Description "Azure VM File Server - owner jdoe"

    # Custom Domain and OU with Description and limited role aka core applications only.
    PS> .\Install-CMClientBootStrapper.ps1 -Domain "AD.DOMAIN.COM" -OUName "Web" -Description "Azure VM IIS Server - owner jsmith" -Role "SHB Base Image - Required Applications Only"

    # Workgroup join with Description
    PS> .\Install-CMClientBootStrapper.ps1 -Description "Azure VM IIS Server - owner jsmith" -WorkgroupJoin
.NOTES
    FileName:   Install-CMClientBootStrapper.ps1
    Author:     Brandon Linton
    Contact:    @Lintnotes
    Created:    2022-02-03
    Updated:
    Version History:
        1.0.0 - (2022-02-03) - Script Created

Disclaimer. The sample scripts are not supported under any Microsoft standard support program or service.
The sample scripts are provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#>

[cmdletbinding()]
Param(
    [Parameter(Mandatory = $False, HelpMessage = "Enter the name of your Management Point")]
    [string]$MP = "CMMP.DOMAIN.COM",
    [Parameter(Mandatory = $False, HelpMessage = "Enter the name of your Fallback Status Point")]
    [string]$FSP = "CMFSP.DOMAIN.COM",
    [Parameter(Mandatory = $False, HelpMessage = "Enter the name of your CM Site Code")]
    [string]$CMSiteCode = "NA1",
    [Parameter(Mandatory = $False, HelpMessage = "Enter the name of your DNS Suffix")]
    [string]$DNSSuffix = "DOMAIN.COM",
    [Parameter(Mandatory = $False, HelpMessage = "Enter the Deployment ID of your Provisioning TS")]
    [string]$ProvisionTSDeploymentID = "NA120018",
    [Parameter(Mandatory = $False, HelpMessage = "Enter the Domain you wish to join.")]
    [ValidateSet("DOMAIN.COM", "AD.DOMAIN.COM", "DEV-TEST.DOMAIN.COM")]
    [string]$Domain = "DOMAIN.COM",
    [Parameter(Mandatory = $False, HelpMessage = "Enter the OU Name you wish to join the system to.")]
    [ValidateSet("Application", "Backup", "Citrix", "Cluster", "Database", "File and Print", "IA", "Infrastructure", "Messaging", "Network Services", "Web", "Workstations")]
    [string]$OUName = "Application",
    [Parameter(Mandatory = $False, HelpMessage = "Enter the Description of the System.")]
    [string]$Description = "",
    [Parameter(Mandatory = $False, HelpMessage = "Enter the Role type of the system to deploy.")]
    [ValidateSet("SHB Corporate Image - Full Build", "SHB Base Image - Required Applications Only", "SHB UMC Image - Unmanaged BYOD", "SHB Domain Controller Image - DS Specific Applications")]
    [string]$Role = "SHB Corporate Image - Full Build",
    [Parameter(Mandatory = $False, HelpMessage = "Workgroup join the device. -Default value is False if flag is used device will be joined to a workgroup.")]
    [Switch]$WorkgroupJoin
)

Function Log-Message() {
    param
    (
        [Parameter(Mandatory = $true, HelpMessage = "Value added to the log file.")]
        [ValidateNotNullOrEmpty()]
        [string] $Value,

        [Parameter(Mandatory = $true, HelpMessage = "Severity for the log entry. 1 for Informational, 2 for Warning and 3 for Error.")]
        [ValidateNotNullOrEmpty()]
        [ValidateSet("0","1", "2", "3")]
        [string]$Severity,

        [Parameter(Mandatory = $false, HelpMessage = "Name of the log file that the entry will written to.")]
        [ValidateNotNullOrEmpty()]
        [string]$FileName = "Install-CMClientBootStrapper.log"
    )

    Try {
        #Set the Location of the Log
        $Script:LogFilePath = Join-Path  -Path "$PSScriptRoot" -ChildPath $FileName

        # Construct time stamp for log entry
        if (-not (Test-Path -Path 'variable:global:TimezoneBias')) {
            [string]$global:TimezoneBias = [System.TimeZoneInfo]::Local.GetUtcOffset((Get-Date)).TotalMinutes
            if ($TimezoneBias -match "^-") {
                $TimezoneBias = $TimezoneBias.Replace('-', '+')
            }
            else {
                $TimezoneBias = '-' + $TimezoneBias
            }
        }
        $Time = -join @((Get-Date -Format "HH:mm:ss.fff"), $TimezoneBias)

        #Get the current date
        $Date = (Get-Date -Format "MM-dd-yyyy")

        # Construct context for log entry
        $Context = $([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)

        # Construct final log entry
        $LogText = "<![LOG[$($Value)]LOG]!><time=""$($Time)"" date=""$($Date)"" component=""Powershell"" context=""$($Context)"" type=""$($Severity)"" thread=""$($PID)"" file="""">"

        # Add value to log file
        try {
            Out-File -InputObject $LogText -Append -NoClobber -Encoding Default -FilePath $LogFilePath -ErrorAction Stop
        }
        catch [System.Exception] {
            Write-Warning -Message "Unable to append log entry to $FileName file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }

        Switch ($Severity) {
            0 { $Color = 'White'}
            1 { $Color = 'Green' }
            2 { $Color = 'Yellow' }
            3 { $Color = 'Red' }
        }
        Write-Host "Message: '$Value'" -ForegroundColor $Color
    }
    Catch {
        Write-Host -f Red "Error:" $_.Exception.Message
    }
}

Clear-Host
Log-Message "Script Execution Started" -Severity 0
Log-Message "Script Logging: $($LogFilePath)" -Severity 0
Log-Message "Gathering Data Please be patient..." -Severity 0

$OSDVarsFile = New-Item -Path $env:WINDIR\Temp -Name "OSDVarsFile.txt" -ItemType File -Force

Log-Message "Disabling Firewall Profiles." -Severity 0
Set-NetFirewallProfile -All -Enabled False
function Get-ADDomainInfo {
    param (
        [String]$Name,
        [String]$Path
    )
    $Domains = @()
    $Domains += [PSCustomObject]@{
        Name   = "CORP.DOMAIN.COM"
        Path = @(
            "OU=Application,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Backup,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Cluster,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Citrix,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Database,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=File and Print,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=IA,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Infrastructure,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Messaging,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Network Services,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Web,OU=Member Servers,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Finance,OU=Devices,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=IT,OU=Devices,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Legal,OU=Devices,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Marketing,OU=Devices,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=Sales,OU=Devices,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM",
            "OU=VDI,OU=Devices,OU=Enterprise,DC=CORP,DC=DOMAIN,DC=COM")
    }
    $Domains += [PSCustomObject]@{
        Name   = "AD.DOMAIN.COM"
        Path = @(
            "OU=Application,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Backup,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Cluster,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Citrix,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Database,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=File and Print,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=IA,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Infrastructure,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Messaging,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Network Services,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Web,OU=Member Servers,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Finance,OU=Devices,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=IT,OU=Devices,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Legal,OU=Devices,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Marketing,OU=Devices,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=Sales,OU=Devices,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM",
            "OU=VDI,OU=Devices,OU=Enterprise,DC=AD,DC=DOMAIN,DC=COM")
                $Domains += [PSCustomObject]@{
        Name   = "DOMAIN.COM"
        Path = @(
            "OU=Application, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Backup, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Cluster, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Citrix, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Database, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=File and Print, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=IA, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Infrastructure, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Messaging, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Network Services, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Web, OU=Member Servers, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Finance, OU=Devices, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=IT, OU=Devices, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Legal, OU=Devices, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Marketing, OU=Devices, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=Sales, OU=Devices, OU=Enterprise, DC=DOMAIN,DC=COM",
            "OU=VDI, OU=Devices, OU=Enterprise, DC=DOMAIN,DC=COM")
    }
    Return $Domains
}

If($WorkgroupJoin -ne $True){
    try {
        $DestinationOU = (Get-ADDomainInfo | Where-Object { $_.Name -eq $Domain -and $_.Path -match $OUName }).Path
        Log-Message "$OUName OU was selected, Path: $DestinationOU" -Severity 1
    }
    catch {
        $DestinationOU = (Get-ADDomainInfo | Where-Object { $_.Name -eq $Domain -and $_.Path -match "Application"}).Path
        Log-Message "$OUName OU was selected but does not exist defaulting to Application, Path: $DestinationOU" -Severity 2
    }
}

Log-Message "Saving OSD Variables Locally." -Severity 0
Log-Message "OSDComputerName=$env:computername" -Severity 1
Add-Content -Path $OSDVarsFile -Value "OSDComputerName=$env:computername"
If ($WorkgroupJoin -ne $True) {
    Add-Content -Path $OSDVarsFile -Value "OSDDomainName=$Domain"
    Add-Content -Path $OSDVarsFile -Value "OSDDomainOUName=$DestinationOU"
    Log-Message "OSDDomainName=$Domain" -Severity 1
    Log-Message "OSDDomainOUName=$DestinationOU" -Severity 1
}
Else {
    Add-Content -Path $OSDVarsFile -Value "OSDDomainName="
    Add-Content -Path $OSDVarsFile -Value "OSDDomainOUName="
    Add-Content -Path $OSDVarsFile -Value "OSDNetworkJoinType=1"
    Log-Message "OSDDomainName=" -Severity 1
    Log-Message "OSDDomainOUName=" -Severity 1
    Log-Message "OSDNetworkJoinType=1" -Severity 1
}
Add-Content -Path $OSDVarsFile -Value "OSDComputerDescription=$Description"
Add-Content -Path $OSDVarsFile -Value "OSDRoleChoice=$Role"
Add-Content -Path $OSDVarsFile -Value "OSDStartTime=$(Get-Date -Format g)"
Log-Message "OSDComputerDescription=$Description" -Severity 1
Log-Message "OSDRoleChoice=$Role" -Severity 1
Log-Message "OSDStartTime=$(Get-Date -Format g)" -Severity 1

Log-Message "Attempting to download ccmsetup.exe" -Severity 0
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$CCMBootStrap = "$PSScriptRoot\ccmsetup.exe"

try {
    $Uri = "http://$($MP)/CCM_Client/ccmsetup.exe"
    Invoke-WebRequest -Uri $Uri -OutFile $CCMBootStrap
    Log-Message "Succesfully Downloaded ccmsetup from $($Uri)" -Severity 1
}
catch {
    $Uri = "https://raw.githubusercontent.com/balinton/MEMCM/master/ccmsetup.exe"
    Invoke-WebRequest -Uri $Uri -OutFile $CCMBootStrap
    Log-Message "Succesfully Downloaded ccmsetup from $($Uri)" -Severity 2
}

If (Test-Path $CCMBootStrap) {
    Log-Message "Invoking ccmsetup with supplied params." -Severity 0
    Start-Process -FilePath $CCMBootStrap -ArgumentList "/mp:$MP SMSMP=$MP SMSSLP=$MP FSP=$FSP SMSSiteCode=$CMSiteCode CCMLOGLEVEL=1 CCMLOGMAXHISTORY=6 CCMLOGMAXSIZE=2621440 SMSCACHESIZE=20480 DNSSUFFIX=$DNSSuffix PROVISIONTS=$ProvisionTSDeploymentID"
}
Else {
    Log-Message "Script Execution Failed." -Severity 3
}

Log-Message "Script Execution Complete." -Severity 0



