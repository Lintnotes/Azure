<#
.SYNOPSIS
    Configures OS Branding Pack for Windows 10,11, and Windows Server 2016,2019,2022
.DESCRIPTION
    This script will verify Supported Operating Systems and configure the OS Branding Pack for each OS and Organizational Settings.
.EXAMPLE
    Set-OSBrandingPack.ps1
.NOTES
    FileName:   Set-OSBrandingPack.ps1
    Author:     Brandon Linton
    Contact:    @Lintnotes
    Created:    2021-12-20
    Updated:
    Version History:
        1.0.0 - (2021-12-20) - Script Created

Disclaimer. The sample scripts are not supported under any Microsoft standard support program or service.
The sample scripts are provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
#>
[CmdletBinding()]
param(
    [parameter(Mandatory = $False, HelpMessage = "Configure Default Start Menu Layout.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$StartLayout = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Taskbar Layout.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$TaskbarLayout = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Lockscreen.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$LockScreen = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Desktop Wallpaper.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$Wallpaper = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Theme.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$Theme = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure Default Desktop Icons.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$DesktopIcons = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure This PC Desktop Icon to Show Computername")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$ThisPCToComputerName = $True,

    [parameter(Mandatory = $False, HelpMessage = "Configure OEM Branding Information.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$OEMBranding = $True,

    [parameter(Mandatory = $False, HelpMessage = "Enter OEM Branding Company Name")]
    [ValidateNotNullOrEmpty()]
    [string]$Manufacturer = "Microsoft Federal",

    [parameter(Mandatory = $False, HelpMessage = "Enter OEM Branding Company Support #")]
    [ValidateNotNullOrEmpty()]
    [string]$SupportPhone = "610-555-1212",

    [parameter(Mandatory = $False, HelpMessage = "Enter OEM Branding Company Support URL")]
    [ValidateNotNullOrEmpty()]
    [string]$SupportURL = "https://www.microsoft.com/en-us/federal/",

    [parameter(Mandatory = $False, HelpMessage = "Configure HKCU Registry Settings.")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$RegistryHKCU = $True,

    [parameter(Mandatory = $False, HelpMessage = "Disable Teams Consumer Experience")]
    [ValidateNotNullOrEmpty()]
    [ValidateSet("True", "False")]
    [string]$DisableTeams = $True,

    [parameter(Mandatory = $False, HelpMessage = "OS Branding Pack SAS URL")]
    [ValidateNotNullOrEmpty()]
    [string]$OSBrandingPackUri = "https://YOURSTORAGEACCOUNTURL"
)

Function Write-CMLogEntry() {
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
        [string]$FileName = "Set-OSBrandingPack.log"
    )

    Try {
        #Set the Location of the Log
        If (!(Test-Path $ENV:WINDIR\Logs\Software)) {
            New-Item -ItemType Directory -Path $ENV:WINDIR\Logs\Software -Force | Out-Null
        }

        $Script:LogFilePath = Join-Path  -Path "$ENV:WINDIR\Logs\Software" -ChildPath $FileName

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
            Write-Warning -Message "Unable to append log entry to Set-OSBrandingPack.log file. Error message at line $($_.InvocationInfo.ScriptLineNumber): $($_.Exception.Message)"
        }

        Switch ($Severity) {
            0 { $Color = 'White' }
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

# Relaunch script as sysnative if architecture is amd64
If ($ENV:PROCESSOR_ARCHITEW6432 -eq "AMD64") {
    Try {
        &"$ENV:WINDIR\SysNative\WindowsPowershell\v1.0\PowerShell.exe" -File $PSCOMMANDPATH
    }
    Catch {
        Throw "Failed to start $PSCOMMANDPATH"
    }
    Exit
}

#Call the function to Log messages and start main routine
Clear-Host
Write-CMLogEntry -Value "Script Execution Started" -Severity 0
Write-CMLogEntry -Value "Script Logging: $($LogFilePath)" -Severity 0
Write-CMLogEntry -Value "Gathering Data Please be patient..." -Severity 0

# Define Variables
$Script:IsWorkstation = $False
$Script:IsDomainController = $False
$Script:IsServer = $False
$Script:OS = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object Caption).Caption
$Script:OSBuild = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object BuildNumber).BuildNumber
$Script:Model = (Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object Model).Model
$Script:Is64Bit = [System.Environment]::Is64BitOperatingSystem
$Script:ProductType = (Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object ProductType).ProductType
switch ($ProductType) {
    1 {$Script:IsWorkstation = $True}
    2 {$Script:IsDomainController = $True}
    3 {$Script:IsServer = $True}
    default { "Unknown" }
}

# Download Branding Pack.
Write-CMLogEntry -Value "Attempting to download OS Branding Pack" -Severity 0
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
$OSBrandingPack = "$PSScriptRoot\OSBrandingPack.zip"

try {
    $Uri = $OSBrandingPackUri
    Invoke-WebRequest -Uri $Uri -OutFile $OSBrandingPack
    Write-CMLogEntry -Value "Succesfully Downloaded OS Branding Pack from $($Uri)" -Severity 1
}
catch {
    Write-CMLogEntry -Value "Failed to download OS Branding Pack from $($Uri)" -Severity 2
}

If(Test-Path $PSScriptRoot\OSBrandingPack.zip){
    Write-CMLogEntry -Value "Extracting files to local storage." -Severity 0
    Expand-Archive -LiteralPath $OSBrandingPack -DestinationPath $PSScriptRoot
}
else {
    Write-CMLogEntry -Value "OS Branding Pack not found..." -Severity 2
    Break
}

#Define Functions

# Configure Start Layout Function
function Set-StartLayout {
    If ($StartLayout -ne $True) {
        Write-CMLogEntry -Value "Start Layout not enabled skipping routine." -Severity 2
    }
    Else {
        Write-CMLogEntry -Value "Configuring Start Layout" -Severity 0
        If ((Test-Path $PSScriptRoot\Files\StartMenu\LayoutModification.json) -and ($OS -match 'Windows 11')) {
            $StartLayoutModification = "$PSScriptRoot\Files\StartMenu\LayoutModification.json"
            Write-CMLogEntry -Value "Detected Start Layout File:$($StartLayoutModification) for $($OS)" -Severity 0
            Copy-Item -Path $StartLayoutModification -Destination "$env:SystemDrive\Users\Default\Appdata\Local\Microsoft\Windows\Shell" -Force | Out-Null
    }
        ElseIf ((Test-Path $PSScriptRoot\Files\StartMenu\LayoutModification.xml) -and ($OS -match 'Windows 10')) {
            $StartLayoutModification = "$PSScriptRoot\Files\StartMenu\LayoutModification.xml"
            Write-CMLogEntry -Value "Detected Start Layout File:$($StartLayoutModification) for $($OS)" -Severity 0
            Import-StartLayout -LayoutPath $StartLayoutModification -MountPath $env:SystemDrive\ -ErrorAction SilentlyContinue
    }
        ElseIf($IsServer -eq $True){
            Write-CMLogEntry -Value "Start Layout not supported on $($OS)." -Severity 2
    }
    Else{
        Write-CMLogEntry -Value "StartLayout File Missing." -Severity 2
    }
        Write-CMLogEntry -Value "Configuring Start Layout Completed Succesfully..." -Severity 1
 }
}

 # Configure Taskbar Layout Function
 function Set-TaskbarLayout {
    If ($TaskbarLayout -ne $True) {
        Write-CMLogEntry -Value "Taskbar Layout not enabled skipping routine." -Severity 1
    }
    Else {
        If ((Test-Path $PSScriptRoot\Files\Taskbar\TaskbarLayoutModification.xml) -and ($OS -match 'Windows 11')) {
            Write-CMLogEntry -Value "Configuring Taskbar Layout" -Severity 0
            $TaskbarLayoutModification = "$PSScriptRoot\Files\Taskbar\TaskbarLayoutModification.xml"
            Write-CMLogEntry -Value "Detected Taskbar Layout File:$($TaskbarLayoutModification) for $($OS)" -Severity 0
            If (!(Test-Path $env:WINDIR\OEM)) { New-Item -ItemType Directory -Path $env:WINDIR\OEM -Force | Out-Null }
            Copy-Item -Path $TaskbarLayoutModification -Destination $env:WINDIR\OEM -Force | Out-Null
            New-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name LayoutXMLPath -Value $env:WINDIR\OEM\TaskbarLayoutModification.xml -Force | Out-Null
    }
        ElseIf ($OS -notmatch "Windows 11") {
            Write-CMLogEntry -Value "Taskbar Layout not supported on $($OS)." -Severity 2
        }
    Else {
        Write-CMLogEntry -Value "Taskbar Layout File Missing." -Severity 2
    }
        Write-CMLogEntry -Value "Configuring Taskbar Layout Completed Succesfully..." -Severity 1
    }
 }

 function Set-DefaultTheme {
If($Theme -ne $True){
    Write-CMLogEntry -Value "Theme not enabled skipping routine..." -Severity 0
}
else{
        Write-CMLogEntry -Value "Configuring Default Windows Corporate Theme." -Severity 0
        Copy-Item "$PSScriptRoot\Files\Theme\CorporateTheme.theme" -Destination $env:WINDIR\Resources\Themes -Force | Out-Null
        $Null = New-Item -Path "HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\Personalization" -ItemType Directory -Force | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name ThemeFile -Value "$env:WINDIR\Resources\Themes\CorporateTheme.Theme" -PropertyType String -Force  | Out-Null
    }
}

function Set-DefaultWallpaper {
     If($Wallpaper -ne $True){
         Write-CMLogEntry -Value "Default Wallpaper not enabled skipping routine." -Severity 2
     }
     Else{
         Write-CMLogEntry -Value "Configuring Default Wallpaper." -Severity 0
         $Files = Get-ChildItem -Path "$env:WINDIR\Web\Wallpaper\Windows","$env:WINDIR\Web\4K\Wallpaper\Windows" -Recurse | Where-Object { $_.Extension -eq ".jpg" }
         Write-CMLogEntry -Value "Replacing Default Wallpaper with Corporate Wallpaper." -Severity 0
        foreach ($Item in $Files) {
            Write-CMLogEntry -Value "Taking Ownership of $($Item.FullName)" -Severity 0
            takeown /f $Item.FullName
            Write-CMLogEntry -Value "Granting Full Control Permission to Administrators Group for $($Item.FullName)" -Severity 0
            & icacls $Item.FullName /grant "Administrators:(F)"
            Remove-Item -Path $Item.FullName -Force -ErrorAction SilentlyContinue | Out-Null
            Write-CMLogEntry -Value "Deleting $($Item.Fullname)" -Severity 0
        }
        Copy-Item "$PSScriptRoot\Files\Wallpaper\CorporateWallpaper.jpg" -Destination $env:WINDIR\Web\Wallpaper\Windows\img0.jpg -Force | Out-Null
        Copy-Item "$PSScriptRoot\Files\Wallpaper\CorporateWallpaper.jpg" -Destination $env:WINDIR\Web\4K\Wallpaper\Windows\img0.jpg -Force | Out-Null
        Copy-Item "$PSScriptRoot\Files\Wallpaper\*" -Destination $env:WINDIR\Web\4K\Wallpaper\Windows -Recurse -Force
        Copy-Item "$PSScriptRoot\Files\Wallpaper\CorporateWallpaper.jpg" -Destination $env:WINDIR\Web\Wallpaper -Force | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\Control Panel\Desktop" -Name Wallpaper -Value "$env:windir\Web\Wallpaper\CorporateWallpaper.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
     }
 }

  function Set-DefaultLockscreen {
     If($LockScreen -ne $True){
         Write-CMLogEntry -Value "Default Lockscreen not enabled skipping routine." -Severity 2
     }
     Else{
        Write-CMLogEntry -Value "Configuring Default Lockscreen." -Severity 0
        $Files = Get-ChildItem -Path "$env:WINDIR\Web\Screen" -Recurse | Where-Object { $_.Name -eq "img100.jpg" -or $_.Name -eq "img105.jpg" }

        Write-CMLogEntry -Value "Replacing Default Lockscreen with Corporate Lockscreen." -Severity 0
        foreach ($Item in $Files) {
            Write-CMLogEntry -Value "Taking Ownership of $($Item.FullName)" -Severity 0
            takeown /f $Item.FullName
            Write-CMLogEntry -Value "Granting Full Control Permission to Administrators Group for $($Item.FullName)" -Severity 0
            & icacls $Item.FullName /grant "Administrators:(F)"
            Remove-Item -Path $Item.FullName -Force -ErrorAction SilentlyContinue | Out-Null
            Write-CMLogEntry -Value "Deleting $($Item.Fullname)" -Severity 0
        }
        Copy-Item "$PSScriptRoot\Files\Lockscreen\CorporateLockScreen.jpg" -Destination $env:WINDIR\Web\Screen\img100.jpg -Force | Out-Null
        Copy-Item "$PSScriptRoot\Files\Lockscreen\CorporateLockScreen.jpg" -Destination $env:WINDIR\Web\Screen\img105.jpg -Force | Out-Null

        If($OS -notcontains 'Server'){
        Write-CMLogEntry -Value "Disabling Locksreen Tools Tips and Rotation" -Severity 0
        If (!(Test-Path HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager)) { $Null = New-Item HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager -ItemType Directory -Force | Out-Null }
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name RotatingLockScreenOverlayEnabled -Value "0" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name RotatingLockScreenEnabled -Value "0" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null

        Write-CMLogEntry -Value "Disabling Lockscreen Bing Rotation" -Severity 0
        If (!(Test-Path "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative")) { $Null = New-Item "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -ItemType Directory -Force | Out-Null}
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name LockImageFlags -Value "0" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name LockScreenOptions -Value "0" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name CreativeId -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name DescriptionText -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name ActionText -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name ActionUri -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name PlacementId -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name ClickthroughToken -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name ImpressionToken -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name CreativeJson -Value "" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name PortraitAssetPath -Value "0" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name LandscapeAssetPath -Value "$env:WINDIR\Web\Screen\img100.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name LockImageFlags -Value "$env:WINDIR\Web\Screen\img100.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Lock Screen\Creative" -Name HotspotImageFolderPath -Value "$env:WINDIR\Web\Screen\img100.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null

        Write-CMLogEntry -Value "Disabling Spotlight" -Severity 0
        If (!(Test-Path HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\CloudContent)) { $Null = New-Item HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\CloudContent -ItemType Directory -Force | Out-Null}
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name DisableWindowsSpotlightFeatures -Value "1" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
        }

        Write-CMLogEntry -Value "Disabling Windows LogonBackGroundImage" -Severity 0
        $Null = New-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\System" -Name DisableLogonBackgroundImage -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null

        Write-CMLogEntry -Value "Enforcing Lockscreen" -Severity 0
        If (!(Test-Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization)) { $Null = New-Item HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Force | Out-Null}
        $Null = New-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization" -Name LockScreenImage -Value "$env:WINDIR\Web\Screen\img100.jpg" -PropertyType String -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name UseDefaultTile -Value "1" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
        $Null = New-ItemProperty "HKLM:\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name UseDefaultTile -Value "1" -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
     }
 }

 function Set-DesktopIcons {
    If($DesktopIcons -ne $True){
        Write-CMLogEntry -Value "Desktop Icons not enabled skipping routine." -Severity 1
    }
    Else{
        Write-CMLogEntry -Value "Configuring Default Windows Desktop Icons - Desktop,Documents,Control Panel,Recycle Bin" -Severity 0
        # Desktop
        $Null = New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
        # Documents
        $Null = New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{59031a47-3f72-44a7-89c5-5595fe6b30ee}" -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
        # Control Panel
        $Null = New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{5399E694-6CE5-4D6C-8FCE-1D8870FDCBA0}" -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
        # Recycle Bin
        $Null = New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{645FF040-5081-101B-9F08-00AA002F954E}" -Value 0 -PropertyType "Dword" -Force -EA SilentlyContinue | Out-Null
    }
 }

 Function Set-ThisPCToComputerName{
     If($ThisPCToComputerName -ne $True){
         Write-CMLogEntry -Value "This PC to Computername not enabled skipping routine." -Severity 1
     }
     Else{
        If ($IsServer -eq $True) {
            Write-CMLogEntry -Value "This PC To Computername not supported on $($OS)." -Severity 2
        }
        Else{
        Write-CMLogEntry -Value "Configuring This PC to display $($env:computername) on the desktop." -Severity 0
            function enable-privilege {
                param(
                    ## The privilege to adjust. This set is taken from
                    ## http://msdn.microsoft.com/en-us/library/bb530716(VS.85).aspx
                    [ValidateSet(
                        "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege",
                        "SeChangeNotifyPrivilege", "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege",
                        "SeCreatePermanentPrivilege", "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege",
                        "SeDebugPrivilege", "SeEnableDelegationPrivilege", "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege",
                        "SeIncreaseQuotaPrivilege", "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege",
                        "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", "SeManageVolumePrivilege",
                        "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
                        "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege",
                        "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege",
                        "SeTakeOwnershipPrivilege", "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege",
                        "SeUndockPrivilege", "SeUnsolicitedInputPrivilege")]
                    $Privilege,
                    ## The process on which to adjust the privilege. Defaults to the current process.
                    $ProcessId = $pid,
                    ## Switch to disable the privilege, rather than enable it.
                    [Switch] $Disable
                )

                ## Taken from P/Invoke.NET with minor adjustments.
                $definition = @'
 using System;
 using System.Runtime.InteropServices;

 public class AdjPriv
 {
  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall,
   ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr relen);

  [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
  internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
  [DllImport("advapi32.dll", SetLastError = true)]
  internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
  [StructLayout(LayoutKind.Sequential, Pack = 1)]
  internal struct TokPriv1Luid
  {
   public int Count;
   public long Luid;
   public int Attr;
  }

  internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
  internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
  internal const int TOKEN_QUERY = 0x00000008;
  internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
  public static bool EnablePrivilege(long processHandle, string privilege, bool disable)
  {
   bool retVal;
   TokPriv1Luid tp;
   IntPtr hproc = new IntPtr(processHandle);
   IntPtr htok = IntPtr.Zero;
   retVal = OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
   tp.Count = 1;
   tp.Luid = 0;
   if(disable)
   {
    tp.Attr = SE_PRIVILEGE_DISABLED;
   }
   else
   {
    tp.Attr = SE_PRIVILEGE_ENABLED;
   }
   retVal = LookupPrivilegeValue(null, privilege, ref tp.Luid);
   retVal = AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
   return retVal;
  }
 }
'@

                $processHandle = (Get-Process -Id $ProcessId).Handle
                $type = Add-Type $definition -PassThru
                $type[0]::EnablePrivilege($processHandle, $Privilege, $Disable)
            }

            #Take OwnerShip
            enable-privilege SeTakeOwnershipPrivilege
            $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}", [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [System.Security.AccessControl.RegistryRights]::takeownership)
            # You must get a blank acl for the key b/c you do not currently have access
            $acl = $key.GetAccessControl([System.Security.AccessControl.AccessControlSections]::None)
            $identity = "BUILTIN\Administrators"
            $me = [System.Security.Principal.NTAccount]$identity
            $acl.SetOwner($me)
            $key.SetAccessControl($acl)

            # After you have set owner you need to get the acl with the perms so you can modify it.
            $acl = $key.GetAccessControl()
            $rule = New-Object System.Security.AccessControl.RegistryAccessRule ($identity, "FullControl", "Allow")
            $acl.SetAccessRule($rule)
            $key.SetAccessControl($acl)

            $key.Close()


            #Grant Rights to Admin & System
            # Set Adminstrators of Full Control of Registry Item
            $RegistryPath = "Registry::HKEY_CLASSES_ROOT\CLSID\{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

            $identity = "BUILTIN\Administrators"
            $RegistrySystemRights = "FullControl"
            $type = "Allow"
            # Create new rule
            $RegistrySystemAccessRuleArgumentList = $identity, $RegistrySystemRights, $type
            $RegistrySystemAccessRule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList $RegistrySystemAccessRuleArgumentList
            # Apply new rule
            $NewAcl.SetAccessRule($RegistrySystemAccessRule)
            Set-Acl -Path $RegistryPath -AclObject $NewAcl


            # Set SYSTEM to Full Control of Registry Item
            $identity = "NT AUTHORITY\SYSTEM"
            $RegistrySystemRights = "FullControl"
            $type = "Allow"
            # Create new rule
            $RegistrySystemAccessRuleArgumentList = $identity, $RegistrySystemRights, $type
            $RegistrySystemAccessRule = New-Object -TypeName System.Security.AccessControl.RegistryAccessRule -ArgumentList $RegistrySystemAccessRuleArgumentList
            # Apply new rule
            $NewAcl.SetAccessRule($RegistrySystemAccessRule)
            Set-Acl -Path $RegistryPath -AclObject $NewAcl


            #Set the Values to actually make this work
            Set-Item -Path $RegistryPath -Value $env:COMPUTERNAME -Force
            Set-ItemProperty -Path $RegistryPath -Name "LocalizedString" -Value  $env:COMPUTERNAME -Force
            #Enable the "This PC" Icon to show on Desktop
            $Null = Set-ItemProperty -Path "HKLM:Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel" -Name "{20D04FE0-3AEA-1069-A2D8-08002B30309D}" -Value 0 -Force
        }
    }
 }

Function Set-OEMBranding {
    If($OEMBranding -ne $True){
        Write-CMLogEntry -Value "OEM Branding not enabled skipping routine." -Severity 2
    }
    Else{
        Write-CMLogEntry -Value "Configuring OEM Branding Information" -Severity 0
        $OEMLogo = "$PSScriptRoot\Files\OEMLogo\OEMLogo.bmp"
        Copy-Item $OEMLogo $env:WINDIR\OEM -Force -ErrorAction SilentlyContinue | Out-Null
        Copy-Item "$PSScriptRoot\Files\UserLogos\" "$env:SystemDrive\ProgramData\Microsoft\User Account Pictures" -Recurse -Force | Out-Null
        Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "UseDefaultTile" -Value "1" -Force -ErrorAction SilentlyContinue | Out-Null
        $OEMKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation"
        Set-ItemProperty -Path $OEMKey -Name "Model" -Value $Script:Model -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "HelpCustomized" -Value 00000000 -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "SupportHours" -Value "24/7" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "Logo" -Value "$env:WINDIR\OEM\OEMLogo.bmp" -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "Manufacturer" -Value $Manufacturer -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "SupportPhone" -Value $SupportPhone -ErrorAction SilentlyContinue | Out-Null
        Set-ItemProperty -Path $OEMKey -Name "SupportURL" -Value $SupportURL -ErrorAction SilentlyContinue | Out-Null
    }
}

Function Set-RegistryHKCU{
    If ($RegistryHKCU -ne $True) {
        Write-CMLogEntry -Value "Registry HKCU Settings not enabled skipping routine." -Severity 2
    }
    Else {
        Write-CMLogEntry -Value "Configuring HKCU Registry Settings" -Severity 0
        Write-CMLogEntry -Value "Configuring File Name Extensions" -Severity 0
        If (!(Test-Path HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced)) { $Null = New-Item HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced -Force | Out-Null }
        New-ItemProperty -Path "HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "HideFileExt" -Value 0 -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
            
        If ($OS -Match "2019|2022") {
            Write-CMLogEntry -Value "Fixing Borderless Windows in Windows Server 2019 and 2022" -Severity 0
            New-ItemProperty -Path "HKLM:\Temp\Control Panel\Desktop" -Name "UserPreferencesMask" -Value "([byte[]](0x90,0x32,0x07,0x80,0x10,0x00,0x00,0x00))" -PropertyType "Binary" -Force
        }
        If ($OS -Match "Windows 11" -and $DisableTeams -eq $True) {
                Write-CMLogEntry -Value "Disabling Teams" -Severity 0
                New-ItemProperty -Path "HKLM:\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "TaskbarMn" -Value 0 -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
                New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Force -ErrorAction SilentlyContinue | Out-Null
                New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Chat" -Name ChatIcon -Value 3 -PropertyType Dword -Force -ErrorAction SilentlyContinue | Out-Null
                Get-AppxPackage -AllUsers -Name '*MicrosoftTeams*' | Remove-AppxPackage -AllUsers -ErrorAction SilentlyContinue
        }
    }
}

Write-CMLogEntry -Value "Detected Operating System: $($OS)" -Severity 0
Write-CMLogEntry "Detected Operating System Version: $($OSBuild)" -Severity 0

If(Test-Path HKLM:\DefaultUser){
    Write-CMLogEntry -Value "Unmounting Default User Hive - Leftover from previous process..." -Severity 3
    reg.exe unload 'HKLM\DefaultUser'
    Start-Sleep -Seconds 5
}
Write-CMLogEntry -Value "Mounting Default User Hive" -Severity 0
Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load HKLM\Temp $env:SystemDrive\Users\Default\NTUSER.dat" -WindowStyle Hidden -PassThru -Wait | Out-Null

Write-CMLogEntry -Value "Renaming OS Drive Label" -Severity 0
Get-Volume -DriveLetter C | Set-Volume -NewFileSystemLabel OS

Set-StartLayout
Set-TaskbarLayout
Set-DefaultWallpaper
Set-DefaultLockscreen
Set-DefaultTheme
Set-DesktopIcons
Set-ThisPCToComputerName
Set-OEMBranding
Set-RegistryHKCU


# Cleanup and dispose of variables.
Get-Variable Registry* | Remove-Variable
[gc]::Collect()
Start-Sleep -Seconds 5
Set-Location C:\
Write-CMLogEntry -Value "Unmounting Default User Hive" -Severity 0
reg.exe unload 'HKLM\Temp'
If (Test-Path $PSScriptRoot\Files) { Remove-Item $PSScriptRoot\Files -Recurse -Force}
