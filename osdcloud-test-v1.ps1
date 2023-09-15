#=========================================================
#   OSDCloud 
#   Windows 11 22H2 Enterprise EN-US Volume
#
#   version: 0.1 - Intial version
#
#=========================================================

#=========================================================
#   Set Version and Title
#=========================================================
$Version = "1.0"
$Title = "OSD Cloud Windows installation"
$host.UI.RawUI.WindowTitle = $Title
Write-Host -ForegroundColor Green "Starting OSDCloud version $Version"

#=========================================================
#   Set Environment Variables
#=========================================================
$env:APPDATA = "C:\Windows\System32\Config\SystemProfile\AppData\Roaming"
$env:LOCALAPPDATA = "C:\Windows\System32\Config\SystemProfile\AppData\Local"
$Env:PSModulePath = $env:PSModulePath+";C:\Program Files\WindowsPowerShell\Scripts"
$env:Path = $env:Path+";C:\Program Files\WindowsPowerShell\Scripts"

#=========================================================
#   Set TLS 1.2
#=========================================================
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

#=========================================================
#   Set Debug to True if you want the errors to be shown
#=========================================================
$OSDDEBUG = "True"

If ($OSDDEBUG -eq "True") {
   Write-Host -ForegroundColor Red "Script is in debug mode!"
}

#=========================================================
#   Change the ErrorActionPreference to 'SilentlyContinue' 
#   or 'Continue'
#=========================================================
If ($OSDDEBUG -ne "True") {
   $ErrorActionPreference = 'SilentlyContinue'
   $ProgressPreference = 'SilentlyContinue'
   $WarningPreference = 'SilentlyContinue'
   }
   Else {
	$ErrorActionPreference = 'Continue'
	$ProgressPreference = 'Continue'
	$WarningPreference = 'Continue'
}

#=========================================================
#   Check if power is plugged in, if not give a warning 
#   and continue after 60 seconds.
#=========================================================
If (([Windows.Forms.SystemInformation]::PowerStatus).PowerLineStatus -ne "Online") {
    Write-Host -ForegroundColor Red "Please insert AC Power, installation might fail if on battery"
    Write-Host -ForegroundColor Red "Installation will continue in 60 seconds!"
    Start-Sleep -Seconds 60
}

#=========================================================
#   [OS] Start-OSDCloud with Parameters
#=========================================================
Start-Sleep -Seconds 5
Start-OSDCloud -ZTI -OSVersion 'Windows 11' -OSBuild 22H2 -OSEdition Enterprise -OSLanguage en-us -OSLicense Volume

#================================================
#   Collect Settings
#================================================
$Started = "Started="
$Started | Out-File X:\OSDCloud\preset.txt -append -NoNewLine
$StartTime = (Get-Date) | Out-File X:\OSDCloud\preset.txt -append -NoNewLine 

Copy-Item "X:\OSDCloud\preset.txt" "C:\OSDCloud\preset.txt" -Force
$Versionvar = "Version="
$Versionvar | Out-File c:\OSDCloud\set.txt -NoNewline
$Version | Out-File c:\OSDCloud\set.txt -append
$Started = "Started="
$Started | Out-File c:\OSDCloud\set.txt -append -NoNewLine
$StartTime = (Get-Date) | Out-File c:\OSDCloud\set.txt -append -NoNewLine

#================================================
#  WinPE PostOS
#  create and write to oobe.cmd
#================================================
Write-Host -ForegroundColor Green "Creating Scripts for OOBE phase"
$OOBEcmdTasks = @'
@echo off
# Import WiFi XML's if they exist
start /wait powershell.exe -NoL -ExecutionPolicy Bypass -F C:\Windows\Setup\Scripts\wifi.ps1
Start-Sleep -Seconds 10
# Download and Install PowerShell 7
start /wait powershell.exe -NoL -ExecutionPolicy Bypass -F C:\Windows\Setup\Scripts\ps.ps1
# VcRedist Download and install supported versions
start /wait pwsh.exe -NoL -ExecutionPolicy Bypass -F C:\Windows\Setup\Scripts\VcRedist.ps1
# Run oobe.ps1 script
start /wait pwsh.exe -NoL -ExecutionPolicy Bypass -F C:\Windows\Setup\Scripts\oobe.ps1
exit 
'@
$OOBEcmdTasks | Out-File -FilePath 'C:\Windows\Setup\scripts\oobe.cmd' -Encoding ascii -Force

#================================================
#   [OS] Check for WinPE WiFi and export profiles
#================================================ 
$XmlDirectory = "C:\Windows\Setup\Scripts"
$wifilist = $(netsh.exe wlan show profiles)
Install-Module -Name VcRedist -Force | Out-Null
write-host "Searching for WiFi Networks configured during WinRE phase" -ForegroundColor Green
if ($null -ne $wifilist -and $wifilist -like 'Profiles on interface Wi-Fi*') {
    $ListOfSSID = ($wifilist | Select-string -pattern "\w*All User Profile.*: (.*)" -allmatches).Matches | ForEach-Object {$_.Groups[1].Value}
    $NumberOfWifi = $ListOfSSID.count
    foreach ($SSID in $ListOfSSID){
        try {
            Write-Host "Exporting WiFi SSID:$SSID"
            $XML = $(netsh.exe wlan export profile name=`"$SSID`" key=clear folder=`"$XmlDirectory`")
            }
            catch [System.Exception] {
                Write-Host -ForegroundColor Red "Failed export of Wifi on system"
                Write-Host -ForegroundColor Red "The error is: $XML"
            }
        }
    }
    Else {
    	Write-Host -ForegroundColor Yellow "No WiFi networks to export, please keep machine connected to a network cable during installation."
        Write-Host -ForegroundColor Yellow $wifilist
    }


#================================================
#  WinPE PostOS
#  Download and install Windows PowerShell 7
#================================================
$OOBEpsTasks = @'
$Title = "OOBE PowerShell 7 Download and install"
$host.UI.RawUI.WindowTitle = $Title
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = "SilentlyContinue"
$WarningPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
write-host "PowerShell 7 Download and install" -ForegroundColor Green
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-PowerShell.log"
$null = Start-Transcript -Path (Join-Path "C:\Windows\Temp" $Transcript ) -ErrorAction Ignore
$env:APPDATA = "C:\Windows\System32\Config\SystemProfile\AppData\Roaming"
$env:LOCALAPPDATA = "C:\Windows\System32\Config\SystemProfile\AppData\Local"
$Env:PSModulePath = $env:PSModulePath+";C:\Program Files\WindowsPowerShell\Scripts"
$env:Path = $env:Path+";C:\Program Files\WindowsPowerShell\Scripts"
Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
Install-Module -Name PowerShellGet -Force | Out-Null
$job = Start-Job -ScriptBlock {Invoke-Expression "& { $(Invoke-RestMethod 'https://aka.ms/install-powershell.ps1') } -UseMSI -Quiet"}
if($job |Wait-Job -Timeout 300) {
  if($job.State -eq 'Completed') {
     Write-Host "PowerShell 7 installed" -ForegroundColor Green
     Start-Sleep -Seconds 5       
  }
  else {
     Write-Host -ForegroundColor Red "Oops, something went wrong!"
     Write-Host -ForegroundColor Red "The error was: $job.State"
     Write-Host -ForegroundColor Red "Lets reboot and try again!"
     Start-Sleep -Seconds 10
     Restart-Computer -Force    
  }
}
'@
$OOBEpsTasks | Out-File -FilePath 'C:\Windows\Setup\scripts\ps.ps1' -Encoding ascii -Force


#================================================
#   WinPE PostOS
#   oobe.ps1
#================================================
$OOBETasks = @'
$Title = "OOBE Windows capabilities and update phase"
$host.UI.RawUI.WindowTitle = $Title
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-OOBE.log"
$null = Start-Transcript -Path (Join-Path "C:\Windows\Temp" $Transcript ) -ErrorAction Ignore
write-host "Powershell Version: "$PSVersionTable.PSVersion -ForegroundColor Green
$OOBESHIFTF10 = "True"
$OSDDEBUG = "False"
If ($OSDDEBUG -eq "True") {
   Write-Host -ForegroundColor Red "Script is in debug mode!"
}
# Change the ActionPreferences
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$WarningPreference = 'SilentlyContinue'
# Set Environment
Write-Host "Set Environment" -ForegroundColor Green
$env:APPDATA = "C:\Windows\System32\Config\SystemProfile\AppData\Roaming"
$env:LOCALAPPDATA = "C:\Windows\System32\Config\SystemProfile\AppData\Local"
$Env:PSModulePath = $env:PSModulePath+";C:\Program Files\WindowsPowerShell\Scripts"
$env:Path = $env:Path+";C:\Program Files\WindowsPowerShell\Scripts"
#Define Icons
    $CheckIcon = @{
        Object          = [Char]8730
        ForegroundColor = 'Green'
        NoNewLine       = $true
    }
# Register Powershell Modules and install tools
Write-Host "Register PSGallery" -ForegroundColor Green
Register-PSRepository -Default | Out-Null
#Write-Host "Install PackageManagement Module" -ForegroundColor Green
#Install-Module -Name PackageManagement -Force | Out-Null
Write-Host "Install PowerShellGet Module" -ForegroundColor Green
Install-Module -Name PowerShellGet -Force | Out-Null
Write-Host -ForegroundColor Green "Install OSD Module"
Install-Module OSD -Force | Out-Null
Write-Host -ForegroundColor Green "Install PSWindowsUpdate Module"
Install-Module PSWindowsUpdate -Force | Out-Null
Start-Sleep -Seconds 5
Clear-Host

Write-Host -ForegroundColor Green "Settings Registry key's to disable some default Windows settings"

#Disables Wi-fi Sense
Write-Host "Disabling Wi-Fi Sense"
$WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
$WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
$WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
If (!(Test-Path $WifiSense1)) {
   New-Item $WifiSense1
}
Set-ItemProperty $WifiSense1  Value -Value 0 
If (!(Test-Path $WifiSense2)) {
   New-Item $WifiSense2
}
Set-ItemProperty $WifiSense2  Value -Value 0 
Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
Start-Sleep -Seconds 1

# Disabled Chat and stopping it from comming back
Write-Host "Disabling Teams Chat app and stopping it from comming back"
$registryPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications"
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}
Set-ItemProperty $registryPath ConfigureChatAutoInstall -Value 0
$registryPath = "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Chat"
If (!(Test-Path $registryPath)) { 
    New-Item $registryPath
}
Set-ItemProperty $registryPath "ChatIcon" -Value 2
Start-Sleep -Seconds 5
Clear-Host

# Remove apps from system
Write-Host -ForegroundColor Green "Remove Builtin Apps"
# Create array to hold list of apps to remove 
$appname = @(
"Clipchamp.Clipchamp"
"Microsoft.BingNews"
"Microsoft.BingWeather"
"Microsoft.GamingApp"
"Microsoft.MicrosoftOfficeHub"
"Microsoft.MicrosoftSolitaireCollection"
"Microsoft.People"
"Microsoft.PowerAutomateDesktop"
"Microsoft.WindowsAlarm"
"Microsoft.windowscommunicationsapps"
"Microsoft.WindowsFeedbackHub"
"Microsoft.WindowsMaps"
"Microsoft.Xbox.TCUI"
"Microsoft.XboxGameOverlay"
"Microsoft.XboxGamingOverlay"
"Microsoft.XboxIdentityProvider"
"Microsoft.XboxSpeechToTextOverlay"
"Microsoft.ZuneMusic"
"Microsoft.ZuneVideo"
"MicrosoftCorporationII.MicrosoftFamily"
"MicrosoftCorporationII.QuickAssist"
) 
ForEach($app in $appname){
    try  {
          # Get Package Name
          $AppProvisioningPackageName = Get-AppxProvisionedPackage -Online | Where-Object { $_.DisplayName -like $app } | Select-Object -ExpandProperty PackageName -First 1
          If (![String]::IsNullOrEmpty($AppProvisioningPackageName)) {
            Write-Host "$($AppProvisioningPackageName) found. Attempting removal ... " -NoNewline
          }
          
          # Attempt removeal if Appx is installed
          If (![String]::IsNullOrEmpty($AppProvisioningPackageName)) {
            Write-Host "removing ... " -NoNewline
            $RemoveAppx = Remove-AppxProvisionedPackage -PackageName $AppProvisioningPackageName -Online -AllUsers
          } 
                   
          #Re-check existence
          $AppProvisioningPackageNameReCheck = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $App }
          If ([string]::IsNullOrEmpty($AppProvisioningPackageNameReCheck) -and ($RemoveAppx.Online -eq $true)) {
                   Write-Host @CheckIcon
                   Write-Host " (Removed)"
            }
        }
           catch [System.Exception] {
               Write-Host " (Failed or $App not on system)"
           }
}
Start-Sleep -Seconds 5
Clear-Host 
Write-Host -ForegroundColor Green "Install another .Net Framework"
$Result = Get-MyWindowsCapability -Match 'NetFX' -Detail
foreach ($Item in $Result) {
    if ($Item.State -eq 'Installed') {
        Write-Host -ForegroundColor DarkGray "$($Item.DisplayName)"
    }
    else {
        Write-Host -ForegroundColor Green "$($Item.DisplayName)"
        $Item | Add-WindowsCapability -Online -ErrorAction Ignore | Out-Null
    }
}
#disable Powershell 2.0 - Powershell 2.0 is no longer blocked when .NET 3.5 is installed. Powershell 2 is security risk and will be disabled
Write-Host -ForegroundColor Green "Powershell 2.0 is no longer blocked when .NET 3.5 is installed. Powershell 2 is security risk and will be disabled"
Disable-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2Root" | Out-Null
Start-Sleep -Seconds 5
Clear-Host

#Install Driver updates
$ProgressPreference = 'Continue'
Write-Host -ForegroundColor Green "Install Drivers from Windows Update"
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-Drivers.log"
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
$driverupdates = Install-WindowsUpdate -UpdateType Driver -NotTitle "Preview" -AcceptAll -IgnoreReboot | Out-File "c:\OSDCloud\DriverUpdate.log" -force
$Pathsetdri = "c:\OSDCloud\DriverUpdate.log"
(gc $Pathsetdri) | ? {$_.trim() -ne "" } | set-content $Pathsetdri
$waardesset1 = Get-Content $Pathsetdri | Select-String -Pattern 'Installed'
$upd2 = $waardesset1 -replace "(?m)^.{43}" 
$resultdriverupdatessplit = $upd2| foreach {$_ +  "<br/>"}
$ProgressPreference = 'SilentlyContinue'
Start-Sleep -Seconds 5
Clear-Host

#Install Software updates
Write-Host -ForegroundColor Green "Install Windows Updates"
$Transcript = "$((Get-Date).ToString('yyyy-MM-dd-HHmmss'))-Updates.log"
Add-WUServiceManager -MicrosoftUpdate -Confirm:$false | Out-Null
$softwareupdates = Install-WindowsUpdate -MicrosoftUpdate -NotTitle "Preview" -AcceptAll -IgnoreReboot | Out-File "c:\OSDCloud\WindowsUpdate.log" -force
$Pathsetupd = "c:\OSDCloud\WindowsUpdate.log"
(gc $Pathsetupd) | ? {$_.trim() -ne "" } | set-content $Pathsetupd
$waardesset = Get-Content $Pathsetupd| Select-String -Pattern 'Installed'
$upd3 = $waardesset -replace "(?m)^.{43}" 
$resultsoftwareupdatessplit = $upd3 | foreach {$_ +  "<br/>"}
$ProgressPreference = 'SilentlyContinue'
Start-Sleep -Seconds 5
Clear-Host

#Sending Teams message about installion
#Write-Host -ForegroundColor Green "Sending Teams message about installation"
#$URI = ''

# Read inputfile
$Pathset = "c:\OSDCloud\set.txt"
$waardesset = Get-Content $Pathset | Out-String | ConvertFrom-StringData 
$verset = $waardesset.Version 
$startset = $waardesset.started
$SSIDset = (Get-NetConnectionProfile).Name
$Pathpreset = "c:\OSDCloud\preset.txt"
$waardespreset = Get-Content $Pathpreset | Out-String | ConvertFrom-StringData 
$startpreset = $waardespreset.started
$usbownerpreset = $waardespreset.USBOwner
$Endime = (Get-Date)
$TimeSpan = New-TimeSpan -Start $startpreset -End $Endime
$Timecompleted = $TimeSpan.ToString("mm' minutes 'ss' seconds'")
$Working_path = "C:\OSDCloud\OS"
$file_version = @(Get-ChildItem $Working_Path\* -include *.esd)
$winversion = $file_version.name -replace ".{4}$"
$Working_path_drv= "C:\Drivers"
$drv_version = @(Get-ChildItem $Working_Path_drv\* -include *.exe,*.msi)
$drvpack = $drv_version.name -replace ".{4}$"
$drvpackProductname = $drv_version.VersionInfo.Productname -replace ".{4}$"
$drvpack = $drvpack +" " +$drvpackProductname
$psversion = $PSVersionTable.PSVersion
$dotnetversion =  (Get-Item C:\Windows\Temp\windowsdesktop-runtime-win-x64.exe).VersionInfo.FileVersion
$paths = @(
	"HKLM:\SOFTWARE\Microsoft\Office\ClickToRun",
	"HKLM:\SOFTWARE\WOW6432Node\Microsoft\Office\ClickToRun"
)
$officeVersion = ""
foreach ($path in $paths)
{
	if (Test-Path -Path "$path\Configuration")
	{
		$officeVersion = (Get-ItemProperty -Path "$path\Configuration" -Name "VersionToReport").VersionToReport
	}
}
$content = Invoke-RestMethod -Uri "https://docs.microsoft.com/en-us/officeupdates/update-history-office365-proplus-by-date" -Method Get
$build = [Version]"$officeVersion"
$content -match "<a href=`"(?<Channel>.+?)`".+?>Version (?<Version>\d{4}) \(Build $($build.Build)\.$($build.Revision)\)"
$output = [PSCustomObject]@{
	Build   = $build
	Version = $Matches['Version']
	Channel = ($Matches['Channel'] -split "#")[0]
}
$office = 'Microsoft 365 Apps for enterprise Version ' + $output.Version + ' Build ' + $output.Build + ' ' + $output.Channel
$VClist = (Get-InstalledVcRedist).Name
$VClistsplit = $VClist | foreach {$_ +  "<br/>"}
$BiosSerialNumber = Get-MyBiosSerialNumber
$ComputerManufacturer = Get-MyComputerManufacturer
$ComputerModel = Get-MyComputerModel
$IPAddress = (Get-WmiObject win32_Networkadapterconfiguration | Where-Object{ $_.ipaddress -notlike $null }).IPaddress | Select-Object -First 1
$connection = Get-NetAdapter -physical | where status -eq 'up'
$int = $connection.InterfaceDescription
$speed = $connection.LinkSpeed
$ip = (Invoke-WebRequest https://ipinfo.io/ip).Content.Trim()
$org = (Invoke-WebRequest https://ipinfo.io/org).Content.Trim()
$body = ConvertTo-Json -Depth 4 @{
   title    = "$pc"
   text   = " "
   sections = @(
   @{
     activityTitle    = 'OS Cloud Installation'
     activitySubtitle = 'OS Deployment'
   },
   @{
     title = '<h2 style=color:blue;>Deployment Details'
     facts = @(
       @{
         name  = 'OSD Cloud version'
         value = $verset
       },
       @{
         name  = 'Completed'
         value = $Timecompleted
       },
       @{
         name  = 'BIOS Serial'
         value = $BiosSerialNumber
       },
        @{
         name  = 'Computer Manufacturer'
         value = "$ComputerManufacturer"
       },
        @{
         name  = 'Computer Model'
         value = "$ComputerModel"
       },
        @{
         name  = 'SSID'
         value = $SSIDset
       },       
        @{
         name  = 'Private IP Address'
         value = $IPAddress
       },
        @{
         name  = 'Public IP Address'
         value = $ip
       },
        @{
         name  = 'Interface'
         value = $int
       },
        @{
         name  = 'LinkSpeed'
         value = $speed
       },
        @{
         name  = 'Provider'
         value = $org
       },
        @{
         name  = 'Windows Image Version'
         value = $winversion
       },         
        @{
         name  = 'Powershell Version'
         value = $psversion
       },          
        @{
         name  = 'Visual C++ Versions'
         value = $VClistsplit
       }, 
        @{
         name  = 'Driver Pack'
         value = $drvpack 
       },
        @{
         name  = 'Sofware Updates'
         value = $resultsoftwareupdatessplit
       },        
       @{
         name  = 'Driver Updates'
         value = $resultdriverupdatessplit
       }
     )
   }
)
}
Invoke-RestMethod -uri $uri -Method Post -body $body -ContentType 'application/json' | Out-Null

Write-Host -ForegroundColor Green "OOBE Installation ready, cleanup and the restarting in 30 seconds!"
Start-Sleep -Seconds 30
If ($OSDDEBUG -eq "False") {
   Remove-Item C:\Drivers -Force -Recurse | Out-Null
   Remove-Item C:\Intel -Force -Recurse | Out-Null
   Remove-Item C:\OSDCloud -Force -Recurse | Out-Null
}

#================================================
#   Disable Shift F10 after installation
#   for security reasons
#================================================
If ($OSDDEBUG -eq "False") {
   If ($OOBESHIFTF10 -eq "False") {
      Remove-Item C:\Windows\Setup\Scripts\*.* -Exclude *.TAG -Force | Out-Null
   }
   Else {
      Remove-Item C:\Windows\Setup\Scripts\*.* -Force | Out-Null
   }
}
Restart-Computer -Force
'@
$OOBETasks | Out-File -FilePath 'C:\Windows\Setup\Scripts\oobe.ps1' -Encoding ascii -Force

#================================================
#   Disable Shift F10 in OOBE
#   for security Reasons
#================================================
If ($OSDDEBUG -eq "False") {
   $Tagpath = "C:\Windows\Setup\Scripts\DisableCMDRequest.TAG"
   If(!(test-path $Tagpath)) {
      #New-Item -ItemType file -Force -Path $Tagpath | Out-Null
      Write-Host -ForegroundColor green "OOBE Shift F10 disabled!"
   }
}

#=========================================================
#   [PostOS] Restart-Computer
#=========================================================
Write-Host -ForegroundColor Green "Restarting in 10 seconds"
Start-Sleep -Seconds 10
wpeutil reboot
