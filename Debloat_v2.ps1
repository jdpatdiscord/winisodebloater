# Copyright 2022, jdp_ (alias) DWIG: Debloated Windows Image Generator

param (
    [Parameter(Mandatory=$true, HelpMessage="Specify directory the script will work within.")] 
        [String]$WorkingDir,
    [Parameter(Mandatory=$true, HelpMessage="Specify which Windows edition.")] 
        [String]$Edition,
    [Parameter(HelpMessage="Leave work like folders and files behind.")] 
        [Switch]$Breadcrumbs = $false
)

$IsoURL = "https://software.download.prss.microsoft.com/dbazure/Win10_21H2_English_x64.iso?t=67e364a7-f7a3-4301-8dee-86083e27302e&e=1659006240&h=63a3e8e80c0ba650f16771138553065b29c1842b46687e2005a053cb1c1c9a38"

$DesiredEdition = $Edition

$INPUT_ISO = "$($DesiredEdition).iso"
$OUTPUT_ISO = "$($DesiredEdition) Debloated.iso"

$DebugMode = $true

Function Debug-Print
{
    param (
        [String]$Msg
    )

    if ($DebugMode -eq $true)
    {
        Echo $Msg
    }
}

if (!(Test-Path -Path "$($WorkingDir)"))
{
    Debug-Print -Msg "Creating working directory"
    Mkdir $WorkingDir | Out-Null
}

if (!(Test-Path -Path "$($WorkingDir)\$($INPUT_ISO)"))
{
    Try
    {
        Debug-Print -Msg "Downloading .ISO"
        Invoke-WebRequest -Uri $IsoURL -OutFile "$($WorkingDir)\$($INPUT_ISO)" | Out-Null
    } Catch [System.Net.WebException] {
        Echo "An error occured when downloading the Windows 10 .ISO. Please go to the following link:`r`nhttps://tb.rg-adguard.net/public.php and refresh the link, or source a new download for the image."
    } Catch [System.IO.IOException] {
        Echo "Could not write file to disk. Check permissions."
    }

    Return
}


$DeploymentTools_Path = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\"
$CopyPE_Path = "${env:ProgramFiles(x86)}\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment"

if (!(Test-Path -Path $DeploymentTools_Path))
{
    Echo "It looks like you don't have the Windows ADK installed. Please install it from the following link:`r`nhttps://docs.microsoft.com/en-us/windows-hardware/get-started/adk-install"
    Return
}

$Arch = ${env:PROCESSOR_ARCHITECTURE}.ToLower() # amd64 arm arm64 x86

$MountResult = Mount-DiskImage -ImagePath (Resolve-Path -Path "$($WorkingDir)\$($INPUT_ISO)")

$DriveLetter = ($MountResult | Get-Volume).DriveLetter

$Installation_WIM_Path = Resolve-Path -Path "$($DriveLetter):\sources\install.wim"
$Boot_WIM_Path = Resolve-Path -Path "$($DriveLetter):\sources\boot.wim"

if (!(Test-Path -Path $Installation_WIM_Path) -or !(Test-Path -Path $Boot_WIM_Path))
{
    Echo "Either the installation or boot image are missing, you may have a bad .ISO. If you think this is an issue, proceed to contact the author."
    Dismount-DiskImage -ImagePath (Resolve-Path -Path "$($WorkingDir)\$($INPUT_ISO)")
    Return
}

$Installation_WIM_Mirror_Path = "$($WorkingDir)\install_copy.wim"

if (!(Test-Path -Path $Installation_WIM_Mirror_Path))
{
    Debug-Print -Msg "Extracting target edition: $($DesiredEdition)"
    Export-WindowsImage -SourceImagePath $Installation_WIM_Path -SourceName $DesiredEdition -DestinationImagePath $Installation_WIM_Mirror_Path -DestinationName $DesiredEdition | Out-Null
}

# Done with the .ISO

Debug-Print -Msg "Unmounting .ISO"
Dismount-DiskImage -ImagePath (Resolve-Path -Path "$($WorkingDir)\$($INPUT_ISO)") | Out-Null

# Mount the .WIM.

$MountedFS_Name = "WinFS"
$MountedFS_Dir = "$($WorkingDir)\$($MountedFS_Name)"
$MountedFS_DriverDir = "$($MountedFS_Dir)\Windows\System32\drivers"

if (!(Test-Path -Path $MountedFS_Dir))
{
    Debug-Print -Msg "Created filesystem directory"
    Mkdir $MountedFS_Dir | Out-Null
}

(Get-Item -Path $Installation_WIM_Mirror_Path).IsReadOnly = $false

Debug-Print -Msg "Mounting image"
Dism /Quiet /Mount-Image /Index:1 /Imagefile:$Installation_WIM_Mirror_Path /MountDir:$MountedFS_Dir

Debug-Print -Msg "Removing Windows Defender"

$UndesiredDrivers = "WdBoot.sys", 
                    "WdFilter.sys", 
                    "WdNisDrv.sys"

$Reference_ACL = Get-Acl "$($MountedFS_Dir)"
$Original_ACL = Get-Acl "$($MountedFS_Dir)"

Takeown /f "$($MountedFS_Dir)" | Out-Null

Takeown /f "$($MountedFS_Dir)\Windows" | Out-Null
Takeown /f "$($MountedFS_Dir)\Windows\System32" | Out-Null
Takeown /f "$($MountedFS_Dir)\Windows\System32\drivers" | Out-Null

$DomainPlusUser = "$($env:USERDOMAIN)\$($env:USERNAME)"

$NewAccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($DomainPlusUser, "FullControl", "None", "None", "Allow")
$Reference_ACL.SetAccessRule($NewAccessRule)

Set-Acl "$($MountedFS_Dir)" $Reference_ACL

Set-Acl "$($MountedFS_Dir)\Windows" $Reference_ACL
Set-Acl "$($MountedFS_Dir)\Windows\System32" $Reference_ACL
Set-Acl "$($MountedFS_Dir)\Windows\System32\drivers" $Reference_ACL

Foreach ($Driver in $UndesiredDrivers)
{
    $DriverPath = "$($MountedFS_DriverDir)\$($Driver)"

    if (Test-Path -Path $DriverPath)
    {
        Takeown /f $DriverPath | Out-Null
        Remove-Item -Path $DriverPath | Out-Null
    }
}

Set-Acl "$($MountedFS_Dir)\Windows\System32\drivers" $Original_ACL | Out-Null
icacls "$($MountedFS_Dir)\Windows\System32\drivers" /setowner "NT SERVICE\TrustedInstaller" | Out-Null

#

Takeown /f "$($MountedFS_Dir)\Program Files" | Out-Null
Set-Acl "$($MountedFS_Dir)\Program Files" $Reference_ACL | Out-Null

Takeown /r /d Y /f "$($MountedFS_Dir)\Program Files\Windows Defender" | Out-Null
Takeown /r /d Y /f "$($MountedFS_Dir)\Program Files\Windows Defender Advanced Threat Protection" | Out-Null

Set-Acl "$($MountedFS_Dir)\Program Files\Windows Defender" $Reference_ACL | Out-Null
Set-Acl "$($MountedFS_Dir)\Program Files\Windows Defender Advanced Threat Protection" $Reference_ACL | Out-Null

Foreach ($item in Get-ChildItem -Recurse -Path "$($MountedFS_Dir)\Program Files\Windows Defender")
{
    Set-Acl -Path $item.FullName -AclObject $Reference_ACL | Out-Null
}

Foreach ($item in Get-ChildItem -Recurse -Path "$($MountedFS_Dir)\Program Files\Windows Defender Advanced Threat Protection")
{
    Set-Acl -Path $item.FullName -AclObject $Reference_ACL | Out-Null
}

Remove-Item -ErrorAction SilentlyContinue -Force -Recurse -Path "$($MountedFS_Dir)\Program Files\Windows Defender" | Out-Null
Remove-Item -ErrorAction SilentlyContinue -Force -Recurse -Path "$($MountedFS_Dir)\Program Files\Windows Defender Advanced Threat Protection" | Out-Null

Set-Acl "$($MountedFS_Dir)\Program Files" $Original_ACL | Out-Null
icacls "$($MountedFS_Dir)\Program Files" /setowner "NT SERVICE\TrustedInstaller" | Out-Null

#

Debug-Print -Msg "Removing slui.exe"

Takeown /f "$($MountedFS_Dir)\Windows\System32\slui.exe" | Out-Null
Remove-Item -Path "$($MountedFS_Dir)\Windows\System32\slui.exe" | Out-Null

#

Set-Acl "$($MountedFS_Dir)\Windows\System32" $Original_ACL | Out-Null
icacls "$($MountedFS_Dir)\Windows\System32" /setowner "NT SERVICE\TrustedInstaller" | Out-Null

#

Debug-Print -Msg "Applying unattend.xml"

$unattend_xml_content = @"
<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <UserData>
        <AcceptEula>true</AcceptEula>
        <ProductKey>
          <Key>blank</Key>
          <WillShowUI>OnError</WillShowUI>
        </ProductKey>
      </UserData>
    </component>
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <SetupUILanguage>
        <UILanguage>en-US</UILanguage>
      </SetupUILanguage>
      <InputLocale>en-US</InputLocale>
      <UILanguage>en-US</UILanguage>
      <SystemLocale>en-US</SystemLocale>
      <UserLocale>en-US</UserLocale>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <UserAccounts>
        <AdministratorPassword>
          <Value>SomeComplicatedDefaultAdminPassword</Value>
          <PlainText>true</PlainText>
        </AdministratorPassword>
        <LocalAccounts>
          <LocalAccount wcm:action="add">
            <Password>
              <Value>DarnItWouldBeAShame</Value>
              <PlainText>true</PlainText>
            </Password>
            <Name>Administrative User</Name>
            <Group>Users;Administrators</Group>
          </LocalAccount>
        </LocalAccounts>
      </UserAccounts>
      <ProductKey>blank</ProductKey>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <ProtectYourPC>3</ProtectYourPC>
        <HideLocalAccountScreen>true</HideLocalAccountScreen>
        <HideOnlineAccountScreens>true</HideOnlineAccountScreens>
        <HideWirelessSetupInOOBE>true</HideWirelessSetupInOOBE>
        <SkipUserOOBE>true</SkipUserOOBE>
        <SkipMachineOOBE>true</SkipMachineOOBE>
        <HideOEMRegistrationScreen>true</HideOEMRegistrationScreen>
      </OOBE>
    </component>
  </settings>
</unattend>
"@

Out-File -Force -Encoding utf8 -FilePath "$($WorkingDir)\unattend.xml" -InputObject $unattend_xml

$DismApplyUnattendResult = Dism /Image:$MountedFS_Dir /Apply-Unattend:"$($WorkingDir)\unattend.xml"

if ($DismApplyUnattendResult.Contains("formatting errors"))
{
    Mkdir "$($MountedFS_Dir)\Windows\Panther" | Out-Null
    Out-File -Force -Encoding utf8 -FilePath "$($MountedFS_Dir)\Windows\Panther\unattend.xml" -InputObject $unattend_xml

    #Set-Acl "$($MountedFS_Dir)\Windows\Panther" $Original_ACL | Out-Null
    icacls "$($MountedFS_Dir)\Windows\Panther" /setowner "NT AUTHORITY\SYSTEM" | Out-Null

    Debug-Print -Msg "dism.exe thinks the provided unattend.xml is invalid. Please review it carefully. The file has been forcefully applied."
}

#

Set-Acl "$($MountedFS_Dir)\Windows" $Original_ACL | Out-Null
icacls "$($MountedFS_Dir)\Windows" /setowner "NT AUTHORITY\SYSTEM" | Out-Null

#

Debug-Print -Msg "Continuing Windows Defender removal"

Takeown /f "$($MountedFS_Dir)\ProgramData" | Out-Null
Set-Acl "$($MountedFS_Dir)\ProgramData" $Reference_ACL | Out-Null

Takeown /f "$($MountedFS_Dir)\ProgramData\Microsoft" | Out-Null
Set-Acl "$($MountedFS_Dir)\ProgramData\Microsoft" $Reference_ACL | Out-Null

Takeown /r /d Y /f "$($MountedFS_Dir)\ProgramData\Microsoft\Windows Defender" | Out-Null
Takeown /r /d Y /f "$($MountedFS_Dir)\ProgramData\Microsoft\Windows Defender Advanced Threat Protection" | Out-Null

Foreach ($item in Get-ChildItem -Recurse -Path "$($MountedFS_Dir)\ProgramData\Microsoft\Windows Defender")
{
    #Takeown /f $item
    Set-Acl -Path $item.FullName -AclObject $Reference_ACL | Out-Null
}

Foreach ($item in Get-ChildItem -Recurse -Path "$($MountedFS_Dir)\ProgramData\Microsoft\Windows Defender Advanced Threat Protection")
{
    #Takeown /f $item
    Set-Acl -Path $item.FullName -AclObject $Reference_ACL | Out-Null
}

Remove-Item -ErrorAction SilentlyContinue -Force -Recurse -Path "$($MountedFS_Dir)\ProgramData\Microsoft\Windows Defender" | Out-Null
Remove-Item -ErrorAction SilentlyContinue -Force -Recurse -Path "$($MountedFS_Dir)\ProgramData\Microsoft\Windows Defender Advanced Threat Protection" | Out-Null

Set-Acl "$($MountedFS_Dir)\ProgramData\Microsoft" $Original_ACL | Out-Null
icacls "$($MountedFS_Dir)\ProgramData\Microsoft" /setowner "NT SERVICE\TrustedInstaller" | Out-Null

Set-Acl "$($MountedFS_Dir)\ProgramData" $Original_ACL | Out-Null
icacls "$($MountedFS_Dir)\ProgramData" /setowner "NT SERVICE\TrustedInstaller" | Out-Null

#

Set-Acl "$($MountedFS_Dir)" $Original_ACL | Out-Null
icacls "$($MountedFS_Dir)" /setowner "NT SERVICE\TrustedInstaller" | Out-Null

#

Debug-Print -Msg "Cleaning up image"
Dism /Quiet /Image:$MountedFS_Dir /Cleanup-Image /StartComponentCleanup

# PACKAGE REMOVAL!

Debug-Print -Msg "Removing unwanted packages"

$DismPackagelistResult = Dism /Image:"$($MountedFS_Dir)" /Get-Packages

Foreach ($Line in $DismPackagelistResult)
{
    $Result = ($Line -Split (" \: "))
    if ($Result.Count -eq 2)
    {
        if ($Result[0] -eq "Package Identity")
        {
            if (
                ($Result[1].StartsWith("Microsoft-Windows-TabletPCMath")) -or
                ($Result[1].StartsWith("Microsoft-Windows-QuickAssist")) -or
                ($Result[1].StartsWith("Microsoft-Windows-LanguageFeatures-TextToSpeech")) -or
                ($Result[1].StartsWith("Microsoft-Windows-LanguageFeatures-OCR")) -or
                ($Result[1].StartsWith("Microsoft-Windows-LanguageFeatures-Speech")) -or
                #($Result[1].StartsWith("Microsoft-Windows-LanguageFeatures-Basic")) -or
                ($Result[1].StartsWith("Microsoft-Windows-Hello"))
            )
            {
                Debug-Print -Msg "Removing Regular Package $($Result[1])"
                Dism /Quiet /Image:"$($MountedFS_Dir)" /Remove-Package /PackageName:"$($Result[1])"
            }
        }
    }
}

$DismProvisionedAppxPackagelistResult = Dism /Image:"$($MountedFS_Dir)" /Get-ProvisionedAppxPackages

Foreach ($Line in $DismProvisionedAppxPackagelistResult)
{
    $Result = ($Line -Split (" \: "))
    if ($Result.Count -eq 2)
    {
        if ($Result[0] -eq "PackageName")
        {
            if (
                ($Result[1].StartsWith("Microsoft.ZuneVideo")) -or
                ($Result[1].StartsWith("Microsoft.ZuneMusic")) -or
                ($Result[1].StartsWith("Microsoft.YourPhone")) -or
                ($Result[1].StartsWith("Microsoft.XboxSpeechToTextOverlay")) -or
                ($Result[1].StartsWith("Microsoft.XboxIdentityProvider")) -or
                ($Result[1].StartsWith("Microsoft.XboxGamingOverlay")) -or
                ($Result[1].StartsWith("Microsoft.XboxApp")) -or
                ($Result[1].StartsWith("Microsoft.Xbox.TCUI")) -or
                ($Result[1].StartsWith("Microsoft.WindowsStore")) -or
                ($Result[1].StartsWith("Microsoft.WindowsMaps")) -or
                ($Result[1].StartsWith("Microsoft.WindowsFeedbackHub")) -or
                ($Result[1].StartsWith("Microsoft.windowscommunicationsapps")) -or
                ($Result[1].StartsWith("Microsoft.Windows.Photos")) -or
                ($Result[1].StartsWith("Microsoft.Wallet")) -or
                ($Result[1].StartsWith("Microsoft.WindowsAlarms")) -or
                ($Result[1].StartsWith("Microsoft.StorePurchaseApp")) -or
                ($Result[1].StartsWith("Microsoft.SkypeApp")) -or
                ($Result[1].StartsWith("Microsoft.ScreenSketch")) -or
                ($Result[1].StartsWith("Microsoft.People")) -or
                ($Result[1].StartsWith("Microsoft.Office.OneNote")) -or
                ($Result[1].StartsWith("Microsoft.MixedReality.Portal")) -or
                ($Result[1].StartsWith("Microsoft.MSPaint")) -or
                ($Result[1].StartsWith("Microsoft.MicrosoftSolitaireCollection")) -or
                ($Result[1].StartsWith("Microsoft.MicrosoftStickyNotes")) -or
                ($Result[1].StartsWith("Microsoft.MicrosoftOfficeHub")) -or
                ($Result[1].StartsWith("Microsoft.Microsoft3DViewer")) -or
                ($Result[1].StartsWith("Microsoft.Getstarted")) -or
                ($Result[1].StartsWith("Microsoft.GetHelp")) -or
                ($Result[1].StartsWith("Microsoft.BingWeather")) -or
                ($Result[1].StartsWith("Microsoft.DesktopAppInstaller")) -or
                ($Result[1].StartsWith("Microsoft.549981C3F5F10")) -or
                ($Result[1].StartsWith("Microsoft.WindowsCamera"))
            )
            {
                Debug-Print -Msg "Removing Provisioned Appx Package $($Result[1])"
                Dism /Quiet /Image:"$($MountedFS_Dir)" /Remove-ProvisionedAppxPackage /PackageName:"$($Result[1])"
            }
        }
    }
}


#NOTES:
# ProgramData\Microsoft\Windows\Start Menu
# remove System32\quickassist.exe (WITH SHORTCUT)
# remove System32\Narrarator.exe (ELEGANTLY)
# remove System32\WSCollect.exe & WSReset.exe
# consider removing (System32) MusNotification.exe/MusNotificationUx.exe/MusNotifyIcon.exe/MusUpdateHandlers.dll
# consider removing (System32) MicrosoftEdgeBCHost.exe/MicrosoftEdgeCP.exe/MicrosoftEdgeDevTools.exe/MicrosoftEdgeSH.exe
# consider removing (System32) GamePanel.exe
# consider removing (System32) hvsievaluator.exe/hvsigpext.dll/HvsiManagementApi.dll (Windows Defender stuff)

# cool: isoburn.exe

$LayoutModification_xml_content = @"
<?xml version="1.0" encoding="utf-8"?>
<LayoutModificationTemplate 
  xmlns:defaultlayout="http://schemas.microsoft.com/Start/2014/FullDefaultLayout"
  xmlns:start="http://schemas.microsoft.com/Start/2014/StartLayout" 
  Version="1" 
  xmlns="http://schemas.microsoft.com/Start/2014/LayoutModification">
  <LayoutOptions DeviceCategoryHint="Commercial" />
  <LayoutOptions StartTileGroupCellWidth="6" />
  <DefaultLayoutOverride>
    <StartLayoutCollection>
      <defaultlayout:StartLayout GroupCellWidth="6" />
    </StartLayoutCollection>
  </DefaultLayoutOverride>
</LayoutModificationTemplate>
"@

Out-File -Force `
         -Encoding utf8 `
         -FilePath "$($MountedFS_Dir)\Users\Default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" `
         -InputObject $LayoutModification_xml_content

#Dism /Quiet /Image:$MountedFS_Dir /Apply-Unattend:"$($WorkingDir)\unattend.xml"

Debug-Print -Msg "Committing changes to .WIM"
Dism /Quiet /Unmount-image /MountDir:$MountedFS_Dir /Commit

Debug-Print -Msg "Extracting .ISO"

$7z_bat = @"
"$env:ProgramFiles\7-Zip\7z.exe" x -y -o$($WorkingDir)\temp_iso "$($WorkingDir)\$($INPUT_ISO)"
"@

Out-File -Encoding utf8 -FilePath "$($WorkingDir)\7z.bat" -InputObject $7z_bat

$7zinfo = New-Object System.Diagnostics.ProcessStartInfo
$7zinfo.FileName = "$env:ProgramFiles\7-Zip\7z.exe"
$7zinfo.RedirectStandardError = $true
$7zinfo.RedirectStandardOutput = $true
$7zinfo.UseShellExecute = $false
$7zinfo.Arguments = "x -y -o$($WorkingDir)\temp_iso `"$($WorkingDir)\$($INPUT_ISO)`""
$7zinfo.WorkingDirectory = (Get-Location).Path
$7zp = New-Object System.Diagnostics.Process
$7zp.StartInfo = $7zinfo
$7zp.Start() | Out-Null
$7zp.WaitForExit()

#$stdout = $7zp.StandardOutput.ReadToEnd()
#$stderr = $7zp.StandardError.ReadToEnd()

#Echo $stdout
#Echo $stderr

if (-not $Breadcrumbs)
{
    Remove-Item -Force -Path "$($WorkingDir)\7z.bat"
}

Debug-Print -Msg "Replacing install.wim"
Copy-Item -Force -Path $Installation_WIM_Mirror_Path -Destination "$($WorkingDir)\temp_iso\sources\install.wim"

$old_path = $env:Path
$env:Path += ";C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\DISM;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\Imaging;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\BCDBoot;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\Oscdimg;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\AMD64\Wdsmcast;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\HelpIndexer;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\WSIM;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Windows Preinstallation Environment;C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Imaging and Configuration Designer\x86"

Debug-Print -Msg "Generating .ISO"

#Start-Process -Wait -NoNewWindow -FilePath 'oscdimg.exe' -ArgumentList @('-ldebloat', '-m', '-u2', "-b$($WorkingDir)\temp_iso\boot\etfsboot.com", "$($WorkingDir)\temp_iso", "$($OUTPUT_ISO)")

$pinfo = New-Object System.Diagnostics.ProcessStartInfo
$pinfo.FileName = "oscdimg.exe"
$pinfo.RedirectStandardError = $true
$pinfo.RedirectStandardOutput = $true
$pinfo.UseShellExecute = $false
$pinfo.WorkingDirectory = (Get-Location).Path
$pinfo.Arguments = "-ldebloat -m -u2 -b$($WorkingDir)\temp_iso\boot\etfsboot.com `"$($WorkingDir)\temp_iso`" `"$($WorkingDir)\$($OUTPUT_ISO)`""
#Echo $pinfo.Arguments
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $pinfo
$p.Start() | Out-Null
$p.WaitForExit()

#$stdout = $p.StandardOutput.ReadToEnd()
#$stderr = $p.StandardError.ReadToEnd()

#Echo $stdout
#Echo $stderr

if (-not $Breadcrumbs)
{
    Remove-Item -ErrorAction SilentlyContinue -Force -Recurse -Path "$($WorkingDir)\temp_iso"
    Remove-Item -Force -Path "$($WorkingDir)\unattend.xml"
    Remove-Item -Force -Path $Installation_WIM_Mirror_Path 
    Remove-Item -Force -Recurse -Path $MountedFS_Dir
}

$env:Path = $old_path

Debug-Print -Msg "Finished"