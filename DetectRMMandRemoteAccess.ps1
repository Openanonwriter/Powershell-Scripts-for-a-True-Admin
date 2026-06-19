<#
.SYNOPSIS
    Detects known 3rd-party RMM agents AND remote access/remote desktop software.

.DESCRIPTION
    Scans Installed Programs (System + ALL user profiles, including profiles that
    are not currently logged in), Services, Running Processes, and common install
    folders against a signature list. Detection only - changes nothing permanently.

    Registry reads use the .NET [Microsoft.Win32.RegistryKey] API with an explicit
    Registry64 view. This (a) defeats WOW6432Node redirection so 64-bit installs are
    seen even when launched from 32-bit PowerShell, and (b) gives deterministic handle
    disposal so temporarily-mounted user hives can be reliably unloaded again.

.PARAMETER Scope
    "All" (default), "RMM", or "Remote Access" - limits which signature set to scan.

.PARAMETER ExportCsv
    If specified, writes results to a CSV file.

.PARAMETER OutputPath
    Path for the CSV export. If omitted, resolves to the script folder ($PSScriptRoot)
    when run from a file, otherwise to $env:TEMP - never the elevated CWD (System32).

.NOTES
    Requires admin/SYSTEM: loading other users' registry hives (reg load) needs it.
    Portable tools with no install/service footprint are only caught if their
    process happens to be running at scan time.
#>

#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet("All","RMM","Remote Access")]
    [string]$Scope = "All",

    [switch]$ExportCsv,
    [string]$OutputPath
)

# Resolve a safe, absolute output path (avoid System32 when elevated via right-click)
if ([string]::IsNullOrWhiteSpace($OutputPath)) {
    $baseDir = if ($PSScriptRoot) { $PSScriptRoot } else { $env:TEMP }
    $OutputPath = Join-Path $baseDir 'RMM-RemoteAccess-Report.csv'
}

# Use the 64-bit registry view on 64-bit OSes; fall back to default on 32-bit-only OSes
$RegView = if ([Environment]::Is64BitOperatingSystem) {
    [Microsoft.Win32.RegistryView]::Registry64
} else {
    [Microsoft.Win32.RegistryView]::Default
}

# =========================================================================
# Signature Definitions
# =========================================================================
$Signatures = @(
    # ---- RMM Tools ----
    [PSCustomObject]@{ Category = "RMM"; Vendor = "ConnectWise Automate (LabTech)"; ProcessNames = @("LTSVC","LTSvcMon","LTTray"); ServiceNames = @("LTService","LTSvcMon"); DisplayNamePatterns = @("*LabTech*"); FolderPatterns = @("$env:WINDIR\LTSvc") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "ConnectWise Control / ScreenConnect"; ProcessNames = @("ScreenConnect.ClientService","ScreenConnect.WindowsClient"); ServiceNames = @("ScreenConnect*"); DisplayNamePatterns = @("*ScreenConnect*"); FolderPatterns = @("${env:ProgramFiles(x86)}\ScreenConnect Client*","$env:ProgramFiles\ScreenConnect Client*") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "Kaseya VSA"; ProcessNames = @("AgentMon","KaseyaAgentMonSvc"); ServiceNames = @("KaseyaAgentMonSvc","Kaseya Agent Monitor"); DisplayNamePatterns = @("*Kaseya*"); FolderPatterns = @("C:\Kaseya","${env:ProgramFiles(x86)}\Kaseya") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "Datto RMM (CentraStage / AEM)"; ProcessNames = @("CagService","AEMAgent"); ServiceNames = @("CagService"); DisplayNamePatterns = @("*CentraStage*"); FolderPatterns = @("${env:ProgramFiles(x86)}\CentraStage") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "NinjaOne (NinjaRMM)"; ProcessNames = @("NinjaRMMAgent"); ServiceNames = @("NinjaRMMAgent"); DisplayNamePatterns = @("*NinjaRMM*"); FolderPatterns = @("${env:ProgramFiles(x86)}\NinjaRMMAgent","$env:ProgramFiles\NinjaRMMAgent") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "Atera"; ProcessNames = @("AteraAgent","AteraAgentPackageHandler"); ServiceNames = @("AteraAgent"); DisplayNamePatterns = @("*Atera*"); FolderPatterns = @("${env:ProgramFiles(x86)}\ATERA Networks") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "Pulseway"; ProcessNames = @("PCMonitorSrv","PCMonitorManager"); ServiceNames = @("PCMonitorSrv"); DisplayNamePatterns = @("*Pulseway*"); FolderPatterns = @("${env:ProgramFiles(x86)}\PCMonitor") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "N-able N-sight / N-central"; ProcessNames = @("winagent","BASupSrvc"); ServiceNames = @("Advanced Monitoring Agent","Windows Agent Service","BASupSrvc"); DisplayNamePatterns = @("*N-able*"); FolderPatterns = @("${env:ProgramFiles(x86)}\N-able Technologies","${env:ProgramFiles(x86)}\SolarWinds MSP") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "ManageEngine Endpoint/Desktop Central"; ProcessNames = @("dcagentservice"); ServiceNames = @("ManageEngine UEMS*","dcagentservice"); DisplayNamePatterns = @("*Desktop Central*"); FolderPatterns = @("${env:ProgramFiles(x86)}\DesktopCentral_Agent") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "Action1"; ProcessNames = @("Action1_Agent"); ServiceNames = @("Action1_Agent"); DisplayNamePatterns = @("*Action1*"); FolderPatterns = @("$env:ProgramFiles\Action1") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "Domotz"; ProcessNames = @("DomotzAgent"); ServiceNames = @("Domotz*"); DisplayNamePatterns = @("*Domotz*"); FolderPatterns = @("$env:ProgramFiles\Domotz*") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "Level.io"; ProcessNames = @("level-agent"); ServiceNames = @("level*"); DisplayNamePatterns = @("*Level.io*","*Level RMM*"); FolderPatterns = @("$env:ProgramData\level.io") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "SuperOps"; ProcessNames = @("SuperOpsAgent"); ServiceNames = @("SuperOps*"); DisplayNamePatterns = @("*SuperOps*"); FolderPatterns = @("${env:ProgramFiles(x86)}\SuperOps") }
    [PSCustomObject]@{ Category = "RMM"; Vendor = "Naverisk"; ProcessNames = @("NaveriskAgent"); ServiceNames = @("Naverisk*"); DisplayNamePatterns = @("*Naverisk*"); FolderPatterns = @("${env:ProgramFiles(x86)}\Naverisk") }

    # ---- Remote Access Tools ----
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "AnyDesk"; ProcessNames = @("AnyDesk"); ServiceNames = @("AnyDesk"); DisplayNamePatterns = @("*AnyDesk*"); FolderPatterns = @("${env:ProgramFiles(x86)}\AnyDesk","$env:ProgramFiles\AnyDesk","$env:APPDATA\AnyDesk") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "TeamViewer"; ProcessNames = @("TeamViewer","TeamViewer_Service","tv_w32","tv_x64"); ServiceNames = @("TeamViewer"); DisplayNamePatterns = @("*TeamViewer*"); FolderPatterns = @("${env:ProgramFiles(x86)}\TeamViewer","$env:ProgramFiles\TeamViewer") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Splashtop Streamer (unattended)"; ProcessNames = @("SRService","SRServer","SRManager","SRFeature","SplashtopStreamer"); ServiceNames = @("SplashtopRemoteService","SplashtopStreamingService","SplashtopUpdateService"); DisplayNamePatterns = @("*Splashtop Streamer*","*Splashtop Business*","*Splashtop for RMM*"); FolderPatterns = @("${env:ProgramFiles(x86)}\Splashtop\Splashtop Remote\Server","$env:ProgramFiles\Splashtop\Splashtop Remote\Server") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Splashtop SOS (on-demand)"; ProcessNames = @("SplashtopSOS","SplashtopSOS_*"); ServiceNames = @(); DisplayNamePatterns = @("*Splashtop SOS*"); FolderPatterns = @("${env:ProgramFiles(x86)}\Splashtop\Splashtop SOS","$env:ProgramFiles\Splashtop\Splashtop SOS") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "RustDesk"; ProcessNames = @("rustdesk"); ServiceNames = @("RustDesk"); DisplayNamePatterns = @("*RustDesk*"); FolderPatterns = @("$env:ProgramFiles\RustDesk","${env:ProgramFiles(x86)}\RustDesk") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "LogMeIn"; ProcessNames = @("LogMeIn","LMIGuardianSvc","RAMaint"); ServiceNames = @("LogMeIn","LMIGuardianSvc"); DisplayNamePatterns = @("*LogMeIn*"); FolderPatterns = @("${env:ProgramFiles(x86)}\LogMeIn") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "GoTo Remote Support (GoToMyPC / GoToAssist / GoTo Resolve)"; ProcessNames = @("GoToAssist","g2mainh","goto-resolve"); ServiceNames = @("GoToMyPC*","GoToAssist*","GoToResolve*"); DisplayNamePatterns = @("*GoToMyPC*","*GoToAssist*","*GoTo Resolve*","*GoToResolve*","*LogMeIn Resolve*"); FolderPatterns = @("${env:ProgramFiles(x86)}\Citrix\GoToMyPC","${env:ProgramFiles(x86)}\GoToAssist*","${env:ProgramFiles(x86)}\GoTo\Resolve*") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Chrome Remote Desktop"; ProcessNames = @("remoting_host"); ServiceNames = @("chromoting"); DisplayNamePatterns = @("*Chrome Remote Desktop*"); FolderPatterns = @("${env:ProgramFiles(x86)}\Google\Chrome Remote Desktop") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "TightVNC"; ProcessNames = @("tvnserver"); ServiceNames = @("tvnserver"); DisplayNamePatterns = @("*TightVNC*"); FolderPatterns = @("$env:ProgramFiles\TightVNC","${env:ProgramFiles(x86)}\TightVNC") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "UltraVNC"; ProcessNames = @("winvnc"); ServiceNames = @("uvnc_service"); DisplayNamePatterns = @("*UltraVNC*"); FolderPatterns = @("${env:ProgramFiles(x86)}\UVNC BVBA\UltraVNC") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "RealVNC"; ProcessNames = @("vncserver","vncviewer"); ServiceNames = @("vncserver"); DisplayNamePatterns = @("*RealVNC*"); FolderPatterns = @("$env:ProgramFiles\RealVNC") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Zoho Assist"; ProcessNames = @("ZohoAssist","ZA_Connect"); ServiceNames = @("ZohoAssistAgentSvc"); DisplayNamePatterns = @("*Zoho Assist*"); FolderPatterns = @("${env:ProgramFiles(x86)}\ZohoMeeting") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "BeyondTrust / Bomgar"; ProcessNames = @("bomgar-scc","bomgar-pac","bomgar-rdp","bomgar-button"); ServiceNames = @("bomgar-scc"); DisplayNamePatterns = @("*Bomgar*"); FolderPatterns = @("$env:ProgramData\bomgar*") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "DameWare (SolarWinds)"; ProcessNames = @("DWRCS","DWService"); ServiceNames = @("DameWare Mini Remote Control"); DisplayNamePatterns = @("*DameWare*"); FolderPatterns = @("${env:ProgramFiles(x86)}\SolarWinds\DameWare*") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Remote Utilities"; ProcessNames = @("rutserv","rfusclient"); ServiceNames = @("Remote Utilities - Host"); DisplayNamePatterns = @("*Remote Utilities*"); FolderPatterns = @("${env:ProgramFiles(x86)}\Remote Utilities - Host") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Ammyy Admin"; ProcessNames = @("AA_v3","Ammyy_Admin"); ServiceNames = @(); DisplayNamePatterns = @("*Ammyy*"); FolderPatterns = @() }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Supremo"; ProcessNames = @("Supremo","SupremoHelper"); ServiceNames = @("SupremoService"); DisplayNamePatterns = @("*Supremo*"); FolderPatterns = @("$env:ProgramFiles\Supremo","${env:ProgramFiles(x86)}\Supremo") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "ShowMyPC"; ProcessNames = @("showmypc"); ServiceNames = @(); DisplayNamePatterns = @("*ShowMyPC*"); FolderPatterns = @() }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "NoMachine"; ProcessNames = @("nxd","nxservice64","nxplayer"); ServiceNames = @("nxservice64"); DisplayNamePatterns = @("*NoMachine*"); FolderPatterns = @("$env:ProgramFiles\NoMachine") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Radmin"; ProcessNames = @("r_server","Radmin"); ServiceNames = @("Radmin Server V3"); DisplayNamePatterns = @("*Radmin*"); FolderPatterns = @("${env:ProgramFiles(x86)}\Radmin Server 3","$env:ProgramFiles\Radmin Server 3") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "AeroAdmin"; ProcessNames = @("AeroAdmin"); ServiceNames = @(); DisplayNamePatterns = @("*AeroAdmin*"); FolderPatterns = @() }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "NetSupport Manager"; ProcessNames = @("client32","pcicfgui","NSMD32"); ServiceNames = @("NetSupport Manager Agent"); DisplayNamePatterns = @("*NetSupport*"); FolderPatterns = @("${env:ProgramFiles(x86)}\NetSupport\NetSupport Manager") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "ISL Light / ISL Online"; ProcessNames = @("islremotecontrol","ISLLight"); ServiceNames = @(); DisplayNamePatterns = @("*ISL Light*"); FolderPatterns = @() }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "UltraViewer"; ProcessNames = @("UltraViewer_Desktop","UltraViewer_Service"); ServiceNames = @("UltraViewer_Service"); DisplayNamePatterns = @("*UltraViewer*"); FolderPatterns = @("${env:ProgramFiles(x86)}\UltraViewer") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "ToDesk"; ProcessNames = @("ToDesk","ToDesk_Service"); ServiceNames = @("ToDesk_Service"); DisplayNamePatterns = @("ToDesk*"); FolderPatterns = @("$env:ProgramFiles\ToDesk") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "AnyViewer"; ProcessNames = @("AnyViewer"); ServiceNames = @("AnyViewerService"); DisplayNamePatterns = @("*AnyViewer*"); FolderPatterns = @() }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Parsec"; ProcessNames = @("parsecd"); ServiceNames = @("Parsec"); DisplayNamePatterns = @("*Parsec*"); FolderPatterns = @("$env:ProgramFiles\Parsec") }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Iperius Remote"; ProcessNames = @("IperiusRemote"); ServiceNames = @("IperiusRemoteService"); DisplayNamePatterns = @("*Iperius Remote*"); FolderPatterns = @() }
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "LiteManager"; ProcessNames = @("ROMServer","ROMViewer"); ServiceNames = @("LiteManager Pro - Server"); DisplayNamePatterns = @("*LiteManager*"); FolderPatterns = @() }
    # Quick Assist is built into Windows - only flag it when actively RUNNING (process only, no install/service/folder match)
    [PSCustomObject]@{ Category = "Remote Access"; Vendor = "Microsoft Quick Assist (running)"; ProcessNames = @("quickassist"); ServiceNames = @(); DisplayNamePatterns = @(); FolderPatterns = @() }
)

if ($Scope -ne "All") {
    $Signatures = $Signatures | Where-Object { $_.Category -eq $Scope }
}

# -----------------------------------------------------------------------
# Folder pattern normalization: make sure BOTH the native 64-bit Program Files
# (ProgramW6432) and the 32-bit Program Files (x86) roots are scanned, no matter
# which bitness of PowerShell is hosting the script.
# -----------------------------------------------------------------------
$pfX86 = ${env:ProgramFiles(x86)}
$pf64  = $env:ProgramW6432
foreach ($sig in $Signatures) {
    if (-not $sig.FolderPatterns -or $sig.FolderPatterns.Count -eq 0) { continue }
    $set = [System.Collections.Generic.List[string]]::new()
    foreach ($p in $sig.FolderPatterns) { if ($p) { [void]$set.Add($p) } }
    if ($pf64 -and $pfX86 -and ($pf64 -ne $pfX86)) {
        foreach ($p in @($set)) {
            if ($p -like "$pfX86*") {
                [void]$set.Add(($p -replace [regex]::Escape($pfX86), $pf64))
            } elseif ($p -like "$pf64*") {
                [void]$set.Add(($p -replace [regex]::Escape($pf64), $pfX86))
            }
        }
    }
    $sig.FolderPatterns = @($set | Select-Object -Unique)
}

$results = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param($Category, $Vendor, $Method, $Detail, $Extra = "")

    $exists = $results | Where-Object { $_.Vendor -eq $Vendor -and $_.Detail -eq $Detail }
    if (-not $exists) {
        $results.Add([PSCustomObject]@{
            Category        = $Category
            Vendor          = $Vendor
            DetectionMethod = $Method
            Detail          = $Detail
            Extra           = $Extra
        })
    }
}

# =========================================================================
# Registry helpers (.NET API - deterministic disposal, explicit 64-bit view)
# =========================================================================
function Read-UninstallContainer {
    param([Microsoft.Win32.RegistryKey]$Container)
    $list = [System.Collections.Generic.List[object]]::new()
    if ($null -eq $Container) { return $list }
    foreach ($name in $Container.GetSubKeyNames()) {
        $k = $null
        try {
            $k = $Container.OpenSubKey($name)
            if ($k) {
                $dn = $k.GetValue('DisplayName')
                if ($dn) {
                    $list.Add([PSCustomObject]@{
                        DisplayName     = [string]$dn
                        DisplayVersion  = [string]$k.GetValue('DisplayVersion')
                        InstallLocation = [string]$k.GetValue('InstallLocation')
                    })
                }
            }
        } catch {
        } finally {
            if ($k) { $k.Dispose() }
        }
    }
    return $list
}

function Get-InstalledFromBase {
    param(
        [Microsoft.Win32.RegistryKey]$Base,
        [string]$Prefix = "",    # "<SID>\" for HKU subtrees, "" for HKLM
        [switch]$IncludeWow6432Node
    )
    $out = [System.Collections.Generic.List[object]]::new()
    
    $pathsToCheck = [System.Collections.Generic.List[string]]::new()
    $pathsToCheck.Add('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall')
    
    if ($IncludeWow6432Node) {
        $pathsToCheck.Add('SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')
    }

    foreach ($sub in $pathsToCheck) {
        $path = if ($Prefix) { "$Prefix$sub" } else { $sub }
        $cont = $null
        try {
            $cont = $Base.OpenSubKey($path)
            foreach ($e in (Read-UninstallContainer -Container $cont)) { $out.Add($e) }
        } catch {
        } finally {
            if ($cont) { $cont.Dispose() }
        }
    }
    return $out
}

# =========================================================================
# 1. Installed Programs - System + ALL user profiles (loaded and unloaded)
# =========================================================================
$installedPrograms = [System.Collections.Generic.List[object]]::new()
$sidPattern = 'S-1-5-21-(\d+-){3}\d+$'

# Track loaded SIDs using a generic list to prevent array rebuilding penalties
$loadedSids = [System.Collections.Generic.List[string]]::new()

# (a) Machine-wide (HKLM, forced 64-bit view)
$hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $RegView)
try {
    # HKLM is the only hive where the WOW6432Node check is valid and necessary
    foreach ($e in (Get-InstalledFromBase -Base $hklm -IncludeWow6432Node)) { $installedPrograms.Add($e) }
} finally {
    $hklm.Dispose()
}

# (b) Currently-loaded user hives (logged-on users) - never unloaded
$hku = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, $RegView)
try {
    foreach ($sidName in $hku.GetSubKeyNames()) {
        if ($sidName -match $sidPattern) {
            $loadedSids.Add($sidName)
            foreach ($e in (Get-InstalledFromBase -Base $hku -Prefix "$sidName\")) { $installedPrograms.Add($e) }
        }
    }
} finally {
    $hku.Dispose()
}

# (c) Profiles NOT currently loaded - mount NTUSER.DAT, read, then unload safely
$profileList = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*" -ErrorAction SilentlyContinue |
    Where-Object { $_.PSChildName -match $sidPattern -and $_.ProfileImagePath }

foreach ($prof in $profileList) {
    $sid = $prof.PSChildName
    if ($loadedSids.Contains($sid)) { continue }   # already covered in (b)

    $ntUserDat = Join-Path $prof.ProfileImagePath 'NTUSER.DAT'
    if (-not (Test-Path -LiteralPath $ntUserDat)) { continue }

    $mountName = "RMMScan_$sid"
    $null = reg load "HKU\$mountName" "$ntUserDat" 2>&1
    if ($LASTEXITCODE -ne 0) { continue }   # hive in use / inaccessible - skip quietly

    try {
        $hkuMounted = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::Users, $RegView)
        try {
            foreach ($e in (Get-InstalledFromBase -Base $hkuMounted -Prefix "$mountName\")) { $installedPrograms.Add($e) }
        } finally {
            $hkuMounted.Dispose()   # deterministic: release the handle before unloading
        }
    } finally {
        # Unload with retries. .NET .Dispose() above releases the handle deterministically;
        # the GC + retry loop is insurance against any lingering finalizable references so
        # we NEVER leave a user's NTUSER.DAT mounted/locked.
        $unloaded = $false
        for ($attempt = 1; $attempt -le 5 -and -not $unloaded; $attempt++) {
            [System.GC]::Collect()
            [System.GC]::WaitForPendingFinalizers()
            $null = reg unload "HKU\$mountName" 2>&1
            if ($LASTEXITCODE -eq 0) {
                $unloaded = $true
            } else {
                Start-Sleep -Milliseconds 250
            }
        }
        if (-not $unloaded) {
            Write-Warning "Could not unload hive HKU\$mountName for profile '$($prof.ProfileImagePath)'. A reboot will release it; the profile is not modified."
        }
    }
}

# Match installed programs against signatures
foreach ($sig in $Signatures) {
    foreach ($prog in $installedPrograms) {
        foreach ($pattern in $sig.DisplayNamePatterns) {
            if ($prog.DisplayName -like $pattern) {
                Add-Finding -Category $sig.Category -Vendor $sig.Vendor -Method "Installed Program" `
                    -Detail "$($prog.DisplayName) ($($prog.DisplayVersion))" -Extra $prog.InstallLocation
                break
            }
        }
    }
}

# =========================================================================
# 2. Services
# =========================================================================
$allServices = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object Name, DisplayName, State, PathName

foreach ($sig in $Signatures) {
    foreach ($svcPattern in $sig.ServiceNames) {
        $svcMatches = $allServices | Where-Object { $_.Name -like $svcPattern -or $_.DisplayName -like $svcPattern }
        foreach ($m in $svcMatches) {
            Add-Finding -Category $sig.Category -Vendor $sig.Vendor -Method "Service" `
                -Detail "$($m.DisplayName) [$($m.Name)] - $($m.State)" -Extra $m.PathName
        }
    }
}

# =========================================================================
# 3. Running Processes (Deduplicated)
# =========================================================================
$allProcesses = Get-Process -ErrorAction SilentlyContinue | Select-Object Name, Path | Sort-Object Name, Path -Unique

foreach ($sig in $Signatures) {
    foreach ($procPattern in $sig.ProcessNames) {
        $procMatches = $allProcesses | Where-Object { $_.Name -like $procPattern }
        foreach ($m in $procMatches) {
            Add-Finding -Category $sig.Category -Vendor $sig.Vendor -Method "Running Process" `
                -Detail "$($m.Name).exe" -Extra $m.Path
        }
    }
}

# =========================================================================
# 4. Common install folders
# =========================================================================
foreach ($sig in $Signatures) {
    foreach ($folderPattern in $sig.FolderPatterns) {
        try {
            $folders = Get-Item -Path $folderPattern -ErrorAction Stop
            foreach ($f in $folders) {
                Add-Finding -Category $sig.Category -Vendor $sig.Vendor -Method "Install Folder" `
                    -Detail $f.FullName -Extra ""
            }
        } catch {
            # Expected if folder doesn't exist
        }
    }
}

# =========================================================================
# 5. Output
# =========================================================================
Write-Host "`n===== RMM & Remote Access Detection Report - $(Get-Date) =====" -ForegroundColor Cyan
Write-Host "Computer: $env:COMPUTERNAME"

function Show-CategoryReport {
    param($CategoryName, $Heading)
    $catResults = $results | Where-Object { $_.Category -eq $CategoryName }

    Write-Host "`n---- $Heading ----" -ForegroundColor Cyan
    if ($catResults.Count -eq 0) {
        Write-Host "None detected." -ForegroundColor Green
    } else {
        $vendors = $catResults.Vendor | Select-Object -Unique
        Write-Host "FOUND $($vendors.Count) vendor(s): $($vendors -join ', ')" -ForegroundColor Yellow
        $catResults | Sort-Object Vendor, DetectionMethod | Format-Table Vendor, DetectionMethod, Detail, Extra -AutoSize -Wrap
    }
}

if ($Scope -in @("All", "RMM"))           { Show-CategoryReport -CategoryName "RMM"           -Heading "RMM / Remote Monitoring Agents" }
if ($Scope -in @("All", "Remote Access")) { Show-CategoryReport -CategoryName "Remote Access" -Heading "Remote Access / Remote Desktop Software" }

Write-Host "`nNote: Portable tools with no install/service footprint are only caught if actively running at scan time." -ForegroundColor DarkGray

if ($ExportCsv) {
    $results | Sort-Object Category, Vendor, DetectionMethod | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "`nResults exported to: $OutputPath" -ForegroundColor Cyan
}
