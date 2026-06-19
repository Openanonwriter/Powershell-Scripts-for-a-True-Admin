#Requires -Version 5.1
#Requires -RunAsAdministrator
<#
.Author
  https://github.com/Openanonwriter/Powershell-Scripts-for-a-True-Admin/

.SYNOPSIS
    Endpoint Degradation Sentinel - evidence-based decision engine.

.DESCRIPTION
    Three independent decisions, each backed by its own evidence:

      chkdsk   -> filesystem / disk corruption
      DISM     -> component-store (WinSxS) corruption
      SFC      -> protected system-file corruption

    Read-only by default. Results + an ordered plan are written to registry.

.PARAMETER Deep
    Run the authoritative active scans. Slow (5-30 min). 

.NOTES
    This still has quirks but it works.
    Version : 3.5.0 (Live DISM CheckHealth is authoritative: stale CBS.log lines
              no longer re-trigger DISM after a successful repair.)
#>
[CmdletBinding()]
param(
    [string] $RegistryPath = 'HKLM:\SOFTWARE\IT\Sentinel',
    [int]    $LookbackDays = 14,
    [int]    $WheaErrorThreshold = 5,
    [int]    $CoreBinaryCrashThreshold = 3,
    [int]    $MinFreeSpaceGB = 15,
    [switch] $Deep,
    [switch] $EmitJson
)

Set-StrictMode -Version Latest
$ScriptVersion = '3.5.0'
$Cutoff        = (Get-Date).AddDays(-[math]::Abs($LookbackDays))
$CbsLog        = Join-Path $env:windir 'Logs\CBS\CBS.log'

$CoreBinaries = @(
    'svchost.exe','services.exe','lsass.exe','csrss.exe','wininit.exe',
    'winlogon.exe','smss.exe','explorer.exe','dwm.exe','sihost.exe',
    'taskhostw.exe','RuntimeBroker.exe','spoolsv.exe'
)

$StoreCorruptHResults = @(
    '0x80073712','0x800F081F','0x80073701','0x80073711',
    '0x80073715','0x8007371B','0x80246007'
)

$Ev = @{
    Chkdsk = New-Object System.Collections.Generic.List[string]
    Dism   = New-Object System.Collections.Generic.List[string]
    Sfc    = New-Object System.Collections.Generic.List[string]
    Context= New-Object System.Collections.Generic.List[string]
}
$CheckErrors = New-Object System.Collections.Generic.List[string]

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')][string]$Level='INFO')
    Write-Verbose ("[{0:u}] [{1}] {2}" -f (Get-Date), $Level, $Message)
}

function Invoke-Check {
    param([string]$Name, [scriptblock]$Body)
    Write-Log "Check: $Name"
    try { & $Body }
    catch {
        $m = "${Name}: $($_.Exception.Message)"
        $CheckErrors.Add($m); Write-Log $m 'ERROR'
    }
}

function Get-EventCount {
    param([hashtable]$Filter)
    try { @(Get-WinEvent -FilterHashtable $Filter -ErrorAction Stop).Count }
    catch { if ($_.Exception.Message -match 'No events were found|do not write events|does not exist') { 0 } else { throw } }
}

function Get-Events {
    param([hashtable]$Filter, [int]$MaxEvents = 200)
    try { @(Get-WinEvent -FilterHashtable $Filter -MaxEvents $MaxEvents -ErrorAction Stop) }
    catch { if ($_.Exception.Message -match 'No events were found|do not write events|does not exist') { @() } else { throw } }
}

function Get-CbsSafeTail {
    param([int]$Lines = 4000)
    if (-not (Test-Path $CbsLog)) { return @() }
    
    $TempPath = Join-Path $env:TEMP "CBS_SentinelCopy_$([guid]::NewGuid()).log"
    try {
        Copy-Item -Path $CbsLog -Destination $TempPath -ErrorAction SilentlyContinue
        if (Test-Path $TempPath) {
            Get-Content -Path $TempPath -Tail $Lines -ErrorAction Stop
        }
    }
    finally {
        if (Test-Path $TempPath) { Remove-Item -Path $TempPath -Force -ErrorAction SilentlyContinue }
    }
}

# ==========================================================================
# GATING CONTEXT  
# ==========================================================================
$PendingReboot = $false
Invoke-Check 'Pending-Reboot' {
    $script:PendingReboot = $false
    $keys = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired',
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\PackagesPending'
    )
    foreach ($k in $keys) { if (Test-Path $k) { $script:PendingReboot = $true; $Ev.Context.Add("Pending reboot: $k") } }
    
    $sm = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
    $pfro = (Get-ItemProperty -Path $sm -Name PendingFileRenameOperations -ErrorAction SilentlyContinue).PendingFileRenameOperations
    $realPfro = @($pfro | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    
    if ($realPfro.Count -gt 0) { 
        $os = Get-CimInstance Win32_OperatingSystem
        $uptimeMins = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalMinutes, 1)
        
        if ($uptimeMins -lt 15) {
            $Ev.Context.Add("Ghost reboot flag detected: System just rebooted ($uptimeMins mins ago). Ignoring PFRO.")
        } else {
            $script:PendingReboot = $true
            $Ev.Context.Add('Pending reboot: PendingFileRenameOperations has active file replacements queued.')
        }
    }
}

$LowDiskSpace = $false
Invoke-Check 'System-Drive-Space' {
    $d = $env:SystemDrive.TrimEnd(':')
    $v = Get-Volume -DriveLetter $d -ErrorAction Stop
    $freeGB = [math]::Round($v.SizeRemaining / 1GB, 2)
    if ($freeGB -lt $MinFreeSpaceGB) {
        $script:LowDiskSpace = $true
        $Ev.Context.Add("Low system-drive space: ${freeGB} GB (< ${MinFreeSpaceGB} GB) - remediate before servicing")
    }
}

Invoke-Check 'System-Uptime-WHEA' {
    $os = Get-CimInstance Win32_OperatingSystem
    $uptimeDays = [math]::Round(((Get-Date) - $os.LastBootUpTime).TotalDays, 1)
    if ($uptimeDays -gt 30) { $Ev.Context.Add("Uptime ${uptimeDays} days - deferred servicing likely; reboot recommended") }
    
    $wheaEvents = @(Get-Events -Filter @{ LogName='System'; ProviderName='Microsoft-Windows-WHEA-Logger'; StartTime=$Cutoff })
    if ($wheaEvents.Count -gt $WheaErrorThreshold) {
        $Ev.Context.Add("WHEA corrected hardware errors: $($wheaEvents.Count) - corruption may be hardware-driven (RAM/CPU)")
        $wheaEvents | Select-Object -First 3 | ForEach-Object { $Ev.Context.Add("  -> WHEA Event $($_.Id) at $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))") }
    }
}

# ==========================================================================
# CHKDSK EVIDENCE 
# ==========================================================================
$ChkdskVolumes = @{}   
Invoke-Check 'Chkdsk-Dirty-Bit' {
    $vols = Get-Volume -ErrorAction Stop | Where-Object { $_.DriveLetter -and $_.FileSystemType -eq 'NTFS' -and $_.DriveType -eq 'Fixed' }
    foreach ($v in $vols) {
        $dl = "$($v.DriveLetter):"
        $null = & fsutil.exe dirty query $dl 2>&1
        if ($LASTEXITCODE -ne 0) {
            $ChkdskVolumes[$dl] = 'Full'
            $Ev.Chkdsk.Add("$dl dirty bit SET - chkdsk is already scheduled at next boot")
        }
        $hs = "$($v.HealthStatus) $($v.OperationalStatus)"
        switch -Regex ($hs) {
            'Full Repair' { $ChkdskVolumes[$dl] = 'Full'; $Ev.Chkdsk.Add("$dl HealthStatus='Full Repair Needed'") }
            'Spot Fix'    { if ($ChkdskVolumes[$dl] -ne 'Full') { $ChkdskVolumes[$dl] = 'SpotFix' }; $Ev.Chkdsk.Add("$dl HealthStatus='Spot Fix Needed'") }
            'Scan Needed' { if (-not $ChkdskVolumes.ContainsKey($dl)) { $ChkdskVolumes[$dl] = 'Scan' }; $Ev.Chkdsk.Add("$dl HealthStatus='Scan Needed'") }
        }
    }
}

Invoke-Check 'Chkdsk-Event-Corroboration' {
    $ntfs = @(Get-Events -Filter @{ LogName='System'; ProviderName='Microsoft-Windows-Ntfs'; Id=55,98,130,137; StartTime=$Cutoff })
    if ($ntfs.Count -gt 0) { 
        $Ev.Chkdsk.Add("NTFS corruption events: $($ntfs.Count) (IDs 55/98/130/137)") 
        $ntfs | Select-Object -First 5 | ForEach-Object { $Ev.Chkdsk.Add("  -> Event $($_.Id) at $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))") }
    }

    $disk = @(Get-Events -Filter @{ LogName='System'; ProviderName='disk'; Id=7,11,51,153; StartTime=$Cutoff })
    if ($disk.Count -gt 0) { 
        $Ev.Chkdsk.Add("Disk I/O / bad-block events: $($disk.Count) - consider chkdsk /r") 
        $disk | Select-Object -First 5 | ForEach-Object { $Ev.Chkdsk.Add("  -> Event $($_.Id) at $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))") }
    }
}

Invoke-Check 'Chkdsk-SMART' {
    foreach ($pd in @(Get-PhysicalDisk -ErrorAction Stop)) {
        if ($pd.HealthStatus -ne 'Healthy') {
            $Ev.Chkdsk.Add("Disk '$($pd.FriendlyName)' HealthStatus=$($pd.HealthStatus) - physical failure; chkdsk /r + backup")
        }
        $rc = $pd | Get-StorageReliabilityCounter -ErrorAction SilentlyContinue
        if ($rc) {
            $unc = (($rc.ReadErrorsUncorrected | Measure-Object -Sum).Sum) + (($rc.WriteErrorsUncorrected | Measure-Object -Sum).Sum)
            if ($unc -gt 0) { $Ev.Chkdsk.Add("Disk '$($pd.FriendlyName)' uncorrected R/W errors: $unc - bad sectors; chkdsk /r") }
        }
    }
}

if ($Deep) {
    Invoke-Check 'Chkdsk-DEEP-Repair-Volume-Scan' {
        $targets = @($ChkdskVolumes.Keys) + $env:SystemDrive | Select-Object -Unique
        foreach ($dl in $targets) {
            $letter = $dl.TrimEnd(':')
            try {
                $r = Repair-Volume -DriveLetter $letter -Scan -ErrorAction Stop
                if ($r -and $r -ne 'NoErrorsFound') {
                    $Ev.Chkdsk.Add("Repair-Volume -Scan on ${dl}: $r")
                    if (-not $ChkdskVolumes.ContainsKey($dl)) { $ChkdskVolumes[$dl] = 'SpotFix' }
                }
            } catch { Write-Log "Repair-Volume -Scan failed" 'WARN' }
        }
    }
}

# ==========================================================================
# DISM EVIDENCE  
# ==========================================================================
# StoreState is set by the LIVE DISM /CheckHealth probe below. CheckHealth
# reports corruption that is currently *flagged*; a successful prior repair
# clears that flag, so 'Healthy' means "no corruption is outstanding right now".
# That makes the live probe the authoritative, most-recent verdict - it wins
# over any historical text still sitting in the rolling CBS.log.
$StoreState = 'Unknown' 
Invoke-Check 'DISM-CheckHealth' {
    $out = (& dism.exe /Online /Cleanup-Image /CheckHealth 2>&1) -join "`n"
    if     ($out -match 'No component store corruption') { $script:StoreState = 'Healthy' }
    elseif ($out -match 'not repairable')                { $script:StoreState = 'NotRepairable'; $Ev.Dism.Add('DISM CheckHealth: store corruption NOT repairable') }
    elseif ($out -match 'repairable')                    { $script:StoreState = 'Repairable';    $Ev.Dism.Add('DISM CheckHealth: component store is repairable') }
}

Invoke-Check 'DISM-WindowsUpdate-HResults' {
    $wu = @(Get-Events -Filter @{ LogName='System'; ProviderName='Microsoft-Windows-WindowsUpdateClient'; Level=2; StartTime=$Cutoff } -MaxEvents 200)
    $hits = @()
    foreach ($e in $wu) { foreach ($h in $StoreCorruptHResults) { if ($e.Message -match [regex]::Escape($h)) { $hits += $h } } }
    $hits = @($hits | Select-Object -Unique)
    if ($hits.Count -gt 0) {
        if ($script:StoreState -eq 'Healthy') {
            $Ev.Context.Add("Historical Windows Update store-corruption codes ($($hits -join ', ')) seen, but live DISM /CheckHealth reports the store is healthy - already resolved.")
        } else {
            $Ev.Dism.Add("Windows Update failed with store-corruption codes: $($hits -join ', ') - run DISM /RestoreHealth")
        }
    }
}

Invoke-Check 'DISM-CBS-Servicing' {
    try {
        $tail = Get-CbsSafeTail -Lines 4000
        if ($tail) {
            $dismErrors = @()
            $lastErrIdx = -1
            $lastOkIdx = -1
            
            # Chronological parser: last action wins.
            for ($i=0; $i -lt $tail.Count; $i++) {
                if ($tail[$i] -match 'Cannot repair member file|store corruption|CSI Manifest .* corrupt|hashes for the file in the manifest do not match') { 
                    $lastErrIdx = $i
                    $dismErrors += $tail[$i]
                }
                # Resolution / success markers that a later repair leaves behind.
                if ($tail[$i] -match 'Total corruptions: 0|Successfully processed all directives|Store coherency.*pass|Repair complete') {
                    $lastOkIdx = $i
                }
            }
            if ($lastErrIdx -gt $lastOkIdx) {
                # If the live store probe says Healthy, the corruption flag has
                # been cleared since these lines were written -> stale residue,
                # NOT an open issue. Don't trigger another DISM pass.
                if ($script:StoreState -eq 'Healthy') {
                    $Ev.Context.Add("CBS.log still contains $($dismErrors.Count) historical store/manifest corruption line(s), but live DISM /CheckHealth reports the store is healthy - already resolved; DISM not required.")
                } else {
                    $Ev.Dism.Add("CBS.log shows unresolved store/manifest corruption markers ($($dismErrors.Count) recent lines)")
                }
            }
        }
    } catch { Write-Log "CBS.log read failed" 'WARN' }
    
    $svc = @(Get-Events -Filter @{ LogName='Setup'; Level=2; StartTime=$Cutoff } -MaxEvents 100)
    $failPkg = @($svc | Where-Object { $_.Message -match 'failed|corrupt' })
    if ($failPkg.Count -ge 3) {
        if ($script:StoreState -eq 'Healthy') {
            $Ev.Context.Add("$($failPkg.Count) historical failed servicing/package operations in Setup log, but live store check is Healthy - already resolved.")
        } else {
            $Ev.Dism.Add("$($failPkg.Count) failed servicing/package operations in Setup log")
        }
    }
}

if ($Deep) {
    Invoke-Check 'DISM-DEEP-ScanHealth' {
        $out = (& dism.exe /Online /Cleanup-Image /ScanHealth /LogLevel:3 2>&1) -join "`n"
        if     ($out -match 'not repairable') { $script:StoreState = 'NotRepairable'; $Ev.Dism.Add('DISM ScanHealth: corruption NOT repairable') }
        elseif ($out -match 'repairable')     { $script:StoreState = 'Repairable';    $Ev.Dism.Add('DISM ScanHealth: corruption found, repairable') }
        elseif ($out -match 'No component store corruption') { $script:StoreState = 'Healthy'; }
    }
}

# ==========================================================================
# SFC EVIDENCE  
# ==========================================================================
Invoke-Check 'SFC-CBS-SR-Lines' {
    try {
        $tail = Get-CbsSafeTail -Lines 4000
        if ($tail) {
            $srErrors = @()
            $lastErrIdx = -1
            $lastOkIdx = -1
            
            # Chronological parser: Last action wins
            for ($i=0; $i -lt $tail.Count; $i++) {
                if ($tail[$i] -match '\[SR\]') {
                    if ($tail[$i] -match 'Cannot repair|corrupt|Repairing') { 
                        $lastErrIdx = $i
                        $srErrors += $tail[$i]
                    }
                    if ($tail[$i] -match 'successfully repaired|Verify complete|Verifying \d+ components') { 
                        $lastOkIdx = $i
                    }
                }
            }
            if ($lastErrIdx -gt $lastOkIdx) { 
                $Ev.Sfc.Add("CBS.log [SR] entries show unresolved system-file corruption ($($srErrors.Count) lines)") 
                # Only escalate to DISM if the store is not currently known-healthy.
                if (($srErrors -match 'Cannot repair member file') -and ($script:StoreState -ne 'Healthy')) {
                    $Ev.Dism.Add('SFC previously could NOT repair files - component store damaged; DISM /RestoreHealth required before SFC')
                }
            }
        }
    } catch { Write-Log "CBS.log read failed" 'WARN' }
}

Invoke-Check 'SFC-SideBySide' {
    $sxs = @(Get-Events -Filter @{ LogName='Application'; ProviderName='SideBySide'; Id=33,35,58,59,78,80; StartTime=$Cutoff } -MaxEvents 20)
    if ($sxs.Count -gt 0) { 
        $Ev.Sfc.Add("SideBySide/manifest errors: $($sxs.Count) - assembly corruption; SFC candidate") 
        $sxs | Select-Object -First 3 | ForEach-Object { $Ev.Sfc.Add("  -> SxS Event $($_.Id) at $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))") }
    }
}

Invoke-Check 'SFC-CoreBinary-Crashes' {
    $crashes = @(Get-Events -Filter @{ LogName='Application'; ProviderName='Application Error'; Id=1000; StartTime=$Cutoff } -MaxEvents 300)
    $coreHits = @($crashes | Where-Object { $e = $_; $CoreBinaries | Where-Object { $e.Message -match [regex]::Escape($_) } })
    if ($coreHits.Count -ge $CoreBinaryCrashThreshold) {
        $Ev.Sfc.Add("$($coreHits.Count) crashes of core OS binaries (>= $CoreBinaryCrashThreshold)")
        $coreHits | Select-Object -First 3 | ForEach-Object { 
            $appName = if ($_.Message -match "Faulting application name: (.*?)\,") { $matches[1] } else { "Core Binary" }
            $Ev.Sfc.Add("  -> $appName crashed at $($_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss'))") 
        }
    }
}

if ($Deep) {
    Invoke-Check 'SFC-DEEP-VerifyOnly' {
        $null = & sfc.exe /verifyonly 2>&1
        $fresh = @(Get-CbsSafeTail -Lines 1000 | Where-Object { $_ -match '\[SR\].*(Cannot repair|corrupt)' })
        if ($fresh.Count) { $Ev.Sfc.Add('sfc /verifyonly confirmed system-file integrity violations') }
    }
}

# ==========================================================================
# DECISION + ORDERED REMEDIATION PLAN
# ==========================================================================
$badDisk   = @($Ev.Chkdsk | Where-Object { $_ -match 'chkdsk /r|uncorrected|physical failure' }).Count -gt 0
$RecChkdsk = $ChkdskVolumes.Count -gt 0

# Live DISM /CheckHealth (and /ScanHealth in -Deep) is authoritative for the
# CURRENT store state. If it reports Healthy, the store is clean right now and
# any historical log/WU/Setup markers are already-resolved residue -> do NOT
# recommend DISM again. This is what stops the script re-asking for a DISM pass
# that already succeeded.
$RecDism   = if ($StoreState -eq 'Healthy') { $false }
             else { ($StoreState -in 'Repairable','NotRepairable') -or ($Ev.Dism.Count -gt 0) }
$RecSfc    = $Ev.Sfc.Count -gt 0

# Make the suppression visible in the output rather than silently dropping it.
if ($StoreState -eq 'Healthy' -and $Ev.Dism.Count -gt 0) {
    $Ev.Context.Add('DISM evidence present in logs, but live store check is Healthy - component store treated as already repaired; DISM step suppressed.')
}

$ConfChkdsk = if (($ChkdskVolumes.Values -contains 'Full') -or ($ChkdskVolumes.Count -and $Deep)) { 'High' } elseif ($RecChkdsk) { 'Medium' } else { 'None' }
$ConfDism   = if (-not $RecDism) { 'None' } elseif ($StoreState -in 'Repairable','NotRepairable') { 'High' } else { 'Medium' }
$ConfSfc    = if ($Deep -and $RecSfc) { 'High' } elseif ($RecSfc) { 'Medium' } else { 'None' }

$Plan = New-Object System.Collections.Generic.List[string]
$step = 1

if ($LowDiskSpace)  { $Plan.Add("$step. FREE DISK SPACE first (servicing fails under $MinFreeSpaceGB GB)."); $step++ }
if ($PendingReboot) { $Plan.Add("$step. REBOOT FIRST - A previous servicing operation has queued files for replacement. Reboot to apply fixes."); $step++ }

if ($RecChkdsk) {
    foreach ($dl in $ChkdskVolumes.Keys) {
        $letter = $dl.TrimEnd(':')
        $action = switch ($ChkdskVolumes[$dl]) {
            'Full'    { if ($badDisk) { "chkdsk $dl /f /r  (offline + bad-sector scan; reboot; BACK UP FIRST)" } else { "chkdsk $dl /f  (offline; reboot)" } }
            'SpotFix' { "Repair-Volume -DriveLetter $letter -SpotFix  (fast, online)" }
            default   { "Repair-Volume -DriveLetter $letter -Scan" }
        }
        $Plan.Add("$step. CHKDSK ${dl}: $action"); $step++
    }
}
if ($RecDism) {
    if ($StoreState -eq 'NotRepairable') {
        $Plan.Add("$step. DISM store NOT repairable -> in-place repair install / reset (RestoreHealth will fail)."); $step++
    } else {
        $src = if ($Ev.Dism -match 'store-corruption codes') { ' /Source:<wim> /LimitAccess' } else { '' }
        # Added LogLevel:3 for verbose technician logging
        $Plan.Add("$step. DISM /Online /Cleanup-Image /RestoreHealth$src /LogLevel:3  (repairs component store)."); $step++
    }
}
if ($RecSfc) {
    $note = if ($RecDism) { ' (run AFTER DISM succeeds - SFC repairs from the store)' } else { '' }
    $Plan.Add("$step. sfc /scannow$note"); $step++
}
if ($Plan.Count -eq 0) { $Plan.Add('No remediation indicated - system files, store, and filesystem all clean by available evidence.') }

# ==========================================================================
# COMMIT
# ==========================================================================
$RunStatus = if ($CheckErrors.Count -eq 0) { 'OK' } else { "PartialErrors($($CheckErrors.Count))" }

$summary = [pscustomobject]([ordered]@{
    ScriptVersion     = $ScriptVersion
    LastRunUtc        = (Get-Date).ToUniversalTime().ToString('o')
    DeepScan          = [bool]$Deep
    RunStatus         = $RunStatus
    PendingReboot     = [int][bool]$PendingReboot
    LowDiskSpace      = [int][bool]$LowDiskSpace
    StoreState        = $StoreState
    RecommendChkdsk   = [int][bool]$RecChkdsk
    RecommendDism     = [int][bool]$RecDism
    RecommendSfc      = [int][bool]$RecSfc
    ConfidenceChkdsk  = $ConfChkdsk
    ConfidenceDism    = $ConfDism
    ConfidenceSfc     = $ConfSfc
    DirtyVolumes      = ($ChkdskVolumes.Keys -join ',')
    RemediationPlan   = ($Plan -join ' | ')
    EvidenceChkdsk    = $Ev.Chkdsk.ToArray()
    EvidenceDism      = $Ev.Dism.ToArray()
    EvidenceSfc       = $Ev.Sfc.ToArray()
    Context           = $Ev.Context.ToArray()
    CheckErrors       = $CheckErrors.ToArray()
})

try {
    if (-not (Test-Path $RegistryPath)) { New-Item -Path $RegistryPath -Force | Out-Null }
    foreach ($n in 'PendingReboot','LowDiskSpace','RecommendChkdsk','RecommendDism','RecommendSfc') {
        Set-ItemProperty -Path $RegistryPath -Name $n -Value ([int]$summary.$n) -Type DWord
    }
    foreach ($n in 'ScriptVersion','LastRunUtc','RunStatus','StoreState','DirtyVolumes',
                   'ConfidenceChkdsk','ConfidenceDism','ConfidenceSfc','RemediationPlan') {
        Set-ItemProperty -Path $RegistryPath -Name $n -Value ([string]$summary.$n) -Type String
    }
    $json = $summary | ConvertTo-Json -Depth 5 -Compress
    Set-ItemProperty -Path $RegistryPath -Name 'Snapshot' -Value $json -Type String

    if ($EmitJson) { Write-Output $json } else { Write-Output $summary }
    exit 0
}
catch {
    Write-Error "Fatal: could not commit Sentinel data: $($_.Exception.Message)"
    exit 1
}
