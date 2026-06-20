<#
.SYNOPSIS
    Statistical system performance baselining and triage for Windows (standalone).

.DESCRIPTION
    BUILD mode : Samples performance counters, APPENDS the raw samples to a rolling
                 history, and recomputes a *distribution* baseline.

    TEST  mode : Samples current state, scores each metric against the baseline
                 distribution, checks event logs, and generates a diagnostic
                 playbook for the technician based on the anomalies found.

.NOTES
    EXIT CODES (for RMM / scheduled-task alerting):
        0 = Clean   (Build run, or Test with no findings)
        1 = Error   (script failed; see log)
        2 = Elevated findings present
        3 = HIGH findings present
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Build', 'Test', 'Inspect')]
    [string]$Mode = 'Test',

    [ValidateRange(5, 600)]
    [int]$SampleSeconds = 30,

    [switch]$Reset,

    [string]$BaselinePath = "$env:ProgramData\SystemBaseline\baseline.json"
)

$ErrorActionPreference = 'Stop'

# Schema describes the STORED file structure (Stats + Samples). The metric SET and the
# TechSteps live in code, not in the file, so adding metrics or playbook text does NOT
# change the structure -- schemas 2 and 3 are byte-identical in layout. We therefore READ
# either one (so a baseline built by the v3 OR the v3.1/3.2 script is always usable) and
# WRITE the latest. This stops version-number drift from silently discarding a good baseline.
$SchemaVersion      = 3          # version stamped onto baselines we write
$CompatibleSchemas  = @(2, 3)    # versions we will READ without discarding
$BaselineDir   = Split-Path -Parent $BaselinePath
$LogPath       = Join-Path $BaselineDir 'baseline.log'

# Rolling-history cap. Size it to your schedule:
#   samples/run (~SampleSeconds/2) x runs/day x retention-days.
# e.g. 14 samples/run x 24 hourly runs x 14 days ~= 4700 for a true two-week window.
# At ~7 bytes/sample, 26 metrics x 11000 ~= 2 MB per baseline.json (steady-state, capped).
$MaxSamplesPerMetric = 11000
$MaxLogBytes         = 5MB   # baseline.log is rotated past this (keeps one .1 archive)

# Severity surfaced to the process exit code (0 clean / 2 elevated / 3 high). Error path sets 1.
$script:ExitCode = 0

# =========================================================================
# METRIC DEFINITIONS & DIAGNOSTIC PLAYBOOK
# =========================================================================
$MetricDefs = @(
    # ---- CPU ----
    [PSCustomObject]@{ 
        Key='CpuPct'; Counter='\Processor Information(_Total)\% Processor Time'; Label='CPU Load'; Unit='%'; Scale=1; Worse='High'; MinConcern=70; 
        Interp='Sustained CPU load is well above normal range. See top processes.'
        TechSteps=@("Review 'Top Processes' output below for runaway threads.", "If CPU is pinned but top processes don't add up, check for hidden system/AV scans.", "Verify cooling/fan speeds if accompanied by firmware throttle events.")
    }
    [PSCustomObject]@{ 
        Key='CpuKernelPct'; Counter='\Processor Information(_Total)\% Privileged Time'; Label='CPU Kernel Time'; Unit='%'; Scale=1; Worse='High'; MinConcern=30; 
        Interp='Elevated time in kernel mode. Suspect drivers, filter drivers (AV/EDR), or the storage stack.'
        TechSteps=@("Check for aggressive real-time Antivirus or EDR scanning.", "Investigate storage stack latency (check disk ms counters).", "Look for heavy network packet inspection or VPN overhead.")
    }
    [PSCustomObject]@{ 
        Key='CpuDpcPct'; Counter='\Processor Information(_Total)\% DPC Time'; Label='CPU DPC Time'; Unit='%'; Scale=1; Worse='High'; MinConcern=10; 
        Interp='High deferred-procedure-call activity. Driver problem -- storage, network, or graphics most common.'
        TechSteps=@("Download and run 'LatencyMon' to identify the exact .sys file causing the spike.", "Update Network Interface (NIC), Storage Controller, and GPU drivers.")
    }
    [PSCustomObject]@{ 
        Key='CpuInterruptPct'; Counter='\Processor Information(_Total)\% Interrupt Time'; Label='CPU Interrupt Time'; Unit='%'; Scale=1; Worse='High'; MinConcern=10; 
        Interp='Elevated hardware interrupt servicing. Suspect failing hardware or a misbehaving driver.'
        TechSteps=@("Inspect physical hardware connections (loose SATA cables, dying USB hubs).", "Look for 'WHEA-Logger' hardware errors in the System Event Log.")
    }
    [PSCustomObject]@{ 
        Key='ProcQueue'; Counter='\System\Processor Queue Length'; Label='Processor Queue'; Unit=''; Scale=1; Worse='High'; MinConcern=4; 
        Interp='Threads waiting on CPU. Compare against logical core count -- sustained >2/core means CPU-bound.'
        TechSteps=@("Compare queue length against logical core count.", "Look for multi-threaded applications locking up or deadlocking.")
    }
    [PSCustomObject]@{ 
        Key='ContextSwitches'; Counter='\System\Context Switches/sec'; Label='Context Switches/s'; Unit=''; Scale=1; Worse='High'; MinConcern=30000; 
        Interp='High context-switch rate. Indicates thread thrashing, lock contention, or a chatty driver.'
        TechSteps=@("Usually indicates poorly written software spinning up too many threads.", "Look for chatty I/O drivers or excessive polling behavior.")
    }

    # ---- Memory ----
    [PSCustomObject]@{ 
        Key='MemAvailMB'; Counter='\Memory\Available MBytes'; Label='Available RAM'; Unit='MB'; Scale=1; Worse='Low'; MinConcern=1024; 
        Interp='Free physical memory is unusually low. Investigate memory growth.'
        TechSteps=@("Review 'Top Memory Processes' below.", "If processes do not account for the missing RAM, check Pool Paged/Nonpaged for driver leaks.", "Consider upgrading physical RAM if the workload has genuinely expanded.")
    }
    [PSCustomObject]@{ 
        Key='MemCommitPct'; Counter='\Memory\% Committed Bytes In Use'; Label='Commit Charge'; Unit='%'; Scale=1; Worse='High'; MinConcern=85; 
        Interp='System is leaning on the page file. Expect paging-induced slowness.'
        TechSteps=@("Verify Pagefile size is managed by Windows and hasn't been manually restricted.", "Check for applications reserving massive amounts of virtual memory without actively using it.")
    }
    [PSCustomObject]@{ 
        Key='HardFaults'; Counter='\Memory\Pages/sec'; Label='Hard Page Faults/s'; Unit=''; Scale=1; Worse='High'; MinConcern=1000; 
        Interp='High rate of pages fetched from disk to satisfy faults. Classic memory-pressure symptom.'
        TechSteps=@("This directly causes disk I/O bottlenecks. Address the RAM shortage.", "Move the pagefile to a faster NVMe/SSD drive if RAM upgrade is not possible.")
    }
    [PSCustomObject]@{ 
        Key='PageFaults'; Counter='\Memory\Page Faults/sec'; Label='Total Page Faults/s'; Unit=''; Scale=1; Worse='High'; MinConcern=5000; 
        Interp='Elevated total page-fault rate (soft+hard). Compare with hard-fault rate.'
        TechSteps=@("If Total Faults are high but Hard Faults are low, the system is successfully pulling from the standby cache (harmless).", "If both are high, the system is actively thrashing the disk.")
    }
    [PSCustomObject]@{ 
        Key='PoolPagedMB'; Counter='\Memory\Pool Paged Bytes'; Label='Paged Pool'; Unit='MB'; Scale=(1/1048576); Worse='High'; MinConcern=800; 
        Interp='Kernel paged-pool usage is climbing. Steady growth across builds = kernel-mode memory leak.'
        TechSteps=@("Steady growth across baseline builds indicates a kernel-mode memory leak.", "Use 'Poolmon.exe' to identify the leaking driver tag.")
    }
    [PSCustomObject]@{ 
        Key='PoolNonpagedMB'; Counter='\Memory\Pool Nonpaged Bytes'; Label='Nonpaged Pool'; Unit='MB'; Scale=(1/1048576); Worse='High'; MinConcern=400; 
        Interp='Kernel nonpaged-pool usage is climbing. Drivers cannot release this -- classic driver-leak signature.'
        TechSteps=@("Nonpaged pool cannot be swapped to disk. A leak here will hard-crash the OS.", "Common culprits: Antivirus filters, VPN adapters, or custom storage drivers.")
    }
    [PSCustomObject]@{ 
        Key='CacheBytesMB'; Counter='\Memory\Cache Bytes'; Label='File Cache'; Unit='MB'; Scale=(1/1048576); Worse='Low'; MinConcern=100; 
        Interp='File system cache has shrunk. Memory pressure is forcing Windows to reclaim cache for processes.'
        TechSteps=@("System will feel sluggish opening files. Find the application hoarding memory and restart it.")
    }
    [PSCustomObject]@{ 
        Key='PagefilePct'; Counter='\Paging File(_Total)\% Usage'; Label='Pagefile Usage'; Unit='%'; Scale=1; Worse='High'; MinConcern=50; 
        Interp='Pagefile usage is high. The system has been actively paging out -- corroborates memory pressure.'
        TechSteps=@("System requires more physical RAM for this workload.", "Check if a database or heavy application is misconfigured to bypass RAM limits.")
    }

    # ---- Disk ----
    [PSCustomObject]@{ 
        Key='DiskReadMs'; Counter='\PhysicalDisk(_Total)\Avg. Disk sec/Read'; Label='Disk Read Latency'; Unit='ms'; Scale=1000; Worse='High'; MinConcern=20; 
        Interp='Elevated disk read latency. Storage is the likely bottleneck.'
        TechSteps=@("If latency > 50ms consistently, the drive is failing or heavily fragmented (if HDD).", "Check System Event Log for NTFS warnings or Disk Error IDs (7, 11, 51, 153).", "Run CrystalDiskInfo to check SMART health status.")
    }
    [PSCustomObject]@{ 
        Key='DiskWriteMs'; Counter='\PhysicalDisk(_Total)\Avg. Disk sec/Write'; Label='Disk Write Latency'; Unit='ms'; Scale=1000; Worse='High'; MinConcern=20; 
        Interp='Elevated disk write latency. Storage is the likely bottleneck.'
        TechSteps=@("If using an SSD, the drive may have exhausted its SLC cache or is failing.", "Check for stuck Volume Shadow Copy (VSS) operations or runaway logging.")
    }
    [PSCustomObject]@{ 
        Key='DiskQueue'; Counter='\PhysicalDisk(_Total)\Current Disk Queue Length'; Label='Disk Queue (context)'; Unit=''; Scale=1; Worse='High'; MinConcern=2; 
        Interp='Disk queue is backed up. Corroborate with latency figures.'
        TechSteps=@("On NVMe/SAN, high queues are normal. On SATA SSD/HDD, a sustained queue > 2 per spindle indicates saturation.", "Identify the process slamming the disk via Resource Monitor.")
    }
    [PSCustomObject]@{ 
        Key='DiskReadIOPS'; Counter='\PhysicalDisk(_Total)\Disk Reads/sec'; Label='Disk Read IOPS'; Unit=''; Scale=1; Worse='High'; MinConcern=500; 
        Interp='High read IOPS. Pair with avg bytes/transfer to tell random reads from sequential streaming.'
        TechSteps=@("Check if an antivirus scan or file indexing service is running.", "Use Resource Monitor -> Disk tab to identify the specific file being read.")
    }
    [PSCustomObject]@{ 
        Key='DiskWriteIOPS'; Counter='\PhysicalDisk(_Total)\Disk Writes/sec'; Label='Disk Write IOPS'; Unit=''; Scale=1; Worse='High'; MinConcern=500; 
        Interp='High write IOPS. Look for log floods, defrag jobs, or backup activity.'
        TechSteps=@("If IOPS are super low but Latency and Queue are through the roof, the drive is likely dying and choking on the commands.", "Ensure standard telemetry or RMM agents aren't writing massive debug logs.", "Verify a database hasn't entered a spin-loop.")
    }
    [PSCustomObject]@{ 
        Key='DiskIdlePct'; Counter='\PhysicalDisk(_Total)\% Idle Time'; Label='Disk Idle Time'; Unit='%'; Scale=1; Worse='Low'; MinConcern=20; 
        Interp='Disk is saturated -- very little idle time. The inverse of utilization.'
        TechSteps=@("Drive is heavily utilized. If IOPS are super low but Idle time is also 0%, the hard drive is failing and hanging entirely.", "Look for continuous sequential write operations locking the disk.")
    }
    [PSCustomObject]@{ 
        Key='DiskSplitIO'; Counter='\PhysicalDisk(_Total)\Split IO/sec'; Label='Split IO/s'; Unit=''; Scale=1; Worse='High'; MinConcern=10; 
        Interp='High split-IO rate. Suggests fragmentation or undersized request buffers in the IO stack.'
        TechSteps=@("Indicates severe file system fragmentation.", "Can also be caused by misaligned partitions or undersized request buffers in the storage controller.")
    }

    # ---- Network ----
    [PSCustomObject]@{ 
        Key='TcpRetransmits'; Counter='\TCPv4\Segments Retransmitted/sec'; Label='TCP Retransmits/s'; Unit=''; Scale=1; Worse='High'; MinConcern=10; 
        Interp='TCP retransmission rate is elevated. Packet loss or congestion somewhere on the network path.'
        TechSteps=@("Check physical cabling and switch port stats for dropped packets/CRC errors.", "Verify VPN tunnels are not dropping packets due to MTU mismatch.", "Test network path with 'ping -t' or 'pathping' to external endpoints.")
    }

    # ---- System health / leak indicators ----
    [PSCustomObject]@{ 
        Key='HandleCount'; Counter='\Process(_Total)\Handle Count'; Label='Total Handles'; Unit=''; Scale=1; Worse='High'; MinConcern=200000; 
        Interp='System-wide handle count is high. Usually a single leaky process -- check Process Explorer for the culprit.'
        TechSteps=@("Open Task Manager, go to Details, and add the 'Handles' column.", "Identify the process leaking handles. Restart the process/service to clear.")
    }
    [PSCustomObject]@{ 
        Key='ProcessCount'; Counter='\System\Processes'; Label='Process Count'; Unit=''; Scale=1; Worse='High'; MinConcern=500; 
        Interp='Process count is high. Investigate for runaway spawns or stuck/respawning services.'
        TechSteps=@("Look for a scheduled task or script stuck in an infinite loop spawning instances.", "Check for malware behavior (e.g., hundreds of cmd.exe or powershell.exe processes).")
    }
    [PSCustomObject]@{ 
        Key='ThreadCount'; Counter='\System\Threads'; Label='Thread Count'; Unit=''; Scale=1; Worse='High'; MinConcern=5000; 
        Interp='Thread count is high. Possible thread leak in a long-running service or app.'
        TechSteps=@("Open Task Manager, go to Details, add the 'Threads' column to find the offender.", "Common culprits are .NET applications failing to clean up background workers.")
    }
)

# =========================================================================
# LOGGING
# =========================================================================
function Invoke-LogRotation {
    try {
        if (Test-Path $LogPath) {
            if ((Get-Item $LogPath).Length -gt $MaxLogBytes) {
                Move-Item $LogPath "$LogPath.1" -Force   # keeps exactly one archive
            }
        }
    } catch { }
}

function Write-Log {
    param([string]$Message, [ValidateSet('INFO','WARN','ERROR')] [string]$Level = 'INFO')
    $line = "{0} [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'WARN'  { Write-Warning $Message }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
    try { Add-Content -Path $LogPath -Value $line -ErrorAction SilentlyContinue } catch { }
}

# =========================================================================
# COUNTER NAME LOCALIZATION
# =========================================================================
function Get-CounterNameMap {
    $base = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Perflib'
    $eng  = (Get-ItemProperty "$base\009" -Name Counter).Counter
    $loc  = (Get-ItemProperty "$base\CurrentLanguage" -Name Counter).Counter
    $engByIdx = @{}; for ($i = 0; $i -lt $eng.Count - 1; $i += 2) { $engByIdx[$eng[$i]] = $eng[$i + 1] }
    $locByIdx = @{}; for ($i = 0; $i -lt $loc.Count - 1; $i += 2) { $locByIdx[$loc[$i]] = $loc[$i + 1] }
    $map = @{}
    foreach ($idx in $engByIdx.Keys) {
        if ($locByIdx.ContainsKey($idx) -and $engByIdx[$idx]) {
            $map[$engByIdx[$idx].ToLower()] = $locByIdx[$idx]
        }
    }
    return $map
}

function Resolve-CounterPath {
    param([string]$Path, [hashtable]$Map)
    if (-not $Map -or $Map.Count -eq 0) { return $Path }
    $m = [regex]::Match($Path, '^\\([^\\(]+)(\([^)]*\))?\\(.+)$')
    if (-not $m.Success) { return $Path }
    $obj = $m.Groups[1].Value.Trim(); $inst = $m.Groups[2].Value; $ctr = $m.Groups[3].Value.Trim()
    $objL = if ($Map.ContainsKey($obj.ToLower())) { $Map[$obj.ToLower()] } else { $obj }
    $ctrL = if ($Map.ContainsKey($ctr.ToLower())) { $Map[$ctr.ToLower()] } else { $ctr }
    return "\$objL$inst\$ctrL"
}

function Test-CounterPath {
    param([string]$Path)
    try { Get-Counter -Counter $Path -MaxSamples 1 -ErrorAction Stop | Out-Null; return $true } catch { return $false }
}

function Resolve-EffectiveMetrics {
    $map = $null
    $effective = @()
    foreach ($def in $MetricDefs) {
        if (Test-CounterPath $def.Counter) {
            $effective += [PSCustomObject]@{ Def = $def; Path = $def.Counter }
            continue
        }
        if ($null -eq $map) { try { $map = Get-CounterNameMap } catch { $map = @{} } }
        $loc = Resolve-CounterPath $def.Counter $map
        if (($loc -ne $def.Counter) -and (Test-CounterPath $loc)) {
            $effective += [PSCustomObject]@{ Def = $def; Path = $loc }
        } else {
            Write-Log "Counter unavailable on this system, skipping: $($def.Counter)" 'WARN'
        }
    }
    if ($effective.Count -eq 0) { throw "No performance counters could be collected on this system." }
    return $effective
}

# =========================================================================
# SAMPLING 
# =========================================================================
function Get-Sample {
    param([Parameter(Mandatory)] $Effective, [int]$Seconds)
    $interval = 2
    $max = [math]::Max(2, [int]($Seconds / $interval))
    Write-Log "Sampling $($Effective.Count) counters for ~$Seconds seconds..."

    $paths = $Effective | ForEach-Object { $_.Path }
    try {
        $raw = Get-Counter -Counter $paths -SampleInterval $interval -MaxSamples $max -ErrorAction Stop
    } catch {
        throw "Performance counter collection failed: $($_.Exception.Message)"
    }

    $out = @{}
    foreach ($e in $Effective) {
        $leaf = ($e.Path.Split('\')[-1]).ToLower()
        $vals = $raw.CounterSamples |
            Where-Object { $_.Path.ToLower().Contains($leaf) -and $null -ne $_.CookedValue } |
            ForEach-Object { 
                $val = [System.Convert]::ToDouble($_.CookedValue, [System.Globalization.CultureInfo]::InvariantCulture)
                [double]($val * $e.Def.Scale) 
            }
        
        if ($vals.Count -gt 2) { $vals = $vals[1..($vals.Count - 1)] }
        if ($vals.Count -gt 0) { $out[$e.Def.Key] = @($vals | ForEach-Object { [math]::Round($_, 3) }) }
    }
    return $out
}

# =========================================================================
# STATISTICS
# =========================================================================
function Get-Percentile {
    param([double[]]$Data, [double]$P)
    if (-not $Data -or $Data.Count -eq 0) { return $null }
    $s = @($Data | Sort-Object)
    if ($s.Count -eq 1) { return [double]$s[0] }
    $rank = ($P / 100.0) * ($s.Count - 1)
    $lo = [math]::Floor($rank); $hi = [math]::Ceiling($rank)
    if ($lo -eq $hi) { return [double]$s[[int]$rank] }
    return [double]($s[[int]$lo] + ($s[[int]$hi] - $s[[int]$lo]) * ($rank - $lo))
}

function Get-Stats {
    param([double[]]$Data)
    $n = $Data.Count
    $mean = ($Data | Measure-Object -Average).Average
    $sd = 0.0
    if ($n -gt 1) {
        $sumSq = ($Data | ForEach-Object { ($_ - $mean) * ($_ - $mean) } | Measure-Object -Sum).Sum
        $sd = [math]::Sqrt($sumSq / ($n - 1))
    }
    [PSCustomObject]@{
        Count = $n
        Mean  = [math]::Round($mean, 2)
        Std   = [math]::Round($sd, 2)
        Min   = [math]::Round(($Data | Measure-Object -Minimum).Minimum, 2)
        Max   = [math]::Round(($Data | Measure-Object -Maximum).Maximum, 2)
        P05   = [math]::Round((Get-Percentile $Data 5), 2)
        P10   = [math]::Round((Get-Percentile $Data 10), 2)
        P50   = [math]::Round((Get-Percentile $Data 50), 2)
        P90   = [math]::Round((Get-Percentile $Data 90), 2)
        P95   = [math]::Round((Get-Percentile $Data 95), 2)
        P99   = [math]::Round((Get-Percentile $Data 99), 2)
    }
}

# =========================================================================
# BASELINE FILE I/O
# =========================================================================
function Read-Baseline {
    if (-not (Test-Path $BaselinePath)) { return $null }
    try {
        $raw = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json
        if ($raw.SchemaVersion -notin $CompatibleSchemas) {
            Write-Log "Baseline schema v$($raw.SchemaVersion) is not in the compatible set ($($CompatibleSchemas -join ', ')). Treating as empty (rebuild recommended)." 'WARN'
            return $null
        }
        if ($raw.SchemaVersion -ne $SchemaVersion) {
            Write-Log "Baseline schema v$($raw.SchemaVersion) read as compatible; will be restamped to v$SchemaVersion on next BUILD." 'INFO'
        }
        return $raw
    } catch {
        Write-Log "Baseline file is unreadable/corrupt: $BaselinePath. Treating as empty to allow rebuild." 'WARN'
        return $null
    }
}

function Get-StoredSamples {
    param($Baseline, [string]$Key)
    if ($null -eq $Baseline -or $null -eq $Baseline.Metrics) { return @() }
    $node = $Baseline.Metrics.$Key
    if ($null -eq $node -or $null -eq $node.Samples) { return @() }
    return @($node.Samples | ForEach-Object { [double]$_ })
}

# =========================================================================
# BUILD MODE
# =========================================================================
function Invoke-Build {
    param($Effective)
    if (-not (Test-Path $BaselineDir)) { New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null }

    $existing = if ($Reset) { $null } else { Read-Baseline }
    if ($Reset -and (Test-Path $BaselinePath)) {
        Copy-Item $BaselinePath "$BaselinePath.bak" -Force
        Write-Log "-Reset specified: previous baseline backed up to $BaselinePath.bak" 'WARN'
    }

    $new = Get-Sample -Effective $Effective -Seconds $SampleSeconds

    $metrics = @{}
    foreach ($e in $Effective) {
        $key = $e.Def.Key
        
        $histList = [System.Collections.Generic.List[double]]::new()
        
        $stored = Get-StoredSamples $existing $key
        if ($null -ne $stored) {
            $histList.AddRange([double[]]$stored)
        }
        
        if ($new.ContainsKey($key)) { 
            foreach ($val in $new[$key]) { $histList.Add($val) }
        }
        
        if ($histList.Count -eq 0) { continue }
        
        if ($histList.Count -gt $MaxSamplesPerMetric) { 
            $histList.RemoveRange(0, $histList.Count - $MaxSamplesPerMetric)
        }
        
        $histArray = $histList.ToArray()
        
        $metrics[$key] = [PSCustomObject]@{
            Label   = $e.Def.Label
            Unit    = $e.Def.Unit
            Stats   = (Get-Stats $histArray)
            Samples = $histArray
        }
    }

    $runs = 1
    if ($existing -and $existing.BuildRuns) { $runs = [int]$existing.BuildRuns + 1 }
    $created = if ($existing -and $existing.Created) { $existing.Created } else { (Get-Date).ToString('yyyy-MM-dd HH:mm:ss') }

    $baseline = [PSCustomObject]@{
        SchemaVersion = $SchemaVersion
        Machine       = $env:COMPUTERNAME
        Created       = $created
        Updated       = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
        BuildRuns     = $runs
        SampleSeconds = $SampleSeconds
        Metrics       = $metrics
    }

    if (Test-Path $BaselinePath) { Copy-Item $BaselinePath "$BaselinePath.bak" -Force }
    $baseline | ConvertTo-Json -Depth 10 | Out-File -FilePath $BaselinePath -Encoding UTF8 -Force

    $sampleCount = ($metrics.Values | ForEach-Object { $_.Stats.Count } | Measure-Object -Maximum).Maximum
    Write-Log "Baseline updated. Build run #$runs. ~$sampleCount samples/metric retained. File: $BaselinePath"
    Write-Host ""
    Write-Host "Current baseline (mean +/- std):" -ForegroundColor Cyan
    foreach ($e in $Effective) {
        if ($metrics.ContainsKey($e.Def.Key)) {
            $s = $metrics[$e.Def.Key].Stats
            Write-Host ("  {0,-22} {1,8} {2,-3}  (sd {3}, p95 {4}, n={5})" -f $e.Def.Label, $s.Mean, $e.Def.Unit, $s.Std, $s.P95, $s.Count)
        }
    }
    if ($runs -lt 5) {
        Write-Host ""
        Write-Log "Baseline still thin (run #$runs). Schedule BUILD across several days/times for a trustworthy distribution." 'WARN'
    }
}

# =========================================================================
# TEST MODE
# =========================================================================
function Get-TopProcesses {
    $excluded = @('Idle', 'System', 'Secure System', 'Registry')
    
    $cpu = Get-Process -ErrorAction SilentlyContinue | 
        Where-Object { $_.CPU -and $_.Name -notin $excluded } |
        Sort-Object CPU -Descending | Select-Object -First 5 `
        Name, @{n='CPU_sec';e={[math]::Round($_.CPU,0)}}, @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,0)}}
        
    $mem = Get-Process -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notin $excluded } |
        Sort-Object WorkingSet64 -Descending | Select-Object -First 5 `
        Name, @{n='WS_MB';e={[math]::Round($_.WorkingSet64/1MB,0)}}, @{n='CPU_sec';e={[math]::Round($_.CPU,0)}}
        
    return [PSCustomObject]@{ Cpu = $cpu; Mem = $mem }
}

function Get-ThrottleEvents {
    try {
        return @(Get-WinEvent -FilterHashtable @{
            LogName='System'; ProviderName='Microsoft-Windows-Kernel-Processor-Power'; Id=37
            StartTime=(Get-Date).AddDays(-7)
        } -MaxEvents 5 -ErrorAction Stop)
    } catch { return $null }
}

function Invoke-Test {
    param($Effective)
    $baseline = Read-Baseline
    if ($null -eq $baseline) {
        throw "No usable baseline found at $BaselinePath. Run:  .\Invoke-SystemBaseline.ps1 -Mode Build"
    }

    $current = Get-Sample -Effective $Effective -Seconds $SampleSeconds

    $minN = ($baseline.Metrics.PSObject.Properties.Value | ForEach-Object { $_.Stats.Count } | Measure-Object -Minimum).Minimum
    $confidence = if ($baseline.BuildRuns -ge 7 -and $minN -ge 300) { 'HIGH' }
                  elseif ($baseline.BuildRuns -ge 3 -and $minN -ge 100) { 'MODERATE' }
                  else { 'LOW' }

    # Build the row set over EVERY metric the script knows about, plus any orphan metrics
    # still living in the baseline. A metric is shown no matter what -- if it could not be
    # sampled this run, or has no baseline yet, it appears with a status flag and '--' in the
    # columns it has no data for. This guarantees the table is always the full picture.
    $defByKey = @{}
    foreach ($d in $MetricDefs) { $defByKey[$d.Key] = $d }

    $orderedKeys = @($MetricDefs | ForEach-Object { $_.Key })
    foreach ($bk in @($baseline.Metrics.PSObject.Properties.Name)) {
        if ($bk -notin $orderedKeys) { $orderedKeys += $bk }   # baseline metric not in current code
    }

    $rows = @()
    foreach ($key in $orderedKeys) {
        $def    = $defByKey[$key]
        $node   = $baseline.Metrics.$key
        $hasCur = $current.ContainsKey($key)

        $label = if ($def) { $def.Label } elseif ($node) { $node.Label } else { $key }
        $unit  = if ($def) { $def.Unit }  elseif ($node) { $node.Unit }  else { '' }

        # Display strings default to '--' so missing data is visually obvious.
        $curDisp = '--'; $meanDisp = '--'; $zDisp = '--'; $pctDisp = '--'
        $curVal = $null; $z = $null; $pct = $null

        if ($hasCur) {
            $curVal  = [math]::Round((($current[$key] | Measure-Object -Average).Average), 2)
            $curDisp = "$curVal$unit"
        }
        if ($node) {
            $s = $node.Stats
            $meanDisp = "$($s.Mean)$unit"
            if ($hasCur) {
                $z = if ($s.Std -gt 0) { [math]::Round((($curVal - $s.Mean) / $s.Std), 1) } else { 0 }
                $zDisp = "$z"
                $samples = Get-StoredSamples $baseline $key
                if ($samples.Count -gt 0) {
                    $pct = [math]::Round(100.0 * (@($samples | Where-Object { $_ -le $curVal }).Count) / $samples.Count, 0)
                    $pctDisp = "$pct%"
                }
            }
        }

        # Status: real scoring when we have BOTH a live reading and a baseline (and a def to
        # know direction/threshold); otherwise a descriptive flag so the row is still meaningful.
        if ($hasCur -and $node -and $def) {
            $status = 'Normal'
            if ($def.Worse -eq 'High') {
                if ($curVal -ge $def.MinConcern) {
                    if     ($curVal -gt $s.P99) { $status = 'HIGH' }
                    elseif ($curVal -gt $s.P95) { $status = 'Elevated' }
                }
            } else { # Low is bad
                if ($curVal -le $def.MinConcern) {
                    if     ($curVal -lt $s.P05) { $status = 'HIGH' }
                    elseif ($curVal -lt $s.P10) { $status = 'Elevated' }
                }
            }
        }
        elseif ($hasCur -and -not $node) { $status = 'NoBaseline'  }  # sampled, never built
        elseif ($node -and -not $hasCur) { $status = 'NotSampled'  }  # counter did not resolve this run
        elseif ($hasCur -and $node)      { $status = 'Normal'      }  # orphan: data but no def to score
        else                             { $status = 'Unavailable' }  # neither sampled nor baselined

        $rows += [PSCustomObject]@{
            Def=$def; Key=$key; Label=$label; Unit=$unit
            CurDisp=$curDisp; MeanDisp=$meanDisp; ZDisp=$zDisp; PctDisp=$pctDisp
            Current=$curVal; Z=$z; Pct=$pct; Status=$status
        }
    }

    $top      = Get-TopProcesses
    $throttle = Get-ThrottleEvents
    $findings = @($rows | Where-Object { $_.Status -in @('HIGH','Elevated') })

    # ---- Coverage reconciliation: never silently hide metrics ----
    # A metric is only scored when it is in BOTH the baseline AND the live sample. Report
    # the gaps explicitly so a partial run is obvious instead of looking like a clean V2 result.
    $baselineKeys = @($baseline.Metrics.PSObject.Properties.Name)
    $sampledKeys  = @($current.Keys)
    $scoredKeys   = @($rows | Where-Object { $_.Status -in @('Normal','HIGH','Elevated') } | ForEach-Object { $_.Key })
    $inBaseNotSampled = @($baselineKeys | Where-Object { $_ -notin $sampledKeys })  # counter missing THIS run
    $sampledNotInBase = @($sampledKeys  | Where-Object { $_ -notin $baselineKeys }) # live metric with no baseline yet

    # Surface worst severity to the process exit code for RMM / scheduled-task alerting.
    $highCount = @($findings | Where-Object { $_.Status -eq 'HIGH' }).Count
    if     ($highCount -gt 0)      { $script:ExitCode = 3 }
    elseif ($findings.Count -gt 0) { $script:ExitCode = 2 }

    # ---- Build report ----
    $nl = [Environment]::NewLine
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.AppendLine("=============================================================")
    [void]$sb.AppendLine("        SYSTEM PERFORMANCE TRIAGE REPORT")
    [void]$sb.AppendLine("=============================================================")
    [void]$sb.AppendLine("Machine            : $env:COMPUTERNAME")
    [void]$sb.AppendLine("Baseline created   : $($baseline.Created)   (last updated $($baseline.Updated))")
    [void]$sb.AppendLine("Baseline build runs: $($baseline.BuildRuns)   |  samples/metric: ~$minN")
    [void]$sb.AppendLine("Tested on          : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')")
    [void]$sb.AppendLine("Baseline confidence: $confidence")
    [void]$sb.AppendLine("Coverage           : $($scoredKeys.Count) of $($rows.Count) metrics fully scored (rest shown with status flags below)")
    if ($inBaseNotSampled.Count -gt 0) {
        [void]$sb.AppendLine("  ! In baseline but NOT sampled this run (counter did not resolve -- see baseline.log):")
        [void]$sb.AppendLine("    $($inBaseNotSampled -join ', ')")
    }
    if ($sampledNotInBase.Count -gt 0) {
        [void]$sb.AppendLine("  ! Sampled live but NOT in baseline (run -Mode Build to add):")
        [void]$sb.AppendLine("    $($sampledNotInBase -join ', ')")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("--- METRIC vs BASELINE ---")
    [void]$sb.AppendLine(("{0,-22} {1,10} {2,10} {3,8} {4,7}  {5}" -f 'Metric','Current','Mean','z-score','pctile','Status'))
    foreach ($r in $rows) {
        [void]$sb.AppendLine(("{0,-22} {1,10} {2,10} {3,8} {4,7}  {5}" -f `
            $r.Label, $r.CurDisp, $r.MeanDisp, $r.ZDisp, $r.PctDisp, $r.Status))
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("--- DIAGNOSTIC PLAYBOOK ---")
    if ($findings.Count -eq 0) {
        [void]$sb.AppendLine("All sampled metrics are within this machine's historical range.")
        [void]$sb.AppendLine("Slowness is likely application-specific or network/DNS related.")
    } else {
        foreach ($f in $findings) {
            [void]$sb.AppendLine(">> [$($f.Status)] $($f.Label) (Current: $($f.CurDisp) | Mean: $($f.MeanDisp) | Z: $($f.Z))")
            [void]$sb.AppendLine("   Context: $($f.Def.Interp)")
            [void]$sb.AppendLine("   Technician Action Items:")
            foreach ($step in $f.Def.TechSteps) {
                [void]$sb.AppendLine("     - $step")
            }
            [void]$sb.AppendLine("")
        }
    }
    if ($confidence -eq 'LOW') {
        [void]$sb.AppendLine("NOTE: Baseline confidence is LOW. Treat findings as directional until more BUILD runs accumulate.")
        [void]$sb.AppendLine("")
    }

    [void]$sb.AppendLine("--- THROTTLING CHECK ---")
    if ($throttle) {
        [void]$sb.AppendLine("Firmware processor-throttle events (ID 37) in last 7 days: $($throttle.Count).")
    } else {
        [void]$sb.AppendLine("No firmware throttle events (ID 37) in last 7 days.")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("--- TOP PROCESSES BY CPU TIME ---")
    [void]$sb.AppendLine(($top.Cpu | Format-Table -AutoSize | Out-String).Trim())
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("--- TOP PROCESSES BY WORKING SET ---")
    [void]$sb.AppendLine(($top.Mem | Format-Table -AutoSize | Out-String).Trim())
    [void]$sb.AppendLine("=============================================================")

    $report = $sb.ToString()
    Write-Host $report
    try { Add-Content -Path $LogPath -Value ($nl + $report) } catch { }
    return $report
}

# =========================================================================
# INSPECT MODE  --  show exactly what is in the baseline file on disk
# =========================================================================
function Invoke-Inspect {
    Write-Host ""
    Write-Host "=== BASELINE INSPECTION ===" -ForegroundColor Cyan
    Write-Host "Path            : $BaselinePath"
    if (-not (Test-Path $BaselinePath)) {
        Write-Host "No baseline file exists at this path. Nothing has been built here yet." -ForegroundColor Yellow
        return
    }
    $raw = $null
    try { $raw = Get-Content -Path $BaselinePath -Raw | ConvertFrom-Json } catch { }
    if ($null -eq $raw) { Write-Host "File exists but is unreadable/corrupt JSON." -ForegroundColor Red; return }

    $compatible = $raw.SchemaVersion -in $CompatibleSchemas
    Write-Host ("Schema version  : {0}   (this script reads {1}; writes {2}){3}" -f `
        $raw.SchemaVersion, ($CompatibleSchemas -join ','), $SchemaVersion, $(if (-not $compatible){'  <-- INCOMPATIBLE: will be ignored'} else {''}))
    Write-Host "Machine         : $($raw.Machine)"
    Write-Host "Created         : $($raw.Created)"
    Write-Host "Updated         : $($raw.Updated)"
    Write-Host "Build runs      : $($raw.BuildRuns)"

    $metricNodes = @($raw.Metrics.PSObject.Properties)
    Write-Host "Metrics stored  : $($metricNodes.Count)"
    Write-Host ""
    Write-Host ("  {0,-18} {1,8} {2,12}" -f 'Key','Samples','Mean')
    Write-Host ("  {0,-18} {1,8} {2,12}" -f '---','-------','----')
    foreach ($p in ($metricNodes | Sort-Object Name)) {
        Write-Host ("  {0,-18} {1,8} {2,12}" -f $p.Name, $p.Value.Stats.Count, $p.Value.Stats.Mean)
    }

    # Reconcile stored metrics against this script's metric set.
    $scriptKeys = @($MetricDefs | ForEach-Object { $_.Key })
    $baseKeys   = @($metricNodes | ForEach-Object { $_.Name })
    $missing = @($scriptKeys | Where-Object { $_ -notin $baseKeys })
    $extra   = @($baseKeys   | Where-Object { $_ -notin $scriptKeys })
    Write-Host ""
    if ($missing.Count -gt 0) { Write-Host "In script but NOT in baseline (next BUILD will add these): $($missing -join ', ')" -ForegroundColor Yellow }
    if ($extra.Count   -gt 0) { Write-Host "In baseline but NOT in this script's metric set: $($extra -join ', ')" -ForegroundColor Yellow }
    if ($missing.Count -eq 0 -and $extra.Count -eq 0) { Write-Host "Baseline metric set matches this script. OK." -ForegroundColor Green }
    Write-Host ""
}

# =========================================================================
# MAIN
# =========================================================================
# Global mutex prevents two overlapping scheduled runs from interleaving writes to
# baseline.json (last-writer-wins corruption). Global\ scope requires admin (already required).
$mutex    = New-Object System.Threading.Mutex($false, "Global\Invoke-SystemBaseline")
$acquired = $false
try {
    $acquired = $mutex.WaitOne(0)
    if (-not $acquired) {
        if (-not (Test-Path $BaselineDir)) { New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null }
        Write-Log "Another instance is already running. Exiting without action." 'WARN'
        exit 0
    }

    if (-not (Test-Path $BaselineDir)) { New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null }
    Invoke-LogRotation

    if ($Mode -eq 'Inspect') { Invoke-Inspect; }
    else {
        $effective = Resolve-EffectiveMetrics
        switch ($Mode) {
            'Build' { Invoke-Build -Effective $effective }
            'Test'  { Invoke-Test  -Effective $effective | Out-Null }
        }
    }
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    $script:ExitCode = 1
}
finally {
    if ($acquired) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}

exit $script:ExitCode
