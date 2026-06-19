<#
.Author
  RTFM
.SYNOPSIS
    Statistical system performance baselining and triage for Windows (standalone).

.DESCRIPTION
    BUILD mode : Samples performance counters, APPENDS the raw samples to a rolling
                 history, and recomputes a *distribution* baseline (mean, stddev,
                 percentiles). Run it on a schedule across different times/days so the
                 baseline captures what "normal" actually looks like for THIS machine.

    TEST  mode : Samples current state, scores each metric against the baseline
                 distribution (z-score + percentile position), captures the processes
                 actually responsible, checks the event log for real throttling, and
                 reports findings with calibrated confidence -- not false certainty.
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [ValidateSet('Build', 'Test')]
    [string]$Mode = 'Test',

    [ValidateRange(5, 600)]
    [int]$SampleSeconds = 30,

    [switch]$Reset,

    [string]$BaselinePath = "$env:ProgramData\SystemBaseline\baseline.json"
)

$ErrorActionPreference = 'Stop'
$SchemaVersion = 2
$BaselineDir   = Split-Path -Parent $BaselinePath
$LogPath       = Join-Path $BaselineDir 'baseline.log'
$MaxSamplesPerMetric = 6000   # cap rolling history so the file stays small

# =========================================================================
# METRIC DEFINITIONS
#   Worse      : 'High' -> big numbers are bad ; 'Low' -> small numbers are bad
#   MinConcern : the operational gate. A metric is only flagged when it is
#                statistically unusual AND crosses this threshold.
# =========================================================================
$MetricDefs = @(
    [PSCustomObject]@{ Key='CpuPct';       Counter='\Processor Information(_Total)\% Processor Time';       Label='CPU Load';            Unit='%';  Scale=1;    Worse='High'; MinConcern=70;   Interp='Sustained CPU load is well above normal range. See top processes.' }
    [PSCustomObject]@{ Key='CpuFreqPct';   Counter='\Processor Information(_Total)\% of Maximum Frequency'; Label='CPU Frequency';       Unit='%';  Scale=1;    Worse='Low';  MinConcern=80;   Interp='CPU is running below rated frequency. Points to thermal/power throttling.' }
    [PSCustomObject]@{ Key='MemAvailMB';   Counter='\Memory\Available MBytes';                              Label='Available RAM';       Unit='MB'; Scale=1;    Worse='Low';  MinConcern=1024; Interp='Free physical memory is unusually low. Investigate memory growth.' }
    [PSCustomObject]@{ Key='MemCommitPct'; Counter='\Memory\% Committed Bytes In Use';                      Label='Commit Charge';       Unit='%';  Scale=1;    Worse='High'; MinConcern=85;   Interp='System is leaning on the page file. Expect paging-induced slowness.' }
    [PSCustomObject]@{ Key='DiskReadMs';   Counter='\PhysicalDisk(_Total)\Avg. Disk sec/Read';              Label='Disk Read Latency';   Unit='ms'; Scale=1000; Worse='High'; MinConcern=20;   Interp='Elevated disk read latency. Storage is the likely bottleneck.' }
    [PSCustomObject]@{ Key='DiskWriteMs';  Counter='\PhysicalDisk(_Total)\Avg. Disk sec/Write';             Label='Disk Write Latency';  Unit='ms'; Scale=1000; Worse='High'; MinConcern=20;   Interp='Elevated disk write latency. Storage is the likely bottleneck.' }
    [PSCustomObject]@{ Key='DiskQueue';    Counter='\PhysicalDisk(_Total)\Current Disk Queue Length';       Label='Disk Queue (context)';Unit='';   Scale=1;    Worse='High'; MinConcern=2;    Interp='Disk queue is backed up. Corroborate with latency figures.' }
)

# =========================================================================
# LOGGING
# =========================================================================
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
                # Culture-invariant parsing to prevent comma/period regional errors
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
        if ($raw.SchemaVersion -ne $SchemaVersion) {
            Write-Log "Baseline schema v$($raw.SchemaVersion) != expected v$SchemaVersion. Treating as empty (rebuild recommended)." 'WARN'
            return $null
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
        
        # Fast generic list for memory-efficient appending
        $histList = [System.Collections.Generic.List[double]]::new()
        
        # Prevent .NET exception by checking for $null (unrolled empty arrays)
        $stored = Get-StoredSamples $existing $key
        if ($null -ne $stored) {
            $histList.AddRange([double[]]$stored)
        }
        
        if ($new.ContainsKey($key)) { 
            foreach ($val in $new[$key]) { $histList.Add($val) }
        }
        
        if ($histList.Count -eq 0) { continue }
        
        # Keep most recent N
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
    # Depth increased to 10 to ensure deep nesting serialization isn't truncated
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

    # Confidence from how much history backs the baseline
    $minN = ($baseline.Metrics.PSObject.Properties.Value | ForEach-Object { $_.Stats.Count } | Measure-Object -Minimum).Minimum
    $confidence = if ($baseline.BuildRuns -ge 7 -and $minN -ge 300) { 'HIGH' }
                  elseif ($baseline.BuildRuns -ge 3 -and $minN -ge 100) { 'MODERATE' }
                  else { 'LOW' }

    $rows = @()
    foreach ($e in $Effective) {
        $def = $e.Def; $key = $def.Key
        if (-not $current.ContainsKey($key)) { continue }
        $node = $baseline.Metrics.$key
        if ($null -eq $node) { continue }

        $cur  = [math]::Round((($current[$key] | Measure-Object -Average).Average), 2)
        $s    = $node.Stats
        $samples = Get-StoredSamples $baseline $key
        $z = if ($s.Std -gt 0) { [math]::Round((($cur - $s.Mean) / $s.Std), 1) } else { 0 }

        # percentile position of the current reading within the baseline distribution
        $pct = if ($samples.Count -gt 0) {
            [math]::Round(100.0 * (@($samples | Where-Object { $_ -le $cur }).Count) / $samples.Count, 0)
        } else { 50 }

        # Two-gate classification: statistically unusual AND operationally meaningful
        $status = 'Normal'; $ref = ''
        if ($def.Worse -eq 'High') {
            $ref = "p95 $($s.P95)$($def.Unit)"
            if ($cur -ge $def.MinConcern) {
                if     ($cur -gt $s.P99) { $status = 'HIGH' }
                elseif ($cur -gt $s.P95) { $status = 'Elevated' }
            }
        } else { # Low is bad
            $ref = "p05 $($s.P05)$($def.Unit)"
            if ($cur -le $def.MinConcern) {
                if     ($cur -lt $s.P05) { $status = 'HIGH' }
                elseif ($cur -lt $s.P10) { $status = 'Elevated' }
            }
        }

        $rows += [PSCustomObject]@{
            Def=$def; Label=$def.Label; Unit=$def.Unit; Current=$cur
            Mean=$s.Mean; Ref=$ref; Z=$z; Pct=$pct; Status=$status
        }
    }

    $top      = Get-TopProcesses
    $throttle = Get-ThrottleEvents
    $findings = @($rows | Where-Object { $_.Status -ne 'Normal' })

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
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("--- METRIC vs BASELINE ---")
    [void]$sb.AppendLine(("{0,-22} {1,10} {2,10} {3,8} {4,7}  {5}" -f 'Metric','Current','Mean','z-score','pctile','Status'))
    foreach ($r in $rows) {
        [void]$sb.AppendLine(("{0,-22} {1,10} {2,10} {3,8} {4,6}%  {5}" -f `
            "$($r.Label)", "$($r.Current)$($r.Unit)", "$($r.Mean)$($r.Unit)", $r.Z, $r.Pct, $r.Status))
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("--- THROTTLING CHECK ---")
    if ($throttle) {
        [void]$sb.AppendLine("Firmware processor-throttle events (ID 37) in last 7 days: $($throttle.Count). Likely thermal/power throttling -- check cooling, power profile, and AC adapter.")
    } else {
        [void]$sb.AppendLine("No firmware throttle events (Kernel-Processor-Power ID 37) in last 7 days.")
    }
    [void]$sb.AppendLine("")
    [void]$sb.AppendLine("--- ASSESSMENT ---")
    if ($findings.Count -eq 0) {
        [void]$sb.AppendLine("All sampled metrics are within this machine's historical range and below operational concern thresholds.")
        [void]$sb.AppendLine("Reported slowness is therefore unlikely to be systemic CPU/RAM/disk load -- look at the specific")
        [void]$sb.AppendLine("application, network path, or DNS/auth latency instead.")
    } else {
        foreach ($f in $findings) {
            [void]$sb.AppendLine("[$($f.Status)] $($f.Label): current $($f.Current)$($f.Unit) vs baseline mean $($f.Mean)$($f.Unit) (z=$($f.Z), $($f.Pct)th pctile).")
            [void]$sb.AppendLine("        $($f.Def.Interp)")
        }
    }
    if ($confidence -eq 'LOW') {
        [void]$sb.AppendLine("")
        [void]$sb.AppendLine("NOTE: Baseline confidence is LOW. Treat findings as directional until more BUILD runs accumulate.")
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
# MAIN
# =========================================================================
try {
    if (-not (Test-Path $BaselineDir)) { New-Item -ItemType Directory -Path $BaselineDir -Force | Out-Null }
    $effective = Resolve-EffectiveMetrics
    switch ($Mode) {
        'Build' { Invoke-Build -Effective $effective }
        'Test'  { Invoke-Test  -Effective $effective | Out-Null }
    }
}
catch {
    Write-Log $_.Exception.Message 'ERROR'
    exit 1
}
