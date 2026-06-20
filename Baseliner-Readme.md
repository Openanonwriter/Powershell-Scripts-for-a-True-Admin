# Invoke-SystemBaseline — Operations Guide

Statistical performance baselining and triage for Windows endpoints. The tool learns what "normal" looks like for **each individual machine**, then scores live readings against that machine's own history — turning "the PC feels slow" into a quantified, per-metric anomaly report with a technician playbook.

- **Script:** `Invoke-SystemBaseline.ps1`
- **Platform:** Windows, PowerShell 5.1+ (Desktop), Administrator
- **Footprint:** one capped JSON state file + one rotating log (~2 MB steady-state per machine)
- **No agent, no central collector, no `.blg`/`.csv` hoarding** — all statistics are computed on the endpoint.

---

## 1. Concept

Traditional Performance Monitor Data Collector Sets record raw counter samples into large files that need central ingestion to interpret. This tool inverts that: it samples counters, folds them into a rolling distribution, and stores only the **distribution** (mean, standard deviation, percentiles) plus a capped window of recent raw samples. The raw firehose is discarded after the math is done.

Two ideas do the work:

- **Per-machine baseline.** A server that idles at 60% CPU and a laptop that idles at 3% are both "normal." Global thresholds can't tell the difference; a baseline built from each machine's own history can.
- **Two-gate anomaly detection.** A reading is only flagged when it is *both* statistically unusual for this machine **and** operationally meaningful. This is what keeps a busy-by-design machine from alerting constantly.

### The three numbers in the report

| Metric | Meaning |
|---|---|
| **mean** | The machine's true normal for this counter, over the retained history. |
| **z-score** | How many standard deviations the current reading sits from the mean. Past ±2–3 is unusual. |
| **percentile** | Where the current reading ranks within the machine's entire recorded history. 99% = worse than 99% of everything previously seen. |

---

## 2. How it works

### Build mode (learning)
Samples every available counter, **appends** the new samples to the rolling history, recomputes the distribution, and writes the baseline JSON. Run it on a schedule across different times and days so the baseline captures real day-to-day variation, not a single moment.

### Test mode (triage)
Samples current state, scores each metric against the stored distribution, captures the top processes by CPU and working set, checks the event log for firmware throttling, and prints a triage report with a per-finding technician playbook. Returns an exit code reflecting the worst severity found.

### Inspect mode (introspection)
Read-only. Dumps exactly what is in the baseline file on disk — schema version, build count, and the sample count and mean of every stored metric — and reconciles that against the script's current metric set. Use it to answer "what does this machine actually have a baseline for?"

### Sampling detail
Each run collects samples at a 2-second interval for `SampleSeconds` (default 30 → ~15 samples), discards the first sample to avoid the counter warm-up artifact, applies any unit scaling, and averages the rest. Counter names are resolved through the registry so the tool works on non-English Windows.

---

## 3. Requirements

- Windows with PowerShell 5.1 (Windows PowerShell Desktop). Not validated on PowerShell 7.
- **Administrator** — required for the performance counters, the event-log throttle check, and the global run-lock.
- Healthy performance counters. If counters are corrupted (common on devices after major updates), some metrics will fail to resolve; see Troubleshooting.

---

## 4. Installation

Place the script somewhere durable and execute it elevated. By default it stores everything under:

```
%ProgramData%\SystemBaseline\
    baseline.json        # the distribution + rolling samples
    baseline.json.bak    # automatic backup of the prior baseline
    baseline.log         # run log + appended triage reports (rotates at 5 MB)
```

If your execution policy blocks the script, run it through an explicit bypass rather than weakening machine policy:

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\Invoke-SystemBaseline.ps1 -Mode Build
```

---

## 5. Usage

```powershell
.\Invoke-SystemBaseline.ps1 [-Mode Build|Test|Inspect] [-SampleSeconds <5-600>] [-Reset] [-BaselinePath <path>]
```

| Parameter | Default | Description |
|---|---|---|
| `-Mode` | `Test` | `Build` learns/updates the baseline. `Test` scores the current state. `Inspect` dumps the baseline contents (read-only). |
| `-SampleSeconds` | `30` | Sampling window per run (5–600). Longer = smoother but slower. |
| `-Reset` | off | On Build, back up and discard the existing baseline, then start fresh. |
| `-BaselinePath` | `%ProgramData%\SystemBaseline\baseline.json` | Where the baseline lives. Use a custom path for per-role baselines. |

### Common commands

```powershell
# Establish or extend the baseline (run this repeatedly over days)
.\Invoke-SystemBaseline.ps1 -Mode Build

# Triage a machine right now
.\Invoke-SystemBaseline.ps1 -Mode Test

# See what the baseline actually contains
.\Invoke-SystemBaseline.ps1 -Mode Inspect

# Start the baseline over from scratch
.\Invoke-SystemBaseline.ps1 -Mode Build -Reset
```

---

## 6. Scheduling (the core workflow)

The baseline is only as good as the variety of conditions it has seen. Schedule **Build** to run regularly so the distribution reflects mornings, afternoons, busy periods, and idle periods.

A reasonable cadence is **hourly Build runs**. Confidence rises with both the number of runs and the number of samples retained:

| Confidence | Condition |
|---|---|
| **LOW** | Fewer than 3 build runs, or under ~100 samples/metric. Treat findings as directional. |
| **MODERATE** | 3+ runs and ~100+ samples/metric. |
| **HIGH** | 7+ runs and ~300+ samples/metric. |

Example scheduled task (Build hourly, as SYSTEM):

```powershell
$action  = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -ExecutionPolicy Bypass -File "C:\Tools\Invoke-SystemBaseline.ps1" -Mode Build'
$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Hours 1)
Register-ScheduledTask -TaskName 'SystemBaseline-Build' -Action $action -Trigger $trigger `
    -User 'SYSTEM' -RunLevel Highest
```

Overlapping runs are safe: a global mutex (`Global\Invoke-SystemBaseline`) makes a second concurrent instance exit cleanly rather than corrupting the JSON.

---

## 7. Reading the report

```
=============================================================
        SYSTEM PERFORMANCE TRIAGE REPORT
=============================================================
Machine            : TONYS-SURFACE
Baseline created   : 2026-06-20 10:54:56   (last updated 2026-06-20 11:09:56)
Baseline build runs: 5   |  samples/metric: ~14
Tested on          : 2026-06-20 11:15:46
Baseline confidence: LOW
Coverage           : 6 of 25 metrics fully scored (rest shown with status flags below)

--- METRIC vs BASELINE ---
Metric                    Current       Mean  z-score  pctile  Status
CPU Load                   92.61%      6.45%     16.1    100%  HIGH
CPU Kernel Time                --         --       --      --  NotSampled
Available RAM           4817.79MB  5121.09MB     -1.8     10%  Normal
...
```

### Header lines
- **build runs / samples/metric** — how much history backs the baseline. A low samples/metric next to a high build count means the metric set grew recently (newer metrics have less history).
- **confidence** — LOW / MODERATE / HIGH, per the table above.
- **Coverage** — how many metrics were *fully scored* (had both a live reading and a baseline) out of the total shown. The rest still appear, flagged.

### Status flags
Every metric appears on every run. The status tells you what kind of row it is:

| Status | Meaning | Action |
|---|---|---|
| `Normal` | Scored and within this machine's normal range. | None. |
| `Elevated` | Scored; past the P95 line and the operational threshold. | Review. |
| `HIGH` | Scored; past the P99 line and the operational threshold. | Investigate — see playbook. |
| `NotSampled` | In the baseline, but the counter did not resolve this run. Shows the baseline mean, `--` for current. | Counter health issue — see Troubleshooting. |
| `NoBaseline` | Sampled live, but no baseline exists yet. | Run more Build cycles. |
| `Unavailable` | Neither sampled nor baselined (counter not present on this machine). | Usually benign (hardware/edition difference). |

Only `Elevated` and `HIGH` drive the diagnostic playbook and the exit code. `NotSampled` / `NoBaseline` are surfaced as coverage warnings rather than alerts, so a flaky counter never pages someone — but the degraded coverage is always visible.

### Diagnostic playbook
For each `Elevated`/`HIGH` finding the report prints the interpretation plus concrete technician action items (e.g., run LatencyMon for DPC spikes, Poolmon for pool leaks, CrystalDiskInfo for SMART health).

### Throttling check
Reports the count of firmware processor-throttle events (Kernel-Processor-Power **ID 37**) in the last 7 days — a direct signal of thermal or power throttling.

### Top processes
Top 5 by CPU time and top 5 by working set, to connect an anomaly to a culprit.

---

## 8. Exit codes (RMM / automation)

The process exit code reflects the worst result, so an RMM or scheduled task can alert on it:

| Code | Meaning |
|---|---|
| `0` | Clean — Build run, or Test with no findings. |
| `1` | Script error (see log). |
| `2` | At least one `Elevated` finding. |
| `3` | At least one `HIGH` finding. |

Map non-zero codes to alerts in your RMM; use `2` vs `3` to set severity.

---

## 9. Metric reference

25 metrics across CPU, memory, disk, network, and system-health. **Direction** indicates whether high or low values are bad. **Threshold** is the operational gate (`MinConcern`) — a metric must cross it *and* be a statistical outlier to flag, so the threshold is a floor, not a trip-wire.

### CPU
| Metric | Counter | Dir | Threshold | What it catches |
|---|---|---|---|---|
| CPU Load | `% Processor Time` | High | 70% | General saturation. |
| CPU Kernel Time | `% Privileged Time` | High | 30% | Driver / AV-EDR / storage-stack overhead. |
| CPU DPC Time | `% DPC Time` | High | 10% | Misbehaving driver (storage/network/GPU). |
| CPU Interrupt Time | `% Interrupt Time` | High | 10% | Failing hardware or bad driver. |
| Processor Queue | `Processor Queue Length` | High | 4 | Threads waiting on CPU (compare to core count). |
| Context Switches/s | `Context Switches/sec` | High | 30000 | Thread thrashing / lock contention. |

### Memory
| Metric | Counter | Dir | Threshold | What it catches |
|---|---|---|---|---|
| Available RAM | `Available MBytes` | Low | 1024 MB | Physical memory exhaustion. |
| Commit Charge | `% Committed Bytes In Use` | High | 85% | Leaning on the page file. |
| Hard Page Faults/s | `Pages/sec` | High | 1000 | Paging from disk — the memory↔disk bridge. |
| Total Page Faults/s | `Page Faults/sec` | High | 5000 | Soft+hard faults; compare to hard to isolate disk thrash. |
| Paged Pool | `Pool Paged Bytes` | High | 800 MB | Kernel-mode (pageable) leak. |
| Nonpaged Pool | `Pool Nonpaged Bytes` | High | 400 MB | Driver leak; exhaustion bug-checks the OS. |
| File Cache | `Cache Bytes` | Low | 100 MB | Cache squeezed out by memory pressure. |
| Pagefile Usage | `% Usage` (Paging File) | High | 50% | Active page-out — corroborates pressure. |

### Disk
| Metric | Counter | Dir | Threshold | What it catches |
|---|---|---|---|---|
| Disk Read Latency | `Avg. Disk sec/Read` | High | 20 ms | Slow/failing storage on reads. |
| Disk Write Latency | `Avg. Disk sec/Write` | High | 20 ms | Slow/failing storage on writes. |
| Disk Queue (context) | `Current Disk Queue Length` | High | 2 | Backed-up I/O (interpret per device type). |
| Disk Read IOPS | `Disk Reads/sec` | High | 500 | Read load (pair with latency). |
| Disk Write IOPS | `Disk Writes/sec` | High | 500 | Write floods (logs, backups, defrag). |
| Disk Idle Time | `% Idle Time` | Low | 20% | Saturation (inverse of utilization). |
| Split IO/s | `Split IO/sec` | High | 10 | Fragmentation / misaligned partitions. |

### Network
| Metric | Counter | Dir | Threshold | What it catches |
|---|---|---|---|---|
| TCP Retransmits/s | `TCPv4\Segments Retransmitted/sec` | High | 10 | Packet loss / congestion on the path. |

### System health (leak indicators)
| Metric | Counter | Dir | Threshold | What it catches |
|---|---|---|---|---|
| Total Handles | `Process(_Total)\Handle Count` | High | 200000 | System-wide handle leak. |
| Process Count | `System\Processes` | High | 500 | Runaway spawns / stuck services. |
| Thread Count | `System\Threads` | High | 5000 | Thread leak in a long-running app. |

> Thresholds are tuned for a typical Windows workstation. Servers will legitimately exceed several of them (context switches, process/thread/handle counts). Because the threshold is ANDed with the statistical gate, an over-high threshold fails safe — it suppresses a flag rather than creating a false one. For leak metrics specifically, keep thresholds low enough that the statistical gate can still detect relative growth.

---

## 10. Baseline file format

`baseline.json` is a single document:

```jsonc
{
  "SchemaVersion": 3,
  "Machine": "TONYS-SURFACE",
  "Created": "2026-06-20 10:54:56",
  "Updated": "2026-06-20 11:09:56",
  "BuildRuns": 5,
  "SampleSeconds": 30,
  "Metrics": {
    "CpuPct": {
      "Label": "CPU Load",
      "Unit": "%",
      "Stats": { "Count": 70, "Mean": 6.45, "Std": 5.1,
                 "P05": 1.2, "P10": 1.8, "P50": 4.9,
                 "P90": 12.0, "P95": 16.4, "P99": 28.1, "Min": 0.4, "Max": 31.0 },
      "Samples": [ 6.1, 5.9, 7.2, ... ]
    }
  }
}
```

- **Stats** is the distribution used for scoring. **Samples** is the capped rolling raw history (default cap 11,000/metric) used to compute percentile position.
- **Schema** describes the file structure only. Versions 2 and 3 share an identical layout; the script **reads either** and **writes 3**, so a baseline created by an older build keeps working and is restamped on the next Build. (A schema outside the readable set is treated as empty, prompting a rebuild.)
- The script keeps a single `.bak` of the prior baseline before each write.

---

## 11. Sizing and footprint

Storage is dominated by the retained sample window. With the default cap:

```
~7 bytes/sample × 25 metrics × 11,000 samples ≈ 2 MB per baseline.json (steady-state)
```

The file is capped and overwritten in place, so it does **not** grow unbounded over time. The log rotates at 5 MB (keeping one `.1` archive), bounding it to ~10 MB.

Size the cap to your retention goal:

```
MaxSamplesPerMetric  =  samples-per-run (~SampleSeconds/2)  ×  runs-per-day  ×  retention-days
```

For a true two-week window at hourly/30-second runs: `~14 × 24 × 14 ≈ 4,700`.

---

## 12. Troubleshooting

### A Test report shows only a few metrics / many rows say `NotSampled`
The counters didn't resolve during that run even though they exist in the baseline. This is almost always **performance-counter corruption** (common after major Windows updates). Confirm and repair:

```powershell
# Confirm which counters were skipped on the last run
Select-String "Counter unavailable" "$env:ProgramData\SystemBaseline\baseline.log" | Select-Object -Last 30

# Repair the performance-counter registry, then resync WMI providers
lodctr /R
winmgmt /resyncperf
```

Re-run `-Mode Test`; the `Coverage` line should climb toward `25 of 25`.

### "No usable baseline found"
Nothing has been built at `-BaselinePath` yet, or the file is corrupt/incompatible. Run `-Mode Inspect` to see the file's state, then `-Mode Build` (with `-Reset` if it's corrupt).

### "Baseline schema … not in the compatible set"
The file was written by a tool version using an incompatible structure. Back it up if you want it, then `-Mode Build -Reset` to start clean.

### Mismatch between what Build and Test see
Use `-Mode Inspect` first — it prints the file path, schema, build count, every stored metric with its sample count, and which metrics are in the script-vs-baseline. Most "it behaves like an old version" issues are actually a **path mismatch** (Build and Test pointed at different `-BaselinePath`) or a stale baseline file. Inspect makes the ground truth obvious.

### Findings look untrustworthy on a fresh baseline
Confidence `LOW` means too little history. Let several Build runs accumulate across different times of day before treating Test results as authoritative.

---

## 13. Design notes

- **Two-gate, no fudge factor.** Status is driven purely by the operational threshold ANDed with the percentile gate (beyond P95/P99 high, below P05/P10 low). The percentile gate already adapts to each machine, so the status stays consistent with the z-score and percentile shown — no hidden multipliers.
- **Localization-safe.** Counter paths are resolved against the registry's English↔local index, so non-English Windows works.
- **Concurrency-safe.** A global mutex prevents overlapping scheduled runs from interleaving writes.
- **Bounded on disk.** Capped sample window + rotating log = predictable footprint per endpoint.
