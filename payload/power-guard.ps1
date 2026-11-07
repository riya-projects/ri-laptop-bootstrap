<#
.SYNOPSIS
  AC power guard for Ri's laptop (REQ #70): on AC power the laptop never sleeps and keeps its
  network adapters on; on battery everything behaves as before.

.DESCRIPTION
  -Action Apply     (the RiLaptop-PowerGuard task: at boot, hourly, on a power source change)
     1. AC indexes only, on EVERY power scheme: sleep 0, hibernate 0, lid close 0 (do nothing),
        unattended sleep 0, hybrid sleep off, wireless adapter power saving 0 (Maximum Performance).
        DC indexes are never written; they are read before and after and any change is an error.
        The active scheme stays the same scheme.
     2. The "Allow the computer to turn off this device to save power" checkbox of each physical
        Wi-Fi/Ethernet adapter (root\wmi MSPower_DeviceEnable.Enable) is one global value, not
        AC/DC. So it is cleared ONLY while on AC. The original value is saved first (once, never
        overwritten), and when the laptop is on battery or the source is unknown, every adapter
        this guard changed is put back to its original value.
     3. powercfg /a is read. Only if Modern Standby (S0) is available AND Windows still has the
        "Networking connectivity in standby" setting, its AC index is set to 1. Otherwise logged
        as unsupported. No registry hacks.
     The log (C:\ProgramData\ri-laptop\power-guard.log) gets a start line on the first run, and
     after that only values that were really corrected and errors.
  -Action Install   copies this script to C:\ProgramData\ri-laptop (SYSTEM and Administrators
                    only), registers the task (refuses a task or file it does not own), runs Apply
                    once and reads everything back.
  -Action Verify    read-only before/after table (JSON, CSV and console) of every scheme's AC/DC
                    index, the adapters, Wi-Fi profiles, services, the task and its files.
  -Action Diagnose  read-only: Verify plus events of one local day (Kernel-Power 42/105/107/506/507,
                    Power-Troubleshooter 1) as XML and lines, sleep study or system power report,
                    Lenovo Vantage, power mode, power group policy, wake timers, Windows Update.
  -Action Compare   -Before a.json -After b.json: one CSV row per item with both values.
  -Action WifiAutoConnect -WifiProfile <name>: netsh wlan set profileparameter connectionmode=auto.

  It never holds a wake or display lock, never changes battery settings, the hibernate feature,
  Modern Standby registry values, sshd, Tailscale, services or the RiKeepAwake task.

  Runtime status: NOT RUN on Windows. Written and tested on Linux with fakes for powercfg, WMI
  and the power source.
#>
[CmdletBinding()]
param(
    [ValidateSet('Apply', 'Install', 'Verify', 'Diagnose', 'Compare', 'WifiAutoConnect')]
    [string]$Action = 'Apply',
    [string]$OutDir,
    [string]$Before,
    [string]$After,
    [string]$WifiProfile,
    [int]$Days = 1
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- constants

$script:PgSelf = $PSCommandPath
$script:PgDir = Join-Path $env:ProgramData 'ri-laptop'
$script:PgScript = Join-Path $script:PgDir 'power-guard.ps1'
$script:PgState = Join-Path $script:PgDir 'power-guard-state.json'
$script:PgLog = Join-Path $script:PgDir 'power-guard.log'
$script:PgReports = Join-Path $script:PgDir 'reports'
$script:PgTaskName = 'RiLaptop-PowerGuard'
$script:PgTaskMarker = 'ri-laptop power guard (REQ70)'
$script:PgMutexName = 'Global\RiLaptopPowerGuard'
$script:PgSidSystem = 'S-1-5-18'
$script:PgSidAdmins = 'S-1-5-32-544'
$script:PgFirstStartLine = 'power-guard start (first run): AC values on every scheme, adapter checkbox on AC only, baseline restored on battery'

# AC targets. Aliases and GUIDs are Microsoft's (learn.microsoft.com, Windows power settings).
$script:AcTargets = @(
    [pscustomobject]@{ Name = 'Sleep after'; Sub = 'SUB_SLEEP'; Setting = 'STANDBYIDLE'; Value = 0 }
    [pscustomobject]@{ Name = 'Hibernate after'; Sub = 'SUB_SLEEP'; Setting = 'HIBERNATEIDLE'; Value = 0 }
    [pscustomobject]@{ Name = 'Lid close action'; Sub = 'SUB_BUTTONS'; Setting = 'LIDACTION'; Value = 0 }
    [pscustomobject]@{ Name = 'Unattended sleep timeout'; Sub = 'SUB_SLEEP'; Setting = 'UNATTENDSLEEP'; Value = 0 }
    [pscustomobject]@{ Name = 'Allow hybrid sleep'; Sub = 'SUB_SLEEP'; Setting = 'HYBRIDSLEEP'; Value = 0 }
    # Wireless Adapter Settings > Power Saving Mode; 0 = Maximum Performance.
    [pscustomobject]@{ Name = 'Wireless power saving mode'; Sub = '19cbb8fa-5279-450e-9fac-8a3d5fedd0c1'; Setting = '12bbebe6-58d6-4636-95bb-3217ef867c1a'; Value = 0 }
)
# Networking connectivity in standby (no subgroup); 1 = enable. Deprecated since Windows 10 2004,
# so it is applied only when Windows still reports it.
$script:NcisTarget = [pscustomobject]@{ Name = 'Networking connectivity in standby'; Sub = 'SUB_NONE'; Setting = 'f15576e8-98b7-4186-b944-eafa664402d9'; Value = 1 }
# NDIS_PHYSICAL_MEDIUM: 9 = Native 802.11 (Wi-Fi), 14 = 802.3 (Ethernet).
$script:NicMedia = @{ 9 = 'Wi-Fi'; 14 = 'Ethernet' }
$script:ServiceNames = @('Tailscale', 'sshd', 'tvnserver', 'RiIndiaProxy')
$script:GuidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

# ---------------------------------------------------------------- boundaries (faked in tests)

function Invoke-GuardNative {
    <# Run a Windows tool; throw with its output if it exits non-zero. #>
    param([string]$FilePath, [string[]]$ArgumentList)
    $ErrorActionPreference = 'Continue'
    $out = (& $FilePath @ArgumentList 2>&1 | Out-String) -replace "`r", ''
    if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($FilePath)) $($ArgumentList -join ' ') failed ($LASTEXITCODE): $($out.Trim())" }
    return $out
}

function Get-PowerLineStatus {
    <# 'AC', 'DC' or 'Unknown' from kernel32 GetSystemPowerStatus (ACLineStatus 1, 0, 255).
       Any failure is 'Unknown', which the guard treats like battery. #>
    try {
        if (-not ('RiLaptop.PowerStatus' -as [type])) {
            Add-Type -Namespace RiLaptop -Name PowerStatus -MemberDefinition @'
[System.Runtime.InteropServices.StructLayout(System.Runtime.InteropServices.LayoutKind.Sequential)]
public struct SYSTEM_POWER_STATUS { public byte ACLineStatus; public byte BatteryFlag; public byte BatteryLifePercent; public byte SystemStatusFlag; public int BatteryLifeTime; public int BatteryFullLifeTime; }
[System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GetSystemPowerStatus(out SYSTEM_POWER_STATUS status);
'@
        }
        $s = New-Object 'RiLaptop.PowerStatus+SYSTEM_POWER_STATUS'
        if (-not [RiLaptop.PowerStatus]::GetSystemPowerStatus([ref]$s)) { return 'Unknown' }
        switch ([int]$s.ACLineStatus) { 1 { return 'AC' } 0 { return 'DC' } default { return 'Unknown' } }
    } catch { return 'Unknown' }
}

function Get-GuardNetAdapter {
    <# Physical adapters (also disabled or disconnected ones). #>
    @(Get-NetAdapter -Physical -ErrorAction Stop)
}

function Get-DeviceEnableInstance {
    <# The WMI objects behind the "Allow the computer to turn off this device" checkbox. #>
    @(Get-CimInstance -Namespace 'root\wmi' -ClassName 'MSPower_DeviceEnable' -ErrorAction Stop)
}

function Set-DeviceEnableValue {
    param([string]$InstanceName, [bool]$Enable)
    $inst = @(Get-DeviceEnableInstance | Where-Object { $_.InstanceName -eq $InstanceName })
    if ($inst.Count -ne 1) { throw "MSPower_DeviceEnable instance $InstanceName not found" }
    Set-CimInstance -InputObject $inst[0] -Property @{ Enable = $Enable } -ErrorAction Stop
}

# ---------------------------------------------------------------- log and state

function Test-HasProperty {
    <# Strict mode safe, also for an object with no properties. #>
    param($Object, [string]$Name)
    if ($null -eq $Object) { return $false }
    return [bool](@($Object.PSObject.Properties | Where-Object { $_.Name -eq $Name }).Count)
}

function Write-GuardLog {
    <# Corrections and errors only (and the first start line). Never secrets. #>
    param([string]$Line)
    try {
        $now = [DateTimeOffset]::Now
        $stamp = '{0} (local {1})' -f $now.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ'), $now.ToString('yyyy-MM-ddTHH:mm:sszzz')
        Add-Content -LiteralPath $script:PgLog -Value "$stamp $Line" -Encoding UTF8
    } catch { Write-Verbose "could not write power guard log: $($_.Exception.Message)" }
}

function New-GuardState { [pscustomobject]@{ version = 1; adapters = [pscustomobject]@{} } }

function Read-GuardState {
    <# The adapter journal. A missing file is a new journal; a damaged one throws (the guard then
       neither disables nor guesses a restore; a person repairs it). #>
    if (-not (Test-Path -LiteralPath $script:PgState)) { return New-GuardState }
    $raw = Get-Content -LiteralPath $script:PgState -Raw
    try { $s = $raw | ConvertFrom-Json } catch { throw "power guard state $($script:PgState) is not valid JSON; adapters left alone" }
    if (-not $s -or $s.version -ne 1 -or -not (Test-HasProperty $s 'adapters')) { throw "power guard state $($script:PgState) has an unknown format; adapters left alone" }
    foreach ($p in @($s.adapters.PSObject.Properties)) {
        $r = $p.Value
        foreach ($f in 'baseline', 'phase', 'instance') { if (-not (Test-HasProperty $r $f)) { throw "power guard state: adapter $($p.Name) has no $f" } }
        if ($r.baseline -isnot [bool]) { throw "power guard state: adapter $($p.Name) baseline is not true/false" }
        if (@('None', 'DisablePending', 'Applied', 'RestorePending') -notcontains $r.phase) { throw "power guard state: adapter $($p.Name) phase '$($r.phase)' is unknown" }
    }
    return $s
}

function Save-GuardState {
    <# Write to a temp file in the same folder, then replace: a crash leaves the old or the new file. #>
    param($State)
    $tmp = "$($script:PgState).tmp"
    $json = $State | ConvertTo-Json -Depth 6
    [IO.File]::WriteAllText($tmp, $json, (New-Object Text.UTF8Encoding $false))
    if (Test-Path -LiteralPath $script:PgState) { [IO.File]::Replace($tmp, $script:PgState, [NullString]::Value) }
    else { [IO.File]::Move($tmp, $script:PgState) }
}

# ---------------------------------------------------------------- powercfg

function Get-PowercfgValue {
    <# AC and DC index from `powercfg /query` output. Labels are translated, so the last two hex
       values ending a line are read (AC, then DC). #>
    param([string]$Text)
    $hex = @([regex]::Matches($Text, '0x([0-9a-fA-F]{8})\s*$', 'Multiline') | ForEach-Object { [Convert]::ToInt64($_.Groups[1].Value, 16) })
    if ($hex.Count -lt 2) { throw 'could not read powercfg values' }
    return [pscustomobject]@{ AC = $hex[$hex.Count - 2]; DC = $hex[$hex.Count - 1] }
}

function Get-PowerSchemeList {
    <# Every scheme GUID from `powercfg /list` (names are translated; GUIDs are not). #>
    $text = Invoke-GuardNative powercfg.exe @('/list')
    $guids = @([regex]::Matches($text, $script:GuidPattern) | ForEach-Object { $_.Value.ToLowerInvariant() } | Select-Object -Unique)
    if (-not $guids.Count) { throw 'powercfg /list returned no scheme GUID' }
    return $guids
}

function Get-ActiveSchemeGuid {
    $text = Invoke-GuardNative powercfg.exe @('/getactivescheme')
    $m = [regex]::Match($text, $script:GuidPattern)
    if (-not $m.Success) { throw 'powercfg /getactivescheme returned no GUID' }
    return $m.Value.ToLowerInvariant()
}

function Get-SchemeSetting {
    <# AC/DC of one setting, or Supported=$false with powercfg's own words as the reason. #>
    param([string]$Scheme, $Target)
    try {
        $v = Get-PowercfgValue -Text (Invoke-GuardNative powercfg.exe @('/query', $Scheme, $Target.Sub, $Target.Setting))
        return [pscustomobject]@{ Supported = $true; AC = $v.AC; DC = $v.DC; Reason = '' }
    } catch {
        return [pscustomobject]@{ Supported = $false; AC = $null; DC = $null; Reason = ($_.Exception.Message -replace '\s+', ' ').Trim() }
    }
}

function Test-ModernStandby {
    <# From `powercfg /a`: the first block (until the next unindented line) lists the available
       states; S0 there means Modern Standby. The header lines are translated, the "S0"/"S3"
       tokens are not. Returns Available plus the raw lines as evidence. #>
    param([string]$Text)
    $lines = @($Text -split "`n" | ForEach-Object { $_.TrimEnd() } | Where-Object { $_ })
    $available = @()
    $seenHeader = $false
    foreach ($l in $lines) {
        if ($l -notmatch '^\s') { if ($seenHeader) { break } else { $seenHeader = $true; continue } }
        if ($seenHeader) { $available += $l.Trim() }
    }
    [pscustomobject]@{
        S0 = [bool](@($available | Where-Object { $_ -match '\bS0\b' }).Count)
        Available = $available
    }
}

function Invoke-SchemePass {
    <# Sets AC indexes on every scheme, reads back, checks DC and the active scheme did not change.
       Returns rows: Scheme, Setting, Before/After AC, DC before/after, Status (OK, CORRECTED,
       UNSUPPORTED, ERROR) and Reason. #>
    param([switch]$ReadOnly)
    $rows = New-Object System.Collections.Generic.List[object]
    $active = Get-ActiveSchemeGuid
    $targets = @($script:AcTargets)
    $ms = $null
    try { $ms = Test-ModernStandby -Text (Invoke-GuardNative powercfg.exe @('/a')) } catch { $ms = $null }
    $changedActive = $false
    foreach ($scheme in Get-PowerSchemeList) {
        $all = @($targets)
        if ($ms -and $ms.S0) { $all += $script:NcisTarget }
        foreach ($t in $all) {
            $b = Get-SchemeSetting -Scheme $scheme -Target $t
            $row = [pscustomobject]@{ Scheme = $scheme; Active = ($scheme -eq $active); Setting = $t.Name; Guid = "$($t.Sub)/$($t.Setting)"
                Target = $t.Value; AcBefore = $b.AC; AcAfter = $b.AC; DcBefore = $b.DC; DcAfter = $b.DC; Status = 'OK'; Reason = '' }
            if (-not $b.Supported) { $row.Status = 'UNSUPPORTED'; $row.Reason = "not on this system/scheme: $($b.Reason)"; $rows.Add($row); continue }
            if ($b.AC -ne $t.Value) {
                if ($ReadOnly) { $row.Status = 'DRIFT'; $rows.Add($row); continue }
                try {
                    Invoke-GuardNative powercfg.exe @('/setacvalueindex', $scheme, $t.Sub, $t.Setting, "$($t.Value)") | Out-Null
                    if ($scheme -eq $active) { $changedActive = $true }
                    $a = Get-SchemeSetting -Scheme $scheme -Target $t
                    $row.AcAfter = $a.AC; $row.DcAfter = $a.DC
                    if (-not $a.Supported -or $a.AC -ne $t.Value) { $row.Status = 'ERROR'; $row.Reason = "AC read back $($a.AC), wanted $($t.Value)" }
                    else { $row.Status = 'CORRECTED' }
                } catch { $row.Status = 'ERROR'; $row.Reason = ($_.Exception.Message -replace '\s+', ' ').Trim() }
            }
            if ($row.DcAfter -ne $row.DcBefore) { $row.Status = 'ERROR'; $row.Reason = "DC index changed $($row.DcBefore) -> $($row.DcAfter)" }
            $rows.Add($row)
        }
    }
    $now = Get-ActiveSchemeGuid
    if ($changedActive) {
        # Re-apply whatever scheme is active at that moment so Windows uses the new AC values
        # now. Never by GUID: a GUID read earlier may be stale (someone switched meanwhile) and
        # would switch the scheme back (Codex r2). Every scheme got the AC values anyway.
        try { Invoke-GuardNative powercfg.exe @('/setactive', 'SCHEME_CURRENT') | Out-Null } catch {
            $rows.Add([pscustomobject]@{ Scheme = $active; Active = $true; Setting = 'setactive'; Guid = ''; Target = ''; AcBefore = ''; AcAfter = ''; DcBefore = ''; DcAfter = ''; Status = 'ERROR'; Reason = $_.Exception.Message })
        }
        $now = Get-ActiveSchemeGuid
    }
    if ($now -ne $active) { $rows.Add([pscustomobject]@{ Scheme = $now; Active = $true; Setting = 'active scheme'; Guid = ''; Target = $active; AcBefore = $active; AcAfter = $now; DcBefore = ''; DcAfter = ''; Status = 'ERROR'; Reason = 'active scheme changed during the run' }) }
    if (-not $ms) { $rows.Add([pscustomobject]@{ Scheme = '*'; Active = $false; Setting = $script:NcisTarget.Name; Guid = ''; Target = 1; AcBefore = ''; AcAfter = ''; DcBefore = ''; DcAfter = ''; Status = 'UNSUPPORTED'; Reason = 'powercfg /a could not be read' }) }
    elseif (-not $ms.S0) { $rows.Add([pscustomobject]@{ Scheme = '*'; Active = $false; Setting = $script:NcisTarget.Name; Guid = ''; Target = 1; AcBefore = ''; AcAfter = ''; DcBefore = ''; DcAfter = ''; Status = 'UNSUPPORTED'; Reason = "no Modern Standby (S0) in powercfg /a available states: $($ms.Available -join '; ')" }) }
    return $rows
}

# ---------------------------------------------------------------- adapters

function Get-GuardAdapterMap {
    <# Physical Wi-Fi/Ethernet adapters with their one checkbox instance. InstanceName is the
       PnP device ID plus "_<n>"; none or several matching instances is Unsupported. #>
    $instances = @(Get-DeviceEnableInstance)
    foreach ($a in Get-GuardNetAdapter) {
        $medium = $null
        try { $medium = [int]$a.NdisPhysicalMedium } catch { $medium = $null }
        if ($null -eq $medium -or -not $script:NicMedia.ContainsKey($medium)) { continue }
        $pnp = "$($a.PnPDeviceID)"
        $prefix = "$pnp" + '_'
        $match = @($instances | Where-Object { $pnp -and "$($_.InstanceName)".StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -and "$($_.InstanceName)".Substring($prefix.Length) -match '^\d+$' })
        $reason = ''
        if (-not $pnp) { $reason = 'adapter has no PnP device ID' }
        elseif ($match.Count -eq 0) { $reason = 'driver exposes no MSPower_DeviceEnable instance (no "Allow the computer to turn off this device" checkbox)' }
        elseif ($match.Count -gt 1) { $reason = "$($match.Count) MSPower_DeviceEnable instances match; ambiguous" }
        [pscustomobject]@{
            Key = "$($a.InterfaceGuid)".ToLowerInvariant(); Name = $a.Name; Description = $a.InterfaceDescription; Medium = $script:NicMedia[$medium]
            Instance = $(if ($match.Count -eq 1) { $match[0].InstanceName } else { '' })
            Enable = $(if ($match.Count -eq 1) { [bool]$match[0].Enable } else { $null })
            Reason = $reason
        }
    }
}

function Read-AdapterEnable {
    param([string]$Instance)
    $m = @(Get-DeviceEnableInstance | Where-Object { $_.InstanceName -eq $Instance })
    if ($m.Count -ne 1) { throw "checkbox instance $Instance is gone" }
    return [bool]$m[0].Enable
}

function Restore-AdapterBaseline {
    <# Battery or unknown source: every record this guard owns (DisablePending, Applied,
       RestorePending) goes back to its saved original value. Records it does not own are never
       touched, so a change made by a person on battery stays. #>
    param($State, $Map, $Result)
    foreach ($p in @($State.adapters.PSObject.Properties)) {
        $r = $p.Value
        if ($r.phase -eq 'None') { continue }
        $now = @($Map | Where-Object { $_.Key -eq $p.Name -and $_.Instance })
        if (-not $now.Count) { $Result.Errors.Add("adapter $($r.name) ($($p.Name)) is not present; its original checkbox value ($($r.baseline)) is still owed and will be restored when it is back"); continue }
        $inst = $now[0].Instance
        if ($inst -ne $r.instance) { $Result.Errors.Add("adapter $($r.name): checkbox instance changed ($($r.instance) -> $inst); original ($($r.baseline)) is still owed to $($r.instance), nothing written"); continue }
        try {
            $r.phase = 'RestorePending'; Save-GuardState $State
            if ((Read-AdapterEnable $inst) -ne $r.baseline) {
                Set-DeviceEnableValue -InstanceName $inst -Enable $r.baseline
                $back = Read-AdapterEnable $inst
                if ($back -ne $r.baseline) { throw "read back $back, wanted $($r.baseline)" }
                $Result.Corrections.Add("adapter $($r.name): restored original 'allow turn off' = $($r.baseline) (power source not AC)")
            }
            $r.phase = 'None'; Save-GuardState $State
        } catch { $Result.Errors.Add("adapter $($r.name): restore to $($r.baseline) failed: $($_.Exception.Message)") }
    }
}

function Invoke-AdapterPass {
    <# On AC: record each adapter's original value once, mark it DisablePending, clear the
       checkbox, read back, mark Applied. The power source is read again right before every
       write and after the pass; if it is not AC, everything owned is restored instead. #>
    param($Result)
    try { $state = Read-GuardState } catch { $Result.Errors.Add($_.Exception.Message); return }
    try { $map = @(Get-GuardAdapterMap) } catch { $Result.Errors.Add("adapters could not be read: $($_.Exception.Message)"); return }
    foreach ($m in $map) { if ($m.Reason) { $Result.Unsupported.Add("adapter $($m.Name) ($($m.Medium)): $($m.Reason)") } }
    $source = Get-PowerLineStatus
    $Result.Source = $source
    if ($source -eq 'AC') {
        foreach ($m in @($map | Where-Object { $_.Instance })) {
            $rec = $null
            if (Test-HasProperty $state.adapters $m.Key) { $rec = $state.adapters.($m.Key) }
            if (-not $rec) {
                # First sight: the value now is the original. Saved before anything is changed.
                $rec = [pscustomobject]@{ name = $m.Name; instance = $m.Instance; baseline = [bool]$m.Enable; phase = 'None'; recordedUtc = [DateTime]::UtcNow.ToString('o') }
                $state.adapters | Add-Member -NotePropertyName $m.Key -NotePropertyValue $rec
                try { Save-GuardState $state } catch { $Result.Errors.Add("state could not be saved; adapters left alone: $($_.Exception.Message)"); return }
            }
            if ($rec.instance -ne $m.Instance) { $Result.Errors.Add("adapter $($m.Name): checkbox instance changed ($($rec.instance) -> $($m.Instance)); left alone"); continue }
            try {
                if ($rec.phase -eq 'None' -and [bool]$rec.baseline -ne [bool]$m.Enable) {
                    # Not owned, so the value now was set by a person or a driver: it is the new
                    # original. (Owned records are never re-baselined.)
                    $rec.baseline = [bool]$m.Enable; $rec.recordedUtc = [DateTime]::UtcNow.ToString('o'); Save-GuardState $state
                }
                if (-not $m.Enable) {
                    # Already off. Ours (pending) means the write had happened: mark it applied.
                    if ($rec.phase -ne 'None' -and $rec.phase -ne 'Applied') { $rec.phase = 'Applied'; Save-GuardState $state }
                    continue
                }
                if ((Get-PowerLineStatus) -ne 'AC') { $Result.Source = 'changed'; break }
                $rec.phase = 'DisablePending'; Save-GuardState $state
                # Saving can take time: read the power source again right at the write.
                if ((Get-PowerLineStatus) -ne 'AC') { $Result.Source = 'changed'; break }
                Set-DeviceEnableValue -InstanceName $m.Instance -Enable $false
                if (Read-AdapterEnable $m.Instance) { throw 'read back still allowed' }
                $Result.Corrections.Add("adapter $($m.Name): 'allow turn off' true -> false (on AC; original true saved)")
                $rec.phase = 'Applied'; Save-GuardState $state
            } catch { $Result.Errors.Add("adapter $($m.Name): could not clear 'allow turn off': $($_.Exception.Message)") }
        }
        $after = Get-PowerLineStatus
        if ($after -ne 'AC') { $Result.Source = "AC->$after"; Restore-AdapterBaseline -State $state -Map $map -Result $Result }
    } else {
        Restore-AdapterBaseline -State $state -Map $map -Result $Result
    }
}

# ---------------------------------------------------------------- apply

function Invoke-PowerGuardApply {
    <# One serialized run. Returns 0 when nothing failed. #>
    $mutex = New-Object Threading.Mutex($false, $script:PgMutexName)
    $owned = $false
    try {
        try { $owned = $mutex.WaitOne([TimeSpan]::FromMinutes(5)) } catch [Threading.AbandonedMutexException] { $owned = $true }
        if (-not $owned) { Write-GuardLog 'ERROR another power guard run held the lock for 5 minutes; skipped'; return 1 }
        if (-not (Test-Path -LiteralPath $script:PgLog) -or -not (Get-Item -LiteralPath $script:PgLog).Length) { Write-GuardLog $script:PgFirstStartLine }
        $result = [pscustomobject]@{ Source = ''; Corrections = (New-Object System.Collections.Generic.List[string]); Errors = (New-Object System.Collections.Generic.List[string]); Unsupported = (New-Object System.Collections.Generic.List[string]) }
        try {
            foreach ($r in Invoke-SchemePass) {
                if ($r.Status -eq 'CORRECTED') { $result.Corrections.Add("scheme $($r.Scheme): $($r.Setting) AC $($r.AcBefore) -> $($r.AcAfter) (DC $($r.DcAfter) unchanged)") }
                elseif ($r.Status -eq 'ERROR') { $result.Errors.Add("scheme $($r.Scheme): $($r.Setting): $($r.Reason)") }
                elseif ($r.Status -eq 'UNSUPPORTED') { $result.Unsupported.Add("scheme $($r.Scheme): $($r.Setting): $($r.Reason)") }
            }
        } catch { $result.Errors.Add("power schemes: $($_.Exception.Message)") }
        Invoke-AdapterPass -Result $result
        foreach ($c in $result.Corrections) { Write-GuardLog "CORRECTED [$($result.Source)] $c" }
        foreach ($e in $result.Errors) { Write-GuardLog "ERROR [$($result.Source)] $e" }
        # Each unsupported item is logged once, not every hour.
        foreach ($u in $result.Unsupported) {
            if (-not (Select-String -LiteralPath $script:PgLog -SimpleMatch "UNSUPPORTED $u" -Quiet)) { Write-GuardLog "UNSUPPORTED $u" }
        }
        $result
        if ($result.Errors.Count) { return 1 }
        return 0
    } finally {
        if ($owned) { $mutex.ReleaseMutex() }
        $mutex.Dispose()
    }
}

# ---------------------------------------------------------------- task and install

function Get-PowerGuardTaskXml {
    <# Task definition: SYSTEM, boot + hourly + power source change (Kernel-Power 105) + resume
       (Power-Troubleshooter 1, Kernel-Power 107/507). Runs on battery (to restore the baseline),
       never wakes the computer, queues overlapping runs. #>
    param([string]$ScriptPath)
    $q = { param($p, $id) [Security.SecurityElement]::Escape("<QueryList><Query Id=`"0`" Path=`"System`"><Select Path=`"System`">*[System[Provider[@Name='$p'] and ($id)]]</Select></Query></QueryList>") }
    $kp = & $q 'Microsoft-Windows-Kernel-Power' 'EventID=105 or EventID=107 or EventID=507'
    $pt = & $q 'Microsoft-Windows-Power-Troubleshooter' 'EventID=1'
    $arg = [Security.SecurityElement]::Escape("-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$ScriptPath`" -Action Apply")
    @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Author>ri-laptop</Author><Description>$($script:PgTaskMarker): AC never sleeps, network adapters stay on while on AC, battery behaviour restored on DC</Description></RegistrationInfo>
  <Triggers>
    <BootTrigger><Enabled>true</Enabled><Delay>PT1M</Delay></BootTrigger>
    <TimeTrigger><Enabled>true</Enabled><StartBoundary>2026-01-01T00:05:00</StartBoundary><Repetition><Interval>PT1H</Interval><StopAtDurationEnd>false</StopAtDurationEnd></Repetition></TimeTrigger>
    <EventTrigger><Enabled>true</Enabled><Subscription>$kp</Subscription><Delay>PT10S</Delay></EventTrigger>
    <EventTrigger><Enabled>true</Enabled><Subscription>$pt</Subscription><Delay>PT10S</Delay></EventTrigger>
  </Triggers>
  <Principals><Principal id="Author"><UserId>$($script:PgSidSystem)</UserId><RunLevel>HighestAvailable</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>Queue</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings><StopOnIdleEnd>false</StopOnIdleEnd><RestartOnIdle>false</RestartOnIdle></IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>powershell.exe</Command><Arguments>$arg</Arguments></Exec></Actions>
</Task>
"@
}

function Test-PowerGuardTask {
    <# Problems with the registered task, as strings (empty = as installed). #>
    param($Task, [string]$ScriptPath)
    $p = @()
    if (-not $Task) { return @('task not registered') }
    if ("$($Task.Description)" -notlike "$($script:PgTaskMarker)*") { $p += 'description is not ours' }
    $sid = "$($Task.Principal.UserId)"
    if ($sid -ne $script:PgSidSystem -and $sid -notmatch '^(NT AUTHORITY\\)?SYSTEM$') { $p += "runs as $sid, not SYSTEM" }
    if ("$($Task.State)" -eq 'Disabled') { $p += 'disabled' }
    $s = $Task.Settings
    if ($s.DisallowStartIfOnBatteries) { $p += 'does not start on battery (cannot restore the baseline)' }
    if ($s.StopIfGoingOnBatteries) { $p += 'stops when going on battery' }
    if (-not $s.StartWhenAvailable) { $p += 'StartWhenAvailable is off' }
    if ($s.WakeToRun) { $p += 'wakes the computer' }
    $acts = @($Task.Actions)
    if ($acts.Count -ne 1 -or "$($acts[0].Arguments)" -notlike "*`"$ScriptPath`"*") { $p += 'action does not run our script' }
    $kinds = @($Task.Triggers | ForEach-Object { $_.CimClass.CimClassName })
    foreach ($k in 'MSFT_TaskBootTrigger', 'MSFT_TaskTimeTrigger', 'MSFT_TaskEventTrigger') { if ($kinds -notcontains $k) { $p += "no $k" } }
    return $p
}

function Test-PrivateAcl {
    <# Owner SYSTEM/Administrators, inheritance cut (for the folder), allow entries only for
       SYSTEM and Administrators. #>
    param([string]$Path, [switch]$Folder)
    $acl = Get-Acl -LiteralPath $Path
    $toSid = { param($i) try { $i.Translate([Security.Principal.SecurityIdentifier]).Value } catch { "$i" } }
    $owner = & $toSid (New-Object Security.Principal.NTAccount $acl.Owner)
    $bad = @()
    if (@($script:PgSidSystem, $script:PgSidAdmins) -notcontains $owner) { $bad += "owner $owner" }
    if ($Folder -and -not $acl.AreAccessRulesProtected) { $bad += 'inherits permissions' }
    foreach ($e in $acl.Access) {
        $sid = & $toSid $e.IdentityReference
        if ($e.AccessControlType -eq 'Allow' -and @($script:PgSidSystem, $script:PgSidAdmins) -notcontains $sid) { $bad += "allows $sid" }
    }
    return $bad
}

function Protect-PowerGuardDir {
    <# C:\ProgramData\ri-laptop: refuse a link or a folder owned by someone else (setup.ps1's
       Protect-SecretDir moves those aside); set owner Administrators, cut inheritance, allow
       SYSTEM and Administrators only, read back. #>
    if (Test-Path -LiteralPath $script:PgDir) {
        $item = Get-Item -LiteralPath $script:PgDir -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($script:PgDir) is a link or junction" }
        $bad = @(Test-PrivateAcl -Path $script:PgDir -Folder | Where-Object { $_ -like 'owner *' })
        if ($bad.Count) { throw "$($script:PgDir) is owned by someone else ($($bad -join ', ')); run setup.ps1 (it moves it aside)" }
    } else { New-Item -ItemType Directory -Path $script:PgDir | Out-Null }
    Invoke-GuardNative icacls.exe @($script:PgDir, '/setowner', "*$($script:PgSidAdmins)", '/L', '/Q') | Out-Null
    Invoke-GuardNative icacls.exe @($script:PgDir, '/inheritance:r', '/grant:r', "*$($script:PgSidAdmins):(OI)(CI)F", '/grant:r', "*$($script:PgSidSystem):(OI)(CI)F", '/L', '/Q') | Out-Null
    foreach ($e in @((Get-Acl -LiteralPath $script:PgDir).Access | Where-Object { -not $_.IsInherited })) {
        $sid = "$($e.IdentityReference)"
        try { $sid = $e.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { Write-Verbose "unresolved $sid" }
        if (@($script:PgSidSystem, $script:PgSidAdmins) -notcontains $sid) { Invoke-GuardNative icacls.exe @($script:PgDir, '/remove:g', "*$sid", '/L', '/Q') | Out-Null }
    }
    $bad = @(Test-PrivateAcl -Path $script:PgDir -Folder)
    if ($bad.Count) { throw "$($script:PgDir) ACL did not read back as SYSTEM+Administrators only: $($bad -join ', ')" }
}

function Install-PowerGuard {
    <# Copies the script, registers the task, runs Apply once, reads back. Returns a detail
       string; throws on any failure. Never touches the RiKeepAwake task. #>
    param([string]$SourceScript = $script:PgSelf)
    # Collisions first, before anything is changed: a task, script, journal or log that is not
    # this guard's is refused, never replaced or adopted.
    $existing = Get-ScheduledTask -TaskName $script:PgTaskName -ErrorAction SilentlyContinue
    if ($existing -and "$($existing.Description)" -notlike "$($script:PgTaskMarker)*") { throw "a task named $($script:PgTaskName) exists that this installer did not make; not replaced" }
    foreach ($f in $script:PgScript, $script:PgState, $script:PgLog) {
        if (-not (Test-Path -LiteralPath $f)) { continue }
        if ((Get-Item -LiteralPath $f -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$f is a link; not used" }
        $bad = @(Test-PrivateAcl -Path $f)
        if ($bad.Count) { throw "$f is not private to SYSTEM and Administrators ($($bad -join ', ')); not adopted" }
    }
    if ((Test-Path -LiteralPath $script:PgScript) -and -not (Select-String -LiteralPath $script:PgScript -SimpleMatch $script:PgTaskMarker -Quiet)) { throw "$($script:PgScript) exists but is not this power guard; not replaced" }
    if (Test-Path -LiteralPath $script:PgState) { try { Read-GuardState | Out-Null } catch { throw "$($script:PgState) is not this guard's journal; not adopted ($($_.Exception.Message))" } }
    if ((Test-Path -LiteralPath $script:PgLog) -and (Get-Item -LiteralPath $script:PgLog).Length) {
        $first = "$(Get-Content -LiteralPath $script:PgLog -TotalCount 1)"
        if ($first -notmatch [regex]::Escape($script:PgFirstStartLine)) { throw "$($script:PgLog) was not written by this guard; not adopted" }
    }
    Protect-PowerGuardDir
    if ((Resolve-Path -LiteralPath $SourceScript).Path -ne $script:PgScript) {
        Copy-Item -LiteralPath $SourceScript -Destination $script:PgScript -Force
        if ((Get-FileHash -LiteralPath $SourceScript).Hash -ne (Get-FileHash -LiteralPath $script:PgScript).Hash) { throw 'power-guard.ps1 copy does not match' }
    }
    Register-ScheduledTask -TaskName $script:PgTaskName -Xml (Get-PowerGuardTaskXml -ScriptPath $script:PgScript) -Force | Out-Null
    $problems = @(Test-PowerGuardTask -Task (Get-ScheduledTask -TaskName $script:PgTaskName) -ScriptPath $script:PgScript)
    if ($problems.Count) { throw "task $($script:PgTaskName) did not read back: $($problems -join '; ')" }
    $out = @(Invoke-PowerGuardApply)
    $code = $out[-1]
    foreach ($f in $script:PgScript, $script:PgState, $script:PgLog) {
        if (Test-Path -LiteralPath $f) { $bad = @(Test-PrivateAcl -Path $f); if ($bad.Count) { throw "$f ACL: $($bad -join ', ')" } }
    }
    if ($code -ne 0) { throw "first guard run reported errors (see $($script:PgLog))" }
    $first = @(Get-Content -LiteralPath $script:PgLog -TotalCount 1)
    "task $($script:PgTaskName) (SYSTEM; boot, hourly, power source change, resume; runs on battery to restore) installed; first log line: $($first -join '')"
}

# ---------------------------------------------------------------- verify and diagnose (read-only)

function Get-WifiProfileReport {
    <# Wi-Fi profile names and connection mode via netsh (never key=clear). Labels are
       translated; the English ones are read, anything else is reported as found. Lines with a
       key are dropped before anything is kept. #>
    $rows = @()
    try { $list = Invoke-GuardNative netsh.exe @('wlan', 'show', 'profiles') } catch { return @([pscustomobject]@{ Category = 'wifi'; Item = '*'; Property = 'profiles'; Value = ''; Expected = ''; Status = 'UNSUPPORTED'; Reason = "netsh wlan: $($_.Exception.Message)" }) }
    foreach ($l in ($list -split "`n")) {
        if ($l -notmatch '^\s{2,}(.+?)\s+:\s(.+)$') { continue }
        $label = $Matches[1].Trim(); $name = $Matches[2].Trim()
        $scope = $(if ($label -eq 'All User Profile') { 'all users' } elseif ($label -eq 'Current User Profile') { 'current user only' } else { "label '$label'" })
        $mode = 'unknown'
        try {
            $detail = (Invoke-GuardNative netsh.exe @('wlan', 'show', 'profile', "name=$name")) -split "`n" | Where-Object { $_ -notmatch 'Key Content|Schl.sselinhalt' }
            $cm = @($detail | Where-Object { $_ -match '^\s*Connection mode\s+:\s(.+)$' })
            if ($cm.Count) { $mode = ($cm[0] -replace '^\s*Connection mode\s+:\s', '').Trim() }
        } catch { $mode = "unreadable: $($_.Exception.Message)" }
        $ok = ($scope -eq 'all users') -and ($mode -match 'automatic')
        $reason = ''
        if ($scope -eq 'current user only') { $reason = 'per-user profile: connects only after that user signs in. Making it all-user needs the key re-entered (netsh wlan add profile user=all needs the profile XML with its key); not done by this script' }
        elseif ($scope -like 'label*' -or $mode -eq 'unknown') { $reason = 'netsh output not in English; read the values by hand' }
        elseif ($mode -notmatch 'automatic') { $reason = 'connection mode is not automatic: power-guard.ps1 -Action WifiAutoConnect -WifiProfile <name>' }
        $rows += [pscustomobject]@{ Category = 'wifi'; Item = $name; Property = 'scope / connection mode'; Value = "$scope / $mode"; Expected = 'all users / Connect automatically'; Status = $(if ($ok) { 'OK' } else { 'REVIEW' }); Reason = $reason }
    }
    return $rows
}

function Get-ServiceReport {
    <# Read-only: start type and state. Never changes or restarts a service. #>
    foreach ($n in $script:ServiceNames) {
        $s = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue)
        if (-not $s.Count -and $n -eq 'tvnserver') { $s = @(Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue | Where-Object { "$($_.PathName)" -match 'tvnserver\.exe' }) }
        if (-not $s.Count) { [pscustomobject]@{ Category = 'service'; Item = $n; Property = 'start / state'; Value = 'missing'; Expected = 'Auto / Running'; Status = 'MISSING'; Reason = 'service not installed (not fixed by this script)' }; continue }
        $v = "$($s[0].StartMode)$(if ($s[0].DelayedAutoStart) { ' (delayed)' }) / $($s[0].State)"
        $ok = $s[0].StartMode -eq 'Auto' -and $s[0].State -eq 'Running'
        [pscustomobject]@{ Category = 'service'; Item = $s[0].Name; Property = 'start / state'; Value = $v; Expected = 'Auto / Running'; Status = $(if ($ok) { 'OK' } else { 'REVIEW' }); Reason = $(if ($ok) { '' } else { 'not Automatic and Running; power settings do not fix this, and this script does not change services' }) }
    }
}

function Get-AdapterExpectation {
    <# What Verify expects of one adapter's checkbox. On AC: off. Otherwise: the saved original,
       but only while the guard owns the record; an unowned value (a person's own choice on
       battery) is never drift. #>
    param([string]$Source, $Record, $Enable)
    if ($Source -eq 'AC') { $want = $false }
    elseif ($Record -and $Record.phase -ne 'None') { $want = [bool]$Record.baseline }
    else { return [pscustomobject]@{ Want = '(not owned: left as it is)'; Status = 'OK' } }
    return [pscustomobject]@{ Want = $want; Status = $(if ("$Enable" -eq "$want") { 'OK' } else { 'DRIFT' }) }
}

function Get-VerifyReport {
    <# Every row the parent needs for a before/after table. No secrets. #>
    $rows = New-Object System.Collections.Generic.List[object]
    $add = { param($c, $i, $p, $v, $e, $s, $r) $rows.Add([pscustomobject]@{ Category = $c; Item = $i; Property = $p; Value = "$v"; Expected = "$e"; Status = $s; Reason = "$r" }) }
    $src = Get-PowerLineStatus
    & $add 'power' 'source' 'now' $src '' 'INFO' 'GetSystemPowerStatus at the time of this report'
    try {
        & $add 'power' 'active scheme' 'guid' (Get-ActiveSchemeGuid) '' 'INFO' ''
        foreach ($r in Invoke-SchemePass -ReadOnly) {
            & $add 'scheme' $r.Scheme "$($r.Setting) AC" $r.AcBefore $r.Target $r.Status $r.Reason
            if ($r.Setting -notin 'active scheme', 'setactive') { & $add 'scheme' $r.Scheme "$($r.Setting) DC" $r.DcBefore '(unchanged)' 'INFO' '' }
        }
        $ms = Test-ModernStandby -Text (Invoke-GuardNative powercfg.exe @('/a'))
        & $add 'power' 'powercfg /a' 'available' ($ms.Available -join '; ') '' 'INFO' $(if ($ms.S0) { 'Modern Standby (S0)' } else { 'no S0' })
    } catch { & $add 'scheme' '*' 'powercfg' '' '' 'ERROR' $_.Exception.Message }
    $state = $null
    try { $state = Read-GuardState } catch { & $add 'adapter' 'state' 'journal' '' '' 'ERROR' $_.Exception.Message }
    try {
        foreach ($m in Get-GuardAdapterMap) {
            $rec = $null
            if ($state -and (Test-HasProperty $state.adapters $m.Key)) { $rec = $state.adapters.($m.Key) }
            if ($m.Reason) { & $add 'adapter' $m.Name 'allow turn off' '' '' 'UNSUPPORTED' $m.Reason; continue }
            $x = Get-AdapterExpectation -Source $src -Record $rec -Enable $m.Enable
            & $add 'adapter' $m.Name 'allow turn off' $m.Enable $x.Want $x.Status "$($m.Medium); baseline $(if ($rec) { $rec.baseline } else { 'not recorded' }); phase $(if ($rec) { $rec.phase } else { '-' })"
        }
    } catch { & $add 'adapter' '*' 'allow turn off' '' '' 'ERROR' $_.Exception.Message }
    foreach ($w in Get-WifiProfileReport) { $rows.Add($w) }
    foreach ($s in Get-ServiceReport) { $rows.Add($s) }
    try {
        $t = Get-ScheduledTask -TaskName $script:PgTaskName -ErrorAction SilentlyContinue
        $p = @(Test-PowerGuardTask -Task $t -ScriptPath $script:PgScript)
        & $add 'task' $script:PgTaskName 'definition' $(if ($t) { "$($t.State)" } else { 'missing' }) 'Ready, SYSTEM, boot+hourly+event, battery allowed' $(if ($p.Count) { 'REVIEW' } else { 'OK' }) ($p -join '; ')
        if ($t) { $i = Get-ScheduledTaskInfo -TaskName $script:PgTaskName; & $add 'task' $script:PgTaskName 'last run / result' "$($i.LastRunTime) / $($i.LastTaskResult)" '0' 'INFO' '' }
        $k = Get-ScheduledTask -TaskName 'RiKeepAwake' -ErrorAction SilentlyContinue
        & $add 'task' 'RiKeepAwake' 'state' $(if ($k) { "$($k.State)" } else { 'missing' }) '' 'INFO' 'read only; not changed by this script'
    } catch { & $add 'task' $script:PgTaskName 'definition' '' '' 'ERROR' $_.Exception.Message }
    foreach ($f in $script:PgDir, $script:PgScript, $script:PgState, $script:PgLog) {
        if (-not (Test-Path -LiteralPath $f)) { & $add 'file' $f 'acl' 'missing' '' 'INFO' ''; continue }
        $bad = @(Test-PrivateAcl -Path $f -Folder:($f -eq $script:PgDir))
        & $add 'file' $f 'acl' $(if ($bad.Count) { $bad -join ', ' } else { 'SYSTEM+Administrators only' }) 'SYSTEM+Administrators only' $(if ($bad.Count) { 'REVIEW' } else { 'OK' }) ''
    }
    if (Test-Path -LiteralPath $script:PgLog) { & $add 'log' $script:PgLog 'first line' ((Get-Content -LiteralPath $script:PgLog -TotalCount 1) -join '') '' 'INFO' '' }
    return $rows
}

function Get-EventFieldMap {
    param([xml]$Xml)
    $h = [ordered]@{}
    foreach ($d in @($Xml.Event.EventData.Data)) { if ($d -and $d.Name) { $h[$d.Name] = $d.'#text' } }
    return $h
}

function Get-PowerEventLine {
    <# Human lines for Kernel-Power and Power-Troubleshooter events, oldest first. The power
       source of a sleep is named only from a Kernel-Power 105 event before it; otherwise
       "unknown". Never from the current power status. #>
    param([object[]]$Events, [string]$TimeZoneId)
    $lastAc = $null
    foreach ($e in @($Events | Sort-Object TimeCreated)) {
        $f = Get-EventFieldMap -Xml ([xml]$e.ToXml())
        $t = $e.TimeCreated
        $when = '{0} {1} (UTC {2})' -f $t.ToString('yyyy-MM-dd HH:mm:ss'), $TimeZoneId, $t.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        $fields = ($f.Keys | ForEach-Object { "$_=$($f[$_])" }) -join ' '
        $src = $(if ($lastAc) { "source $($lastAc.Source) per Kernel-Power 105 at $($lastAc.When)" } else { 'source unknown (no Kernel-Power 105 earlier in this window)' })
        $what = switch ($e.Id) {
            105 { 'power source change'; break }
            42 { 'entering sleep'; break }
            107 { 'resumed from sleep'; break }
            506 { 'entering Modern Standby'; break }
            507 { 'leaving Modern Standby'; break }
            1 { 'woke (Power-Troubleshooter)'; break }
            default { 'event' }
        }
        if ($e.Id -eq 105) {
            $ac = "$($f['AcOnline'])"
            $lastAc = [pscustomobject]@{ When = $when; Source = $(if ($ac -match '^(true|1)$') { 'AC' } elseif ($ac -match '^(false|0)$') { 'DC' } else { "unknown (AcOnline='$ac')" }) }
            "$when $($e.ProviderName) $($e.Id) $what $fields"
        } elseif ($e.Id -in 42, 506) {
            "$when $($e.ProviderName) $($e.Id) $what $fields; $src; reason code as logged (not interpreted)"
        } else { "$when $($e.ProviderName) $($e.Id) $what $fields" }
    }
}

function Invoke-PowerGuardDiagnose {
    param([string]$Dir, [int]$Days = 1)
    $tz = [TimeZoneInfo]::Local.Id
    $since = (Get-Date).Date.AddDays(1 - [Math]::Max(1, $Days))
    $rows = New-Object System.Collections.Generic.List[object]
    foreach ($r in Get-VerifyReport) { $rows.Add($r) }
    $add = { param($c, $i, $p, $v, $s, $r) $rows.Add([pscustomobject]@{ Category = $c; Item = $i; Property = $p; Value = "$v"; Expected = ''; Status = $s; Reason = "$r" }) }
    $events = @()
    foreach ($q in @(@{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = @(42, 105, 107, 506, 507); StartTime = $since },
                     @{ LogName = 'System'; ProviderName = 'Microsoft-Windows-Power-Troubleshooter'; Id = 1; StartTime = $since })) {
        try { $events += @(Get-WinEvent -FilterHashtable $q -ErrorAction Stop) } catch { & $add 'events' $q.ProviderName 'query' "since $since" 'INFO' $_.Exception.Message }
    }
    $xml = '<Events>' + (($events | Sort-Object TimeCreated | ForEach-Object { $_.ToXml() }) -join "`n") + '</Events>'
    [IO.File]::WriteAllText((Join-Path $Dir 'events.xml'), $xml, (New-Object Text.UTF8Encoding $false))
    $lines = @(Get-PowerEventLine -Events $events -TimeZoneId $tz)
    Set-Content -LiteralPath (Join-Path $Dir 'events.txt') -Value (@("events since $($since.ToString('yyyy-MM-dd HH:mm')) $tz") + $lines) -Encoding UTF8
    & $add 'events' 'Kernel-Power/Power-Troubleshooter' 'count' $events.Count 'INFO' "since $($since.ToString('yyyy-MM-dd HH:mm')) $tz; lines in events.txt"
    try {
        $ms = Test-ModernStandby -Text (Invoke-GuardNative powercfg.exe @('/a'))
        if ($ms.S0) { $rp = Join-Path $Dir 'sleepstudy.html'; Invoke-GuardNative powercfg.exe @('/sleepstudy', '/output', $rp, '/duration', "$([Math]::Max(1, $Days))") | Out-Null }
        else { $rp = Join-Path $Dir 'systempowerreport.html'; Invoke-GuardNative powercfg.exe @('/systempowerreport', '/output', $rp) | Out-Null }
        & $add 'report' 'powercfg' 'path' $rp 'INFO' 'in the private reports folder (SYSTEM+Administrators)'
    } catch { & $add 'report' 'powercfg' 'sleepstudy/systempowerreport' '' 'UNSUPPORTED' $_.Exception.Message }
    try { & $add 'power' 'wake timers' 'powercfg /waketimers' (((Invoke-GuardNative powercfg.exe @('/waketimers')) -split "`n" | Where-Object { $_.Trim() }) -join ' | ') 'INFO' '' } catch { & $add 'power' 'wake timers' 'powercfg /waketimers' '' 'ERROR' $_.Exception.Message }
    try { & $add 'power' 'requests' 'powercfg /requests' (((Invoke-GuardNative powercfg.exe @('/requests')) -split "`n" | Where-Object { $_.Trim() }) -join ' | ') 'INFO' '' } catch { & $add 'power' 'requests' 'powercfg /requests' '' 'ERROR' $_.Exception.Message }
    # Power mode (slider) overlay, read only.
    $ov = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes' -ErrorAction SilentlyContinue
    foreach ($n in 'ActiveOverlayAcPowerScheme', 'ActiveOverlayDcPowerScheme') { & $add 'power' 'power mode' $n $(if ($ov -and (Test-HasProperty $ov $n)) { $ov.$n } else { 'not set' }) 'INFO' 'Windows power mode overlay (read only)' }
    # Group Policy power settings, read only.
    $gp = 'HKLM:\SOFTWARE\Policies\Microsoft\Power\PowerSettings'
    if (Test-Path $gp) {
        foreach ($k in @(Get-ChildItem -Path $gp -Recurse -ErrorAction SilentlyContinue)) {
            $p = Get-ItemProperty -Path $k.PSPath
            foreach ($n in 'ACSettingIndex', 'DCSettingIndex') { if (Test-HasProperty $p $n) { & $add 'policy' $k.PSChildName $n $p.$n 'REVIEW' 'a power policy overrides the scheme value' } }
        }
    } else { & $add 'policy' 'power' 'PowerSettings' 'none' 'INFO' 'no power group policy' }
    # Windows Update, read only.
    $ux = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings' -ErrorAction SilentlyContinue
    foreach ($n in 'ActiveHoursStart', 'ActiveHoursEnd', 'IsActiveHoursEnabled', 'SmartActiveHoursState') { & $add 'update' 'UX settings' $n $(if ($ux -and (Test-HasProperty $ux $n)) { $ux.$n } else { 'not set' }) 'INFO' '' }
    foreach ($k in 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU') {
        $p = Get-ItemProperty -Path $k -ErrorAction SilentlyContinue
        if ($p) { foreach ($prop in @($p.PSObject.Properties | Where-Object { $_.Name -notlike 'PS*' })) { & $add 'update' (Split-Path $k -Leaf) $prop.Name $prop.Value 'INFO' 'policy (read only)' } }
    }
    # Lenovo Vantage / power manager presence. Their settings are not documented; reported as opaque.
    try {
        $apps = @(Get-AppxPackage -AllUsers -ErrorAction Stop | Where-Object { $_.Name -match '^E046963F\.(LenovoCompanion|LenovoSettingsforEnterprise)' })
        & $add 'vendor' 'Lenovo Vantage' 'app' $(if ($apps.Count) { ($apps | ForEach-Object { "$($_.Name) $($_.Version)" }) -join ', ' } else { 'not installed' }) 'INFO' $(if ($apps.Count) { 'settings (battery/always-on USB/smart standby) are not documented or readable here; check in the app with Ri' } else { '' })
    } catch { & $add 'vendor' 'Lenovo Vantage' 'app' '' 'UNSUPPORTED' "Get-AppxPackage: $($_.Exception.Message)" }
    foreach ($n in 'ImControllerService', 'LenovoVantageService', 'LITSSVC', 'Power Manager') {
        $s = @(Get-CimInstance -ClassName Win32_Service -Filter "Name='$n'" -ErrorAction SilentlyContinue)
        & $add 'vendor' $n 'service' $(if ($s.Count) { "$($s[0].StartMode) / $($s[0].State)" } else { 'not installed' }) 'INFO' ''
    }
    return $rows
}

function Write-Report {
    <# JSON + CSV in a private folder, table on the console. #>
    param($Rows, [string]$Dir, [string]$Name)
    $Rows | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $Dir "$Name.json") -Encoding UTF8
    $Rows | Export-Csv -LiteralPath (Join-Path $Dir "$Name.csv") -NoTypeInformation -Encoding UTF8
    $Rows | Format-Table -AutoSize -Wrap Category, Item, Property, Value, Expected, Status, Reason | Out-String -Width 250 | Out-Host
    Write-Host "report: $(Join-Path $Dir "$Name.json") and .csv"
}

function Compare-PowerGuardReport {
    <# One row per Category/Item/Property with the value before and after. #>
    param([string]$BeforePath, [string]$AfterPath)
    $b = @(Get-Content -LiteralPath $BeforePath -Raw | ConvertFrom-Json)
    $a = @(Get-Content -LiteralPath $AfterPath -Raw | ConvertFrom-Json)
    $key = { param($r) "$($r.Category)|$($r.Item)|$($r.Property)" }
    $bm = @{}; foreach ($r in $b) { $bm[(& $key $r)] = $r }
    $am = @{}; foreach ($r in $a) { $am[(& $key $r)] = $r }
    foreach ($k in @(@($bm.Keys) + @($am.Keys) | Select-Object -Unique | Sort-Object)) {
        $x = $bm[$k]; $y = $am[$k]; $parts = $k -split '\|', 3
        [pscustomobject]@{ Category = $parts[0]; Item = $parts[1]; Property = $parts[2]
            Before = $(if ($x) { $x.Value } else { '(absent)' }); After = $(if ($y) { $y.Value } else { '(absent)' })
            Changed = (-not $x) -or (-not $y) -or ("$($x.Value)" -ne "$($y.Value)"); StatusAfter = $(if ($y) { $y.Status } else { '' }) }
    }
}

function Assert-PrivateReportDir {
    <# A report folder (made if missing) must not be a link and must allow only SYSTEM and
       Administrators, so event XML and power reports stay private. #>
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }
    if ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$Path is a link or junction; no report written" }
    $bad = @(Test-PrivateAcl -Path $Path)
    if ($bad.Count) { throw "$Path is not private to SYSTEM and Administrators ($($bad -join ', ')); no report written" }
}

function New-ReportDir {
    param([string]$Name)
    if (-not (Test-Path -LiteralPath $script:PgDir)) { throw "$($script:PgDir) does not exist; run -Action Install or setup.ps1 first (reports are kept there, private)" }
    Assert-PrivateReportDir -Path $script:PgReports
    $d = Join-Path $script:PgReports "$Name-$([DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ'))"
    Assert-PrivateReportDir -Path $d
    return $d
}

function Invoke-PowerGuard {
    switch ($Action) {
        'Apply' { $out = @(Invoke-PowerGuardApply); return [int]$out[-1] }
        default { return 1 }
        'Install' { try { Write-Host "PASS: $(Install-PowerGuard)"; return 0 } catch { Write-Host "FAIL: $($_.Exception.Message)"; return 1 } }
        'Verify' { $d = $(if ($OutDir) { Assert-PrivateReportDir -Path $OutDir; $OutDir } else { New-ReportDir 'verify' }); Write-Report -Rows (Get-VerifyReport) -Dir $d -Name 'verify'; return 0 }
        'Diagnose' { $d = $(if ($OutDir) { Assert-PrivateReportDir -Path $OutDir; $OutDir } else { New-ReportDir 'diagnose' }); Write-Report -Rows (Invoke-PowerGuardDiagnose -Dir $d -Days $Days) -Dir $d -Name 'diagnose'; return 0 }
        'Compare' {
            $rows = @(Compare-PowerGuardReport -BeforePath $Before -AfterPath $After)
            $d = $(if ($OutDir) { $OutDir } else { Split-Path -Parent $After })
            $rows | Export-Csv -LiteralPath (Join-Path $d 'compare.csv') -NoTypeInformation -Encoding UTF8
            $rows | Format-Table -AutoSize -Wrap | Out-String -Width 250 | Out-Host
            return 0
        }
        'WifiAutoConnect' {
            if (-not $WifiProfile) { Write-Host 'FAIL: -WifiProfile is required'; return 1 }
            Invoke-GuardNative netsh.exe @('wlan', 'set', 'profileparameter', "name=$WifiProfile", 'connectionmode=auto') | Out-Null
            $r = @(Get-WifiProfileReport | Where-Object { $_.Item -eq $WifiProfile })
            if (-not $r.Count) { Write-Host "FAIL: profile $WifiProfile not listed after the change"; return 1 }
            $r | Format-List | Out-String | Out-Host
            return 0
        }
    }
}

# Dot-sourcing (setup.ps1, tests) loads the functions only.
if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-PowerGuard) }
