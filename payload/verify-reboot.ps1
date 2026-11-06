<#
  After a reboot with no one signed in, run this (e.g. over ssh once ssh works, or as
  administrator) to see whether every remote-access service came up on its own.
  Reads the newest line of C:\ProgramData\RiLaptop\boot-probe.jsonl. Exit 0 = PASS.
#>
param([string]$Path = (Join-Path $env:ProgramData 'RiLaptop\boot-probe.jsonl'), [switch]$RequireRustDesk)

function ConvertTo-Utc {
    <# PowerShell 7 turns ISO dates from JSON into DateTime; 5.1 keeps strings. Accept both. #>
    param($Value)
    if ($Value -is [DateTime]) { return $Value.ToUniversalTime() }
    return [DateTime]::Parse("$Value", [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal')
}

function Test-BootProbeRecord {
    param($Record, [bool]$RequireRustDesk, [string]$CurrentBootUtc)
    $problems = @()
    if ($CurrentBootUtc) {
        $diff = [Math]::Abs(((ConvertTo-Utc $Record.boot_utc) - (ConvertTo-Utc $CurrentBootUtc)).TotalMinutes)
        if ($diff -gt 2) { $problems += "the newest probe is from an earlier boot ($($Record.boot_utc)); the probe did not run after this boot ($CurrentBootUtc)" }
    }
    if ($Record.interactive_sessions -gt 0 -or $Record.explorer_processes -gt 0) {
        $problems += 'someone was signed in when the probe ran, so this boot does not prove no-login start'
    }
    $need = @('Tailscale', 'sshd', 'iphlpsvc', 'TightVNC')
    if (-not ($Record.PSObject.Properties.Name -contains 'vnc_problems')) { $problems += 'probe has no VNC check (old boot-probe.ps1?)' }
    else { foreach ($p in @($Record.vnc_problems)) { if ("$p") { $problems += "VNC: $p" } } }
    if ($RequireRustDesk) { $need += 'RustDesk' }
    $names = @($Record.services.PSObject.Properties.Name)
    $sync = $names | Where-Object { $_ -like '*syncthing*' }
    if (-not $sync) { $problems += 'no Syncthing service recorded' } else { $need += $sync }
    foreach ($n in $need) {
        $s = if ($names -contains $n) { $Record.services.$n } else { $null }
        if (-not $s) { $problems += "${n}: not installed"; continue }
        if ($s.Status -ne 'Running' -or $s.StartType -ne 'Automatic') { $problems += "${n}: $($s.Status)/$($s.StartType)" }
    }
    if ($Record.tailscale_backend -ne 'Running') { $problems += "Tailscale backend: $($Record.tailscale_backend)" }
    return $problems
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not (Test-Path $Path)) { Write-Host 'FAIL: no boot probe yet. Reboot, do not sign in, wait 12 minutes.'; exit 1 }
    $last = Get-Content $Path | Where-Object { $_.Trim() } | Select-Object -Last 1
    $rec = $last | ConvertFrom-Json
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    $problems = @(Test-BootProbeRecord -Record $rec -RequireRustDesk $RequireRustDesk.IsPresent -CurrentBootUtc $boot)
    if ($problems.Count) {
        Write-Host "FAIL (boot $($rec.boot_utc), probe $($rec.probe_utc)):"
        $problems | ForEach-Object { Write-Host "  $_" }
        exit 1
    }
    Write-Host "PASS: boot $($rec.boot_utc); with no one signed in, all remote-access services were Automatic and Running at $($rec.probe_utc)"
    exit 0
}
