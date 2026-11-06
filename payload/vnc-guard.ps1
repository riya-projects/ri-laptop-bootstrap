<#
  Runs at every startup as SYSTEM from the scheduled task RiLaptop-VncGuard, before anyone
  signs in. Waits (up to $WaitSeconds) for Tailscale to have an IPv4 address, then:
    - same address as setup recorded in vnc.json and the proxy table as setup left it: runs
      every VNC check (listeners, password handshake on loopback and on 5900); if one fails,
      restarts IP Helper once (the address may have come up after it) and re-checks for up to
      30 seconds;
    - different address, none, TightVNC disabled (off switch), a changed proxy table, or a
      check still failing: deletes the VNC port proxy and disables the VNC firewall rule, so the screen is
      not reachable on any other address. Run setup.ps1 again to use the new address.
  Appends one JSON line to C:\ProgramData\RiLaptop\vnc-guard.jsonl.
#>
param([int]$WaitSeconds = 300, [int]$SettleSeconds = 30)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'vnc-common.ps1')

function Invoke-VncGuard {
    param([int]$WaitSeconds, [int]$SettleSeconds = 30)
    $state = Read-VncState
    $recorded = if ($state -and ($state.PSObject.Properties.Name -contains 'TailscaleIPv4')) { "$($state.TailscaleIPv4)" } else { '' }
    $notes = @()
    # The off switch wins: with TightVNC disabled or missing, only close.
    $vnc = $null
    try { $vnc = Find-VncService } catch { $vnc = $null; $notes += 'could not read services' }
    $off = (-not $vnc) -or ("$($vnc.StartMode)" -eq 'Disabled')
    $current = ''
    if (-not $off) {
        $deadline = (Get-Date).AddSeconds($WaitSeconds)
        do {
            try { $current = Get-TailscaleIPv4 } catch { $current = '' }
            if ($current) { break }
            Start-Sleep -Seconds 10
        } while ((Get-Date) -lt $deadline)
    }
    $action = if ($off) { 'remove' } else { Get-VncGuardAction -Recorded $recorded -Current $current }
    if ($action -eq 'ok') {
        # tvnserver may start after Tailscale: give its service up to a minute to be Running.
        $until = (Get-Date).AddSeconds(60)
        while ((Get-Date) -lt $until) {
            $st = $null
            try { $st = Get-Service -Name $vnc.Name -ErrorAction Stop } catch { $st = $null }
            if ($st -and "$($st.Status)" -eq 'Running') { break }
            Start-Sleep -Seconds 5
        }
    }
    if ($action -eq 'ok') {
        try {
            if (@(Get-VncProxyProblem -Rows @(Get-VncPortProxy) -TailscaleIPv4 $recorded).Count) {
                # Something other than setup changed the table: fail closed, never repair it.
                $action = 'remove'; $notes += 'port proxy table was not as setup left it'
            } else {
                $problems = @(Test-VncAccess -TailscaleIPv4 $recorded)
                if ($problems.Count) {
                    # The address may have come up after IP Helper started: restart it once and
                    # give everything up to $SettleSeconds to come right.
                    Restart-Service -Name iphlpsvc -Force
                    $notes += 'restarted IP Helper'
                    $until = (Get-Date).AddSeconds($SettleSeconds)
                    do {
                        Start-Sleep -Seconds 3
                        $problems = @(Test-VncAccess -TailscaleIPv4 $recorded)
                    } while ($problems.Count -and (Get-Date) -lt $until)
                    if ($problems.Count) { $action = 'remove'; $notes += $problems }
                }
            }
        } catch { $action = 'remove'; $notes += "check failed: $($_.Exception.Message)" }
    }
    if ($action -eq 'remove') {
        $c = Close-VncAccess
        $notes += $c.Notes
        if (-not $c.Complete) { $action = 'remove-incomplete' }
    }
    return [ordered]@{
        guard_utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        recorded_ip = $recorded
        current_ip = $current
        action = $action
        detail = ($notes -join '; ')
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    $rec = Invoke-VncGuard -WaitSeconds $WaitSeconds -SettleSeconds $SettleSeconds
    Add-Content -Path (Join-Path $script:VncDataDir 'vnc-guard.jsonl') -Value ($rec | ConvertTo-Json -Compress) -Encoding UTF8
}
