<#
  Runs at every startup as SYSTEM from the scheduled task RiLaptop-BootProbe, before anyone
  signs in. Waits 3 minutes, then appends one JSON line to
  C:\ProgramData\RiLaptop\boot-probe.jsonl: boot time, whether anyone was signed in, and the
  state of each remote-access service. verify-reboot.ps1 reads it.
#>
param([int]$WaitSeconds = 180)

. (Join-Path $PSScriptRoot 'vnc-common.ps1')

function Get-BootProbeRecord {
    $os = Get-CimInstance Win32_OperatingSystem
    $names = @('Tailscale', 'sshd', 'RustDesk')
    $st = Get-CimInstance Win32_Service | Where-Object { $_.PathName -like '*syncthing*' -or $_.Name -like 'syncthing*' } | Select-Object -First 1
    if ($st) { $names += $st.Name }
    $names += 'iphlpsvc'
    $services = @{}
    foreach ($n in $names) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if ($s) { $services[$n] = @{ Status = "$($s.Status)"; StartType = "$($s.StartType)" } } else { $services[$n] = $null }
    }
    # TightVNC is found by its program and recorded as "TightVNC", whatever its service name.
    $vnc = $null
    try { $vnc = Find-VncService } catch { $vnc = $null }
    $s = if ($vnc) { Get-Service -Name $vnc.Name -ErrorAction SilentlyContinue } else { $null }
    $services['TightVNC'] = if ($s) { @{ Status = "$($s.Status)"; StartType = "$($s.StartType)" } } else { $null }
    # Someone signed in means a desktop shell (explorer.exe) owned by a real user. The sign-in
    # screen has its own "interactive" logon sessions (DWM-*, UMFD-*), so logon sessions alone
    # would count no-one as someone.
    $owners = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object {
        $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
        if ($o.ReturnValue -eq 0 -and $o.Domain -notin @('Window Manager', 'Font Driver Host')) { "$($o.Domain)\$($o.User)" }
    } | Sort-Object -Unique)
    $interactive = $owners.Count
    $explorer = @(Get-Process -Name explorer -ErrorAction SilentlyContinue).Count
    $ts = $null
    $exe = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
    if (Test-Path $exe) {
        try { $ts = ((& $exe status --json 2>$null | Out-String) | ConvertFrom-Json).BackendState } catch { $ts = 'unknown' }
    }
    # Screen access: the same listener and password checks setup ends with.
    $vncProblems = @()
    try {
        $state = Read-VncState
        if (-not $state) { $vncProblems += 'no vnc.json (setup did not finish the VNC steps)' }
        else {
            $vncProblems += @(Test-VncAccess -TailscaleIPv4 "$($state.TailscaleIPv4)")
        }
    } catch { $vncProblems += "check failed: $($_.Exception.Message)" }
    return [ordered]@{
        probe_utc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        boot_utc = $os.LastBootUpTime.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
        interactive_sessions = $interactive
        explorer_processes = $explorer
        tailscale_backend = $ts
        services = $services
        vnc_problems = @($vncProblems)
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Start-Sleep -Seconds $WaitSeconds
    # Let the VNC guard finish first (it may wait for Tailscale or restart IP Helper): wait up
    # to 6 more minutes for a guard line written after this boot.
    $boot = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime.ToUniversalTime()
    $guardLog = Join-Path $env:ProgramData 'RiLaptop\vnc-guard.jsonl'
    $until = (Get-Date).AddMinutes(6)
    while ((Get-Date) -lt $until) {
        $last = if (Test-Path $guardLog) { Get-Content $guardLog -Tail 1 } else { $null }
        $t = $null
        if ($last) { try { $t = [DateTime]::Parse((($last | ConvertFrom-Json).guard_utc).ToString(), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AdjustToUniversal, AssumeUniversal') } catch { $t = $null } }
        if ($t -and $t -ge $boot) { break }
        Start-Sleep -Seconds 15
    }
    $rec = Get-BootProbeRecord
    $path = Join-Path $env:ProgramData 'RiLaptop\boot-probe.jsonl'
    Add-Content -Path $path -Value ($rec | ConvertTo-Json -Compress -Depth 4) -Encoding UTF8
}
