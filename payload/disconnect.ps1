<#
  "Disconnect remote access": the desktop shortcut runs this. It asks for administrator
  rights, then stops Tailscale, SSH, TightVNC and RustDesk and sets them to Disabled, so
  remote access stays off after a restart too. It also deletes the VNC port proxy (the
  only listener on the Tailscale address for the screen) and disables its firewall rule.
  Quitting the Tailscale app is not enough while Run unattended is on.

  It also disables the Syncthing inbound rule (TCP 22000 from Tailscale). The Syncthing
  service keeps running (it gives no remote access to the laptop), but the hub reaches it only
  over Tailscale on that port, so notes stop syncing until setup.ps1 runs again.
  Withdrawing yes #4 (notes) is a separate step: Services > Syncthing > Stop and Disabled.

  To reconnect, run setup.ps1 again as administrator; it sets Tailscale and sshd back to
  Automatic, TightVNC and its proxy back on (and RustDesk when -RustDeskPassword is given again).
#>
param([switch]$NoPause)

. (Join-Path $PSScriptRoot 'vnc-common.ps1')

$script:RemoteServices = @('Tailscale', 'sshd', 'tvnserver', 'RustDesk')

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Disable-RemoteAccess {
    $report = @()
    # The TightVNC service is found by its program, in case its name differs.
    $names = @($script:RemoteServices)
    try { $v = Find-VncService; if ($v -and $names -notcontains $v.Name) { $names = @($names | Where-Object { $_ -ne 'tvnserver' }) + $v.Name } } catch { Write-Verbose 'no CIM' }
    foreach ($name in $names) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { $report += "${name}: not installed"; continue }
        try {
            Set-Service -Name $name -StartupType Disabled -ErrorAction Stop
            if ($svc.Status -ne 'Stopped') { Stop-Service -Name $name -Force -ErrorAction Stop }
        } catch { $report += "${name}: ERROR $($_.Exception.Message)" }
        $svc = Get-Service -Name $name
        $report += "${name}: $($svc.Status), start type $($svc.StartType)"
    }
    # The RustDesk window process can hold a session open after its service stops; the same
    # for a tvnserver started in application mode.
    Get-Process -Name 'rustdesk', 'tvnserver' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    # Proxy entries (all tables), the allow rule and any 5900 socket left, each read back.
    $c = Close-VncAccess
    if ($c.Complete) { $report += 'VNC port proxy and rule: closed' } else { $report += "VNC port proxy and rule: ERROR $($c.Notes -join '; ')" }
    # Syncthing's inbound rule: the service stays (notes are yes #4, not remote access).
    $label = "Syncthing inbound rule (TCP $($script:SyncthingPort))"
    try {
        if (Get-NetFirewallRule -Name $script:SyncthingFirewallRule -ErrorAction SilentlyContinue) {
            Disable-NetFirewallRule -Name $script:SyncthingFirewallRule -ErrorAction Stop
            if ("$((Get-NetFirewallRule -Name $script:SyncthingFirewallRule -ErrorAction Stop).Enabled)" -ne 'False') { throw 'still enabled' }
            $report += "${label}: disabled"
        } else { $report += "${label}: not present" }
    } catch { $report += "${label}: ERROR $($_.Exception.Message)" }
    return $report
}

function Test-RemoteAccessOff {
    <# Every service is either not installed, or Stopped and Disabled. #>
    param([string[]]$Report)
    foreach ($line in $Report) {
        if ($line -notmatch ': not installed$' -and $line -notmatch ': Stopped, start type Disabled$' -and
            $line -ne 'VNC port proxy and rule: closed' -and $line -notmatch '^Syncthing inbound rule \(TCP \d+\): (disabled|not present)$') { return $false }
    }
    return $true
}

if ($MyInvocation.InvocationName -ne '.') {
    if (-not (Test-IsAdmin)) {
        Start-Process -FilePath 'powershell.exe' -Verb RunAs -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$PSCommandPath`"")
        exit 0
    }
    $lines = Disable-RemoteAccess
    $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
    try { Add-Content -Path (Join-Path $env:ProgramData 'RiLaptop\setup-log.txt') -Value "$stamp disconnect: $($lines -join '; ')" } catch { Write-Verbose 'could not write log' }
    if (Test-RemoteAccessOff -Report $lines) { Write-Host 'Remote access is off.' -ForegroundColor Green }
    else { Write-Host 'Remote access is NOT fully off. Restart the laptop, or tell Elara.' -ForegroundColor Red }
    $lines | ForEach-Object { Write-Host "  $_" }
    Write-Host 'Syncthing (notes) is still running, but notes stop syncing: the hub can no longer reach it. To turn remote access and note sync back on, run setup.ps1 as administrator.'
    if (-not $NoPause) { Read-Host 'Press Enter to close' | Out-Null }
    if (-not (Test-RemoteAccessOff -Report $lines)) { exit 1 }
}
