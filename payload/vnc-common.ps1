<#
  Shared TightVNC helpers, dot-sourced by setup.ps1, vnc-guard.ps1, disconnect.ps1 and
  boot-probe.ps1 (copies live in C:\ProgramData\RiLaptop).

  TightVNC documents no setting that binds its listener to one network interface (its MSI
  guide lists LOOPBACKONLY, RFBPORT and the rest, but no listen address). So:
    - tvnserver listens on loopback only, port 5901 (LOOPBACKONLY=1, ALLOWLOOPBACK=1);
    - Windows' own port proxy (netsh interface portproxy, IP Helper service) listens on the
      laptop's Tailscale IPv4 only, port 5900, and forwards to 127.0.0.1:5901;
    - the firewall allows 5900 only to that local address and only from 100.64.0.0/10.
  If the Tailscale address changes, vnc-guard.ps1 removes the proxy (fails closed) until
  setup.ps1 is run again.
#>

$script:VncPublicPort = 5900
$script:VncInternalPort = 5901
$script:VncHttpPort = 5800
$script:VncFirewallRule = 'RiLaptop-VNC-Tailnet'
# Syncthing (TCP 22000) from the tailnet only: the hub dials the laptop, never the other way.
$script:SyncthingFirewallRule = 'RiLaptop-Syncthing-Tailnet'
$script:SyncthingPort = 22000
$script:VncBlockRule = 'RiLaptop-VNC-Block-Direct'
$script:VncDataDir = Join-Path $env:ProgramData 'RiLaptop'
$script:VncStateFile = Join-Path $script:VncDataDir 'vnc.json'
$script:VncExeName = 'tvnserver.exe'
$script:PortProxyKinds = @('v4tov4', 'v4tov6', 'v6tov4', 'v6tov6')

function Test-InCgnat {
    <# True if a dotted IPv4 address is inside Tailscale's 100.64.0.0/10. #>
    param([string]$Address)
    $ip = $null
    if (-not [Net.IPAddress]::TryParse($Address, [ref]$ip) -or $ip.AddressFamily -ne 'InterNetwork') { return $false }
    if ($ip.ToString() -ne $Address) { return $false }
    $b = $ip.GetAddressBytes()
    return ($b[0] -eq 100 -and $b[1] -ge 64 -and $b[1] -le 127)
}

function Select-TailscaleIPv4 {
    <# The one IPv4 address from `tailscale ip -4` output; throws unless it is exactly one
       address inside 100.64.0.0/10. #>
    param([string]$Text)
    $lines = @(("$Text" -replace "`r", '') -split "`n" | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($lines.Count -ne 1) { throw "expected one Tailscale IPv4 address, got $($lines.Count)" }
    if (-not (Test-InCgnat $lines[0])) { throw "'$($lines[0])' is not a Tailscale IPv4 address (100.64.0.0/10)" }
    return $lines[0]
}

function ConvertFrom-PortProxyShow {
    <# Rows of `netsh interface portproxy show <kind>`. Header lines are translated on
       non-English Windows, so only rows of address, port, address, port are read. #>
    param([string]$Text, [string]$Kind = 'v4tov4')
    foreach ($line in (("$Text" -replace "`r", '') -split "`n")) {
        if ($line -match '^\s*(\S+)\s+(\d+)\s+(\S+)\s+(\d+)\s*$') {
            [pscustomobject]@{ Kind = $Kind; ListenAddress = $Matches[1]; ListenPort = [int]$Matches[2]; ConnectAddress = $Matches[3]; ConnectPort = [int]$Matches[4] }
        }
    }
}

function Test-VncProxyRow {
    <# True for any port proxy entry (any of the four tables) that listens on 5900 or forwards to 5901. #>
    param($Row)
    return ($Row.ListenPort -eq $script:VncPublicPort -or $Row.ConnectPort -eq $script:VncInternalPort)
}

function Get-VncProxyProblem {
    <# Problems with the port proxy table: exactly one 5900 entry, on the Tailscale address,
       to 127.0.0.1:5901, and nothing else forwarding to 5901. #>
    param([object[]]$Rows, [string]$TailscaleIPv4)
    $problems = @()
    $ours = @($Rows | Where-Object { $_.ListenPort -eq $script:VncPublicPort })
    $toVnc = @($Rows | Where-Object { $_.ConnectPort -eq $script:VncInternalPort -and $_.ListenPort -ne $script:VncPublicPort })
    foreach ($r in $ours) {
        if ($r.ListenAddress -ne $TailscaleIPv4 -or "$($r.Kind)" -ne 'v4tov4') { $problems += "port proxy ($($r.Kind)) listens on $($r.ListenAddress):$($r.ListenPort), not only on $TailscaleIPv4" }
        elseif ($r.ConnectAddress -ne '127.0.0.1' -or $r.ConnectPort -ne $script:VncInternalPort) { $problems += "port proxy on ${TailscaleIPv4}:5900 goes to $($r.ConnectAddress):$($r.ConnectPort), not 127.0.0.1:5901" }
    }
    if (-not @($ours | Where-Object { $_.ListenAddress -eq $TailscaleIPv4 -and "$($_.Kind)" -eq 'v4tov4' })) { $problems += "no port proxy on ${TailscaleIPv4}:5900" }
    foreach ($r in $toVnc) { $problems += "another port proxy ($($r.ListenAddress):$($r.ListenPort)) forwards to 5901" }
    return $problems
}

function Get-VncListenerProblem {
    <# Given TCP listeners (LocalAddress, LocalPort, Process), check that tvnserver listens only
       on loopback 5901, that 5900 is open only on the Tailscale address, and that nothing
       listens on the web viewer port 5800. #>
    param([object[]]$Listeners, [string]$TailscaleIPv4)
    $problems = @()
    $loop = @('127.0.0.1', '::1')
    $vnc = @($Listeners | Where-Object { "$($_.Process)" -match '^tvnserver(\.exe)?$' })
    foreach ($l in $vnc) {
        if ($l.LocalPort -ne $script:VncInternalPort) { $problems += "tvnserver also listens on $($l.LocalAddress):$($l.LocalPort)" }
        elseif ($loop -notcontains "$($l.LocalAddress)") { $problems += "tvnserver listens on $($l.LocalAddress):5901, not loopback only" }
    }
    if (-not @($vnc | Where-Object { $_.LocalPort -eq $script:VncInternalPort })) { $problems += 'tvnserver is not listening on 127.0.0.1:5901' }
    foreach ($l in @($Listeners | Where-Object { $_.LocalPort -eq $script:VncInternalPort -and "$($_.Process)" -notmatch '^tvnserver(\.exe)?$' })) {
        $problems += "$($l.Process) also listens on $($l.LocalAddress):5901"
    }
    $pub = @($Listeners | Where-Object { $_.LocalPort -eq $script:VncPublicPort })
    foreach ($l in $pub) { if ("$($l.LocalAddress)" -ne $TailscaleIPv4) { $problems += "5900 is open on $($l.LocalAddress), not only on $TailscaleIPv4" } }
    if (-not @($pub | Where-Object { "$($_.LocalAddress)" -eq $TailscaleIPv4 })) { $problems += "nothing listens on ${TailscaleIPv4}:5900" }
    foreach ($l in @($Listeners | Where-Object { $_.LocalPort -eq $script:VncHttpPort })) { $problems += "web viewer port 5800 is open on $($l.LocalAddress) ($($l.Process))" }
    return $problems
}

function Get-RfbSecurityProblem {
    <# Reads an RFB 3.8 security-type list (the count byte, then the types). Every way in must
       need the VNC password: "None" (1) fails, and so does any type other than VNC
       authentication (2) and Tight (16). Tight (16) wraps its own list of auth methods, so
       when it is offered, $TightAuth (from Read-TightAuthCode) must be exactly VNC auth. #>
    param([byte[]]$Bytes, [object]$TightAuth = $null)
    # Not `-not $Bytes`: a one-byte array holding 0 would count as empty.
    if ($null -eq $Bytes -or $Bytes.Count -lt 1) { return @('no security types received') }
    $n = [int]$Bytes[0]
    if ($n -eq 0) { return @('server refused the connection') }
    if ($Bytes.Count -lt 1 + $n) { return @('short security type list') }
    $types = @($Bytes[1..$n] | ForEach-Object { [int]$_ })
    $problems = @()
    if ($types -contains 1) { $problems += 'VNC offers connections without a password (security type None)' }
    $other = @($types | Where-Object { $_ -ne 1 -and $_ -ne 2 -and $_ -ne 16 })
    if ($other.Count) { $problems += "VNC offers security types this check cannot confirm: $($other -join ',')" }
    if ($types -contains 16) {
        if ($null -eq $TightAuth) { $problems += 'Tight security offered but its auth methods were not read' }
        else {
            $codes = @($TightAuth | ForEach-Object { [int]$_ })
            if ($codes.Count -eq 0) { $problems += 'Tight security needs no authentication' }
            elseif (@($codes | Where-Object { $_ -ne 2 }).Count) { $problems += "Tight security offers auth methods other than the VNC password: $($codes -join ',')" }
        }
    }
    if ($types -notcontains 2 -and $types -notcontains 16) { $problems += "VNC password authentication not offered (types: $($types -join ','))" }
    return $problems
}

function ConvertFrom-BigEndian {
    param([byte[]]$Bytes, [int]$Offset)
    return ([int64]$Bytes[$Offset] -shl 24) -bor ([int64]$Bytes[$Offset + 1] -shl 16) -bor ([int64]$Bytes[$Offset + 2] -shl 8) -bor [int64]$Bytes[$Offset + 3]
}

function Read-Exactly {
    param($Stream, [int]$Count)
    $buf = New-Object byte[] $Count
    $got = 0
    while ($got -lt $Count) { $r = $Stream.Read($buf, $got, $Count - $got); if ($r -le 0) { throw 'connection closed' }; $got += $r }
    return , $buf
}

function Read-TightAuthCode {
    <# After choosing Tight (16): the server lists tunnel types (count, then 16-byte
       capabilities); with any listed we choose 0 (no tunnel). Then it lists auth methods the
       same way; each capability starts with its 4-byte code (1 None, 2 VNC). Returns the codes. #>
    param($Stream)
    $nt = ConvertFrom-BigEndian (Read-Exactly $Stream 4) 0
    if ($nt -gt 64) { throw "implausible tunnel count $nt" }
    if ($nt -gt 0) {
        Read-Exactly $Stream (16 * $nt) | Out-Null
        $zero = [byte[]](0, 0, 0, 0)
        $Stream.Write($zero, 0, 4)
    }
    $na = ConvertFrom-BigEndian (Read-Exactly $Stream 4) 0
    if ($na -gt 64) { throw "implausible auth count $na" }
    $codes = @()
    for ($i = 0; $i -lt $na; $i++) { $cap = Read-Exactly $Stream 16; $codes += ConvertFrom-BigEndian $cap 0 }
    return , $codes
}

function Test-RfbEndpoint {
    <# Connects, does the RFB 3.8 greeting and reads the security types (and Tight's auth
       list when Tight is offered), then hangs up before authenticating. Returns a list of
       problems (empty = every way in needs the password). #>
    param([string]$Address, [int]$Port, [int]$TimeoutMs = 5000)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($Address, $Port)
        if (-not $task.Wait($TimeoutMs)) { return @("no answer from ${Address}:$Port") }
        $s = $client.GetStream()
        $s.ReadTimeout = $TimeoutMs
        $greeting = [Text.Encoding]::ASCII.GetString((Read-Exactly $s 12))
        if ($greeting -notmatch '^RFB 003\.\d{3}\n$') { return @("${Address}:$Port is not a VNC server") }
        $reply = [Text.Encoding]::ASCII.GetBytes("RFB 003.008`n")
        $s.Write($reply, 0, $reply.Length)
        $first = (Read-Exactly $s 1)[0]
        $list = [byte[]](@($first) + @($(if ($first -gt 0) { Read-Exactly $s $first })))
        $tight = $null
        if ($first -gt 0 -and @($list[1..$first]) -contains 16 -and @($list[1..$first]) -notcontains 1) {
            $s.Write([byte[]](16), 0, 1)
            $tight = Read-TightAuthCode -Stream $s
        }
        return @(Get-RfbSecurityProblem -Bytes $list -TightAuth $tight | ForEach-Object { "${Address}:${Port}: $_" })
    } catch {
        return @("${Address}:${Port}: $($_.Exception.Message)")
    } finally { $client.Close() }
}

function Get-VncAuthResponse {
    <# The VNC authentication answer: the 16-byte challenge DES-encrypted (ECB) with the
       password as key, padded with zeros to 8 bytes, each key byte bit-reversed (RFB 3.8,
       section 7.2.2). #>
    param([byte[]]$Challenge, [string]$Plain)
    $key = New-Object byte[] 8
    $pw = [Text.Encoding]::ASCII.GetBytes($Plain)
    for ($i = 0; $i -lt 8 -and $i -lt $pw.Length; $i++) {
        $b = $pw[$i]; $r = 0
        for ($j = 0; $j -lt 8; $j++) { if ($b -band (1 -shl $j)) { $r = $r -bor (1 -shl (7 - $j)) } }
        $key[$i] = [byte]$r
    }
    $des = [Security.Cryptography.DES]::Create()
    try {
        $des.Mode = 'ECB'; $des.Padding = 'None'; $des.Key = $key
        return , $des.CreateEncryptor().TransformFinalBlock($Challenge, 0, 16)
    } finally { $des.Dispose() }
}

function Test-VncPasswordLogin {
    <# Logs in once with the password and expects the server to accept it. This proves the
       password setup asked for is the one in force (a blank or different password would be
       refused), which the security-type list alone cannot show. Uses VNC authentication (2)
       directly, or inside Tight (16). Returns a list of problems. #>
    param([string]$Address, [int]$Port, [string]$Plain, [int]$TimeoutMs = 5000)
    $client = New-Object Net.Sockets.TcpClient
    try {
        $task = $client.ConnectAsync($Address, $Port)
        if (-not $task.Wait($TimeoutMs)) { return @("no answer from ${Address}:$Port") }
        $s = $client.GetStream()
        $s.ReadTimeout = $TimeoutMs
        $greeting = [Text.Encoding]::ASCII.GetString((Read-Exactly $s 12))
        if ($greeting -notmatch '^RFB 003\.\d{3}\n$') { return @("${Address}:$Port is not a VNC server") }
        $reply = [Text.Encoding]::ASCII.GetBytes("RFB 003.008`n")
        $s.Write($reply, 0, $reply.Length)
        $n = (Read-Exactly $s 1)[0]
        if ($n -eq 0) { return @("${Address}:$Port refused the connection") }
        $raw = Read-Exactly $s $n
        $types = @($raw | ForEach-Object { [int]$_ })
        if ($types -contains 2) { $s.Write([byte[]](2), 0, 1) }
        elseif ($types -contains 16) {
            $s.Write([byte[]](16), 0, 1)
            $codes = Read-TightAuthCode -Stream $s
            if (@($codes) -notcontains 2) { return @("${Address}:${Port}: Tight offers no VNC password authentication") }
            $s.Write([byte[]](0, 0, 0, 2), 0, 4)
        } else { return @("${Address}:${Port}: no VNC password authentication offered") }
        $challenge = Read-Exactly $s 16
        $answer = Get-VncAuthResponse -Challenge $challenge -Plain $Plain
        $s.Write($answer, 0, 16)
        $result = ConvertFrom-BigEndian (Read-Exactly $s 4) 0
        if ($result -ne 0) { return @("${Address}:${Port}: the VNC password setup set is not the one in force (login refused)") }
        return @()
    } catch {
        return @("${Address}:${Port}: $($_.Exception.Message)")
    } finally { $client.Close() }
}

function Get-VncGuardAction {
    <# What the startup guard does: 'ok' when the Tailscale address is the one setup recorded;
       'remove' (fail closed) when it changed or there is none. #>
    param([string]$Recorded, [string]$Current)
    if (-not $Recorded -or -not (Test-InCgnat $Recorded)) { return 'remove' }
    if ($Current -ne $Recorded) { return 'remove' }
    return 'ok'
}

# ---------------------------------------------------------------- Windows calls

function Invoke-Netsh {
    param([string[]]$ArgumentList)
    $ErrorActionPreference = 'Continue'
    $out = (& netsh.exe @ArgumentList 2>&1 | Out-String) -replace "`r", ''
    if ($LASTEXITCODE -ne 0) { throw "netsh $($ArgumentList -join ' ') failed ($LASTEXITCODE): $($out.Trim())" }
    return $out
}

function Get-VncPortProxy {
    <# Every port proxy entry, from all four tables. #>
    foreach ($k in $script:PortProxyKinds) {
        ConvertFrom-PortProxyShow -Kind $k -Text (Invoke-Netsh @('interface', 'portproxy', 'show', $k))
    }
}

function Get-PortProxyDeleteArgument {
    <# netsh arguments that delete one entry; a wildcard (*) entry is deleted without listenaddress. #>
    param($Row)
    $a = @('interface', 'portproxy', 'delete', "$($Row.Kind)", "listenport=$($Row.ListenPort)")
    if ("$($Row.ListenAddress)" -ne '*') { $a += "listenaddress=$($Row.ListenAddress)" }
    return , $a
}

function Remove-VncPortProxy {
    <# Deletes every entry, in any table, that listens on 5900 or forwards to 5901. Returns how many. #>
    $n = 0
    foreach ($r in @(Get-VncPortProxy | Where-Object { Test-VncProxyRow $_ })) {
        Invoke-Netsh (Get-PortProxyDeleteArgument $r) | Out-Null
        $n++
    }
    return $n
}

function Test-VncAccess {
    <# Every VNC check in one place (setup, guard and boot probe use it): the proxy table, the
       listeners, and the password handshake on loopback and on the Tailscale address. #>
    param([string]$TailscaleIPv4)
    $problems = @()
    $problems += @(Get-VncProxyProblem -Rows @(Get-VncPortProxy) -TailscaleIPv4 $TailscaleIPv4)
    $problems += @(Get-VncListenerProblem -Listeners @(Get-ListenerSummary) -TailscaleIPv4 $TailscaleIPv4)
    $problems += @(Test-RfbEndpoint -Address '127.0.0.1' -Port $script:VncInternalPort)
    $problems += @(Test-RfbEndpoint -Address $TailscaleIPv4 -Port $script:VncPublicPort)
    # Callers wrap the result in @(); no leading comma, or an empty result would count as one.
    return @($problems | Where-Object { $_ })
}

function Close-VncAccess {
    <# Fail closed: delete the proxy, disable the allow rule, and restart IP Helper if a 5900
       socket is still open. Each part is tried on its own and read back. Returns
       Complete (bool) and Notes. #>
    $notes = @()
    $complete = $true
    try { $n = Remove-VncPortProxy; $notes += "removed $n port proxy entr(ies)" } catch { $complete = $false; $notes += "proxy delete failed: $($_.Exception.Message)" }
    try {
        if (Get-NetFirewallRule -Name $script:VncFirewallRule -ErrorAction SilentlyContinue) {
            Disable-NetFirewallRule -Name $script:VncFirewallRule -ErrorAction Stop
            if ("$((Get-NetFirewallRule -Name $script:VncFirewallRule -ErrorAction Stop).Enabled)" -ne 'False') { throw 'still enabled' }
        }
        $notes += 'VNC allow rule disabled'
    } catch { $complete = $false; $notes += "rule disable failed: $($_.Exception.Message)" }
    try {
        if (@(Get-ListenerSummary | Where-Object { $_.LocalPort -eq $script:VncPublicPort }).Count) {
            Restart-Service -Name iphlpsvc -Force -ErrorAction Stop
            $notes += 'restarted IP Helper to close 5900'
        }
        if (@(Get-VncPortProxy | Where-Object { Test-VncProxyRow $_ }).Count) { throw 'entries left' }
        if (@(Get-ListenerSummary | Where-Object { $_.LocalPort -eq $script:VncPublicPort }).Count) { throw '5900 still listening' }
    } catch { $complete = $false; $notes += "read back: $($_.Exception.Message)" }
    return [pscustomobject]@{ Complete = $complete; Notes = $notes }
}

function Get-TailscaleIPv4 {
    $exe = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
    $ErrorActionPreference = 'Continue'
    $out = (& $exe ip -4 2>$null | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "tailscale ip -4 failed ($LASTEXITCODE)" }
    return Select-TailscaleIPv4 -Text $out
}

function Get-ListenerSummary {
    $names = @{}
    Get-Process | ForEach-Object { $names[[int]$_.Id] = $_.ProcessName }
    Get-NetTCPConnection -State Listen | ForEach-Object {
        [pscustomobject]@{ LocalAddress = $_.LocalAddress; LocalPort = [int]$_.LocalPort; Process = $names[[int]$_.OwningProcess] }
    }
}

function Find-VncService {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -like "*$($script:VncExeName)*" } | Select-Object -First 1
}

function Read-VncState {
    if (-not (Test-Path $script:VncStateFile)) { return $null }
    try { return (Get-Content $script:VncStateFile -Raw | ConvertFrom-Json) } catch { return $null }
}
