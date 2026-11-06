<#
.SYNOPSIS
  One-time setup of Ri's laptop for remote access over Tailscale (plan v1, 6 Nov 2026).

.DESCRIPTION
  Run as administrator, only after Ri's yeses. It asks nothing: no prompts, no passwords typed.
  Safe to run again: every step checks first and only changes what is not already right. Each
  step prints PASS, FAIL or SKIP, and a summary at the end. The last line is
  "Done. You can close this window." only when no step failed; exit code 0 means the same.

  Steps: Tailscale (Run unattended and exit node), OpenSSH Server, admin key, sshd config, SSH firewall,
  power, Windows Update active hours, Syncthing service, shared Brain folder, Obsidian,
  TightVNC (screen), RustDesk (optional, only with -RustDeskPassword), off-switch shortcut,
  boot probe and VNC guard, final service check.

  Every download is a pinned version, checked against its SHA-256 before use. Nothing is
  downloaded from a "latest" link.

.PARAMETER BrainUser
  Optional. Ri's Windows account name. Without it, setup uses the one user signed in at the
  console (Win32_ComputerSystem.UserName, cross-checked with the owners of explorer.exe) and
  FAILs the Brain step if that is missing or ambiguous. The shared Brain notes go to
  C:\Users\<user>\Brain (her profile folder directly under <drive>:\Users, read from Windows),
  never to a SYSTEM or service profile.

  The TightVNC password is never typed or passed: setup generates a random 8-character one on
  the laptop and keeps it in C:\ProgramData\ri-laptop\vnc.txt, readable by SYSTEM and
  Administrators only (the ACL is set and checked before the password is written). Reruns
  reuse it. Nova reads it later over ssh into the OpenBot Vault.

.PARAMETER RotateVncPassword
  Generate a new VNC password, write it to vnc.txt and reinstall TightVNC with it.

.PARAMETER TailscaleIPv4
  Optional. If given, it must equal the address `tailscale ip -4` reports, or the VNC steps fail.

.PARAMETER RustDeskPassword
  Optional and excluded from the one-paste bootstrap (TightVNC is the screen access). A
  SecureString permanent RustDesk password, only for a later run over ssh by Astro. Never
  stored in this repo or in any log. Without it, the RustDesk steps are skipped.

.PARAMETER SkipObsidian
  Do not install Obsidian.
#>
[CmdletBinding()]
param(
    [string]$BrainUser,
    [switch]$RotateVncPassword,
    [string]$TailscaleIPv4,
    [SecureString]$RustDeskPassword,
    [switch]$SkipObsidian
)

Set-StrictMode -Version 2.0
# Any failing cmdlet throws, so a step can never print PASS after an error.
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------- constants

$script:TailnetV4 = '100.64.0.0/10'
$script:TailnetV6 = 'fd7a:115c:a1e0::/48'
$script:DataDir = Join-Path $env:ProgramData 'RiLaptop'
$script:SshDir = Join-Path $env:ProgramData 'ssh'
$script:AdminKeysFile = Join-Path $script:SshDir 'administrators_authorized_keys'
$script:SshdConfig = Join-Path $script:SshDir 'sshd_config'
$script:SshdExe = Join-Path $env:SystemRoot 'System32\OpenSSH\sshd.exe'
$script:TailscaleExe = Join-Path $env:ProgramFiles 'Tailscale\tailscale.exe'
$script:RustDeskExe = Join-Path $env:ProgramFiles 'RustDesk\rustdesk.exe'
$script:RustDeskPort = 21118
$script:SidAdministrators = 'S-1-5-32-544'
$script:SidSystem = 'S-1-5-18'
$script:RulePrefix = 'RiLaptop-'
$script:InstallerTimeoutMinutes = 15
# The VNC password lives here, readable by SYSTEM and Administrators only (REQ #51).
$script:SecretDir = Join-Path $env:ProgramData 'ri-laptop'
$script:VncPasswordFile = Join-Path $script:SecretDir 'vnc.txt'

# Shared Brain vault (plan section 3). The hub ID was read on astrolab-nova by Nova on 6 Nov 2026.
$script:HubDeviceId = '3JMTZAQ-62GEPRB-FFEF3NX-RZVZG5O-K4OC4HU-VLT7UEE-EEZRQBO-IPSPPQX'
$script:HubDeviceName = 'astrolab-nova'
$script:BrainFolderId = 'brain'
$script:BrainFolderLabel = 'Brain'
# Syncthing Windows Setup with /allusers: service account and config folder (its README).
$script:SyncthingAccount = 'SyncthingServiceAcct'
$script:SyncthingHome = Join-Path $env:ProgramData 'Syncthing'
$script:SyncthingExe = Join-Path $env:ProgramFiles 'Syncthing\syncthing.exe'

. (Join-Path $PSScriptRoot 'vnc-common.ps1')

# Pinned downloads: official GitHub releases, SHA-256 from GitHub's asset digest (checked 6 Nov 2026).
$script:Pinned = @{
    SyncthingSetup = @{
        Version = '2.1.1'
        Url     = 'https://github.com/Bill-Stewart/SyncthingWindowsSetup/releases/download/v2.1.1/syncthing-windows-setup-v2.1.1.exe'
        Sha256  = 'dd255e8b8e59a0fff25a0e09959a2c76f10fce91bfdc8ab931d3436f483fce51'
    }
    Obsidian       = @{
        Version = '1.15.0'
        Url     = 'https://github.com/obsidianmd/obsidian-releases/releases/download/v1.15.0/Obsidian-1.15.0.exe'
        Sha256  = 'b0f60c75a12f96d54cb16b9fc32919966f2ebf029d9af75d67a19ba6555e1da0'
    }
    # TightVNC is not on GitHub. Its site publishes no checksum, so the hash is of the MSI
    # downloaded twice from tightvnc.com on 6 Nov 2026 (same size as the download page lists);
    # setup also requires a valid Authenticode signature by GlavSoft.
    TightVnc       = @{
        Version = '2.8.90'
        Url     = 'https://www.tightvnc.com/download/2.8.90/tightvnc-2.8.90-gpl-setup-64bit.msi'
        Sha256  = '9693cb4cdc2e7e482e8e3f5890415b57ef87de3369fa5c337db516218a1170ce'
        Signer  = 'GlavSoft'
    }
    RustDesk       = @{
        Version = '1.5.1'
        Url     = 'https://github.com/rustdesk/rustdesk/releases/download/1.5.1/rustdesk-1.5.1-x86_64.exe'
        Sha256  = '319206042390ebfcba934cf0baa2f612f34de463c78c843b7cb8c22097c4bf7b'
    }
}

# RustDesk options. Keys and values from rustdesk.com/docs (client "Advanced settings").
# There is no documented way to turn the public ID/relay servers off, so the firewall
# blocks rustdesk.exe from reaching anything outside the tailnet instead.
$script:RustDeskOptions = [ordered]@{
    'direct-server'         = 'Y'
    'direct-access-port'    = '21118'
    'verification-method'   = 'use-permanent-password'
    'approve-mode'          = 'password'
    'enable-lan-discovery'  = 'N'
    'allow-auto-update'     = 'N'
    'whitelist'             = '100.64.0.0/10'
}

# ---------------------------------------------------------------- step runner

$script:Results = New-Object System.Collections.Generic.List[object]

function Write-SetupLog {
    param([string]$Line)
    try {
        if (-not (Test-Path $script:DataDir)) { New-Item -ItemType Directory -Path $script:DataDir -Force | Out-Null }
        # Never write through a link (Initialize-DataDir moves such a folder aside).
        if ((Get-Item -LiteralPath $script:DataDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { return }
        $stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
        Add-Content -Path (Join-Path $script:DataDir 'setup-log.txt') -Value "$stamp $Line" -Encoding UTF8
    } catch { Write-Verbose "could not write setup log: $($_.Exception.Message)" }
}

function Invoke-Step {
    <# Runs one step. The action throws on failure, returns a detail string on success,
       a string starting with 'SKIP:' when the step does not apply, or 'WARN:' when it
       worked but a person should look at something. #>
    param([string]$Name, [scriptblock]$Action)
    $status = 'PASS'
    try {
        $detail = (& $Action | Out-String).Trim()
        if ($detail -like 'SKIP:*') { $status = 'SKIP'; $detail = $detail.Substring(5).Trim() }
        elseif ($detail -like 'WARN:*') { $status = 'WARN'; $detail = $detail.Substring(5).Trim() }
    } catch {
        $status = 'FAIL'
        $detail = $_.Exception.Message
    }
    $row = [pscustomobject]@{ Step = $Name; Status = $status; Detail = $detail }
    $script:Results.Add($row)
    $color = @{ PASS = 'Green'; FAIL = 'Red'; SKIP = 'Yellow'; WARN = 'Yellow' }[$status]
    Write-Host ('[{0}] {1}: {2}' -f $status, $Name, $detail) -ForegroundColor $color
    Write-SetupLog ('[{0}] {1}: {2}' -f $status, $Name, $detail)
    return $row
}

# ---------------------------------------------------------------- pure helpers (tested on Linux)

function Invoke-Native {
    <# Run a Windows tool and throw if it exits non-zero. #>
    param([string]$FilePath, [string[]]$ArgumentList)
    # Stderr text from a tool is not an error by itself; the exit code decides.
    $ErrorActionPreference = 'Continue'
    # Windows tools end lines with CRLF; drop the CR so ^...$ patterns match.
    $out = (& $FilePath @ArgumentList 2>&1 | Out-String) -replace "`r", ''
    if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($FilePath)) $($ArgumentList -join ' ') failed ($LASTEXITCODE): $($out.Trim())" }
    return $out
}

function Get-KeyBody {
    <# "ssh-ed25519 AAAA..." without the comment, to compare keys. #>
    param([string]$Line)
    $parts = $Line.Trim() -split '\s+'
    if ($parts.Count -lt 2) { return $Line.Trim() }
    return "$($parts[0]) $($parts[1])"
}

function Get-AdminPublicKey {
    <# The one public key setup.ps1 trusts, from admin_key.pub next to this script. #>
    param([string]$Path = (Join-Path $PSScriptRoot 'admin_key.pub'))
    $lines = @(Get-Content -Path $Path | Where-Object { $_.Trim() -ne '' })
    if ($lines.Count -ne 1) { throw "admin_key.pub must hold exactly one key line" }
    $key = $lines[0].Trim()
    if ($key -notmatch '^ssh-ed25519 [A-Za-z0-9+/]{68}(=){0,2}( .*)?$') { throw 'admin_key.pub is not an ssh-ed25519 public key' }
    return $key
}

function Set-SshdOption {
    <# Returns sshd_config text with a global option set to a value. Global options must come
       before the first Match block, so an active setting before Match is replaced, and
       otherwise the option is inserted just before the first Match (or at the end). #>
    param([string[]]$Lines, [string]$Name, [string]$Value)
    $out = New-Object System.Collections.Generic.List[string]
    $firstMatch = -1
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        if ($Lines[$i] -match '^\s*Match\s') { $firstMatch = $i; break }
    }
    $globalEnd = if ($firstMatch -ge 0) { $firstMatch } else { $Lines.Count }
    $done = $false
    for ($i = 0; $i -lt $Lines.Count; $i++) {
        $line = $Lines[$i]
        if ($i -lt $globalEnd -and $line -match ('^\s*' + [regex]::Escape($Name) + '(\s|=)')) {
            if (-not $done) { $out.Add("$Name $Value"); $done = $true }
            continue
        }
        if ($i -eq $globalEnd -and -not $done) { $out.Add("$Name $Value"); $done = $true }
        $out.Add($line)
    }
    if (-not $done) { $out.Add("$Name $Value") }
    return , $out.ToArray()
}

function Add-AdminMatchBlock {
    <# Make sure the Windows default admin block is present (it is in the default config). #>
    param([string[]]$Lines)
    $joined = $Lines -join "`n"
    if ($joined -match '(?im)^\s*Match\s+Group\s+administrators\s*$' -and
        $joined -match '(?im)^\s*AuthorizedKeysFile\s+__PROGRAMDATA__/ssh/administrators_authorized_keys\s*$') {
        return , $Lines
    }
    return , ($Lines + @('', 'Match Group administrators', '       AuthorizedKeysFile __PROGRAMDATA__/ssh/administrators_authorized_keys'))
}

function Get-HardenedSshdConfig {
    param([string[]]$Lines)
    $l = $Lines
    # ChallengeResponseAuthentication, not KbdInteractiveAuthentication: Windows 10 ships
    # OpenSSH 8.1, which does not know the newer name; newer versions accept both.
    foreach ($kv in @(@('PubkeyAuthentication', 'yes'), @('PasswordAuthentication', 'no'),
                      @('ChallengeResponseAuthentication', 'no'), @('PermitEmptyPasswords', 'no'))) {
        $l = Set-SshdOption -Lines $l -Name $kv[0] -Value $kv[1]
    }
    # A Match block must not turn password login back on for anyone.
    # (-replace ignores case, like sshd.)
    $l = @($l | ForEach-Object {
        $_ -replace '^(\s*)PasswordAuthentication(\s+|\s*=\s*)yes\s*$', '$1PasswordAuthentication no' `
           -replace '^(\s*)(ChallengeResponseAuthentication|KbdInteractiveAuthentication)(\s+|\s*=\s*)yes\s*$', '$1ChallengeResponseAuthentication no'
    })
    return , (Add-AdminMatchBlock -Lines $l)
}

function Get-ActiveHours {
    <# Windows Update active hours (whole hours, local time) covering 18:00-01:00 India time.
       If the laptop is not on India time, the window is converted for the given date and
       widened to whole hours (start rounded down, end rounded up). #>
    param([string]$TimeZoneId, [DateTime]$OnDate = [DateTime]::UtcNow)
    $ist = [TimeZoneInfo]::FindSystemTimeZoneById('India Standard Time')
    $zone = [TimeZoneInfo]::FindSystemTimeZoneById($TimeZoneId)
    $day = $OnDate.Date
    $startIst = New-Object DateTime ($day.Year, $day.Month, $day.Day, 18, 0, 0, [DateTimeKind]::Unspecified)
    $endIst = $startIst.AddHours(7)
    $s = [TimeZoneInfo]::ConvertTime($startIst, $ist, $zone)
    $e = [TimeZoneInfo]::ConvertTime($endIst, $ist, $zone)
    $start = $s.Hour
    $end = $e.Hour
    if ($e.Minute -gt 0) { $end = ($end + 1) % 24 }
    $span = ($end - $start + 24) % 24
    if ($span -gt 18) { throw "active hours span $span h is over the 18 h Windows allows" }
    return [pscustomobject]@{ Start = $start; End = $end; ZoneId = $TimeZoneId }
}

function Get-PowercfgIndex {
    <# AC and DC values from `powercfg /query <scheme> <sub> <setting>` output. The labels are
       translated on non-English Windows, so read the last two hex values (AC, then DC). #>
    param([string]$Text)
    $hex = [regex]::Matches($Text, '0x([0-9a-fA-F]{8})\s*$', 'Multiline') | ForEach-Object { [Convert]::ToInt32($_.Groups[1].Value, 16) }
    $hex = @($hex)
    if ($hex.Count -lt 2) { throw 'could not read powercfg values' }
    return [pscustomobject]@{ AC = $hex[$hex.Count - 2]; DC = $hex[$hex.Count - 1] }
}

function Test-InTailnet {
    <# True if every address in a firewall RemoteAddress list is inside the tailnet ranges. #>
    param([string[]]$RemoteAddress)
    if (-not $RemoteAddress -or $RemoteAddress.Count -eq 0) { return $false }
    foreach ($a in $RemoteAddress) {
        if ($a -ne $script:TailnetV4 -and $a -ne $script:TailnetV6 -and
            $a -ne '100.64.0.0/255.192.0.0') { return $false }
    }
    return $true
}

function Select-BroadInboundRule {
    <# Given firewall rule summaries (Name, Enabled, Direction, Action, Protocol, LocalPort,
       Program, RemoteAddress), return the enabled inbound Allow rules that would let the
       given port or program in from outside the tailnet, except our own rules. #>
    param([object[]]$Rules, [int]$Port, [string]$ProgramLike)
    foreach ($r in $Rules) {
        if ($r.Name -like "$($script:RulePrefix)*") { continue }
        if ("$($r.Enabled)" -ne 'True' -or "$($r.Direction)" -ne 'Inbound' -or "$($r.Action)" -ne 'Allow') { continue }
        # Only rules that name this port or this program. Catch-all rules (any port, any
        # program) are not ours to switch off; Get-CatchAllInboundRule reports them.
        $ports = @($r.LocalPort | ForEach-Object { "$_" })
        $tcp = @('TCP', 'Any', '6') -contains "$($r.Protocol)"
        $hitsPort = $tcp -and (Test-PortListed -Ports $ports -Port $Port)
        $hitsProgram = $ProgramLike -and ("$($r.Program)" -like $ProgramLike)
        if (-not ($hitsPort -or $hitsProgram)) { continue }
        if (Test-InTailnet -RemoteAddress @($r.RemoteAddress)) { continue }
        $r
    }
}

function Test-PortListed {
    <# True if a firewall LocalPort list names the port, alone or in a range like 21115-21119. #>
    param([string[]]$Ports, [int]$Port)
    foreach ($p in $Ports) {
        if ($p -match '^\d+$' -and [int]$p -eq $Port) { return $true }
        if ($p -match '^(\d+)-(\d+)$' -and [int]$Matches[1] -le $Port -and $Port -le [int]$Matches[2]) { return $true }
    }
    return $false
}

function Get-CatchAllInboundRule {
    <# Enabled inbound Allow rules for any port, any program, any app package and any service,
       from outside the tailnet. #>
    param([object[]]$Rules)
    foreach ($r in $Rules) {
        if ("$($r.Enabled)" -ne 'True' -or "$($r.Direction)" -ne 'Inbound' -or "$($r.Action)" -ne 'Allow') { continue }
        $ports = @($r.LocalPort | ForEach-Object { "$_" })
        $pkg = if ($r.PSObject.Properties.Name -contains 'Package') { "$($r.Package)" } else { '' }
        $svc = if ($r.PSObject.Properties.Name -contains 'Service') { "$($r.Service)" } else { 'Any' }
        if ($pkg -ne '' -and $pkg -ne 'Any') { continue }
        if ($svc -ne '' -and $svc -ne 'Any') { continue }
        if (($ports -contains 'Any') -and (@('', 'Any') -contains "$($r.Program)") -and
            (@('TCP', 'Any', '6') -contains "$($r.Protocol)") -and -not (Test-InTailnet -RemoteAddress @($r.RemoteAddress))) { $r }
    }
}

function Get-OutsideTailnetRange {
    <# Address ranges that are neither the tailnet nor loopback, for an outbound block rule. #>
    return @(
        '0.0.0.0-100.63.255.255',
        '100.128.0.0-126.255.255.255',
        '128.0.0.0-255.255.255.255',
        '::2-fd7a:115c:a1df:ffff:ffff:ffff:ffff:ffff',
        'fd7a:115c:a1e1::-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
    )
}

function Test-OnlySystemAndAdmins {
    <# True if an ACL (list of identity SIDs and an inheritance flag) grants only SYSTEM and Administrators. #>
    param([string[]]$Sids, [bool]$InheritanceProtected)
    if (-not $InheritanceProtected) { return $false }
    $u = @($Sids | Sort-Object -Unique)
    return ($u.Count -eq 2 -and $u -contains $script:SidSystem -and $u -contains $script:SidAdministrators)
}

function ConvertFrom-SecureToPlain {
    param([SecureString]$Secure)
    $ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secure)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
}


# ---------------------------------------------------------------- Brain and TightVNC helpers (tested on Linux)

# TightVNC 2.x MSI properties used here, all from the vendor's MSI guide
# (tightvnc.com/doc/win/TightVNC_2.7_for_Windows_Installing_from_MSI_Packages.pdf).
$script:VncDocumentedProperties = @(
    'ADDLOCAL', 'SERVER_REGISTER_AS_SERVICE', 'SERVER_ADD_FIREWALL_EXCEPTION', 'SERVER_ALLOW_SAS',
    'VIEWER_ADD_FIREWALL_EXCEPTION', 'SET_ACCEPTRFBCONNECTIONS', 'VALUE_OF_ACCEPTRFBCONNECTIONS',
    'SET_ACCEPTHTTPCONNECTIONS', 'VALUE_OF_ACCEPTHTTPCONNECTIONS', 'SET_RFBPORT', 'VALUE_OF_RFBPORT',
    'SET_LOOPBACKONLY', 'VALUE_OF_LOOPBACKONLY', 'SET_ALLOWLOOPBACK', 'VALUE_OF_ALLOWLOOPBACK',
    'SET_EXTRAPORTS', 'SET_USEVNCAUTHENTICATION', 'VALUE_OF_USEVNCAUTHENTICATION',
    'SET_PASSWORD', 'VALUE_OF_PASSWORD', 'SET_VIEWONLYPASSWORD', 'SET_IPACCESSCONTROL',
    'SET_RUNCONTROLINTERFACE', 'VALUE_OF_RUNCONTROLINTERFACE',
    'SET_USECONTROLAUTHENTICATION', 'VALUE_OF_USECONTROLAUTHENTICATION', 'SET_CONTROLPASSWORD', 'VALUE_OF_CONTROLPASSWORD'
)

function New-RandomControlPassword {
    <# A random 8-character control-interface password that is never stored or shown: it only
       locks TightVNC's control interface, so its settings change only by running setup again. #>
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $bytes = New-Object byte[] 8
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })
}

function Assert-VncPassword {
    <# VNC authentication uses at most 8 characters; anything longer would be cut silently.
       The password goes on the msiexec command line, so quoting characters are refused.
       Messages never include the password. #>
    param([string]$Plain)
    # Exactly 8: VNC uses only 8, and a shorter one pads the DES key with zeros.
    if ($Plain.Length -ne 8) { throw 'VNC password must be exactly 8 characters (VNC uses only 8)' }
    # Letters, digits and a few marks only: nothing the command line or MSI could read as
    # quoting or a property reference (" ' % [ ] { } ; spaces).
    if ($Plain -cnotmatch '^[A-Za-z0-9!#$*+,./:=?@^_~-]{8}$') { throw 'VNC password may use letters, digits and ! # $ * + , . / : = ? @ ^ _ ~ - only' }
}

function New-VncPassword {
    <# A random 8-character VNC password from letters and digits (no look-alikes), drawn without
       modulo bias. It passes Assert-VncPassword. #>
    $chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'
    $limit = 256 - (256 % $chars.Length)
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $out = New-Object Text.StringBuilder
    $b = New-Object byte[] 1
    try {
        while ($out.Length -lt 8) {
            $rng.GetBytes($b)
            if ($b[0] -lt $limit) { [void]$out.Append($chars[$b[0] % $chars.Length]) }
        }
    } finally { $rng.Dispose() }
    return $out.ToString()
}

function Test-SecretAcl {
    <# True only if every Allow entry is SYSTEM or Administrators, nothing else (no read for
       Users either), the owner is one of them, and inheritance from above is cut (or, for a
       file, everything it has is inherited from the checked folder). #>
    param([string[]]$AllowSids, [string]$OwnerSid, [bool]$Protected, [bool]$InheritedOnly)
    if (-not ($Protected -or $InheritedOnly)) { return $false }
    if (@($script:SidSystem, $script:SidAdministrators) -notcontains $OwnerSid) { return $false }
    $u = @($AllowSids | Sort-Object -Unique)
    if (-not $u.Count) { return $false }
    foreach ($sid in $u) { if (@($script:SidSystem, $script:SidAdministrators) -notcontains $sid) { return $false } }
    return $true
}

function Assert-SecretAcl {
    param([string]$Path, [switch]$Folder)
    $acl = Get-Acl -LiteralPath $Path
    $allow = @($acl.Access | Where-Object { "$($_.AccessControlType)" -eq 'Allow' })
    $sids = @($allow | ForEach-Object { Get-Sid $_.IdentityReference })
    $owner = Get-Sid (New-Object Security.Principal.NTAccount $acl.Owner)
    $inheritedOnly = (-not $Folder) -and $allow.Count -gt 0 -and -not @($allow | Where-Object { -not $_.IsInherited }).Count
    if (-not (Test-SecretAcl -AllowSids $sids -OwnerSid $owner -Protected $acl.AreAccessRulesProtected -InheritedOnly $inheritedOnly)) {
        throw "$Path is not limited to SYSTEM and Administrators; the VNC password is not written there"
    }
}

function Protect-SecretDir {
    <# C:\ProgramData\ri-laptop: owner Administrators, inheritance cut, full control for SYSTEM
       and Administrators only, then read back. Runs before any secret is written. #>
    # A folder someone else made first (owner not SYSTEM or Administrators) may hold rights or
    # open handles that an ACL change does not take back: it is moved aside, never trusted.
    if (Test-Path -LiteralPath $script:SecretDir) {
        $item = Get-Item -LiteralPath $script:SecretDir -Force
        $owner = Get-Sid (New-Object Security.Principal.NTAccount (Get-Acl -LiteralPath $script:SecretDir).Owner)
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @($script:SidSystem, $script:SidAdministrators) -notcontains $owner) {
            # Never move the folder this script runs from (the bootstrap makes it safe first).
            if ($PSScriptRoot -and "$PSScriptRoot\".StartsWith("$($script:SecretDir)\", [StringComparison]::OrdinalIgnoreCase)) { throw "$($script:SecretDir) is not owned by SYSTEM or Administrators; not writing the VNC password" }
            $aside = "$($script:SecretDir).untrusted-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
            Move-Item -LiteralPath $script:SecretDir -Destination $aside
            Write-Host "WARNING: $($script:SecretDir) was made by someone else; moved aside to $aside" -ForegroundColor Yellow
        }
    }
    if (-not (Test-Path -LiteralPath $script:SecretDir)) {
        New-Item -ItemType Directory -Path $script:SecretDir | Out-Null
        # A folder made by this elevated run is owned by Administrators (or SYSTEM); any other
        # owner means someone made it in between: refuse.
        $owner = Get-Sid (New-Object Security.Principal.NTAccount (Get-Acl -LiteralPath $script:SecretDir).Owner)
        if (@($script:SidSystem, $script:SidAdministrators) -notcontains $owner) { throw "$($script:SecretDir) was made by someone else while setup ran; not writing the VNC password" }
    }
    if ((Get-Item -LiteralPath $script:SecretDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($script:SecretDir) is a link or junction; not writing the VNC password" }
    # Not recursive (/T): nothing below is walked, so a planted link inside is never followed.
    Invoke-Native icacls.exe @($script:SecretDir, '/setowner', "*$($script:SidAdministrators)", '/L', '/Q') | Out-Null
    Invoke-Native icacls.exe @($script:SecretDir, '/inheritance:r', '/grant:r', "*$($script:SidAdministrators):(OI)(CI)F",
        '/grant:r', "*$($script:SidSystem):(OI)(CI)F", '/L', '/Q') | Out-Null
    # Remove every other entry (for example a user who made the folder first).
    foreach ($e in @((Get-Acl -LiteralPath $script:SecretDir).Access | Where-Object { -not $_.IsInherited })) {
        $sid = Get-Sid $e.IdentityReference
        if (@($script:SidSystem, $script:SidAdministrators) -notcontains $sid) { Invoke-Native icacls.exe @($script:SecretDir, '/remove:g', "*$sid", '/L', '/Q') | Out-Null }
    }
    # A link inside (made in the moment before the ACL was cut) is refused, not followed.
    $links = @(Get-ChildItem -LiteralPath $script:SecretDir -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($links.Count) { throw "$($script:SecretDir) holds a link or junction ($($links[0].Name)); not writing the VNC password" }
    Assert-SecretAcl -Path $script:SecretDir -Folder
}

function Read-VncPasswordFile {
    <# The stored password, or $null if there is none or it is not a valid one. Never printed. #>
    if (-not (Test-Path -LiteralPath $script:VncPasswordFile)) { return $null }
    if ((Get-Item -LiteralPath $script:VncPasswordFile -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($script:VncPasswordFile) is a link; not using it" }
    # An older file gets only the folder's inherited entries (this file only, not recursive).
    Invoke-Native icacls.exe @($script:VncPasswordFile, '/setowner', "*$($script:SidAdministrators)", '/L', '/Q') | Out-Null
    Invoke-Native icacls.exe @($script:VncPasswordFile, '/reset', '/L', '/Q') | Out-Null
    Assert-SecretAcl -Path $script:VncPasswordFile
    $v = ([IO.File]::ReadAllText($script:VncPasswordFile)).Trim()
    try { Assert-VncPassword -Plain $v } catch { return $null }
    return $v
}

function Write-VncPasswordFile {
    <# Writes a password: the file is created empty first, its ACL is checked, and only then is
       the password written. The finished file replaces vnc.txt and is checked again. #>
    param([string]$Plain)
    Assert-VncPassword -Plain $Plain
    $tmp = "$($script:VncPasswordFile).new"
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force }
    $fs = [IO.File]::Open($tmp, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $fs.Dispose()
    # A new file is owned by whoever ran setup; the owner could change the ACL, so it is reset.
    Invoke-Native icacls.exe @($tmp, '/setowner', "*$($script:SidAdministrators)", '/L', '/Q') | Out-Null
    Assert-SecretAcl -Path $tmp
    try {
        [IO.File]::WriteAllText($tmp, $Plain, (New-Object Text.ASCIIEncoding))
        # One replace: the old file stays until the new one takes its place (no Move-Item -Force,
        # which Windows PowerShell 5.1 may not let overwrite).
        if (Test-Path -LiteralPath $script:VncPasswordFile) {
            # Replace keeps the old file's ACL: reset and check it first (rotate skips the read).
            if ((Get-Item -LiteralPath $script:VncPasswordFile -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($script:VncPasswordFile) is a link; not writing the VNC password" }
            Invoke-Native icacls.exe @($script:VncPasswordFile, '/setowner', "*$($script:SidAdministrators)", '/L', '/Q') | Out-Null
            Invoke-Native icacls.exe @($script:VncPasswordFile, '/reset', '/L', '/Q') | Out-Null
            Assert-SecretAcl -Path $script:VncPasswordFile
            [IO.File]::Replace($tmp, $script:VncPasswordFile, [NullString]::Value)
        }
        else { [IO.File]::Move($tmp, $script:VncPasswordFile) }
    } finally {
        if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    Assert-SecretAcl -Path $script:VncPasswordFile
}

function Initialize-VncPassword {
    <# The VNC password for this run: the stored one if valid, else (or with -Rotate) a new one,
       written before TightVNC is installed with it. New = $true means TightVNC must be
       (re)installed so it matches the file. #>
    param([switch]$Rotate)
    Protect-SecretDir
    $old = if ($Rotate) { $null } else { Read-VncPasswordFile }
    if ($old) { return [pscustomobject]@{ Plain = $old; New = $false } }
    # From here TightVNC may not match vnc.txt until an install finishes: drop the proof first,
    # so a failed install is retried on the next run (and the startup guard keeps VNC closed).
    Remove-Item -LiteralPath $script:VncStateFile -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $script:VncStateFile) { throw "could not remove $($script:VncStateFile); not changing the VNC password" }
    $new = New-VncPassword
    Write-VncPasswordFile -Plain $new
    return [pscustomobject]@{ Plain = $new; New = $true }
}

function Select-TargetUser {
    <# The Windows account that gets the Brain folder, without asking: the console user, which
       must also be the one and only owner of explorer.exe. Anything missing, unreadable or
       ambiguous throws. #>
    param([string]$ConsoleUser, [string[]]$ExplorerOwners)
    if (-not $ConsoleUser) { throw 'no user is signed in at the console; sign in as Ri and run setup again (or give -BrainUser)' }
    $owners = @($ExplorerOwners | ForEach-Object { "$_".ToLowerInvariant() } | Sort-Object -Unique)
    if (-not $owners.Count) { throw "no desktop (explorer.exe) found for $ConsoleUser; sign in as Ri and run setup again (or give -BrainUser)" }
    if ($owners -contains '') { throw 'could not read the owner of every explorer.exe; give -BrainUser' }
    if ($owners.Count -gt 1) { throw "more than one user is signed in ($($owners -join ', ')); sign the others out or give -BrainUser" }
    if ($owners[0] -ne $ConsoleUser.ToLowerInvariant()) { throw "the console user $ConsoleUser is not the desktop owner $($owners[0]); give -BrainUser" }
    return $ConsoleUser
}

function Resolve-BrainUser {
    <# Returns DOMAIN\user (or the given -BrainUser). #>
    if ($BrainUser) { return $BrainUser }
    $console = "$((Get-CimInstance Win32_ComputerSystem).UserName)"
    $owners = @(Get-CimInstance Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object {
        $o = Invoke-CimMethod -InputObject $_ -MethodName GetOwner
        # An owner that cannot be read counts as unknown, which Select-TargetUser refuses.
        if ($o -and $o.ReturnValue -eq 0 -and $o.User) { "$($o.Domain)\$($o.User)" } else { '' } })
    return Select-TargetUser -ConsoleUser $console -ExplorerOwners $owners
}

function Test-TailscalePrefs {
    <# Problems with the prefs from `tailscale debug prefs`: Run unattended (ForceDaemon) and the
       exit node (AdvertiseRoutes has 0.0.0.0/0 and ::/0). #>
    param($Prefs)
    $problems = @()
    $names = @($Prefs.PSObject.Properties.Name)
    if (-not ($names -contains 'ForceDaemon') -or -not $Prefs.ForceDaemon) { $problems += 'Run unattended is off' }
    $routes = if ($names -contains 'AdvertiseRoutes') { @($Prefs.AdvertiseRoutes) } else { @() }
    if (-not ($routes -contains '0.0.0.0/0' -and $routes -contains '::/0')) { $problems += 'exit node is not advertised' }
    return $problems
}

function Get-VncMsiArgument {
    <# msiexec arguments for a silent, server-only TightVNC install with the safe settings:
       service mode, loopback only on 5901, no web viewer, no extra ports, no IP rules (all
       callers come from the local port proxy), password required, no installer firewall rule.
       No /l: Windows Installer would write property values (the password) to the log. #>
    param([string]$MsiPath, [string]$Plain, [string]$ControlPlain)
    Assert-VncPassword -Plain $Plain
    Assert-VncPassword -Plain $ControlPlain
    return @('/i', "`"$MsiPath`"", '/quiet', '/norestart',
        'ADDLOCAL=Server', 'SERVER_REGISTER_AS_SERVICE=1', 'SERVER_ADD_FIREWALL_EXCEPTION=0',
        'VIEWER_ADD_FIREWALL_EXCEPTION=0', 'SERVER_ALLOW_SAS=1',
        'SET_ACCEPTRFBCONNECTIONS=1', 'VALUE_OF_ACCEPTRFBCONNECTIONS=1',
        'SET_ACCEPTHTTPCONNECTIONS=1', 'VALUE_OF_ACCEPTHTTPCONNECTIONS=0',
        'SET_RFBPORT=1', "VALUE_OF_RFBPORT=$($script:VncInternalPort)",
        'SET_LOOPBACKONLY=1', 'VALUE_OF_LOOPBACKONLY=1',
        'SET_ALLOWLOOPBACK=1', 'VALUE_OF_ALLOWLOOPBACK=1',
        'SET_EXTRAPORTS=-1', 'SET_IPACCESSCONTROL=-1', 'SET_VIEWONLYPASSWORD=-1',
        # No tray icon, and the control interface (tray and `tvnserver -controlservice`) needs
        # a random password no one keeps, so a signed-in user cannot change the settings.
        'SET_RUNCONTROLINTERFACE=1', 'VALUE_OF_RUNCONTROLINTERFACE=0',
        'SET_USECONTROLAUTHENTICATION=1', 'VALUE_OF_USECONTROLAUTHENTICATION=1',
        'SET_CONTROLPASSWORD=1', "VALUE_OF_CONTROLPASSWORD=$ControlPlain",
        'SET_USEVNCAUTHENTICATION=1', 'VALUE_OF_USEVNCAUTHENTICATION=1',
        # No quotes, as in the vendor's example; Assert-VncPassword allows no spaces or quotes.
        'SET_PASSWORD=1', "VALUE_OF_PASSWORD=$Plain")
}

function Test-BrainProfile {
    <# The Brain folder must be in a real user's own profile: not SYSTEM, LocalService,
       NetworkService, a service account or the systemprofile folder. Returns the Brain path. #>
    param([string]$Sid, [string]$ProfilePath, [string]$UserName)
    if (-not $UserName -or $UserName -match '[\\/:*?"<>|]') { throw '-BrainUser must be a plain Windows account name' }
    if ($UserName -eq $script:SyncthingAccount) { throw 'the Syncthing service account cannot be the Brain user' }
    if ($Sid -notmatch '^S-1-5-21-') { throw "$UserName is not a local or domain user account ($Sid)" }
    if (-not $ProfilePath) { throw "$UserName has no profile yet; sign in as $UserName once, then run setup again" }
    if ($ProfilePath -match '(?i)\\(system32|syswow64)\\config\\systemprofile' -or $ProfilePath -match '(?i)\\ServiceProfiles\\') { throw "profile $ProfilePath is a system profile" }
    if ($ProfilePath -notmatch '(?i)^[A-Z]:\\Users\\[^\\]+$') { throw "profile $ProfilePath is not a folder directly under <drive>:\Users" }
    return "$ProfilePath\Brain"
}

function Get-BrainConfigPlan {
    <# Syncthing cli calls (argument lists after `cli --home <dir>`) that make the hub a device
       and share folder `brain` at $Path with it. Only adds; never removes or edits anything.
       An existing `brain` folder at another path is an error, not something to move. #>
    param([string[]]$Devices, [string[]]$Folders, [string]$ExistingPath, [string[]]$FolderDevices, [string]$Path)
    $plan = @()
    if ($Devices -notcontains $script:HubDeviceId) {
        $plan += , @('config', 'devices', 'add', '--device-id', $script:HubDeviceId, '--name', $script:HubDeviceName)
    }
    if ($Folders -contains $script:BrainFolderId) {
        if ((ConvertTo-WindowsPathKey $ExistingPath) -ne (ConvertTo-WindowsPathKey $Path)) { throw "Syncthing already has folder '$($script:BrainFolderId)' at '$ExistingPath', not '$Path'; not changing it" }
    } else {
        $plan += , @('config', 'folders', 'add', '--id', $script:BrainFolderId, '--label', $script:BrainFolderLabel, '--path', $Path)
    }
    if (($Folders -notcontains $script:BrainFolderId) -or ($FolderDevices -notcontains $script:HubDeviceId)) {
        $plan += , @('config', 'folders', $script:BrainFolderId, 'devices', 'add', '--device-id', $script:HubDeviceId)
    }
    return , $plan
}

function ConvertTo-WindowsPathKey {
    <# Windows paths compare case-insensitively, with either slash and no trailing one. #>
    param([string]$Path)
    return ("$Path" -replace '/', '\').TrimEnd('\').ToLowerInvariant()
}

function Get-LostItem {
    <# Items in Before that are missing from After (to prove nothing was removed). #>
    param([string[]]$Before, [string[]]$After)
    return @($Before | Where-Object { $_ -and $After -notcontains $_ })
}

function Get-VncInstallPlan {
    <# How to (re)install TightVNC. MSI settings apply only when the product is installed, so
       the same version is uninstalled first (by its ProductCode); an older or newer version is
       upgraded by /i directly, as the vendor guide describes. Installed: objects with
       ProductCode and DisplayVersion from the Uninstall registry keys. #>
    param([object[]]$Installed, [string]$Version)
    $same = @($Installed | Where-Object { "$($_.DisplayVersion)" -eq $Version -or "$($_.DisplayVersion)" -like "$Version.*" })
    if ($same.Count) { return [pscustomobject]@{ Uninstall = "$($same[0].ProductCode)" } }
    return [pscustomobject]@{ Uninstall = '' }
}

# ---------------------------------------------------------------- Windows helpers

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-PinnedFile {
    <# Download a pinned file once into ProgramData\RiLaptop\downloads and check its SHA-256.
       A cached copy is reused only if its hash still matches. #>
    param([string]$Key)
    $p = $script:Pinned[$Key]
    $dir = Join-Path $script:DataDir 'downloads'
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $dest = Join-Path $dir ([IO.Path]::GetFileName(([Uri]$p.Url).AbsolutePath))
    if ((Test-Path $dest) -and ((Get-FileHash -Algorithm SHA256 $dest).Hash -eq $p.Sha256.ToUpper())) { return $dest }
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $tmp = "$dest.part"
    $ProgressPreference = 'SilentlyContinue'
    Invoke-WebRequest -Uri $p.Url -OutFile $tmp -UseBasicParsing
    $hash = (Get-FileHash -Algorithm SHA256 $tmp).Hash
    if ($hash -ne $p.Sha256.ToUpper()) {
        Remove-Item $tmp -Force
        throw "$Key download hash mismatch (got $hash); not installing"
    }
    Move-Item -Force $tmp $dest
    return $dest
}

function Assert-NoLinkBelow {
    <# Walks a folder without ever entering a link: any link or junction at any depth throws, so
       the recursive icacls and Get-ChildItem calls after it cannot be led elsewhere. #>
    param([string]$Path)
    $todo = [System.Collections.Generic.Queue[string]]::new()
    $todo.Enqueue($Path)
    while ($todo.Count) {
        foreach ($c in @(Get-ChildItem -LiteralPath $todo.Dequeue() -Force)) {
            if ($c.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($c.FullName) is a link or junction; not changing anything through it" }
            if ($c.PSIsContainer) { $todo.Enqueue($c.FullName) }
        }
    }
}

function Initialize-DataDir {
    <# C:\ProgramData\RiLaptop holds installers and scripts that run elevated or as SYSTEM, so
       only SYSTEM and Administrators may write there. A folder someone else made first (owner
       not SYSTEM or Administrators) or a link is moved aside, not adopted; a link anywhere
       inside stops setup before anything recursive runs (review r3). #>
    if (Test-Path -LiteralPath $script:DataDir) {
        $item = Get-Item -LiteralPath $script:DataDir -Force
        $owner = Get-Sid (New-Object Security.Principal.NTAccount (Get-Acl -LiteralPath $script:DataDir).Owner)
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @($script:SidSystem, $script:SidAdministrators) -notcontains $owner) {
            if ($PSScriptRoot -and "$PSScriptRoot\".StartsWith("$($script:DataDir)\", [StringComparison]::OrdinalIgnoreCase)) { throw "$($script:DataDir) is not owned by SYSTEM or Administrators" }
            $aside = "$($script:DataDir).untrusted-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
            Move-Item -LiteralPath $script:DataDir -Destination $aside
            Write-Host "WARNING: $($script:DataDir) was made by someone else; moved aside to $aside" -ForegroundColor Yellow
        }
    }
    if (-not (Test-Path -LiteralPath $script:DataDir)) { New-Item -ItemType Directory -Path $script:DataDir | Out-Null }
    if ((Get-Item -LiteralPath $script:DataDir -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$($script:DataDir) is a link or junction" }
    Assert-NoLinkBelow -Path $script:DataDir
    Invoke-Native icacls.exe @($script:DataDir, '/setowner', "*$($script:SidAdministrators)", '/T', '/C', '/L', '/Q') | Out-Null
    Invoke-Native icacls.exe @($script:DataDir, '/inheritance:r', '/grant:r', "*$($script:SidAdministrators):(OI)(CI)F",
        '/grant:r', "*$($script:SidSystem):(OI)(CI)F", '/grant:r', '*S-1-5-32-545:(OI)(CI)RX', '/T', '/C', '/L', '/Q') | Out-Null
    # Files that were already there (possibly made by a standard user) get their own entries
    # removed and inherit the folder's ACL.
    if (Get-ChildItem -Path $script:DataDir -Force) {
        Invoke-Native icacls.exe @((Join-Path $script:DataDir '*'), '/reset', '/T', '/C', '/L', '/Q') | Out-Null
    }
    foreach ($item in @(Get-Item $script:DataDir) + @(Get-ChildItem -Path $script:DataDir -Recurse -Force)) {
        $acl = Get-Acl $item.FullName
        $writers = @($acl.Access | Where-Object { $_.AccessControlType -eq 'Allow' -and ($_.FileSystemRights -band 0xD0116) } |
            ForEach-Object { Get-Sid $_.IdentityReference })
        $protectedOrInherited = $acl.AreAccessRulesProtected -or ($item.FullName -ne (Get-Item $script:DataDir).FullName)
        if (-not (Test-OnlySystemAndAdmins -Sids $writers -InheritanceProtected $protectedOrInherited)) { throw "$($item.FullName) is writable by more than SYSTEM and Administrators" }
    }
}

function Get-Sid {
    param($Identity)
    try { return $Identity.Translate([Security.Principal.SecurityIdentifier]).Value } catch { return "$Identity" }
}

function Wait-Installer {
    <# Start an installer and wait for that process only, with a timeout. (Start-Process -Wait in
       PowerShell 5.1 also waits for every child, such as a service the installer starts.) #>
    param([string]$FilePath, [string[]]$ArgumentList)
    $p = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -PassThru
    # Touch the handle now: in Windows PowerShell 5.1, ExitCode is otherwise empty after the wait.
    $null = $p.Handle
    if (-not $p.WaitForExit($script:InstallerTimeoutMinutes * 60 * 1000)) { throw "$([IO.Path]::GetFileName($FilePath)) still running after $($script:InstallerTimeoutMinutes) minutes" }
    return $p.ExitCode
}

function Set-ServiceAutoRunning {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction Stop
    if ($svc.StartType -ne 'Automatic') { Set-Service -Name $Name -StartupType Automatic }
    if ($svc.Status -ne 'Running') { Start-Service -Name $Name }
    $svc = Get-Service -Name $Name
    if ($svc.StartType -ne 'Automatic' -or $svc.Status -ne 'Running') { throw "$Name is $($svc.StartType)/$($svc.Status)" }
    return "$Name Automatic and Running"
}

function Get-FirewallRuleSummary {
    <# Enabled inbound allow rules with their port, address, program and service filters, for
       Select-BroadInboundRule. Each filter type is read once (-All) and joined by InstanceID,
       which is much faster than querying per rule. #>
    $index = @{}
    foreach ($kind in 'Port', 'Address', 'Application', 'Service') {
        $index[$kind] = @{}
        foreach ($f in (& "Get-NetFirewall$($kind)Filter" -All)) { $index[$kind][$f.InstanceID] = $f }
    }
    Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow | ForEach-Object {
        $id = $_.InstanceID
        $pf = $index.Port[$id]; $af = $index.Address[$id]; $ap = $index.Application[$id]; $sf = $index.Service[$id]
        [pscustomobject]@{
            Name = $_.Name; DisplayName = $_.DisplayName; Enabled = $_.Enabled; Direction = $_.Direction
            Action = $_.Action
            Protocol = if ($pf) { $pf.Protocol } else { 'Any' }
            LocalPort = if ($pf) { $pf.LocalPort } else { 'Any' }
            Program = if ($ap) { $ap.Program } else { 'Any' }
            Package = if ($ap) { $ap.Package } else { '' }
            Service = if ($sf) { $sf.Service } else { 'Any' }
            RemoteAddress = if ($af) { $af.RemoteAddress } else { 'Any' }
        }
    }
}

function Set-TailnetInboundRule {
    param([string]$Name, [string]$DisplayName, [int]$Port, [string]$Program)
    $ruleArgs = @{
        Name = $Name; DisplayName = $DisplayName; Direction = 'Inbound'; Action = 'Allow'
        Protocol = 'TCP'; LocalPort = $Port; RemoteAddress = @($script:TailnetV4, $script:TailnetV6)
        Profile = 'Any'; Enabled = 'True'
    }
    if ($Program) { $ruleArgs.Program = $Program }
    # Update in place: never a moment where the rule is gone.
    $existing = Get-NetFirewallRule -Name $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Set-NetFirewallRule -Name $Name -Enabled True -Action Allow -Direction Inbound -Profile Any `
            -Protocol TCP -LocalPort $Port -RemoteAddress @($script:TailnetV4, $script:TailnetV6)
        if ($Program) { Set-NetFirewallRule -Name $Name -Program $Program }
    } else {
        New-NetFirewallRule @ruleArgs | Out-Null
    }
    $r = Get-NetFirewallRule -Name $Name
    $addr = @(($r | Get-NetFirewallAddressFilter).RemoteAddress)
    $pf = $r | Get-NetFirewallPortFilter
    if ("$($r.Enabled)" -ne 'True' -or "$($r.Action)" -ne 'Allow' -or -not (Test-InTailnet -RemoteAddress $addr) -or
        -not (Test-PortListed -Ports @($pf.LocalPort) -Port $Port)) {
        throw "firewall rule $Name did not read back as allow TCP $Port from the tailnet"
    }
}

function Disable-BroadInboundRule {
    param([int]$Port, [string]$ProgramLike)
    $broad = @(Select-BroadInboundRule -Rules @(Get-FirewallRuleSummary) -Port $Port -ProgramLike $ProgramLike)
    foreach ($r in $broad) {
        Disable-NetFirewallRule -Name $r.Name
        Write-SetupLog "disabled broad firewall rule '$($r.Name)' ($($r.DisplayName))"
    }
    $left = @(Select-BroadInboundRule -Rules @(Get-FirewallRuleSummary) -Port $Port -ProgramLike $ProgramLike)
    if ($left.Count -gt 0) { throw "broad rules still enabled: $(($left | ForEach-Object Name) -join ', ')" }
    return $broad.Count
}

function Find-SyncthingService {
    Get-CimInstance Win32_Service | Where-Object { $_.PathName -like '*syncthing*' -or $_.Name -like 'syncthing*' } | Select-Object -First 1
}

# ---------------------------------------------------------------- steps

function Step-Preflight {
    if (-not (Test-IsAdmin)) { throw 'not running as administrator; right-click PowerShell > Run as administrator' }
    $os = Get-CimInstance Win32_OperatingSystem
    $tz = (Get-TimeZone).Id
    "$($os.Caption) build $($os.BuildNumber); time zone $tz; PowerShell $($PSVersionTable.PSVersion)"
}

function Step-Tailscale {
    # Run unattended and Run exit node, from the command line (tailscale.com/kb/1088, kb/1103).
    # The service is set back to Automatic and started, which also undoes the off switch.
    $svc = Get-Service -Name 'Tailscale' -ErrorAction SilentlyContinue
    if (-not $svc) { throw 'Tailscale is not installed' }
    # Tailscale lets only the Windows user who owns its login change it: if the admin who
    # elevated this window is someone else, `tailscale set` is refused and the tray is the way.
    $tray = 'by hand (signed in as the Tailscale user): right-click the Tailscale tray icon > Preferences > Run unattended > Yes, and tray icon > Exit node > Run exit node'
    $problems = @()
    try { Set-ServiceAutoRunning -Name 'Tailscale' | Out-Null } catch { $problems += $_.Exception.Message }
    if (Test-Path $script:TailscaleExe) {
        try {
            $ErrorActionPreference = 'Continue'
            $setOut = (& $script:TailscaleExe set --unattended=true --advertise-exit-node=true 2>&1 | Out-String)
            $setCode = $LASTEXITCODE
            $ErrorActionPreference = 'Stop'
            if ($setCode -ne 0) { $problems += "tailscale set exit $setCode ($($setOut.Trim()))" }
        } catch { $ErrorActionPreference = 'Stop'; $problems += "tailscale set failed: $($_.Exception.Message)" }
        # stdout only: a warning on stderr must not break the JSON.
        $p = $null
        try {
            $ErrorActionPreference = 'Continue'
            $json = (& $script:TailscaleExe debug prefs 2>$null | Out-String)
            $ErrorActionPreference = 'Stop'
            if ($LASTEXITCODE -ne 0) { throw "exit $LASTEXITCODE" }
            $p = $json | ConvertFrom-Json
        } catch { $ErrorActionPreference = 'Stop'; $problems += "could not read Tailscale prefs: $($_.Exception.Message)" }
        if ($p) { $problems += @(Test-TailscalePrefs -Prefs $p) }
    } else { $problems += 'tailscale.exe not found' }
    if ($problems.Count) { throw "$($problems -join '; '). Fix $tray" }
    'service Automatic and Running; Run unattended on; exit node advertised (approve it in the admin console)'
}

function Step-OpenSsh {
    $cap = Get-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0'
    if ($cap.State -ne 'Installed') { Add-WindowsCapability -Online -Name 'OpenSSH.Server~~~~0.0.1.0' | Out-Null }
    Set-ServiceAutoRunning -Name 'sshd'
}

function Step-AdminKey {
    $key = Get-AdminPublicKey
    if (-not (Test-Path $script:SshDir)) { throw "$($script:SshDir) missing; OpenSSH step must pass first" }
    $current = @()
    if (Test-Path $script:AdminKeysFile) { $current = @(Get-Content $script:AdminKeysFile | Where-Object { $_.Trim() -ne '' }) }
    $note = ''
    $bodies = @($current | ForEach-Object { Get-KeyBody $_ })
    if ($bodies -notcontains (Get-KeyBody $key)) {
        [IO.File]::WriteAllText($script:AdminKeysFile, (($current + $key) -join "`r`n") + "`r`n", (New-Object Text.UTF8Encoding $false))
    }
    $others = @($current | Where-Object { (Get-KeyBody $_) -ne (Get-KeyBody $key) }).Count
    if ($others) { $note = "; NOTE: $others other key(s) also in the file" }
    # Microsoft's documented command, with SIDs so it works on any Windows language.
    Invoke-Native icacls.exe @($script:AdminKeysFile, '/inheritance:r', '/grant', "*$($script:SidAdministrators):F", '/grant', "*$($script:SidSystem):F") | Out-Null
    $acl = Get-Acl $script:AdminKeysFile
    $sids = @($acl.Access | ForEach-Object { Get-Sid $_.IdentityReference })
    foreach ($sid in ($sids | Sort-Object -Unique)) {
        if ($sid -ne $script:SidSystem -and $sid -ne $script:SidAdministrators) {
            $who = if ($sid -like 'S-1-*') { "*$sid" } else { $sid }
            Invoke-Native icacls.exe @($script:AdminKeysFile, '/remove:g', $who) | Out-Null
        }
    }
    $acl = Get-Acl $script:AdminKeysFile
    $sids = @($acl.Access | ForEach-Object { Get-Sid $_.IdentityReference })
    if (-not (Test-OnlySystemAndAdmins -Sids $sids -InheritanceProtected $acl.AreAccessRulesProtected)) {
        throw "administrators_authorized_keys ACL is not SYSTEM+Administrators only"
    }
    "key present; ACL SYSTEM and Administrators only$note"
}

function Step-SshdConfig {
    if (-not (Test-Path $script:SshdConfig)) { throw 'sshd_config missing; start sshd once first' }
    $orig = [IO.File]::ReadAllLines($script:SshdConfig)
    $new = Get-HardenedSshdConfig -Lines $orig
    $backup = "$($script:SshdConfig).before-ri-setup"
    if (-not (Test-Path $backup)) { Copy-Item $script:SshdConfig $backup }
    $changed = (($orig -join "`n") -ne ($new -join "`n"))
    if ($changed) {
        $candidate = "$($script:SshdConfig).ri-candidate"
        [IO.File]::WriteAllLines($candidate, $new, (New-Object Text.UTF8Encoding $false))
        try { Invoke-Native $script:SshdExe @('-t', '-f', $candidate) | Out-Null }
        catch { Remove-Item $candidate -Force; throw "new sshd_config failed sshd -t; left the old one in place ($($_.Exception.Message))" }
        # Write into the existing file so its ACL stays as OpenSSH set it.
        [IO.File]::WriteAllLines($script:SshdConfig, $new, (New-Object Text.UTF8Encoding $false))
        Remove-Item $candidate -Force
        Restart-Service sshd
    }
    Invoke-Native $script:SshdExe @('-t') | Out-Null
    # -C applies Match blocks, here for the administrator running setup from a tailnet address.
    $ctx = "user=$($env:USERNAME),host=ri-check,addr=100.64.0.1"
    foreach ($effective in @((Invoke-Native $script:SshdExe @('-T')), (Invoke-Native $script:SshdExe @('-T', '-C', $ctx)))) {
        if ($effective -notmatch '(?im)^passwordauthentication no$') { throw 'sshd -T does not show passwordauthentication no' }
        if ($effective -notmatch '(?im)^pubkeyauthentication yes$') { throw 'sshd -T does not show pubkeyauthentication yes' }
        if ($effective -notmatch '(?im)^(kbdinteractiveauthentication|challengeresponseauthentication) no$') { throw 'sshd -T does not show keyboard-interactive login off' }
    }
    if ($changed) { 'updated and validated (sshd -t, sshd -T); sshd restarted' } else { 'already hardened; validated (sshd -t, sshd -T)' }
}

function Step-SshFirewall {
    Set-TailnetInboundRule -Name "$($script:RulePrefix)SSH-Tailnet" -DisplayName 'Ri laptop: SSH from Tailscale only' -Port 22
    $n = Disable-BroadInboundRule -Port 22 -ProgramLike '*\OpenSSH\sshd.exe'
    $done = "port 22 allowed from $($script:TailnetV4) and $($script:TailnetV6) only; disabled $n broad rule(s) (not deleted)"
    $catchAll = @(Get-CatchAllInboundRule -Rules @(Get-FirewallRuleSummary))
    if ($catchAll.Count) { return "WARN: $done. But catch-all inbound rule(s) may let anything in; review by hand: $(($catchAll | ForEach-Object DisplayName) -join ', ')" }
    $done
}

function Step-Power {
    Invoke-Native powercfg.exe @('/change', 'standby-timeout-ac', '0') | Out-Null
    Invoke-Native powercfg.exe @('/change', 'hibernate-timeout-ac', '0') | Out-Null
    Invoke-Native powercfg.exe @('/setacvalueindex', 'SCHEME_CURRENT', 'SUB_BUTTONS', 'LIDACTION', '0') | Out-Null
    # The "system unattended sleep timeout" applies when Windows woke itself; 0 = never.
    Invoke-Native powercfg.exe @('/setacvalueindex', 'SCHEME_CURRENT', 'SUB_SLEEP', 'UNATTENDSLEEP', '0') | Out-Null
    Invoke-Native powercfg.exe @('/setactive', 'SCHEME_CURRENT') | Out-Null
    $sleep = Get-PowercfgIndex -Text (Invoke-Native powercfg.exe @('/query', 'SCHEME_CURRENT', 'SUB_SLEEP', 'STANDBYIDLE'))
    $hib = Get-PowercfgIndex -Text (Invoke-Native powercfg.exe @('/query', 'SCHEME_CURRENT', 'SUB_SLEEP', 'HIBERNATEIDLE'))
    $lid = Get-PowercfgIndex -Text (Invoke-Native powercfg.exe @('/query', 'SCHEME_CURRENT', 'SUB_BUTTONS', 'LIDACTION'))
    $unattended = Get-PowercfgIndex -Text (Invoke-Native powercfg.exe @('/query', 'SCHEME_CURRENT', 'SUB_SLEEP', 'UNATTENDSLEEP'))
    if ($unattended.AC -ne 0) { throw "AC unattended sleep timeout is $($unattended.AC)" }
    if ($sleep.AC -ne 0 -or $hib.AC -ne 0 -or $lid.AC -ne 0) { throw "AC values: sleep=$($sleep.AC) hibernate=$($hib.AC) lid=$($lid.AC)" }
    'on AC: sleep never, hibernate timeout 0, lid close does nothing (battery settings unchanged)'
}

function Step-ActiveHours {
    $tz = (Get-TimeZone).Id
    $h = Get-ActiveHours -TimeZoneId $tz
    # The Settings app value (works on Home) and the policy (Pro and later). Both read back below.
    $ux = 'HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings'
    if (-not (Test-Path $ux)) { New-Item -Path $ux -Force | Out-Null }
    Set-ItemProperty -Path $ux -Name ActiveHoursStart -Value $h.Start -Type DWord
    Set-ItemProperty -Path $ux -Name ActiveHoursEnd -Value $h.End -Type DWord
    Set-ItemProperty -Path $ux -Name SmartActiveHoursState -Value 0 -Type DWord
    $pol = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
    if (-not (Test-Path $pol)) { New-Item -Path $pol -Force | Out-Null }
    Set-ItemProperty -Path $pol -Name SetActiveHours -Value 1 -Type DWord
    Set-ItemProperty -Path $pol -Name ActiveHoursStart -Value $h.Start -Type DWord
    Set-ItemProperty -Path $pol -Name ActiveHoursEnd -Value $h.End -Type DWord
    $r = Get-ItemProperty -Path $ux
    $p = Get-ItemProperty -Path $pol
    if ($r.ActiveHoursStart -ne $h.Start -or $r.ActiveHoursEnd -ne $h.End -or $p.ActiveHoursStart -ne $h.Start -or $p.ActiveHoursEnd -ne $h.End) { throw 'active hours did not read back' }
    $note = if ($tz -eq 'India Standard Time') { '' } else { " (laptop zone ${tz}: converted from 18:00-01:00 IST for today; re-run setup if the zone changes)" }
    "active hours $($h.Start):00-$($h.End):00 local$note"
}

function Step-Syncthing {
    $svc = Find-SyncthingService
    if (-not $svc) {
        # Syncthing has no official Windows installer. Its docs list this community setup, which
        # installs a service under a dedicated low-privilege account (not LocalSystem).
        # Automatic upgrades off, so the pinned version stays until setup is updated.
        $exe = Get-PinnedFile -Key 'SyncthingSetup'
        $code = Wait-Installer -FilePath $exe -ArgumentList @('/allusers', '/verysilent', '/suppressmsgboxes', '/norestart', '/autoupgradeinterval=0')
        if ($code -ne 0) { throw "Syncthing setup exit code $code" }
        $svc = Find-SyncthingService
        if (-not $svc) { throw 'Syncthing setup finished but no Syncthing service found' }
    }
    $r = Set-ServiceAutoRunning -Name $svc.Name
    "$r (account $($svc.StartName)); runs at boot with no one signed in"
}

function Step-Obsidian {
    if ($SkipObsidian) { return 'SKIP: -SkipObsidian' }
    $paths = @((Join-Path $env:ProgramFiles 'Obsidian\Obsidian.exe'), (Join-Path $env:LOCALAPPDATA 'Programs\Obsidian\Obsidian.exe'))
    $found = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($found) { return "already installed: $found" }
    $exe = Get-PinnedFile -Key 'Obsidian'
    $code = Wait-Installer -FilePath $exe -ArgumentList @('/S', '/allusers')
    if ($code -ne 0) { throw "Obsidian installer exit code $code" }
    $found = $paths | Where-Object { Test-Path $_ } | Select-Object -First 1
    if (-not $found) { throw 'Obsidian installer finished but Obsidian.exe not found' }
    "installed $($script:Pinned.Obsidian.Version): $found"
}

function Step-RustDesk {
    if (-not $RustDeskPassword) { return 'SKIP: no -RustDeskPassword given (screen access not set up or left as it is)' }
    if ($RustDeskPassword.Length -lt 8) { throw 'RustDesk password must be at least 8 characters' }
    if (-not (Test-Path $script:RustDeskExe)) {
        $exe = Get-PinnedFile -Key 'RustDesk'
        $code = Wait-Installer -FilePath $exe -ArgumentList @('--silent-install')
        if ($code -ne 0) { throw "RustDesk install exit code $code" }
        $deadline = (Get-Date).AddMinutes(2)
        while (-not (Get-Service -Name 'RustDesk' -ErrorAction SilentlyContinue) -and (Get-Date) -lt $deadline) { Start-Sleep 3 }
    }
    Set-ServiceAutoRunning -Name 'RustDesk' | Out-Null
    foreach ($k in $script:RustDeskOptions.Keys) {
        & $script:RustDeskExe --option $k $script:RustDeskOptions[$k] | Out-Null
        $got = (& $script:RustDeskExe --option $k | Out-String).Trim()
        if ($got -ne $script:RustDeskOptions[$k]) { throw "RustDesk option $k reads back '$got'" }
    }
    $plain = ConvertFrom-SecureToPlain -Secure $RustDeskPassword
    try {
        $out = (& $script:RustDeskExe --password $plain | Out-String).Trim()
    } finally { $plain = $null }
    if ($out -notmatch '(?i)\bdone\b') { throw 'RustDesk did not confirm the password (expected "Done!")' }
    # Restart so the service runs with the new options, behind the firewall rules made earlier.
    Restart-Service -Name 'RustDesk'
    Set-ServiceAutoRunning -Name 'RustDesk' | Out-Null
    'service Automatic and Running; direct IP on 21118, permanent password only, whitelist tailnet, LAN discovery and auto-update off'
}

function Step-RustDeskFirewall {
    # Runs before the install (so RustDesk can never reach the public servers) and again after
    # (to switch off the installer's own broad rules). Also runs if RustDesk is already installed.
    if (-not $RustDeskPassword -and -not (Test-Path $script:RustDeskExe)) { return 'SKIP: RustDesk not set up' }
    Set-TailnetInboundRule -Name "$($script:RulePrefix)RustDesk-Tailnet" -DisplayName 'Ri laptop: RustDesk direct IP from Tailscale only' -Port $script:RustDeskPort -Program $script:RustDeskExe
    $n = Disable-BroadInboundRule -Port $script:RustDeskPort -ProgramLike '*\RustDesk\rustdesk.exe'
    $name = "$($script:RulePrefix)RustDesk-Block-Outside-Tailnet"
    # Block rules win over allow rules: rustdesk.exe cannot reach the public ID/relay servers.
    # Updated in place when it exists, so the block is never missing while RustDesk runs.
    if (Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue) {
        Set-NetFirewallRule -Name $name -Enabled True -Direction Outbound -Action Block -Program $script:RustDeskExe -RemoteAddress (Get-OutsideTailnetRange) -Profile Any
    } else {
        New-NetFirewallRule -Name $name -DisplayName 'Ri laptop: RustDesk may not reach anything outside Tailscale' -Direction Outbound -Action Block -Program $script:RustDeskExe -RemoteAddress (Get-OutsideTailnetRange) -Profile Any | Out-Null
    }
    $b = Get-NetFirewallRule -Name $name
    if ("$($b.Enabled)" -ne 'True' -or "$($b.Action)" -ne 'Block') { throw 'RustDesk outbound block rule did not read back' }
    "inbound 21118 from tailnet only; disabled $n broad rule(s); outbound to anything outside the tailnet blocked"
}

function Invoke-SyncthingCli {
    <# `syncthing cli` against the service's own config folder (it reads the GUI address and
       API key from there). Command forms from syncthing/cmd/syncthing/cli (v2), see README. #>
    param([string[]]$ArgumentList)
    # stdout only: a warning on stderr must not turn into a device or folder id.
    $ErrorActionPreference = 'Continue'
    $out = (& $script:SyncthingExe cli --home $script:SyncthingHome @ArgumentList 2>$null | Out-String) -replace "`r", ''
    if ($LASTEXITCODE -ne 0) { throw "syncthing cli $($ArgumentList -join ' ') failed ($LASTEXITCODE)" }
    return $out
}

function Get-SyncthingList {
    param([string[]]$ArgumentList)
    # The comma keeps an empty or one-item list an array.
    return , @(((Invoke-SyncthingCli $ArgumentList) -split "`n") | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}

function Get-BrainState {
    $devices = Get-SyncthingList @('config', 'devices', 'list')
    $folders = Get-SyncthingList @('config', 'folders', 'list')
    $path = ''; $fdev = @()
    if ($folders -contains $script:BrainFolderId) {
        $path = (Invoke-SyncthingCli @('config', 'folders', $script:BrainFolderId, 'path', 'get')).Trim()
        $fdev = Get-SyncthingList @('config', 'folders', $script:BrainFolderId, 'devices', 'list')
    }
    return [pscustomobject]@{ Devices = $devices; Folders = $folders; Path = $path; FolderDevices = $fdev }
}

function Step-Brain {
    $account = Resolve-BrainUser
    $userName = @($account -split '\\')[-1]
    if (@($account -split '\\').Count -gt 2) { throw "-BrainUser $account is not an account name" }
    $sid = (New-Object Security.Principal.NTAccount $account).Translate([Security.Principal.SecurityIdentifier]).Value
    $prof = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'"
    $profilePath = if ($prof) { "$($prof.LocalPath)" } else { '' }
    $path = Test-BrainProfile -Sid $sid -ProfilePath $profilePath -UserName $userName
    if (-not (Test-Path $script:SyncthingExe)) { throw "$($script:SyncthingExe) not found; the Syncthing step must pass first" }
    # The vault must be synced by the low-privilege service account, never LocalSystem.
    $svc = Find-SyncthingService
    $startName = if ($svc) { "$($svc.StartName)" } else { '(no service)' }
    if ("$startName" -notmatch ('(^|\\)' + [regex]::Escape($script:SyncthingAccount) + '$')) { throw "Syncthing service runs as '$startName', not $($script:SyncthingAccount)" }
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path | Out-Null }
    $item = Get-Item $path -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$path is a link or junction; not syncing through it" }
    # The service account needs Modify on the folder (Syncthing Windows Setup README). Ri keeps
    # her own rights; nothing else changes.
    # /L: if Brain were swapped for a link after the check above, change the link, not its target.
    # /T: files already in the folder get the entry too (the Syncthing Windows Setup README uses /t).
    Invoke-Native icacls.exe @($path, '/grant', "$($script:SyncthingAccount):(OI)(CI)M", '/T', '/L') | Out-Null
    if ((Get-Item $path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$path became a link or junction; stopping" }
    $acct = (New-Object Security.Principal.NTAccount $script:SyncthingAccount).Translate([Security.Principal.SecurityIdentifier]).Value
    $ok = @((Get-Acl $path).Access | Where-Object {
        $_.AccessControlType -eq 'Allow' -and (Get-Sid $_.IdentityReference) -eq $acct -and
        ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::Modify) -eq [Security.AccessControl.FileSystemRights]::Modify -and
        ($_.InheritanceFlags -band 'ContainerInherit') -and ($_.InheritanceFlags -band 'ObjectInherit') })
    if (-not $ok) { throw "$($script:SyncthingAccount) does not have inherited Modify on $path" }
    # The service may still be starting; wait for its API.
    $before = $null
    $deadline = (Get-Date).AddSeconds(90)
    while (-not $before) {
        try { $before = Get-BrainState } catch { if ((Get-Date) -gt $deadline) { throw "syncthing cli does not answer: $($_.Exception.Message)" }; Start-Sleep 5 }
    }
    $plan = Get-BrainConfigPlan -Devices $before.Devices -Folders $before.Folders -ExistingPath $before.Path -FolderDevices $before.FolderDevices -Path $path
    foreach ($a in $plan) { Invoke-SyncthingCli $a | Out-Null }
    $after = Get-BrainState
    $lost = @(Get-LostItem -Before $before.Devices -After $after.Devices) + @(Get-LostItem -Before $before.Folders -After $after.Folders) + @(Get-LostItem -Before $before.FolderDevices -After $after.FolderDevices)
    if ($lost.Count) { throw "Syncthing config lost: $($lost -join ', ')" }
    if ($after.Devices -notcontains $script:HubDeviceId -or $after.FolderDevices -notcontains $script:HubDeviceId -or
        (ConvertTo-WindowsPathKey $after.Path) -ne (ConvertTo-WindowsPathKey $path)) { throw 'Syncthing config did not read back: brain folder shared with astrolab-nova' }
    "folder '$($script:BrainFolderId)' at $path shared with $($script:HubDeviceName) ($($plan.Count) change(s); existing devices and folders kept). Next: Nova runs brain-accept on the hub; Ri opens $path in Obsidian (Open folder as vault)"
}

function Assert-NoInstallerLogging {
    <# Windows Installer logs every property (the password too) if the documented Logging
       policy is set, so the install is refused then. #>
    $pol = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' -Name Logging -ErrorAction SilentlyContinue
    if ($pol -and "$($pol.Logging)".Trim()) { throw 'Windows Installer logging policy is on, so the VNC password would be written to a log; not installing' }
    # The msiexec command line holds the password: refuse if Windows records command lines
    # (process creation auditing with command line) or PowerShell module logging (which logs
    # Start-Process arguments) is on.
    $audit = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
    if ($audit -and "$($audit.ProcessCreationIncludeCmdLine_Enabled)" -eq '1') { throw 'command lines of new processes are audited, so the VNC password would reach the event log; not installing' }
    $ml = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -Name EnableModuleLogging -ErrorAction SilentlyContinue
    if ($ml -and "$($ml.EnableModuleLogging)" -eq '1') { throw 'PowerShell module logging is on, so the VNC password would reach the event log; not installing' }
}

function Get-CheckedVncInstaller {
    $msi = Get-PinnedFile -Key 'TightVnc'
    $sig = Get-AuthenticodeSignature -FilePath $msi
    $subject = if ($sig.SignerCertificate) { "$($sig.SignerCertificate.Subject)" } else { '(no signer)' }
    if ("$($sig.Status)" -ne 'Valid' -or $subject -notmatch [regex]::Escape($script:Pinned.TightVnc.Signer)) {
        throw "TightVNC installer signature is $($sig.Status) ($subject); not installing"
    }
    return $msi
}

function Resolve-VncAddress {
    $ip = Get-TailscaleIPv4
    if ($TailscaleIPv4 -and $TailscaleIPv4 -ne $ip) { throw "-TailscaleIPv4 $TailscaleIPv4 does not match tailscale ip -4 ($ip)" }
    if (-not (Get-NetIPAddress -IPAddress $ip -ErrorAction SilentlyContinue)) { throw "$ip is not assigned to any interface on this laptop" }
    return $ip
}

function Step-VncFirewall {
    # Before the install: TightVNC's installer adds no rule (SERVER_ADD_FIREWALL_EXCEPTION=0),
    # and any older broad rule for 5900/5800/5901 or tvnserver.exe is switched off.
    $ip = Resolve-VncAddress
    $name = $script:VncFirewallRule
    $existing = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
    if ($existing) {
        Set-NetFirewallRule -Name $name -Enabled False -Action Allow -Direction Inbound -Profile Any -Protocol TCP `
            -LocalPort $script:VncPublicPort -LocalAddress $ip -RemoteAddress $script:TailnetV4
    } else {
        New-NetFirewallRule -Name $name -DisplayName 'Ri laptop: VNC on the Tailscale address only' -Direction Inbound -Action Allow `
            -Profile Any -Protocol TCP -LocalPort $script:VncPublicPort -LocalAddress $ip -RemoteAddress $script:TailnetV4 -Enabled False | Out-Null
    }
    # The rule stays disabled until "VNC listeners and password" passes.
    $r = Get-NetFirewallRule -Name $name
    $af = $r | Get-NetFirewallAddressFilter
    if ("$($r.Enabled)" -ne 'False' -or "$($r.Action)" -ne 'Allow' -or @($af.LocalAddress) -join ',' -ne $ip -or
        @($af.RemoteAddress) -join ',' -notmatch '^100\.64\.0\.0/(10|255\.192\.0\.0)$') { throw "firewall rule $name did not read back as $ip from $($script:TailnetV4) only" }
    # The web viewer and the loopback port must never be reached from outside, whatever binds them.
    $block = $script:VncBlockRule
    if (Get-NetFirewallRule -Name $block -ErrorAction SilentlyContinue) {
        Set-NetFirewallRule -Name $block -Enabled True -Direction Inbound -Action Block -Protocol TCP -LocalPort @($script:VncHttpPort, $script:VncInternalPort) -Profile Any
    } else {
        New-NetFirewallRule -Name $block -DisplayName 'Ri laptop: block VNC web and loopback ports from the network' -Direction Inbound -Action Block `
            -Protocol TCP -LocalPort @($script:VncHttpPort, $script:VncInternalPort) -Profile Any | Out-Null
    }
    $n = 0
    foreach ($port in @($script:VncPublicPort, $script:VncHttpPort, $script:VncInternalPort)) {
        $n += Disable-BroadInboundRule -Port $port -ProgramLike '*\TightVNC\tvnserver.exe'
    }
    "inbound 5900 only to ${ip} from $($script:TailnetV4) (rule off until the VNC check passes); 5800 and 5901 blocked from the network; disabled $n broad rule(s)"
}

function Get-InstalledTightVnc {
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*', 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*') {
        Get-ItemProperty -Path $k -ErrorAction SilentlyContinue | Where-Object { $_.PSObject.Properties.Name -contains 'DisplayName' -and "$($_.DisplayName)" -like 'TightVNC*' } |
            ForEach-Object { [pscustomobject]@{ ProductCode = $_.PSChildName; DisplayVersion = "$($_.DisplayVersion)" } }
    }
}

function Remove-NewInstallerLog {
    <# Windows Installer can write MSI*.log to TEMP on its own (the package carries an
       MsiLogging string). Logs written during this install are deleted. #>
    param([DateTime]$Since)
    $n = 0
    foreach ($dir in @($env:TEMP, (Join-Path $env:SystemRoot 'Temp')) | Where-Object { $_ -and (Test-Path $_) }) {
        foreach ($f in @(Get-ChildItem -Path $dir -Filter 'MSI*.log' -File -ErrorAction SilentlyContinue | Where-Object { $_.LastWriteTime -ge $Since })) {
            Remove-Item -LiteralPath $f.FullName -Force
            $n++
        }
    }
    return $n
}

function Step-TightVnc {
    $svc = Find-VncService
    $plain = $null
    # The password file comes first (ACL checked before writing). A new password, a missing
    # TightVNC, or an install that this setup did not finish (no vnc.json) means install now,
    # so the service always has the password in vnc.txt.
    $pw = Initialize-VncPassword -Rotate:$RotateVncPassword
    $install = $pw.New -or -not $svc -or -not (Read-VncState)
    # Not installing: the running server must accept the password in vnc.txt (one login on
    # loopback), else it is installed again with it, so the two can never silently differ.
    if (-not $install -and @(Test-VncPasswordLogin -Address '127.0.0.1' -Port $script:VncInternalPort -Plain $pw.Plain).Count) { $install = $true }
    $logs = 0
    if ($install) {
        $plain = $pw.Plain
        $since = Get-Date
        try {
            # Inside the try: a refused check also closes what an earlier run left open.
            Assert-NoInstallerLogging
            $msi = Get-CheckedVncInstaller
            $plan = Get-VncInstallPlan -Installed @(Get-InstalledTightVnc) -Version $script:Pinned.TightVnc.Version
            # From here the old proof no longer holds: only a passing check writes vnc.json again.
            Remove-Item -LiteralPath $script:VncStateFile -Force -ErrorAction SilentlyContinue
            $msiArgs = Get-VncMsiArgument -MsiPath $msi -Plain $plain -ControlPlain (New-RandomControlPassword)
            if ($plan.Uninstall) {
                # Same version installed: its settings only change on a fresh install.
                $code = Wait-Installer -FilePath 'msiexec.exe' -ArgumentList @('/x', $plan.Uninstall, '/quiet', '/norestart')
                if ($code -ne 0 -and $code -ne 3010) { throw "TightVNC uninstall exit code $code" }
            }
            # Wait-Installer's errors name the file only, never the arguments.
            try { $code = Wait-Installer -FilePath 'msiexec.exe' -ArgumentList $msiArgs }
            catch { throw 'msiexec could not be started for TightVNC' }
            if ($code -ne 0 -and $code -ne 3010) { throw "TightVNC install exit code $code" }
            $msiArgs = $null
            $svc = Find-VncService
            if (-not $svc) { throw 'TightVNC installed but no service with tvnserver.exe found' }
            Set-ServiceAutoRunning -Name $svc.Name | Out-Null
            # Prove the password took: one login with it on loopback must be accepted (a blank
            # or old password would be refused). Only loopback is open at this point.
            $login = @()
            $deadline = (Get-Date).AddSeconds(30)
            do {
                $login = @(Test-VncPasswordLogin -Address '127.0.0.1' -Port $script:VncInternalPort -Plain $plain)
                # Retry only while the server is starting; a refused login is final (TightVNC
                # blocks an address after repeated failures, and every viewer is 127.0.0.1).
                if (-not $login.Count -or ($login -join ';') -match 'login refused') { break }
                Start-Sleep 3
            } while ((Get-Date) -lt $deadline)
            # The catch below closes anything a previous run left open.
            if ($login.Count) { throw "$($login -join '; '); the password is not proven" }
        } catch {
            # Any install failure: close what an earlier run may have left open (fail closed now,
            # not only at the next boot).
            $c = Close-VncAccess
            throw "$($_.Exception.Message) (VNC closed: $($c.Notes -join '; '))"
        } finally {
            $plain = $null; $msiArgs = $null; $pw = $null
            $logError = $null
            try { $logs = Remove-NewInstallerLog -Since $since } catch { $logError = $_.Exception.Message }
            # Also shown when the install itself failed (its error is the one thrown then).
            if ($logError) { Write-Host "WARNING: delete the MSI*.log files in TEMP by hand; one may hold the VNC password: $logError" -ForegroundColor Red }
        }
        # A log that may hold the password must not stay behind: FAIL so nothing is opened.
        if ($logError) { Close-VncAccess | Out-Null; throw "could not delete a Windows Installer log in TEMP (it may hold the VNC password): $logError" }
    }
    $r = Set-ServiceAutoRunning -Name $svc.Name
    $pw = $null
    $how = if ($install) { "; installed $($script:Pinned.TightVnc.Version) with loopback-only 5901, no web viewer, control interface locked; login with the password in vnc.txt accepted on 127.0.0.1:5901; removed $logs new installer log(s)" } else { '; password in vnc.txt unchanged' }
    "$r ($($svc.StartName))$how"
}

function Step-VncProxy {
    $ip = Resolve-VncAddress
    Set-ServiceAutoRunning -Name 'iphlpsvc' | Out-Null
    try { Set-VncProxy -TailscaleIPv4 $ip }
    catch { Remove-Item -LiteralPath $script:VncStateFile -Force -ErrorAction SilentlyContinue; $c = Close-VncAccess; throw "$($_.Exception.Message). VNC closed again ($($c.Notes -join '; '))" }
    "port proxy ${ip}:5900 -> 127.0.0.1:5901 (IP Helper Automatic and Running)"
}

function Set-VncProxy {
    param([string]$TailscaleIPv4)
    $ip = $TailscaleIPv4
    $rows = @(Get-VncPortProxy)
    if (@(Get-VncProxyProblem -Rows $rows -TailscaleIPv4 $ip).Count) {
        Remove-VncPortProxy | Out-Null
        Invoke-Netsh @('interface', 'portproxy', 'add', 'v4tov4', "listenaddress=$ip", "listenport=$($script:VncPublicPort)",
            'connectaddress=127.0.0.1', "connectport=$($script:VncInternalPort)") | Out-Null
    }
    $left = @(Get-VncProxyProblem -Rows @(Get-VncPortProxy) -TailscaleIPv4 $ip)
    if ($left.Count) { throw ($left -join '; ') }
}

function Step-VncCheck {
    $ip = Resolve-VncAddress
    # The handshake to the Tailscale address needs the (already scoped) allow rule; it is
    # closed again below if anything fails.
    $problems = @()
    try {
        Enable-NetFirewallRule -Name $script:VncFirewallRule
        $deadline = (Get-Date).AddSeconds(30)
        do {
            $problems = @(Test-VncAccess -TailscaleIPv4 $ip)
            if (-not $problems.Count) { break }
            Start-Sleep 3
        } while ((Get-Date) -lt $deadline)
    } catch { $problems = @("VNC check failed: $($_.Exception.Message)") }
    if ($problems.Count) {
        # Fail closed: nothing reaches tvnserver from the tailnet until setup passes.
        Remove-Item -LiteralPath $script:VncStateFile -Force -ErrorAction SilentlyContinue
        $c = Close-VncAccess
        throw "$($problems -join '; '). VNC closed again ($($c.Notes -join '; '))"
    }
    if ("$((Get-NetFirewallRule -Name $script:VncFirewallRule).Enabled)" -ne 'True') { Close-VncAccess | Out-Null; throw 'VNC allow rule did not enable' }
    # Recorded only now, so the startup guard trusts an address only after a passing check.
    $json = @{ TailscaleIPv4 = $ip; SetUtc = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ') } | ConvertTo-Json -Compress
    [IO.File]::WriteAllText($script:VncStateFile, $json, (New-Object Text.UTF8Encoding $false))
    "proxy only ${ip}:5900 -> 127.0.0.1:5901; tvnserver on loopback 5901 only; nothing on 5800; password required on 127.0.0.1:5901 and ${ip}:5900 (no None, also inside Tight); allow rule on; address recorded for the startup guard"
}

function Step-OffSwitch {
    $target = Join-Path $script:DataDir 'disconnect.ps1'
    foreach ($f in 'disconnect.ps1', 'vnc-common.ps1') {
        Copy-Item -Force (Join-Path $PSScriptRoot $f) (Join-Path $script:DataDir $f)
        if ((Get-FileHash (Join-Path $PSScriptRoot $f)).Hash -ne (Get-FileHash (Join-Path $script:DataDir $f)).Hash) { throw "$f copy does not match" }
    }
    # It runs elevated, so only SYSTEM and Administrators may change it (the folder is locked too).
    $lnk = Join-Path $env:PUBLIC 'Desktop\Disconnect remote access.lnk'
    $shell = New-Object -ComObject WScript.Shell
    $s = $shell.CreateShortcut($lnk)
    $s.TargetPath = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $s.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$target`""
    $s.Description = 'Stops Tailscale, SSH, TightVNC (and its port proxy) and RustDesk so no one can connect remotely'
    $s.Save()
    if (-not (Test-Path $lnk)) { throw 'shortcut not created' }
    # The shortcut starts an elevated script, so users may run it but not change where it points.
    Invoke-Native icacls.exe @($lnk, '/inheritance:r', '/grant:r', "*$($script:SidAdministrators):F", '/grant:r', "*$($script:SidSystem):F", '/grant:r', '*S-1-5-32-545:RX') | Out-Null
    "public desktop shortcut -> $target (stops and disables Tailscale, sshd, TightVNC, RustDesk and removes the VNC port proxy; Syncthing keeps running)"
}

function Step-BootProbe {
    $target = Join-Path $script:DataDir 'boot-probe.ps1'
    foreach ($f in 'boot-probe.ps1', 'verify-reboot.ps1', 'vnc-common.ps1', 'vnc-guard.ps1') {
        Copy-Item -Force (Join-Path $PSScriptRoot $f) (Join-Path $script:DataDir $f)
        if ((Get-FileHash (Join-Path $PSScriptRoot $f)).Hash -ne (Get-FileHash (Join-Path $script:DataDir $f)).Hash) { throw "$f copy does not match" }
    }
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$target`""
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    # Runs on battery too, and is stopped if it hangs.
    # The probe waits 3 minutes plus up to 6 for the guard, then checks: 20-minute limit.
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 20)
    Register-ScheduledTask -TaskName 'RiLaptop-BootProbe' -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    $t = Get-ScheduledTask -TaskName 'RiLaptop-BootProbe'
    if ($t.Principal.UserId -notmatch 'SYSTEM' -or "$($t.State)" -eq 'Disabled' -or $t.Settings.DisallowStartIfOnBatteries) { throw 'boot probe task did not read back as SYSTEM, enabled, battery allowed' }
    # The VNC guard: at startup, keep the port proxy only on the recorded Tailscale address.
    $guard = Join-Path $script:DataDir 'vnc-guard.ps1'
    $gAction = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$guard`""
    Register-ScheduledTask -TaskName 'RiLaptop-VncGuard' -Action $gAction -Trigger (New-ScheduledTaskTrigger -AtStartup) -Principal $principal -Settings $settings -Force | Out-Null
    $g = Get-ScheduledTask -TaskName 'RiLaptop-VncGuard'
    if ($g.Principal.UserId -notmatch 'SYSTEM' -or "$($g.State)" -eq 'Disabled') { throw 'VNC guard task did not read back as SYSTEM and enabled' }
    'scheduled tasks RiLaptop-BootProbe (writes boot-probe.jsonl) and RiLaptop-VncGuard (keeps the VNC proxy on the recorded Tailscale address, else removes it) run at startup as SYSTEM, no sign-in'
}

function Step-FinalServices {
    $names = @('Tailscale', 'sshd')
    $st = Find-SyncthingService
    $bad = @()
    if ($st) { $names += $st.Name } else { $bad += 'Syncthing (no service)' }
    $vnc = Find-VncService
    if ($vnc) { $names += $vnc.Name, 'iphlpsvc' } else { $bad += 'TightVNC (no service)' }
    if ($RustDeskPassword) { $names += 'RustDesk' }
    foreach ($n in $names) {
        $s = Get-Service -Name $n -ErrorAction SilentlyContinue
        if (-not $s -or $s.StartType -ne 'Automatic' -or $s.Status -ne 'Running') { $bad += $n }
    }
    if ($bad.Count) { throw "not Automatic+Running: $($bad -join ', ')" }
    "Automatic and Running: $($names -join ', '). Boot with no one signed in is NOT proven yet: reboot, do not sign in, then run verify-reboot.ps1"
}

function Invoke-Setup {
    Write-SetupLog "setup.ps1 start"
    $pre = Invoke-Step 'Preflight' { Step-Preflight; Initialize-DataDir }
    if ($pre.Status -eq 'FAIL') { return 1 }
    Invoke-Step 'Tailscale (unattended check)' { Step-Tailscale } | Out-Null
    $ssh = Invoke-Step 'OpenSSH Server' { Step-OpenSsh }
    if ($ssh.Status -eq 'PASS') {
        $key = Invoke-Step 'Admin key' { Step-AdminKey }
        # Turning password login off without a working key would leave no way in.
        if ($key.Status -eq 'PASS') { Invoke-Step 'sshd config' { Step-SshdConfig } | Out-Null }
        else { Invoke-Step 'sshd config' { 'SKIP: admin key step did not pass; password login left as it was' } | Out-Null }
    }
    # Even if OpenSSH failed, an existing allow-from-anywhere rule for port 22 must go.
    Invoke-Step 'SSH firewall' { Step-SshFirewall } | Out-Null
    Invoke-Step 'Power on AC' { Step-Power } | Out-Null
    Invoke-Step 'Update active hours' { Step-ActiveHours } | Out-Null
    $sync = Invoke-Step 'Syncthing service' { Step-Syncthing }
    if ($sync.Status -eq 'PASS') { Invoke-Step 'Brain folder (Syncthing)' { Step-Brain } | Out-Null }
    else { Invoke-Step 'Brain folder (Syncthing)' { throw 'Syncthing service step did not pass' } | Out-Null }
    Invoke-Step 'Obsidian' { Step-Obsidian } | Out-Null
    # Screen: firewall first, so tvnserver is never reachable beyond the tailnet.
    $vfw = Invoke-Step 'VNC firewall' { Step-VncFirewall }
    if ($vfw.Status -eq 'PASS') {
        $vnc = Invoke-Step 'TightVNC service' { Step-TightVnc }
        if ($vnc.Status -eq 'PASS') {
            $proxy = Invoke-Step 'VNC port proxy (Tailscale IPv4 only)' { Step-VncProxy }
            if ($proxy.Status -eq 'PASS') { Invoke-Step 'VNC listeners and password' { Step-VncCheck } | Out-Null }
            else { Invoke-Step 'VNC listeners and password' { throw 'port proxy step did not pass' } | Out-Null }
        } else { Invoke-Step 'VNC port proxy (Tailscale IPv4 only)' { throw 'TightVNC step did not pass; proxy not added' } | Out-Null }
    } else { Invoke-Step 'TightVNC service' { throw 'VNC firewall step did not pass; TightVNC not installed' } | Out-Null }
    $fw = Invoke-Step 'RustDesk firewall (before install)' { Step-RustDeskFirewall }
    if ($fw.Status -ne 'FAIL') { Invoke-Step 'RustDesk' { Step-RustDesk } | Out-Null }
    else { Invoke-Step 'RustDesk' { 'SKIP: its firewall rules failed, so it was not installed' } | Out-Null }
    Invoke-Step 'RustDesk firewall (after install)' { Step-RustDeskFirewall } | Out-Null
    Invoke-Step 'Off switch' { Step-OffSwitch } | Out-Null
    Invoke-Step 'Boot probe' { Step-BootProbe } | Out-Null
    Invoke-Step 'Services at the end' { Step-FinalServices } | Out-Null
    Write-Host ''
    $script:Results | Format-Table -AutoSize | Out-String | Write-Host
    $fails = @($script:Results | Where-Object Status -eq 'FAIL').Count
    Write-SetupLog "setup.ps1 end: $fails failed"
    if ($fails) {
        Write-Host "NOT DONE: $fails step(s) FAILED (see the list above). Leave this window open and send a photo of it to Elara." -ForegroundColor Red
        return 1
    }
    Write-Host 'Done. You can close this window.' -ForegroundColor Green
    return 0
}

# Dot-sourcing (tests) loads the functions only.
if ($MyInvocation.InvocationName -ne '.') { exit (Invoke-Setup) }
