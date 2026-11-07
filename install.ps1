# One-paste installer for Ri's laptop. Paste the one line from README.md into
# Terminal (Admin). It asks nothing.
#
# Every file below is fetched from one fixed commit of this public repo and its SHA-256 is
# checked in memory before anything is written or run. Any mismatch, missing file or failed
# download stops everything: nothing is run. The files are written into a folder that only
# SYSTEM and Administrators can change, hashed again on disk, and only then is setup.ps1 run.

$script:PayloadCommit = 'd4438190945256f643336690a4879f58a3d10c5a'
$script:PayloadBase = "https://raw.githubusercontent.com/riya-projects/ri-laptop-bootstrap/$($script:PayloadCommit)/payload"
# File name -> SHA-256 (lowercase hex). The list is the whole payload: nothing else is fetched.
$script:Manifest = [ordered]@{
    'admin_key.pub' = '6beba9d625e1daaa65fefe1120a35d37e1dc7bc8dd56d06d4b13ade4a64f3d93'
    'boot-probe.ps1' = '91d562e21e0c7198c7db886d1733c73e3a84e678b0d8d83e5f415e42f3cce23e'
    'disconnect.ps1' = '16677384f12e6f70881e4e493f1fc62a1e69037aeab8f5b8053572be38516b53'
    'power-guard.ps1' = '7c60b264c961615d96380c70095781ce2381ecbedf27398958da75f569e43344'
    'setup.ps1' = 'acb830ee0bb713568cb062b6e722e61dc164b5b1d7abbbb11685cf24c8d1c18d'
    'verify-reboot.ps1' = 'aa8aa25c5d2f31820fd3d557752de98806c191a068e43b0b27a66da330fe73de'
    'vnc-common.ps1' = '356c14fc21afd4351eb3ed5e0f3909b405bbf136ecf86d3e830792ba96a946d0'
    'vnc-guard.ps1' = '82a9e007eaf396d3560e4a1e0b0c0abccab394023bc9b96cacba6434c2533713'
}
$script:BootRoot = Join-Path $env:ProgramData 'ri-laptop'
# A new folder every run, so nothing old is reused or deleted recursively.
$script:BootDir = Join-Path $script:BootRoot ('bootstrap-' + [DateTime]::UtcNow.ToString('yyyyMMddHHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$script:SidSystem = 'S-1-5-18'
$script:PowerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$script:SidAdministrators = 'S-1-5-32-544'

function Get-Sha256Hex {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return (-join ($sha.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') })) } finally { $sha.Dispose() }
}

function Get-RemoteBytes {
    param([string]$Url)
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $wc = New-Object Net.WebClient
    try { return , $wc.DownloadData($Url) } finally { $wc.Dispose() }
}

function Get-VerifiedPayload {
    <# Downloads every manifest file and checks its hash. Returns name -> bytes only if all match;
       throws on the first problem, before anything is written. #>
    param([string]$Base, [System.Collections.IDictionary]$Manifest, [scriptblock]$Fetch = { param($u) Get-RemoteBytes -Url $u })
    if ($Base -notmatch '^https://raw\.githubusercontent\.com/riya-projects/ri-laptop-bootstrap/[0-9a-f]{40}/payload$') { throw "payload URL is not pinned to a commit: $Base" }
    if (-not $Manifest.Count) { throw 'empty manifest' }
    $files = [ordered]@{}
    foreach ($name in $Manifest.Keys) {
        if ($name -notmatch '^[A-Za-z0-9][A-Za-z0-9._-]*$') { throw "bad file name in manifest: $name" }
        $url = "$Base/$name"
        try { $bytes = [byte[]](& $Fetch $url) } catch { throw "download failed: $name ($($_.Exception.Message))" }
        if ($null -eq $bytes) { throw "download failed: $name (empty)" }
        $got = Get-Sha256Hex -Bytes $bytes
        if ($got -ne "$($Manifest[$name])".ToLowerInvariant()) { throw "TAMPERED or changed: $name has SHA-256 $got, expected $($Manifest[$name]); nothing was run" }
        $files[$name] = $bytes
    }
    return $files
}

function Invoke-Icacls {
    param([string[]]$ArgumentList)
    $out = & icacls.exe @ArgumentList 2>&1 | Out-String
    if ($LASTEXITCODE -ne 0) { throw "icacls failed ($LASTEXITCODE): $($out.Trim())" }
}

function Get-SidOf {
    param($Identity)
    try { return (New-Object Security.Principal.NTAccount "$Identity").Translate([Security.Principal.SecurityIdentifier]).Value } catch { return "$Identity" }
}

function Test-AdminOnlyAcl {
    <# True only if the owner is SYSTEM or Administrators, inheritance is cut, and every Allow
       entry is SYSTEM or Administrators. #>
    param([string]$OwnerSid, [bool]$Protected, [string[]]$AllowSids)
    $ok = @($script:SidSystem, $script:SidAdministrators)
    if (-not $Protected -or $ok -notcontains $OwnerSid -or -not @($AllowSids).Count) { return $false }
    foreach ($sid in $AllowSids) { if ($ok -notcontains $sid) { return $false } }
    return $true
}

function Protect-BootDir {
    <# C:\ProgramData\ri-laptop\bootstrap: inheritance cut, SYSTEM and Administrators full
       control only, read back, so no standard user can swap a file between check and run.
       A folder someone else made first (owner not SYSTEM or Administrators, or a link) may
       hold rights or open handles that an ACL change does not take back: it is moved aside. #>
    foreach ($d in @($script:BootRoot, $script:BootDir)) {
        if (Test-Path -LiteralPath $d) {
            $item = Get-Item -LiteralPath $d -Force
            $owner = Get-SidOf (Get-Acl -LiteralPath $d).Owner
            if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or @($script:SidSystem, $script:SidAdministrators) -notcontains $owner) {
                $aside = "$d.untrusted-$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))-$([guid]::NewGuid().ToString('N').Substring(0, 8))"
                Move-Item -LiteralPath $d -Destination $aside
                Write-Host "WARN  $d was made by someone else; moved aside to $aside"
            }
        }
        if (-not (Test-Path -LiteralPath $d)) {
            New-Item -ItemType Directory -Path $d | Out-Null
            # Made by this elevated run, so owned by Administrators or SYSTEM; else someone raced us.
            if (@($script:SidSystem, $script:SidAdministrators) -notcontains (Get-SidOf (Get-Acl -LiteralPath $d).Owner)) { throw "$d was made by someone else while this ran; nothing was run" }
        }
        if ((Get-Item -LiteralPath $d -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "$d is a link or junction; nothing was run" }
        Invoke-Icacls @($d, '/setowner', "*$($script:SidAdministrators)", '/L', '/Q')
        Invoke-Icacls @($d, '/inheritance:r', '/grant:r', "*$($script:SidAdministrators):(OI)(CI)F", '/grant:r', "*$($script:SidSystem):(OI)(CI)F", '/L', '/Q')
        foreach ($e in @((Get-Acl -LiteralPath $d).Access | Where-Object { -not $_.IsInherited })) {
            $sid = Get-SidOf $e.IdentityReference
            if (@($script:SidSystem, $script:SidAdministrators) -notcontains $sid) { Invoke-Icacls @($d, '/remove:g', "*$sid", '/L', '/Q') }
        }
        $acl = Get-Acl -LiteralPath $d
        $allow = @($acl.Access | Where-Object { "$($_.AccessControlType)" -eq 'Allow' } | ForEach-Object { Get-SidOf $_.IdentityReference })
        if (-not (Test-AdminOnlyAcl -OwnerSid (Get-SidOf $acl.Owner) -Protected $acl.AreAccessRulesProtected -AllowSids $allow)) { throw "$d is not limited to SYSTEM and Administrators; nothing was run" }
    }
    # The run folder is new: anything in it (for example a link made in the moment before its
    # ACL was cut) means someone raced us. Nothing is deleted or followed; the run stops.
    if (@(Get-ChildItem -LiteralPath $script:BootDir -Force).Count) { throw "$($script:BootDir) is not empty; nothing was run" }
}

function Save-VerifiedPayload {
    <# Writes the checked bytes and hashes them again from disk. #>
    param([string]$Dir, [System.Collections.IDictionary]$Files, [System.Collections.IDictionary]$Manifest)
    foreach ($name in $Files.Keys) { [IO.File]::WriteAllBytes((Join-Path $Dir $name), $Files[$name]) }
    foreach ($name in $Manifest.Keys) {
        $disk = Get-Sha256Hex -Bytes ([IO.File]::ReadAllBytes((Join-Path $Dir $name)))
        if ($disk -ne "$($Manifest[$name])".ToLowerInvariant()) { throw "TAMPERED on disk: $name; nothing was run" }
    }
}

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-Bootstrap {
    param([scriptblock]$Fetch = { param($u) Get-RemoteBytes -Url $u }, [scriptblock]$RunSetup = $null)
    $ErrorActionPreference = 'Stop'
    try {
        if (-not (Test-IsAdmin)) { throw 'not running as administrator: Start > type Terminal > right-click > Run as administrator, then paste again' }
        $files = Get-VerifiedPayload -Base $script:PayloadBase -Manifest $script:Manifest -Fetch $Fetch
        Write-Host "PASS  download: $($files.Count) files, every SHA-256 matches commit $($script:PayloadCommit.Substring(0, 12))"
        Protect-BootDir
        Save-VerifiedPayload -Dir $script:BootDir -Files $files -Manifest $script:Manifest
        $setup = Join-Path $script:BootDir 'setup.ps1'
        if ($RunSetup) { $code = & $RunSetup $setup }
        else {
            $ps = $script:PowerShellExe
            # Out-Host: setup's PASS/FAIL list goes to the window, not into this function's result.
            & $ps -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $setup | Out-Host
            $code = $LASTEXITCODE
        }
        # setup.ps1 prints its PASS/FAIL list and, only when nothing failed, the Done line.
        if ($code -ne 0) { Write-Host "FAIL  setup.ps1 exit code $($code): NOT DONE. Leave this window open and send a photo of it to Elara." -ForegroundColor Red }
        return $code
    } catch {
        Write-Host "FAIL  $($_.Exception.Message)" -ForegroundColor Red
        Write-Host 'NOT DONE. Nothing more was run. Leave this window open and send a photo of it to Elara.' -ForegroundColor Red
        return 1
    }
}

# Tests set $RiBootstrapTest before dot-sourcing, so only the functions load.
if (-not (Get-Variable -Name RiBootstrapTest -ValueOnly -ErrorAction SilentlyContinue)) { Invoke-Bootstrap | Out-Null }
