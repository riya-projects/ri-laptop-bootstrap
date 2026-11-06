# Pester tests for install.ps1 on Linux pwsh. Nothing is downloaded: the fetcher reads the
# payload folder of this checkout. Run: pwsh -c 'Invoke-Pester -Path tests'

BeforeAll {
    $repo = Split-Path -Parent $PSScriptRoot
    foreach ($v in 'ProgramData', 'SystemRoot') { if (-not [Environment]::GetEnvironmentVariable($v)) { [Environment]::SetEnvironmentVariable($v, (Join-Path $TestDrive $v)) } }
    $RiBootstrapTest = $true
    . (Join-Path $repo 'install.ps1')
    $payload = Join-Path $repo 'payload'
    $script:fetched = New-Object System.Collections.Generic.List[string]
    $localFetch = { param($u) $script:fetched.Add($u); [IO.File]::ReadAllBytes((Join-Path $payload ($u -split '/')[-1])) }
}

Describe 'manifest' {
    It 'pins one full commit on raw.githubusercontent.com' {
        $script:PayloadCommit | Should -Match '^[0-9a-f]{40}$'
        $script:PayloadBase | Should -Be "https://raw.githubusercontent.com/riya-projects/ri-laptop-bootstrap/$($script:PayloadCommit)/payload"
    }
    It 'lists exactly the files in payload/, with their SHA-256' {
        $names = @(Get-ChildItem -File $payload | ForEach-Object Name | Sort-Object)
        @($script:Manifest.Keys | Sort-Object) | Should -Be $names
        foreach ($n in $names) { $script:Manifest[$n] | Should -Be (Get-FileHash -Algorithm SHA256 (Join-Path $payload $n)).Hash.ToLowerInvariant() }
    }
    It 'the payload holds scripts and the public key only' {
        foreach ($f in Get-ChildItem -File $payload) {
            $f.Name | Should -Match '\.(ps1|pub)$'
            Get-Content $f.FullName -Raw | Should -Not -Match 'PRIVATE KEY|ghp_|github_pat_|tskey-'
        }
    }
}

Describe 'hash check before anything runs' {
    BeforeEach { $script:fetched.Clear() }
    It 'returns every file when all hashes match' {
        $files = Get-VerifiedPayload -Base $script:PayloadBase -Manifest $script:Manifest -Fetch $localFetch
        $files.Count | Should -Be $script:Manifest.Count
        $script:fetched.Count | Should -Be $script:Manifest.Count
        foreach ($u in $script:fetched) { $u | Should -BeLike "$($script:PayloadBase)/*" }
    }
    It 'refuses any single changed byte in any file' {
        foreach ($target in $script:Manifest.Keys) {
            $script:target = $target
            $tamper = { param($u) $b = [IO.File]::ReadAllBytes((Join-Path $payload ($u -split '/')[-1])); if ($u.EndsWith("/$($script:target)")) { $b[0] = $b[0] -bxor 1 }; , $b }
            { Get-VerifiedPayload -Base $script:PayloadBase -Manifest $script:Manifest -Fetch $tamper } | Should -Throw "*TAMPERED or changed: $target*"
        }
    }
    It 'refuses an appended line, a failed download and an empty body' {
        $append = { param($u) $b = [IO.File]::ReadAllBytes((Join-Path $payload ($u -split '/')[-1])); if ($u.EndsWith('/setup.ps1')) { $b += [Text.Encoding]::ASCII.GetBytes("`nWrite-Host evil`n") }; , $b }
        { Get-VerifiedPayload -Base $script:PayloadBase -Manifest $script:Manifest -Fetch $append } | Should -Throw '*TAMPERED*setup.ps1*'
        { Get-VerifiedPayload -Base $script:PayloadBase -Manifest $script:Manifest -Fetch { throw '404' } } | Should -Throw '*download failed*'
        { Get-VerifiedPayload -Base $script:PayloadBase -Manifest $script:Manifest -Fetch { $null } } | Should -Throw '*download failed*'
    }
    It 'refuses an unpinned base URL' {
        { Get-VerifiedPayload -Base 'https://raw.githubusercontent.com/riya-projects/ri-laptop-bootstrap/main/payload' -Manifest $script:Manifest -Fetch $localFetch } | Should -Throw '*not pinned*'
    }
}

Describe 'Invoke-Bootstrap' {
    BeforeEach {
        Mock Write-Host { }
        Mock Test-IsAdmin { $true }
        Mock Protect-BootDir { }
        $script:BootDir = Join-Path $TestDrive "boot-$([guid]::NewGuid())"
        New-Item -ItemType Directory $script:BootDir | Out-Null
        $script:ran = $null
    }
    It 'a tampered file means nothing is written and setup never runs' {
        $tamper = { param($u) $b = [IO.File]::ReadAllBytes((Join-Path $payload ($u -split '/')[-1])); if ($u.EndsWith('/vnc-common.ps1')) { $b[-1] = $b[-1] -bxor 1 }; , $b }
        Invoke-Bootstrap -Fetch $tamper -RunSetup { param($p) $script:ran = $p; 0 } | Should -Be 1
        $script:ran | Should -BeNullOrEmpty
        Should -Invoke Protect-BootDir -Times 0 -Exactly
        @(Get-ChildItem $script:BootDir).Count | Should -Be 0
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'TAMPERED or changed: vnc-common.ps1' }
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'Done\. You can close' } -Times 0 -Exactly
    }
    It 'all hashes good: locks the folder, writes, re-checks, runs setup.ps1 and passes its exit code' {
        Invoke-Bootstrap -Fetch $localFetch -RunSetup { param($p) $script:ran = $p; 0 } | Should -Be 0
        $script:ran | Should -Be (Join-Path $script:BootDir 'setup.ps1')
        Should -Invoke Protect-BootDir -Times 1 -Exactly
        foreach ($n in $script:Manifest.Keys) { (Get-FileHash -Algorithm SHA256 (Join-Path $script:BootDir $n)).Hash.ToLowerInvariant() | Should -Be $script:Manifest[$n] }
        Invoke-Bootstrap -Fetch $localFetch -RunSetup { 1 } | Should -Be 1
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'FAIL  setup.ps1 exit code 1: NOT DONE' }
    }
    It 'runs the real setup process: its output reaches the window and only its exit code is returned' {
        $fake = Join-Path $TestDrive 'powershell.exe'
        Set-Content $fake "#!/bin/sh`necho 'PASS  step one'`necho 'NOT DONE: 1 step(s) FAILED'`nexit 3"
        chmod +x $fake
        $script:PowerShellExe = $fake
        $shown = New-Object System.Collections.Generic.List[string]
        Mock Out-Host { $shown.Add("$InputObject") }
        $r = @(Invoke-Bootstrap -Fetch $localFetch)
        $r.Count | Should -Be 1
        $r[0] | Should -Be 3
        $shown | Should -Contain 'NOT DONE: 1 step(s) FAILED'
        Should -Invoke Write-Host -ParameterFilter { "$Object" -match 'FAIL  setup.ps1 exit code 3: NOT DONE' }
    }
    It 'not elevated: nothing is fetched or run' {
        Mock Test-IsAdmin { $false }
        $script:fetched.Clear()
        Invoke-Bootstrap -Fetch $localFetch -RunSetup { param($p) $script:ran = $p; 0 } | Should -Be 1
        $script:fetched.Count | Should -Be 0
        $script:ran | Should -BeNullOrEmpty
    }
    It 'a file changed on disk after the check is caught before setup runs' {
        Mock Save-VerifiedPayload { throw 'TAMPERED on disk: setup.ps1; nothing was run' }
        Invoke-Bootstrap -Fetch $localFetch -RunSetup { param($p) $script:ran = $p; 0 } | Should -Be 1
        $script:ran | Should -BeNullOrEmpty
    }
    It 'Save-VerifiedPayload re-hashes from disk' {
        $files = Get-VerifiedPayload -Base $script:PayloadBase -Manifest $script:Manifest -Fetch $localFetch
        $bad = [ordered]@{}; foreach ($k in $files.Keys) { $bad[$k] = $files[$k] }
        $bad['setup.ps1'] = [Text.Encoding]::ASCII.GetBytes('x')
        { Save-VerifiedPayload -Dir $script:BootDir -Files $bad -Manifest $script:Manifest } | Should -Throw '*TAMPERED on disk: setup.ps1*'
    }
}

Describe 'bootstrap folder ACL (review r1)' {
    It 'accepts only an admin owner, cut inheritance and SYSTEM/Administrators entries' {
        Test-AdminOnlyAcl -OwnerSid 'S-1-5-32-544' -Protected $true -AllowSids @('S-1-5-18', 'S-1-5-32-544') | Should -BeTrue
        Test-AdminOnlyAcl -OwnerSid 'S-1-5-21-1-2-3-1009' -Protected $true -AllowSids @('S-1-5-18', 'S-1-5-32-544') | Should -BeFalse
        Test-AdminOnlyAcl -OwnerSid 'S-1-5-32-544' -Protected $false -AllowSids @('S-1-5-18', 'S-1-5-32-544') | Should -BeFalse
        Test-AdminOnlyAcl -OwnerSid 'S-1-5-32-544' -Protected $true -AllowSids @('S-1-5-18', 'S-1-5-32-545') | Should -BeFalse
        Test-AdminOnlyAcl -OwnerSid 'S-1-5-32-544' -Protected $true -AllowSids @() | Should -BeFalse
    }
    It 'moves aside a folder someone else made, and fails when the ACL does not read back' {
        foreach ($c in 'Get-Acl') { if (-not (Get-Command $c -ErrorAction SilentlyContinue)) { Set-Item -Path "function:global:$c" -Value { param([Parameter(ValueFromRemainingArguments)]$rest) } } }
        Mock Write-Host { }
        Mock Invoke-Icacls { }
        Mock Get-SidOf { if ("$Identity" -eq 'eve') { 'S-1-5-21-1-2-3-1009' } else { "$Identity" } }
        $script:BootRoot = Join-Path $TestDrive "root-$([guid]::NewGuid())"
        $script:BootDir = Join-Path $script:BootRoot 'bootstrap-1'
        New-Item -ItemType Directory $script:BootRoot -Force | Out-Null
        Set-Content (Join-Path $script:BootRoot 'planted.txt') 'planted'
        $script:owner = 'eve'
        Mock Get-Acl { $o = $script:owner; $script:owner = 'S-1-5-32-544'; [pscustomobject]@{ Owner = $o; AreAccessRulesProtected = $true; Access = @([pscustomobject]@{ AccessControlType = 'Allow'; IdentityReference = 'S-1-5-18'; IsInherited = $false }) } }
        Protect-BootDir
        Test-Path (Join-Path $script:BootRoot 'planted.txt') | Should -BeFalse
        @(Get-ChildItem -Directory (Split-Path $script:BootRoot) | Where-Object Name -like "$(Split-Path -Leaf $script:BootRoot).untrusted-*").Count | Should -Be 1
        Mock Get-Acl { [pscustomobject]@{ Owner = 'S-1-5-32-544'; AreAccessRulesProtected = $true; Access = @([pscustomobject]@{ AccessControlType = 'Allow'; IdentityReference = 'S-1-5-32-545'; IsInherited = $false }) } }
        $script:BootDir = Join-Path $script:BootRoot 'bootstrap-2'
        { Protect-BootDir } | Should -Throw '*not limited to SYSTEM and Administrators*'
    }
    It 'a link planted in the run folder stops the run and its target is untouched (review r2)' {
        Mock Write-Host { }
        Mock Invoke-Icacls { }
        Mock Get-SidOf { 'S-1-5-32-544' }
        Mock Get-Acl { [pscustomobject]@{ Owner = 'S-1-5-32-544'; AreAccessRulesProtected = $true; Access = @([pscustomobject]@{ AccessControlType = 'Allow'; IdentityReference = 'S-1-5-18'; IsInherited = $false }) } }
        $script:BootRoot = Join-Path $TestDrive "root-$([guid]::NewGuid())"
        $script:BootDir = Join-Path $script:BootRoot 'bootstrap-x'
        New-Item -ItemType Directory $script:BootDir -Force | Out-Null
        $victim = Join-Path $TestDrive "victim-$([guid]::NewGuid())"
        New-Item -ItemType Directory $victim | Out-Null
        Set-Content (Join-Path $victim 'keep.txt') 'keep'
        New-Item -ItemType SymbolicLink -Path (Join-Path $script:BootDir 'link') -Target $victim | Out-Null
        { Protect-BootDir } | Should -Throw '*not empty; nothing was run*'
        Test-Path (Join-Path $victim 'keep.txt') | Should -BeTrue
        # The root itself as a link is refused too.
        $script:BootRoot = Join-Path $TestDrive "rootlink-$([guid]::NewGuid())"
        New-Item -ItemType SymbolicLink -Path $script:BootRoot -Target $victim | Out-Null
        Mock Get-SidOf { 'S-1-5-32-544' }
        Mock Move-Item { throw 'moved' }
        { Protect-BootDir } | Should -Throw
        Test-Path (Join-Path $victim 'keep.txt') | Should -BeTrue
    }
    It 'every run uses a new folder name' {
        $script:BootDir | Should -Not -BeNullOrEmpty
        (Get-Content (Join-Path $repo 'install.ps1') -Raw) | Should -Match "'bootstrap-' \+ \[DateTime\]::UtcNow"
        (Get-Content (Join-Path $repo 'install.ps1') -Raw) | Should -Not -Match 'Remove-Item -Recurse'
    }
}

Describe 'no prompts' {
    It 'install.ps1 asks nothing and runs setup non-interactively' {
        $src = Get-Content (Join-Path $repo 'install.ps1') -Raw
        foreach ($bad in 'Read-Host', 'Get-Credential', 'PromptForChoice', 'ReadKey', '\bpause\b') { $src | Should -Not -Match $bad }
        $src | Should -Match '-NonInteractive -ExecutionPolicy Bypass -File \$setup'
        # It is run with iex in her window: it must never call exit.
        $src | Should -Not -Match '(?m)^\s*exit\b|[;{]\s*exit\b'
    }
    It 'install.ps1 is ASCII without a BOM (the one paste decodes it as ASCII and runs it)' {
        $b = [IO.File]::ReadAllBytes((Join-Path $repo 'install.ps1'))
        @($b | Where-Object { $_ -gt 127 }).Count | Should -Be 0
    }
}

Describe 'static checks' {
    It 'PSScriptAnalyzer finds no errors and only PowerShell 5.1 syntax in install.ps1' {
        if (-not (Get-Module -ListAvailable PSScriptAnalyzer)) { Set-ItResult -Skipped -Because 'PSScriptAnalyzer not installed'; return }
        $settings = @{
            Severity = @('Error', 'Warning')
            ExcludeRules = @('PSAvoidUsingWriteHost', 'PSUseShouldProcessForStateChangingFunctions', 'PSUseSingularNouns', 'PSAvoidUsingInvokeExpression')
            Rules = @{ PSUseCompatibleSyntax = @{ Enable = $true; TargetVersions = @('5.1') } }
        }
        $issues = Invoke-ScriptAnalyzer -Path (Join-Path $repo 'install.ps1') -Settings $settings
        ($issues | ForEach-Object { "$($_.Line) $($_.RuleName) $($_.Message)" }) -join "`n" | Should -BeNullOrEmpty
    }
}
