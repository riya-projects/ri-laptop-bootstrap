# ri-laptop-bootstrap

One paste sets up Ri's Windows laptop for remote access over Tailscale. It asks nothing.

Only a fixed list of scripts and one **public** SSH key are published here (`payload/`). The private repo's docs, tests and everything else stay private. No passwords or keys are in this repo: the VNC password is generated on the laptop.

## The one paste

Laptop on, plugged in, on Wi-Fi. Start > type **Terminal** > right-click > **Run as administrator** > Yes > paste this one line > Enter:

```powershell
[Net.ServicePointManager]::SecurityProtocol=3072;$b=(New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/riya-projects/ri-laptop-bootstrap/22cb0d67d60639f655b7adc57727e2e0ea0083fb/install.ps1');$h=-join([Security.Cryptography.SHA256]::Create().ComputeHash($b)|%{$_.ToString('x2')});if($h -eq '7404fc8c540a8738903b1463ae57365e088da25812ca4ba5a7bf23e5cb7b5836'){iex ([Text.Encoding]::ASCII.GetString($b))}else{Write-Host "FAIL: install.ps1 hash $h does not match; nothing was run" -ForegroundColor Red}
```

It prints PASS/FAIL per step. The last line is **Done. You can close this window.** only if nothing failed; otherwise **NOT DONE**.

## What is checked

| Item | Value |
|---|---|
| Bootstrap commit (install.ps1) | `22cb0d67d60639f655b7adc57727e2e0ea0083fb` |
| install.ps1 SHA-256 | `7404fc8c540a8738903b1463ae57365e088da25812ca4ba5a7bf23e5cb7b5836` |
| Payload commit | `d4438190945256f643336690a4879f58a3d10c5a` |

`install.ps1` holds the SHA-256 of every payload file and fetches them only from the payload commit. It checks every hash in memory before writing anything, writes the files into a new `C:\ProgramData\ri-laptop\bootstrap-<time>-<id>` folder each run (SYSTEM and Administrators only, read back, must be empty; earlier run folders are kept, never deleted recursively), hashes them again from disk, and only then runs `setup.ps1`. Any mismatch stops everything.

Payload SHA-256:

```
6beba9d625e1daaa65fefe1120a35d37e1dc7bc8dd56d06d4b13ade4a64f3d93  admin_key.pub
91d562e21e0c7198c7db886d1733c73e3a84e678b0d8d83e5f415e42f3cce23e  boot-probe.ps1
16677384f12e6f70881e4e493f1fc62a1e69037aeab8f5b8053572be38516b53  disconnect.ps1
7c60b264c961615d96380c70095781ce2381ecbedf27398958da75f569e43344  power-guard.ps1
acb830ee0bb713568cb062b6e722e61dc164b5b1d7abbbb11685cf24c8d1c18d  setup.ps1
aa8aa25c5d2f31820fd3d557752de98806c191a068e43b0b27a66da330fe73de  verify-reboot.ps1
356c14fc21afd4351eb3ed5e0f3909b405bbf136ecf86d3e830792ba96a946d0  vnc-common.ps1
82a9e007eaf396d3560e4a1e0b0c0abccab394023bc9b96cacba6434c2533713  vnc-guard.ps1
```

The simpler `irm https://raw.githubusercontent.com/riya-projects/ri-laptop-bootstrap/22cb0d67d60639f655b7adc57727e2e0ea0083fb/install.ps1 | iex` also works (the URL is pinned to a commit), but it skips the check of install.ps1 itself, so use the line above.

Earlier pinned commits (`08a30d75067c767226a21aed77bae682014d0a7c`, `04217aed63a329ceb3e17f055eaf5e195730012a`) stay as they were; only this line is current.

**Windows runtime: NOT RUN.** Tested on Linux only (Pester, `tests/`).

Payload source: `riya-projects/ri-laptop@075e3f5a7636f651311f78fd1ea89ef2ba17658f`. The fixed public file set now includes `power-guard.ps1`, required by setup to install the AC power guard. Battery settings are preserved by that guard.
