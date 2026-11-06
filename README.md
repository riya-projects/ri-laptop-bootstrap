# ri-laptop-bootstrap

One paste sets up Ri's Windows laptop for remote access over Tailscale. It asks nothing.

Only a fixed list of scripts and one **public** SSH key are published here (`payload/`). The private repo's docs, tests and everything else stay private. No passwords or keys are in this repo: the VNC password is generated on the laptop.

## The one paste

Laptop on, plugged in, on Wi-Fi. Start > type **Terminal** > right-click > **Run as administrator** > Yes > paste this one line > Enter:

```powershell
[Net.ServicePointManager]::SecurityProtocol=3072;$b=(New-Object Net.WebClient).DownloadData('https://raw.githubusercontent.com/riya-projects/ri-laptop-bootstrap/04217aed63a329ceb3e17f055eaf5e195730012a/install.ps1');$h=-join([Security.Cryptography.SHA256]::Create().ComputeHash($b)|%{$_.ToString('x2')});if($h -eq '5fbbb447d63cce052cddd6f7b51c5fe5743f64e025f2b39614c5776c80efa46e'){iex ([Text.Encoding]::ASCII.GetString($b))}else{Write-Host "FAIL: install.ps1 hash $h does not match; nothing was run" -ForegroundColor Red}
```

It prints PASS/FAIL per step. The last line is **Done. You can close this window.** only if nothing failed; otherwise **NOT DONE**.

## What is checked

| Item | Value |
|---|---|
| Bootstrap commit (install.ps1) | `04217aed63a329ceb3e17f055eaf5e195730012a` |
| install.ps1 SHA-256 | `5fbbb447d63cce052cddd6f7b51c5fe5743f64e025f2b39614c5776c80efa46e` |
| Payload commit | `0c70d6d09b1ca8b9ff4153bdf3cf5d4b2c7fad30` |

`install.ps1` holds the SHA-256 of every payload file and fetches them only from the payload commit. It checks every hash in memory before writing anything, writes the files into a new `C:\ProgramData\ri-laptop\bootstrap-<time>-<id>` folder each run (SYSTEM and Administrators only, read back, must be empty; earlier run folders are kept, never deleted recursively), hashes them again from disk, and only then runs `setup.ps1`. Any mismatch stops everything.

Payload SHA-256:

```
6beba9d625e1daaa65fefe1120a35d37e1dc7bc8dd56d06d4b13ade4a64f3d93  admin_key.pub
91d562e21e0c7198c7db886d1733c73e3a84e678b0d8d83e5f415e42f3cce23e  boot-probe.ps1
eba08a0de49aa57afe5d5c0ffd414b5c0874b43d34a7ea928d502dec249845ea  disconnect.ps1
f36147ade01015e44eb481dbac29753288fa44c3b1131aaaae9ac1f779ad87ea  setup.ps1
aa8aa25c5d2f31820fd3d557752de98806c191a068e43b0b27a66da330fe73de  verify-reboot.ps1
b51ed99ed14b3e51b2e41b373bde82d0953910c44ca672f29dc5763b0eb39031  vnc-common.ps1
82a9e007eaf396d3560e4a1e0b0c0abccab394023bc9b96cacba6434c2533713  vnc-guard.ps1
```

The simpler `irm https://raw.githubusercontent.com/riya-projects/ri-laptop-bootstrap/04217aed63a329ceb3e17f055eaf5e195730012a/install.ps1 | iex` also works (the URL is pinned to a commit), but it skips the check of install.ps1 itself, so use the line above.

**Windows runtime: NOT RUN.** Tested on Linux only (Pester, `tests/`).
