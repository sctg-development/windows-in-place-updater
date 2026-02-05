# windows-in-place-updater ✅

A small interactive PowerShell helper to perform in-place upgrades of Windows installations outside the standard Microsoft update channel.

## What it does 🔧

- Guides the user through selecting or providing Windows installation media (ISO or `sources\`).
- Can create a custom ISO from UUP Dump (download UUP files and convert them to an ISO) using UUP Dump + UUP Converter.
- Lets you select an image within the media and perform an in-place upgrade (standard or with a pre-installed product key).
- Includes safety checks (signature verification for setup.exe, SHA256 checks for downloaded helper tools).

## Important notes ⚠️

> **This script does NOT activate Windows.** You must already have a valid license for the **target edition** you install. Using this tool without a proper license may violate Microsoft's terms.

- The script requires Administrator privileges (it will relaunch itself elevated when needed).
- A reliable internet connection and about 10 GiB free space are recommended when creating ISOs from UUP Dump.
- The script attempts to verify downloaded helper binaries (aria2c, 7zr, UUP converter) using SHA256; always inspect and verify before trusting binaries.

## Prerequisites ✔️

- Windows (client or server)
- PowerShell (run the script using an elevated PowerShell session)
- Internet access for UUP downloads (when using the ISO creation feature)

## How to use ▶️

1. Clone or download this repository.
2. Open an elevated PowerShell prompt in the repository root.
3. Run:

```powershell
.\windows-in-place-updater.ps1
```

Follow the interactive menus to choose a source, create an ISO from UUP Dump, pick an image, and start setup.

## UUP & converter links 🔗

- UUP Dump: https://git.uupdump.net/uup-dump
- UUP Converter (uup-converter-wimlib / convert-UUP.cmd): https://github.com/abbodi1406/BatUtil/tree/master/uup-converter-wimlib

The script can automatically download and verify these helper tools when needed.

## Security & Legal 📜

Use this script at your own risk. Always back up important data before performing upgrades. This repository is provided as-is; it does not bypass licensing or activation requirements.

## License

This project is released under the MIT License. See `LICENSE.md` for details.
