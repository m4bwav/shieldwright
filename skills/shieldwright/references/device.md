# Device checks

`SW device` (Windows, no admin, about 3 s) prints ok / FIX / ?? per check; `--json` for the raw values. Checked on Windows 11 Home 2026-11-21.

| Check | Source | FIX means |
|---|---|---|
| Defender realtime, signature age (<= 3 days), tamper protection | Get-MpComputerStatus | Windows Security, Virus and threat protection. "unavailable" usually means another antivirus owns it: ask which. |
| Firewall per profile | Get-NetFirewallProfile | turn the off profile on in Windows Security, Firewall |
| Last Windows update | Microsoft.Update.Session history | Settings, Windows Update; older than a month is a FIX in conversation |
| Drive encryption | Shell System.Volume.BitLockerProtection (the BitLocker cmdlets need admin) | "not available": Windows Home has Device encryption only on supported hardware; say so, no FIX. "off": Settings, Privacy and security, Device encryption |
| UAC | registry EnableLUA | must be 1 |
| SMB1 server | registry | turn off the SMB 1.0 Windows feature |
| Remote desktop | registry fDenyTSConnections | off unless the user uses it on purpose |

The BitLockerProtection value map (1 on, 2 off, 3 encrypting, 0 not available) comes from community sources, not Microsoft docs; the value 0 was seen on a Home box without Device encryption.

Not covered by sw.py (ask or guide): router admin password and firmware, Wi-Fi WPA2/WPA3, a backup that is offline or versioned, macOS (FileVault, Firewall, automatic updates in System Settings), phones (OS updates, screen lock, Find My).
