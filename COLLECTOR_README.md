# Cerberus Collector — how a scan works

One file, three steps: **collect → analyse → upload a small results package.**

## What you need

- `CerberusCollector.exe` (build it once with `build_windows.bat`, or ask your
  provider for the file)
- Any ordinary domain user account (no admin rights needed for collection)
- A machine inside the network that can reach a domain controller

## Run it

```
CerberusCollector.exe --dc 192.168.1.10 --user "DOMAIN\user"
```

It asks for the password at a prompt (nothing is stored). Add
`--skip-remote` for a faster scan that skips per-machine session data.

## What you get

| File | What it is |
|---|---|
| `CerberusScan-<domain>-<date>.json` | The scan package — upload this in the dashboard under **Clients → Add Scan** |
| `report.html` | The full local report (yours to keep, no upload needed) |
| `remediation.ps1` | Ready PowerShell fixes, every command in safe `-WhatIf` preview mode |

## Privacy

The raw directory data (`collected.json`) is processed in a temporary folder
on **your** machine and deleted when the run finishes. It is never uploaded.
Only the findings summary — the scan package — goes to the dashboard.

## Re-package an old collection

Already have a `collected.json` from an earlier run?

```
CerberusCollector.exe --from-collected collected.json
```
