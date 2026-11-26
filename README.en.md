# Windows Miner Audit

**Understand suspicious Windows activity before changing anything.**

[Русский](README.ru.md) · [Bilingual home](README.md) · Python 3.10+ · Windows 10/11 · No third-party Python packages

Windows Miner Audit is a lightweight, read-only triage tool inspired by a real investigation involving disguised miners, malicious scheduled tasks, broad Defender exclusions and blocked security websites. It produces a self-contained HTML report and machine-readable JSON. It does not delete files, stop processes, change Defender settings or upload data.

> This is a heuristic audit, not an antivirus or a certificate that a computer is clean. A legitimate miner can match the mining rule. Configuration findings need human review.

## Quick start

1. Install Python 3.10 or newer from [python.org](https://www.python.org/downloads/windows/), with Python available on PATH.
2. Download or clone this repository and extract it to a folder.
3. Double-click `Start-Audit.cmd` for a Russian report, or open a terminal in this folder:

```powershell
python audit.py --lang en
```

Open the HTML path printed in the terminal. Reports are stored in `reports/`; each run uses a unique filename. A normal terminal works, but protected processes and some security settings may be inaccessible. For broader coverage, use a terminal opened as administrator. Errors remain visible as **incomplete**, never silently interpreted as a clean result.

The collector runs Windows PowerShell with a process-scoped execution-policy bypass. It does not change the machine's execution policy. Do not disable antivirus protection to run this tool.

## What it checks

| Area | Signals | Interpretation |
|---|---|---|
| Running processes | Pool endpoint **and** mining tuning arguments | Strong mining indication; verify authorization |
| Process identity | Familiar executable name, unusual writable location and untrusted signature | Corroborated impersonation heuristic |
| Persistence | Scheduled tasks and Run/RunOnce references to known suspicious path patterns or mining commands | Disabled references are informational; running processes are never exempted by a folder name |
| Defender | Effective and policy exclusions; realtime/script/tamper protection | Broad exclusions and disabled protection need review |
| Hosts | Active redirects affecting security and update domains | Could be deliberate filtering; comments are ignored |
| Folder permissions | Explicit write-deny ACLs on selected antivirus directories | Can obstruct installation; never automatically reset |
| Remote access | RDP configuration and port 3389 listener | Informational exposure, not a malware verdict |
| Storage | Local fixed drives with under 2 GB free | Possible performance or installation problem |

Rules do not classify every unsigned app, Steam subprocess, VPN driver, optimizer setting or high-CPU process as malware. The tool does not inspect passwords, browser profiles, file contents across the disk, network payloads, kernel memory or all possible persistence methods. It does not detect every miner, rootkit or remote-access tool. Reports show coverage and collection errors.

## CLI and results

```powershell
python audit.py --lang ru --output reports --timeout 90
python audit.py --snapshot examples/suspicious.json --output reports/demo --lang en
python -m unittest discover -s tests -v
```

`--snapshot` analyzes an existing schema-v1 JSON instead of the live computer. The included example is entirely synthetic. Offline analysis and tests also run on Linux/macOS; live collection requires Windows PowerShell 5.1 with the standard CIM, ScheduledTasks, Defender and NetTCPIP modules.

| Exit code | Meaning |
|---|---|
| 0 | No active high/warning rule matches; informational findings may exist |
| 1 | Active findings need review |
| 2 | Collection incomplete, invalid input, timeout or another execution failure |

`status` is `no_rule_matches`, `attention` or `incomplete`. Severity is a review priority, not an antivirus confidence score. A timed-out collector preserves completed sections when available; missing sections are explicitly listed. A collector that fails before the first checkpoint cannot produce an inspection report.

## Reviewing findings safely

Verify the executable path, signature, installation source and related persistence together. Preserve a report before making changes. For an unknown miner, disconnect unnecessary network access and seek a second opinion using trusted security software. Do not indiscriminately delete Windows files or reset all permissions. Corporate policy, another antivirus or privacy choices can explain some findings.

Reports stay local and have no remote images, scripts or analytics. Common command-line secrets and usernames in standard profile paths are redacted, but **redaction is incomplete by design**: custom paths, task names and unusual secret formats may remain. Review every report before sharing it. Raw investigation files and personal logs do not belong in this repository.

## Development

`audit.py` contains pure detection/reporting functions and the CLI; `collect.ps1` only reads Windows state. Tests exercise detection, benign cases, inactive references, policy exclusions, HTML escaping, redaction, report output and exit codes. CI runs on Windows and Linux. No administrator rights or live malware are required for unit tests.

For security reports, see [SECURITY.md](SECURITY.md). MIT license. Independent project; not affiliated with Microsoft.
