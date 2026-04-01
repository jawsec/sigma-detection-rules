# MITRE ATT&CK Coverage Matrix

This matrix maps each Sigma rule in this pack to its corresponding MITRE ATT&CK technique. The "Gaps" section at the bottom documents known coverage gaps and planned additions.

## Coverage

| Rule | Tactic | Technique ID | Technique Name | Platform |
|------|--------|-------------|----------------|----------|
| Brute Force Authentication | Initial Access | T1110, T1110.001, T1110.003 | Brute Force / Password Guessing / Password Spraying | Windows |
| SSH Login from Unusual Source | Initial Access / Lateral Movement | T1078.004, T1021.004 | Cloud Accounts / Remote Services: SSH | Linux |
| New Windows Service Created | Persistence / Privilege Escalation | T1543.003, T1569.002 | Create or Modify System Process: Windows Service | Windows |
| Startup Folder File Drop | Persistence | T1547.001 | Boot or Logon Autostart: Registry Run Keys / Startup Folder | Windows |
| Cron Job Created or Modified | Persistence / Execution | T1053.003 | Scheduled Task/Job: Cron | Linux |
| Suspicious Sudo/Su Usage | Privilege Escalation | T1548.003, T1078.003 | Abuse Elevation Control: Sudo and Su / Local Accounts | Linux |
| User Added to Local Admins | Privilege Escalation / Persistence | T1098, T1136.001 | Account Manipulation / Create Account: Local | Windows |
| Windows Event Log Cleared | Defense Evasion | T1070.001 | Indicator Removal: Clear Windows Event Logs | Windows |
| Security Service Stopped | Defense Evasion | T1562.001 | Impair Defenses: Disable or Modify Tools | Windows |
| Timestomping Detected | Defense Evasion | T1070.006 | Indicator Removal: Timestomp | Windows |
| Cryptomining Pool Connection | Impact | T1496 | Resource Hijacking | Windows |
| API Key / Seed Phrase Exposure | Credential Access / Exfiltration | T1552.001, T1041 | Unsecured Credentials: Credentials in Files / Exfiltration Over C2 | Windows |
| Unauthorized Wallet/Miner Execution | Impact / Execution | T1496, T1204.002 | Resource Hijacking / User Execution: Malicious File | Windows |
| Crypto Drainer DNS Query | Initial Access / C2 | T1566.002, T1071.001 | Phishing: Spearphishing Link / Application Layer Protocol: Web | Windows |

## Tactics Covered (8 of 14)

- Initial Access
- Execution
- Persistence
- Privilege Escalation
- Defense Evasion
- Credential Access
- Exfiltration
- Impact

## Known Gaps

The following MITRE ATT&CK tactics are **not covered** by this rule pack. These are documented intentionally — 14 rules cannot cover the entire framework, and acknowledging gaps is more honest than pretending they don't exist.

| Tactic | Why It's Not Covered | Planned |
|--------|---------------------|---------|
| Reconnaissance | Requires external threat intel feeds, not host-based logs | Future |
| Resource Development | Happens outside the target environment — not observable from endpoint telemetry | No |
| Collection | Requires DLP-level monitoring beyond Sigma's typical scope | Future |
| Lateral Movement | Partially covered by SSH rule; full coverage needs network flow analysis | v2 |
| Command and Control | Partially covered by crypto drainer DNS rule; beacon detection is complex | v2 |
| Discovery | High false positive rate — most discovery commands are also used legitimately | Under evaluation |
