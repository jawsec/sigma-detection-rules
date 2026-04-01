# sigma-detection-rules

SIEM-agnostic detection rules written in Sigma. 14 rules covering 8 MITRE ATT&CK tactics, organized by attack phase, with a dedicated Crypto/Web3 Threats category you won't find in other public rule packs.

Built for home users, small businesses, and lean security teams who need real detection coverage without a dedicated detection engineering department.

## What's In Here

**Initial Access** — Brute force authentication, SSH login from unusual external sources

**Persistence** — New Windows service creation, startup folder file drops, cron job modifications

**Privilege Escalation** — Suspicious sudo/su usage, user added to local Administrators group

**Defense Evasion** — Event log clearing, security service tampering, timestomping

**Crypto/Web3 Threats** — Mining pool connections, API key and seed phrase exposure in process command lines, unauthorized wallet and miner execution, wallet drainer phishing DNS detection

Every rule includes MITRE ATT&CK mapping, false positive documentation, severity reasoning, and a step-by-step lab testing methodology so you can validate it before deploying.

## Quick Start

These are Sigma rules (YAML). They work with any SIEM that supports Sigma conversion.

```bash
git clone https://github.com/jawsec/sigma-detection-rules.git
cd sigma-detection-rules

# Install sigma-cli
pip install sigma-cli

# Convert to Splunk
sigma plugin install splunk
sigma convert -t splunk rules/

# Convert to Elastic
sigma plugin install elasticsearch
sigma convert -t elasticsearch rules/

# Convert to Microsoft Sentinel
sigma plugin install microsoft365defender
sigma convert -t microsoft365defender rules/
```

See [docs/SIEM_CONVERSION.md](docs/SIEM_CONVERSION.md) for full conversion instructions including Wazuh, bulk export, and pipeline configuration.

## Repo Structure

```
sigma-detection-rules/
├── rules/
│   ├── initial-access/
│   │   ├── brute_force_authentication.yml
│   │   └── ssh_login_unusual_source.yml
│   ├── persistence/
│   │   ├── new_windows_service_created.yml
│   │   ├── startup_folder_file_drop.yml
│   │   └── cron_job_created_modified.yml
│   ├── privilege-escalation/
│   │   ├── suspicious_sudo_su_usage.yml
│   │   └── user_added_local_admins.yml
│   ├── defense-evasion/
│   │   ├── event_log_cleared.yml
│   │   ├── security_service_stopped.yml
│   │   └── timestomping_detected.yml
│   └── crypto-web3-threats/
│       ├── cryptomining_pool_connection.yml
│       ├── api_key_seed_phrase_exposure.yml
│       ├── unauthorized_wallet_miner_execution.yml
│       └── crypto_drainer_dns_query.yml
└── docs/
    ├── THREAT_MODEL.md
    ├── MITRE_COVERAGE.md
    └── SIEM_CONVERSION.md
```

## MITRE ATT&CK Coverage

| Tactic | Rules | Key Techniques |
|--------|-------|----------------|
| Initial Access | 2 | T1110 (Brute Force), T1078 (Valid Accounts) |
| Persistence | 3 | T1543.003 (Windows Service), T1547.001 (Startup), T1053.003 (Cron) |
| Privilege Escalation | 2 | T1548.003 (Sudo/Su), T1098 (Account Manipulation) |
| Defense Evasion | 3 | T1070.001 (Log Clearing), T1562.001 (Disable Tools), T1070.006 (Timestomp) |
| Crypto/Web3 | 4 | T1496 (Cryptojacking), T1552.001 (Credential Exposure), T1566.002 (Phishing) |

Full coverage matrix with gap analysis: [docs/MITRE_COVERAGE.md](docs/MITRE_COVERAGE.md)

## Why a Crypto/Web3 Category

Most public detection rule repositories don't cover cryptocurrency-specific threats at all. This pack includes four rules targeting the crypto threat landscape because cryptojacking, wallet drainers, and credential theft are real and growing attack vectors that standard detection packs ignore. If you hold crypto, work in Web3, or manage systems where users interact with blockchain services, these rules fill a gap nothing else covers.

Read the full reasoning: [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md)

## Companion Project

This rule pack covers threats visible in SIEM logs. For threats that don't show up in Sysmon — blockchain transaction monitoring, file integrity checking, and network threat feeds — see [vigil](https://github.com/jawsec/vigil).

Together they cover the full kill chain: Sigma catches the attack, vigil catches the impact.

## Requirements

- [sigma-cli](https://github.com/SigmaHQ/sigma-cli) for SIEM conversion
- Sysmon on Windows endpoints (recommended: [SwiftOnSecurity config](https://github.com/SwiftOnSecurity/sysmon-config) as a starting point)
- A SIEM that ingests the relevant log sources (Wazuh, Splunk, Elastic, Sentinel, etc.)

## License

MIT — see [LICENSE](LICENSE).

---

Built by [jawsec](https://github.com/jawsec) | Kino Security LLC
