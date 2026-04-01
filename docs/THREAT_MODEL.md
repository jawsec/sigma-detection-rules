# Threat Model

## Target Environment

This rule pack is designed for home users, small businesses, and security teams who need practical detection coverage without the overhead of a commercial detection engineering team. The rules assume:

- A mixed Windows and Linux environment (most rules target Windows with Sysmon, some target Linux syslog)
- Sysmon is installed on Windows endpoints with a reasonable configuration (process creation, file events, DNS queries, and file creation time changes enabled)
- A SIEM is ingesting logs (Wazuh, Splunk, Elastic, Microsoft Sentinel, or similar)
- No dedicated SOC staff — alerts need to be high-confidence with low false positive rates to be actionable by a single admin or small team

## Why These Detections

The 14 rules in this pack were chosen based on three criteria:

1. **High frequency in real-world attacks.** Every technique covered here appears consistently in public incident reports, MITRE ATT&CK's "most commonly observed" data, and commodity malware analysis. These are not theoretical attacks — they happen daily.

2. **Observable from endpoint telemetry.** All rules can fire from standard log sources (Windows Security logs, Sysmon, Linux syslog). No network taps, packet captures, or expensive sensors required.

3. **Actionable at small scale.** Each rule has documented false positives and tuning guidance so a solo admin can deploy them without drowning in noise. Rules with inherently high false positive rates (like generic PowerShell logging) were intentionally excluded.

## The Crypto/Web3 Category

Most public Sigma rule repositories ignore cryptocurrency-specific threats entirely. This pack includes four rules targeting the crypto threat landscape because:

- Cryptojacking (unauthorized mining) is one of the most common post-compromise monetization strategies, and mining pool DNS queries are a near-zero false positive detection
- Wallet drainer phishing is the single largest source of consumer crypto theft, and DNS-level detection catches it before funds are lost
- API key and seed phrase exposure in command lines is a real and preventable credential theft vector
- Unauthorized wallet or miner software on managed endpoints is a policy violation at minimum and an active compromise indicator at worst

These rules are useful to anyone managing systems where cryptocurrency is relevant — from personal machines with wallet software to businesses that accept or hold crypto.

## What This Pack Does NOT Cover

This is not a comprehensive detection program. 14 rules cover 8 of 14 MITRE ATT&CK tactics. Notable gaps include lateral movement, advanced C2 beaconing, in-memory-only attacks, and data collection/staging. See [MITRE_COVERAGE.md](MITRE_COVERAGE.md) for a full gap analysis.

For monitoring that falls outside of SIEM log analysis — such as blockchain transaction monitoring and file integrity checking — see the companion project [vigil](https://github.com/jawsec/vigil).
