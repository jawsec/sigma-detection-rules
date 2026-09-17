# Threat model

## Environment and assets

Scope: managed Windows endpoints with Security and Sysmon logs, and Linux hosts
with sshd/sudo syslog and configured auditd cron watches. Assets of interest are
administrative access, persistence locations, endpoint telemetry integrity,
compute resources, and secrets that could be recorded in process logs.

This is a small experimental set for an administrator or security team able to
review and tune its signals. It does not assume that every selector is suitable
for unattended high-severity alerting. No measured precision, recall, noise
rate, or pre-loss prevention claim is available.

## Observable behaviors

| Concern | Observation | What remains unproven |
|---|---|---|
| Password attacks | Repeated network-logon failures on one Windows host | Attacker intent, password spraying versus guessing, successful compromise |
| Access and privilege use | Accepted SSH, sudo root requests, Administrators group changes | Unusual source, stolen credentials, unauthorized elevation |
| Persistence | Service-creation command, Startup file creation, watched cron operation | Successful service install, execution at logon, valid scheduled payload |
| Defense impairment / stealth | Security log clear, security-service stop command, creation-time change | Malicious intent, successful service stop, comprehensive timestamp tampering |
| Compute misuse | Selected pool DNS queries or miner indicators | Successful mining, resource consumption, authorization |
| Crypto-related hygiene / hunting | API-header marker or wallet-lure DNS keyword | Real secret, exfiltration, user click, drainer execution, transaction signing |

Mappings use [Enterprise ATT&CK](https://attack.mitre.org/tactics/enterprise/)
19.2 and are generated in [MITRE_COVERAGE.md](MITRE_COVERAGE.md). They describe
possible adversary behavior, not an attribution decision. No ATT&CK tag is
assigned to the header-marker and lure-keyword selectors because their events
do not establish the proposed credential-theft or phishing techniques.

## Trust and visibility limits

Endpoint and collector configuration determine what reaches a rule. An attacker
may disable collection, rename tools, encode commands, use APIs, modify files
through unmonitored mechanisms, or use private infrastructure. DNS-over-HTTPS,
direct IP use, caching, and non-Windows clients limit this DNS coverage. Logs can
arrive late, duplicate, truncate, or omit fields. A compromised host can also
make its own telemetry less trustworthy.

[Sysmon's event descriptions](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
define the sensors' scope. Event 2 observes creation-time changes, not every
filesystem timestamp. Event 22 records DNS queries; it is not a network-flow or
wallet-transaction sensor. Linux audit collection must be explicitly configured;
[auditctl](https://man7.org/linux/man-pages/man8/auditctl.8.html) documents the
watch and syscall mechanisms used here.

There is no behavioral baseline, reputation service, enrichment feed, or policy
inventory in this repository. "Authorized" must be established from the owner's
asset and change records. Source geography alone is not a compromise verdict.

## Overlap and omissions

[SigmaHQ already publishes mining DNS content](https://github.com/SigmaHQ/sigma/blob/2e8fd89f82d9104c1b30321a307254ddeea17de2/rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml).
This pack does not claim novelty or a gap that other rule packs ignore. Pool
operators' sites establish the selected domains' stated function, not maliciousness;
see [INDICATORS.md](INDICATORS.md). Lure keywords are not a threat-intelligence feed.

Not covered comprehensively: credential dumping, discovery, lateral movement,
C2, collection, exfiltration, in-memory activity, cloud identity abuse, browser
extensions, smart-contract behavior, and on-chain transfers. Endpoint logs alone
cannot establish that a wallet was drained. No combination with another project
is claimed to cover a full kill chain.
