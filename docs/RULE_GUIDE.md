# Rule guide and lab requirements

All selectors and the correlation are experimental. The checks below are plans,
not executed tests or real telemetry samples. `tests/captures/manifest.json`
records the missing evidence. Low/informational content is for baselining or
hunting until a local enrichment or policy decision makes it actionable.

## Per-rule review

Names below are file stems under `rules/`, except the correlation.

| Selector | Likely benign sources and tuning | Important blind spots / lab TODO |
|---|---|---|
| `windows_failed_network_logon` | Typos, stale service accounts, authenticated scanners. Preserve machine accounts; investigate account/source/host context. | Enable Audit Logon failure; capture Security 4625 LogonType 3 with `IpAddress`. Test absent, empty, dash, loopback, IPv4, IPv6, and machine accounts. Other logon types and 4771/4776 are outside scope. This selector never counts. |
| `windows_repeated_network_logon_failures` (correlation) | NAT, proxies, shared scanners, stale credentials. Tune threshold per source/host class; do not suppress machine accounts globally. | Capture 9/10/11 failures, two hosts, two sources, multiple usernames, late/duplicate events, and a bucket-boundary burst. Splunk output uses fixed five-minute bins; distributed/slow attacks and split buckets evade it. |
| `sshd_accepted_authentication` | All normal SSH administration and automation. Build approved source/account/host baselines outside Sigma; use parsed IP/CIDR enrichment when available. | Capture accepted password/key/PAM messages and failed authentication. No external-source, geography, novelty, or Cloud Accounts claim. Authentication is observed, not subsequent commands. Message-format variants may be missed. |
| `windows_service_creation_command` | Installers, deployment agents, administrators. Correlate approved package/change and service image path. | Capture sc create and New-Service, failed attempts, and sc query/config as negatives. This rule excludes config deliberately. Compare System 7045 or Security 4697 to establish installation; service start is separate. Renames, API calls, encoded PowerShell, and altered spacing can evade it. |
| `startup_folder_file_drop` | Installers, approved login scripts, restored files. Tune approved target+writer+package, not all signed processes. | Capture Sysmon 11 for per-user and all-users paths, desktop.ini exclusion, and a similar path outside Startup. Redirected/localized paths need local review. Files may not be runnable; execution is not established. |
| `cron_path_write_auditd` | Package managers, configuration management, cron administration, attribute maintenance. Group by audit serial and review `auid`, `exe`, and associated PATH records. | Install watches below; capture successful write/attribute syscalls and a read-only listing. Watch must pre-exist; new paths, mount boundaries, audit loss, and key/parser changes cause misses. A write-capable syscall can leave file contents unchanged. |
| `sudo_command_as_root` | Normal administrator use, backups, Ansible and other automation. Tune command+user+host+change rather than usernames alone. | Capture root and non-root target commands and denied authentication. Sudo's message body and program identity must survive ingestion. No auditd rule is required for this syslog selector. No su coverage or proof of successful command completion. |
| `user_added_local_admins` | Provisioning, help-desk elevation, endpoint management. Review subject SID, member SID, destination host, and change authorization. | Enable Audit Security Group Management success. Capture Security 4732 for built-in SID S-1-5-32-544 and another local group. Test a non-English host. Adding a member normally already requires suitable privileges; the event is not an escalation exploit or account creation. |
| `windows_security_log_cleared` | Image preparation, approved lab resets, administrative maintenance. Scope exceptions to actor+host+time; preserve central logs. | Collect 1102 from Security on a disposable VM. Application-log clearing is a negative, not an alternative positive. Confirm collection survives the clear; no guarantee about forwarding order or delivery is made. |
| `security_service_stop_command` | Agent upgrades and maintenance. Verify real service names, change window, actor, process ancestry, and service state. | Capture commands directed at disposable test services, then review approved real-service telemetry. Compare nonsecurity stops and substring collisions such as Sense-related names. No stop-success claim; quoting, encoding, renamed binaries and APIs evade it. Do not stop production sensors for a test. |
| `file_creation_time_changed` | Installers, archive extraction, sync, backup restore, browser/OS updates. Baseline writer+target+signer and compare timestamps in a downstream hunt. | Capture Sysmon 2 for a temporary file, plus representative benign changes. No blanket setup.exe, svchost.exe, browser, or trusted-directory exclusions. Event 2 covers creation-time changes only, not all NTFS attributes or direct disk writes; the selector performs no age comparison. |
| `mining_pool_dns_query` | Authorized mining, pool-site browsing, DNS prefetch, threat research. Review query initiator, host policy, network flow and resource use; DNS alone is insufficient. | Capture Sysmon 22, including apex, subdomain, trailing-dot, mixed-case and suffix-lookalike names. Do not confuse a failed lookup with a connection. Direct IPs, other pools, caching, DoH visibility gaps and other operating systems are outside scope. |
| `curl_binance_api_header` | Authorized API scripts, test keys and examples. Review secret handling without copying captured keys into tickets. Empty/test header values may match intentionally. | Capture curl with an obviously fake header value against an isolated local endpoint; compare a SHA-256 argument, a seed-word string, and other HTTP clients. No real keys. A shell built-in echo may not create the process event suggested by the old test. Header-file use, renamed clients, whitespace and other key formats are outside scope. |
| `miner_process_execution` | Authorized mining, tests, inert command-line examples. Confirm binary hash/signer, ancestry, network activity and host authorization. | Capture an inert executable with a matching filename in an isolated VM; record that this tests only name matching. Capture real approved miner startup separately if needed. Renamed miners without visible Stratum markers evade it. Wallet apps and generic --pool/--algo/--coin arguments no longer alert. |
| `wallet_lure_dns_keywords` | Educational domains, security tooling, prefetch and accidental substrings. Use as an opt-in hunt; enrich with current reputation and investigation. | Capture queries for reserved `.test` names using the three keywords and unrelated negatives. Record expected failure to resolve. No verified IOC list, delivery/click inference, C2 claim, or guarantee of detection before a transaction. |

## auditd cron collection

The rule requires the raw SYSCALL fields `type=SYSCALL`, `key=kino_cron`, and
`success=yes`. Use one watch key, preserve its string form, and do not confuse
an EXECVE record with a file-write record. The key is an administrator-configured
value in a real auditd field, not an automatically emitted cron label.

Example persistent syscall rules for a **64-bit x86 Linux lab**, for paths that
exist on that distribution:

```text
-a always,exit -F arch=b64 -F path=/etc/crontab -F perm=wa -k kino_cron
-a always,exit -F arch=b64 -F dir=/etc/cron.d/ -F perm=wa -k kino_cron
-a always,exit -F arch=b64 -F dir=/var/spool/cron/ -F perm=wa -k kino_cron
```

Place adapted rules in `/etc/audit/rules.d/` and load through the distribution's
audit tooling in a lab. Add b32 equivalents if 32-bit syscalls are supported and
relevant; these examples alone do not cover them. Add existing `/etc/cron.hourly`,
`daily`, `weekly`, `monthly`, and distribution-specific spool paths as needed.
Validate directory recursion and mount boundaries. Monitor lost/backlogged audit
events. Do not delete existing audit rules to install these examples.

These commands were **NOT RUN** in this environment. Verify with the owner's
[auditctl](https://man7.org/linux/man-pages/man8/auditctl.8.html) and auditd version.
The sudo and SSH selectors consume their service logs; they do not require
process_creation normalization or these auditd watches.

## Capturing evidence

Use disposable systems, record OS/sensor/configuration versions, export original
events and normalized SIEM records, and preserve hashes and timestamps. Redact
user data and secrets while documenting which fields were altered. For each
capture, record rule UUID, benign versus behavior-positive classification,
expected match, observed match, exact backend query, and replay command/output.
A behavior-positive event generated by authorized activity is not proof that an
alert correctly identifies an adversary. Do not promote status based on conversion.
