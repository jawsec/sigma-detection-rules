# Changelog

## Unreleased

Breaking corrections to the initial experimental pack:

- Replace legacy brute-force aggregation with a Windows network-logon base and
  event-count correlation; document Splunk fixed-bucket semantics.
- Rescope SSH and sudo to observable authentication/command hunting signals;
  replace cron process-name guesses with configured auditd watch telemetry.
- Use Administrators SID and T1098.007; remove account-creation and cloud-account
  overclaims. Update mappings to Enterprise ATT&CK 19.2, including T1685,
  T1685.005, Stealth and Defense Impairment.
- Narrow API exposure to a curl Binance header marker; remove seed-phrase,
  exfiltration, phishing and C2 claims unsupported by those events.
- Narrow miners and pool lists, document primary sources and upkeep, and demote
  wallet-lure DNS matching to a lexical hunt.
- Remove blanket timestamp process exclusions; document event 2 limitations.
- Normalize dates, replace invalid tags, fix duplicate YAML keys and severity.
  Materially replaced selectors receive new UUIDv4 IDs with explicit relationships.
- Replace the purported complete Wazuh port with four experimental XML examples.
  Withdraw untested translations; no Wazuh runtime success is claimed.
- Add pinned tooling, source-specific pipelines, generated ATT&CK inventory,
  validation/conversion CI, regression checks, and a missing-capture manifest.
- Remove native Wazuh Sigma support, immediate firing, uniqueness, low-noise,
  comprehensive coverage and full-kill-chain claims.

No release tag has been created. A reviewed pre-1.0 release is appropriate only
after these breaking changes and the remaining lab limitations are acknowledged.
