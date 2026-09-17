# sigma-detection-rules

Experimental Sigma content for mixed Windows/Linux environments, maintained by
[jawsec](https://github.com/jawsec) / Kino Security LLC.

The repository contains **14 single-event selectors and one correlation**. The
failed-logon selector is the correlation's input, not an additional brute-force
detection. Several rules are intentionally low/informational hunting signals.
All rules remain `experimental`: automated parsing and query generation do not
establish detection efficacy, acceptable noise, or production readiness.

## Scope and telemetry

| Source | Requirement | Content |
|---|---|---|
| Windows Security | Collect 4625, 4732, 1102; enable failed Logon and successful Security Group Management auditing | Failed network logons, Administrators membership, Security log clearing |
| Windows Sysmon | Explicitly collect events 1, 2, 11, 22 with required fields; review filters | Process commands, Startup writes, creation-time changes, DNS |
| Linux sshd/sudo | Forward original message body and program identity | Accepted SSH authentication and sudo commands targeting root; hunting baselines |
| Linux auditd | Install documented `kino_cron` write/attribute watches and parse SYSCALL records | Operations on cron paths |

See the [per-rule guide](docs/RULE_GUIDE.md) for false positives, tuning, blind
spots, and unexecuted lab checks. A default Sysmon installation or generic
process log feed is insufficient for the whole pack.

## Quick start

Python 3.12 is the tested interpreter. Run from the repository root:

```bash
git clone https://github.com/jawsec/sigma-detection-rules.git
cd sigma-detection-rules
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
yamllint -s .
python scripts/check.py
sigma check -x d3_fendtag --fail-on-issues .build/validation/
python scripts/coverage.py --check
python scripts/convert.py splunk
python scripts/convert.py lucene
python scripts/convert.py kusto
sigma convert -t splunk -p splunk_windows .build/correlation/ > .build/correlation.spl
python -m unittest discover -s tests -v
```

The conversion script selects source-specific pipelines and prints the actual
commands and generated queries. Outputs are under `.build/`. Read the
[conversion contracts](docs/SIEM_CONVERSION.md) before using them. These are query
strings, not deployed alerts. Splunk, Elasticsearch Lucene, and Sentinel KQL
single-event conversion are supported by this workflow; correlation export is
currently Splunk-only. SIEM execution and real-event replay remain unverified.

## Repository map

- `rules/`: single-event Sigma selectors, organized by tactic or subject.
- `correlations/`: repeated failed network logons, grouped by source and host.
- `pipelines/`: explicit local ingestion contracts for Linux, ECS IP fields, and Sentinel.
- `scripts/`: checks, conversions, and generated ATT&CK inventory.
- `tests/`: conversion regression checks and a real-capture TODO manifest.
- `conversions/wazuh/`: **four experimental XML examples**, not a complete port.
- `docs/`: threat model, tuning, indicator provenance, conversion guide, and mappings.

[ATT&CK mappings](docs/MITRE_COVERAGE.md) are generated from rule tags and checked
for drift in CI. Crypto/Web3 is a subject folder, not an ATT&CK tactic. Tag counts
do not measure operational coverage. The reference snapshot is Enterprise
ATT&CK 19.2; it uses Stealth and Defense Impairment and excludes revoked techniques.

## Crypto/Web3 content

Selected mining pool lookups and miner process indicators overlap with existing
[SigmaHQ mining detections](https://github.com/SigmaHQ/sigma/blob/2e8fd89f82d9104c1b30321a307254ddeea17de2/rules/network/dns/net_dns_pua_cryptocoin_mining_xmr.yml).
This project offers a small reviewable set, not unique threat coverage.
Wallet-lure DNS keywords are unverified lexical heuristics. The curl header rule
is a potential secret-handling issue, not a seed-phrase or theft detector.
[Indicator maintenance](docs/INDICATORS.md) records the list's limits and review dates.

## Wazuh and validation

Wazuh does not compile these Sigma YAML files. The
[hand-maintained XML subset](conversions/wazuh/README.md) requires local decoder,
ruleset, and `wazuh-logtest` testing. No immediate-alerting claim is made.

CI checks YAML, Sigma parsing/validators, UUIDs, ATT&CK relationships, generated
document freshness, query conversion, and XML well-formedness. No real telemetry
captures are committed yet. See [tests/README.md](tests/README.md).

The separate [vigil project](https://github.com/jawsec/vigil) may be relevant to
other monitoring tasks; this repository makes no combined kill-chain coverage claim.

## Contributing and license

See [CONTRIBUTING.md](CONTRIBUTING.md) and [CHANGELOG.md](CHANGELOG.md).
MIT; see [LICENSE](LICENSE).
