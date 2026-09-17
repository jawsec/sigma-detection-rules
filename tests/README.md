# Test evidence

There are **no real telemetry captures** in this repository yet. The manifest
lists a behavior-positive and benign capture TODO for every selector and the
correlation. Null paths mean missing evidence, not zero-result tests. Lab tasks
and negatives are in [RULE_GUIDE.md](../docs/RULE_GUIDE.md).

`test_conversion_contracts.py` checks generated output for regressions that can
otherwise pass conversion: dropped Sysmon event/channel constraints, missing
Linux source scopes, a Windows sentinel compared against an IP-typed ECS field,
incorrect correlation grouping/threshold, and DNS suffix-boundary drift between
Sigma and XML. Domain strings in unit tests are not telemetry samples and do not
prove Wazuh PCRE2 runtime behavior. Python regex matching only checks the shared
pattern subset; `wazuh-logtest` remains required.

Run the README conversion/check sequence first, then:

```bash
python -m unittest discover -s tests -v
```

For each future capture, store original EVTX/JSON/syslog under
`tests/captures/<rule-uuid>/`, plus normalized SIEM records and a provenance note:
OS, sensor/version/config, UTC capture time, lab action, redactions, SHA-256,
expected match, observed match, backend/version/query, replay command/output and
cleanup. Update the manifest to CAPTURED and supply its path/hash/provenance.
Add assertions based on those captured records; do not mark a rule validated
merely because a file now exists. Correlation samples must preserve event times
and independent host/source groupings. Use only fake test credentials, and never
publish production secrets or identifying user data.

The manifest is a manual evidence inventory. CI currently checks its completeness,
not live SIEM replay. Capture ingestion and replay tooling will need to be added
for the chosen lab platforms. GitHub Actions execution itself must be observed
after the owner pushes the branch; local workflow-equivalent checks do not prove
that a hosted workflow has run.
