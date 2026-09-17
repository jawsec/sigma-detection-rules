# Conversion contracts and limits

The pinned environment in `requirements-dev.txt` uses sigma-cli 3.1.0, pySigma
1.5.0, Splunk 2.1.0, Elasticsearch 2.1.1, Kusto 1.0.1, and Sysmon pipeline 2.0.0.
These versions were installed and exercised during the review. Pins make the
review repeatable; review updates deliberately. They do not claim to remain latest.

## Commands and outputs

Use README setup first. The tested entry points are:

```bash
sigma list targets
sigma list pipelines
python scripts/convert.py splunk
python scripts/convert.py lucene
python scripts/convert.py kusto
python scripts/check.py
sigma check -x d3_fendtag --fail-on-issues .build/validation/
sigma convert -t splunk -p splunk_windows .build/correlation/ > .build/correlation.spl
```

Each single-event target emits fourteen nonempty queries. The helper prints each
underlying `sigma convert` invocation. No `--without-pipeline` conversion is
advertised: that flag bypasses a requirement; it does not normalize telemetry.

The combined staging directories matter. With this sigma-cli version, passing
the correlation and base as separate input arguments failed reference resolution.
`scripts/check.py` stages one complete collection. The correlation has no
`logsource` or `detection`: those belong to its referenced single-event rule.

| Target | Windows pipeline chain | Linux pipeline | Output |
|---|---|---|---|
| `splunk` | `sysmon`, `splunk_windows` | `pipelines/splunk_linux.yml` | SPL search text |
| `lucene` | `sysmon`, `ecs_windows`, `pipelines/ecs_security_raw_ip.yml` | `pipelines/lucene_linux.yml` | Lucene query text |
| `kusto` | `pipelines/sentinel.yml` | Same local pipeline | Sentinel `WindowsEvent` / `Syslog` KQL |

`elasticsearch` is a plugin/package name, not a target in this installed version;
use `lucene` here. EQL is a distinct target/format, not an automatic effect of
selecting `ecs_windows`. EQL, ES|QL, Elastalert, QRadar, savedsearches, and NDJSON
exports are outside this repository's tested support matrix.

The current [Kusto backend](https://github.com/AttackIQ/pySigma-backend-kusto)
provides target `kusto` and pipelines including `microsoft_xdr`,
`microsoft_365_defender` (compatibility), `sentinel_asim`, and `azure_monitor`.
The old `-t microsoft365defender` command failed in the installed environment.
Microsoft XDR and Sentinel use different tables. This pack's Sentinel contract
must not be described as Defender Advanced Hunting support.

## Windows source constraints

The [Sysmon pipeline](https://github.com/SigmaHQ/pySigma-pipeline-sysmon)
translates `process_creation`, `file_change`, `file_event`, and `dns_query` to
Sysmon events 1, 2, 11, and 22. In the tested versions, `splunk_windows` or
`ecs_windows` alone left those generic selectors without event constraints.
Both pipeline stages are necessary. Security rules retain the Security channel.

Splunk assumes `source=WinEventLog:Security` or
`source=WinEventLog:Microsoft-Windows-Sysmon/Operational`, `EventCode`, and the
original event-data field names. XML rendering, add-ons, and local extraction
can use other source/field names; adapt the pipeline to actual ingested records.
Correlation grouping requires a populated destination `Computer` field. Select
an appropriate index and search interval locally. [Splunk search syntax](https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/9.4/search-commands/search)
gives OR higher precedence than AND; do not reinterpret generated searches as SQL.

Elastic assumes Winlogbeat-style ECS fields and the mapping expected by the
[backend](https://github.com/SigmaHQ/pySigma-backend-elasticsearch). Its pipeline
emits `process.executable.caseless`, which is not guaranteed to exist in your
indices. Configure that searchable multifield or adapt the mapping and replay
mixed-case paths. Also verify wildcard/case behavior for `process.command_line`,
`file.path`, `dns.question.name`, and Linux `message`; parsing is not a guarantee
of equivalent matching on text, keyword, and wildcard field types. No index
mapping or live Elasticsearch validation is supplied here.

The local ECS override preserves raw `winlog.event_data.IpAddress` for Security
rules, because Windows uses `-` and empty sentinels that are not valid values
for the ECS `source.ip` IP type. Verify this original field is retained.

Sentinel's local pipeline explicitly queries
[WindowsEvent](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/windowsevent),
scopes the channel and event ID, and extracts named members from dynamic
`EventData`. It does not query `SecurityEvent`, `Event`, or `DeviceProcessEvents`.
Configure collection to this table and verify its event-data shape. The KQL was
generated, not submitted to a Log Analytics workspace. Do not assume connector
installation creates these exact table mappings.

## Linux source contracts

Rules use actual auditd fields or a defined raw `message` field, not invented SSH
normalization. The message field is the full unchanged service message body;
the pipeline maps it to the destination's field.

| Source | Splunk | Elastic/Filebeat-style | Sentinel |
|---|---|---|---|
| sshd / sudo | `sourcetype=syslog`, extracted `process=sshd` or `sudo`, `_raw` | `event.dataset=system.auth`, `process.name`, `message` | `Syslog`, `ProcessName`, `SyslogMessage` |
| auditd | `sourcetype=auditd`, extracted `type`, `key`, `success` | `event.dataset=auditd.log`, `auditd.log.record_type`, `.key`, `.success` | Raw auditd SYSCALL forwarded to `Syslog` with `ProcessName=auditd`; explicit KQL extraction |

These are integration contracts, not universal defaults. Filebeat documents
[auditd fields](https://www.elastic.co/docs/reference/beats/filebeat/exported-fields-auditd);
`record_type` is an alias to `event.action`. Verify key/success preservation in
your pipeline. Auditbeat's coalesced events need different mappings.
Sentinel does not automatically ingest auditd as the required Syslog records;
configure forwarding and preserve the raw `type=`, `key=`, `success=` tokens.
The provided extraction expects the single watch key `kino_cron`.

Do not apply a Windows pipeline blindly to the mixed `rules/` directory.
A command can succeed while leaving Linux fields unmapped and sources unscoped.
The helper selects pipelines per file to avoid that silent failure.

## Correlation

The Sigma correlation counts **at least ten** network-logon failures per
`Computer, IpAddress` in five minutes. It includes machine accounts and excludes
only explicit local/empty IP sentinels in the selector. It covers neither every
logon type nor domain-controller 4771/4776 failures. NAT aggregates users; a
source distributed across hosts is split; missing group keys can disappear from
aggregation. Deduplicate reingested events before counting.

The tested Splunk backend emits `bin _time span=5m` and `stats count`: these are
**fixed buckets**, not a rolling window. Ten failures straddling a bucket boundary
can be missed. Choose a local rolling-window implementation if that tradeoff is
unacceptable, then test it separately. Scheduling, late arrival, lookback,
throttling, and alert grouping are not implemented by query conversion.

Lucene and this Kusto backend do not supply a tested correlation export here.
Their single-event failed-logon queries are **not brute-force detections**.
Implement and test an equivalent native scheduled analytic before claiming that
coverage. Unsupported exports are not silently skipped or counted as passes.

## Wazuh

There is no official pySigma Wazuh backend in the reviewed plugin workflow.
Wazuh uses decoders and XML rules, not automatic loading of a Sigma YAML folder.
The [four XML examples](../conversions/wazuh/README.md) are a separately maintained,
unverified runtime subset. No count-based Wazuh rule remains.

## Evidence boundary

Local results establish YAML/Sigma parsing, source/field transformation, generated
query output, and XML well-formedness only. They do not establish backend query
acceptance, capture fidelity, actual matches, alert delivery, or noise rates.
The review's validation log records actual commands and stdout/stderr.

Authoritative tooling references: [sigma-cli](https://github.com/SigmaHQ/sigma-cli),
[pySigma pipelines](https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html),
[Sigma correlations](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/specification/sigma-correlation-rules-specification.md),
and [Splunk backend](https://github.com/SigmaHQ/pySigma-backend-splunk).
