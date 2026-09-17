# Contributing

Each change must state the observable behavior, telemetry prerequisites, likely
benign sources, evasions, and why the title and severity are justified. Preserve
scope: no unsupported claims of compromise, authorization, unusualness, or
complete ATT&CK coverage. Use current primary references. SigmaHQ-quality style
is a goal; this repository does not claim SigmaHQ acceptance.

## Rule bar

- Use valid YAML with no duplicate keys and ISO `YYYY-MM-DD` dates.
- Include title, UUIDv4, status, description, references, author, date, tags,
  logsource, detection/condition, falsepositives, and level. The repository bar
  is stricter than the core spec's mandatory-field minimum.
- Start new rules as `experimental`. Real captures, benign evaluation and review
  are required before promoting status. Query conversion is not a detection test.
- Use standard source categories/services and actual fields or documented raw
  message contracts. Do not borrow normalized fields without a mapping.
- Use lowercase technique tags, e.g. `attack.t1098.007`, and current tactic shortnames.
  Current Sigma conventions use hyphens, e.g. `attack.privilege-escalation`.
  Do not force ATT&CK tags onto a policy or lexical signal; use
  `detection.threat-hunting` where appropriate.
- Count with Sigma correlations, not legacy condition pipes. Referenced base
  rules and correlations must be loaded in one collection. Correlations have
  their own schema and do not repeat detection/logsource.
- Keep original IDs for corrections to the same behavior. Use a new UUIDv4 and
  `related: type: obsolete` when replacing a materially different detection;
  use `derived` when the original remains active. Never generate sequential IDs.
- Cite behavior/source documentation, not only ATT&CK pages. Use commit permalinks
  for git-hosted references. Update provenance for static indicators.
- Add true-positive and benign captures with provenance, or explicitly record
  their absence in the capture manifest. Never fabricate telemetry.
- Update conversion contracts and Wazuh examples only when semantics are understood.
  Wazuh runtime claims require `wazuh-logtest` and real decoder/replay evidence.

Follow the [specification](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/specification/sigma-rules-specification.md)
and [SigmaHQ conventions](https://github.com/SigmaHQ/sigma-specification/blob/ba9251aa834b11a70dbf80836b453dba99c5159e/sigmahq/sigmahq-rule-convention.md).

## Template

This is a template, not an executable detection. Replace every placeholder,
select a defensible behavior and references, and generate a fresh UUIDv4.

```yaml
title: REPLACE With Observable Behavior
id: REPLACE_WITH_UUIDV4
status: experimental
description: |
    Detects REPLACE with the precise observation, scope, and limitations.
references:
    - https://REPLACE_WITH_PRIMARY_REFERENCE
author: REPLACE_WITH_AUTHOR
date: 2026-09-17
tags:
    - detection.threat-hunting
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\REPLACE.exe'
    condition: selection
falsepositives:
    - REPLACE with specific benign behavior and tuning context
level: low
```

## Verification and releases

Run every README validation command. Regenerate mappings with
`python scripts/coverage.py`; CI's `--check` mode rejects stale output. Update
`docs/attack-reference.json` from a pinned MITRE Enterprise STIX snapshot when
adding techniques; verify revocation, tactic relationships and snapshot hash.
The local checker checks that reviewed snapshot, not live ATT&CK automatically.

Include exact commands, versions, exit codes, outputs, capture provenance, and
remaining NOT RUN checks in the PR. Review generated queries for field mappings
and source constraints; do not accept a zero exit code as sufficient evidence.

Use SemVer for future releases. A pre-1.0 minor release should identify renamed
files, replaced UUIDs, removed translations and changed matching. Leave changes
under Unreleased until a reviewed merge and release decision. No tag should imply
production validation. Tooling pins are reviewed together with generated output.
