# SIEM Conversion Guide

Sigma rules are SIEM-agnostic by design. Use the [sigma-cli](https://github.com/SigmaHQ/sigma-cli) tool or [pySigma](https://github.com/SigmaHQ/pySigma) to convert these YAML rules into the native query language of your SIEM.

## Install sigma-cli

```bash
pip install sigma-cli
```

Install the backend plugin for your SIEM:

```bash
# Splunk
sigma plugin install splunk

# Elastic / OpenSearch
sigma plugin install elasticsearch

# Microsoft Sentinel
sigma plugin install microsoft365defender

# IBM QRadar
sigma plugin install qradar
```

## Convert Rules

### Splunk

```bash
# Single rule
sigma convert -t splunk rules/initial-access/brute_force_authentication.yml

# All rules in a category
sigma convert -t splunk rules/crypto-web3-threats/

# Entire pack
sigma convert -t splunk rules/
```

### Elastic / Kibana

```bash
sigma convert -t elasticsearch rules/

# For Elastic SIEM (EQL format)
sigma convert -t elasticsearch -p ecs_windows rules/
```

### Microsoft Sentinel (KQL)

```bash
sigma convert -t microsoft365defender rules/
```

### Wazuh

Wazuh does not have an official sigma-cli backend. Two options:

**Option A — Use the Wazuh Sigma integration (recommended)**

Wazuh 4.x+ includes built-in Sigma rule support. Place the YAML files in `/var/ossec/etc/rules/sigma/` and Wazuh will convert them automatically during rule compilation.

**Option B — Manual conversion**

Convert to a generic format and manually translate to Wazuh XML rule syntax. Each Sigma rule's detection logic maps to Wazuh's `<rule>` XML format:

```xml
<!-- Example: Event Log Cleared (Sigma rule -> Wazuh XML) -->
<rule id="100001" level="15">
  <if_sid>60100</if_sid>
  <field name="win.system.eventID">^1102$</field>
  <description>Windows Security audit log was cleared</description>
  <mitre>
    <id>T1070.001</id>
  </mitre>
</rule>
```

## Pipeline Configuration

Some conversions require a processing pipeline to map Sigma's generic field names to your SIEM's specific field names. For example, Sigma uses `Image` for process paths, but your SIEM might call it `process.executable` or `NewProcessName`.

```bash
# List available pipelines for a backend
sigma plugin list -t splunk

# Convert with a specific pipeline
sigma convert -t splunk -p sysmon rules/
```

## Validation

After converting, always test each rule against known-good log data before deploying to production. Every rule in this pack includes a testing methodology section with instructions for generating test events in a lab.

## Bulk Export

To export all rules as a single file for import into your SIEM:

```bash
# Splunk saved searches format
sigma convert -t splunk -f savedsearches rules/ > sigma_detections.conf

# Elastic NDJSON (for Kibana import)
sigma convert -t elasticsearch -f ndjson rules/ > sigma_detections.ndjson
```
