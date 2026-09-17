# Wazuh examples: experimental subset

`sigma_converted.xml` is a legacy filename. It now contains four hand-maintained
examples, not fourteen automatic conversions. XML well-formedness and custom ID
uniqueness are checked in CI. Wazuh compilation, decoder behavior, parent-rule
selection, alert generation, and Sigma/XML semantic parity require lab testing.
No `wazuh-logtest` result is claimed.

Source audit used Wazuh **v4.14.0**, not every 4.x release:

- [Windows channel parents](https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0575-win-base_rules.xml):
  60001 is Security; 60004 is Sysmon.
- [Sysmon groups](https://github.com/wazuh/wazuh/blob/v4.14.0/ruleset/rules/0595-win-sysmon_rules.xml):
  `sysmon_event2` and `sysmon_event_22` have different underscore conventions.
- [Custom rules](https://documentation.wazuh.com/current/user-manual/ruleset/custom.html)
  and [XML syntax](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html).

| ID | Source behavior | Required decoded fields |
|---|---|---|
| 110003 | Security log cleared | `win.system.eventID` 1102, Security channel |
| 110004 | Creation-time change hunt | Sysmon 2, `win.eventdata.image` |
| 110007 | Administrators membership | Security 4732, `win.eventdata.targetSid` |
| 110012 | Selected pool DNS query | Sysmon 22, `win.eventdata.queryName` |

Pool regexes anchor domain boundaries, include apex names and optional trailing
dots, and ignore case. No broad process-name timestamp exclusions remain.
ATT&CK tags remain in Sigma and the generated mapping document; XML omits
`mitre` blocks because the manager's embedded ATT&CK database can predate these
mappings. Map locally after checking the installed database.

The old SSH, failed-logon/count, service-command, sudo/su, cron, Startup, API-key,
wallet-lure, and wallet/miner translations were withdrawn. They broadened or
changed the Sigma logic and lacked replay evidence. Their Sigma replacements
remain available. No Wazuh count-based detection is shipped now.

For a future failed-logon port, use `same_field` for the dynamic decoded
`win.eventdata.ipAddress`, not `same_source_ip` unless a decoder actually populates
static `srcip`. Establish destination-host grouping as well. Test exactly 9, 10,
and 11 events, window boundaries, independent sources/hosts, and counter reset
behavior on the installed version before claiming parity. A configured
`frequency` alone does not prove the desired threshold semantics.

Evaluate on a disposable manager with its existing ruleset. Check ID collisions
in 100000–120000, install the examples, run the manager's ruleset configuration
test and `/var/ossec/bin/wazuh-logtest`, and replay real eventchannel records.
Verify phase 2 fields and phase 3 rule IDs. Send non-Sysmon event 2/22 records
and benign domain suffix lookalikes as negatives. Only deploy after these checks
pass. Copying a file and restarting a service does not establish useful alerting.
