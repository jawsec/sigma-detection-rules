"""Regression checks on generated queries, not live SIEM or telemetry replay tests."""
import json
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

import yaml

ROOT = Path(__file__).resolve().parents[1]
EVENTS = {'process_creation': 1, 'file_change': 2, 'file_event': 11, 'dns_query': 22}


class ConversionContracts(unittest.TestCase):
    def test_every_selector_has_each_backend_output(self):
        for path in (ROOT / 'rules').rglob('*.yml'):
            for target in ('splunk', 'lucene', 'kusto'):
                with self.subTest(rule=path.stem, target=target):
                    query = (ROOT / '.build' / target / (path.stem + '.txt')).read_text()
                    self.assertTrue(query.strip())

    def test_generic_windows_sources_keep_event_constraints(self):
        for path in (ROOT / 'rules').rglob('*.yml'):
            rule = yaml.safe_load(path.read_text())
            source = rule['logsource']
            if source.get('product') != 'windows' or source.get('category') not in EVENTS:
                continue
            event_id = EVENTS[source['category']]
            for target, marker in [('splunk', f'EventCode={event_id}'),
                                   ('lucene', f'event.code:{event_id}'),
                                   ('kusto', f'EventID == {event_id}')]:
                with self.subTest(rule=path.stem, target=target):
                    query = (ROOT / '.build' / target / (path.stem + '.txt')).read_text()
                    self.assertIn(marker, query)
                    self.assertIn('Sysmon', query)

    def test_security_sources_keep_channel(self):
        for stem in ('windows_failed_network_logon', 'windows_security_log_cleared', 'user_added_local_admins'):
            for target in ('splunk', 'lucene', 'kusto'):
                with self.subTest(rule=stem, target=target):
                    self.assertIn('Security', (ROOT / '.build' / target / (stem + '.txt')).read_text())

    def test_linux_sources_are_scoped(self):
        for stem, service in [('sshd_accepted_authentication', 'sshd'),
                              ('sudo_command_as_root', 'sudo'), ('cron_path_write_auditd', 'auditd')]:
            for target in ('splunk', 'lucene', 'kusto'):
                with self.subTest(rule=stem, target=target):
                    query = (ROOT / '.build' / target / (stem + '.txt')).read_text()
                    self.assertIn(service, query)
                    self.assertNotIn('WinEventLog:', query)

    def test_raw_ip_override_preserves_windows_sentinels(self):
        query = (ROOT / '.build/lucene/windows_failed_network_logon.txt').read_text()
        self.assertIn('winlog.event_data.IpAddress', query)
        self.assertNotIn('source.ip:', query)

    def test_splunk_correlation_threshold_and_grouping(self):
        query = (ROOT / '.build/correlation.spl').read_text()
        self.assertIn('bin _time span=5m', query)
        self.assertIn('by _time Computer IpAddress', query)
        self.assertIn('event_count >= 10', query)
        self.assertNotIn('TargetUserName', query)

    def test_pool_xml_and_sigma_domain_boundaries(self):
        # These are unit-test strings, not fabricated DNS events or telemetry captures.
        rule = yaml.safe_load((ROOT / 'rules/crypto-web3-threats/mining_pool_dns_query.yml').read_text())
        apex = rule['detection']['selection_apex']['QueryName']
        suffixes = tuple(rule['detection']['selection_subdomain']['QueryName|endswith'])
        xml = ET.parse(ROOT / 'conversions/wazuh/sigma_converted.xml')
        regex = re.compile(xml.find(".//rule[@id='110012']/field").text)
        positives = [name for root in ('supportxmr.com', 'moneroocean.stream', '2miners.com')
                     for name in (root, 'pool.' + root, root.upper(), root + '.', 'pool.' + root + '.')]
        negatives = ['not2miners.com', '2miners.com.example.test', 'supportxmr.comevil', 'example.test']
        for value in positives + negatives:
            with self.subTest(value=value):
                sigma_match = value.lower() in apex or value.lower().endswith(suffixes)
                self.assertEqual(sigma_match, value in positives)
                self.assertEqual(bool(regex.fullmatch(value)), sigma_match)

    def test_capture_manifest_covers_every_rule(self):
        manifest = json.loads((ROOT / 'tests/captures/manifest.json').read_text())
        expected = {yaml.safe_load(p.read_text())['id'] for directory in ('rules', 'correlations')
                    for p in (ROOT / directory).rglob('*.yml')}
        self.assertEqual(expected, {entry['rule_id'] for entry in manifest['rules']})
        for entry in manifest['rules']:
            for capture in ('behavior_positive', 'benign'):
                item = entry[capture]
                self.assertIn(item['status'], ('TODO_NOT_CAPTURED', 'CAPTURED'))
                if item['status'] == 'CAPTURED':
                    self.assertTrue(item['path'])
                    self.assertTrue((ROOT / item['path']).is_file())
                    self.assertTrue(item.get('provenance'))
                    self.assertTrue(item.get('sha256'))


if __name__ == '__main__':
    unittest.main()
