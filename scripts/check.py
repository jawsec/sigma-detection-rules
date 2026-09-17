"""Validate metadata, UUIDs, ATT&CK relationships, correlations, and Wazuh XML."""
import datetime
import json
from pathlib import Path
import shutil
import uuid
import xml.etree.ElementTree as ET

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main():
    attack = json.loads((ROOT / 'docs/attack-reference.json').read_text())
    paths = sorted((ROOT / 'rules').rglob('*.yml')) + sorted((ROOT / 'correlations').glob('*.yml'))
    required = {'title', 'id', 'status', 'description', 'references', 'author', 'date', 'falsepositives', 'level'}
    ids = set()
    names = set()
    stage = ROOT / '.build' / 'validation'
    if stage.exists():
        shutil.rmtree(stage)
    stage.mkdir(parents=True)
    for path in paths:
        rule = yaml.safe_load(path.read_text())
        assert required <= rule.keys(), f'Missing metadata: {path}'
        uid = uuid.UUID(rule['id'])
        assert uid.version == 4 and str(uid) == rule['id'], f'Invalid UUIDv4: {path}'
        assert uid not in ids, f'Duplicate UUID: {path}'
        ids.add(uid)
        if 'name' in rule:
            assert rule['name'] not in names, f'Duplicate rule name: {path}'
            names.add(rule['name'])
        for field in ('date', 'modified'):
            if field in rule:
                value = rule[field]
                assert isinstance(value, datetime.date), f'Use unquoted YYYY-MM-DD: {path}'
                assert value <= datetime.date.today(), f'Future date: {path}'
        if 'modified' in rule:
            assert rule['modified'] >= rule['date'], f'Modified before creation: {path}'
        if 'correlation' not in rule:
            assert {'logsource', 'detection'} <= rule.keys(), path
            assert 'condition' in rule['detection'], path
        tags = [tag.removeprefix('attack.') for tag in rule.get('tags', []) if tag.startswith('attack.')]
        techniques = [tag.upper() for tag in tags if tag.startswith('t') and tag[1:2].isdigit()]
        tactics = set(tags) - {tag.lower() for tag in techniques}
        assert tactics <= attack['tactics'].keys(), f'Unknown tactic: {path}'
        supported = set()
        for technique in techniques:
            assert technique in attack['techniques'], f'Unreviewed technique: {path}'
            supported.update(attack['techniques'][technique]['tactics'])
        assert tactics <= supported, f'Tactic/technique mismatch: {path}'
        assert not (stage / path.name).exists(), f'Duplicate filename: {path}'
        shutil.copyfile(path, stage / path.name)
    print(f'Metadata, dates, unique UUIDv4 IDs, and ATT&CK relationships: {len(paths)} documents OK')
    tree = ET.parse(ROOT / 'conversions/wazuh/sigma_converted.xml')
    xml_ids = [int(rule.attrib['id']) for rule in tree.findall('.//rule')]
    assert len(xml_ids) == len(set(xml_ids)), 'Duplicate Wazuh IDs'
    assert all(100000 <= value <= 120000 for value in xml_ids), 'Wazuh ID outside custom range'
    print(f'XML well-formed; {len(xml_ids)} unique Wazuh IDs in custom range. Runtime NOT tested.')
    print('Combined Sigma collection staged at .build/validation/ for sigma check and correlations.')
    correlation_stage = ROOT / '.build' / 'correlation'
    if correlation_stage.exists():
        shutil.rmtree(correlation_stage)
    correlation_stage.mkdir()
    for path in paths:
        rule = yaml.safe_load(path.read_text())
        if 'correlation' in rule or rule.get('name') == 'windows_failed_network_logon':
            shutil.copyfile(path, correlation_stage / path.name)
    print('Brute-force base and correlation staged at .build/correlation/.')


if __name__ == '__main__':
    main()
