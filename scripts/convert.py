"""Compile all single-event rules using explicit, source-specific pipelines."""
import argparse
from pathlib import Path
import subprocess
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=['splunk', 'lucene', 'kusto'])
    args = parser.parse_args()
    output = ROOT / '.build' / args.target
    output.mkdir(parents=True, exist_ok=True)
    count = 0
    for path in sorted((ROOT / 'rules').rglob('*.yml')):
        rule = yaml.safe_load(path.read_text())
        product = rule['logsource']['product']
        if args.target == 'kusto':
            pipelines = ['pipelines/sentinel.yml']
        elif product == 'windows':
            pipelines = ['sysmon', 'splunk_windows' if args.target == 'splunk' else 'ecs_windows']
            if args.target == 'lucene':
                pipelines.append('pipelines/ecs_security_raw_ip.yml')
        else:
            pipelines = [f'pipelines/{args.target}_linux.yml']
        command = ['sigma', 'convert', '-t', args.target]
        for pipeline in pipelines:
            command += ['-p', pipeline]
        command.append(str(path.relative_to(ROOT)))
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        print('$ ' + ' '.join(command))
        if result.stderr:
            print(result.stderr, end='')
        if result.returncode:
            print(result.stdout, end='')
            return result.returncode
        if not result.stdout.strip():
            raise RuntimeError(f'No query produced for {path}')
        destination = output / (path.stem + '.txt')
        destination.write_text(result.stdout)
        print(result.stdout, end='')
        count += 1
    print(f'Converted {count} single-event rules to {args.target}. Queries: .build/{args.target}/')
    return 0


if __name__ == '__main__':
    sys.exit(main())
