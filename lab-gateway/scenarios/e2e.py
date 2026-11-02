#!/usr/bin/env python3
"""Build isolated Compose stacks and run the CIA checks against both modes."""
import argparse
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import uuid

HERE = Path(__file__).resolve().parent
COMPOSE = HERE / 'compose.e2e.yaml'

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', required=True, help='New directory for reports; must not already exist')
    args = parser.parse_args()
    output = Path(args.output_dir).resolve()
    output.mkdir(parents=True, exist_ok=False)
    run_id = uuid.uuid4().hex[:12]
    password, reader, producer = (secrets.token_hex(24) for _ in range(3))
    clients = json.dumps([{'name': 'reader', 'token': reader, 'objects': ['demo']}, {'name': 'producer', 'token': producer, 'objects': ['demo'], 'producer': True, 'metrics': True}], separators=(',', ':'))
    env = os.environ.copy()
    env.update(LAB_DB_PASSWORD=password, LAB_READER_TOKEN=reader, LAB_PRODUCER_TOKEN=producer, LAB_CLIENTS_JSON=clients)
    summary = {}
    for mode in ('baseline', 'secure'):
        directory = output / mode
        directory.mkdir()
        env.update(LAB_MODE=mode, LAB_REPORT_DIR=str(directory))
        command = ['docker', 'compose', '-p', 'iar-e2e-' + run_id + '-' + mode, '-f', str(COMPOSE)]
        try:
            print(f'Running {mode}...', flush=True)
            proc = subprocess.run(command + ['run', '--build', '--rm', 'checks'], env=env, check=False)
            report_file = directory / 'report.json'
            if not report_file.exists():
                summary[mode] = {'status': 'ERROR', 'exit_code': proc.returncode, 'reason': 'report missing'}
                continue
            report = json.loads(report_file.read_text(encoding='utf-8'))
            rows = report.get('results', [])
            failures = [row['scenario'] for row in rows if row['result'] == 'FAIL']
            skips = [row['scenario'] for row in rows if row['result'] == 'SKIP']
            # Baseline must expose both HTTP and WS IDOR; all other checks must pass.
            expected = {'T2: чужая история', 'T2: WS чужой объект'} if mode == 'baseline' else set()
            required = {'T1: HTTP без токена', 'T2: чужая история', 'запись без роли producer', 'T10: некорректный JSON', 'запись и чтение без изменения', 'T7: большой payload отклонён', 'контрольные запросы после ошибок', 'T1: WS без токена', 'T2: WS чужой объект', 'доставка события по WS', 'T4/T5: лимит подключений'}
            names = [row['scenario'] for row in rows]
            ok = not report.get('error') and not skips and set(names) == required and len(names) == len(required) and set(failures) == expected and proc.returncode == (1 if expected else 0)
            summary[mode] = {'status': 'PASS' if ok else 'FAIL', 'exit_code': proc.returncode, 'failed_scenarios': failures, 'skipped_scenarios': skips, 'report_error': report.get('error')}
        except (OSError, ValueError, KeyError) as exc:
            summary[mode] = {'status': 'ERROR', 'reason': type(exc).__name__}
        finally:
            try:
                subprocess.run(command + ['down', '--volumes', '--remove-orphans'], env=env, check=False)
            except OSError:
                pass
    (output / 'summary.json').write_text(json.dumps(summary, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if len(summary) == 2 and all(x['status'] == 'PASS' for x in summary.values()) else 1

if __name__ == '__main__':
    sys.exit(main())
