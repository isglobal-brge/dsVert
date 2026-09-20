#!/usr/bin/env python3
"""Re-score immutable fleet records; never execute a release or change source pins."""
import argparse
import hashlib
import json
import math
from pathlib import Path


def rescore(record, policy):
    result = dict(record)
    metrics = record.get('metrics') or {}
    rpc = metrics.get('end_to_end_serialized_rpc_bytes')
    seconds = metrics.get('end_to_end_release_elapsed')
    capacity = all(type(value) in (int, float) and math.isfinite(value)
                   and 0 <= value <= limit for value, limit in (
                       (rpc, policy['capacity_bytes']), (seconds, policy['capacity_seconds'])))
    lifecycle = (record.get('returncode') == 0
                 and all(record.get(key) is True for key in ('oracle_equal', 'cold', 'tamper'))
                 and (record.get('mode') == 'baseline' or
                      (record.get('mode') == 'recovery' and record.get('recovery') is True)))
    result['original_scoring'] = record.get('original_scoring', {
        key: record.get(key) for key in ('status', 'capacity_pass', 'failure_reason')})
    result['capacity_policy'] = policy
    result['capacity_pass'] = capacity
    result['status'] = 'PASS' if lifecycle else 'FAIL'
    result['rescore_only'] = True
    if result['status'] == 'PASS':
        result.pop('failure_reason', None)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', type=Path)
    parser.add_argument('output', type=Path)
    args = parser.parse_args()
    assert args.input.resolve() != args.output.resolve(), 'Preserve the original records'
    policy = json.loads(Path(__file__).with_name('release-capacity.json').read_text())
    blob = args.input.read_bytes()
    rows = [rescore(json.loads(line), policy) for line in blob.splitlines() if line]
    for row in rows:
        row['rescore_input_sha256'] = hashlib.sha256(blob).hexdigest()
    with args.output.open('x') as output:
        output.write(''.join(json.dumps(row) + '\n' for row in rows))
    print(json.dumps({'records': len(rows), 'pass': sum(r['status'] == 'PASS' for r in rows),
                      'policy': policy}))


if __name__ == '__main__':
    main()
