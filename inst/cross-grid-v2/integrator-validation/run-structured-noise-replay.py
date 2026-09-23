#!/usr/bin/env python3
"""Recompute a public synthetic cell from its embedded record, without state homes."""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile


def validate_record(record):
    record = record.get('recomputation', record)
    assert record['version'] == 'dsvert-public-synthetic-release-replay-v1'
    assert record['data_classification'] == 'public-synthetic-test-fixture'
    assert record['seed_scope'] == 'test-harness-only-never-production-secrets'
    exact, released = record['exact_coordinates'], record['released_coordinates']
    assert isinstance(exact, list) and len(exact) == len(released) and len(exact) >= 2
    assert all(isinstance(x, str) and re.fullmatch(r'0|-?[1-9][0-9]*', x)
               for x in exact + released)
    encoded = ('\n'.join(exact) + '\n').encode()
    assert hashlib.sha256(encoded).hexdigest() == record['exact_coordinates_sha256']
    indices = record['criterion_indices']
    assert indices and len(set(indices)) == len(indices)
    assert record['criterion_index_base'] == 1
    assert all(isinstance(i, int) and 2 <= i <= len(exact) for i in indices)
    assert [exact[i - 1] for i in indices] == record['exact_candidate_criterion_integers']
    assert len(record['signed_contract']['signatures']) >= 2
    assert len(record['signed_schema']['signatures']) >= 2
    assert record['native_calls'] or record['peer_draws']
    return record


def replay_native(record, binary):
    shares, finals = {}, {}
    for call in record['native_calls']:
        command, inputs = call['command'], call['input']
        assert re.fullmatch(r'joint-dp-vector-(convolution|gaussian)-(share|finalize)-v[0-9]+', command)
        result = subprocess.run([str(binary), command], input=json.dumps(inputs),
                                text=True, capture_output=True, check=True)
        output = json.loads(result.stdout)
        assert output == call['output'], 'native output differs from recorded output'
        key = (inputs['release_contract_hash'], inputs['chunk_start'], inputs['coordinate_count'])
        if '-share-' in command:
            shares.setdefault(key, []).append((inputs, output))
        else:
            assert key not in finals, 'duplicate finalizer chunk'
            finals[key] = (inputs, output)
    assert shares.keys() == finals.keys()
    released = [None] * len(record['exact_coordinates'])
    for key, pair in shares.items():
        assert len(pair) == 2 and pair[0][0]['peer_name'] != pair[1][0]['peer_name']
        _, start, count = key
        assert 0 <= start < start + count <= len(released)
        sources = [base64.b64decode(p[0]['source_share'], validate=True) for p in pair]
        assert all(len(source) == count * 16 for source in sources)
        for j in range(count):
            value = sum(int.from_bytes(source[16*j:16*(j+1)], 'little') for source in sources)
            assert value % (1 << 128) == int(record['exact_coordinates'][start+j])
        inputs, output = finals[key]
        private = {'version', 'private_seed', 'source_share', 'peer_name',
                   'commitment_context', 'seed_commitment'}
        policy = [{k: v for k, v in p[0].items() if k not in private} for p in pair]
        assert policy[0] == policy[1], 'peers disagree on public sampler policy'
        assert all(inputs[k] == v for k, v in policy[0].items())
        assert sorted([inputs['left_noised_share'], inputs['right_noised_share']]) == sorted(
            p[1]['noised_share'] for p in pair)
        values = output['clamped_scaled_values']
        assert len(values) == count
        for j, value in enumerate(values):
            assert released[start+j] is None, 'overlapping release chunk'
            released[start+j] = value
    assert released == record['released_coordinates'], 'released vector differs'


def replay_reference(record, binary):
    with tempfile.TemporaryDirectory(prefix='dsvert-synthetic-replay-') as directory:
        root = Path(directory)
        fixture = dict(Exact=record['exact_coordinates'], Draws=record['peer_draws'],
                       Output=str(root / 'output.json'))
        path = root / 'input.json'
        path.write_text(json.dumps(fixture))
        env = dict(os.environ, DSVERT_STRUCTURED_ORACLE_FIXTURE=str(path))
        subprocess.run([str(binary), '-test.run=^TestStructuredGridNoiseOracle$'],
                       env=env, capture_output=True, text=True, check=True)
        actual = json.loads((root / 'output.json').read_text())
        assert actual['Exact'] == record['exact_coordinates'][1:]
        assert actual['Released'] == record['released_coordinates']


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('record', type=Path)
    parser.add_argument('--binary', type=Path, help='production dsvert-mpc binary for native records')
    parser.add_argument('--oracle-binary', type=Path, help='test oracle for retained exact-GC records')
    args = parser.parse_args()
    record = validate_record(json.loads(args.record.read_text()))
    if record['native_calls']:
        if args.binary is None:
            parser.error('--binary is required for a production native sampler record')
        replay_native(record, args.binary.resolve())
    else:
        if args.oracle_binary is None:
            parser.error('--oracle-binary is required for an exact-GC reference record')
        replay_reference(record, args.oracle_binary.resolve())
    print('SYNTHETIC_RELEASE_REPLAY_BITWISE_EQUAL coordinates=' + str(len(record['released_coordinates'])))


if __name__ == '__main__':
    main()
