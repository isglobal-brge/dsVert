"""Test-only replay of retained PUBLIC SYNTHETIC LASSO fixture noise."""
import json
import os
from pathlib import Path
import subprocess
import tempfile

state = Path('/var/lib/dsvert-integrator-lasso/cross-grid-dslite-2e1e737a55b6fb')
original = json.loads((state / 'synthetic-oracle-input.json').read_text())
expected = json.loads((state / 'synthetic-oracle-output.json').read_text())
with tempfile.TemporaryDirectory(prefix='structured-synthetic-oracle-') as directory:
    root = Path(directory)
    fixture = {'Exact': [str(len(original['Rows'])), *expected['Exact']],
               'Draws': original['Draws'], 'Output': str(root / 'output.json')}
    path = root / 'input.json'
    path.write_text(json.dumps(fixture)); path.chmod(0o600)
    binary = os.environ['DSVERT_STRUCTURED_ORACLE_BINARY']
    env = dict(os.environ, DSVERT_STRUCTURED_ORACLE_FIXTURE=str(path))
    result = subprocess.run([binary, '-test.run=^TestStructuredGridNoiseOracle$'],
                            env=env, capture_output=True, text=True, check=True)
    actual = json.loads((root / 'output.json').read_text())
    assert actual == expected
    print('STRUCTURED_NOISE_REPLAY_BITWISE_EQUAL n=2000 K=3 coordinates=' + str(len(actual['Released'])))
    fixture['Draws'].append(fixture['Draws'][0])
    path.write_text(json.dumps(fixture))
    rejected = subprocess.run([binary, '-test.run=^TestStructuredGridNoiseOracle$'],
                              env=env, capture_output=True, text=True)
    assert rejected.returncode != 0
    print('STRUCTURED_NOISE_DUPLICATE_CHUNK_REJECTED')
