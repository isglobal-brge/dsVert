"""Compose final coverage without treating a superseded comparison as passing."""
import csv,json,hashlib
from pathlib import Path
out=Path(__file__).resolve().parent
name='test-crossgrid-cox.R.csv'
raw=out/name
prior=list(csv.DictReader(raw.open()))
final=list(csv.DictReader((out/'final-tests'/name).open()))
assert len(final)==1
selected=final[0]['test']
assert selected=='Cox worker preparation authenticates the owner route and cold source before native handoff'
assert final[0]['failed']=='0' and final[0]['error']=='FALSE'
replaced=[r for r in prior if r['test']==selected]
assert len(replaced)==1
assert replaced[0]['failed']=='9' and replaced[0]['error']=='FALSE'
rows=[final[0] if r['test']==selected else r for r in prior]
assert all(r['failed']=='0' and r['error']=='FALSE' and r['warning']=='0' and r['skipped']=='FALSE' for r in rows)
(out/'raw-r3-test-crossgrid-cox.R.csv').write_bytes(raw.read_bytes())
(out/'final-cox-endpoint.csv').write_bytes((out/'final-tests'/name).read_bytes())
with raw.open('w') as f:
 w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
for p in (out/'final-tests').glob('test-*.csv'):
 if p.name!=name:(out/p.name).write_bytes(p.read_bytes())
(out/'RESULT_ASSEMBLY.json').write_text(json.dumps({'cox_unchanged_tests_snapshot':'remote-r3','cox_updated_test_snapshot':'remote-r4','updated_test':selected,'superseded_failures':9,'reason':'Only evaluator list field ordering changed by canonical JSON; final comparison covers complete canonical content, including signatures.','shared_server_snapshot':'remote-r4','client_and_existing_endpoint_snapshot':'remote-r2'},indent=2)+'\n')
