import csv,datetime,hashlib,json,subprocess
from pathlib import Path
out=Path(__file__).resolve().parent;root=out.parents[1];snap=out/'proof-r1'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
m=json.loads((snap/'source-manifest.json').read_text())
assert all(sha(snap/n)==h and sha(root/n)==h for n,h in m['sha256'].items())
files=sorted(out.glob('test-*.csv'));assert len(files)==8
rows=[r for p in files for r in csv.DictReader(p.open())]
assert all(r['failed']=='0' and r['error']=='FALSE' and r['warning']=='0' and r['skipped']=='FALSE' for r in rows)
proof=dict(observed_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),source_commits={r:subprocess.check_output(['git','-C',str(root/r),'rev-parse','HEAD'],text=True).strip() for r in ('dsVert','dsVertClient')},tests=len(rows),assertions=sum(int(r['nb']) for r in rows),failures=0,errors=0,warnings=0,skips=0,frozen_source_files=len(m['sha256']),frozen_source_changed=[],final_source_differences=[],manifest_sha256=sha(snap/'source-manifest.json'),scope='Exact Cox producer selection for Claim and source sharing, all source owners at K2/K3/K5; equal bytes and value commitments across base and Synopsis namespace; altered contracts/version and schema lookup failures reject. Catalog admission, schema cache lookup, and transport context use test doubles in the new test. Existing real signed Cox validation, native worker, durable source/reader and shared Synopsis regressions included. Additional fixture-catalog K2 Ed25519 Claims verify and match the real sharing commitment validator; altered bytes and signatures reject. No complete admitted Cox sharing/persistence transaction, DP release, capacity or promotion.',test_results={p.name:sha(p) for p in files})
(out/'R_PROOF.json').write_text(json.dumps(proof,indent=2)+'\n');print(json.dumps(proof,indent=2))
