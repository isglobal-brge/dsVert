# Final Cox release-manifest review

**PASS.** Independent read-only audit of the emitted manifest, status, committed source and retained proof evidence. No source edits, commits or job launches.

- Exactly four ready Cox rows: epsilon 8, K2/K3/K5 baseline and K2 recovery; each uses N=400, P=5, grid=2, one real release, cold/tamper checks and detached stdin. Only K2 recovery enables interruption.
- All 20 non-Cox release rows remain byte-for-byte identical, in the same order, to `prior-manifests/RELEASE_MANIFEST.jsonl`. Existing status fields remain unchanged except the intended Cox family readiness/source additions and removal from pending families. Global `fleet_ready=false` correctly preserves pending GEE families.
- Every Cox row and the family preparation command pin server `c97cd193c06dbae695792b4a03644c05fa733f8f` and client `28be3cd6fea312d8f1c2442c810b453ad81080ce`. Both source trees are clean. Committed source and the retained signed Cox contract have `runtime_enabled=true`; both spec constructors enforce N<=400.
- All rows bind oracle hash `ba5d77ddffabca8ce5b9be5f516aee3662b90b6e44a2ef0bfb886da6c8bb950d`. K2/K3/K5 bound records match original metrics hashes and the final source-attribution audit; all 2078 target dependency hashes were independently rechecked. Attribution explicitly records retained-oracle source equivalence, not rerunning on the final pair.
- Baseline `proof-r3` and native recovery `proof-r4-recovery` both exit 0 and contain bitwise oracle, sticky replay, cold tamper and cold exported-API authentication markers. Recovery records actual prepare/remask and unilateral-commit exact replay. These are small signed proofs; N400 fleet jobs were not launched or claimed completed.

Reviewed release manifest SHA256: `39337a1ffd1911cc0a5cee4375739ecbf22ea9036af92956c42a820265dca3f2`.

Evidence: `ORACLE_SOURCE_EQUIVALENCE.json`, `oracles-bound/cox-k{2,3,5}.json`, `baseline-certificate.json`, and both proof directories under `integrator-evidence/cox-ultra/`.
