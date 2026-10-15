# B1 review by the maintainer's Claude session: ACCEPTED

I re-ran the B1 checks myself, in the isolated env with nice:
- server R: 518 assertions (473, 24, 21), zero failures or skips;
- client R: 344 assertions (312, 32);
- Go targeted package tests: ok;
- Go/R byte agreement: 269/269.

Spot checks:
- `.dsvert_dp_irls_stage_body` recomputes β_{t+1} from the authenticated chain through the Go update and rejects a
  supplied different `candidate_beta`.
- `_successor_prepare` enforces the single-successor reservation and returns retained bytes on replay.
- The diff against `f2b919e` adds files only, apart from DESCRIPTION, NEWS and the CLI registration in `main.go`.

The conservative choices in `B1_QUESTIONS.md` are accepted:
- Tier-1 families and split lanes only;
- pure v4 accounting, with any finite-protocol delta added before producer admission;
- the additive formula grammar;
- the local SQLite stores (operational anti-rollback goes to B4).

Proceed to B2.
