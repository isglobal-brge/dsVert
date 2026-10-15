# B1 decisions and B2 review questions

The maintainer's Phase A session review was read before implementation. No
`claude` CLI was invoked. The approved design bytes are unchanged.

No maintainer decision blocks the public B1 implementation. These conservative
choices need review with the B1 report:

* The new signed schema admits Tier-1 binomial/logit and Poisson/log, split lanes,
  and pure v4 Laplace accounting only. A future finite validity protocol must add
  and validate its implementation delta before producer admission; B1 does not
  assert that a future complete protected route is pure DP.
* JSON ordering and reduced `{d,n}` rationals are fixed in the new update ABI.
  Contract flags are integer strings. The public arithmetic engine has fixed
  maximum shape and byte ceilings; these are not protected-producer admissions.
* B1 reservations use private, explicitly provisioned SQLite stores, one per
  authority/path, with FULL synchronization, atomic transactions, signatures,
  and a retained directory marker. Process crashes, corrupt/missing databases,
  and competing requests fail closed. A privileged operator rolling back the
  entire store and its directory requires an external anti-rollback trust
  anchor, beyond this local-store model; B4 must settle operational recovery.
* Existing registry identifiers, canonicalization, Synopsis catalog pinsets and
  complete provenance-closure checks, and Ed25519 helpers are reused. Actual
  selector/catalog registration and R/DSI availability remain B3/B4 work.
* The contract wire validator is mirrored in the client; the client arithmetic
  implementation is independent R/gmp and never calls Go or the server package.

B2 must freeze the actual fused score/H definitions, signed evaluation-point
ABI, public p/n admission profile, translation/scaling constants, deterministic
source ranges, approximation errors, person-level rounding sensitivity and
numeric certificate. Both lanes must derive from one protected evaluation.
The smoke profile still needs those producer-certified constants before timing.

The showcase profile `irls-showcase-k2-p3-v1` must choose the smallest n achieving
at least 80% acceptance at epsilon 8, p=3 using the public whole-mechanism
simulator before any live run. The roughly 200-dataset smoke/showcase refusal
pre-check and accepted-fit coverage remain mandatory before B5, under the
review's five-minute/nice limit. B1 does not invent a showcase n or run a demo.

The B1 report is ready for the maintainer's Claude-session review when complete;
implementation tests do not substitute for that review. A failed or delayed
B3 week-2 cost gate still requires a maintainer decision and stops promotion.
