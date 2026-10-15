# Phase A review by the maintainer's Claude session

Document reviewed: `DESIGN_V3_DP_IRLS.md`, SHA256 `f67bdabbb8b2b6fdda36b8062c5e7e5e85a064bba3905c256f5e6e543b08aa9b`.

## Process note (for the record)

`CONSENSUS_V3_DP_IRLS.md` reports consensus with "Claude", reached by invoking a separate `claude` CLI instance in
text-only mode. That instance is not the Claude session working with the maintainer. It had no repository or
conversation context, and it is not the reviewer named in the brief. Its two rounds are useful additional review, but
they are **not** the consensus the brief required.

Future briefs:
- "Claude" means this session;
- exchange through files in this directory and messages to this session;
- do not invoke the `claude` CLI.

## Verdict: AGREE, with five additions

I read the whole document. I agree with these decisions:
- the cross-grid production lifecycle with a fused public-point score/H GC program;
- the exact rational diagonal-shift update, with both authorities recomputing and signing the successor, an
  independent bignum client verifier and frozen #25 epochs;
- one dual-signed artifact per stage, split g/H lanes with atomic publication, and v4 two-full-draw convolution;
- the signed-translation adapter for negative coordinates (a necessary catch: the current vector finaliser clamps to
  `[0,U]`);
- the budgeted terminal audit, the replay+H⁻¹ inference candidate, the refusal rules and the sensitivity algebra (§7);
- the Tier-2 order, the week-2 go/no-go cost gate, and mechanism-level validation only.

### Additions, binding for Phase B

1. **Defence showcase profile.** The frozen smoke profile (n = 64, p = 3, T = 2, ε = 8) is a wiring and cost fixture.
   By §8's own rules it will probably refuse inference. The maintainer needs to show coefficients **with** SEs next to
   `glm()`.
   - Add a second signed profile, `irls-showcase-k2-p3-v1`, with n chosen by the clear-text whole-mechanism simulator.
     It is the smallest n at which the refusal policy accepts at least 80% of fits for a stated design, at
     ε_total = 8, p = 3.
   - Choose n **before** any live run, from public simulation only.
   - Run it once live after the Tier-1 gates pass. If it exceeds 15 minutes, it needs the maintainer's explicit
     one-off approval, as with the 1.4.2 K3 run.
   - Report it as a demonstration, not as qualification.
2. **Refusal-policy pre-check in the clear.** Before the live demo, run the corrected replay candidate and the §8
   refusal rules on the clear-text whole-mechanism simulator for the smoke and showcase profiles: about 200 datasets,
   ≤ 5 min, nice. Report the acceptance rate and accepted-fit coverage. This is a sanity check, not the qualification
   milestone.
3. **Milestone reports.** Phase B runs as separate astra tasks, each ending with a report and a review by this session:
   - B1: contract, path, accounting and the rational update, with its verifier;
   - B2: fused score/H program and numeric certificate, exactness against the integer oracle;
   - B3: thin R/DSI stage and the week-2 cost gate;
   - B4: durable publication, client, inference candidate and refusal;
   - B5: live smoke and showcase.

   A failed B3 gate stops the line for a maintainer decision.
4. **Environment isolation.**
   - New worktrees: `/workspace/dsflower/v3-dsVert` and `/workspace/dsflower/v3-dsVertClient`, branch
     `feature/v3-dp-irls`, from 1.4.2 on main (server `f2b919e`, client `5245af5`).
   - A separate runtime: `/workspace/dsflower/.tmp/v3/env.sh`, with its own R library, Go caches and `bin/dsvert-mpc`
     build, and `DSVERT_SERVER_SOURCE` pointing to the v3 server worktree.
   - Never overwrite the 1.4.2 runtime under `.tmp/vertcor`.
5. **Versioning.** Use `1.5.0.9000` on the dev branch, as proposed. The maintainer chooses the final number. The
   house rule is a patch bump, so ask before release.

**Scope commitment to the maintainer by about December:**
- Tier 1 (binomial and Poisson) with continuous estimates, and SEs as an experimental candidate with refusal;
- the Tier-2 first slice: person-period/PEM survival and multinomial;
- NB2 and ordinal only with demonstrated slack;
- Tier 3 is not committed.

With these additions, Phase B may start at B1.
