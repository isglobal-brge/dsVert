# Cox decisions

## 2026-09-18 resumed
- Apply DECISION_DAY1_ARITHMETIC_ROUTE.md and REVIEW_NOTE_PRIMITIVE.md. Frozen f50/f100 source encoding is retained; one rounding after the two-owner sum produces q16 eta. Nonlinearities use pinned 64-piece linear profiles, 32-bit scalar operands, q20 outputs. Prefix and cohort sums use exact wider integers.
- Minimize negative Breslow partial log likelihood (the negative of the user equation), with one whole-cohort ties-even quantization and clamp. No per-row independent-loss sensitivity claim: changing one record changes other risk sets. Conservative whole-coordinate range bounds cover both adjacencies.
- Chunk schedule per candidate: prepare at most 32 rows, Beneš tiles of at most 64 switches, forward prefix tiles of at most 32 padded rows, backward tie-denominator propagation and loss tiles in reverse order, finalize. Every lane receives a fresh mask. Carry W/H/L and private validity must persist across chunks. Outcome owner supplies private descending-time routing/tie ends; input order remains PSI order.
- Registration is an internal integration boundary. No RPC or production plaintext fallback. Tests alone cannot promote the signed states; source/lifecycle wiring remains explicitly fail closed until the separate integration session connects authenticated joint DP publication.
- Keep all work additive except the single export(dp_cox_grid) client registration. Preserve same-owner and generation-one code.
