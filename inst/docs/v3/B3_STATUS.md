# B3 status (maintainer-session record, 15 Oct 2026)

astra's B3 run stopped at its Codex usage limit (it resets on 22 Oct) while B3 was mid-flight. The maintainer's
Claude session completed it.

## Fixes

| Fix | Commit |
|---|---|
| Harness transport-clock tracer (environment substituted as an assignment target) | client `1ea82b6` |
| DSI-safe relay frames: first the DSI text framing, then verbatim base64url with a `"none"` sentinel for an empty frame, because the text framing cost about 0.7 s per frame | server `5cc4ba8`, `e5b0b44`; client `a44423a`, `13c4351` |
| Finaliser output decoded without simplification, so each lane keeps its `translated_values` | server `5cc4ba8` |
| Relay chunk follows the exact-GC chunk policy, capped at 384 KiB so that the nested base64 of the sealed envelope (about 1.78×) stays under the client's 768 KiB DSI expression bound; the native worker and progress check use the signed `max_stage_seconds` instead of a hard-coded 900 s | server `5db89ab`, `e387eee` |

## Outcomes

- **n = 4 integration:** one complete stage (MPC, mandatory two-lane noise, dual-signed publication) PASS in 102 s.
- **n = 64 cost gate:** FAIL against the 240 s per-stage target (stopped at 242 s). The maintainer chose option A:
  accept for a proof of concept and document the cost.
- **n = 64 proof of concept:** the full path (three signed releases) PASS. Stages took 268 s, 453 s and 493 s; the
  path took 1,219 s. Results and evidence are in dsVertClient `inst/validation/v1.5.0-poc/`.
- **Inference:** correctly refused at n = 64 (trust truncation, floor shift, replay bias).

## Open items

- Row tiling for C > 64.
- Poisson end-to-end.
- Transport efficiency: multi-chunk frames, fewer process spawns per relay call.
- Statistical qualification of the inference candidate.
- Tier 2.
