# LMM sampler coordinate admission

Reuse the existing signed Synopsis lifecycle and joint exact-GC sampler.
The LMM ML contract admits up to 256 variance/beta candidates. Its public
vector also contains the admitted-count coordinate, hence 257 total.

For a single LMM artifact above 51 total coordinates, server and client select
`dsvert-lmm-grid-exact-gc-cost-policy-v1` (ceiling 257). Existing small LMM
releases retain their v2 policy identity for authenticated cold replay.
Simple-family and GLMM policy ceilings remain unchanged. The new policy uses
the existing certified sampler chunk capacity, including the final short chunk;
it neither changes native arithmetic nor authorizes a different noise draw.
Preflight still rebuilds and authenticates the signed profile and artifact.
Public release verification derives and checks the same policy.

This is public sampler admission, not heavy-family promotion or a capacity
measurement. The internal backend field `promoted` selects the exact-GC sampler;
it is not the PROMOTION_TABLE.md gate. Actual n2000 proof remains required.

The structured release fixture already assigns the smaller pinned transport
identity to the grouping owner's bootstrap home before pinning or signing.
The same harness already binds signed workload/profile/artifact admission,
public structured readers, publication provenance, sticky/tamper and cold paths.
Do not replace it or modify existing frozen release snapshots.
