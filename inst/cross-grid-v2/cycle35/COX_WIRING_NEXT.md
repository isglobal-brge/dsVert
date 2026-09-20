# Cox lifecycle after cycle35

Completed shared hooks (not public admission):
- `dpSynopsisLifecycleDS.R`: retain signed Cox schema in the authenticated cache.
- `dpSynopsisExecutionDS.R`: public terminal binding before compiler/START; reject
  non-exact sampling so private validity cannot be discarded.
- `dpCapsuleSourceTransportDS.R`: durable candidate injection after completed-source
  checks on the post-START reader path.
- `jointDPVectorCapsuleDS.R`: legacy PREPARE/START cannot bypass the validity gate.

Remaining integration, preserving N<=400 staged scope:
1. `dpGLMGridCrossMaterializer.R` discovery/source blocks, `dpCapsuleMaterializer.R`
   schema/artifact validation, and matching client discovery currently exclude
   the Cox cross artifact. Do not add Cox to a grouped predicate: its time-owner
   routing and `cox-loss-staged-v1` operation are distinct.
2. `dpGLMGridCrossLifecycle.R` remote admission around bind/evidence must dispatch
   explicit Cox context, authenticated schema lookup and owner-route receipt.
   Reuse the existing request/artifact/source validation and source transport
   gate. `dpLMMGridCrossLifecycle.R` remote bind assumes `grouping`, so cannot be
   called directly. Existing staged session dispatch can consume the bound Cox
   worker only after these validations. Keep source rematerialization and durable
   owner commitment checks before preparing native input.
3. `dp_synopsis_vector_runner.R` needs explicit Cox orchestration and publication
   receipt collection. `dp_gaussian_certificate.R` must authenticate the Cox
   descriptor, lattice, bounds and evidence before result reading; the old
   same-owner Cox partial-likelihood descriptor is a different family path.
4. Feed only authenticated trusted bundle/compilation into the cycle34 internal
   `.dsvert_dp_cox_cross_read_vector`. Its signature/REPLAY/Merkle/publication
   checks are not a substitute for public compilation/admission.

Then prove a fresh small complete signed producer -> native -> durable DP ->
cold public reader lifecycle, including bilateral/unilateral recovery and
source/stage tamper rejection, before fleet readiness. Kernel-only capacity
and mocked release/compilation fixtures do not establish this proof.
