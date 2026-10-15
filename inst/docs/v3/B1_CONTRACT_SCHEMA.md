# B1 contract schema / internal API

All numeric leaves are canonical decimal integer strings or rational objects
`{d:"...",n:"..."}` with a positive denominator. Flags are `"0"` or `"1"`.
Arrays are unnamed lists; object keys sort lexicographically. No float/bool/null.
Normalization reduces rational pairs; signed envelopes must carry the normalized
contract. No analysis/display alias enters the contract. Root includes all groups.

Signed envelope: `{version:"dsvert-dp-irls-contract-v1", contract:SPEC, signatures:{peer:signature}}`.
SPEC has exactly `mechanism:"dp_irls_v1"`, `profile_id`, and these seven groups:

* estimand: `formula`, `coefficient_order` [strings], `family`, `link`,
  `levels` [objects {column_id,values:[strings]}], `contrasts` [objects
  {column_id,coding,coefficient_names:[strings]}], `columns` [objects
  {column_id,owner,source_id,role}], `offset` {kind,column_id,zero_exposure},
  `intercept` flag, `clamped_target`, `model_assumptions` [strings].
* privacy_source: `adjacency`, `capacity`, `row_cap`, `closure` (existing
  Synopsis complete authorization closure), `source_ids` [strings in closure
  order, all dependencies including membership-only], `alignment_purpose`,
  `missing_rule`, `duplicate_rule`, `ordering_rule`, `x_bounds` [{lower,upper}],
  `y_bounds` {lower,upper}, `offset_bounds` {lower,upper},
  `person_caps` {score_abs:[q],curvature_abs:[q]}, `peer_pins` {peer:pk},
  `pinset_sha256`, `computation_peers` [two peer names], `schema_sha256`.
* numeric: `eta_bounds` {lower,upper}, `score_definition`, `curvature_definition`,
  `curvature_role`, `approximation_certificate_sha256`, `lattice`
  {g:q,H:q,beta:q}, `rounding`, `rounding_slack` {g:q,H:q}, `ring_bits`,
  `source_intermediate_bits`, `layout` [strings g:1,...,H:1:1,...],
  `translation` {g:[int],H:[int]}, `person_integer_caps` {g:[int],H:[int]},
  `translation_margin` {g:[int],H:[int]}, `upper_limits` {g:[int],H:[int]},
  `compiler_version`, `backend_version`, `sampler_version`, `certificate`
  (numeric ABI bounds object, finalized with arithmetic agent), `certificate_sha256`.
* path: `T`, `start` {kind,digest,beta:[q],epsilon:q,composition_sha256},
  `box` {lower:[q],upper:[q]}, `floor`, `floor_quantum`, `ridge`,
  `damping` [q], `trust` [q], `refresh_mask` [flag], `terminal_audit`,
  `update_version`, `tie_rule`, `root_domain`, `stage_domain`, `lane_domain`,
  `role_domain`, `pin_domain`.
* accounting: `geometry:"split-block-v1"`, `stages` [{t,purpose,g:q,H:q,epsilon:q,
  alpha_g:q,alpha_H:q}], `sensitivity` {g:int,H:int}, `pilot_epsilon`:q,
  `auxiliary` [{id,epsilon:q}], `epsilon_path`:q, `delta`:q, `rho`:q,
  `noise_law`, `draws_per_authority`, `authority_count`, `failure_semantics`.
* inference: `mode`, `method`, `qualification_certificate_sha256`,
  `replay` {law,version,seed,replicates}, `confidence`,
  `refusal` {any_shift,any_trust,any_projection,any_saturation,ridge,
  positive_information,domain_margin,terminal_audit} (flags),
  `thresholds` {diagnostic_tail,curvature_error_ratio,condition_max,bias_sd_ratio,
  replay_precision}, `tolerances` {approximation,bias,noise_tail},
  `allowed_contrasts` [[q]].
* operations: `shape` {p,coordinates,capacity,row_cap}, `max_compile_bytes`,
  `max_memory_bytes`, `max_stage_seconds`, `max_path_seconds`,
  `recovery_version`, `retention_policy`, `resource_failure`.

API prefix `.dsvert_dp_irls_`: `contract_normalize(spec)`,
`contract_validate(envelope,trusted_pins) -> spec`, `contract_message(unsigned_envelope)`,
`json(value)`, `hash(domain,value)`, `root(spec)`, `start_digest(spec)`,
`stage_id(spec,t,predecessor,purpose=NULL)`, `lane_id(stage_id,lane)`,
`payload_digest(spec,t,payload)`, `accounting(spec,observed=list())`.
Payload is `{g:[integer strings],H:[integer strings]}` at refresh/audit stages,
or `{g:[integer strings],H_reference:{stage_id,payload_digest}}` at score-only
stages. H reference is authenticated by parent stage signature, not separately
randomized signature bytes. Observed accounting entries are `{t,lanes:["g","H"]}`;
pilot epsilon is always conservatively charged (existing release). Complete and
partial stages charge observed lanes, without refunding reserved full path.

`numeric$lattice$g` and `$H` are effective physical units `s_g*h_g` and
`s_H*h_H`; beta is the coefficient quantum. B2 must not multiply another scale.

B1 formula grammar is deliberately restricted: a two-sided outcome symbol and
additive declared predictor symbols, parentheses, optional `0`, `1`, or `-1`
intercept directives, and an explicitly signed `offset(column)` or
`offset(log(exposure))`. Unknown, duplicate, transformed, interacted, dotted,
or conflicting terms reject without evaluation. Canonical text orders predictor
terms as written, places a signed offset last, and omits a redundant intercept 1.
Coefficient order must equal intercept plus predictor order, expanding categorical
predictors by their declared contrast coefficient names; categorical levels require
an explicit contrast declaration. No R evaluation/model-matrix expansion occurs.
Broader formulas need a future signed compiler grammar/certificate rather than an
implicit B1 interpretation. This restriction makes inconsistent declarations
fail closed before any protected producer exists.
