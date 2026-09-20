# Private Cox worker preparation using the existing authenticated source store
# and staged native ABI. Only the signed routing commitment may leave the owner;
# the opaque worker input, observed times and permutation remain server-local.
.dsvert_dp_cox_cross_prepare_worker <- function(policy, secret, manifest,
    source_contract, schema_manifest, ss, analysis_id,
    resolved_snapshots = NULL, routing_receipt = NULL) {
  context <- .dsvert_dp_cox_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  spec <- context$spec
  .dsvert_dp_cox_cross_source_alignment(spec, policy, ss,
    source_contract$capsule_id, context$source_hash)
  owner <- spec$time$owner_peer
  garbler <- identical(policy$peer_name, owner)
  authorities <- sort(vapply(unlist(spec$computation_peers, use.names = FALSE),
    function(peer) .dsvert_relay_peer_id(unname(policy$peer_pinset[[peer]])),
    character(1L)), method = "radix")
  semantic_key <- .dsvert_dp_glm_grid_cross_key(manifest, context$artifact, source_contract)
  expected <- list(version = "dsvert-cox-staged-routing-receipt-v1",
    capsule_id = source_contract$capsule_id, analysis_id = analysis_id,
    peer_name = owner, peer_identity_pk = unname(policy$peer_pinset[[owner]]),
    semantic_key = semantic_key, artifact_sha256 = .dsvert_joint_dp_hash(context$artifact),
    source_contract_sha256 = context$source_hash,
    profile_sha256 = context$artifact$numeric_certificate$profile_sha256,
    certificate_sha256 = context$artifact$numeric_certificate$certificate_sha256,
    private_result_exposed = FALSE)
  digest <- ""
  if (!is.null(routing_receipt)) {
    .dsvert_dp_glm_grid_cross_fields(routing_receipt,
      c(names(expected), "routing_digest", "stage_plan_digest", "signature"))
    .dsvert_dp_glm_grid_cross_equal(routing_receipt[names(expected)], expected)
    if (!.dsvert_dp_capsule_source_verify(routing_receipt, policy,
        "cross-grid-result", owner)) .dsvert_dp_cox_grid_cross_fail()
    for (field in c("routing_digest", "stage_plan_digest")) {
      value <- routing_receipt[[field]]
      .dsvert_joint_dp_vector_exact_gc_hex(value, "Cox routing receipt")
      if (identical(value, strrep("0", 64))) .dsvert_dp_cox_grid_cross_fail()
    }
    digest <- routing_receipt$routing_digest
  } else if (!garbler) .dsvert_dp_cox_grid_cross_fail()
  routing <- NULL
  if (garbler) {
    if (is.null(resolved_snapshots)) .dsvert_dp_cox_grid_cross_fail()
    committed <- .dsvert_dp_cox_cross_committed_source(policy, secret, manifest,
      source_contract, schema_manifest, analysis_id, resolved_snapshots)
    on.exit(try(committed$producer$reset(), silent = TRUE), add = TRUE)
    # The adapter regenerated this private route from the same authenticated
    # snapshots and matched the durable outbound commitment before returning it.
    routing <- committed$private_route$routing
  } else if (!is.null(resolved_snapshots)) .dsvert_dp_cox_grid_cross_fail()
  handoff <- .dsvert_dp_cox_cross_load_handoff(policy, secret, manifest,
    source_contract, schema_manifest, ss, analysis_id)
  directory <- file.path(dirname(.dsvert_dp_capsule_source_store_path(policy)),
    "cox-staged-v1", semantic_key)
  if (!dir.exists(directory) &&
      !dir.create(directory, recursive = TRUE, mode = "0700", showWarnings = FALSE)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  key <- .dsvert_dp_capsule_source_mac(secret, "cox-stage-store-key-v1", semantic_key)
  worker <- .dsvert_dp_cox_cross_prepare_native(handoff,
    if (garbler) "garbler" else "evaluator", paste0("cox-staged-", semantic_key),
    unname(authorities), semantic_key, directory,
    .dsvert_dp_capsule_source_hex_raw(key, "Cox durable stage key"), routing, digest)
  if (!is.null(routing_receipt) &&
      !identical(worker$stage_plan_digest, routing_receipt$stage_plan_digest)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  if (garbler) routing_receipt <- .dsvert_dp_capsule_source_sign(c(expected,
    worker[c("routing_digest", "stage_plan_digest")]), policy, "cross-grid-result")
  list(worker = worker, routing_receipt = routing_receipt)
}

# Bind only after the existing source/alignment/owner-route checks succeed.
# Public dispatch remains closed until the signed source catalog is integrated.
.dsvert_dp_cox_cross_bind <- function(policy, secret, manifest, source_contract,
    schema_manifest, analysis_id, ss, resolved_snapshots = NULL, routing_receipt = NULL) {
  context <- .dsvert_dp_cox_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  prepared <- .dsvert_dp_cox_cross_prepare_worker(policy, secret, manifest,
    source_contract, schema_manifest, ss, analysis_id, resolved_snapshots, routing_receipt)
  bound <- .dsvert_dp_staged_cross_bind_worker(policy, manifest, source_contract,
    analysis_id, ss, context, prepared$worker)
  list(bound = bound, routing_receipt = prepared$routing_receipt)
}

# Internal DP adapters: public identity is read before START; private candidate
# shares/validities are consumed only by the post-START source path. Registration
# and remote dispatch must compose these adapters before admitting Cox releases.
.dsvert_dp_cox_cross_sampler_binding <- function(policy, secret, manifest,
    source_contract, schema_manifest, analysis_id) {
  context <- .dsvert_dp_cox_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  record <- .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    public <- .dsvert_dp_glm_grid_cross_load(con, secret,
      source_contract$capsule_id, analysis_id, -1L)
    .dsvert_dp_lmm_cross_public_record_validate(public, manifest,
      context$artifact, source_contract)
  })
  record[c("stage_receipt", "stage_plan_digest")]
}

.dsvert_dp_cox_cross_inject <- function(con, secret, manifest, source_contract,
    chunk, share, policy, schema_manifest, analysis_id) {
  context <- .dsvert_dp_cox_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  .dsvert_dp_staged_cross_inject_artifact(con, secret, manifest, source_contract,
    chunk, share, policy, context$artifact, context$spec$time$owner_peer)
}

# A Cox source is an exclusive opaque native input, never a public ring share.
.dsvert_dp_cox_cross_validate_worker_source <- function(source, ring, frac_bits, purpose) {
  input <- source$cox_loss
  other <- Filter(Negate(is.null), source[c("grouped_lmm", "grouped_glmm", "grouped_gee", "cross_grid")])
  if (ring != 128L || frac_bits != 0L || length(other) != 0L ||
      !identical(source$producer, "dp.cox-grid-cross.staged-v1") ||
      !identical(source$share, "") || !is.character(input) ||
      length(input) != 1L || is.na(input) || !nzchar(input) ||
      nchar(input, type = "bytes") > 64 * 1024^2 ||
      !grepl("^cox-loss-staged-v1/[0-9a-f]{64}$", purpose)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  invisible(NULL)
}
