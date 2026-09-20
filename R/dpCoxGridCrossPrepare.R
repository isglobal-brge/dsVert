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

# DP adapters: public identity is read before START; private candidate
# shares/validities are consumed only by the post-START source path.
.dsvert_dp_cox_cross_artifacts <- function(manifest) {
  Filter(function(artifact) identical(artifact$family, "cox"),
    manifest$workload$families$gaussian_models$artifacts)
}

.dsvert_dp_cox_cross_release_context <- function(policy, secret, manifest,
    source_contract, schema_manifest = NULL, analysis_id = NULL) {
  artifacts <- .dsvert_dp_cox_cross_artifacts(manifest)
  if (!length(artifacts)) return(NULL)
  if (length(artifacts) != 1L) .dsvert_dp_cox_grid_cross_fail()
  if (is.null(analysis_id)) analysis_id <- artifacts[[1L]]$analysis_id
  if (!identical(analysis_id, artifacts[[1L]]$analysis_id)) .dsvert_dp_cox_grid_cross_fail()
  if (is.null(schema_manifest)) {
    schema_manifest <- .dsvert_dp_lmm_cross_signed_schema(policy, secret,
      .dsvert_joint_dp_hash(manifest), manifest)
  }
  .dsvert_dp_cox_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
}

.dsvert_dp_cox_cross_sampler_binding <- function(policy, secret, manifest,
    source_contract, schema_manifest = NULL, analysis_id = NULL) {
  context <- .dsvert_dp_cox_cross_release_context(policy, secret, manifest,
    source_contract, schema_manifest, analysis_id)
  if (is.null(context)) return(NULL)
  record <- .dsvert_dp_cox_cross_public_record(policy, secret, manifest, context)
  record[c("stage_receipt", "stage_plan_digest")]
}

.dsvert_dp_cox_cross_public_record <- function(policy, secret, manifest, context) {
  record <- .dsvert_dp_capsule_source_with_store(policy, secret, function(con) {
    public <- .dsvert_dp_glm_grid_cross_load(con, secret,
      context$source_contract$capsule_id, context$spec$analysis_id, -1L)
    .dsvert_dp_lmm_cross_public_record_validate(public, manifest,
      context$artifact, context$source_contract)
  })
  record
}

# Internal publication adapter. The durable publication reader authenticates
# the existing DP release; this adds its Cox terminal provenance without
# reading private candidate rows or admitting a new release.
.dsvert_dp_cox_cross_evidence <- function(policy, secret, manifest, source_contract,
    schema_manifest, analysis_id, manifest_sha256, artifact_key) {
  context <- .dsvert_dp_cox_cross_source_context(policy, manifest,
    source_contract, schema_manifest, analysis_id)
  if (!policy$peer_name %in% unlist(context$spec$computation_peers, use.names = FALSE)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  record <- .dsvert_dp_cox_cross_public_record(policy, secret, manifest, context)
  publication <- .dsvert_dp_synopsis_publication_v1(manifest_sha256, policy, secret)
  released <- publication$release_receipt
  if (!identical(publication$artifact_key, artifact_key) ||
      !identical(released$artifact_key, artifact_key) ||
      !identical(released$source_contract_sha256, context$source_hash)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  binding <- list(contract = context$source_contract, analysis_id = analysis_id,
    semantic_key = record$semantic_key, artifact = context$artifact,
    contract_hash = context$source_hash, stage = list(stage_plan_digest = record$stage_plan_digest))
  .dsvert_dp_lmm_cross_public(binding, policy, "published", c(list(
    coordinate_count = context$artifact$coordinate_count, stage_receipt = record$stage_receipt),
    released[c("artifact_key", "execution_id", "final_vector_root", "result_set_sha256")]))
}

.dsvert_dp_cox_cross_inject <- function(con, secret, manifest, source_contract,
    chunk, share, policy, schema_manifest = NULL, analysis_id = NULL) {
  context <- .dsvert_dp_cox_cross_release_context(policy, secret, manifest,
    source_contract, schema_manifest, analysis_id)
  if (is.null(context)) return(share)
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
