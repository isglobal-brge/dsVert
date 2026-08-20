# Product-bound adapter between the biomedical vector and the durable
# cross-signed capsule allocator.  Unlike the generic bridge, the analyst
# cannot provide a proposal: every proposal field is derived from a manifest
# that this server already authenticated and memoized.

.DSVERT_JOINT_DP_VECTOR_ALLOCATION_VERSION <-
  "dsvert-joint-dp-biomedical-vector-allocation-v1"

.dsvert_joint_dp_vector_allocator_proposal <- function(
    policy, manifest_json, secret = NULL,
    .manifest_gate = .dsvert_dp_capsule_manifest_require_built) {
  if (is.null(secret)) secret <- .dsvert_dp_secret()
  if (!is.function(.manifest_gate)) {
    stop("Invalid biomedical manifest authorization gate.", call. = FALSE)
  }
  record <- .manifest_gate(policy, manifest_json, secret = secret)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  validated <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  context <- .dsvert_joint_dp_policy_context(policy)
  source <- .dsvert_dp_capsule_source_contract_json(policy, manifest_json)
  source_contract <- .dsvert_dp_capsule_source_contract_validate(
    source$contract)
  if (!identical(source$contract_hash,
                 .dsvert_joint_dp_hash(source_contract))) {
    stop("The biomedical source contract hash is invalid.", call. = FALSE)
  }
  manifest_sha256 <- digest::digest(
    manifest_json, algo = "sha256", serialize = FALSE)
  if (!is.list(record) ||
      !identical(record$manifest_json, manifest_json) ||
      !identical(record$manifest_sha256, manifest_sha256) ||
      !is.character(record$cache_key) || length(record$cache_key) != 1L ||
      is.na(record$cache_key) || !grepl("^[0-9a-f]{64}$", record$cache_key) ||
      !is.character(record$local_authority_sha256) ||
      length(record$local_authority_sha256) != 1L ||
      is.na(record$local_authority_sha256) ||
      !grepl("^[0-9a-f]{64}$", record$local_authority_sha256)) {
    stop("The biomedical manifest authority record is invalid.",
         call. = FALSE)
  }
  protected_fingerprint <- .dsvert_joint_dp_hash(list(
    protocol = .DSVERT_JOINT_DP_VECTOR_ALLOCATION_VERSION,
    consortium_id = context$consortium_id,
    peer_name = context$peer_name,
    capsule_id = validated$identity$capsule_id,
    manifest_sha256 = manifest_sha256,
    manifest_cache_key = record$cache_key,
    local_authority_sha256 = record$local_authority_sha256,
    source_contract_sha256 = source$contract_hash))
  .dsvert_joint_dp_proposal(
    policy = policy,
    logical_snapshot = manifest$logical_snapshot,
    method = "biomedical_capsule_vector",
    arguments = list(
      allocation_protocol = .DSVERT_JOINT_DP_VECTOR_ALLOCATION_VERSION),
    protected_fingerprint = protected_fingerprint,
    mechanism = manifest$workload$capsule_mechanism,
    capsule_identity = validated$identity,
    .secret = secret)
}

.dsvert_joint_dp_vector_allocation_prepare_impl <- function(
    manifest_json, leader_prepare_json = "", .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL,
    .manifest_gate = .dsvert_dp_capsule_manifest_require_built) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (!is.character(leader_prepare_json) ||
      length(leader_prepare_json) != 1L || is.na(leader_prepare_json)) {
    stop("Invalid biomedical vector leader allocation receipt.",
         call. = FALSE)
  }
  proposal <- .dsvert_joint_dp_vector_allocator_proposal(
    .policy, manifest_json, .secret, .manifest_gate)
  leader <- if (!nzchar(leader_prepare_json)) NULL else
    .dsvert_joint_dp_dsi_receipt(
      leader_prepare_json, "biomedical vector leader prepare receipt")
  .dsvert_joint_dp_dsi_receipt_json(
    .dsvert_joint_dp_prepare(
      .policy, proposal, leader_prepare = leader,
      .secret = .secret, .signer = .signer, .verifier = .verifier,
      .phase_hook = .phase_hook),
    "biomedical vector allocation prepare receipt")
}

.dsvert_joint_dp_vector_allocation_commit_impl <- function(
    first_prepare_json, second_prepare_json, .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  .dsvert_joint_dp_dsi_commit_impl(
    first_prepare_json, second_prepare_json, .policy, .secret,
    .signer, .verifier, .phase_hook)
}

.dsvert_joint_dp_vector_allocation_authorize_impl <- function(
    first_commit_json, second_commit_json, .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  .dsvert_joint_dp_dsi_authorize_impl(
    first_commit_json, second_commit_json, .policy, .secret,
    .signer, .verifier, .phase_hook)
}

.dsvert_joint_dp_vector_allocation_open_impl <- function(
    first_authorization_json, second_authorization_json, .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  .dsvert_joint_dp_dsi_open_impl(
    first_authorization_json, second_authorization_json, .policy, .secret,
    .signer, .verifier, .phase_hook)
}

.dsvert_joint_dp_vector_allocation_require <- function(
    policy, manifest_json, secret = NULL, verifier = NULL,
    .manifest_gate = .dsvert_dp_capsule_manifest_require_built) {
  if (is.null(secret)) secret <- .dsvert_dp_secret()
  proposal <- .dsvert_joint_dp_vector_allocator_proposal(
    policy, manifest_json, secret, .manifest_gate)
  context <- .dsvert_joint_dp_policy_context(policy)
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_allocator_forensic_audit(
      handle$connection, policy, secret, verifier)
  })
  binding <- .dsvert_joint_dp_capsule_registry_reconcile(
    handle$connection, policy, context, secret,
    query_id = proposal$capsule_id, verifier = verifier)
  record <- .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_load(
      handle$connection, proposal$capsule_id, secret)
  })
  valid <- is.list(record) && identical(record$state, "open_authorized") &&
    identical(record$query_id, proposal$query_id) &&
    identical(.dsvert_joint_dp_hash(record$common_query),
              .dsvert_joint_dp_hash(proposal$common_query)) &&
    is.list(record$own_prepare) &&
    identical(record$own_prepare$capsule_id, proposal$capsule_id) &&
    identical(record$own_prepare$mechanism_hash, proposal$mechanism_hash) &&
    identical(record$own_prepare$snapshot_binding,
              proposal$snapshot_binding) &&
    is.list(record$own_authorization) &&
    is.list(record$peer_authorization) &&
    is.list(record$opening_token) &&
    is.list(binding) && is.list(binding$binding)
  if (!isTRUE(valid)) {
    stop("The biomedical capsule has no matching cross-signed allocation.",
         call. = FALSE)
  }
  invisible(list(
    version = .DSVERT_JOINT_DP_VECTOR_ALLOCATION_VERSION,
    capsule_id = proposal$capsule_id,
    allocation_index = record$allocation_index,
    registry_sequence = binding$binding$registry_sequence,
    authorized = TRUE, data_access = FALSE,
    history_gate = TRUE, request_limit = FALSE,
    operation_limit = TRUE))
}

.dsvert_joint_dp_vector_allocation_observer_require <- function(
    policy, manifest_json, first_opening_json, second_opening_json,
    secret = NULL, verifier = NULL,
    .manifest_gate = .dsvert_dp_capsule_manifest_require_built) {
  if (is.null(secret)) secret <- .dsvert_dp_secret()
  if (!is.function(.manifest_gate)) {
    stop("Invalid biomedical manifest authorization gate.", call. = FALSE)
  }
  .manifest_gate(policy, manifest_json, secret = secret)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  validated <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  openings <- .dsvert_joint_dp_receipt_set(
    .dsvert_joint_dp_dsi_receipt(
      first_opening_json, "first biomedical allocation opening proof"),
    .dsvert_joint_dp_dsi_receipt(
      second_opening_json, "second biomedical allocation opening proof"),
    policy, .DSVERT_JOINT_DP_OPEN_VERSION, "open_authorized", verifier,
    require_designated = FALSE)
  common <- .dsvert_joint_dp_output_common(
    openings,
    c("consortium_id", "capsule_id", "query_id", "allocation_index",
      "new_chain", "joint_record_hash", "authorization_set_hash",
      "release_scope", "capability_available"),
    "biomedical allocation opening")
  context <- .dsvert_joint_dp_policy_context(
    policy, require_designated = FALSE)
  if (!identical(common$consortium_id, context$consortium_id) ||
      !identical(common$capsule_id, validated$identity$capsule_id) ||
      !identical(common$query_id, validated$identity$capsule_id) ||
      !identical(common$release_scope, .DSVERT_JOINT_DP_SCOPE) ||
      !identical(common$capability_available, FALSE)) {
    stop("The cross-signed allocation does not authorize this biomedical capsule.",
         call. = FALSE)
  }
  invisible(list(
    version = .DSVERT_JOINT_DP_VECTOR_ALLOCATION_VERSION,
    capsule_id = common$capsule_id,
    allocation_index = common$allocation_index,
    opening_set_hash = .dsvert_joint_dp_hash(openings),
    designated_noise_peers = names(openings),
    authorized = TRUE, data_access = FALSE,
    relay_is_authority = FALSE, capability_available = FALSE,
    history_gate = TRUE, request_limit = FALSE,
    operation_limit = TRUE))
}

.dsvert_joint_dp_vector_allocation_proof_impl <- function(
    manifest_json, .policy = NULL, .secret = NULL, .verifier = NULL,
    .manifest_gate = .dsvert_dp_capsule_manifest_require_built) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  proposal <- .dsvert_joint_dp_vector_allocator_proposal(
    .policy, manifest_json, .secret, .manifest_gate)
  handle <- .dsvert_joint_dp_open_ledger(.policy)
  on.exit(if (!is.null(handle)) {
    .dsvert_joint_dp_close_ledger(handle)
  }, add = TRUE)
  pending <- .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_initialize_validate(
      handle$connection, .policy, .secret, .verifier)
    .dsvert_joint_dp_load(
      handle$connection, proposal$capsule_id, .secret)
  })
  if (is.null(pending)) {
    stop(.dsvert_phase_not_ready_condition())
  }
  matching <- identical(pending$query_id, proposal$query_id) &&
    identical(.dsvert_joint_dp_hash(pending$common_query),
              .dsvert_joint_dp_hash(proposal$common_query)) &&
    is.list(pending$own_prepare) &&
    identical(pending$own_prepare$capsule_id, proposal$capsule_id) &&
    identical(pending$own_prepare$mechanism_hash,
              proposal$mechanism_hash) &&
    identical(pending$own_prepare$snapshot_binding,
              proposal$snapshot_binding)
  if (!isTRUE(matching)) {
    stop("The biomedical allocation record conflicts with its manifest.",
         call. = FALSE)
  }
  if (!identical(pending$state, "open_authorized")) {
    if (pending$state %in% setdiff(
          .DSVERT_JOINT_DP_STATES, "open_authorized")) {
      stop(.dsvert_phase_not_ready_condition())
    }
    stop("The biomedical allocation record has an invalid state.",
         call. = FALSE)
  }
  .dsvert_joint_dp_close_ledger(handle)
  handle <- NULL
  certificate <- .dsvert_joint_dp_vector_allocation_require(
    .policy, manifest_json, .secret, .verifier, .manifest_gate)
  handle <- .dsvert_joint_dp_open_ledger(.policy)
  record <- .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_initialize_validate(
      handle$connection, .policy, .secret, .verifier)
    .dsvert_joint_dp_load(
      handle$connection, certificate$capsule_id, .secret)
  })
  if (!is.list(record) || !is.list(record$opening_token) ||
      !identical(record$opening_token$capsule_id,
                 certificate$capsule_id) ||
      !identical(record$opening_token$allocation_index,
                 certificate$allocation_index)) {
    stop("The biomedical allocation opening proof is unavailable.",
         call. = FALSE)
  }
  .dsvert_joint_dp_dsi_receipt_json(
    record$opening_token, "biomedical vector allocation opening proof")
}

.dsvert_joint_dp_vector_allocation_public <- function(phase, code) {
  tryCatch(force(code), error = function(error) {
    .dsvert_dp_transcript_stop(error)
  })
}

#' Prepare the server-authoritative biomedical capsule allocation (AGGREGATE)
#'
#' @param manifest_json Canonical manifest memoized by this server.
#' @param leader_prepare_json Empty on the deterministic leader; otherwise the
#'   leader's signed prepare receipt.
#' @return A signed allocation prepare receipt. No protected value is read.
#' @keywords internal
dsvertJointDPVectorAllocationPrepareDS <- function(
    manifest_json, leader_prepare_json = "DSV1R_") {
  .dsvert_joint_dp_vector_allocation_public("prepare", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    leader_prepare_json <- .dsvert_dsi_text_decode(
      leader_prepare_json, "biomedical vector leader prepare receipt",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_allocation_prepare_impl(
      manifest_json, leader_prepare_json)
  })
}

#' Commit the biomedical capsule allocation (AGGREGATE)
#' @param first_prepare_json,second_prepare_json Signed prepare receipts.
#' @return A signed durable commit receipt.
#' @keywords internal
dsvertJointDPVectorAllocationCommitDS <- function(
    first_prepare_json, second_prepare_json) {
  .dsvert_joint_dp_vector_allocation_public("commit", {
    first_prepare_json <- .dsvert_dsi_text_decode(
      first_prepare_json, "first biomedical allocation prepare receipt",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    second_prepare_json <- .dsvert_dsi_text_decode(
      second_prepare_json, "second biomedical allocation prepare receipt",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_allocation_commit_impl(
      first_prepare_json, second_prepare_json)
  })
}

#' Authorize the biomedical capsule allocation (AGGREGATE)
#' @param first_commit_json,second_commit_json Signed commit receipts.
#' @return A signed authorization receipt.
#' @keywords internal
dsvertJointDPVectorAllocationAuthorizeDS <- function(
    first_commit_json, second_commit_json) {
  .dsvert_joint_dp_vector_allocation_public("authorization", {
    first_commit_json <- .dsvert_dsi_text_decode(
      first_commit_json, "first biomedical allocation commit receipt",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    second_commit_json <- .dsvert_dsi_text_decode(
      second_commit_json, "second biomedical allocation commit receipt",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_allocation_authorize_impl(
      first_commit_json, second_commit_json)
  })
}

#' Finalize the biomedical capsule allocation (AGGREGATE)
#' @param first_authorization_json,second_authorization_json Signed
#'   authorization receipts.
#' @return A signed opening proof. It contains no sampling capability.
#' @keywords internal
dsvertJointDPVectorAllocationOpenDS <- function(
    first_authorization_json, second_authorization_json) {
  .dsvert_joint_dp_vector_allocation_public("opening", {
    first_authorization_json <- .dsvert_dsi_text_decode(
      first_authorization_json,
      "first biomedical allocation authorization receipt",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    second_authorization_json <- .dsvert_dsi_text_decode(
      second_authorization_json,
      "second biomedical allocation authorization receipt",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    .dsvert_joint_dp_vector_allocation_open_impl(
      first_authorization_json, second_authorization_json)
  })
}

#' Replay the durable biomedical capsule allocation proof (AGGREGATE)
#' @param manifest_json Canonical manifest memoized by this server.
#' @return The local signed opening proof. It contains no sampling capability.
#' @keywords internal
dsvertJointDPVectorAllocationProofDS <- function(manifest_json) {
  .dsvert_joint_dp_vector_allocation_public("proof replay", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    .dsvert_joint_dp_vector_allocation_proof_impl(manifest_json)
  })
}
