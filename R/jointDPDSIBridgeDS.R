# Purpose-bound DSI adapter for the unavailable joint-DP control plane.
#
# The analyst relays canonical signed receipts between the two
# custodian-designated noise peers.  These entrypoints cannot mint a proposal,
# sample noise, stage a result, or return persisted result bytes.  A future
# server-side statistical producer must mint the authenticated proposal token
# and persist its own purpose-bound result share before these phases can run.
# Relay-visible v2 receipts bind that share with a server-keyed HMAC; the
# future share channel remains the context-authenticated exact-GC AEAD.

.DSVERT_JOINT_DP_DSI_PROPOSAL_VERSION <-
  "dsvert-joint-dp-dsi-proposal-token-v1"
.DSVERT_JOINT_DP_DSI_PROPOSAL_PHASE <- "proposal_minted"
.DSVERT_JOINT_DP_DSI_MAX_PROPOSAL_BYTES <- 256L * 1024L
.DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES <- 64L * 1024L

.dsvert_joint_dp_dsi_encode <- function(value, what, maximum_bytes) {
  value <- .dsvert_dp_canonical_query_value(value)
  encoded <- .dsvert_dp_canonical_json(value)
  if (nchar(encoded, type = "bytes") > maximum_bytes) {
    stop("The joint-DP DSI ", what, " exceeds its protocol byte bound.",
         call. = FALSE)
  }
  encoded
}

.dsvert_joint_dp_dsi_decode <- function(value, what, maximum_bytes) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes) {
    stop("Invalid joint-DP DSI ", what, ".", call. = FALSE)
  }
  decoded <- tryCatch(
    jsonlite::fromJSON(value, simplifyVector = FALSE),
    error = function(e) NULL)
  canonical <- tryCatch(
    .dsvert_joint_dp_dsi_encode(decoded, what, maximum_bytes),
    error = function(e) NULL)
  if (is.null(canonical) || !identical(canonical, value) ||
      !is.list(decoded)) {
    stop("Invalid or non-canonical joint-DP DSI ", what, ".",
         call. = FALSE)
  }
  decoded
}

.dsvert_joint_dp_dsi_hex_equal <- function(left, right) {
  valid <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^[0-9a-f]{64}$", value)
  }
  if (!valid(left) || !valid(right)) return(FALSE)
  positions <- seq.int(1L, 63L, by = 2L)
  left_raw <- strtoi(substring(left, positions, positions + 1L), base = 16L)
  right_raw <- strtoi(substring(right, positions, positions + 1L), base = 16L)
  identical(sum(bitwXor(left_raw, right_raw)), 0L)
}

.dsvert_joint_dp_dsi_proposal_message <- function(unsigned) {
  charToRaw(paste0(
    "dsVert/joint-dp/dsi-proposal-token/v1|",
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

# Internal producer hook.  It is intentionally neither exported nor a DS
# method: an analyst cannot use the bridge itself to create ledger work.
.dsvert_joint_dp_dsi_mint_proposal <- function(
    policy, proposal, .secret = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  proposal <- .dsvert_dp_canonical_query_value(proposal)
  unsigned <- list(
    version = .DSVERT_JOINT_DP_DSI_PROPOSAL_VERSION,
    phase = .DSVERT_JOINT_DP_DSI_PROPOSAL_PHASE,
    consortium_id = context$consortium_id,
    peer_name = context$peer_name,
    peer_identity_pk = unname(context$pins[[context$peer_name]]),
    capsule_id = proposal$capsule_id,
    query_id = proposal$query_id,
    proposal_hash = .dsvert_joint_dp_hash(proposal),
    proposal = proposal,
    authentication = "server_local_hmac_sha256")
  token <- c(unsigned, list(proposal_mac = digest::hmac(
    key = .secret,
    object = .dsvert_joint_dp_dsi_proposal_message(unsigned),
    algo = "sha256", serialize = FALSE)))
  .dsvert_joint_dp_dsi_encode(
    token, "proposal token", .DSVERT_JOINT_DP_DSI_MAX_PROPOSAL_BYTES)
}

.dsvert_joint_dp_dsi_open_proposal <- function(
    policy, proposal_token_json, .secret = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  token <- .dsvert_joint_dp_dsi_decode(
    proposal_token_json, "proposal token",
    .DSVERT_JOINT_DP_DSI_MAX_PROPOSAL_BYTES)
  required <- c(
    "version", "phase", "consortium_id", "peer_name",
    "peer_identity_pk", "capsule_id", "query_id", "proposal_hash", "proposal",
    "authentication", "proposal_mac")
  unsigned <- token[setdiff(names(token), "proposal_mac")]
  expected_mac <- digest::hmac(
    key = .secret,
    object = .dsvert_joint_dp_dsi_proposal_message(unsigned),
    algo = "sha256", serialize = FALSE)
  if (is.null(names(token)) || anyNA(names(token)) ||
      anyDuplicated(names(token)) || !setequal(names(token), required) ||
      !identical(token$version, .DSVERT_JOINT_DP_DSI_PROPOSAL_VERSION) ||
      !identical(token$phase, .DSVERT_JOINT_DP_DSI_PROPOSAL_PHASE) ||
      !identical(token$consortium_id, context$consortium_id) ||
      !identical(token$peer_name, context$peer_name) ||
      !identical(token$peer_identity_pk,
                 unname(context$pins[[context$peer_name]])) ||
      !identical(token$authentication, "server_local_hmac_sha256") ||
      !is.list(token$proposal) ||
      !is.character(token$capsule_id) || length(token$capsule_id) != 1L ||
      is.na(token$capsule_id) ||
      !grepl("^[0-9a-f]{64}$", token$capsule_id) ||
      !identical(token$capsule_id, token$query_id) ||
      !identical(token$capsule_id, token$proposal$capsule_id) ||
      !is.character(token$query_id) || length(token$query_id) != 1L ||
      !grepl("^[0-9a-f]{64}$", token$query_id) ||
      !identical(token$query_id, token$proposal$query_id) ||
      !is.character(token$proposal_hash) ||
      length(token$proposal_hash) != 1L ||
      !identical(token$proposal_hash,
                 .dsvert_joint_dp_hash(token$proposal)) ||
      !.dsvert_joint_dp_dsi_hex_equal(token$proposal_mac, expected_mac)) {
    stop("The joint-DP DSI proposal token is invalid.", call. = FALSE)
  }
  token$proposal
}

.dsvert_joint_dp_dsi_receipt <- function(value, what) {
  receipt <- .dsvert_joint_dp_dsi_decode(
    value, what, .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
  prefix <- c(
    "version", "phase", "consortium_id", "peer_name",
    "peer_identity_pk", "capsule_id", "query_id")
  version <- receipt$version
  fields <- if (!is.character(version) || length(version) != 1L ||
      is.na(version)) NULL else switch(version,
    "dsvert-joint-dp-prepare-receipt-v1" = c(
      prefix, "privacy_epoch", "noise_key_id", "mechanism_hash",
      "allocation_index", "epsilon", "delta", "previous_chain",
      "snapshot_binding", "seed_commitment", "rollback_mode", "signature"),
    "dsvert-joint-dp-commit-receipt-v1" = c(
      prefix, "allocation_index", "previous_chain", "new_chain",
      "joint_record_hash", "prepare_set_hash", "seed_commitment",
      "external_anchor", "signature"),
    "dsvert-joint-dp-authorize-receipt-v1" = c(
      prefix, "allocation_index", "new_chain", "joint_record_hash",
      "commit_set_hash", "peer_commit_stored", "signature"),
    "dsvert-joint-dp-opening-token-v1" = c(
      prefix, "allocation_index", "new_chain", "joint_record_hash",
      "authorization_set_hash", "seed_commitment", "release_scope",
      "capability_available", "signature"),
    "dsvert-joint-dp-result-prepare-receipt-v2" = c(
      prefix, "allocation_index", "opening_set_hash",
      "result_contract_hash", "payload_commitment", "capability_available",
      "signature"),
    "dsvert-joint-dp-result-commit-receipt-v2" = c(
      prefix, "allocation_index", "opening_set_hash",
      "result_contract_hash", "result_set_hash", "payload_commitment",
      "peer_result_stored", "capability_available", "signature"),
    "dsvert-joint-dp-delivery-token-v2" = c(
      prefix, "allocation_index", "result_contract_hash", "result_set_hash",
      "delivery_commit_set_hash", "payload_delivery_available",
      "capability_available", "signature"),
    NULL)
  if (!is.null(fields)) {
    if (!setequal(names(receipt), fields)) {
      stop("Invalid joint-DP DSI ", what, " schema.", call. = FALSE)
    }
    receipt <- receipt[fields]
  }
  receipt
}

.dsvert_joint_dp_dsi_receipt_json <- function(value, what) {
  .dsvert_joint_dp_dsi_encode(
    value, what, .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
}

.dsvert_joint_dp_dsi_prepare_impl <- function(
    proposal_token_json, leader_prepare_json = "", .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  proposal <- .dsvert_joint_dp_dsi_open_proposal(
    .policy, proposal_token_json, .secret)
  if (!is.character(leader_prepare_json) ||
      length(leader_prepare_json) != 1L || is.na(leader_prepare_json)) {
    stop("Invalid joint-DP leader prepare receipt.", call. = FALSE)
  }
  leader_prepare <- if (!nzchar(leader_prepare_json)) NULL else
    .dsvert_joint_dp_dsi_receipt(
      leader_prepare_json, "leader prepare receipt")
  .dsvert_joint_dp_dsi_receipt_json(
    .dsvert_joint_dp_prepare(
      .policy, proposal, leader_prepare = leader_prepare,
      .secret = .secret, .signer = .signer, .verifier = .verifier,
      .phase_hook = .phase_hook),
    "prepare receipt")
}

.dsvert_joint_dp_dsi_commit_impl <- function(
    first_prepare_json, second_prepare_json, .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  .dsvert_joint_dp_dsi_receipt_json(
    .dsvert_joint_dp_commit(
      .policy,
      .dsvert_joint_dp_dsi_receipt(
        first_prepare_json, "first prepare receipt"),
      .dsvert_joint_dp_dsi_receipt(
        second_prepare_json, "second prepare receipt"),
      .secret = .secret, .signer = .signer, .verifier = .verifier,
      .phase_hook = .phase_hook),
    "commit receipt")
}

.dsvert_joint_dp_dsi_authorize_impl <- function(
    first_commit_json, second_commit_json, .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  .dsvert_joint_dp_dsi_receipt_json(
    .dsvert_joint_dp_authorize(
      .policy,
      .dsvert_joint_dp_dsi_receipt(
        first_commit_json, "first commit receipt"),
      .dsvert_joint_dp_dsi_receipt(
        second_commit_json, "second commit receipt"),
      .secret = .secret, .signer = .signer, .verifier = .verifier,
      .phase_hook = .phase_hook),
    "authorization receipt")
}

.dsvert_joint_dp_dsi_open_impl <- function(
    first_authorization_json, second_authorization_json, .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  .dsvert_joint_dp_dsi_receipt_json(
    .dsvert_joint_dp_finalize_authorization(
      .policy,
      .dsvert_joint_dp_dsi_receipt(
        first_authorization_json, "first authorization receipt"),
      .dsvert_joint_dp_dsi_receipt(
        second_authorization_json, "second authorization receipt"),
      .secret = .secret, .signer = .signer, .verifier = .verifier,
      .phase_hook = .phase_hook),
    "opening token")
}

.dsvert_joint_dp_dsi_result_receipt_impl <- function(
    first_result_json, second_result_json, .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  .dsvert_joint_dp_dsi_receipt_json(
    .dsvert_joint_dp_result_commit(
      .policy,
      .dsvert_joint_dp_dsi_receipt(
        first_result_json, "first result receipt"),
      .dsvert_joint_dp_dsi_receipt(
        second_result_json, "second result receipt"),
      .secret = .secret, .signer = .signer, .verifier = .verifier,
      .phase_hook = .phase_hook),
    "result commit receipt")
}

.dsvert_joint_dp_dsi_delivery_impl <- function(
    first_result_commit_json, second_result_commit_json, .policy = NULL,
    .secret = NULL, .signer = NULL, .verifier = NULL,
    .phase_hook = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  .dsvert_joint_dp_dsi_receipt_json(
    .dsvert_joint_dp_finalize_delivery(
      .policy,
      .dsvert_joint_dp_dsi_receipt(
        first_result_commit_json, "first result commit receipt"),
      .dsvert_joint_dp_dsi_receipt(
        second_result_commit_json, "second result commit receipt"),
      .secret = .secret, .signer = .signer, .verifier = .verifier,
      .phase_hook = .phase_hook),
    "delivery token")
}

.dsvert_joint_dp_dsi_delivery_contract_impl <- function(
    first_delivery_json, second_delivery_json, .policy = NULL,
    .secret = NULL, .verifier = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  context <- .dsvert_joint_dp_policy_context(.policy)
  first <- .dsvert_joint_dp_dsi_receipt(
    first_delivery_json, "first delivery token")
  second <- .dsvert_joint_dp_dsi_receipt(
    second_delivery_json, "second delivery token")
  if (identical(first$peer_name, context$peer_name)) {
    own <- first
    peer <- second
  } else if (identical(second$peer_name, context$peer_name)) {
    own <- second
    peer <- first
  } else {
    stop("The local joint-DP delivery token is absent.", call. = FALSE)
  }
  contract <- .dsvert_joint_dp_delivery_contract(
    .policy, own, peer,
    .secret = .secret, .verifier = .verifier)
  .dsvert_joint_dp_dsi_receipt_json(contract, "delivery contract")
}

.dsvert_joint_dp_dsi_public <- function(phase, code) {
  tryCatch(
    force(code),
    error = function(e) stop(
      "Joint-DP DSI ", phase, " failed closed.", call. = FALSE))
}

#' Prepare one authenticated joint-DP allocation (AGGREGATE)
#' @param proposal_token_json Canonical server-minted proposal token.
#' @param leader_prepare_json Empty on the deterministic leader; on the
#'   follower, the leader's canonical signed prepare receipt.
#' @return A canonical signed prepare receipt. No protected value is returned.
#' @details V2 result receipts carry only a server-keyed HMAC payload
#'   commitment. Legacy enumerable public-hash result receipts fail closed.
#'   Capability and payload delivery remain unavailable.
#' @keywords internal
dsvertJointDPPrepareDS <- function(proposal_token_json,
                                   leader_prepare_json = "") {
  .dsvert_joint_dp_dsi_public(
    "prepare", .dsvert_joint_dp_dsi_prepare_impl(
      proposal_token_json, leader_prepare_json))
}

#' Commit matching joint-DP prepare receipts (AGGREGATE)
#' @param first_prepare_json,second_prepare_json Canonical signed receipts.
#' @return A canonical signed commit receipt.
#' @keywords internal
dsvertJointDPCommitDS <- function(first_prepare_json, second_prepare_json) {
  .dsvert_joint_dp_dsi_public("commit", .dsvert_joint_dp_dsi_commit_impl(
    first_prepare_json, second_prepare_json))
}

#' Authorize matching durable joint-DP commits (AGGREGATE)
#' @param first_commit_json,second_commit_json Canonical signed receipts.
#' @return A canonical signed authorization receipt.
#' @keywords internal
dsvertJointDPAuthorizeDS <- function(first_commit_json, second_commit_json) {
  .dsvert_joint_dp_dsi_public(
    "authorization", .dsvert_joint_dp_dsi_authorize_impl(
      first_commit_json, second_commit_json))
}

#' Finalize matching joint-DP authorizations (AGGREGATE)
#' @param first_authorization_json,second_authorization_json Canonical signed
#'   receipts.
#' @return A signed opening token whose capability remains unavailable.
#' @keywords internal
dsvertJointDPOpenDS <- function(
    first_authorization_json, second_authorization_json) {
  .dsvert_joint_dp_dsi_public("opening", .dsvert_joint_dp_dsi_open_impl(
    first_authorization_json, second_authorization_json))
}

#' Commit server-persisted joint-DP result receipts (AGGREGATE)
#' @param first_result_json,second_result_json Canonical signed result receipts
#'   created by a future server-local producer.
#' @return A canonical signed result-commit receipt. No payload is returned.
#' @keywords internal
dsvertJointDPResultReceiptDS <- function(
    first_result_json, second_result_json) {
  .dsvert_joint_dp_dsi_public(
    "result receipt", .dsvert_joint_dp_dsi_result_receipt_impl(
      first_result_json, second_result_json))
}

#' Finalize joint-DP delivery authorization (AGGREGATE)
#' @param first_result_commit_json,second_result_commit_json Canonical signed
#'   result-commit receipts.
#' @return A signed token with payload delivery explicitly unavailable.
#' @keywords internal
dsvertJointDPDeliveryDS <- function(
    first_result_commit_json, second_result_commit_json) {
  .dsvert_joint_dp_dsi_public(
    "delivery", .dsvert_joint_dp_dsi_delivery_impl(
      first_result_commit_json, second_result_commit_json))
}

#' Verify durable joint-DP delivery tokens without opening bytes (AGGREGATE)
#' @param first_delivery_json,second_delivery_json Canonical signed tokens.
#' @return A redacted contract: both capability and payload delivery are false.
#' @keywords internal
dsvertJointDPDeliveryContractDS <- function(
    first_delivery_json, second_delivery_json) {
  .dsvert_joint_dp_dsi_public(
    "delivery contract", .dsvert_joint_dp_dsi_delivery_contract_impl(
      first_delivery_json, second_delivery_json))
}
