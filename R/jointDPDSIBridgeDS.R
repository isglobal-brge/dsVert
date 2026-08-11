# Shared canonical receipt codec and allocation-phase adapters for the
# server-authoritative joint-DP vector allocator.

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
