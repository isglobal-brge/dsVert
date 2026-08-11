# Final all-peer compilation receipts for one stateless sticky synopsis.
# This layer creates no session, authorization, seed or execution state.

.DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_VERSION <-
  "dsvert-stateless-catalog-synopsis-compile-receipt-v1"
.DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/compile-receipt/v1|"
.DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_SET_VERSION <-
  "dsvert-stateless-catalog-synopsis-compile-receipt-set-v1"
.DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_SET_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/compile-receipt-set/v1|"

.dsvert_dp_synopsis_unsigned_compile_receipt_v1 <- function(value) {
  fields <- c(
    "version", "peer_name", "peer_identity_pk", "manifest_sha256",
    "artifact_key", "source_claim_set_sha256", "full_plan_sha256")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(
        value$version, .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_VERSION)) {
    stop("Invalid synopsis compile receipt fields.", call. = FALSE)
  }
  list(
    version = .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_VERSION,
    peer_name = .dsvert_dp_analysis_scalar_id(
      value$peer_name, "synopsis compiler peer"),
    peer_identity_pk = .dsvert_dp_analysis_identity_pk(
      value$peer_identity_pk, "synopsis compiler identity"),
    manifest_sha256 = .dsvert_dp_synopsis_hex_v1(
      value$manifest_sha256, "compile manifest hash"),
    artifact_key = .dsvert_dp_synopsis_hex_v1(
      value$artifact_key, "compile artifact key"),
    source_claim_set_sha256 = .dsvert_dp_synopsis_hex_v1(
      value$source_claim_set_sha256, "compile source Claim-set hash"),
    full_plan_sha256 = .dsvert_dp_synopsis_hex_v1(
      value$full_plan_sha256, "compile full-plan hash"))
}

.dsvert_dp_synopsis_compile_receipt_message_v1 <- function(value) {
  unsigned <- .dsvert_dp_synopsis_unsigned_compile_receipt_v1(
    value[setdiff(names(value), "signature")])
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_analysis_canonical_value_v1(unsigned))))
}

.dsvert_dp_synopsis_sign_compile_receipt_v1 <- function(
    draft, identity, .signer) {
  draft <- .dsvert_dp_synopsis_unsigned_compile_receipt_v1(draft)
  if (!is.list(identity) || is.null(identity$identity_sk) ||
      !is.function(.signer)) {
    stop("Invalid synopsis compile receipt signer.", call. = FALSE)
  }
  signature <- .signer(
    .dsvert_dp_synopsis_compile_receipt_message_v1(draft),
    identity$identity_sk)
  signature <- .dsvert_dp_synopsis_signature_v1(signature)
  c(draft, list(signature = signature))
}

.dsvert_dp_synopsis_compile_receipt_verify_v1 <- function(
    receipt, expected, pins,
    .verifier = .dsvert_relay_verify_message) {
  signed_fields <- c(
    names(.dsvert_dp_synopsis_unsigned_compile_receipt_v1(expected)),
    "signature")
  if (!is.list(receipt) || is.null(names(receipt)) ||
      anyNA(names(receipt)) || anyDuplicated(names(receipt)) ||
      !setequal(names(receipt), signed_fields) || !is.function(.verifier)) {
    stop("Invalid signed synopsis compile receipt.", call. = FALSE)
  }
  pins <- .dsvert_dp_synopsis_peer_pins_v1(pins)
  unsigned <- .dsvert_dp_synopsis_unsigned_compile_receipt_v1(
    receipt[setdiff(names(receipt), "signature")])
  peer <- unsigned$peer_name
  if (!peer %in% names(pins) ||
      !identical(unsigned$peer_identity_pk, unname(pins[[peer]]))) {
    stop("The synopsis compiler identity is not pinned.", call. = FALSE)
  }
  signature <- .dsvert_dp_synopsis_signature_v1(receipt$signature)
  if (!isTRUE(tryCatch(
      .verifier(
        .dsvert_dp_synopsis_compile_receipt_message_v1(unsigned),
        unsigned$peer_identity_pk, signature),
      error = function(error) FALSE))) {
    stop("Synopsis compile receipt signature verification failed.",
         call. = FALSE)
  }
  common <- setdiff(names(unsigned), c("peer_name", "peer_identity_pk"))
  if (!identical(unsigned[common], expected[common])) {
    stop("The synopsis compile receipts do not agree.", call. = FALSE)
  }
  c(unsigned, list(signature = signature))
}

.dsvert_dp_synopsis_local_compile_v1 <- function(
    manifest_sha256, claim_set, .policy = NULL, .secret = NULL,
    .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .planner = NULL, .signer = .dsvert_relay_sign_message,
    .verifier = .dsvert_relay_verify_message) {
  if (!is.function(.signer) || !is.function(.verifier) ||
      (!is.null(.planner) && !is.function(.planner) &&
       !is.list(.planner))) {
    stop("Invalid local synopsis compiler dependencies.", call. = FALSE)
  }
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  manifest_sha256 <- .dsvert_dp_synopsis_hex_v1(
    manifest_sha256, "manifest selector")
  manifest_json <- .dsvert_dp_synopsis_cached_manifest_v1(
    manifest_sha256, .policy, .secret, .cache_get)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(.policy$peer_pinset)
  peer <- .dsvert_dp_analysis_scalar_id(
    .policy$peer_name, "local synopsis compiler peer")
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  identity_pk <- if (is.list(.identity) &&
      !is.null(.identity$identity_pk)) {
    tryCatch(.dsvert_dp_analysis_identity_pk(
      .identity$identity_pk, "local synopsis compiler identity"),
      error = function(error) NULL)
  } else NULL
  if (is.null(identity_pk) || is.null(.identity$identity_sk) ||
      !peer %in% names(pins) ||
      !identical(identity_pk, unname(pins[[peer]]))) {
    stop("The local synopsis compiler identity is not pinned.",
         call. = FALSE)
  }
  artifact <- .dsvert_dp_synopsis_artifact_v1(
    .policy, manifest, claim_set, .planner = .planner,
    .verifier = .verifier)
  draft <- list(
    version = .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_VERSION,
    peer_name = peer, peer_identity_pk = identity_pk,
    manifest_sha256 = manifest_sha256,
    artifact_key = artifact$artifact_key,
    source_claim_set_sha256 =
      artifact$semantic$source_claim_set_sha256,
    full_plan_sha256 = artifact$physical_plan$full_plan_sha256)
  list(
    artifact = artifact,
    receipt = .dsvert_dp_synopsis_sign_compile_receipt_v1(
      draft, .identity, .signer))
}

.dsvert_dp_synopsis_compile_v1 <- function(
    receipts, artifact, claim_set, policy, manifest,
    .verifier = .dsvert_relay_verify_message) {
  if (!is.function(.verifier)) {
    stop("Invalid synopsis compile receipt verifier.", call. = FALSE)
  }
  artifact <- .dsvert_dp_synopsis_artifact_validate_v1(
    artifact, policy, manifest, claim_set, .verifier = .verifier)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  if (!is.list(receipts) || length(receipts) != length(pins)) {
    stop("Synopsis compilation requires exactly one receipt per peer.",
         call. = FALSE)
  }
  expected <- list(
    version = .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_VERSION,
    peer_name = names(pins)[[1L]],
    peer_identity_pk = unname(pins[[1L]]),
    manifest_sha256 = .dsvert_joint_dp_hash(manifest),
    artifact_key = artifact$artifact_key,
    source_claim_set_sha256 =
      artifact$semantic$source_claim_set_sha256,
    full_plan_sha256 = artifact$physical_plan$full_plan_sha256)
  verified <- lapply(
    receipts, .dsvert_dp_synopsis_compile_receipt_verify_v1,
    expected = expected, pins = pins, .verifier = .verifier)
  peers <- vapply(verified, `[[`, character(1L), "peer_name")
  if (anyDuplicated(peers) || !setequal(peers, names(pins))) {
    stop("The synopsis compile receipt coverage is invalid.", call. = FALSE)
  }
  names(verified) <- peers
  verified <- verified[names(pins)]
  unsigned <- unname(lapply(verified, function(receipt) {
    receipt[setdiff(names(receipt), "signature")]
  }))
  receipt_set_sha256 <- digest::digest(
    charToRaw(paste0(
      .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_SET_DOMAIN,
      .dsvert_dp_canonical_json(
        .dsvert_dp_analysis_canonical_value_v1(list(
          version = .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_SET_VERSION,
          receipts = unsigned))))),
    algo = "sha256", serialize = FALSE)
  list(
    version = .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_SET_VERSION,
    artifact = artifact, receipts = verified,
    receipt_set_sha256 = receipt_set_sha256)
}
