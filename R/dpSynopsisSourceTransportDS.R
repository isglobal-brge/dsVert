# Internal artifact-bound source contract for a stateless sticky synopsis.
#
# This file defines no endpoint.  It namespaces the existing durable capsule
# transport by the validated artifact while preserving the manifest capsule ID
# needed by the source producer.

.DSVERT_DP_SYNOPSIS_SOURCE_CONTRACT_VERSION <-
  "dsvert-stateless-catalog-synopsis-source-contract-v1"
.DSVERT_DP_SYNOPSIS_SOURCE_NAMESPACE_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/source-namespace/v1|"

.dsvert_dp_synopsis_source_namespace_id_v1 <- function(binding) {
  fields <- c(
    "version", "manifest_capsule_id", "artifact_key",
    "source_claim_set_sha256")
  if (!is.list(binding) || is.null(names(binding)) || anyNA(names(binding)) ||
      anyDuplicated(names(binding)) || !setequal(names(binding), fields) ||
      !identical(
        binding$version, .DSVERT_DP_SYNOPSIS_SOURCE_CONTRACT_VERSION)) {
    stop("Invalid synopsis source namespace binding.", call. = FALSE)
  }
  lapply(binding[setdiff(fields, "version")],
         .dsvert_dp_synopsis_hex_v1, what = "source namespace hash")
  digest::digest(charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_SOURCE_NAMESPACE_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(binding)))),
  algo = "sha256", serialize = FALSE)
}

.dsvert_dp_synopsis_source_contract_v1 <- function(
    policy, manifest, artifact, claim_set,
    .verifier = .dsvert_relay_verify_message) {
  artifact <- .dsvert_dp_synopsis_artifact_validate_v1(
    artifact, policy, manifest, claim_set, .verifier = .verifier)
  base <- .dsvert_dp_capsule_source_contract(policy, manifest)
  binding <- list(
    version = .DSVERT_DP_SYNOPSIS_SOURCE_CONTRACT_VERSION,
    manifest_capsule_id = base$capsule_id,
    artifact_key = artifact$artifact_key,
    source_claim_set_sha256 =
      artifact$semantic$source_claim_set_sha256)
  base$capsule_id <-
    .dsvert_dp_synopsis_source_namespace_id_v1(binding)
  base$synopsis_binding <- binding
  .dsvert_dp_capsule_source_contract_validate(
    .dsvert_dp_canonical_query_value(base))
}

.dsvert_dp_synopsis_source_transport_context_v1 <- function(
    manifest_sha256, artifact, claim_set, receipts,
    .policy = NULL, .secret = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message) {
  if (!is.function(.verifier)) {
    stop("Invalid synopsis source transport verifier.", call. = FALSE)
  }
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  manifest_json <- .dsvert_dp_synopsis_cached_manifest_v1(
    manifest_sha256, .policy, .secret, .cache_get)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  claim_set <- .dsvert_dp_synopsis_source_claim_set_validate_v1(
    claim_set, .policy, manifest, .verifier = .verifier)
  compilation <- .dsvert_dp_synopsis_compile_v1(
    receipts, artifact, claim_set, .policy, manifest,
    .verifier = .verifier)
  source_contract <- .dsvert_dp_synopsis_source_contract_v1(
    .policy, manifest, compilation$artifact, claim_set,
    .verifier = .verifier)
  peer <- .dsvert_dp_analysis_scalar_id(
    .policy$peer_name, "local synopsis source peer")
  local_claim <- if (peer %in% names(claim_set$claims)) {
    claim_set$claims[[peer]]
  } else {
    NULL
  }
  list(
    manifest_json = manifest_json, source_contract = source_contract,
    local_claim = local_claim)
}

.dsvert_dp_synopsis_source_transport_gate_v1 <- function(
    manifest_sha256, artifact, claim_set, receipts,
    .policy = NULL, .secret = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message) {
  context <- .dsvert_dp_synopsis_source_transport_context_v1(
    manifest_sha256, artifact, claim_set, receipts,
    .policy = .policy, .secret = .secret,
    .cache_get = .cache_get, .verifier = .verifier)
  if (is.null(context$local_claim)) {
    stop("The local peer is not a source for this synopsis artifact.",
         call. = FALSE)
  }
  source_contract <- context$source_contract
  expected <- context$local_claim[
    setdiff(names(context$local_claim), "signature")]
  public_fields <- setdiff(names(expected), "source_vector_commitment")
  materializer <- function(
      policy, manifest, resolved_snapshots,
      compute_commitment, include_release) {
    .dsvert_dp_gaussian_cross_source_producer(
      policy, manifest, resolved_snapshots,
      compute_commitment = compute_commitment,
      include_release = include_release)
  }
  producer_validator <- function(producer, policy, manifest, contract) {
    if (!identical(contract, source_contract)) return(FALSE)
    actual <- .dsvert_dp_synopsis_source_vector_unsigned_from_producer_v1(
      policy, manifest, producer, expected$source_identity_pk)
    identical(actual[public_fields], expected[public_fields]) &&
      .dsvert_joint_dp_dsi_hex_equal(
        actual$source_vector_commitment,
        expected$source_vector_commitment)
  }
  list(
    manifest_json = context$manifest_json,
    source_contract = source_contract,
    materializer = materializer,
    producer_validator = producer_validator)
}

.dsvert_dp_synopsis_source_transport_ticket_v1 <- function(
    manifest_sha256, artifact, claim_set, receipts,
    .policy = NULL, .secret = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_dp_synopsis_source_transport_context_v1(
    manifest_sha256, artifact, claim_set, receipts,
    .policy = .policy, .secret = .secret,
    .cache_get = .cache_get, .verifier = .verifier)
  .dsvert_dp_capsule_source_ticket_impl(
    context$manifest_json, .policy = .policy, .secret = .secret,
    .verifier = .verifier, source_contract = context$source_contract)
}

.dsvert_dp_synopsis_source_transport_prepare_v1 <- function(
    manifest_sha256, artifact, claim_set, receipts,
    first_ticket_json, second_ticket_json,
    first_opening_json, second_opening_json,
    .policy = NULL, .secret = NULL, .envir = parent.frame(),
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  gate <- .dsvert_dp_synopsis_source_transport_gate_v1(
    manifest_sha256, artifact, claim_set, receipts,
    .policy = .policy, .secret = .secret,
    .cache_get = .cache_get, .verifier = .verifier)
  .dsvert_dp_capsule_source_prepare_negotiated_impl(
    gate$manifest_json,
    first_ticket_json, second_ticket_json,
    first_opening_json, second_opening_json,
    .policy = .policy, .secret = .secret, .envir = .envir,
    .materializer = gate$materializer, .verifier = .verifier,
    .producer_validator = gate$producer_validator,
    source_contract = gate$source_contract)
}

.dsvert_dp_synopsis_source_transport_chunk_v1 <- function(
    manifest_sha256, artifact, claim_set, receipts,
    source_transfer_id, chunk_index,
    .policy = NULL, .secret = NULL, .envir = parent.frame(),
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .verifier = .dsvert_relay_verify_message) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  source_transfer_id <- .dsvert_dp_capsule_source_scalar(
    source_transfer_id, "transfer id",
    pattern = "^csrc_[0-9a-f]{64}$", maximum_bytes = 69L)
  gate <- .dsvert_dp_synopsis_source_transport_gate_v1(
    manifest_sha256, artifact, claim_set, receipts,
    .policy = .policy, .secret = .secret,
    .cache_get = .cache_get, .verifier = .verifier)
  expected <- .dsvert_dp_capsule_source_transfer_id(
    gate$source_contract, .policy$peer_name)
  if (!identical(source_transfer_id, expected)) {
    stop("The synopsis source transfer targets a different artifact.",
         call. = FALSE)
  }
  .dsvert_dp_capsule_source_chunk_impl(
    source_transfer_id, chunk_index,
    .policy = .policy, .secret = .secret, .envir = .envir,
    .materializer = gate$materializer, .verifier = .verifier)
}
