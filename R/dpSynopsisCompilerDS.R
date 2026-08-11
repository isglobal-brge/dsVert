# Pure source-Claim compilation for the stateless sticky synopsis.
# This layer authorizes no state or execution.  The later artifact compiler
# adds privacy calibration, the physical plan, authority roles and K receipts.

.DSVERT_DP_SYNOPSIS_SOURCE_CLAIM_SET_VERSION <-
  "dsvert-stateless-catalog-synopsis-source-claim-set-v1"
.DSVERT_DP_SYNOPSIS_SOURCE_CLAIM_SET_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/source-claim-set/v1|"

.dsvert_dp_synopsis_source_claim_context_v1 <- function(policy, manifest) {
  projection <- .dsvert_dp_synopsis_catalog_projection_v1(policy, manifest)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  if (!identical(
      .dsvert_dp_synopsis_pinset_hash_v1(pins),
      projection$catalog$peer_pinset_sha256)) {
    stop("The synopsis catalog targets a different peer pinset.",
         call. = FALSE)
  }
  source_contract <- .dsvert_dp_capsule_source_contract(policy, manifest)
  source_peers <- .dsvert_dp_capsule_source_names(
    source_contract$source_peers, "synopsis source-peer list")
  if (length(source_peers) > length(pins) || anyDuplicated(source_peers) ||
      !identical(source_peers, sort(source_peers, method = "radix")) ||
      !all(source_peers %in% names(pins))) {
    stop("The synopsis source-peer assignment is invalid.", call. = FALSE)
  }
  list(projection = projection, pins = pins, source_peers = source_peers)
}

.dsvert_dp_synopsis_source_claims_v1 <- function(
    claims, context, .verifier) {
  expected <- context$source_peers
  if (!is.list(claims) || length(claims) != length(expected)) {
    stop("The synopsis source Claim coverage is incomplete.", call. = FALSE)
  }
  verified <- lapply(
    claims, .dsvert_dp_synopsis_source_vector_claim_validate_v1,
    projection = context$projection, peer_pins = context$pins,
    .verifier = .verifier)
  peers <- vapply(verified, `[[`, character(1L), "source_peer_name")
  if (anyDuplicated(peers) || !setequal(peers, expected)) {
    stop("The synopsis source Claim coverage is invalid.", call. = FALSE)
  }
  names(verified) <- peers
  verified[expected]
}

.dsvert_dp_synopsis_source_claim_set_hash_v1 <- function(
    projection, claims) {
  unsigned <- unname(lapply(claims, function(claim) {
    claim[setdiff(names(claim), "signature")]
  }))
  digest::digest(
    charToRaw(paste0(
      .DSVERT_DP_SYNOPSIS_SOURCE_CLAIM_SET_DOMAIN,
      .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(list(
        version = .DSVERT_DP_SYNOPSIS_SOURCE_CLAIM_SET_VERSION,
        catalog_sha256 = projection$sha256,
        claims = unsigned))))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_dp_synopsis_source_claim_set_validate_v1 <- function(
    value, policy, manifest,
    .verifier = .dsvert_relay_verify_message) {
  fields <- c("version", "sha256", "projection", "claims")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(
        value$version, .DSVERT_DP_SYNOPSIS_SOURCE_CLAIM_SET_VERSION) ||
      !is.function(.verifier)) {
    stop("Invalid synopsis source Claim set.", call. = FALSE)
  }
  context <- .dsvert_dp_synopsis_source_claim_context_v1(policy, manifest)
  projection <- .dsvert_dp_synopsis_catalog_projection_validate_v1(
    value$projection)
  if (!identical(
      .dsvert_dp_canonical_json(projection),
      .dsvert_dp_canonical_json(context$projection))) {
    stop("The synopsis source Claim set targets a different catalog.",
         call. = FALSE)
  }
  claims <- .dsvert_dp_synopsis_source_claims_v1(
    value$claims, context, .verifier)
  sha256 <- .dsvert_dp_synopsis_hex_v1(
    value$sha256, "source Claim-set hash")
  if (!identical(
      sha256,
      .dsvert_dp_synopsis_source_claim_set_hash_v1(projection, claims))) {
    stop("The synopsis source Claim-set hash is invalid.", call. = FALSE)
  }
  list(
    version = .DSVERT_DP_SYNOPSIS_SOURCE_CLAIM_SET_VERSION,
    sha256 = sha256, projection = projection, claims = claims)
}

.dsvert_dp_synopsis_source_claim_set_v1 <- function(
    policy, manifest, claims,
    .verifier = .dsvert_relay_verify_message) {
  if (!is.function(.verifier)) {
    stop("Invalid synopsis source Claim verifier.", call. = FALSE)
  }
  context <- .dsvert_dp_synopsis_source_claim_context_v1(policy, manifest)
  claims <- .dsvert_dp_synopsis_source_claims_v1(
    claims, context, .verifier)
  result <- list(
    version = .DSVERT_DP_SYNOPSIS_SOURCE_CLAIM_SET_VERSION,
    sha256 = .dsvert_dp_synopsis_source_claim_set_hash_v1(
      context$projection, claims),
    projection = context$projection, claims = claims)
  result
}
