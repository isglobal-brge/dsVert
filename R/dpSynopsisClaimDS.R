# Safe local wrapper for minting one internal stateless-synopsis source Claim.
# It accepts only an authenticated cache selector.  Manifest bytes, snapshot
# bindings and protected objects are obtained inside the server process.

.DSVERT_DP_SYNOPSIS_LOCAL_CLAIM_VERSION <-
  "dsvert-stateless-catalog-synopsis-local-claim-v1"

.dsvert_dp_synopsis_cached_manifest_v1 <- function(
    manifest_sha256, policy, secret,
    cache_get = .dsvert_dp_capsule_manifest_cache_get) {
  manifest_sha256 <- .dsvert_dp_synopsis_hex_v1(
    manifest_sha256, "manifest selector")
  if (!is.function(cache_get)) {
    stop("Invalid synopsis manifest-cache reader.", call. = FALSE)
  }
  record <- cache_get(
    policy, secret, manifest_sha256 = manifest_sha256)
  fields <- c(
    "version", "cache_key", "public_capsule_key",
    "local_authority_sha256", "schema_sha256",
    "workload_contract_sha256", "manifest_sha256", "manifest_json")
  valid <- is.list(record) && !is.null(names(record)) &&
    !anyNA(names(record)) && !anyDuplicated(names(record)) &&
    setequal(names(record), fields) &&
    is.character(record$version) && length(record$version) == 1L &&
    !is.na(record$version) &&
    record$version %in% .DSVERT_DP_CAPSULE_MANIFEST_REPLAY_CACHE_VERSIONS &&
    identical(record$manifest_sha256, manifest_sha256) &&
    is.character(record$manifest_json) && length(record$manifest_json) == 1L &&
    !is.na(record$manifest_json) && nzchar(record$manifest_json) &&
    nchar(record$manifest_json, type = "bytes") <=
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES &&
    identical(
      digest::digest(
        record$manifest_json, algo = "sha256", serialize = FALSE),
      manifest_sha256) &&
    identical(
      record$local_authority_sha256,
      .dsvert_dp_capsule_manifest_local_authority(policy, secret))
  if (isTRUE(valid)) {
    valid <- all(vapply(c(
      "cache_key", "public_capsule_key", "local_authority_sha256",
      "schema_sha256", "workload_contract_sha256", "manifest_sha256"),
      function(field) {
        is.character(record[[field]]) && length(record[[field]]) == 1L &&
          !is.na(record[[field]]) &&
          grepl("^[0-9a-f]{64}$", record[[field]])
      }, logical(1L)))
  }
  if (!isTRUE(valid)) {
    stop("The synopsis manifest was not emitted and authorized by this server.",
         call. = FALSE)
  }
  record$manifest_json
}

.dsvert_dp_synopsis_local_claim_v1 <- function(
    manifest_sha256, .policy = NULL, .secret = NULL,
    .envir = parent.frame(), .identity = NULL,
    .cache_get = .dsvert_dp_capsule_manifest_cache_get,
    .resolver = .dsvert_dp_resolve_snapshot,
    .signer = .dsvert_relay_sign_message,
    .verifier = .dsvert_relay_verify_message) {
  if (!is.function(.resolver) || !is.function(.signer) ||
      !is.function(.verifier) || !is.environment(.envir)) {
    stop("Invalid local synopsis Claim dependencies.", call. = FALSE)
  }
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  manifest_json <- .dsvert_dp_synopsis_cached_manifest_v1(
    manifest_sha256, .policy, .secret, .cache_get)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  projection <- .dsvert_dp_synopsis_catalog_projection_v1(
    .policy, manifest)
  source_contract <- .dsvert_dp_capsule_source_contract(
    .policy, manifest)
  source_peers <- .dsvert_dp_capsule_source_names(
    source_contract$source_peers, "source-peer list")
  if (!.policy$peer_name %in% source_peers) {
    stop("The local peer is not a source for this synopsis catalog.",
         call. = FALSE)
  }
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  pins <- .dsvert_dp_synopsis_peer_pins_v1(.policy$peer_pinset)
  identity_pk <- if (is.list(.identity) && !is.null(.identity$identity_pk)) {
    tryCatch(.dsvert_dp_analysis_identity_pk(
      .identity$identity_pk, "synopsis source identity"),
      error = function(error) NULL)
  } else NULL
  if (is.null(identity_pk) || is.null(.identity$identity_sk) ||
      !.policy$peer_name %in% names(pins) ||
      !identical(identity_pk, unname(pins[[.policy$peer_name]]))) {
    stop("The local synopsis source identity is not pinned.", call. = FALSE)
  }
  # The immutable synopsis snapshot is the full custodian-registered local
  # dataset set.  A different registered snapshot is a different DP artifact;
  # no global privacy bound is claimed across distinct snapshots.
  dataset_names <- names(.policy$datasets)
  if (!is.character(dataset_names) || !length(dataset_names) ||
      length(dataset_names) > 4096L || anyNA(dataset_names) ||
      any(!nzchar(dataset_names)) || anyDuplicated(dataset_names)) {
    stop("The local synopsis source dataset registry is invalid.",
         call. = FALSE)
  }
  dataset_names <- sort(dataset_names, method = "radix")
  snapshots <- lapply(dataset_names, function(data_name) {
    .resolver(.policy, data_name, .envir, .secret)
  })
  names(snapshots) <- dataset_names
  claim <- .dsvert_dp_synopsis_snapshot_claim_v1(
    .policy, manifest, snapshots, .identity,
    .signer = .signer, .verifier = .verifier)
  list(
    version = .DSVERT_DP_SYNOPSIS_LOCAL_CLAIM_VERSION,
    projection = projection, claim = claim)
}
