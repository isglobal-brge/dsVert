# Internal snapshot-and-catalog identity for a stateless sticky DP synopsis.
#
# This file deliberately defines no remote endpoint.  It binds an existing
# custodian-authoritative catalog_v1 manifest to opaque, owner-minted snapshot
# commitments.  Execution and public method rewiring are separate milestones.
# The catalog hash is not an artifact key: privacy calibration, the physical
# sampler plan, and both pinned noise-authority roles must be added before any
# sticky subseed can be derived.

.DSVERT_DP_SYNOPSIS_CATALOG_VERSION <-
  "dsvert-stateless-catalog-synopsis-catalog-v1"
.DSVERT_DP_SYNOPSIS_PROJECTION_VERSION <-
  "dsvert-stateless-catalog-synopsis-projection-v1"
.DSVERT_DP_SYNOPSIS_CLAIM_VERSION <-
  "dsvert-stateless-catalog-synopsis-source-claim-v1"
.DSVERT_DP_SYNOPSIS_SNAPSHOT_VERSION <-
  "dsvert-stateless-catalog-synopsis-snapshot-commitment-v1"
.DSVERT_DP_SYNOPSIS_CATALOG_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/catalog/v1|"
.DSVERT_DP_SYNOPSIS_CLAIM_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/source-claim/v1|"
.DSVERT_DP_SYNOPSIS_SNAPSHOT_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/dataset-snapshot/v1|"

.dsvert_dp_synopsis_hex_v1 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      nchar(value, type = "bytes") != 64L ||
      !grepl("^[0-9a-f]{64}$", value)) {
    stop("Invalid synopsis ", what, ".", call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_signature_v1 <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      nchar(value, type = "bytes") != 86L ||
      !grepl("^[A-Za-z0-9_-]{86}$", value)) {
    stop("Invalid synopsis signature.", call. = FALSE)
  }
  decoded <- tryCatch(
    .dsvert_relay_b64url_decode(value, "synopsis signature"),
    error = function(error) raw())
  if (length(decoded) != 64L) {
    stop("Invalid synopsis signature.", call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_peer_pins_v1 <- function(value) {
  if (!is.character(value) || length(value) < 2L || length(value) > 4096L ||
      is.null(names(value)) || anyNA(names(value)) ||
      any(!nzchar(names(value))) || anyDuplicated(names(value))) {
    stop("Invalid synopsis peer pinset.", call. = FALSE)
  }
  peers <- tryCatch(vapply(
    names(value), .dsvert_dp_analysis_scalar_id, character(1L),
    what = "synopsis peer name"), error = function(error) character())
  pins <- tryCatch(vapply(
    value, .dsvert_dp_analysis_identity_pk, character(1L),
    what = "synopsis peer identity"), error = function(error) character())
  if (length(peers) != length(value) || length(pins) != length(value) ||
      anyDuplicated(pins)) {
    stop("Invalid synopsis peer pinset.", call. = FALSE)
  }
  names(pins) <- peers
  pins[order(names(pins), method = "radix")]
}

.dsvert_dp_synopsis_pinset_hash_v1 <- function(pins) {
  pins <- .dsvert_dp_synopsis_peer_pins_v1(pins)
  digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
}

.dsvert_dp_synopsis_catalog_hash_v1 <- function(catalog) {
  digest::digest(
    paste0(
      .DSVERT_DP_SYNOPSIS_CATALOG_DOMAIN,
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(catalog))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_dp_synopsis_catalog_projection_validate_v1 <- function(value) {
  required <- c("version", "sha256", "catalog")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), required) ||
      !identical(value$version, .DSVERT_DP_SYNOPSIS_PROJECTION_VERSION)) {
    stop("Invalid synopsis catalog projection.", call. = FALSE)
  }
  fields <- c(
    "version", "domain", "cohort_id", "peer_pinset_sha256",
    "logical_snapshot", "capsule_schema", "schema_manifest_sha256",
    "admission", "bounds", "families", "vertical_crosses",
    "primitive_scope", "release_lattice", "sensitivity",
    "coordinate_count", "coordinate_order_sha256", "clipping_sha256")
  catalog <- tryCatch(
    .dsvert_dp_canonical_query_value(value$catalog),
    error = function(error) NULL)
  if (!is.list(catalog) || is.null(names(catalog)) ||
      anyNA(names(catalog)) || anyDuplicated(names(catalog)) ||
      !setequal(names(catalog), fields) ||
      !identical(catalog$version, .DSVERT_DP_SYNOPSIS_CATALOG_VERSION) ||
      !is.list(catalog$primitive_scope) ||
      !identical(catalog$primitive_scope$mode, "catalog_v1") ||
      !identical(catalog$primitive_scope$analyst_expandable, FALSE) ||
      !identical(
        catalog$primitive_scope$client_query_can_add_coordinates, FALSE)) {
    stop("Invalid synopsis catalog projection.", call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(catalog$domain, "synopsis domain")
  .dsvert_dp_analysis_scalar_id(catalog$cohort_id, "synopsis cohort ID")
  for (field in c(
      "peer_pinset_sha256", "schema_manifest_sha256",
      "coordinate_order_sha256", "clipping_sha256")) {
    .dsvert_dp_synopsis_hex_v1(catalog[[field]], field)
  }
  .dsvert_dp_analysis_positive_integer(
    catalog$coordinate_count, "synopsis coordinate count")
  .dsvert_dp_analysis_reject_operational_fields(catalog)
  sha256 <- .dsvert_dp_synopsis_hex_v1(value$sha256, "catalog hash")
  if (!identical(sha256, .dsvert_dp_synopsis_catalog_hash_v1(catalog))) {
    stop("The synopsis catalog hash does not match its projection.",
         call. = FALSE)
  }
  list(
    version = .DSVERT_DP_SYNOPSIS_PROJECTION_VERSION,
    sha256 = sha256, catalog = catalog)
}

.dsvert_dp_synopsis_catalog_projection_v1 <- function(policy, manifest) {
  validated <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  manifest <- validated$manifest
  scope <- manifest$workload$primitive_scope
  if (!identical(scope$mode, "catalog_v1") ||
      !identical(scope$analyst_expandable, FALSE) ||
      !identical(scope$client_query_can_add_coordinates, FALSE)) {
    stop("A stateless synopsis requires a closed custodian catalog_v1.",
         call. = FALSE)
  }
  catalog <- list(
    version = .DSVERT_DP_SYNOPSIS_CATALOG_VERSION,
    domain = policy$domain, cohort_id = policy$cohort_id,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    logical_snapshot = manifest$logical_snapshot,
    capsule_schema = manifest$capsule_schema,
    schema_manifest_sha256 =
      manifest$workload$schema_attestation$manifest_sha256,
    admission = manifest$admission, bounds = manifest$bounds,
    families = manifest$workload$families,
    vertical_crosses = manifest$workload$vertical_crosses,
    primitive_scope = scope,
    release_lattice = manifest$workload$release_lattice,
    sensitivity = manifest$workload$sensitivity,
    coordinate_count = manifest$workload$coordinate_count,
    coordinate_order_sha256 = validated$layout$sha256,
    clipping_sha256 = manifest$workload$capsule_mechanism$clipping_hash)
  .dsvert_dp_synopsis_catalog_projection_validate_v1(list(
    version = .DSVERT_DP_SYNOPSIS_PROJECTION_VERSION,
    sha256 = .dsvert_dp_synopsis_catalog_hash_v1(catalog),
    catalog = catalog))
}

.dsvert_dp_synopsis_claim_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_CLAIM_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_synopsis_dataset_claim_validate_v1 <- function(value, key) {
  fields <- c(
    "dataset_key", "dataset_id", "dataset_version",
    "alignment_attested", "alignment_protocol_version")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(value$dataset_key, key)) {
    stop("Invalid synopsis dataset Claim.", call. = FALSE)
  }
  .dsvert_dp_analysis_scalar_id(value$dataset_key, "synopsis dataset key")
  .dsvert_dp_analysis_scalar_id(value$dataset_id, "synopsis dataset ID")
  .dsvert_dp_analysis_scalar_id(
    value$dataset_version, "synopsis dataset version")
  if (!is.logical(value$alignment_attested) ||
      length(value$alignment_attested) != 1L ||
      is.na(value$alignment_attested)) {
    stop("Invalid synopsis dataset Claim.", call. = FALSE)
  }
  .dsvert_dp_analysis_positive_integer(
    value$alignment_protocol_version, "synopsis alignment version")
  list(
    dataset_key = value$dataset_key, dataset_id = value$dataset_id,
    dataset_version = value$dataset_version,
    alignment_attested = value$alignment_attested,
    alignment_protocol_version = value$alignment_protocol_version)
}

.dsvert_dp_synopsis_snapshot_claim_validate_v1 <- function(
    claim, projection, peer_pins,
    .verifier = .dsvert_relay_verify_message) {
  # Signature validation authenticates the claimed set.  Exact K-peer and
  # owner-dataset coverage must additionally be checked by the later compiler
  # against the server-built manifest before materialization.
  projection <- .dsvert_dp_synopsis_catalog_projection_validate_v1(projection)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(peer_pins)
  required <- c(
    "version", "source_peer_name", "source_identity_pk",
    "peer_pinset_sha256", "catalog_sha256", "datasets",
    "snapshot_set_commitment", "signature")
  if (!is.list(claim) || is.null(names(claim)) || anyNA(names(claim)) ||
      anyDuplicated(names(claim)) || !setequal(names(claim), required) ||
      !identical(claim$version, .DSVERT_DP_SYNOPSIS_CLAIM_VERSION) ||
      !is.function(.verifier)) {
    stop("Invalid signed synopsis Claim.", call. = FALSE)
  }
  peer <- .dsvert_dp_analysis_scalar_id(
    claim$source_peer_name, "synopsis source peer")
  identity_pk <- .dsvert_dp_analysis_identity_pk(
    claim$source_identity_pk, "synopsis source identity")
  if (!peer %in% names(pins) ||
      !identical(identity_pk, unname(pins[[peer]]))) {
    stop("The synopsis Claim source identity is not pinned.", call. = FALSE)
  }
  pinset_sha256 <- .dsvert_dp_synopsis_hex_v1(
    claim$peer_pinset_sha256, "Claim pinset hash")
  expected_pinset <- .dsvert_dp_synopsis_pinset_hash_v1(pins)
  if (!identical(pinset_sha256, expected_pinset) ||
      !identical(pinset_sha256,
                 projection$catalog$peer_pinset_sha256)) {
    stop("The synopsis Claim targets a different peer pinset.",
         call. = FALSE)
  }
  catalog_sha256 <- .dsvert_dp_synopsis_hex_v1(
    claim$catalog_sha256, "Claim catalog hash")
  if (!identical(catalog_sha256, projection$sha256)) {
    stop("The synopsis Claim targets a different catalog.", call. = FALSE)
  }
  if (!is.list(claim$datasets) || !length(claim$datasets) ||
      length(claim$datasets) > 4096L || is.null(names(claim$datasets)) ||
      anyNA(names(claim$datasets)) || any(!nzchar(names(claim$datasets))) ||
      anyDuplicated(names(claim$datasets)) ||
      !identical(names(claim$datasets),
                 sort(names(claim$datasets), method = "radix"))) {
    stop("Invalid signed synopsis Claim datasets.", call. = FALSE)
  }
  datasets <- Map(
    .dsvert_dp_synopsis_dataset_claim_validate_v1,
    claim$datasets, names(claim$datasets))
  names(datasets) <- names(claim$datasets)
  snapshot_set_commitment <- .dsvert_dp_synopsis_hex_v1(
    claim$snapshot_set_commitment, "snapshot-set commitment")
  signature <- .dsvert_dp_synopsis_signature_v1(claim$signature)
  normalized <- list(
    version = .DSVERT_DP_SYNOPSIS_CLAIM_VERSION,
    source_peer_name = peer, source_identity_pk = identity_pk,
    peer_pinset_sha256 = pinset_sha256,
    catalog_sha256 = catalog_sha256, datasets = datasets,
    snapshot_set_commitment = snapshot_set_commitment,
    signature = signature)
  if (!isTRUE(tryCatch(
      .verifier(
        .dsvert_dp_synopsis_claim_message_v1(normalized),
        identity_pk, signature), error = function(error) FALSE))) {
    stop("Synopsis Claim signature verification failed.", call. = FALSE)
  }
  normalized
}

.dsvert_dp_synopsis_snapshot_claim_v1 <- function(
    policy, manifest, resolved_snapshots, identity,
    .signer = .dsvert_relay_sign_message,
    .verifier = .dsvert_relay_verify_message) {
  # This low-level helper accepts only server-resolved snapshots.  A future
  # endpoint must obtain the cached manifest and snapshots itself; neither
  # object may come from an analyst request.
  projection <- .dsvert_dp_synopsis_catalog_projection_v1(policy, manifest)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  peer <- .dsvert_dp_analysis_scalar_id(
    policy$peer_name, "synopsis source peer")
  if (!peer %in% names(pins) || !is.list(identity) ||
      is.null(identity$identity_pk) || is.null(identity$identity_sk) ||
      !is.function(.signer) || !is.function(.verifier)) {
    stop("Invalid synopsis Claim source identity.", call. = FALSE)
  }
  identity_pk <- .dsvert_dp_analysis_identity_pk(
    identity$identity_pk, "synopsis source identity")
  if (!identical(identity_pk, unname(pins[[peer]]))) {
    stop("The synopsis Claim source identity is not pinned.", call. = FALSE)
  }
  snapshots <- .dsvert_dp_capsule_resolved_snapshots(
    policy, resolved_snapshots)
  snapshot_key <- .dsvert_dp_analysis_snapshot_key_v1()
  if (!is.raw(snapshot_key) || length(snapshot_key) != 32L) {
    stop("The synopsis snapshot commitment key is invalid.", call. = FALSE)
  }
  protected_datasets <- lapply(names(snapshots), function(dataset_key) {
    snapshot <- snapshots[[dataset_key]]
    descriptor <- policy$datasets[[dataset_key]]
    expected_public <- list(
      data_name = dataset_key, id = descriptor$id,
      version = descriptor$version,
      alignment_manifest_hash = descriptor$alignment_manifest_hash,
      alignment_manifest_version = descriptor$alignment_manifest_version)
    if (!identical(snapshot$dataset$public, expected_public)) {
      stop("The synopsis snapshot binding disagrees with local policy.",
           call. = FALSE)
    }
    list(
      dataset_key = dataset_key, dataset = snapshot$dataset$public,
      protected_fingerprint = snapshot$dataset$fingerprint)
  })
  names(protected_datasets) <- names(snapshots)
  snapshot_set_commitment <- digest::hmac(
    key = snapshot_key,
    object = charToRaw(paste0(
      .DSVERT_DP_SYNOPSIS_SNAPSHOT_DOMAIN,
      .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(list(
        version = .DSVERT_DP_SYNOPSIS_SNAPSHOT_VERSION,
        domain = projection$catalog$domain,
        cohort_id = projection$catalog$cohort_id,
        source_identity_pk = identity_pk,
        peer_pinset_sha256 = projection$catalog$peer_pinset_sha256,
        catalog_sha256 = projection$sha256,
        datasets = protected_datasets))))),
    algo = "sha256", serialize = FALSE, raw = FALSE)
  datasets <- lapply(names(snapshots), function(dataset_key) {
    public <- snapshots[[dataset_key]]$dataset$public
    list(
      dataset_key = dataset_key, dataset_id = public$id,
      dataset_version = public$version,
      alignment_attested = !is.null(public$alignment_manifest_hash),
      alignment_protocol_version = public$alignment_manifest_version)
  })
  names(datasets) <- names(snapshots)
  unsigned <- list(
    version = .DSVERT_DP_SYNOPSIS_CLAIM_VERSION,
    source_peer_name = peer, source_identity_pk = identity_pk,
    peer_pinset_sha256 = projection$catalog$peer_pinset_sha256,
    catalog_sha256 = projection$sha256, datasets = datasets,
    snapshot_set_commitment = snapshot_set_commitment)
  signature <- .signer(
    .dsvert_dp_synopsis_claim_message_v1(unsigned), identity$identity_sk)
  .dsvert_dp_synopsis_snapshot_claim_validate_v1(
    c(unsigned, list(signature = signature)), projection, pins,
    .verifier = .verifier)
}
