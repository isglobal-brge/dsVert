# Internal source-vector-and-catalog identity for a stateless sticky DP synopsis.
#
# This file deliberately defines no remote endpoint.  It binds an existing
# custodian-authoritative catalog_v1 manifest to opaque, owner-minted effective
# source-vector commitments.  Execution and public method rewiring are separate
# milestones.  The catalog hash is not an artifact key: privacy calibration,
# the normative draw law/backend, and both pinned noise-authority roles must be
# added before any sticky subseed can be derived.

.DSVERT_DP_SYNOPSIS_CATALOG_VERSION <-
  "dsvert-stateless-catalog-synopsis-catalog-v1"
.DSVERT_DP_SYNOPSIS_PROJECTION_VERSION <-
  "dsvert-stateless-catalog-synopsis-projection-v1"
.DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_CLAIM_VERSION <-
  "dsvert-stateless-catalog-synopsis-source-vector-claim-v1"
.DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_PROFILE <-
  "dsvert-stateless-catalog-synopsis-source-vector-profile-v1"
.DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_HASH_BLOCK <- 65536L
.DSVERT_DP_SYNOPSIS_CATALOG_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/catalog/v1|"
.DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_CLAIM_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/source-vector-claim/v1|"
.DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_HMAC_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/source-vector-hmac/v1|"
.DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_BLOCK_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/source-vector-block/v1|"

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

.dsvert_dp_synopsis_catalog_ids_v1 <- function(value) {
  if (!is.list(value)) return(value)
  fields <- names(value)
  if (!is.null(fields)) {
    renamed <- fields
    renamed[renamed == "analysis_id"] <- "catalog_entry_id"
    if (anyNA(fields) || any(!nzchar(fields)) || anyDuplicated(fields) ||
        anyDuplicated(renamed)) {
      stop("The synopsis catalog ID namespace has a collision.",
           call. = FALSE)
    }
    names(value) <- renamed
  }
  lapply(value, .dsvert_dp_synopsis_catalog_ids_v1)
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
  # `analysis_id` inside the signed custodian catalog is a semantic entry ID,
  # not an analyst request field.  Namespace it only in this projection so
  # the global operational-field rejection remains strict.
  catalog <- .dsvert_dp_synopsis_catalog_ids_v1(catalog)
  .dsvert_dp_synopsis_catalog_projection_validate_v1(list(
    version = .DSVERT_DP_SYNOPSIS_PROJECTION_VERSION,
    sha256 = .dsvert_dp_synopsis_catalog_hash_v1(catalog),
    catalog = catalog))
}

.dsvert_dp_synopsis_source_vector_claim_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_CLAIM_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_synopsis_source_vector_claim_validate_v1 <- function(
    claim, projection, peer_pins,
    .verifier = .dsvert_relay_verify_message) {
  projection <- .dsvert_dp_synopsis_catalog_projection_validate_v1(projection)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(peer_pins)
  required <- c(
    "version", "source_peer_name", "source_identity_pk",
    "catalog_sha256", "source_vector_commitment", "signature")
  if (!is.list(claim) || is.null(names(claim)) || anyNA(names(claim)) ||
      anyDuplicated(names(claim)) || !setequal(names(claim), required) ||
      !identical(
        claim$version, .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_CLAIM_VERSION) ||
      !is.function(.verifier)) {
    stop("Invalid signed synopsis source-vector Claim.", call. = FALSE)
  }
  peer <- .dsvert_dp_analysis_scalar_id(
    claim$source_peer_name, "synopsis source peer")
  identity_pk <- .dsvert_dp_analysis_identity_pk(
    claim$source_identity_pk, "synopsis source identity")
  if (!peer %in% names(pins) ||
      !identical(identity_pk, unname(pins[[peer]]))) {
    stop("The synopsis Claim source identity is not pinned.", call. = FALSE)
  }
  if (!identical(
        .dsvert_dp_synopsis_pinset_hash_v1(pins),
        projection$catalog$peer_pinset_sha256)) {
    stop("The synopsis Claim targets a different peer pinset.",
         call. = FALSE)
  }
  catalog_sha256 <- .dsvert_dp_synopsis_hex_v1(
    claim$catalog_sha256, "Claim catalog hash")
  if (!identical(catalog_sha256, projection$sha256)) {
    stop("The synopsis Claim targets a different catalog.", call. = FALSE)
  }
  commitment <- .dsvert_dp_synopsis_hex_v1(
    claim$source_vector_commitment, "source-vector commitment")
  signature <- .dsvert_dp_synopsis_signature_v1(claim$signature)
  normalized <- list(
    version = .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_CLAIM_VERSION,
    source_peer_name = peer, source_identity_pk = identity_pk,
    catalog_sha256 = catalog_sha256,
    source_vector_commitment = commitment,
    signature = signature)
  if (!isTRUE(tryCatch(
      .verifier(
        .dsvert_dp_synopsis_source_vector_claim_message_v1(normalized),
        identity_pk, signature), error = function(error) FALSE))) {
    stop("Synopsis source-vector Claim signature verification failed.",
         call. = FALSE)
  }
  normalized
}

.dsvert_dp_synopsis_source_vector_blocks_v1 <- function(
    producer, blocks, what, order_by_start = FALSE) {
  if (!is.list(blocks) || (length(blocks) &&
      (is.null(names(blocks)) || anyNA(names(blocks)) ||
       any(!nzchar(names(blocks))) || anyDuplicated(names(blocks)))) ||
      !is.logical(order_by_start) || length(order_by_start) != 1L ||
      is.na(order_by_start)) {
    stop("Invalid synopsis source-vector ", what, " layout.", call. = FALSE)
  }
  if (!length(blocks)) return(list())
  keys <- if (isTRUE(order_by_start)) {
    starts <- vapply(blocks, function(block) {
      .dsvert_dp_analysis_positive_integer(
        block$start, paste("synopsis", what, "block start"))
    }, numeric(1L))
    names(blocks)[order(starts, method = "radix")]
  } else {
    sort(names(blocks), method = "radix")
  }
  result <- lapply(keys, function(key) {
    block <- blocks[[key]]
    start <- .dsvert_dp_analysis_positive_integer(
      block$start, paste("synopsis", what, "block start"))
    block_length <- .dsvert_dp_analysis_positive_integer(
      block$length, paste("synopsis", what, "block length"))
    chunk_starts <- seq.int(
      0, block_length - 1L,
      by = .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_HASH_BLOCK)
    chunk_hashes <- vapply(seq_along(chunk_starts), function(chunk_index) {
      offset <- chunk_starts[[chunk_index]]
      count <- min(
        .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_HASH_BLOCK,
        block_length - offset)
      values <- .dsvert_dp_integer_vector(
        producer$read_range(start + offset, count),
        paste("synopsis", what, "block values"))
      if (length(values) != count) {
        stop("The synopsis source-vector block has the wrong length.",
             call. = FALSE)
      }
      digest::digest(
        paste0(
          .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_BLOCK_DOMAIN,
          .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(list(
            profile = .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_PROFILE,
            semantic_block_key = key, block_length = block_length,
            chunk_index = as.integer(chunk_index),
            chunk_count = length(chunk_starts), values = values)))),
        algo = "sha256", serialize = FALSE)
    }, character(1L))
    list(
      length = block_length,
      block_hashes = unname(chunk_hashes))
  })
  names(result) <- keys
  result[order(names(result), method = "radix")]
}

.dsvert_dp_synopsis_source_vector_unsigned_from_producer_v1 <- function(
    policy, manifest, producer, identity_pk) {
  # The caller owns the producer.  This helper only borrows read_range and
  # must never reset or retain the producer on success or failure.
  projection <- .dsvert_dp_synopsis_catalog_projection_v1(policy, manifest)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  peer <- .dsvert_dp_analysis_scalar_id(
    policy$peer_name, "synopsis source peer")
  if (!peer %in% names(pins)) {
    stop("Invalid synopsis Claim source identity.", call. = FALSE)
  }
  identity_pk <- .dsvert_dp_analysis_identity_pk(
    identity_pk, "synopsis source identity")
  if (!identical(identity_pk, unname(pins[[peer]]))) {
    stop("The synopsis Claim source identity is not pinned.", call. = FALSE)
  }
  release <- .dsvert_dp_capsule_coordinate_layout(manifest)
  if (!identical(as.numeric(release$coordinate_count),
                 as.numeric(projection$catalog$coordinate_count)) ||
      !identical(release$sha256,
                 projection$catalog$coordinate_order_sha256)) {
    stop("The synopsis release layout disagrees with its catalog.",
         call. = FALSE)
  }
  cross <- .dsvert_dp_gaussian_cross_layout(manifest, release)
  owns_release <- any(vapply(release$blocks, function(block) {
    identical(block$owner_peer, peer)
  }, logical(1L)))
  if (!is.list(producer) || !is.function(producer$read_range) ||
      !is.function(producer$reset) ||
      !identical(as.numeric(producer$coordinate_count),
                 as.numeric(cross$transport_coordinate_count)) ||
      !identical(producer$coordinate_order_sha256,
                 cross$transport_coordinate_order_sha256) ||
      !identical(as.numeric(cross$release_coordinate_count),
                 as.numeric(release$coordinate_count)) ||
      !identical(cross$release_coordinate_order_sha256, release$sha256)) {
    stop("The synopsis source-vector producer has the wrong layout.",
         call. = FALSE)
  }
  release_cache <- new.env(parent = emptyenv())
  release_reader <- if (!isTRUE(owns_release)) list(
    read_range = function(start, count) numeric(count)) else list(
    read_range = function(start, count) {
      result <- numeric(count)
      position <- start
      last <- start + count - 1L
      while (position <= last) {
        chunk_start <- floor(
          (position - 1L) /
            .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_HASH_BLOCK) *
          .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_HASH_BLOCK + 1L
        chunk_count <- min(
          .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_HASH_BLOCK,
          release$coordinate_count - chunk_start + 1L)
        if (!identical(release_cache$start, chunk_start)) {
          values <- .dsvert_dp_integer_vector(
            producer$read_range(chunk_start, chunk_count),
            "synopsis release source chunk")
          if (length(values) != chunk_count) {
            stop("The synopsis release source chunk has the wrong length.",
                 call. = FALSE)
          }
          release_cache$start <- chunk_start
          release_cache$values <- values
        }
        take <- min(last - position + 1L,
                    chunk_start + chunk_count - position)
        result[seq.int(position - start + 1L, length.out = take)] <-
          release_cache$values[
            seq.int(position - chunk_start + 1L, length.out = take)]
        position <- position + take
      }
      result
    })
  release_blocks <- .dsvert_dp_synopsis_source_vector_blocks_v1(
    release_reader, release$blocks, "release", order_by_start = TRUE)
  cross_blocks <- cross$blocks[vapply(cross$blocks, function(block) {
    identical(block$owner_peer, peer)
  }, logical(1L))]
  cross_blocks <- .dsvert_dp_synopsis_source_vector_blocks_v1(
    producer, cross_blocks, "private cross")
  hmac_key <- .dsvert_dp_analysis_snapshot_key_v1()
  if (!is.raw(hmac_key) || length(hmac_key) != 32L) {
    stop("The synopsis source-vector HMAC key is invalid.", call. = FALSE)
  }
  commitment <- digest::hmac(
    key = hmac_key,
    object = charToRaw(paste0(
      .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_HMAC_DOMAIN,
      .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(list(
        version = .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_CLAIM_VERSION,
        profile = .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_PROFILE,
        catalog_sha256 = projection$sha256,
        source_identity = list(
          peer_name = peer, identity_pk = identity_pk),
        release_blocks = release_blocks,
        local_cross_blocks = cross_blocks))))),
    algo = "sha256", serialize = FALSE, raw = FALSE)
  unsigned <- list(
    version = .DSVERT_DP_SYNOPSIS_SOURCE_VECTOR_CLAIM_VERSION,
    source_peer_name = peer, source_identity_pk = identity_pk,
    catalog_sha256 = projection$sha256,
    source_vector_commitment = commitment)
  unsigned
}

.dsvert_dp_synopsis_source_vector_claim_v1 <- function(
    policy, manifest, resolved_snapshots, identity,
    .signer = .dsvert_relay_sign_message,
    .verifier = .dsvert_relay_verify_message) {
  # This is a low-level, server-only Claim.  A future K-peer compiler must
  # validate its plan and authority roles before invoking it.  It is not an
  # endpoint and the catalog hash alone is not a sticky artifact key.
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
  projection <- .dsvert_dp_synopsis_catalog_projection_v1(policy, manifest)
  release <- .dsvert_dp_capsule_coordinate_layout(manifest)
  if (!identical(as.numeric(release$coordinate_count),
                 as.numeric(projection$catalog$coordinate_count)) ||
      !identical(release$sha256,
                 projection$catalog$coordinate_order_sha256)) {
    stop("The synopsis release layout disagrees with its catalog.",
         call. = FALSE)
  }
  owns_release <- any(vapply(release$blocks, function(block) {
    identical(block$owner_peer, peer)
  }, logical(1L)))
  producer <- .dsvert_dp_gaussian_cross_source_producer(
    policy, manifest, resolved_snapshots, compute_commitment = FALSE,
    include_release = owns_release)
  on.exit(producer$reset(), add = TRUE)
  unsigned <- .dsvert_dp_synopsis_source_vector_unsigned_from_producer_v1(
    policy, manifest, producer, identity_pk)
  signature <- .signer(
    .dsvert_dp_synopsis_source_vector_claim_message_v1(unsigned),
    identity$identity_sk)
  .dsvert_dp_synopsis_source_vector_claim_validate_v1(
    c(unsigned, list(signature = signature)), projection, pins,
    .verifier = .verifier)
}
