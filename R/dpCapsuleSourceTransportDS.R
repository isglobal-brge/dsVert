# Purpose-bound transport for exact biomedical-capsule source coordinates.
#
# This boundary is intentionally narrower than the generic MPC transports.
# A server-local producer binds one fixed-shape Ring128 vector at preparation,
# then materializes, splits and encrypts bounded chunks on demand.  Both shares
# of every emitted chunk are committed atomically before returning anything to
# the relay.  Recipients aggregate shares in canonical source/chunk order.  No
# registered method can read a plaintext share or the aggregate.

.DSVERT_DP_CAPSULE_SOURCE_CONTRACT_VERSION <-
  "dsvert-biomedical-capsule-source-contract-v1"
.DSVERT_DP_CAPSULE_SOURCE_CROSS_CONTRACT_VERSION <-
  "dsvert-biomedical-capsule-source-contract-v4-cross-gaussian-xor-alignment"
.DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_CONTRACT_VERSION <-
  "dsvert-biomedical-capsule-source-contract-v5-cross-categorical-xor-alignment"
.DSVERT_DP_CAPSULE_SOURCE_TICKET_VERSION <-
  "dsvert-biomedical-capsule-source-recipient-ticket-v1"
.DSVERT_DP_CAPSULE_SOURCE_SUMMARY_VERSION <-
  "dsvert-biomedical-capsule-source-summary-v2-streaming"
.DSVERT_DP_CAPSULE_SOURCE_CHUNK_VERSION <-
  "dsvert-biomedical-capsule-source-encrypted-chunk-v1"
.DSVERT_DP_CAPSULE_SOURCE_BUNDLE_VERSION <-
  "dsvert-biomedical-capsule-source-encrypted-bundle-v1"
.DSVERT_DP_CAPSULE_SOURCE_PLAINTEXT_VERSION <-
  "dsvert-biomedical-capsule-source-plaintext-chunk-v2-xor-alignment"
.DSVERT_DP_CAPSULE_SOURCE_ACK_VERSION <-
  "dsvert-biomedical-capsule-source-ack-v1"
.DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION <-
  "dsvert-biomedical-capsule-source-byte-window-v1"
.DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT <-
  "dsvert-biomedical-capsule-source-adaptive-window-v2"
.DSVERT_DP_CAPSULE_SOURCE_SCALAR_TRANSPORT <-
  "dsvert-biomedical-capsule-source-scalar-v1"
.DSVERT_DP_CAPSULE_SOURCE_TICKET_NEGOTIATION_VERSION <-
  "dsvert-biomedical-capsule-source-ticket-negotiation-v1"
.DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ATTESTATION_VERSION <-
  "dsvert-biomedical-capsule-source-capability-attestation-v1"
.DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ONLY_REQUEST <-
  "dsvert-biomedical-capsule-source-capability-only-v1"
.DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ONLY_REQUEST_V2 <-
  "dsvert-biomedical-capsule-source-capability-only-v2"
.DSVERT_DP_CAPSULE_SOURCE_SUMMARY_NEGOTIATION_VERSION <-
  "dsvert-biomedical-capsule-source-summary-negotiation-v1"
.DSVERT_DP_CAPSULE_SOURCE_ACK_WINDOW_VERSION <-
  "dsvert-biomedical-capsule-source-ack-window-v1"
.DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION <-
  "dsvert-biomedical-capsule-source-store-v3"
.DSVERT_DP_CAPSULE_SOURCE_COMPACTION_VERSION <-
  "dsvert-biomedical-capsule-source-compaction-v1"
.DSVERT_DP_CAPSULE_SOURCE_COMPACTION_AUTH_VERSION <-
  "dsvert-biomedical-capsule-source-compaction-authorization-v1"
.DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES <- 16L * 1024L
.DSVERT_DP_CAPSULE_SOURCE_RECIPIENT_KEY_OVERHEAD_BYTES <- 64L * 1024L
.DSVERT_DP_CAPSULE_SOURCE_PURPOSE <-
  "biomedical_capsule_ring128_source_shares_only"
.DSVERT_DP_CAPSULE_SOURCE_CROSS_PURPOSE <-
  "biomedical_capsule_ring128_cross_gaussian_inputs_and_release_shares_only"
.DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_PURPOSE <-
  "biomedical_capsule_ring128_cross_categorical_inputs_and_release_shares_only"
.DSVERT_DP_CAPSULE_SOURCE_ALIGNMENT_SHARING <-
  "recipient_specific_xor_share_exact_gc_gate_v1"
.DSVERT_DP_CAPSULE_SOURCE_RING_BITS <- 128L
.DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES <- 16L
.DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES <- 8192L
.DSVERT_DP_CAPSULE_SOURCE_MAX_MANIFEST_BYTES <- 32L * 1024L^2
.DSVERT_DP_CAPSULE_SOURCE_MAX_ENVELOPE_BYTES <- 1024L * 1024L
.DSVERT_DP_CAPSULE_SOURCE_MAX_BUNDLE_BYTES <- 768L * 1024L
.DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_WINDOW_BYTES <- 768L * 1024L
.DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_ACCEPT_WINDOW_BYTES <- 1024L * 1024L
.DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_BYTES <- 8L * 1024L^2
.DSVERT_DP_CAPSULE_SOURCE_MAX_ACCEPT_WINDOW_BYTES <- 8L * 1024L^2
.DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_CHUNKS <- 8L
.DSVERT_DP_CAPSULE_SOURCE_MAX_STORE_RECORD_BYTES <-
  2L * .DSVERT_DP_CAPSULE_SOURCE_MAX_MANIFEST_BYTES + 512L * 1024L

.dsvert_dp_capsule_source_cross_contract <- function(contract) {
  is.list(contract) && contract$version %in% c(
    .DSVERT_DP_CAPSULE_SOURCE_CROSS_CONTRACT_VERSION,
    .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_CONTRACT_VERSION)
}

.dsvert_dp_capsule_source_scalar <- function(value, what, pattern = NULL,
                                              maximum_bytes = 512L) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value)) {
    stop("Invalid biomedical capsule source ", what, ".", call. = FALSE)
  }
  size <- nchar(value, type = "bytes")
  if (size > maximum_bytes) {
    .dsvert_resource_oversize(
      size, maximum_bytes,
      paste("biomedical capsule source", what))
  }
  if (!is.null(pattern) && !grepl(pattern, value)) {
    stop("Invalid biomedical capsule source ", what, ".", call. = FALSE)
  }
  enc2utf8(value)
}

.dsvert_dp_capsule_source_index <- function(value, what, minimum = 0,
                                             maximum = 2^31 - 1) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) || value < minimum ||
      value > maximum) {
    stop("Invalid biomedical capsule source ", what, ".", call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_dp_capsule_source_decode_json <- function(
    value, what, maximum_bytes) {
  value <- .dsvert_dp_capsule_source_scalar(
    value, what, maximum_bytes = maximum_bytes)
  decoded <- tryCatch(
    jsonlite::fromJSON(value, simplifyVector = FALSE),
    error = function(e) NULL)
  canonical <- tryCatch(
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(decoded)),
    error = function(e) NULL)
  if (!is.list(decoded) || is.null(canonical) ||
      !identical(canonical, value)) {
    stop("Invalid or non-canonical biomedical capsule source ", what, ".",
         call. = FALSE)
  }
  decoded
}

.dsvert_dp_capsule_source_encode_json <- function(value) {
  .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(value))
}

.dsvert_dp_capsule_source_manifest <- function(manifest_json) {
  manifest_json <- .dsvert_dp_capsule_source_scalar(
    manifest_json, "manifest",
    maximum_bytes = .DSVERT_DP_CAPSULE_SOURCE_MAX_MANIFEST_BYTES)
  # The internal capsule builder canonicalises every numeric field as an R
  # double and retains homogeneous vectors.  `simplifyVector = FALSE` would
  # turn those vectors into lists; the ordinary JSON integer parser would in
  # turn change exact doubles such as 1 to R integers.  Restore precisely the
  # builder's type contract before running its strict identity validator.
  decoded <- tryCatch(jsonlite::fromJSON(
    manifest_json, simplifyVector = TRUE, simplifyDataFrame = FALSE,
    simplifyMatrix = FALSE), error = function(e) NULL)
  restore_numeric <- function(value) {
    if (is.integer(value)) return(as.numeric(value))
    if (!is.list(value)) return(value)
    result <- lapply(value, restore_numeric)
    names(result) <- names(value)
    result
  }
  decoded <- if (is.list(decoded)) restore_numeric(decoded) else NULL
  canonical <- tryCatch(
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(decoded)),
    error = function(e) NULL)
  if (is.null(canonical) || !identical(canonical, manifest_json)) {
    stop("Invalid or non-canonical biomedical capsule source manifest.",
         call. = FALSE)
  }
  decoded
}

.dsvert_dp_capsule_source_contract <- function(policy, manifest) {
  validated <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  layout <- validated$layout
  cross_layout <- .dsvert_dp_gaussian_cross_layout(manifest, layout)
  categorical_cross <- length(
    .dsvert_dp_categorical_cross_artifacts(manifest)) > 0L
  ordinary_source_peers <- vapply(
    layout$blocks, `[[`, character(1L), "owner_peer")
  cross_source_peers <- if (isTRUE(cross_layout$enabled)) {
    .dsvert_dp_gaussian_cross_names(
      cross_layout$source_peers, "source-peer list")
  } else {
    character()
  }
  source_peers <- sort(unique(c(
    ordinary_source_peers, cross_source_peers)), method = "radix")
  pins <- policy$peer_pinset
  designated <- sort(policy$designated_noise_peers, method = "radix")
  if (!is.character(pins) || is.null(names(pins)) ||
      anyNA(names(pins)) || anyDuplicated(names(pins)) ||
      !length(source_peers) || !all(source_peers %in% names(pins)) ||
      length(designated) != 2L || anyNA(designated) ||
      anyDuplicated(designated) || !all(designated %in% names(pins)) ||
      !identical(policy$peer_pinset_sha256,
                 manifest$capsule_identity$contract$peer_pinset_sha256)) {
    stop("The biomedical capsule source peer assignment is invalid.",
         call. = FALSE)
  }
  coordinate_count <- if (isTRUE(cross_layout$enabled)) {
    cross_layout$transport_coordinate_count
  } else {
    layout$coordinate_count
  }
  coordinate_order_sha256 <- if (isTRUE(cross_layout$enabled)) {
    cross_layout$transport_coordinate_order_sha256
  } else {
    layout$sha256
  }
  chunk_count <- ceiling(
    coordinate_count /
      .DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES)
  contract <- list(
    version = if (isTRUE(categorical_cross)) {
      .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_CONTRACT_VERSION
    } else if (isTRUE(cross_layout$enabled)) {
      .DSVERT_DP_CAPSULE_SOURCE_CROSS_CONTRACT_VERSION
    } else {
      .DSVERT_DP_CAPSULE_SOURCE_CONTRACT_VERSION
    },
    purpose = if (isTRUE(categorical_cross)) {
      .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_PURPOSE
    } else if (isTRUE(cross_layout$enabled)) {
      .DSVERT_DP_CAPSULE_SOURCE_CROSS_PURPOSE
    } else {
      .DSVERT_DP_CAPSULE_SOURCE_PURPOSE
    },
    capsule_id = validated$identity$capsule_id,
    logical_snapshot_sha256 = .dsvert_joint_dp_hash(
      manifest$logical_snapshot),
    workload_sha256 = .dsvert_joint_dp_hash(manifest$workload),
    source_context_hash =
      manifest$workload$capsule_mechanism$source_context_hash,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    source_peers = as.list(source_peers),
    designated_noise_peers = as.list(designated),
    coordinate_count = as.integer(coordinate_count),
    coordinate_order_sha256 = coordinate_order_sha256,
    ring_bits = .DSVERT_DP_CAPSULE_SOURCE_RING_BITS,
    record_bytes = .DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES,
    record_encoding = "little_endian_unsigned_fixed_16_bytes",
    chunk_coordinates = .DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES,
    chunk_count = as.integer(chunk_count),
    chunk_shape = if (isTRUE(cross_layout$enabled)) {
      "fixed_release_prefix_and_capacity_padded_private_slices"
    } else {
      "fixed_public_coordinate_slices"
    },
    history_gate = FALSE,
    ready_for_sampling = FALSE)
  if (isTRUE(cross_layout$enabled)) {
    contract <- c(contract, list(
      release_coordinate_count =
        as.integer(cross_layout$release_coordinate_count),
      release_coordinate_order_sha256 =
        cross_layout$release_coordinate_order_sha256,
      private_layout_sha256 =
        cross_layout$transport_coordinate_order_sha256,
      cross_input_peers = as.list(cross_source_peers),
      private_alignment_consensus =
        .DSVERT_DP_CAPSULE_SOURCE_ALIGNMENT_SHARING))
  }
  .dsvert_dp_canonical_query_value(contract)
}

.dsvert_dp_capsule_source_contract_json <- function(
    policy, manifest_json, source_contract = NULL) {
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  base <- .dsvert_dp_capsule_source_contract(policy, manifest)
  contract <- if (is.null(source_contract)) {
    base
  } else {
    supplied <- tryCatch(
      .dsvert_dp_capsule_source_contract_validate(
        .dsvert_dp_canonical_query_value(source_contract)),
      error = function(error) NULL)
    binding <- if (is.list(supplied)) supplied$synopsis_binding else NULL
    detached <- supplied
    if (is.list(detached)) {
      detached$synopsis_binding <- NULL
      detached$capsule_id <- binding$manifest_capsule_id
      detached <- tryCatch(
        .dsvert_dp_canonical_query_value(detached),
        error = function(error) NULL)
    }
    if (is.null(binding) || !identical(detached, base)) {
      stop("The synopsis source contract targets a different manifest.",
           call. = FALSE)
    }
    supplied
  }
  list(
    manifest = manifest, contract = contract,
    contract_json = .dsvert_dp_canonical_json(contract),
    contract_hash = .dsvert_joint_dp_hash(contract))
}

.dsvert_dp_capsule_source_names <- function(value, what) {
  if (!is.list(value) || !length(value) ||
      !all(vapply(value, function(item) {
        is.character(item) && length(item) == 1L && !is.na(item) &&
          grepl("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", item)
      }, logical(1L)))) {
    stop("Invalid biomedical capsule source ", what, ".", call. = FALSE)
  }
  unname(unlist(value, use.names = FALSE))
}

.dsvert_dp_capsule_source_contract_validate <- function(contract) {
  synopsis <- is.list(contract) &&
    "synopsis_binding" %in% names(contract)
  base_required <- c(
    "version", "purpose", "capsule_id", "logical_snapshot_sha256",
    "workload_sha256", "source_context_hash", "peer_pinset_sha256",
    "source_peers", "designated_noise_peers", "coordinate_count",
    "coordinate_order_sha256", "ring_bits", "record_bytes",
    "record_encoding", "chunk_coordinates", "chunk_count", "chunk_shape",
    "history_gate", "ready_for_sampling")
  cross <- .dsvert_dp_capsule_source_cross_contract(contract)
  cross_required <- c(
    "release_coordinate_count", "release_coordinate_order_sha256",
    "private_layout_sha256", "cross_input_peers",
    "private_alignment_consensus")
  required <- c(
    base_required, if (cross) cross_required else character(),
    if (synopsis) "synopsis_binding" else character())
  valid <- is.list(contract) && !is.null(names(contract)) &&
    !anyNA(names(contract)) && !anyDuplicated(names(contract)) &&
    setequal(names(contract), required) &&
    contract$version %in% c(
      .DSVERT_DP_CAPSULE_SOURCE_CONTRACT_VERSION,
      .DSVERT_DP_CAPSULE_SOURCE_CROSS_CONTRACT_VERSION,
      .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_CONTRACT_VERSION) &&
    identical(contract$purpose, if (identical(
        contract$version,
        .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_CONTRACT_VERSION)) {
      .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_PURPOSE
    } else if (cross) {
      .DSVERT_DP_CAPSULE_SOURCE_CROSS_PURPOSE
    } else {
      .DSVERT_DP_CAPSULE_SOURCE_PURPOSE
    }) &&
    grepl("^[0-9a-f]{64}$", contract$capsule_id) &&
    all(vapply(contract[c(
      "logical_snapshot_sha256", "workload_sha256", "source_context_hash",
      "peer_pinset_sha256", "coordinate_order_sha256")], function(value) {
        is.character(value) && length(value) == 1L && !is.na(value) &&
          grepl("^[0-9a-f]{64}$", value)
      }, logical(1L))) &&
    identical(as.numeric(contract$ring_bits), 128) &&
    identical(as.numeric(contract$record_bytes), 16) &&
    identical(contract$record_encoding,
              "little_endian_unsigned_fixed_16_bytes") &&
    identical(as.numeric(contract$chunk_coordinates),
              as.numeric(.DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES)) &&
    identical(contract$chunk_shape, if (cross) {
      "fixed_release_prefix_and_capacity_padded_private_slices"
    } else {
      "fixed_public_coordinate_slices"
    }) &&
    identical(contract$history_gate, FALSE) &&
    identical(contract$ready_for_sampling, FALSE)
  if (!isTRUE(valid)) {
    stop("Invalid biomedical capsule source contract.", call. = FALSE)
  }
  if (synopsis) {
    binding <- contract$synopsis_binding
    binding_fields <- c(
      "version", "manifest_capsule_id", "artifact_key",
      "source_claim_set_sha256")
    valid_binding <- is.list(binding) && !is.null(names(binding)) &&
      !anyNA(names(binding)) && !anyDuplicated(names(binding)) &&
      setequal(names(binding), binding_fields) &&
      identical(
        binding$version, .DSVERT_DP_SYNOPSIS_SOURCE_CONTRACT_VERSION) &&
      all(vapply(binding[setdiff(binding_fields, "version")],
        function(value) {
          is.character(value) && length(value) == 1L && !is.na(value) &&
            grepl("^[0-9a-f]{64}$", value)
        }, logical(1L))) &&
      identical(contract$capsule_id, tryCatch(
        .dsvert_dp_synopsis_source_namespace_id_v1(binding),
        error = function(error) NULL))
    if (!isTRUE(valid_binding)) {
      stop("Invalid synopsis capsule source binding.", call. = FALSE)
    }
  }
  coordinate_count <- .dsvert_dp_capsule_source_index(
    contract$coordinate_count, "coordinate count", 1,
    if (cross) .DSVERT_DP_GAUSSIAN_CROSS_MAX_TRANSPORT_COORDINATES else
      .DSVERT_DP_MAX_COORDINATES)
  chunk_count <- .dsvert_dp_capsule_source_index(
    contract$chunk_count, "chunk count", 1,
    ceiling((if (cross) {
      .DSVERT_DP_GAUSSIAN_CROSS_MAX_TRANSPORT_COORDINATES
    } else {
      .DSVERT_DP_MAX_COORDINATES
    }) /
              .DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES))
  if (!identical(
        chunk_count,
        ceiling(coordinate_count /
                  .DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES))) {
    stop("The biomedical capsule source chunk shape is invalid.",
         call. = FALSE)
  }
  sources <- .dsvert_dp_capsule_source_names(
    contract$source_peers, "source peer list")
  recipients <- .dsvert_dp_capsule_source_names(
    contract$designated_noise_peers, "noise-peer list")
  if (anyDuplicated(sources) ||
      !identical(sources, sort(sources, method = "radix")) ||
      length(recipients) != 2L || anyDuplicated(recipients) ||
      !identical(recipients, sort(recipients, method = "radix"))) {
    stop("The biomedical capsule source peer order is invalid.",
         call. = FALSE)
  }
  if (cross) {
    release_count <- .dsvert_dp_capsule_source_index(
      contract$release_coordinate_count, "release coordinate count", 1,
      .DSVERT_DP_MAX_COORDINATES)
    cross_peers <- .dsvert_dp_capsule_source_names(
      contract$cross_input_peers, "cross-input peer list")
    cross_hashes <- contract[c(
      "release_coordinate_order_sha256", "private_layout_sha256")]
    if (release_count >= coordinate_count ||
        anyDuplicated(cross_peers) ||
        !identical(cross_peers, sort(cross_peers, method = "radix")) ||
        !all(cross_peers %in% sources) ||
        !all(vapply(cross_hashes, function(value) {
          is.character(value) && length(value) == 1L && !is.na(value) &&
            grepl("^[0-9a-f]{64}$", value)
        }, logical(1L))) ||
        !identical(contract$private_layout_sha256,
                   contract$coordinate_order_sha256) ||
        !identical(
          contract$private_alignment_consensus,
          .DSVERT_DP_CAPSULE_SOURCE_ALIGNMENT_SHARING)) {
      stop("The cross-owner source contract is invalid.",
           call. = FALSE)
    }
  }
  contract
}

.dsvert_dp_capsule_source_manifest_capsule_id <- function(contract) {
  contract <- .dsvert_dp_capsule_source_contract_validate(contract)
  if (is.null(contract$synopsis_binding)) contract$capsule_id else
    contract$synopsis_binding$manifest_capsule_id
}

.dsvert_dp_capsule_source_store_path <- function(policy) {
  # v1/v2 remain untouched as historical authenticated state. v3 starts a new
  # wire epoch because cross-owner alignment commitments are now XOR-shared;
  # replaying a v2 ciphertext would disclose the complete commitment to one
  # compute peer. Source coordinates remain semantic-capsule state, so v3
  # deliberately excludes the local noise-root epoch from its store binding.
  path <- paste0(policy$ledger_path, ".capsule-source-v3.sqlite")
  .dsvert_dp_assert_private_file(
    path, "biomedical capsule source store",
    require_private = isTRUE(policy$ledger_private))
  path
}

.dsvert_dp_capsule_source_resource_owner <- function(policy) {
  .dsvert_resource_external_owner(
    "capsule-source", .dsvert_dp_capsule_source_store_path(policy))
}

.dsvert_dp_capsule_source_resource_reconcile <- function(policy, state) {
  if (!is.list(state) || is.null(state$reserved_bytes)) {
    stop("The biomedical capsule source capacity state is invalid.",
         call. = FALSE)
  }
  owner <- .dsvert_dp_capsule_source_resource_owner(policy)
  .dsvert_resource_external_reconcile(
    owner, .dsvert_dp_capsule_source_index(
      state$reserved_bytes, "reserved-byte state", 0, 2^53 - 1),
    "capsule-source")
  invisible(owner)
}

.dsvert_dp_capsule_source_spool_max_bytes <- function() {
  value <- getOption("dsvert.dp.capsule_source_spool_max_bytes", 64 * 1024^3)
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) || value < 64 * 1024^2 ||
      value > 1024^4) {
    stop("Invalid biomedical capsule source spool capacity.", call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_dp_capsule_source_mac <- function(secret, domain, value) {
  if (!is.raw(secret) || length(secret) != 32L ||
      !is.character(domain) || length(domain) != 1L || is.na(domain) ||
      !is.character(value) || length(value) != 1L || is.na(value)) {
    stop("Invalid biomedical capsule source authentication input.",
         call. = FALSE)
  }
  digest::hmac(
    key = secret,
    object = charToRaw(paste0(
      "dsVert/biomedical-capsule/source-store/v2/", domain, "|", value)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_dp_capsule_source_hex_raw <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    stop("Invalid biomedical capsule source ", what, ".", call. = FALSE)
  }
  starts <- seq.int(1L, 63L, by = 2L)
  as.raw(strtoi(substring(value, starts, starts + 1L), base = 16L))
}

.dsvert_dp_capsule_source_alignment_shares <- function(
    secret, contract, source_name, alignment_hash) {
  contract <- .dsvert_dp_capsule_source_contract_validate(contract)
  if (!.dsvert_dp_capsule_source_cross_contract(contract)) {
    stop("Alignment shares require a cross-owner source contract.",
         call. = FALSE)
  }
  source_name <- .dsvert_dp_capsule_source_scalar(
    source_name, "alignment-share source name",
    "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", 128L)
  sources <- .dsvert_dp_capsule_source_names(
    contract$source_peers, "source peer list")
  if (!source_name %in% sources) {
    stop("The alignment-share source is outside the capsule contract.",
         call. = FALSE)
  }
  recipients <- .dsvert_dp_capsule_source_names(
    contract$designated_noise_peers, "noise-peer list")
  participants <- .dsvert_dp_capsule_source_names(
    contract$cross_input_peers, "cross-input peer list")
  if (!source_name %in% participants) {
    if (!identical(alignment_hash, "not_applicable")) {
      stop("A non-participating source supplied private alignment material.",
           call. = FALSE)
    }
    result <- as.list(rep("not_applicable", 2L))
    names(result) <- recipients
    return(result)
  }
  alignment <- .dsvert_dp_capsule_source_hex_raw(
    alignment_hash, "private alignment consensus")
  mask_material <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(list(
      version = .DSVERT_DP_CAPSULE_SOURCE_ALIGNMENT_SHARING,
      capsule_id = contract$capsule_id,
      contract_hash = .dsvert_joint_dp_hash(contract),
      peer_pinset_sha256 = contract$peer_pinset_sha256,
      source_name = source_name,
      recipients = as.list(recipients),
      alignment_commitment_sha256 = alignment_hash)))
  mask <- .dsvert_dp_capsule_source_hex_raw(
    .dsvert_dp_capsule_source_mac(
      secret, "private-alignment-xor-mask-v1", mask_material),
    "private alignment mask")
  second <- as.raw(bitwXor(as.integer(mask), as.integer(alignment)))
  result <- list(
    .dsvert_relay_b64url_encode(mask),
    .dsvert_relay_b64url_encode(second))
  names(result) <- recipients
  result
}

.dsvert_dp_capsule_source_record_mac <- function(secret, table, json) {
  .dsvert_dp_capsule_source_mac(secret, paste0("row/", table), json)
}

.dsvert_dp_capsule_source_record_decode <- function(
    row, secret, table, what) {
  if (nrow(row) != 1L ||
      !.dsvert_joint_dp_dsi_hex_equal(
        row$row_mac[[1L]], .dsvert_dp_capsule_source_record_mac(
          secret, table, row$record_json[[1L]]))) {
    stop("The biomedical capsule source ", what,
         " failed private-store authentication.", call. = FALSE)
  }
  .dsvert_dp_capsule_source_decode_json(
    row$record_json[[1L]], what,
    .DSVERT_DP_CAPSULE_SOURCE_MAX_STORE_RECORD_BYTES)
}

.dsvert_dp_capsule_source_record_insert <- function(
    connection, table, columns, values, record, secret) {
  json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(record))
  mac <- .dsvert_dp_capsule_source_record_mac(secret, table, json)
  names <- c(columns, "record_json", "row_mac")
  placeholders <- paste(rep("?", length(names)), collapse = ", ")
  sql <- paste0(
    "INSERT INTO ", table, "(", paste(names, collapse = ", "),
    ") VALUES(", placeholders, ")")
  DBI::dbExecute(connection, sql, params = c(values, list(json, mac)))
}

.dsvert_dp_capsule_source_record_update <- function(
    connection, table, record, secret, where, params) {
  json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(record))
  mac <- .dsvert_dp_capsule_source_record_mac(secret, table, json)
  changed <- DBI::dbExecute(
    connection,
    paste0("UPDATE ", table,
           " SET record_json = ?, row_mac = ? WHERE ", where),
    params = c(list(json, mac), params))
  if (!identical(as.integer(changed), 1L)) {
    stop("The biomedical capsule source durable update was lost.",
         call. = FALSE)
  }
  invisible(record)
}

.dsvert_dp_capsule_source_compaction_load <- function(
    connection, capsule_id, secret) {
  capsule_id <- .dsvert_dp_capsule_source_scalar(
    capsule_id, "compacted capsule id", "^[0-9a-f]{64}$", 64L)
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT release_instance_id, record_json, row_mac",
    "FROM source_compaction_receipts WHERE capsule_id = ?"),
    params = list(capsule_id))
  if (!nrow(row)) return(NULL)
  record <- .dsvert_dp_capsule_source_record_decode(
    row, secret, "source_compaction_receipts", "compaction receipt")
  required <- c(
    "version", "capsule_id", "source_contract_hash",
    "release_instance_id", "release_contract_hash", "final_vector_root",
    "result_set_hash", "final_chunk_commitments_sha256",
    "release_receipts_sha256", "authorization_sha256", "state",
    "compacted", "source_intermediates_compacted",
    "final_chunks_retained_elsewhere", "durable_replay_retained_elsewhere",
    "active_reservation_bytes", "released_bytes", "retained_receipt_bytes")
  hex_fields <- c(
    "capsule_id", "source_contract_hash", "release_instance_id",
    "release_contract_hash", "final_vector_root", "result_set_hash",
    "final_chunk_commitments_sha256", "release_receipts_sha256",
    "authorization_sha256")
  valid <- !is.null(names(record)) && !anyNA(names(record)) &&
    !anyDuplicated(names(record)) && setequal(names(record), required) &&
    identical(record$version,
                     .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_VERSION) &&
    identical(record$capsule_id, capsule_id) &&
    identical(record$release_instance_id, row$release_instance_id[[1L]]) &&
    all(vapply(record[hex_fields], function(value) {
      is.character(value) && length(value) == 1L && !is.na(value) &&
        grepl("^[0-9a-f]{64}$", value)
    }, logical(1L))) &&
    identical(record$state, "compacted_after_durable_publication") &&
    identical(record$compacted, TRUE) &&
    identical(record$source_intermediates_compacted, TRUE) &&
    identical(record$final_chunks_retained_elsewhere, TRUE) &&
    identical(record$durable_replay_retained_elsewhere, TRUE) &&
    is.numeric(record$active_reservation_bytes) &&
    length(record$active_reservation_bytes) == 1L &&
    !is.na(record$active_reservation_bytes) &&
    is.finite(record$active_reservation_bytes) &&
    record$active_reservation_bytes >=
      .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES &&
    is.numeric(record$released_bytes) &&
    length(record$released_bytes) == 1L &&
    !is.na(record$released_bytes) && is.finite(record$released_bytes) &&
    identical(as.numeric(record$released_bytes),
              as.numeric(record$active_reservation_bytes) -
                .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES) &&
    identical(as.numeric(record$retained_receipt_bytes),
              as.numeric(.DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES))
  if (!isTRUE(valid)) {
    stop("The biomedical capsule source compaction receipt is invalid.",
         call. = FALSE)
  }
  record
}

.dsvert_dp_capsule_source_compaction_authorization_seal <- function(
    unsigned, secret) {
  if (!is.list(unsigned) || is.null(names(unsigned)) ||
      anyNA(names(unsigned)) || anyDuplicated(names(unsigned)) ||
      "authorization_mac" %in% names(unsigned)) {
    stop("Invalid biomedical capsule source compaction authorization.",
         call. = FALSE)
  }
  canonical <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(unsigned))
  c(unsigned, list(authorization_mac =
    .dsvert_dp_capsule_source_mac(
      secret, "compaction-authorization", canonical)))
}

.dsvert_dp_capsule_source_compaction_authorization_validate <- function(
    authorization, contract, secret) {
  required <- c(
    "version", "capsule_id", "source_contract_hash",
    "release_instance_id", "release_contract_hash", "final_vector_root",
    "result_set_hash", "final_chunk_commitments_sha256",
    "release_receipts_sha256", "durable_release_receipts_verified",
    "public_release_memoized", "final_chunks_retained",
    "authorization_mac")
  unsigned <- authorization
  if (is.list(unsigned)) unsigned$authorization_mac <- NULL
  expected_mac <- tryCatch(.dsvert_dp_capsule_source_mac(
    secret, "compaction-authorization",
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))), error = function(e) NULL)
  hex_fields <- c(
    "capsule_id", "source_contract_hash", "release_instance_id",
    "release_contract_hash", "final_vector_root", "result_set_hash",
    "final_chunk_commitments_sha256", "release_receipts_sha256")
  valid <- is.list(authorization) && !is.null(names(authorization)) &&
    !anyNA(names(authorization)) && !anyDuplicated(names(authorization)) &&
    setequal(names(authorization), required) &&
    identical(authorization$version,
              .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_AUTH_VERSION) &&
    all(vapply(authorization[hex_fields], function(value) {
      is.character(value) && length(value) == 1L && !is.na(value) &&
        grepl("^[0-9a-f]{64}$", value)
    }, logical(1L))) &&
    identical(authorization$capsule_id, contract$capsule_id) &&
    identical(authorization$source_contract_hash,
              .dsvert_joint_dp_hash(contract)) &&
    identical(authorization$durable_release_receipts_verified, TRUE) &&
    identical(authorization$public_release_memoized, TRUE) &&
    identical(authorization$final_chunks_retained, TRUE) &&
    is.character(authorization$authorization_mac) &&
    length(authorization$authorization_mac) == 1L &&
    !is.na(authorization$authorization_mac) &&
    grepl("^[0-9a-f]{64}$", authorization$authorization_mac) &&
    is.character(expected_mac) &&
    .dsvert_joint_dp_dsi_hex_equal(
      authorization$authorization_mac, expected_mac)
  if (!isTRUE(valid)) {
    stop(paste(
      "Biomedical capsule source compaction requires an authenticated",
      "durable public-release authorization."), call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(authorization)
}

.dsvert_dp_capsule_source_require_not_compacted <- function(
    connection, capsule_id, secret) {
  compacted <- .dsvert_dp_capsule_source_compaction_load(
    connection, capsule_id, secret)
  if (!is.null(compacted)) {
    stop(paste(
      "The biomedical capsule source was durably finalized and compacted;",
      "private source state cannot be recreated."), call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_capsule_source_compact_pages <- function(
    connection, maximum_pages = 256L) {
  maximum_pages <- .dsvert_dp_capsule_source_index(
    maximum_pages, "incremental-vacuum page limit", 0, 4096)
  # PASSIVE never waits for readers. Incremental vacuum is enabled only for
  # stores created with the v2 schema and releases a bounded number of free
  # pages; a full VACUUM (which may need a second database-sized file) is
  # deliberately never run from a request path.
  try(DBI::dbGetQuery(connection, "PRAGMA wal_checkpoint(PASSIVE)"),
      silent = TRUE)
  mode <- tryCatch(
    DBI::dbGetQuery(connection, "PRAGMA auto_vacuum")[[1L]][[1L]],
    error = function(e) 0L)
  free <- tryCatch(
    DBI::dbGetQuery(connection, "PRAGMA freelist_count")[[1L]][[1L]],
    error = function(e) 0L)
  pages <- min(as.numeric(maximum_pages), as.numeric(free))
  if (identical(as.numeric(mode), 2) && is.finite(pages) && pages > 0) {
    DBI::dbExecute(
      connection, paste0("PRAGMA incremental_vacuum(", as.integer(pages), ")"))
  }
  invisible(list(
    incremental = identical(as.numeric(mode), 2),
    requested_pages = as.integer(max(0, pages))))
}

.dsvert_dp_capsule_source_transaction <- function(connection, code) {
  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  committed <- FALSE
  on.exit(if (!committed) try(DBI::dbRollback(connection), silent = TRUE),
          add = TRUE)
  value <- force(code)
  DBI::dbCommit(connection)
  committed <- TRUE
  value
}

.dsvert_dp_capsule_source_store_state <- function(connection, secret) {
  row <- DBI::dbGetQuery(
    connection,
    "SELECT record_json, row_mac FROM source_store_state WHERE singleton = 1")
  if (!nrow(row)) {
    record <- list(
      version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
      reserved_bytes = 0)
    .dsvert_dp_capsule_source_record_insert(
      connection, "source_store_state", "singleton", list(1L),
      record, secret)
    return(record)
  }
  record <- .dsvert_dp_capsule_source_record_decode(
    row, secret, "source_store_state", "capacity state")
  if (!identical(record$version,
                 .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION)) {
    stop("The biomedical capsule source capacity state is invalid.",
         call. = FALSE)
  }
  .dsvert_dp_capsule_source_index(
    record$reserved_bytes, "reserved-byte state", 0, 2^53 - 1)
  record
}

.dsvert_dp_capsule_source_reserve <- function(
    connection, secret, additional_bytes, resource_owner) {
  additional_bytes <- .dsvert_dp_capsule_source_index(
    additional_bytes, "byte reservation", 0, 2^53 - 1)
  state <- .dsvert_dp_capsule_source_store_state(connection, secret)
  if (!is.character(resource_owner) || length(resource_owner) != 1L ||
      is.na(resource_owner) ||
      !grepl("^external-[0-9a-f]{64}$", resource_owner)) {
    stop("Invalid biomedical capsule source resource owner.",
         call. = FALSE)
  }
  local_capacity <- .dsvert_dp_capsule_source_spool_max_bytes()
  .dsvert_resource_external_reconcile(
    resource_owner, as.numeric(state$reserved_bytes), "capsule-source")
  if (additional_bytes > local_capacity) {
    .dsvert_resource_oversize(
      additional_bytes, local_capacity,
      "biomedical capsule source durable reservation")
  }
  next_bytes <- as.numeric(state$reserved_bytes) + additional_bytes
  if (!is.finite(next_bytes)) {
    stop("Invalid biomedical capsule source capacity state.",
         call. = FALSE)
  }
  if (as.numeric(state$reserved_bytes) >
      local_capacity - additional_bytes) {
    .dsvert_resource_backpressure(
      as.numeric(state$reserved_bytes), additional_bytes, local_capacity,
      "biomedical capsule source durable store")
  }
  .dsvert_resource_admit_external(
    resource_owner, as.numeric(state$reserved_bytes), additional_bytes,
    "capsule-source")
  state$reserved_bytes <- next_bytes
  .dsvert_dp_capsule_source_record_update(
    connection, "source_store_state", state, secret,
    "singleton = 1", list())
  # Publish the conservative head before the surrounding COMMIT. If COMMIT is
  # interrupted the process can temporarily over-reserve (safe); the next
  # authenticated store open reconciles the rolled-back row. Publishing only
  # after COMMIT would create an unsafe under-count window in this process.
  .dsvert_resource_external_reconcile(
    resource_owner, next_bytes, "capsule-source")
  invisible(state)
}

.dsvert_dp_capsule_source_store_initialize <- function(
    connection, policy, secret) {
  statements <- c(
    paste(
      "CREATE TABLE IF NOT EXISTS source_meta (",
      "key TEXT PRIMARY KEY, value TEXT NOT NULL, row_mac TEXT NOT NULL)"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_store_state (",
      "singleton INTEGER PRIMARY KEY CHECK(singleton = 1),",
      "record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_recipient_keys (",
      "capsule_id TEXT PRIMARY KEY, record_json TEXT NOT NULL,",
      "row_mac TEXT NOT NULL)"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_outbound (",
      "transfer_id TEXT PRIMARY KEY, capsule_id TEXT NOT NULL UNIQUE,",
      "status TEXT NOT NULL, record_json TEXT NOT NULL,",
      "row_mac TEXT NOT NULL)"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_outbound_chunks (",
      "transfer_id TEXT NOT NULL, recipient_name TEXT NOT NULL,",
      "chunk_index INTEGER NOT NULL, record_json TEXT NOT NULL,",
      "row_mac TEXT NOT NULL,",
      "PRIMARY KEY(transfer_id, recipient_name, chunk_index))"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_incoming_state (",
      "capsule_id TEXT PRIMARY KEY, record_json TEXT NOT NULL,",
      "row_mac TEXT NOT NULL)"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_aggregate_chunks (",
      "capsule_id TEXT NOT NULL, chunk_index INTEGER NOT NULL,",
      "record_json TEXT NOT NULL, row_mac TEXT NOT NULL,",
      "PRIMARY KEY(capsule_id, chunk_index))"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_cross_gaussian_results (",
      "capsule_id TEXT NOT NULL, analysis_id TEXT NOT NULL,",
      "record_json TEXT NOT NULL, row_mac TEXT NOT NULL,",
      "PRIMARY KEY(capsule_id, analysis_id))"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_cross_categorical_results (",
      "capsule_id TEXT NOT NULL, analysis_id TEXT NOT NULL,",
      "record_json TEXT NOT NULL, row_mac TEXT NOT NULL,",
      "PRIMARY KEY(capsule_id, analysis_id))"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_incoming_receipts (",
      "transfer_id TEXT NOT NULL, chunk_index INTEGER NOT NULL,",
      "envelope_hash TEXT NOT NULL, record_json TEXT NOT NULL,",
      "row_mac TEXT NOT NULL,",
      "PRIMARY KEY(transfer_id, chunk_index))"),
    paste(
      "CREATE TABLE IF NOT EXISTS source_compaction_receipts (",
      "capsule_id TEXT PRIMARY KEY, release_instance_id TEXT NOT NULL,",
      "record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"))
  for (statement in statements) DBI::dbExecute(connection, statement)

  # A durable tombstone is also an enforcement boundary: delayed or duplicated
  # requests cannot repopulate private source state after final publication.
  guarded_tables <- c(
    "source_recipient_keys", "source_outbound", "source_incoming_state",
    "source_aggregate_chunks", "source_cross_gaussian_results",
    "source_cross_categorical_results")
  for (table in guarded_tables) {
    trigger <- paste0("source_no_reopen_", table)
    DBI::dbExecute(connection, paste0(
      "CREATE TRIGGER IF NOT EXISTS ", trigger, " BEFORE INSERT ON ", table,
      " WHEN EXISTS(SELECT 1 FROM source_compaction_receipts ",
      "WHERE capsule_id = NEW.capsule_id) BEGIN SELECT RAISE(ABORT, ",
      "'biomedical capsule source already finalized'); END"))
  }

  binding <- .dsvert_dp_canonical_json(list(
    version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
    domain = policy$domain, cohort_id = policy$cohort_id,
    peer_name = policy$peer_name,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    privacy_epoch_scope = "release_instance_receipts_only_v1"))
  expected_mac <- .dsvert_dp_capsule_source_mac(
    secret, "metadata/policy-binding", binding)
  row <- DBI::dbGetQuery(
    connection,
    "SELECT value, row_mac FROM source_meta WHERE key = 'policy_binding'")
  if (!nrow(row)) {
    DBI::dbExecute(
      connection,
      "INSERT INTO source_meta(key, value, row_mac) VALUES('policy_binding', ?, ?)",
      params = list(binding, expected_mac))
  } else if (nrow(row) != 1L || !identical(row$value[[1L]], binding) ||
             !.dsvert_joint_dp_dsi_hex_equal(
               row$row_mac[[1L]], expected_mac)) {
    stop("The biomedical capsule source store belongs to a different policy or failed authentication.",
         call. = FALSE)
  }
  invisible(.dsvert_dp_capsule_source_store_state(connection, secret))
}

.dsvert_dp_capsule_source_recipient_reservations_migrate <- function(
    connection, policy, secret) {
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT capsule_id, record_json, row_mac FROM source_recipient_keys",
    "ORDER BY capsule_id"))
  if (!nrow(rows)) {
    return(invisible(
      .dsvert_dp_capsule_source_store_state(connection, secret)))
  }
  records <- lapply(seq_len(nrow(rows)), function(index) {
    record <- .dsvert_dp_capsule_source_record_decode(
      rows[index, , drop = FALSE], secret, "source_recipient_keys",
      "recipient-key reservation migration record")
    if (!identical(record$capsule_id, rows$capsule_id[[index]])) {
      stop("The biomedical capsule recipient-key migration identity is invalid.",
           call. = FALSE)
    }
    record
  })
  missing <- vapply(records, function(record) {
    !"reserved_bytes" %in% names(record)
  }, logical(1L))
  reservations <- numeric(length(records))
  for (index in which(!missing)) {
    reservations[[index]] <-
      .dsvert_dp_capsule_source_recipient_reservation_validate(
        records[[index]])
  }
  state <- .dsvert_dp_capsule_source_store_state(connection, secret)
  if (as.numeric(state$reserved_bytes) < sum(reservations)) {
    stop("The biomedical capsule source store under-counts recipient-key bytes.",
         call. = FALSE)
  }
  if (!any(missing)) {
    return(invisible(state))
  }

  owner <- .dsvert_dp_capsule_source_resource_owner(policy)
  state <- .dsvert_dp_capsule_source_transaction(connection, {
    capacity_state <- NULL
    for (index in which(missing)) {
      record <- records[[index]]
      record$reserved_bytes <-
        .dsvert_dp_capsule_source_recipient_reservation(record)
      reservations[[index]] <- as.numeric(record$reserved_bytes)
      capacity_state <- .dsvert_dp_capsule_source_reserve(
        connection, secret, record$reserved_bytes, owner)
      .dsvert_dp_capsule_source_record_update(
        connection, "source_recipient_keys", record, secret,
        "capsule_id = ?", list(rows$capsule_id[[index]]))
    }
    if (as.numeric(capacity_state$reserved_bytes) < sum(reservations)) {
      stop("The biomedical capsule source store under-counts recipient-key bytes.",
           call. = FALSE)
    }
    capacity_state
  })
  invisible(state)
}

.dsvert_dp_capsule_source_with_store <- function(policy, secret, code) {
  if (!is.function(code)) {
    stop("Invalid biomedical capsule source store callback.", call. = FALSE)
  }
  path <- .dsvert_dp_capsule_source_store_path(policy)
  require_private <- isTRUE(policy$ledger_private)
  paths <- c(
    store = path, lock = paste0(path, ".lock"),
    wal = paste0(path, "-wal"), shm = paste0(path, "-shm"))
  for (name in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[name]], paste0("biomedical capsule source store ", name),
      require_private)
  }
  previous_umask <- Sys.umask("0077")
  on.exit(Sys.umask(previous_umask), add = TRUE)
  lock <- filelock::lock(paths[["lock"]],
                         timeout = policy$lock_timeout_ms %||% 30000)
  if (is.null(lock)) {
    stop("The biomedical capsule source store is busy.", call. = FALSE)
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  for (name in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[name]], paste0("biomedical capsule source store ", name),
      require_private)
  }
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  # This must precede journal creation and the first schema statement. It is a
  # no-op for historical stores, which remain logically reclaimable but are
  # never subjected to an unbounded full VACUUM on a request path.
  DBI::dbExecute(connection, "PRAGMA auto_vacuum=INCREMENTAL")
  DBI::dbExecute(connection, "PRAGMA busy_timeout=30000")
  DBI::dbExecute(connection, "PRAGMA journal_mode=WAL")
  DBI::dbExecute(connection, "PRAGMA synchronous=FULL")
  capacity_state <- .dsvert_dp_capsule_source_store_initialize(
    connection, policy, secret)
  capacity_state <- .dsvert_dp_capsule_source_recipient_reservations_migrate(
    connection, policy, secret)
  .dsvert_dp_capsule_source_resource_reconcile(policy, capacity_state)
  .dsvert_dp_chmod_private_files(paths)
  for (name in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[name]], paste0("biomedical capsule source store ", name),
      require_private)
  }
  code(connection)
}

.dsvert_dp_capsule_source_signature_message <- function(domain, unsigned) {
  # Ciphertext authenticity is bound through its signed SHA-256 digest and
  # byte length.  Excluding the (potentially large) Base64 body keeps signing
  # and verification O(metadata) while a separately verified digest still
  # rejects any ciphertext mutation.
  signed_value <- unsigned
  if (identical(domain, "encrypted-chunk") && is.list(signed_value)) {
    signed_value$ciphertext <- NULL
  }
  charToRaw(paste0(
    "dsVert/biomedical-capsule/source-transport/v1/", domain, "|",
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(signed_value))))
}

.dsvert_dp_capsule_source_sign <- function(
    unsigned, policy, domain, signer = NULL) {
  message <- .dsvert_dp_capsule_source_signature_message(domain, unsigned)
  pin <- unname(policy$peer_pinset[[policy$peer_name]])
  if (is.null(signer)) {
    identity <- .get_identity_keypair()
    if (!identical(.dsvert_relay_normalize_identity_pk(identity$identity_pk),
                   .dsvert_relay_normalize_identity_pk(pin))) {
      stop("Runtime identity does not match the biomedical capsule source pin.",
           call. = FALSE)
    }
    signature <- .dsvert_relay_sign_message(message, identity$identity_sk)
  } else {
    if (!is.function(signer)) {
      stop("Invalid biomedical capsule source signer.", call. = FALSE)
    }
    signature <- signer(message, policy$peer_name, pin)
  }
  if (!is.character(signature) || length(signature) != 1L ||
      is.na(signature) || !grepl("^[A-Za-z0-9_-]{86}$", signature)) {
    stop("Invalid biomedical capsule source signature.", call. = FALSE)
  }
  c(unsigned, list(signature = signature))
}

.dsvert_dp_capsule_source_verify <- function(
    signed, policy, domain, peer_name, verifier = NULL) {
  if (!is.list(signed) || is.null(names(signed)) ||
      anyNA(names(signed)) || anyDuplicated(names(signed)) ||
      !"signature" %in% names(signed) ||
      !peer_name %in% names(policy$peer_pinset)) {
    return(FALSE)
  }
  unsigned <- signed[setdiff(names(signed), "signature")]
  message <- .dsvert_dp_capsule_source_signature_message(domain, unsigned)
  if (is.null(verifier)) verifier <- .dsvert_relay_verify_message
  if (!is.function(verifier)) return(FALSE)
  isTRUE(tryCatch(
    verifier(message, unname(policy$peer_pinset[[peer_name]]),
             signed$signature),
    error = function(e) FALSE))
}

.dsvert_dp_capsule_source_window_capability <- function() {
  list(
    version = .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT,
    maximum_window_chunks =
      as.numeric(.DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_CHUNKS),
    maximum_response_bytes =
      as.numeric(.DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_BYTES),
    maximum_accept_bytes =
      as.numeric(.DSVERT_DP_CAPSULE_SOURCE_MAX_ACCEPT_WINDOW_BYTES),
    byte_bounded_prefix = TRUE,
    scalar_legacy_byte_identical = TRUE,
    operation_or_request_limit = FALSE)
}

.dsvert_dp_capsule_source_legacy_window_capability <- function() {
  list(
    version = .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
    maximum_window_chunks =
      as.numeric(.DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_CHUNKS),
    maximum_response_bytes =
      as.numeric(.DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_WINDOW_BYTES),
    maximum_accept_bytes =
      as.numeric(.DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_ACCEPT_WINDOW_BYTES),
    byte_bounded_prefix = TRUE,
    scalar_legacy_byte_identical = TRUE,
    operation_or_request_limit = FALSE)
}

.dsvert_dp_capsule_source_transport_capability <- function(
    transport_contract) {
  if (identical(
      transport_contract, .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT)) {
    return(.dsvert_dp_capsule_source_window_capability())
  }
  if (identical(
      transport_contract, .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION)) {
    return(.dsvert_dp_capsule_source_legacy_window_capability())
  }
  stop("Unsupported biomedical capsule source window contract.",
       call. = FALSE)
}

.dsvert_dp_capsule_source_ticket_negotiation_wrap <- function(
    ticket_json, policy,
    transport_contract = .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
    signer = NULL) {
  ticket <- .dsvert_dp_capsule_source_decode_json(
    ticket_json, "recipient ticket", 64L * 1024L)
  if (!identical(ticket$version,
                 .DSVERT_DP_CAPSULE_SOURCE_TICKET_VERSION) ||
      !identical(ticket$recipient_name, policy$peer_name)) {
    stop("Invalid capsule source ticket negotiation input.", call. = FALSE)
  }
  unsigned <- list(
    version = .DSVERT_DP_CAPSULE_SOURCE_TICKET_NEGOTIATION_VERSION,
    phase = "recipient_transport_window_attested",
    ticket_json = ticket_json,
    ticket_sha256 = .dsvert_joint_dp_hash(ticket),
    capability = .dsvert_dp_capsule_source_transport_capability(
      transport_contract))
  .dsvert_dp_capsule_source_encode_json(
    .dsvert_dp_capsule_source_sign(
      unsigned, policy, "recipient-window-capability", signer))
}

.dsvert_dp_capsule_source_ticket_negotiation_validate <- function(
    value_json, policy, contract, verifier = NULL) {
  value <- .dsvert_dp_capsule_source_decode_json(
    value_json, "recipient transport negotiation", 64L * 1024L)
  required <- c(
    "version", "phase", "ticket_json", "ticket_sha256", "capability",
    "signature")
  if (!identical(value$version,
                 .DSVERT_DP_CAPSULE_SOURCE_TICKET_NEGOTIATION_VERSION)) {
    return(NULL)
  }
  ticket <- tryCatch(
    .dsvert_dp_capsule_source_ticket_validate(
      value$ticket_json, policy, contract, verifier),
    error = function(error) NULL)
  recipient <- if (is.list(ticket)) ticket$ticket$recipient_name else NULL
  capability <- value$capability
  supported_capability <- identical(
    .dsvert_dp_capsule_source_encode_json(capability),
    .dsvert_dp_capsule_source_encode_json(
      .dsvert_dp_capsule_source_window_capability())) || identical(
    .dsvert_dp_capsule_source_encode_json(capability),
    .dsvert_dp_capsule_source_encode_json(
      .dsvert_dp_capsule_source_legacy_window_capability()))
  valid <- !is.null(names(value)) && !anyNA(names(value)) &&
    !anyDuplicated(names(value)) && setequal(names(value), required) &&
    identical(value$phase, "recipient_transport_window_attested") &&
    is.list(ticket) &&
    identical(value$ticket_sha256, ticket$hash) &&
    isTRUE(supported_capability) &&
    is.character(recipient) && length(recipient) == 1L &&
    .dsvert_dp_capsule_source_verify(
      value, policy, "recipient-window-capability", recipient, verifier)
  if (!isTRUE(valid)) {
    stop("Invalid capsule source ticket negotiation.", call. = FALSE)
  }
  list(
    value = value, json = value_json, hash = .dsvert_joint_dp_hash(value),
    ticket = ticket)
}

.dsvert_dp_capsule_source_capability_attestation <- function(
    manifest_json, policy,
    transport_contract = .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
    signer = NULL) {
  parsed <- .dsvert_dp_capsule_source_contract_json(policy, manifest_json)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  sources <- .dsvert_dp_capsule_source_names(
    contract$source_peers, "source peer list")
  if (!policy$peer_name %in% sources) {
    stop("Only a declared source owner can attest source transport support.",
         call. = FALSE)
  }
  unsigned <- list(
    version = .DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ATTESTATION_VERSION,
    phase = "source_transport_capability_attested",
    capsule_id = contract$capsule_id,
    contract_hash = parsed$contract_hash,
    source_name = policy$peer_name,
    source_identity_pk = unname(
      policy$peer_pinset[[policy$peer_name]]),
    capability = .dsvert_dp_capsule_source_transport_capability(
      transport_contract))
  .dsvert_dp_capsule_source_encode_json(
    .dsvert_dp_capsule_source_sign(
      unsigned, policy, "source-window-capability-advertisement", signer))
}

.dsvert_dp_capsule_source_ticket_validate <- function(
    ticket_json, policy, contract, verifier = NULL) {
  ticket <- .dsvert_dp_capsule_source_decode_json(
    ticket_json, "recipient ticket", 64L * 1024L)
  required <- c(
    "version", "phase", "purpose", "capsule_id", "contract_hash",
    "recipient_name", "recipient_identity_pk", "transport_key_id",
    "transport_pk", "peer_pinset_sha256", "designated_noise_peers",
    "source_peers", "coordinate_count", "chunk_coordinates",
    "chunk_count", "persistent", "ready_for_sampling", "signature")
  recipient <- ticket$recipient_name
  valid <- !is.null(names(ticket)) && !anyNA(names(ticket)) &&
    !anyDuplicated(names(ticket)) && setequal(names(ticket), required) &&
    identical(ticket$version, .DSVERT_DP_CAPSULE_SOURCE_TICKET_VERSION) &&
    identical(ticket$phase, "recipient_key_committed") &&
    identical(ticket$purpose, contract$purpose) &&
    identical(ticket$capsule_id, contract$capsule_id) &&
    identical(ticket$contract_hash, .dsvert_joint_dp_hash(contract)) &&
    is.character(recipient) && length(recipient) == 1L &&
    recipient %in% .dsvert_dp_capsule_source_names(
      contract$designated_noise_peers, "noise-peer list") &&
    identical(ticket$recipient_identity_pk,
              unname(policy$peer_pinset[[recipient]])) &&
    identical(ticket$peer_pinset_sha256, contract$peer_pinset_sha256) &&
    identical(ticket$designated_noise_peers,
              contract$designated_noise_peers) &&
    identical(ticket$source_peers, contract$source_peers) &&
    identical(as.numeric(ticket$coordinate_count),
              as.numeric(contract$coordinate_count)) &&
    identical(as.numeric(ticket$chunk_coordinates),
              as.numeric(contract$chunk_coordinates)) &&
    identical(as.numeric(ticket$chunk_count),
              as.numeric(contract$chunk_count)) &&
    identical(ticket$persistent, TRUE) &&
    identical(ticket$ready_for_sampling, FALSE) &&
    grepl("^[0-9a-f]{64}$", ticket$transport_key_id) &&
    identical(ticket$transport_key_id, .dsvert_joint_dp_hash(list(
      protocol = "dsvert-biomedical-capsule-source-key-id-v1",
      capsule_id = contract$capsule_id, recipient_name = recipient,
      transport_pk = ticket$transport_pk)))
  normalized_transport <- tryCatch(
    .dsvert_normalize_crypto_b64(
      ticket$transport_pk, 32L, "capsule source transport key"),
    error = function(e) NULL)
  if (!isTRUE(valid) || is.null(normalized_transport) ||
      !.dsvert_dp_capsule_source_verify(
        ticket, policy, "recipient-ticket", recipient, verifier)) {
    stop("The biomedical capsule source recipient ticket is invalid.",
         call. = FALSE)
  }
  list(
    ticket = ticket, json = ticket_json,
    hash = .dsvert_joint_dp_hash(ticket),
    transport_pk = normalized_transport)
}

.dsvert_dp_capsule_source_ticket_impl <- function(
    manifest_json, .policy = NULL, .secret = NULL, .keygen = NULL,
    .signer = NULL, .verifier = NULL,
    .allocation_require =
      .dsvert_joint_dp_vector_allocation_require,
    source_contract = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  parsed <- .dsvert_dp_capsule_source_contract_json(
    .policy, manifest_json, source_contract)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  recipient <- .policy$peer_name
  if (!recipient %in% .dsvert_dp_capsule_source_names(
        contract$designated_noise_peers, "noise-peer list")) {
    stop("Only a designated pinned noise peer can mint a capsule source ticket.",
         call. = FALSE)
  }
  if (!is.function(.allocation_require)) {
    stop("Invalid biomedical capsule allocation gate.", call. = FALSE)
  }
  .allocation_require(
    policy = .policy, manifest_json = manifest_json,
    secret = .secret, verifier = .verifier)
  .dsvert_dp_capsule_source_with_store(.policy, .secret, function(connection) {
    .dsvert_dp_capsule_source_require_not_compacted(
      connection, contract$capsule_id, .secret)
    row <- DBI::dbGetQuery(
      connection,
      "SELECT record_json, row_mac FROM source_recipient_keys WHERE capsule_id = ?",
      params = list(contract$capsule_id))
    if (nrow(row)) {
      record <- .dsvert_dp_capsule_source_record_decode(
        row, .secret, "source_recipient_keys", "recipient-key record")
      .dsvert_dp_capsule_source_recipient_reservation_validate(record)
      if (!identical(record$contract_hash, parsed$contract_hash) ||
          !identical(record$recipient_name, recipient)) {
        stop("The persisted capsule source key conflicts with this contract.",
             call. = FALSE)
      }
      return(record$ticket_json)
    }
    keypair <- if (is.null(.keygen)) {
      .callMpcTool("transport-keygen", list())
    } else {
      if (!is.function(.keygen)) {
        stop("Invalid capsule source key generator.", call. = FALSE)
      }
      .keygen()
    }
    public <- .dsvert_normalize_crypto_b64(
      keypair$public_key, 32L, "capsule source transport public key")
    private <- .dsvert_normalize_crypto_b64(
      keypair$secret_key, 32L, "capsule source transport secret key")
    public_url <- base64_to_base64url(public)
    unsigned <- list(
      version = .DSVERT_DP_CAPSULE_SOURCE_TICKET_VERSION,
      phase = "recipient_key_committed",
      purpose = contract$purpose,
      capsule_id = contract$capsule_id,
      contract_hash = parsed$contract_hash,
      recipient_name = recipient,
      recipient_identity_pk = unname(.policy$peer_pinset[[recipient]]),
      transport_key_id = .dsvert_joint_dp_hash(list(
        protocol = "dsvert-biomedical-capsule-source-key-id-v1",
        capsule_id = contract$capsule_id, recipient_name = recipient,
        transport_pk = public_url)),
      transport_pk = public_url,
      peer_pinset_sha256 = contract$peer_pinset_sha256,
      designated_noise_peers = contract$designated_noise_peers,
      source_peers = contract$source_peers,
      coordinate_count = contract$coordinate_count,
      chunk_coordinates = contract$chunk_coordinates,
      chunk_count = contract$chunk_count,
      persistent = TRUE, ready_for_sampling = FALSE)
    ticket <- .dsvert_dp_capsule_source_sign(
      unsigned, .policy, "recipient-ticket", .signer)
    ticket_json <- .dsvert_dp_capsule_source_encode_json(ticket)
    record <- list(
      version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
      capsule_id = contract$capsule_id,
      contract_hash = parsed$contract_hash,
      contract_json = parsed$contract_json,
      recipient_name = recipient,
      transport_pk = public,
      transport_sk = private,
      ticket_json = ticket_json)
    record$reserved_bytes <-
      .dsvert_dp_capsule_source_recipient_reservation(record)
    resource_owner <- .dsvert_dp_capsule_source_resource_owner(.policy)
    capacity_state <- NULL
    .dsvert_dp_capsule_source_transaction(connection, {
      capacity_state <- .dsvert_dp_capsule_source_reserve(
        connection, .secret, record$reserved_bytes, resource_owner)
      .dsvert_dp_capsule_source_record_insert(
        connection, "source_recipient_keys", "capsule_id",
        list(contract$capsule_id), record, .secret)
    })
    .dsvert_dp_capsule_source_resource_reconcile(.policy, capacity_state)
    ticket_json
  })
}

.dsvert_dp_capsule_source_split_ring128 <- function(
    values, random_bytes = .dsvert_secure_random_bytes) {
  values <- .dsvert_dp_integer_vector(values, "capsule source coordinates")
  if (!length(values) || !is.function(random_bytes)) {
    stop("Invalid Ring128 capsule source split input.", call. = FALSE)
  }
  left <- random_bytes(.DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES * length(values))
  if (!is.raw(left) ||
      length(left) != .DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES * length(values)) {
    stop("The capsule source CSPRNG returned an invalid byte string.",
         call. = FALSE)
  }
  bytes <- matrix(
    as.integer(left), nrow = .DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES)
  right <- matrix(0L, nrow = .DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES,
                  ncol = length(values))
  remaining <- as.numeric(values)
  borrow <- numeric(length(values))
  for (limb in seq_len(8L)) {
    low <- 2L * limb - 1L
    high <- low + 1L
    left_limb <- bytes[low, ] + 256 * bytes[high, ]
    value_limb <- remaining %% 65536
    remaining <- floor(remaining / 65536)
    difference <- value_limb - left_limb - borrow
    borrow <- as.numeric(difference < 0)
    residue <- difference + borrow * 65536
    right[low, ] <- as.integer(residue %% 256)
    right[high, ] <- as.integer(floor(residue / 256))
  }
  list(left = left, right = as.raw(as.vector(right)))
}

.dsvert_dp_capsule_source_add_ring128 <- function(left, right) {
  if (!is.raw(left) || !is.raw(right) || !length(left) ||
      !identical(length(left), length(right)) || length(left) %% 16L != 0L) {
    stop("Invalid Ring128 capsule source aggregate chunks.", call. = FALSE)
  }
  n <- length(left) / 16L
  a <- matrix(as.integer(left), nrow = 16L)
  b <- matrix(as.integer(right), nrow = 16L)
  result <- matrix(0L, nrow = 16L, ncol = n)
  carry <- numeric(n)
  for (limb in seq_len(8L)) {
    low <- 2L * limb - 1L
    high <- low + 1L
    total <- a[low, ] + 256 * a[high, ] +
      b[low, ] + 256 * b[high, ] + carry
    residue <- total %% 65536
    carry <- floor(total / 65536)
    result[low, ] <- as.integer(residue %% 256)
    result[high, ] <- as.integer(floor(residue / 256))
  }
  as.raw(as.vector(result))
}

.dsvert_dp_capsule_source_raw_b64 <- function(value) {
  .dsvert_relay_b64url_encode(value)
}

.dsvert_dp_capsule_source_b64_raw <- function(value, what, maximum) {
  value <- .dsvert_dp_capsule_source_scalar(
    value, what, pattern = "^[A-Za-z0-9_-]+$",
    maximum_bytes = 4 * ceiling(maximum / 3) + 4L)
  decoded <- tryCatch(
    .dsvert_relay_b64url_decode(value, what), error = function(e) NULL)
  if (!is.raw(decoded) || length(decoded) > maximum) {
    stop("Invalid biomedical capsule source ", what, ".", call. = FALSE)
  }
  decoded
}

.dsvert_dp_capsule_source_uint32 <- function(value) {
  value <- .dsvert_dp_capsule_source_index(value, "header length", 0, 2^32 - 1)
  as.raw(c(
    floor(value / 2^24) %% 256,
    floor(value / 2^16) %% 256,
    floor(value / 2^8) %% 256,
    value %% 256))
}

.dsvert_dp_capsule_source_pack <- function(header, share) {
  header_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(header))
  header_raw <- charToRaw(header_json)
  if (length(header_raw) > 65535L || !is.raw(share)) {
    stop("Invalid biomedical capsule source plaintext chunk.",
         call. = FALSE)
  }
  c(.dsvert_dp_capsule_source_uint32(length(header_raw)), header_raw, share)
}

.dsvert_dp_capsule_source_unpack <- function(value, expected_share_bytes) {
  if (!is.raw(value) || length(value) < 5L) {
    stop("Invalid biomedical capsule source decrypted chunk.",
         call. = FALSE)
  }
  header_length <- sum(as.numeric(value[1:4]) * c(2^24, 2^16, 2^8, 1))
  header_length <- .dsvert_dp_capsule_source_index(
    header_length, "plaintext header length", 1, 65535)
  if (length(value) != 4 + header_length + expected_share_bytes) {
    stop("The biomedical capsule source decrypted chunk has the wrong shape.",
         call. = FALSE)
  }
  header_json <- rawToChar(value[seq.int(5L, 4L + header_length)])
  header <- .dsvert_dp_capsule_source_decode_json(
    header_json, "decrypted header", 65535L)
  share <- value[seq.int(5L + header_length, length(value))]
  list(header = header, share = share)
}

.dsvert_dp_capsule_source_encrypt <- function(
    plaintext, recipient_pk, encryptor = NULL) {
  if (is.null(encryptor)) {
    result <- .callMpcTool("transport-encrypt", list(
      data = gsub("[\r\n]", "", jsonlite::base64_enc(plaintext)),
      recipient_pk = .base64url_to_base64(recipient_pk)))
    sealed <- result$sealed
  } else {
    if (!is.function(encryptor)) {
      stop("Invalid biomedical capsule source encryptor.", call. = FALSE)
    }
    sealed <- encryptor(plaintext, recipient_pk)
  }
  standard <- .dsvert_dp_capsule_source_scalar(
    sealed, "ciphertext", maximum_bytes =
      .DSVERT_DP_CAPSULE_SOURCE_MAX_ENVELOPE_BYTES)
  encoded <- base64_to_base64url(standard)
  raw <- tryCatch(
    .dsvert_relay_b64url_decode(encoded, "capsule source ciphertext"),
    error = function(e) NULL)
  if (!is.raw(raw) || length(raw) < 60L) {
    stop("The biomedical capsule source encryptor returned an invalid ciphertext.",
         call. = FALSE)
  }
  list(raw = raw, encoded = encoded)
}

.dsvert_dp_capsule_source_decrypt <- function(
    ciphertext, recipient_sk, decryptor = NULL) {
  if (is.null(decryptor)) {
    result <- .callMpcTool("transport-decrypt", list(
      sealed = gsub("[\r\n]", "", jsonlite::base64_enc(ciphertext)),
      recipient_sk = recipient_sk))
    plaintext <- tryCatch(.dsvert_relay_b64url_decode(
      base64_to_base64url(result$data),
      "capsule source decrypted payload"), error = function(e) NULL)
  } else {
    if (!is.function(decryptor)) {
      stop("Invalid biomedical capsule source decryptor.", call. = FALSE)
    }
    plaintext <- decryptor(ciphertext, recipient_sk)
  }
  if (!is.raw(plaintext)) {
    stop("The biomedical capsule source ciphertext could not be authenticated.",
         call. = FALSE)
  }
  plaintext
}

.dsvert_dp_capsule_source_transfer_id <- function(contract, source_name) {
  paste0("csrc_", .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-source-transfer-id-v1",
    contract_hash = .dsvert_joint_dp_hash(contract),
    capsule_id = contract$capsule_id, source_name = source_name)))
}

.dsvert_dp_capsule_source_chunk_geometry <- function(contract, chunk_index) {
  chunk_index <- .dsvert_dp_capsule_source_index(
    chunk_index, "chunk index", 0, contract$chunk_count - 1)
  offset <- chunk_index * contract$chunk_coordinates
  count <- min(contract$chunk_coordinates,
               contract$coordinate_count - offset)
  list(index = chunk_index, offset = offset, count = count)
}

.dsvert_dp_capsule_source_outbound_reservation <- function(contract) {
  # Conservative fixed reservation for both ciphertexts, their signatures,
  # SQLite rows and retry metadata.  It depends only on public vector shape.
  as.numeric(64 * contract$coordinate_count +
               128 * 1024 * contract$chunk_count + 64 * 1024)
}

.dsvert_dp_capsule_source_recipient_reservation <- function(record) {
  if (!is.list(record) || is.null(names(record)) || anyNA(names(record)) ||
      anyDuplicated(names(record))) {
    stop("Invalid biomedical capsule recipient-key reservation input.",
         call. = FALSE)
  }
  # Reserve the complete authenticated row at the widest possible decimal
  # representation of its own reservation. Three copies conservatively cover
  # the durable SQLite row, its WAL frame and serialization/retry material;
  # the fixed allowance covers page, index and transaction metadata.
  base <- record[setdiff(names(record), "reserved_bytes")]
  widest <- c(base, list(reserved_bytes = 2^53 - 1))
  payload_bytes <- nchar(
    .dsvert_dp_capsule_source_encode_json(widest), type = "bytes")
  as.numeric(3 * payload_bytes +
               .DSVERT_DP_CAPSULE_SOURCE_RECIPIENT_KEY_OVERHEAD_BYTES)
}

.dsvert_dp_capsule_source_recipient_reservation_validate <- function(record) {
  expected <- .dsvert_dp_capsule_source_recipient_reservation(record)
  observed <- .dsvert_dp_capsule_source_index(
    record$reserved_bytes, "recipient-key byte reservation", 1, 2^53 - 1)
  if (!identical(as.numeric(observed), expected)) {
    stop("The biomedical capsule recipient-key reservation is invalid.",
         call. = FALSE)
  }
  as.numeric(observed)
}

.dsvert_dp_capsule_source_inbound_reservation <- function(contract) {
  source_count <- length(.dsvert_dp_capsule_source_names(
    contract$source_peers, "source peer list"))
  # The aggregate is one Ring128 vector, but authenticated retry receipts are
  # retained for every source/chunk pair until final compaction.
  as.numeric(24 * contract$coordinate_count +
               16 * 1024 * source_count * contract$chunk_count + 32 * 1024)
}

.dsvert_dp_capsule_source_material_private <- function(
    secret, material, contract_hash) {
  required <- c(
    "version", "purpose", "capsule_id", "peer_name", "logical_snapshot",
    "source_context_hash", "coordinate_count", "coordinate_order_sha256",
    "snapshot_binding_sha256", "state", "values",
    "value_commitment_sha256", "authenticatable_sha256")
  has_alignment <- "private_alignment_consensus_hash" %in% names(material)
  expected_names <- c(required, if (has_alignment) {
    "private_alignment_consensus_hash"
  } else {
    character()
  })
  if (!is.list(material) || is.null(names(material)) ||
      anyNA(names(material)) || anyDuplicated(names(material)) ||
      !setequal(names(material), expected_names) ||
      !identical(material$version,
                 .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION) ||
      !identical(material$purpose,
                 .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE) ||
      !identical(material$state,
                 "internal_unshared_secret_share_input_never_release") ||
      !grepl("^[0-9a-f]{64}$", material$snapshot_binding_sha256) ||
      !grepl("^[0-9a-f]{64}$", material$value_commitment_sha256)) {
    stop("The biomedical capsule source material is invalid.",
         call. = FALSE)
  }
  values <- .dsvert_dp_integer_vector(
    material$values, "capsule source coordinates")
  alignment <- if (has_alignment) {
    value <- material$private_alignment_consensus_hash
    if (!is.character(value) || length(value) != 1L || is.na(value) ||
        !(identical(value, "not_applicable") ||
          grepl("^[0-9a-f]{64}$", value))) {
      stop("The biomedical capsule source private alignment binding is invalid.",
           call. = FALSE)
    }
    value
  } else {
    "not_applicable"
  }
  snapshot_mac <- .dsvert_dp_capsule_source_mac(
    secret, "private-snapshot-binding", .dsvert_dp_canonical_json(list(
      contract_hash = contract_hash,
      peer_name = material$peer_name,
      snapshot_binding_sha256 = material$snapshot_binding_sha256)))
  value_mac <- .dsvert_dp_capsule_source_mac(
    secret, "private-value-commitment", .dsvert_dp_canonical_json(list(
      contract_hash = contract_hash,
      peer_name = material$peer_name,
      value_commitment_sha256 = material$value_commitment_sha256,
      authenticatable_sha256 = material$authenticatable_sha256)))
  list(
    values = values, snapshot_mac = snapshot_mac, value_mac = value_mac,
    alignment_consensus_hash = alignment)
}

.dsvert_dp_capsule_source_producer_private <- function(
    secret, producer, contract_hash, require_commitment = TRUE) {
  required <- c(
    "version", "purpose", "capsule_id", "peer_name", "logical_snapshot",
    "source_context_hash", "coordinate_count", "coordinate_order_sha256",
    "snapshot_binding_sha256", "producer_version", "state",
    "value_commitment_sha256", "authenticatable_sha256",
    "private_alignment_consensus_hash", "read_range", "generation_chunks",
    "reset")
  valid <- inherits(producer, "dsvert_capsule_source_producer") &&
    is.list(producer) && !is.null(names(producer)) &&
    !anyNA(names(producer)) && !anyDuplicated(names(producer)) &&
    setequal(names(producer), required) &&
    identical(producer$version,
              .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION) &&
    identical(producer$purpose,
              .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE) &&
    identical(
      producer$producer_version,
      .DSVERT_DP_GAUSSIAN_CROSS_SOURCE_PRODUCER_VERSION) &&
    identical(
      producer$state,
      "internal_incremental_secret_share_input_never_release") &&
    is.character(producer$snapshot_binding_sha256) &&
    length(producer$snapshot_binding_sha256) == 1L &&
    grepl("^[0-9a-f]{64}$", producer$snapshot_binding_sha256) &&
    is.function(producer$read_range) &&
    is.function(producer$generation_chunks) && is.function(producer$reset)
  if (!isTRUE(valid)) {
    stop("The biomedical capsule incremental source producer is invalid.",
         call. = FALSE)
  }
  commitment_valid <- if (isTRUE(require_commitment)) {
    is.character(producer$value_commitment_sha256) &&
      length(producer$value_commitment_sha256) == 1L &&
      grepl("^[0-9a-f]{64}$", producer$value_commitment_sha256) &&
      is.character(producer$authenticatable_sha256) &&
      length(producer$authenticatable_sha256) == 1L &&
      grepl("^[0-9a-f]{64}$", producer$authenticatable_sha256)
  } else {
    (is.null(producer$value_commitment_sha256) &&
       is.null(producer$authenticatable_sha256)) ||
      (is.character(producer$value_commitment_sha256) &&
         length(producer$value_commitment_sha256) == 1L &&
         grepl("^[0-9a-f]{64}$", producer$value_commitment_sha256) &&
         is.character(producer$authenticatable_sha256) &&
         length(producer$authenticatable_sha256) == 1L &&
         grepl("^[0-9a-f]{64}$", producer$authenticatable_sha256))
  }
  alignment <- producer$private_alignment_consensus_hash
  alignment_valid <- is.character(alignment) && length(alignment) == 1L &&
    !is.na(alignment) && (identical(alignment, "not_applicable") ||
      grepl("^[0-9a-f]{64}$", alignment))
  if (!isTRUE(commitment_valid) || !isTRUE(alignment_valid)) {
    stop("The biomedical capsule incremental source binding is invalid.",
         call. = FALSE)
  }
  snapshot_mac <- .dsvert_dp_capsule_source_mac(
    secret, "private-snapshot-binding", .dsvert_dp_canonical_json(list(
      contract_hash = contract_hash, peer_name = producer$peer_name,
      snapshot_binding_sha256 = producer$snapshot_binding_sha256)))
  value_mac <- if (isTRUE(require_commitment)) {
    .dsvert_dp_capsule_source_mac(
      secret, "private-value-commitment", .dsvert_dp_canonical_json(list(
        contract_hash = contract_hash, peer_name = producer$peer_name,
        value_commitment_sha256 = producer$value_commitment_sha256,
        authenticatable_sha256 = producer$authenticatable_sha256)))
  } else {
    NULL
  }
  list(
    read_range = producer$read_range,
    generation_chunks = producer$generation_chunks,
    reset = producer$reset,
    snapshot_mac = snapshot_mac, value_mac = value_mac,
    alignment_consensus_hash = alignment)
}

.dsvert_dp_capsule_source_snapshot_changed <- function() {
  stop(structure(list(
    message = paste(
      "The protected capsule source snapshot changed before an",
      "unmaterialized chunk could be committed."),
    call = NULL, reason = "capsule_source_snapshot_changed"),
    class = c("dsvert_capsule_source_snapshot_changed", "error",
              "condition")))
}

.dsvert_dp_capsule_source_snapshot_error <- function(error) {
  message <- conditionMessage(error)
  changed <- inherits(error, c(
    "dsvert_non_prealigned_cohort",
    "dsvert_non_prealigned_categorical_cohort")) ||
    grepl(
      paste(
        "immutable protected DP snapshot binding changed",
        "resolved biomedical capsule snapshot digest changed",
        "resolved biomedical capsule alignment binding changed",
        sep = "|"),
      message, ignore.case = TRUE)
  if (isTRUE(changed)) .dsvert_dp_capsule_source_snapshot_changed()
  stop(error)
}

.dsvert_dp_capsule_source_outbound_load <- function(
    connection, transfer_id, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT status, record_json, row_mac FROM source_outbound",
    "WHERE transfer_id = ?"), params = list(transfer_id))
  if (!nrow(row)) return(NULL)
  record <- .dsvert_dp_capsule_source_record_decode(
    row, secret, "source_outbound", "outbound record")
  if (!identical(record$transfer_id, transfer_id) ||
      !identical(record$status, row$status[[1L]]) ||
      !record$status %in% c("building", "ready", "complete")) {
    stop("The biomedical capsule source outbound record is invalid.",
         call. = FALSE)
  }
  record
}

.dsvert_dp_capsule_source_envelope <- function(
    policy, contract, transfer_id, ticket, ticket_hash, chunk, plaintext,
    encryptor, signer) {
  encrypted <- .dsvert_dp_capsule_source_encrypt(
    plaintext, ticket$transport_pk, encryptor)
  unsigned <- list(
    version = .DSVERT_DP_CAPSULE_SOURCE_CHUNK_VERSION,
    phase = "encrypted_source_chunk_committed",
    purpose = contract$purpose,
    capsule_id = contract$capsule_id,
    contract_hash = .dsvert_joint_dp_hash(contract),
    source_transfer_id = transfer_id,
    source_name = policy$peer_name,
    source_identity_pk = unname(policy$peer_pinset[[policy$peer_name]]),
    recipient_name = ticket$recipient_name,
    recipient_identity_pk = ticket$recipient_identity_pk,
    recipient_ticket_hash = ticket_hash,
    chunk_index = as.integer(chunk$index),
    chunk_count = contract$chunk_count,
    coordinate_offset = as.integer(chunk$offset),
    coordinates_in_chunk = as.integer(chunk$count),
    chunk_coordinates = contract$chunk_coordinates,
    ring_bits = contract$ring_bits,
    record_encoding = contract$record_encoding,
    ciphertext_bytes = as.numeric(length(encrypted$raw)),
    ciphertext_sha256 = digest::digest(
      encrypted$raw, algo = "sha256", serialize = FALSE),
    ciphertext = encrypted$encoded,
    ready_for_sampling = FALSE)
  .dsvert_dp_capsule_source_sign(
    unsigned, policy, "encrypted-chunk", signer)
}

.dsvert_dp_capsule_source_prepare_impl <- function(
    manifest_json, first_ticket_json, second_ticket_json,
    first_opening_json, second_opening_json,
    .policy = NULL, .secret = NULL, .envir = parent.frame(),
    .resolved_snapshots = NULL, .materializer = NULL,
    .random_bytes = .dsvert_secure_random_bytes, .encryptor = NULL,
    .signer = NULL, .verifier = NULL,
    .allocation_observer =
      .dsvert_joint_dp_vector_allocation_observer_require,
    .producer_validator = NULL, source_contract = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  parsed <- .dsvert_dp_capsule_source_contract_json(
    .policy, manifest_json, source_contract)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  synopsis <- !is.null(contract$synopsis_binding)
  if ((!is.null(.producer_validator) &&
       !is.function(.producer_validator)) ||
      (synopsis && !is.function(.producer_validator))) {
    stop("A synopsis source contract requires a producer validator.",
         call. = FALSE)
  }
  sources <- .dsvert_dp_capsule_source_names(
    contract$source_peers, "source peer list")
  if (!.policy$peer_name %in% sources) {
    stop("The local peer is not a source owner for this capsule.",
         call. = FALSE)
  }
  tickets <- lapply(
    list(first_ticket_json, second_ticket_json),
    .dsvert_dp_capsule_source_ticket_validate,
    policy = .policy, contract = contract, verifier = .verifier)
  recipients <- vapply(tickets, function(value) {
    value$ticket$recipient_name
  }, character(1L))
  expected_recipients <- .dsvert_dp_capsule_source_names(
    contract$designated_noise_peers, "noise-peer list")
  if (anyDuplicated(recipients) || !setequal(recipients, expected_recipients)) {
    stop("Capsule source tickets must cover exactly the two designated noise peers.",
         call. = FALSE)
  }
  tickets <- tickets[order(recipients, method = "radix")]
  names(tickets) <- sort(recipients, method = "radix")
  ticket_set_hash <- .dsvert_joint_dp_hash(lapply(tickets, `[[`, "hash"))
  transfer_id <- .dsvert_dp_capsule_source_transfer_id(
    contract, .policy$peer_name)

  .dsvert_dp_capsule_source_with_store(.policy, .secret, function(connection) {
    .dsvert_dp_capsule_source_require_not_compacted(
      connection, contract$capsule_id, .secret)
    existing <- .dsvert_dp_capsule_source_outbound_load(
      connection, transfer_id, .secret)
    if (!is.null(existing) && existing$status %in% c("ready", "complete")) {
      if (!identical(existing$contract_hash, parsed$contract_hash) ||
          !identical(existing$ticket_set_hash, ticket_set_hash) ||
          (synopsis && !identical(
            existing$contract_json, parsed$contract_json))) {
        stop("The persisted capsule source conflicts with this retry.",
             call. = FALSE)
      }
      if (!synopsis) return(existing$summary_json)
    }

    if (!is.function(.allocation_observer)) {
      stop("Invalid biomedical capsule allocation observer gate.",
           call. = FALSE)
    }
    .allocation_observer(
      policy = .policy, manifest_json = manifest_json,
      first_opening_json = first_opening_json,
      second_opening_json = second_opening_json,
      secret = .secret, verifier = .verifier)

    snapshots <- .resolved_snapshots
    if (is.null(snapshots)) {
      snapshots <- lapply(names(.policy$datasets), function(data_name) {
        .dsvert_dp_resolve_snapshot(.policy, data_name, .envir, .secret)
      })
      names(snapshots) <- names(.policy$datasets)
    }
    if (!is.null(.materializer) && !is.function(.materializer)) {
      stop("Invalid biomedical capsule source materializer.", call. = FALSE)
    }
    producer <- if (is.null(.materializer)) {
      .dsvert_dp_gaussian_cross_source_producer(
        .policy, parsed$manifest, snapshots, compute_commitment = TRUE)
    } else {
      .materializer(
        .policy, parsed$manifest, snapshots,
        compute_commitment = TRUE, include_release = TRUE)
    }
    if (!is.list(producer) || !is.function(producer$reset)) {
      stop("The biomedical capsule source producer cannot be released.",
           call. = FALSE)
    }
    on.exit(try(producer$reset(), silent = TRUE), add = TRUE)
    if (is.function(.producer_validator) && !isTRUE(
        .producer_validator(
          producer = producer, policy = .policy,
          manifest = parsed$manifest, contract = contract))) {
      stop("The synopsis source producer failed validation.",
           call. = FALSE)
    }
    private <- .dsvert_dp_capsule_source_producer_private(
      .secret, producer, parsed$contract_hash,
      require_commitment = TRUE)
    release_count <- if (.dsvert_dp_capsule_source_cross_contract(contract)) {
      as.integer(contract$release_coordinate_count)
    } else {
      as.integer(contract$coordinate_count)
    }
    if (!identical(
          producer$capsule_id,
          .dsvert_dp_capsule_source_manifest_capsule_id(contract)) ||
        !identical(producer$peer_name, .policy$peer_name) ||
        !identical(producer$source_context_hash,
                   contract$source_context_hash) ||
        !identical(as.numeric(producer$coordinate_count),
                   as.numeric(contract$coordinate_count)) ||
        !identical(producer$coordinate_order_sha256,
                   contract$coordinate_order_sha256)) {
      stop("The local capsule source material does not match its transport contract.",
           call. = FALSE)
    }
    if (synopsis && !is.null(existing)) {
      stable <- tryCatch(
        .dsvert_joint_dp_dsi_hex_equal(
          private$snapshot_mac, existing$private_snapshot_mac) &&
        .dsvert_joint_dp_dsi_hex_equal(
          private$value_mac, existing$private_value_mac) &&
        identical(private$alignment_consensus_hash,
                  existing$private_alignment_consensus_hash),
        error = function(error) FALSE)
      if (!isTRUE(stable)) .dsvert_dp_capsule_source_snapshot_changed()
      return(existing$summary_json)
    }
    release_values <- private$read_range(1L, release_count)
    .dsvert_dp_capsule_assert_signed_coordinate_bounds(
      release_values,
      list(
        manifest = parsed$manifest,
        layout = .dsvert_dp_capsule_coordinate_layout(parsed$manifest)))
    unsigned <- list(
      version = .DSVERT_DP_CAPSULE_SOURCE_SUMMARY_VERSION,
      phase = "source_chunk_stream_ready",
      purpose = contract$purpose,
      capsule_id = contract$capsule_id,
      contract_hash = parsed$contract_hash,
      source_transfer_id = transfer_id,
      source_name = .policy$peer_name,
      source_identity_pk = unname(
        .policy$peer_pinset[[.policy$peer_name]]),
      recipients = as.list(names(tickets)),
      coordinate_count = contract$coordinate_count,
      chunk_coordinates = contract$chunk_coordinates,
      chunk_count = contract$chunk_count,
      ring_bits = contract$ring_bits,
      record_encoding = contract$record_encoding,
      emitted_chunk_durable_replay = TRUE,
      unmaterialized_requires_same_snapshot = TRUE,
      complete_durable_replay = FALSE, history_gate = FALSE,
      ready_for_sampling = FALSE)
    summary <- .dsvert_dp_capsule_source_sign(
      unsigned, .policy, "source-summary", .signer)
    summary_json <- .dsvert_dp_capsule_source_encode_json(summary)
    record <- list(
      version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
      materialization =
        .DSVERT_DP_GAUSSIAN_CROSS_SOURCE_PRODUCER_VERSION,
      transfer_id = transfer_id, capsule_id = contract$capsule_id,
      contract_hash = parsed$contract_hash,
      source_name = .policy$peer_name,
      ticket_set_hash = ticket_set_hash,
      manifest_json = manifest_json,
      contract_json = parsed$contract_json,
      ticket_jsons = unname(lapply(tickets, `[[`, "json")),
      private_snapshot_mac = private$snapshot_mac,
      private_value_mac = private$value_mac,
      private_alignment_consensus_hash =
        private$alignment_consensus_hash,
      chunk_count = contract$chunk_count,
      reserved_bytes =
        .dsvert_dp_capsule_source_outbound_reservation(contract),
      status = "ready", summary_json = summary_json)
    resource_owner <- .dsvert_dp_capsule_source_resource_owner(.policy)
    capacity_state <- .dsvert_dp_capsule_source_transaction(connection, {
      next_capacity <- .dsvert_dp_capsule_source_reserve(
        connection, .secret, record$reserved_bytes, resource_owner)
      .dsvert_dp_capsule_source_record_insert(
        connection, "source_outbound",
        c("transfer_id", "capsule_id", "status"),
        list(transfer_id, contract$capsule_id, "ready"),
        record, .secret)
      next_capacity
    })
    .dsvert_dp_capsule_source_resource_reconcile(.policy, capacity_state)
    summary_json
  })
}

.dsvert_dp_capsule_source_prepare_negotiated_impl <- function(
    manifest_json, first_ticket_json, second_ticket_json,
    first_opening_json, second_opening_json,
    .policy = NULL, .secret = NULL, .envir = parent.frame(),
    .resolved_snapshots = NULL, .materializer = NULL,
    .random_bytes = .dsvert_secure_random_bytes, .encryptor = NULL,
    .signer = NULL, .verifier = NULL,
    .allocation_observer =
      .dsvert_joint_dp_vector_allocation_observer_require,
    .producer_validator = NULL,
    source_contract = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  previews <- lapply(
    list(first_ticket_json, second_ticket_json),
    .dsvert_dp_capsule_source_decode_json,
    what = "recipient ticket or transport negotiation",
    maximum_bytes = 64L * 1024L)
  negotiated <- vapply(previews, function(value) {
    identical(value$version,
              .DSVERT_DP_CAPSULE_SOURCE_TICKET_NEGOTIATION_VERSION)
  }, logical(1L))
  if (!any(negotiated)) {
    return(.dsvert_dp_capsule_source_prepare_impl(
      manifest_json, first_ticket_json, second_ticket_json,
      first_opening_json, second_opening_json,
      .policy = .policy, .secret = .secret, .envir = .envir,
      .resolved_snapshots = .resolved_snapshots,
      .materializer = .materializer, .random_bytes = .random_bytes,
      .encryptor = .encryptor, .signer = .signer, .verifier = .verifier,
      .allocation_observer = .allocation_observer,
      .producer_validator = .producer_validator,
      source_contract = source_contract))
  }
  if (!all(negotiated)) {
    stop("Capsule source transport negotiation must cover both recipients.",
         call. = FALSE)
  }
  parsed <- .dsvert_dp_capsule_source_contract_json(
    .policy, manifest_json, source_contract)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  negotiations <- lapply(
    list(first_ticket_json, second_ticket_json),
    .dsvert_dp_capsule_source_ticket_negotiation_validate,
    policy = .policy, contract = contract, verifier = .verifier)
  if (any(vapply(negotiations, is.null, logical(1L))) ||
      !identical(negotiations[[1L]]$value$capability,
                 negotiations[[2L]]$value$capability)) {
    stop("Capsule source transport negotiations disagree.", call. = FALSE)
  }
  tickets <- lapply(negotiations, `[[`, "ticket")
  recipients <- vapply(tickets, function(value) {
    value$ticket$recipient_name
  }, character(1L))
  expected <- .dsvert_dp_capsule_source_names(
    contract$designated_noise_peers, "noise-peer list")
  if (anyDuplicated(recipients) || !setequal(recipients, expected)) {
    stop("Capsule source transport negotiations have the wrong recipients.",
         call. = FALSE)
  }
  order <- order(recipients, method = "radix")
  negotiations <- negotiations[order]
  summary_json <- .dsvert_dp_capsule_source_prepare_impl(
    manifest_json,
    negotiations[[1L]]$ticket$json,
    negotiations[[2L]]$ticket$json,
    first_opening_json, second_opening_json,
    .policy = .policy, .secret = .secret, .envir = .envir,
    .resolved_snapshots = .resolved_snapshots,
    .materializer = .materializer, .random_bytes = .random_bytes,
    .encryptor = .encryptor, .signer = .signer, .verifier = .verifier,
    .allocation_observer = .allocation_observer,
    .producer_validator = .producer_validator,
    source_contract = source_contract)
  summary <- .dsvert_dp_capsule_source_decode_json(
    summary_json, "source summary", 64L * 1024L)
  negotiation_set_sha256 <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-source-negotiation-set-v1",
    negotiation_hashes = unname(lapply(negotiations, `[[`, "hash"))))
  unsigned <- list(
    version = .DSVERT_DP_CAPSULE_SOURCE_SUMMARY_NEGOTIATION_VERSION,
    phase = "source_transport_window_attested",
    summary_json = summary_json,
    summary_sha256 = .dsvert_joint_dp_hash(summary),
    ticket_negotiation_set_sha256 = negotiation_set_sha256,
    capability = negotiations[[1L]]$value$capability)
  .dsvert_dp_capsule_source_encode_json(
    .dsvert_dp_capsule_source_sign(
      unsigned, .policy, "source-window-capability", .signer))
}

.dsvert_dp_capsule_source_chunk_impl <- function(
    source_transfer_id, chunk_index,
    .policy = NULL, .secret = NULL, .envir = parent.frame(),
    .resolved_snapshots = NULL, .materializer = NULL,
    .random_bytes = .dsvert_secure_random_bytes, .encryptor = NULL,
    .signer = NULL, .verifier = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  transfer_id <- .dsvert_dp_capsule_source_scalar(
    source_transfer_id, "transfer id",
    pattern = "^csrc_[0-9a-f]{64}$", maximum_bytes = 69L)
  chunk_index <- .dsvert_dp_capsule_source_index(
    chunk_index, "chunk index", 0,
    ceiling(.DSVERT_DP_GAUSSIAN_CROSS_MAX_TRANSPORT_COORDINATES /
              .DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES) - 1)
  .dsvert_dp_capsule_source_with_store(.policy, .secret, function(connection) {
    source <- .dsvert_dp_capsule_source_outbound_load(
      connection, transfer_id, .secret)
    if (is.null(source) || !source$status %in% c("ready", "complete") ||
        !identical(
          source$materialization,
          .DSVERT_DP_GAUSSIAN_CROSS_SOURCE_PRODUCER_VERSION)) {
      stop("The biomedical capsule source chunk stream is not ready.",
           call. = FALSE)
    }
    durable_contract <- if (is.null(source$contract_json)) NULL else
      .dsvert_dp_capsule_source_decode_json(
        source$contract_json, "persisted source contract", 256L * 1024L)
    supplied <- if (is.list(durable_contract) &&
        !is.null(durable_contract$synopsis_binding)) {
      durable_contract
    } else {
      NULL
    }
    parsed <- .dsvert_dp_capsule_source_contract_json(
      .policy, source$manifest_json, supplied)
    contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
    if (!identical(parsed$contract_hash, source$contract_hash) ||
        !identical(contract$capsule_id, source$capsule_id) ||
        (!is.null(source$contract_json) &&
         !identical(parsed$contract_json, source$contract_json)) ||
        chunk_index >= contract$chunk_count) {
      stop("The persisted capsule source stream contract is invalid.",
           call. = FALSE)
    }
    rows <- DBI::dbGetQuery(connection, paste(
      "SELECT recipient_name, record_json, row_mac",
      "FROM source_outbound_chunks",
      "WHERE transfer_id = ? AND chunk_index = ?",
      "ORDER BY recipient_name"),
      params = list(transfer_id, as.integer(chunk_index)))
    if (nrow(rows) == 1L) {
      stop("The persisted capsule source split is incomplete; paired ciphertexts were not committed atomically.",
           call. = FALSE)
    }
    if (nrow(rows) == 0L) {
      if (identical(source$status, "complete")) {
        stop("The completed capsule source stream lost a durable chunk.",
             call. = FALSE)
      }
      if (!is.list(source$ticket_jsons) ||
          length(source$ticket_jsons) != 2L) {
        stop("The persisted capsule source ticket set is invalid.",
             call. = FALSE)
      }
      tickets <- lapply(
        source$ticket_jsons,
        .dsvert_dp_capsule_source_ticket_validate,
        policy = .policy, contract = contract, verifier = .verifier)
      recipients <- vapply(tickets, function(value) {
        value$ticket$recipient_name
      }, character(1L))
      tickets <- tickets[order(recipients, method = "radix")]
      names(tickets) <- sort(recipients, method = "radix")
      if (!identical(
            .dsvert_joint_dp_hash(lapply(tickets, `[[`, "hash")),
            source$ticket_set_hash)) {
        stop("The persisted capsule source ticket binding is invalid.",
             call. = FALSE)
      }
      snapshots <- .resolved_snapshots
      if (is.null(snapshots)) {
        snapshots <- tryCatch(
          lapply(names(.policy$datasets), function(data_name) {
            .dsvert_dp_resolve_snapshot(.policy, data_name, .envir, .secret)
          }),
          error = .dsvert_dp_capsule_source_snapshot_error)
        names(snapshots) <- names(.policy$datasets)
      }
      if (!is.null(.materializer) && !is.function(.materializer)) {
        stop("Invalid biomedical capsule source materializer.", call. = FALSE)
      }
      requested <- .dsvert_dp_capsule_source_chunk_geometry(
        contract, chunk_index)
      release_count <- if (
          .dsvert_dp_capsule_source_cross_contract(contract)) {
        as.numeric(contract$release_coordinate_count)
      } else {
        as.numeric(contract$coordinate_count)
      }
      producer <- tryCatch(
        if (is.null(.materializer)) {
          .dsvert_dp_gaussian_cross_source_producer(
            .policy, parsed$manifest, snapshots, compute_commitment = FALSE,
            include_release = requested$offset < release_count)
        } else {
          .materializer(
            .policy, parsed$manifest, snapshots,
            compute_commitment = FALSE,
            include_release = requested$offset < release_count)
        },
        error = .dsvert_dp_capsule_source_snapshot_error)
      if (!is.list(producer) || !is.function(producer$reset)) {
        stop("The biomedical capsule source producer cannot be released.",
             call. = FALSE)
      }
      on.exit(try(producer$reset(), silent = TRUE), add = TRUE)
      private <- .dsvert_dp_capsule_source_producer_private(
        .secret, producer, parsed$contract_hash,
        require_commitment = FALSE)
      binding_valid <-
        identical(
          producer$capsule_id,
          .dsvert_dp_capsule_source_manifest_capsule_id(contract)) &&
        identical(producer$peer_name, .policy$peer_name) &&
        identical(producer$source_context_hash,
                  contract$source_context_hash) &&
        identical(as.numeric(producer$coordinate_count),
                  as.numeric(contract$coordinate_count)) &&
        identical(producer$coordinate_order_sha256,
                  contract$coordinate_order_sha256)
      if (!isTRUE(binding_valid)) {
        stop("The incremental capsule source does not match its transport contract.",
             call. = FALSE)
      }
      if (!.dsvert_joint_dp_dsi_hex_equal(
            private$snapshot_mac, source$private_snapshot_mac) ||
          !identical(private$alignment_consensus_hash,
                     source$private_alignment_consensus_hash)) {
        .dsvert_dp_capsule_source_snapshot_changed()
      }
      generation <- private$generation_chunks(
        requested$offset + 1L, requested$count,
        contract$chunk_coordinates)
      valid_generation <- is.numeric(generation) && length(generation) &&
        !anyNA(generation) && all(is.finite(generation)) &&
        all(generation == floor(generation)) &&
        all(generation >= 0 & generation < contract$chunk_count) &&
        chunk_index %in% generation
      if (!isTRUE(valid_generation)) {
        stop("The incremental capsule source generation window is invalid.",
             call. = FALSE)
      }
      alignment_shares <- if (
          .dsvert_dp_capsule_source_cross_contract(contract)) {
        .dsvert_dp_capsule_source_alignment_shares(
          .secret, contract, .policy$peer_name,
          source$private_alignment_consensus_hash)
      } else {
        NULL
      }
      generation <- c(chunk_index, setdiff(generation, chunk_index))
      for (candidate_index in generation) {
        candidate_rows <- DBI::dbGetQuery(connection, paste(
          "SELECT recipient_name, record_json, row_mac",
          "FROM source_outbound_chunks",
          "WHERE transfer_id = ? AND chunk_index = ?",
          "ORDER BY recipient_name"),
          params = list(transfer_id, as.integer(candidate_index)))
        if (nrow(candidate_rows) == 2L) next
        if (nrow(candidate_rows) != 0L) {
          stop("The persisted capsule source split is incomplete; paired ciphertexts were not committed atomically.",
               call. = FALSE)
        }
        chunk <- .dsvert_dp_capsule_source_chunk_geometry(
          contract, candidate_index)
        values <- private$read_range(chunk$offset + 1L, chunk$count)
        split <- .dsvert_dp_capsule_source_split_ring128(
          values, .random_bytes)
        shares <- list(split$left, split$right)
        names(shares) <- names(tickets)
        envelopes <- vector("list", 2L)
        names(envelopes) <- names(tickets)
        for (recipient in names(tickets)) {
          ticket <- tickets[[recipient]]
          header <- list(
            version = .DSVERT_DP_CAPSULE_SOURCE_PLAINTEXT_VERSION,
            purpose = contract$purpose,
            capsule_id = contract$capsule_id,
            contract_hash = parsed$contract_hash,
            logical_snapshot_sha256 = contract$logical_snapshot_sha256,
            workload_sha256 = contract$workload_sha256,
            source_context_hash = contract$source_context_hash,
            peer_pinset_sha256 = contract$peer_pinset_sha256,
            coordinate_order_sha256 = contract$coordinate_order_sha256,
            source_transfer_id = transfer_id,
            source_name = .policy$peer_name,
            recipient_name = recipient,
            recipient_ticket_hash = ticket$hash,
            chunk_index = as.integer(chunk$index),
            chunk_count = contract$chunk_count,
            coordinate_offset = as.integer(chunk$offset),
            coordinates_in_chunk = as.integer(chunk$count),
            ring_bits = contract$ring_bits,
            record_encoding = contract$record_encoding,
            private_snapshot_binding_mac = source$private_snapshot_mac,
            private_value_commitment_mac = source$private_value_mac)
          if (.dsvert_dp_capsule_source_cross_contract(contract)) {
            header$private_alignment_sharing <-
              .DSVERT_DP_CAPSULE_SOURCE_ALIGNMENT_SHARING
            header$private_alignment_consensus_share <-
              alignment_shares[[recipient]]
          }
          plaintext <- .dsvert_dp_capsule_source_pack(
            header, shares[[recipient]])
          envelopes[[recipient]] <- .dsvert_dp_capsule_source_envelope(
            .policy, contract, transfer_id, ticket$ticket, ticket$hash,
            chunk, plaintext, .encryptor, .signer)
        }
        .dsvert_dp_capsule_source_transaction(connection, {
          for (recipient in names(envelopes)) {
            .dsvert_dp_capsule_source_record_insert(
              connection, "source_outbound_chunks",
              c("transfer_id", "recipient_name", "chunk_index"),
              list(transfer_id, recipient, as.integer(candidate_index)),
              envelopes[[recipient]], .secret)
          }
          committed <- DBI::dbGetQuery(connection, paste(
            "SELECT COUNT(*) AS n FROM source_outbound_chunks",
            "WHERE transfer_id = ?"), params = list(transfer_id))$n[[1L]]
          if (identical(as.numeric(committed),
                        as.numeric(2 * contract$chunk_count))) {
            source$status <- "complete"
            .dsvert_dp_capsule_source_record_update(
              connection, "source_outbound", source, .secret,
              "transfer_id = ?", list(transfer_id))
            changed <- DBI::dbExecute(
              connection, paste(
                "UPDATE source_outbound SET status = 'complete'",
                "WHERE transfer_id = ?"), params = list(transfer_id))
            if (!identical(as.integer(changed), 1L)) {
              stop("The capsule source completion commit was lost.",
                   call. = FALSE)
            }
          }
        })
      }
      rows <- DBI::dbGetQuery(connection, paste(
        "SELECT recipient_name, record_json, row_mac",
        "FROM source_outbound_chunks",
        "WHERE transfer_id = ? AND chunk_index = ?",
        "ORDER BY recipient_name"),
        params = list(transfer_id, as.integer(chunk_index)))
    }
    if (nrow(rows) != 2L) {
      stop("The persisted capsule source ciphertext bundle is incomplete.",
           call. = FALSE)
    }
    envelopes <- lapply(seq_len(2L), function(index) {
      .dsvert_dp_capsule_source_record_decode(
        rows[index, , drop = FALSE], .secret,
        "source_outbound_chunks", "outbound chunk")
    })
    summary <- .dsvert_dp_capsule_source_decode_json(
      source$summary_json, "persisted source summary", 64L * 1024L)
    recipients <- .dsvert_dp_capsule_source_names(
      summary$recipients, "source summary recipient list")
    observed_recipients <- vapply(
      envelopes, `[[`, character(1L), "recipient_name")
    first <- envelopes[[1L]]
    common_fields <- c(
      "purpose", "capsule_id", "contract_hash", "source_transfer_id", "source_name",
      "source_identity_pk", "chunk_index", "chunk_count",
      "coordinate_offset", "coordinates_in_chunk", "chunk_coordinates",
      "ring_bits", "record_encoding")
    valid <- identical(observed_recipients, recipients) &&
      identical(observed_recipients,
                sort(observed_recipients, method = "radix")) &&
      all(vapply(envelopes, function(envelope) {
        identical(envelope$source_transfer_id, transfer_id) &&
          identical(as.numeric(envelope$chunk_index), chunk_index) &&
          identical(envelope[common_fields], first[common_fields])
      }, logical(1L))) &&
      identical(first$capsule_id, source$capsule_id) &&
      identical(first$contract_hash, source$contract_hash) &&
      identical(first$source_name, source$source_name)
    if (!isTRUE(valid)) {
      stop("The persisted capsule source ciphertext bundle has the wrong binding.",
           call. = FALSE)
    }
    bundle <- list(
      version = .DSVERT_DP_CAPSULE_SOURCE_BUNDLE_VERSION,
      phase = "encrypted_source_chunk_bundle_committed",
      purpose = first$purpose,
      capsule_id = first$capsule_id,
      contract_hash = first$contract_hash,
      source_transfer_id = transfer_id,
      source_name = first$source_name,
      source_identity_pk = first$source_identity_pk,
      recipients = as.list(observed_recipients),
      chunk_index = first$chunk_index,
      chunk_count = first$chunk_count,
      coordinate_offset = first$coordinate_offset,
      coordinates_in_chunk = first$coordinates_in_chunk,
      chunk_coordinates = first$chunk_coordinates,
      ring_bits = first$ring_bits,
      record_encoding = first$record_encoding,
      envelopes = unname(envelopes),
      ready_for_sampling = FALSE)
    encoded <- .dsvert_dp_capsule_source_encode_json(bundle)
    if (nchar(encoded, type = "bytes") >
        .DSVERT_DP_CAPSULE_SOURCE_MAX_BUNDLE_BYTES) {
      .dsvert_resource_oversize(
        nchar(encoded, type = "bytes"),
        .DSVERT_DP_CAPSULE_SOURCE_MAX_BUNDLE_BYTES,
        "biomedical capsule source DSI response")
    }
    encoded
  })
}

.dsvert_dp_capsule_source_chunk_window_impl <- function(
    source_transfer_id, chunk_indices,
    .chunk_impl = .dsvert_dp_capsule_source_chunk_impl,
    .maximum_bytes = .DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_WINDOW_BYTES) {
  valid_indices <- is.numeric(chunk_indices) &&
    length(chunk_indices) >= 2L &&
    length(chunk_indices) <= .DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_CHUNKS &&
    !anyNA(chunk_indices) && all(is.finite(chunk_indices)) &&
    all(chunk_indices == floor(chunk_indices)) &&
    all(chunk_indices >= 0) &&
    identical(as.numeric(diff(chunk_indices)),
              rep(1, length(chunk_indices) - 1L))
  if (!isTRUE(valid_indices) || !is.function(.chunk_impl)) {
    stop("Invalid biomedical capsule source chunk window.", call. = FALSE)
  }
  bundles <- list()
  bundle_bytes <- numeric()
  empty_window <- .dsvert_dp_capsule_source_encode_json(list(
    version = .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
    phase = "encrypted_source_chunk_window_committed",
    bundles = list(), ready_for_sampling = FALSE))
  for (chunk_index in as.numeric(chunk_indices)) {
    bundle_json <- .chunk_impl(source_transfer_id, chunk_index)
    bundle <- .dsvert_dp_capsule_source_decode_json(
      bundle_json, "ciphertext bundle",
      .DSVERT_DP_CAPSULE_SOURCE_MAX_BUNDLE_BYTES)
    if (!identical(bundle$version,
                   .DSVERT_DP_CAPSULE_SOURCE_BUNDLE_VERSION) ||
        !identical(bundle$source_transfer_id, source_transfer_id) ||
        !identical(as.numeric(bundle$chunk_index), chunk_index)) {
      stop("Invalid biomedical capsule source window bundle.", call. = FALSE)
    }
    candidate_bytes <- nchar(empty_window, type = "bytes") +
      sum(bundle_bytes) + nchar(bundle_json, type = "bytes") +
      length(bundle_bytes)
    if (candidate_bytes > .maximum_bytes) {
      if (!length(bundles)) return(bundle_json)
      break
    }
    bundles <- c(bundles, list(bundle))
    bundle_bytes <- c(bundle_bytes, nchar(bundle_json, type = "bytes"))
  }
  if (!length(bundles)) {
    stop("The biomedical capsule source window is empty.", call. = FALSE)
  }
  result <- .dsvert_dp_capsule_source_encode_json(list(
    version = .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
    phase = "encrypted_source_chunk_window_committed",
    bundles = bundles, ready_for_sampling = FALSE))
  if (nchar(result, type = "bytes") > .maximum_bytes) {
    stop("The biomedical capsule source window exceeded its byte cap.",
         call. = FALSE)
  }
  result
}

.dsvert_dp_capsule_source_envelope_validate <- function(
    envelope_json, policy, key_record, verifier = NULL) {
  envelope <- .dsvert_dp_capsule_source_decode_json(
    envelope_json, "encrypted chunk",
    .DSVERT_DP_CAPSULE_SOURCE_MAX_ENVELOPE_BYTES)
  contract <- .dsvert_dp_capsule_source_contract_validate(
    .dsvert_dp_capsule_source_decode_json(
      key_record$contract_json, "stored contract", 128L * 1024L))
  required <- c(
    "version", "phase", "purpose", "capsule_id", "contract_hash",
    "source_transfer_id", "source_name", "source_identity_pk",
    "recipient_name", "recipient_identity_pk", "recipient_ticket_hash",
    "chunk_index", "chunk_count", "coordinate_offset",
    "coordinates_in_chunk", "chunk_coordinates", "ring_bits",
    "record_encoding", "ciphertext_bytes", "ciphertext_sha256",
    "ciphertext", "ready_for_sampling", "signature")
  source <- envelope$source_name
  chunk <- tryCatch(
    .dsvert_dp_capsule_source_chunk_geometry(
      contract, as.numeric(envelope$chunk_index)),
    error = function(e) NULL)
  valid <- !is.null(names(envelope)) && !anyNA(names(envelope)) &&
    !anyDuplicated(names(envelope)) && setequal(names(envelope), required) &&
    identical(envelope$version, .DSVERT_DP_CAPSULE_SOURCE_CHUNK_VERSION) &&
    identical(envelope$phase, "encrypted_source_chunk_committed") &&
    identical(envelope$purpose, contract$purpose) &&
    identical(envelope$capsule_id, contract$capsule_id) &&
    identical(envelope$contract_hash, .dsvert_joint_dp_hash(contract)) &&
    is.character(source) && length(source) == 1L &&
    source %in% .dsvert_dp_capsule_source_names(
      contract$source_peers, "source peer list") &&
    identical(envelope$source_identity_pk,
              unname(policy$peer_pinset[[source]])) &&
    identical(envelope$source_transfer_id,
              .dsvert_dp_capsule_source_transfer_id(contract, source)) &&
    identical(envelope$recipient_name, policy$peer_name) &&
    identical(envelope$recipient_identity_pk,
              unname(policy$peer_pinset[[policy$peer_name]])) &&
    identical(envelope$recipient_ticket_hash,
              .dsvert_joint_dp_hash(
                .dsvert_dp_capsule_source_decode_json(
                  key_record$ticket_json, "stored ticket", 64L * 1024L))) &&
    identical(as.numeric(envelope$chunk_count),
              as.numeric(contract$chunk_count)) &&
    identical(as.numeric(envelope$chunk_coordinates),
              as.numeric(contract$chunk_coordinates)) &&
    identical(as.numeric(envelope$ring_bits), 128) &&
    identical(envelope$record_encoding, contract$record_encoding) &&
    identical(envelope$ready_for_sampling, FALSE) &&
    !is.null(chunk) &&
    identical(as.numeric(envelope$coordinate_offset), chunk$offset) &&
    identical(as.numeric(envelope$coordinates_in_chunk), chunk$count)
  if (!isTRUE(valid) ||
      !.dsvert_dp_capsule_source_verify(
        envelope, policy, "encrypted-chunk", source, verifier)) {
    stop("The biomedical capsule source encrypted chunk is invalid.",
         call. = FALSE)
  }
  ciphertext <- .dsvert_dp_capsule_source_b64_raw(
    envelope$ciphertext, "ciphertext",
    .DSVERT_DP_CAPSULE_SOURCE_MAX_ENVELOPE_BYTES)
  if (!identical(as.numeric(length(ciphertext)),
                 as.numeric(envelope$ciphertext_bytes)) ||
      !identical(digest::digest(
        ciphertext, algo = "sha256", serialize = FALSE),
        envelope$ciphertext_sha256)) {
    stop("The biomedical capsule source ciphertext hash is invalid.",
         call. = FALSE)
  }
  list(
    envelope = envelope, contract = contract, chunk = chunk,
    ciphertext = ciphertext,
    envelope_hash = .dsvert_joint_dp_hash(envelope))
}

.dsvert_dp_capsule_source_key_load <- function(
    connection, capsule_id, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT record_json, row_mac FROM source_recipient_keys",
    "WHERE capsule_id = ?"), params = list(capsule_id))
  if (!nrow(row)) {
    stop("The designated peer has no persistent key for this capsule.",
         call. = FALSE)
  }
  record <- .dsvert_dp_capsule_source_record_decode(
    row, secret, "source_recipient_keys", "recipient-key record")
  .dsvert_dp_capsule_source_recipient_reservation_validate(record)
  if (!identical(record$capsule_id, capsule_id)) {
    stop("The capsule source recipient key has the wrong identity.",
         call. = FALSE)
  }
  record
}

.dsvert_dp_capsule_source_aggregate_load <- function(
    connection, capsule_id, chunk_index, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT record_json, row_mac FROM source_aggregate_chunks",
    "WHERE capsule_id = ? AND chunk_index = ?"),
    params = list(capsule_id, as.integer(chunk_index)))
  if (!nrow(row)) return(NULL)
  .dsvert_dp_capsule_source_record_decode(
    row, secret, "source_aggregate_chunks", "aggregate chunk")
}

.dsvert_dp_capsule_source_incoming_load <- function(
    connection, capsule_id, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT record_json, row_mac FROM source_incoming_state",
    "WHERE capsule_id = ?"), params = list(capsule_id))
  if (!nrow(row)) return(NULL)
  .dsvert_dp_capsule_source_record_decode(
    row, secret, "source_incoming_state", "incoming state")
}

.dsvert_dp_capsule_source_accept_impl <- function(
    envelope_json, .policy = NULL, .secret = NULL, .decryptor = NULL,
    .signer = NULL, .verifier = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  preview <- .dsvert_dp_capsule_source_decode_json(
    envelope_json, "encrypted chunk",
    .DSVERT_DP_CAPSULE_SOURCE_MAX_ENVELOPE_BYTES)
  capsule_id <- .dsvert_dp_capsule_source_scalar(
    preview$capsule_id, "capsule id", "^[0-9a-f]{64}$", 64L)
  .dsvert_dp_capsule_source_with_store(.policy, .secret, function(connection) {
    .dsvert_dp_capsule_source_require_not_compacted(
      connection, capsule_id, .secret)
    key_record <- .dsvert_dp_capsule_source_key_load(
      connection, capsule_id, .secret)
    validated <- .dsvert_dp_capsule_source_envelope_validate(
      envelope_json, .policy, key_record, .verifier)
    envelope <- validated$envelope

    prior_row <- DBI::dbGetQuery(connection, paste(
      "SELECT envelope_hash, record_json, row_mac",
      "FROM source_incoming_receipts",
      "WHERE transfer_id = ? AND chunk_index = ?"),
      params = list(envelope$source_transfer_id,
                    as.integer(envelope$chunk_index)))
    if (nrow(prior_row)) {
      prior <- .dsvert_dp_capsule_source_record_decode(
        prior_row, .secret, "source_incoming_receipts", "incoming receipt")
      if (!identical(prior_row$envelope_hash[[1L]],
                     validated$envelope_hash) ||
          !identical(prior$envelope_hash, validated$envelope_hash)) {
        stop("Conflicting biomedical capsule source chunk retry.",
             call. = FALSE)
      }
      return(prior$ack_json)
    }

    state <- .dsvert_dp_capsule_source_incoming_load(
      connection, capsule_id, .secret)
    sources <- .dsvert_dp_capsule_source_names(
      validated$contract$source_peers, "source peer list")
    if (is.null(state)) {
      state <- list(
        version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
        capsule_id = capsule_id,
        contract_hash = validated$envelope$contract_hash,
        recipient_name = .policy$peer_name,
        ticket_hash = validated$envelope$recipient_ticket_hash,
        next_source_index = 1L, next_chunk_index = 0L,
        complete = FALSE,
        reserved_bytes = .dsvert_dp_capsule_source_inbound_reservation(
          validated$contract))
    }
    source_index <- match(envelope$source_name, sources)
    if (isTRUE(state$complete) || is.na(source_index) ||
        !identical(as.numeric(state$next_source_index),
                   as.numeric(source_index)) ||
        !identical(as.numeric(state$next_chunk_index),
                   as.numeric(envelope$chunk_index)) ||
        !identical(state$contract_hash, envelope$contract_hash) ||
        !identical(state$recipient_name, .policy$peer_name) ||
        !identical(state$ticket_hash, envelope$recipient_ticket_hash)) {
      stop("Biomedical capsule source chunks must arrive in canonical owner and chunk order.",
           call. = FALSE)
    }

    plaintext <- .dsvert_dp_capsule_source_decrypt(
      validated$ciphertext, key_record$transport_sk, .decryptor)
    unpacked <- .dsvert_dp_capsule_source_unpack(
      plaintext, validated$chunk$count * 16L)
    header <- unpacked$header
    header_required <- c(
      "version", "purpose", "capsule_id", "contract_hash",
      "logical_snapshot_sha256", "workload_sha256", "source_context_hash",
      "peer_pinset_sha256", "coordinate_order_sha256",
      "source_transfer_id", "source_name", "recipient_name",
      "recipient_ticket_hash", "chunk_index", "chunk_count",
      "coordinate_offset", "coordinates_in_chunk", "ring_bits",
      "record_encoding", "private_snapshot_binding_mac",
      "private_value_commitment_mac")
    cross_contract <-
      .dsvert_dp_capsule_source_cross_contract(validated$contract)
    if (cross_contract) {
      header_required <- c(
        header_required, "private_alignment_sharing",
        "private_alignment_consensus_share")
    }
    public_binding <- c(
      "capsule_id", "contract_hash", "source_transfer_id", "source_name",
      "recipient_name", "recipient_ticket_hash", "chunk_index",
      "chunk_count", "coordinate_offset", "coordinates_in_chunk",
      "ring_bits", "record_encoding")
    valid_header <- !is.null(names(header)) && !anyNA(names(header)) &&
      !anyDuplicated(names(header)) &&
      setequal(names(header), header_required) &&
      identical(header$version,
                .DSVERT_DP_CAPSULE_SOURCE_PLAINTEXT_VERSION) &&
      identical(header$purpose, validated$contract$purpose) &&
      identical(header[public_binding], envelope[public_binding]) &&
      identical(header$logical_snapshot_sha256,
                validated$contract$logical_snapshot_sha256) &&
      identical(header$workload_sha256,
                validated$contract$workload_sha256) &&
      identical(header$source_context_hash,
                validated$contract$source_context_hash) &&
      identical(header$peer_pinset_sha256,
                validated$contract$peer_pinset_sha256) &&
      identical(header$coordinate_order_sha256,
                validated$contract$coordinate_order_sha256) &&
      all(vapply(header[c(
        "private_snapshot_binding_mac", "private_value_commitment_mac")],
        function(value) {
          is.character(value) && length(value) == 1L && !is.na(value) &&
            grepl("^[0-9a-f]{64}$", value)
        }, logical(1L)))
    if (!isTRUE(valid_header)) {
      stop("The decrypted biomedical capsule source binding is invalid.",
           call. = FALSE)
    }
    if (cross_contract) {
      cross_peers <- .dsvert_dp_capsule_source_names(
        validated$contract$cross_input_peers, "cross-input peer list")
      participant <- envelope$source_name %in% cross_peers
      alignment_share <- header$private_alignment_consensus_share
      alignment_raw <- if (participant) {
        tryCatch(.dsvert_relay_b64url_decode(
          alignment_share, "private alignment consensus share"),
          error = function(error) raw())
      } else {
        raw()
      }
      alignment_valid <- identical(
        header$private_alignment_sharing,
        .DSVERT_DP_CAPSULE_SOURCE_ALIGNMENT_SHARING) &&
        is.character(alignment_share) &&
        length(alignment_share) == 1L && !is.na(alignment_share) &&
        if (participant) {
          is.raw(alignment_raw) && length(alignment_raw) == 32L
        } else {
          identical(alignment_share, "not_applicable")
        }
      if (!isTRUE(alignment_valid)) {
        if (identical(
            validated$contract$version,
            .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_CONTRACT_VERSION)) {
          .dsvert_dp_categorical_cross_alignment_error()
        }
        .dsvert_dp_gaussian_cross_alignment_error()
      }
      prior_shares <- state$private_alignment_consensus_shares
      if (is.null(prior_shares)) prior_shares <- list()
      if (!is.list(prior_shares) || is.null(names(prior_shares)) &&
          length(prior_shares) || anyNA(names(prior_shares)) ||
          anyDuplicated(names(prior_shares)) ||
          !all(names(prior_shares) %in% cross_peers)) {
        stop("The private alignment-share state is invalid.", call. = FALSE)
      }
      prior_alignment <- prior_shares[[envelope$source_name]]
      if (participant && !is.null(prior_alignment) &&
          !identical(prior_alignment, alignment_share)) {
        if (identical(
            validated$contract$version,
            .DSVERT_DP_CAPSULE_SOURCE_CATEGORICAL_CROSS_CONTRACT_VERSION)) {
          .dsvert_dp_categorical_cross_alignment_error()
        }
        .dsvert_dp_gaussian_cross_alignment_error()
      }
      if (participant && is.null(prior_alignment)) {
        prior_shares[[envelope$source_name]] <- alignment_share
        prior_shares <- prior_shares[order(names(prior_shares),
                                           method = "radix")]
        state$private_alignment_consensus_shares <- prior_shares
      }
    }

    aggregate <- .dsvert_dp_capsule_source_aggregate_load(
      connection, capsule_id, envelope$chunk_index, .secret)
    if (source_index == 1L) {
      if (!is.null(aggregate)) {
        stop("The biomedical capsule source aggregate has a conflicting first owner.",
             call. = FALSE)
      }
      aggregate_raw <- unpacked$share
    } else {
      if (is.null(aggregate) ||
          !identical(as.numeric(aggregate$source_count),
                     as.numeric(source_index - 1L))) {
        stop("The biomedical capsule source aggregate owner count is invalid.",
             call. = FALSE)
      }
      prior_raw <- .dsvert_dp_capsule_source_b64_raw(
        aggregate$aggregate_b64, "private aggregate chunk",
        validated$chunk$count * 16L)
      if (length(prior_raw) != length(unpacked$share)) {
        stop("The biomedical capsule source aggregate shape changed.",
             call. = FALSE)
      }
      aggregate_raw <- .dsvert_dp_capsule_source_add_ring128(
        prior_raw, unpacked$share)
    }
    aggregate_record <- list(
      version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
      capsule_id = capsule_id,
      contract_hash = envelope$contract_hash,
      recipient_name = .policy$peer_name,
      chunk_index = envelope$chunk_index,
      coordinates_in_chunk = envelope$coordinates_in_chunk,
      source_count = as.integer(source_index),
      aggregate_b64 = .dsvert_dp_capsule_source_raw_b64(aggregate_raw))

    source_complete <-
      envelope$chunk_index == validated$contract$chunk_count - 1L
    aggregation_complete <- source_complete && source_index == length(sources)
    if (cross_contract && aggregation_complete) {
      cross_peers <- .dsvert_dp_capsule_source_names(
        validated$contract$cross_input_peers, "cross-input peer list")
      observed <- names(state$private_alignment_consensus_shares %||% list())
      if (!setequal(observed, cross_peers)) {
        stop("The private alignment-share set is incomplete.", call. = FALSE)
      }
    }
    next_state <- state
    if (source_complete) {
      next_state$next_source_index <- as.integer(source_index + 1L)
      next_state$next_chunk_index <- 0L
    } else {
      next_state$next_chunk_index <- as.integer(envelope$chunk_index + 1L)
    }
    next_state$complete <- aggregation_complete
    unsigned_ack <- list(
      version = .DSVERT_DP_CAPSULE_SOURCE_ACK_VERSION,
      phase = "source_chunk_aggregated",
      purpose = validated$contract$purpose,
      capsule_id = capsule_id,
      contract_hash = envelope$contract_hash,
      source_transfer_id = envelope$source_transfer_id,
      source_name = envelope$source_name,
      source_identity_pk = envelope$source_identity_pk,
      recipient_name = .policy$peer_name,
      recipient_identity_pk = unname(
        .policy$peer_pinset[[.policy$peer_name]]),
      recipient_ticket_hash = envelope$recipient_ticket_hash,
      chunk_index = envelope$chunk_index,
      chunk_count = envelope$chunk_count,
      ciphertext_sha256 = envelope$ciphertext_sha256,
      source_complete = source_complete,
      capsule_aggregation_complete = aggregation_complete,
      history_gate = FALSE, ready_for_sampling = FALSE)
    ack <- .dsvert_dp_capsule_source_sign(
      unsigned_ack, .policy, "aggregate-ack", .signer)
    ack_json <- .dsvert_dp_capsule_source_encode_json(ack)
    receipt <- list(
      version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
      envelope_hash = validated$envelope_hash,
      ciphertext_sha256 = envelope$ciphertext_sha256,
      ack_json = ack_json)

    resource_owner <- .dsvert_dp_capsule_source_resource_owner(.policy)
    capacity_state <- NULL
    .dsvert_dp_capsule_source_transaction(connection, {
      if (is.null(.dsvert_dp_capsule_source_incoming_load(
            connection, capsule_id, .secret))) {
        capacity_state <- .dsvert_dp_capsule_source_reserve(
          connection, .secret, state$reserved_bytes, resource_owner)
        .dsvert_dp_capsule_source_record_insert(
          connection, "source_incoming_state", "capsule_id",
          list(capsule_id), next_state, .secret)
      } else {
        .dsvert_dp_capsule_source_record_update(
          connection, "source_incoming_state", next_state, .secret,
          "capsule_id = ?", list(capsule_id))
      }
      if (is.null(aggregate)) {
        .dsvert_dp_capsule_source_record_insert(
          connection, "source_aggregate_chunks",
          c("capsule_id", "chunk_index"),
          list(capsule_id, as.integer(envelope$chunk_index)),
          aggregate_record, .secret)
      } else {
        .dsvert_dp_capsule_source_record_update(
          connection, "source_aggregate_chunks", aggregate_record, .secret,
          "capsule_id = ? AND chunk_index = ?",
          list(capsule_id, as.integer(envelope$chunk_index)))
      }
      .dsvert_dp_capsule_source_record_insert(
        connection, "source_incoming_receipts",
        c("transfer_id", "chunk_index", "envelope_hash"),
        list(envelope$source_transfer_id, as.integer(envelope$chunk_index),
             validated$envelope_hash), receipt, .secret)
    })
    if (!is.null(capacity_state)) {
      .dsvert_dp_capsule_source_resource_reconcile(.policy, capacity_state)
    }
    ack_json
  })
}

.dsvert_dp_capsule_source_accept_window_impl <- function(
    envelope_json,
    .accept_impl = .dsvert_dp_capsule_source_accept_impl,
    .maximum_bytes =
      .DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_ACCEPT_WINDOW_BYTES) {
  window <- .dsvert_dp_capsule_source_decode_json(
    envelope_json, "encrypted chunk window",
    .maximum_bytes)
  required <- c("version", "phase", "envelopes", "ready_for_sampling")
  envelopes <- window$envelopes
  common <- c(
    "capsule_id", "contract_hash", "source_transfer_id", "source_name",
    "source_identity_pk", "recipient_name", "recipient_identity_pk",
    "recipient_ticket_hash", "chunk_count", "chunk_coordinates",
    "ring_bits", "record_encoding")
  valid <- !is.null(names(window)) && !anyNA(names(window)) &&
    !anyDuplicated(names(window)) && setequal(names(window), required) &&
    identical(window$version,
              .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION) &&
    identical(window$phase, "recipient_encrypted_chunk_window") &&
    identical(window$ready_for_sampling, FALSE) &&
    is.list(envelopes) && is.null(names(envelopes)) &&
    length(envelopes) >= 2L &&
    length(envelopes) <= .DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_CHUNKS &&
    all(vapply(envelopes, function(value) {
      is.list(value) &&
        identical(value$version,
                  .DSVERT_DP_CAPSULE_SOURCE_CHUNK_VERSION) &&
        all(c(common, "chunk_index", "ciphertext_sha256") %in%
              names(value))
    }, logical(1L)))
  if (isTRUE(valid)) {
    reference <- envelopes[[1L]]
    indices <- vapply(
      envelopes, function(value) as.numeric(value$chunk_index), numeric(1L))
    valid <- all(vapply(envelopes, function(value) {
      identical(value[common], reference[common])
    }, logical(1L))) &&
      !anyNA(indices) && all(is.finite(indices)) &&
      all(indices == floor(indices)) && all(indices >= 0) &&
      identical(as.numeric(diff(indices)), rep(1, length(indices) - 1L))
  }
  if (!isTRUE(valid) || !is.function(.accept_impl)) {
    stop("Invalid biomedical capsule source recipient window.", call. = FALSE)
  }
  acknowledgements <- lapply(envelopes, function(envelope) {
    ack_json <- .accept_impl(
      .dsvert_dp_capsule_source_encode_json(envelope))
    ack <- .dsvert_dp_capsule_source_decode_json(
      ack_json, "source acknowledgement", 64L * 1024L)
    if (!identical(ack$version, .DSVERT_DP_CAPSULE_SOURCE_ACK_VERSION) ||
        !identical(ack$source_transfer_id, envelope$source_transfer_id) ||
        !identical(as.numeric(ack$chunk_index),
                   as.numeric(envelope$chunk_index)) ||
        !identical(ack$ciphertext_sha256, envelope$ciphertext_sha256)) {
      stop("Invalid biomedical capsule source window acknowledgement.",
           call. = FALSE)
    }
    ack
  })
  result <- .dsvert_dp_capsule_source_encode_json(list(
    version = .DSVERT_DP_CAPSULE_SOURCE_ACK_WINDOW_VERSION,
    phase = "source_chunk_window_aggregated",
    acknowledgements = acknowledgements,
    ready_for_sampling = FALSE))
  if (nchar(result, type = "bytes") > 64L * 1024L) {
    .dsvert_resource_oversize(
      nchar(result, type = "bytes"), 64L * 1024L,
      "biomedical capsule source acknowledgement window")
  }
  result
}

# Internal sampler boundary.  It deliberately requires the immutable source
# contract and returns one recipient-local aggregate chunk only to server code.
# No AggregateMethods entry references this helper.
.dsvert_dp_capsule_source_aggregate_range_in_store <- function(
    connection, contract, capsule_id, start, count, secret) {
  start <- .dsvert_dp_capsule_source_index(
    start, "private aggregate range start", 1, contract$coordinate_count)
  count <- .dsvert_dp_capsule_source_index(
    count, "private aggregate range length", 1,
    contract$coordinate_count - start + 1)
  first_chunk <- floor((start - 1) / contract$chunk_coordinates)
  last_chunk <- floor((start + count - 2) / contract$chunk_coordinates)
  parts <- vector("list", last_chunk - first_chunk + 1L)
  out_index <- 1L
  for (chunk_index in seq.int(first_chunk, last_chunk)) {
    geometry <- .dsvert_dp_capsule_source_chunk_geometry(
      contract, chunk_index)
    aggregate <- .dsvert_dp_capsule_source_aggregate_load(
      connection, capsule_id, chunk_index, secret)
    sources <- .dsvert_dp_capsule_source_names(
      contract$source_peers, "source peer list")
    if (is.null(aggregate) ||
        !identical(as.numeric(aggregate$source_count),
                   as.numeric(length(sources))) ||
        !identical(as.numeric(aggregate$coordinates_in_chunk),
                   as.numeric(geometry$count))) {
      stop("The biomedical capsule source aggregate failed completeness validation.",
           call. = FALSE)
    }
    raw <- .dsvert_dp_capsule_source_b64_raw(
      aggregate$aggregate_b64, "private aggregate chunk",
      geometry$count * .DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES)
    requested_first <- max(start, geometry$offset + 1)
    requested_last <- min(start + count - 1,
                          geometry$offset + geometry$count)
    local_first <- requested_first - geometry$offset
    local_count <- requested_last - requested_first + 1
    byte_first <- (local_first - 1) *
      .DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES + 1
    byte_count <- local_count * .DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES
    parts[[out_index]] <- raw[seq.int(
      byte_first, length.out = byte_count)]
    out_index <- out_index + 1L
  }
  result <- do.call(c, parts)
  if (!is.raw(result) || length(result) !=
      count * .DSVERT_DP_CAPSULE_SOURCE_RECORD_BYTES) {
    stop("The biomedical capsule source aggregate range has the wrong shape.",
         call. = FALSE)
  }
  result
}

.dsvert_dp_capsule_source_aggregate_range_internal <- function(
    policy, manifest_json, start, count, secret = NULL,
    source_contract = NULL) {
  if (is.null(secret)) secret <- .dsvert_dp_secret()
  parsed <- .dsvert_dp_capsule_source_contract_json(
    policy, manifest_json, source_contract)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  if (!policy$peer_name %in% .dsvert_dp_capsule_source_names(
        contract$designated_noise_peers, "noise-peer list")) {
    stop("Only a designated noise peer can consume an aggregate source share.",
         call. = FALSE)
  }
  .dsvert_dp_capsule_source_with_store(policy, secret, function(connection) {
    state <- .dsvert_dp_capsule_source_incoming_load(
      connection, contract$capsule_id, secret)
    if (is.null(state) || !isTRUE(state$complete) ||
        !identical(state$contract_hash, parsed$contract_hash)) {
      stop("The biomedical capsule source aggregate is incomplete.",
           call. = FALSE)
    }
    .dsvert_dp_capsule_source_aggregate_range_in_store(
      connection, contract, contract$capsule_id, start, count, secret)
  })
}

.dsvert_dp_capsule_source_aggregate_release_range_internal <- function(
    policy, manifest_json, offset, count, secret = NULL,
    source_contract = NULL) {
  if (is.null(secret)) secret <- .dsvert_dp_secret()
  parsed <- .dsvert_dp_capsule_source_contract_json(
    policy, manifest_json, source_contract)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  if (!policy$peer_name %in% .dsvert_dp_capsule_source_names(
        contract$designated_noise_peers, "noise-peer list")) {
    stop("Only a designated noise peer can consume an aggregate source share.",
         call. = FALSE)
  }
  release_count <- if (.dsvert_dp_capsule_source_cross_contract(contract)) {
    as.numeric(contract$release_coordinate_count)
  } else {
    as.numeric(contract$coordinate_count)
  }
  offset <- .dsvert_dp_capsule_source_index(
    offset, "release coordinate offset", 0, release_count - 1)
  count <- .dsvert_dp_capsule_source_index(
    count, "release coordinate count", 1, release_count - offset)
  chunk <- list(index = 0L, offset = offset, count = count)
  .dsvert_dp_capsule_source_with_store(policy, secret, function(connection) {
    state <- .dsvert_dp_capsule_source_incoming_load(
      connection, contract$capsule_id, secret)
    if (is.null(state) || !isTRUE(state$complete) ||
        !identical(state$contract_hash, parsed$contract_hash)) {
      stop("The biomedical capsule source aggregate is incomplete.",
           call. = FALSE)
    }
    share <- .dsvert_dp_capsule_source_aggregate_range_in_store(
      connection, contract, contract$capsule_id,
      chunk$offset + 1L, chunk$count, secret)
    if (.dsvert_dp_capsule_source_cross_contract(contract)) {
      share <- .dsvert_dp_gaussian_cross_inject_release_share_internal(
        connection, secret, parsed$manifest, contract, chunk, share)
      share <- .dsvert_dp_categorical_cross_inject_release_share_internal(
        connection, secret, parsed$manifest, contract, chunk, share,
        policy = policy)
    }
    if (length(share) != chunk$count * 16L) {
      stop("The biomedical capsule source aggregate has the wrong byte shape.",
           call. = FALSE)
    }
    share
  })
}

.dsvert_dp_capsule_source_aggregate_chunk_internal <- function(
    policy, manifest_json, chunk_index, secret = NULL,
    source_contract = NULL) {
  if (is.null(secret)) secret <- .dsvert_dp_secret()
  parsed <- .dsvert_dp_capsule_source_contract_json(
    policy, manifest_json, source_contract)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  release_count <- if (.dsvert_dp_capsule_source_cross_contract(contract)) {
    as.numeric(contract$release_coordinate_count)
  } else {
    as.numeric(contract$coordinate_count)
  }
  release_chunk_count <- ceiling(
    release_count / contract$chunk_coordinates)
  chunk_index <- .dsvert_dp_capsule_source_index(
    chunk_index, "release chunk index", 0, release_chunk_count - 1)
  offset <- chunk_index * contract$chunk_coordinates
  .dsvert_dp_capsule_source_aggregate_release_range_internal(
    policy, manifest_json, offset,
    min(contract$chunk_coordinates, release_count - offset), secret,
    source_contract)
}

.dsvert_dp_capsule_source_public <- function(phase, code) {
  tryCatch(force(code), error = function(e) {
    # `phase` is deliberately not included in the relay-visible failure.  The
    # caller already knows which public method it invoked, while protected
    # admission, snapshot, range and integrity details must remain server-side.
    .dsvert_dp_transcript_stop(e)
  })
}

#' Mint or replay a persistent capsule-source recipient ticket (AGGREGATE)
#'
#' @param manifest_json Canonical immutable biomedical capsule manifest.
#' @param transport_contract Public transport negotiation request. The default
#'   returns the byte-identical scalar v1 ticket; the byte-window value returns
#'   a signed wrapper around that same persistent ticket. The internal
#'   capability-only value returns a signed, source-data-independent public
#'   capability attestation for rolling upgrades.
#' @return A canonical signed recipient ticket, a signed wrapper containing
#'   that same ticket, or a signed public source-capability attestation,
#'   according to \code{transport_contract}. No protected source value is
#'   returned.
#' @export
dsvertDPCapsuleSourceTicketDS <- function(
    manifest_json,
    transport_contract = .DSVERT_DP_CAPSULE_SOURCE_SCALAR_TRANSPORT) {
  .dsvert_dp_capsule_source_public("recipient ticket", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_SOURCE_MAX_MANIFEST_BYTES)
    transport_contract <- .dsvert_dp_capsule_source_scalar(
      transport_contract, "transport contract", maximum_bytes = 128L)
    if (!transport_contract %in% c(
        .DSVERT_DP_CAPSULE_SOURCE_SCALAR_TRANSPORT,
        .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
        .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT,
        .DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ONLY_REQUEST,
        .DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ONLY_REQUEST_V2)) {
      stop("Unsupported biomedical capsule source transport contract.",
           call. = FALSE)
    }
    policy <- .dsvert_dp_policy()
    secret <- .dsvert_dp_secret()
    .dsvert_dp_capsule_manifest_require_built(
      policy, manifest_json, secret)
    if (transport_contract %in% c(
        .DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ONLY_REQUEST,
        .DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ONLY_REQUEST_V2)) {
      capability_contract <- if (identical(
          transport_contract,
          .DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ONLY_REQUEST_V2)) {
        .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT
      } else {
        .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION
      }
      .dsvert_dp_capsule_source_capability_attestation(
        manifest_json, policy, capability_contract)
    } else {
      ticket_json <- .dsvert_dp_capsule_source_ticket_impl(
        manifest_json, .policy = policy, .secret = secret)
      if (identical(transport_contract,
                    .DSVERT_DP_CAPSULE_SOURCE_SCALAR_TRANSPORT)) {
        ticket_json
      } else if (transport_contract %in% c(
          .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
          .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT)) {
        .dsvert_dp_capsule_source_ticket_negotiation_wrap(
          ticket_json, policy, transport_contract)
      }
    }
  })
}

#' Bind one owner's incremental capsule-share stream (AGGREGATE)
#'
#' @param manifest_json Canonical immutable biomedical capsule manifest.
#' @param first_ticket_json,second_ticket_json Signed tickets from the two
#'   designated pinned noise peers.
#' @param first_opening_json,second_opening_json Cross-signed allocation
#'   openings from those peers. They are verified locally before protected
#'   source material is resolved.
#' @return A canonical signed redacted summary, or a signed transport wrapper
#'   containing that byte-identical summary and its public capability. No
#'   statistic, share, mask, seed, or patient-derived digest is returned.
#' @export
dsvertDPCapsuleSourcePrepareDS <- function(
    manifest_json, first_ticket_json, second_ticket_json,
    first_opening_json, second_opening_json) {
  .dsvert_dp_capsule_source_public("preparation", {
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_SOURCE_MAX_MANIFEST_BYTES)
    first_ticket_json <- .dsvert_dsi_text_decode(
      first_ticket_json, "first biomedical capsule recipient ticket",
      64L * 1024L)
    second_ticket_json <- .dsvert_dsi_text_decode(
      second_ticket_json, "second biomedical capsule recipient ticket",
      64L * 1024L)
    first_opening_json <- .dsvert_dsi_text_decode(
      first_opening_json, "first biomedical allocation opening",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    second_opening_json <- .dsvert_dsi_text_decode(
      second_opening_json, "second biomedical allocation opening",
      .DSVERT_JOINT_DP_DSI_MAX_RECEIPT_BYTES)
    policy <- .dsvert_dp_policy()
    secret <- .dsvert_dp_secret()
    .dsvert_dp_capsule_manifest_require_built(
      policy, manifest_json, secret)
    .dsvert_dp_capsule_source_prepare_negotiated_impl(
      manifest_json, first_ticket_json, second_ticket_json,
      first_opening_json, second_opening_json,
      .policy = policy, .secret = secret, .envir = parent.frame())
  })
}

#' Fetch both durable opaque capsule-source ciphertexts (AGGREGATE)
#'
#' @param source_transfer_id Purpose-bound source transfer identifier.
#' @param chunk_index One zero-based public chunk index for the byte-identical
#'   scalar response, or a bounded consecutive vector for a negotiated
#'   byte-window response.
#' @param transport_contract Public framing contract. Omission preserves the
#'   legacy v1 768-KiB response cap; the fully attested adaptive v2 contract
#'   selects the independent 8-MiB hard cap.
#' @return A canonical bundle containing exactly two individually signed
#'   ciphertext envelopes in designated-peer order, or a bounded consecutive
#'   window of those bundles. Window framing is not independently signed; every
#'   enclosed envelope remains signed and fully bound.
#' @export
dsvertDPCapsuleSourceChunkDS <- function(
    source_transfer_id, chunk_index,
    transport_contract = .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION) {
  transport_contract <- .dsvert_dp_capsule_source_scalar(
    transport_contract, "window transport contract", maximum_bytes = 128L)
  capability <- .dsvert_dp_capsule_source_transport_capability(
    transport_contract)
  source_envir <- parent.frame()
  .dsvert_dp_capsule_source_public(
    "ciphertext bundle fetch",
    if (length(chunk_index) == 1L) {
      .dsvert_dp_capsule_source_chunk_impl(
        source_transfer_id, chunk_index, .envir = source_envir)
    } else {
        .dsvert_dp_capsule_source_chunk_window_impl(
          source_transfer_id, chunk_index,
          .chunk_impl = function(transfer_id, index) {
            .dsvert_dp_capsule_source_chunk_impl(
              transfer_id, index, .envir = source_envir)
          },
          .maximum_bytes = capability$maximum_response_bytes)
    })
}

#' Accept and aggregate one opaque capsule-source ciphertext (AGGREGATE)
#'
#' @param envelope_json One canonical signed ciphertext envelope, or a
#'   negotiated bounded wrapper of consecutive envelopes from one pinned
#'   source owner.
#' @param transport_contract Public framing contract. Omission preserves the
#'   legacy v1 1-MiB request cap; the fully attested adaptive v2 contract
#'   selects the independent 8-MiB hard cap.
#' @return A canonical signed idempotent acknowledgement containing only
#'   public progress metadata, or a bounded window of such acknowledgements.
#'   Window framing is not independently signed; every enclosed acknowledgement
#'   remains signed and fully bound.
#' @export
dsvertDPCapsuleSourceAcceptDS <- function(
    envelope_json,
    transport_contract = .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION) {
  transport_contract <- .dsvert_dp_capsule_source_scalar(
    transport_contract, "window transport contract", maximum_bytes = 128L)
  capability <- .dsvert_dp_capsule_source_transport_capability(
    transport_contract)
  .dsvert_dp_capsule_source_public("acceptance", {
    envelope_json <- .dsvert_dsi_text_decode(
      envelope_json, "biomedical capsule encrypted chunk or window",
      .DSVERT_DP_CAPSULE_SOURCE_MAX_ACCEPT_WINDOW_BYTES)
    preview <- .dsvert_dp_capsule_source_decode_json(
      envelope_json, "encrypted chunk or window",
      capability$maximum_accept_bytes)
    if (identical(preview$version,
                  .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION)) {
      .dsvert_dp_capsule_source_accept_window_impl(
        envelope_json,
        .maximum_bytes = capability$maximum_accept_bytes)
    } else {
      .dsvert_dp_capsule_source_accept_impl(envelope_json)
    }
  })
}
