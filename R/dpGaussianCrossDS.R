# Purpose-bound cross-owner Gaussian inputs and exact sufficient statistics.
#
# The public capsule vector contains only the final DP release block.  The
# fixed-capacity value/validity arrays below are an internal extension of the
# encrypted source transport.  They are never registered as DataSHIELD
# methods and are available only as additive Ring128 shares at the two signed
# computation peers.

.DSVERT_DP_GAUSSIAN_CROSS_ARTIFACT_VERSION <-
  "bounded-normalized-gaussian-cross-sufficient-statistics-v1"
.DSVERT_DP_GAUSSIAN_CROSS_LAYOUT_VERSION <-
  "dsvert-cross-gaussian-private-source-layout-v1"
.DSVERT_DP_GAUSSIAN_CROSS_MAX_TRANSPORT_COORDINATES <- 64L * 1024L^2
.DSVERT_DP_GAUSSIAN_CROSS_PRODUCER <- "dp.gaussian-cross.v1"
.DSVERT_DP_GAUSSIAN_CROSS_BIND_VERSION <-
  "dsvert-cross-gaussian-exact-binding-v1"
.DSVERT_DP_GAUSSIAN_CROSS_STAGE_VERSION <-
  "dsvert-cross-gaussian-exact-stage-v1"
.DSVERT_DP_GAUSSIAN_CROSS_RESULT_VERSION <-
  "dsvert-cross-gaussian-result-share-v1"
.DSVERT_DP_GAUSSIAN_CROSS_RECEIPT_VERSION <-
  "dsvert-cross-gaussian-result-receipt-v1"
.DSVERT_DP_GAUSSIAN_CROSS_REDUCER_VERSION <-
  "dsvert-ring128-sum-records-v1"
.DSVERT_DP_GAUSSIAN_CROSS_REDUCER_MAX_RECORDS <- 2000000L
.DSVERT_DP_GAUSSIAN_CROSS_SOURCE_PRODUCER_VERSION <-
  "dsvert-cross-source-incremental-producer-v1"

.dsvert_dp_gaussian_cross_artifacts <- function(manifest) {
  artifacts <- tryCatch(
    manifest$workload$families$gaussian_models$artifacts,
    error = function(error) NULL)
  if (!is.list(artifacts)) return(list())
  result <- artifacts[vapply(artifacts, function(artifact) {
    is.list(artifact) && identical(
      artifact$version, .DSVERT_DP_GAUSSIAN_CROSS_ARTIFACT_VERSION)
  }, logical(1L))]
  if (length(result)) result[order(names(result), method = "radix")] else list()
}

.dsvert_dp_gaussian_cross_names <- function(value, what) {
  if (is.character(value) && is.null(names(value))) {
    items <- unname(value)
  } else if (is.list(value) && is.null(names(value))) {
    items <- unname(unlist(value, use.names = FALSE))
  } else {
    items <- NULL
  }
  if (!is.character(items) || !length(items) || anyNA(items) ||
      any(!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", items))) {
    stop("Invalid cross-owner Gaussian ", what, ".", call. = FALSE)
  }
  items
}

.dsvert_dp_gaussian_cross_variable <- function(artifact, variable) {
  if (identical(variable, artifact$outcome$column)) return(artifact$outcome)
  descriptor <- artifact$predictors[[variable]]
  if (is.null(descriptor)) {
    stop("The signed cross-owner Gaussian variable order is invalid.",
         call. = FALSE)
  }
  descriptor
}

.dsvert_dp_gaussian_cross_layout <- function(manifest, release_layout = NULL) {
  if (is.null(release_layout)) {
    release_layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  }
  artifacts <- .dsvert_dp_gaussian_cross_artifacts(manifest)
  categorical_artifacts <- .dsvert_dp_categorical_cross_artifacts(manifest)
  if (!length(artifacts) && !length(categorical_artifacts)) {
    return(list(
      version = .DSVERT_DP_GAUSSIAN_CROSS_LAYOUT_VERSION,
      enabled = FALSE,
      release_coordinate_count = release_layout$coordinate_count,
      transport_coordinate_count = release_layout$coordinate_count,
      release_coordinate_order_sha256 = release_layout$sha256,
      transport_coordinate_order_sha256 = release_layout$sha256,
      padding_coordinates = 0L, blocks = list(),
      source_peers = character(), computation_peers = character()))
  }
  capacity <- suppressWarnings(as.numeric(manifest$admission$unit_capacity))
  if (length(capacity) != 1L || is.na(capacity) || !is.finite(capacity) ||
      capacity != floor(capacity) || capacity < 1 ||
      capacity > .DSVERT_DP_MAX_COORDINATES) {
    stop("The cross-owner Gaussian padded capacity is invalid.",
         call. = FALSE)
  }
  capacity <- as.integer(capacity)
  release_count <- as.numeric(release_layout$coordinate_count)
  chunk <- as.numeric(.DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES)
  private_start <- ceiling(release_count / chunk) * chunk + 1
  padding <- private_start - release_count - 1
  cursor <- private_start
  blocks <- list()
  source_peers <- computation_peers <- character()
  for (analysis_id in names(artifacts)) {
    artifact <- artifacts[[analysis_id]]
    variables <- unname(as.character(artifact$input_variable_order))
    participants <- .dsvert_dp_gaussian_cross_names(
      artifact$participating_peers, "participant list")
    computation <- .dsvert_dp_gaussian_cross_names(
      artifact$computation_peers, "computation-peer list")
    if (anyNA(variables) || !length(variables) || anyDuplicated(variables) ||
        length(computation) != 2L || anyDuplicated(computation) ||
        !identical(computation, sort(computation, method = "radix")) ||
        !identical(participants, sort(participants, method = "radix"))) {
      stop("The signed cross-owner Gaussian private layout is invalid.",
           call. = FALSE)
    }
    source_peers <- c(source_peers, participants)
    computation_peers <- c(computation_peers, computation)
    for (variable in variables) {
      descriptor <- .dsvert_dp_gaussian_cross_variable(artifact, variable)
      required <- c("column", "dataset", "owner_peer", "lower", "upper")
      if (!is.list(descriptor) || is.null(names(descriptor)) ||
          !setequal(names(descriptor), required) ||
          !identical(descriptor$column, variable) ||
          !descriptor$owner_peer %in% participants) {
        stop("The signed cross-owner Gaussian input descriptor is invalid.",
             call. = FALSE)
      }
      for (kind in c("value", "validity")) {
        end <- cursor + capacity - 1
        if (!is.finite(end) ||
            end > .DSVERT_DP_GAUSSIAN_CROSS_MAX_TRANSPORT_COORDINATES) {
          stop(structure(
            list(
              message = paste(
                "The fixed-capacity cross-owner Gaussian source layout",
                "exceeds the bounded transport spool."),
              call = NULL,
              reason = "cross_gaussian_transport_shape_unrepresentable"),
            class = c("dsvert_resource_shape_unrepresentable", "error",
                      "condition")))
        }
        key <- paste(analysis_id, variable, kind, sep = "::")
        blocks[[key]] <- list(
          analysis_id = analysis_id, variable = variable, kind = kind,
          dataset = descriptor$dataset, owner_peer = descriptor$owner_peer,
          lower = descriptor$lower, upper = descriptor$upper,
          start = as.integer(cursor), end = as.integer(end),
          length = capacity)
        cursor <- end + 1
      }
    }
  }
  for (analysis_id in names(categorical_artifacts)) {
    artifact <- categorical_artifacts[[analysis_id]]
    participants <- .dsvert_dp_gaussian_cross_names(
      artifact$participating_peers, "categorical participant list")
    computation <- .dsvert_dp_gaussian_cross_names(
      artifact$computation_peers, "categorical computation-peer list")
    if (length(participants) != 2L || anyDuplicated(participants) ||
        length(computation) != 2L || anyDuplicated(computation) ||
        !identical(participants, sort(participants, method = "radix")) ||
        !identical(computation, sort(computation, method = "radix"))) {
      stop("The signed cross-owner categorical private layout is invalid.",
           call. = FALSE)
    }
    source_peers <- c(source_peers, participants)
    computation_peers <- c(computation_peers, computation)
    for (side in c("left", "right")) {
      descriptor <- artifact[[side]]
      required <- c("dataset", "column", "owner_peer", "levels")
      if (!is.list(descriptor) || is.null(names(descriptor)) ||
          !setequal(names(descriptor), required) ||
          !descriptor$owner_peer %in% participants ||
          !is.character(descriptor$levels) || !length(descriptor$levels) ||
          anyNA(descriptor$levels) || anyDuplicated(descriptor$levels)) {
        stop("The signed cross-owner categorical input descriptor is invalid.",
             call. = FALSE)
      }
      shapes <- c(
        one_hot = as.double(capacity) * length(descriptor$levels),
        validity = capacity)
      for (kind in names(shapes)) {
        block_length <- shapes[[kind]]
        end <- cursor + block_length - 1
        if (!is.finite(end) || block_length < 1L ||
            block_length > 2^31 - 1 ||
            end > .DSVERT_DP_GAUSSIAN_CROSS_MAX_TRANSPORT_COORDINATES) {
          stop(structure(list(
            message = paste(
              "The fixed-capacity cross-owner categorical source layout",
              "exceeds the bounded transport spool."),
            call = NULL,
            reason = "cross_categorical_transport_shape_unrepresentable"),
            class = c("dsvert_resource_shape_unrepresentable", "error",
                      "condition")))
        }
        key <- paste("categorical", analysis_id, side, kind, sep = "::")
        blocks[[key]] <- list(
          input_family = "categorical", analysis_id = analysis_id,
          side = side, variable = descriptor$column, kind = kind,
          dataset = descriptor$dataset, owner_peer = descriptor$owner_peer,
          levels = descriptor$levels,
          start = as.integer(cursor), end = as.integer(end),
          length = as.integer(block_length))
        cursor <- end + 1
      }
    }
  }
  source_peers <- sort(unique(source_peers), method = "radix")
  computation_peers <- sort(unique(computation_peers), method = "radix")
  if (length(computation_peers) != 2L) {
    stop("Cross-owner artifacts disagree on their two computation peers.",
         call. = FALSE)
  }
  public_shape <- list(
    version = .DSVERT_DP_GAUSSIAN_CROSS_LAYOUT_VERSION,
    capsule_id = manifest$capsule_identity$capsule_id,
    release_coordinate_count = as.integer(release_count),
    release_coordinate_order_sha256 = release_layout$sha256,
    private_start = as.integer(private_start),
    padding_coordinates = as.integer(padding),
    transport_coordinate_count = as.integer(cursor - 1),
    blocks = blocks,
    source_peers = as.list(source_peers),
    computation_peers = as.list(computation_peers),
    padding_rule = "zero_to_next_source_chunk_boundary_v1",
    payload_rule = if (length(categorical_artifacts)) paste0(
      "manifest_order_capacity_padded_ring128_value_one_hot_and_validity_",
      "no_exact_release_v1") else
      "manifest_order_capacity_padded_ring128_value_then_validity_no_exact_release_v1")
  public_shape$transport_coordinate_order_sha256 <-
    .dsvert_joint_dp_hash(public_shape)
  c(public_shape, list(enabled = TRUE))
}

.dsvert_dp_gaussian_cross_alignment_error <- function() {
  stop(structure(
    list(
      message = paste(
        "The cross-owner Gaussian inputs do not have one privately",
        "authenticated ordered PSI alignment manifest."),
      call = NULL,
      reason = "non_prealigned_cross_gaussian_cohort"),
    class = c("dsvert_non_prealigned_cohort", "error", "condition")))
}

.dsvert_dp_cross_source_alignment_error <- function(manifest) {
  if (length(.dsvert_dp_categorical_cross_artifacts(manifest))) {
    .dsvert_dp_categorical_cross_alignment_error()
  }
  .dsvert_dp_gaussian_cross_alignment_error()
}

.dsvert_dp_gaussian_cross_source_context <- function(
    policy, manifest, resolved_snapshots, include_release = TRUE) {
  validated <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  release_layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  layout <- .dsvert_dp_gaussian_cross_layout(manifest, release_layout)
  snapshots <- tryCatch(
    .dsvert_dp_capsule_resolved_snapshots(policy, resolved_snapshots),
    error = function(error) {
      if (grepl("PSI alignment|alignment binding", conditionMessage(error))) {
        .dsvert_dp_cross_source_alignment_error(manifest)
      }
      stop(error)
    })
  local_peer <- .dsvert_dp_capsule_id(policy$peer_name, "local peer")
  release <- if (isTRUE(include_release)) {
    tryCatch(
      .dsvert_dp_capsule_materialize_local(
        policy, manifest, snapshots),
      error = function(error) {
        message <- conditionMessage(error)
        if (grepl("PSI alignment|alignment binding", message)) {
          .dsvert_dp_cross_source_alignment_error(manifest)
        }
        stop(error)
      })
  } else {
    snapshot_binding <- .dsvert_joint_dp_hash(list(
      protocol = "dsvert-biomedical-capsule-local-snapshots-v1",
      capsule_id = validated$identity$capsule_id,
      peer_name = local_peer,
      datasets = lapply(snapshots, function(snapshot) list(
        public = snapshot$dataset$public,
        protected_fingerprint = snapshot$dataset$fingerprint))))
    list(
      version = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION,
      purpose = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE,
      capsule_id = validated$identity$capsule_id,
      peer_name = local_peer, logical_snapshot = manifest$logical_snapshot,
      source_context_hash =
        manifest$workload$capsule_mechanism$source_context_hash,
      snapshot_binding_sha256 = snapshot_binding, values = NULL)
  }
  local_blocks <- layout$blocks[vapply(layout$blocks, function(block) {
    identical(block$owner_peer, local_peer)
  }, logical(1L))]
  datasets <- if (length(local_blocks)) sort(unique(vapply(
    local_blocks, `[[`, character(1L), "dataset")), method = "radix") else
      character()
  alignment_hashes <- vapply(datasets, function(data_name) {
    descriptor <- policy$datasets[[data_name]]
    if (!is.list(descriptor) ||
        is.null(descriptor$alignment_manifest_hash) ||
        is.null(descriptor$alignment_manifest_version) ||
        !data_name %in% names(snapshots)) {
      .dsvert_dp_cross_source_alignment_error(manifest)
    }
    alignment <- tryCatch(
      .dsvert_dp_validate_descriptor_alignment(
        snapshots[[data_name]]$data, descriptor, policy$patient_column,
        expected_pinset = policy$peer_pinset),
      error = function(error) NULL)
    if (is.null(alignment)) {
      .dsvert_dp_cross_source_alignment_error(manifest)
    }
    alignment$hash
  }, character(1L))
  if (length(alignment_hashes) && length(unique(alignment_hashes)) != 1L) {
    .dsvert_dp_cross_source_alignment_error(manifest)
  }
  list(
    policy = policy, manifest = manifest, release = release,
    release_layout = release_layout, layout = layout,
    snapshots = snapshots, local_peer = local_peer,
    local_blocks = local_blocks,
    private_alignment_consensus_hash = if (length(alignment_hashes)) {
      alignment_hashes[[1L]]
    } else {
      "not_applicable"
    })
}

.dsvert_dp_gaussian_cross_source_segments <- function(context) {
  layout <- context$layout
  segments <- list(list(
    type = "release", start = 1L,
    end = as.integer(layout$release_coordinate_count),
    length = as.integer(layout$release_coordinate_count),
    cache_key = "release"))
  if (isTRUE(layout$enabled) && layout$padding_coordinates > 0L) {
    segments[[length(segments) + 1L]] <- list(
      type = "zero", start = as.integer(layout$release_coordinate_count + 1L),
      end = as.integer(layout$private_start - 1L),
      length = as.integer(layout$padding_coordinates),
      cache_key = "padding")
  }
  blocks <- layout$blocks
  if (length(blocks)) {
    blocks <- blocks[order(vapply(blocks, `[[`, numeric(1L), "start"))]
  }
  for (block in blocks) {
    categorical_one_hot <-
      identical(block$input_family, "categorical") &&
      identical(block$kind, "one_hot")
    cache_key <- paste(
      block$input_family %||% "numeric", block$dataset, block$variable,
      sep = "::")
    if (categorical_one_hot) {
      capacity <- as.integer(block$length / length(block$levels))
      for (level_index in seq_along(block$levels)) {
        start <- block$start + (level_index - 1L) * capacity
        segments[[length(segments) + 1L]] <- list(
          type = "private", start = as.integer(start),
          end = as.integer(start + capacity - 1L), length = capacity,
          cache_key = cache_key, block = block,
          level_index = as.integer(level_index))
      }
    } else {
      segments[[length(segments) + 1L]] <- list(
        type = "private", start = as.integer(block$start),
        end = as.integer(block$end), length = as.integer(block$length),
        cache_key = cache_key, block = block)
    }
  }
  expected_start <- 1L
  for (segment in segments) {
    if (!identical(as.numeric(segment$start), as.numeric(expected_start)) ||
        segment$end < segment$start ||
        !identical(as.numeric(segment$length),
                   as.numeric(segment$end - segment$start + 1L))) {
      stop("The cross-owner incremental source layout is not contiguous.",
           call. = FALSE)
    }
    expected_start <- segment$end + 1L
  }
  if (!identical(as.numeric(expected_start - 1L),
                 as.numeric(layout$transport_coordinate_count))) {
    stop("The cross-owner incremental source layout has the wrong shape.",
         call. = FALSE)
  }
  segments
}

.dsvert_dp_gaussian_cross_source_producer <- function(
    policy, manifest, resolved_snapshots, compute_commitment = TRUE,
    include_release = TRUE) {
  if (!is.logical(compute_commitment) || length(compute_commitment) != 1L ||
      is.na(compute_commitment) || !is.logical(include_release) ||
      length(include_release) != 1L || is.na(include_release) ||
      (isTRUE(compute_commitment) && !isTRUE(include_release))) {
    stop("Invalid incremental source commitment mode.", call. = FALSE)
  }
  context <- .dsvert_dp_gaussian_cross_source_context(
    policy, manifest, resolved_snapshots, include_release = include_release)
  segments <- .dsvert_dp_gaussian_cross_source_segments(context)
  state <- new.env(parent = emptyenv())
  reset <- function() {
    for (name in ls(state, all.names = TRUE)) {
      rm(list = name, envir = state)
    }
    invisible(NULL)
  }
  admission_for <- function(data_name) {
    if (!identical(state$admission_key %||% "", data_name)) {
      state$admission_key <- data_name
      state$admission <- .dsvert_dp_admit_units(
        context$snapshots[[data_name]]$data, context$policy)
      state$bounded_key <- NULL
      state$bounded <- NULL
    }
    state$admission
  }
  bounded_for <- function(block) {
    categorical <- identical(block$input_family, "categorical")
    key <- paste(
      if (categorical) "categorical" else "numeric",
      block$dataset, block$variable, sep = "::")
    if (!identical(state$bounded_key %||% "", key)) {
      admission <- admission_for(block$dataset)
      state$bounded_key <- key
      state$bounded <- if (categorical) {
        .dsvert_dp_capsule_bounded_category(
          context$snapshots[[block$dataset]]$data, context$policy,
          block$variable, block$levels, admission)
      } else {
        .dsvert_dp_bounded_numeric(
          context$snapshots[[block$dataset]]$data, context$policy,
          block$variable, admission)
      }
    }
    state$bounded
  }
  segment_values <- function(segment) {
    if (identical(segment$type, "release")) {
      return(context$release$values)
    }
    if (identical(segment$type, "zero") ||
        !identical(segment$block$owner_peer, context$local_peer)) {
      return(numeric(segment$length))
    }
    block <- segment$block
    input <- bounded_for(block)
    scale <- 2^as.integer(context$manifest$bounds$numeric_grid_bits)
    categorical <- identical(block$input_family, "categorical")
    values <- if (categorical && identical(block$kind, "validity")) {
      as.numeric(!is.na(input$cell)) * scale
    } else if (categorical) {
      as.numeric(!is.na(input$cell) &
                   input$cell == segment$level_index) * scale
    } else if (identical(block$kind, "validity")) {
      as.numeric(input$valid) * scale
    } else {
      normalized <- pmin(1, pmax(
        0, (input$unit_values - block$lower) /
          (block$upper - block$lower)))
      result <- round(normalized * scale)
      result[!input$valid] <- 0
      result
    }
    if (length(values) != segment$length || anyNA(values) ||
        any(!is.finite(values)) || any(values < 0 | values > scale) ||
        any(values != floor(values))) {
      stop("A cross-owner private input violated its signed bound.",
           call. = FALSE)
    }
    unname(as.numeric(values))
  }
  read_range <- function(start, count) {
    start <- .dsvert_dp_capsule_source_index(
      start, "incremental range start", 1,
      context$layout$transport_coordinate_count)
    count <- .dsvert_dp_capsule_source_index(
      count, "incremental range length", 1,
      context$layout$transport_coordinate_count - start + 1L)
    result <- numeric(count)
    last <- start + count - 1L
    for (segment in segments) {
      first <- max(start, segment$start)
      end <- min(last, segment$end)
      if (first > end) next
      values <- segment_values(segment)
      result[seq.int(first - start + 1L, end - start + 1L)] <-
        values[seq.int(first - segment$start + 1L,
                       end - segment$start + 1L)]
    }
    .dsvert_dp_integer_vector(result, "incremental source coordinates")
  }
  generation_chunks <- function(start, count, chunk_coordinates) {
    start <- .dsvert_dp_capsule_source_index(
      start, "generation range start", 1,
      context$layout$transport_coordinate_count)
    count <- .dsvert_dp_capsule_source_index(
      count, "generation range length", 1,
      context$layout$transport_coordinate_count - start + 1L)
    chunk_coordinates <- .dsvert_dp_capsule_source_index(
      chunk_coordinates, "generation chunk shape", 1,
      2^31 - 1)
    last <- start + count - 1L
    keys <- unique(vapply(segments[vapply(segments, function(segment) {
      max(start, segment$start) <= min(last, segment$end)
    }, logical(1L))], `[[`, character(1L), "cache_key"))
    grouped <- segments[vapply(segments, function(segment) {
      segment$cache_key %in% keys
    }, logical(1L))]
    sort(unique(unlist(lapply(grouped, function(segment) {
      seq.int(
        floor((segment$start - 1L) / chunk_coordinates),
        floor((segment$end - 1L) / chunk_coordinates))
    }), use.names = FALSE)), method = "radix")
  }
  binding <- context$release[c(
    "version", "purpose", "capsule_id", "peer_name", "logical_snapshot",
    "source_context_hash", "snapshot_binding_sha256")]
  binding$coordinate_count <- context$layout$transport_coordinate_count
  binding$coordinate_order_sha256 <-
    context$layout$transport_coordinate_order_sha256
  binding <- binding[c(
    "version", "purpose", "capsule_id", "peer_name", "logical_snapshot",
    "source_context_hash", "coordinate_count",
    "coordinate_order_sha256", "snapshot_binding_sha256")]
  value_commitment <- authenticatable <- NULL
  if (isTRUE(compute_commitment)) {
    block_size <- .DSVERT_DP_CAPSULE_VALUE_BLOCK
    pending <- numeric()
    block_hashes <- character()
    for (segment in segments) {
      values <- segment_values(segment)
      cursor <- 1L
      while (cursor <= length(values)) {
        take <- min(block_size - length(pending),
                    length(values) - cursor + 1L)
        pending <- c(pending, values[seq.int(cursor, length.out = take)])
        cursor <- cursor + take
        if (length(pending) == block_size) {
          block_hashes <- c(block_hashes, digest::digest(
            unname(pending), algo = "sha256", serialize = TRUE,
            serializeVersion = 3L))
          pending <- numeric()
        }
      }
    }
    if (length(pending)) {
      block_hashes <- c(block_hashes, digest::digest(
        unname(pending), algo = "sha256", serialize = TRUE,
        serializeVersion = 3L))
    }
    value_commitment <- .dsvert_joint_dp_hash(list(
      protocol = "dsvert-biomedical-capsule-value-blocks-v1",
      coordinate_count = context$layout$transport_coordinate_count,
      block_size = block_size, block_hashes = unname(block_hashes),
      binding = binding))
    authenticatable <- .dsvert_joint_dp_hash(list(
      authentication_domain =
        "dsVert/biomedical-capsule/local-secret-share-input/v1|",
      binding = binding, value_commitment_sha256 = value_commitment))
    reset()
  }
  structure(c(binding, list(
    producer_version = .DSVERT_DP_GAUSSIAN_CROSS_SOURCE_PRODUCER_VERSION,
    state = "internal_incremental_secret_share_input_never_release",
    value_commitment_sha256 = value_commitment,
    authenticatable_sha256 = authenticatable,
    private_alignment_consensus_hash =
      context$private_alignment_consensus_hash,
    read_range = read_range, generation_chunks = generation_chunks,
    reset = reset)),
    class = c("dsvert_capsule_source_producer", "list"))
}

.dsvert_dp_gaussian_cross_materialize_source <- function(
    policy, manifest, resolved_snapshots) {
  producer <- .dsvert_dp_gaussian_cross_source_producer(
    policy, manifest, resolved_snapshots, compute_commitment = TRUE)
  values <- producer$read_range(1L, producer$coordinate_count)
  producer$reset()
  binding_names <- c(
    "version", "purpose", "capsule_id", "peer_name", "logical_snapshot",
    "source_context_hash", "coordinate_count", "coordinate_order_sha256",
    "snapshot_binding_sha256")
  c(unclass(producer)[binding_names], list(
    state = "internal_unshared_secret_share_input_never_release",
    values = values,
    value_commitment_sha256 = producer$value_commitment_sha256,
    authenticatable_sha256 = producer$authenticatable_sha256,
    private_alignment_consensus_hash =
      producer$private_alignment_consensus_hash))
}

.dsvert_dp_gaussian_cross_result_load <- function(
    connection, capsule_id, analysis_id, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT record_json, row_mac FROM source_cross_gaussian_results",
    "WHERE capsule_id = ? AND analysis_id = ?"),
    params = list(capsule_id, analysis_id))
  if (!nrow(row)) return(NULL)
  .dsvert_dp_capsule_source_record_decode(
    row, secret, "source_cross_gaussian_results",
    "cross-owner Gaussian result")
}

.dsvert_dp_gaussian_cross_inject_release_share_internal <- function(
    connection, secret, manifest, contract, chunk, share) {
  if (!is.raw(share) || length(share) != chunk$count * 16L) {
    stop("The cross-owner Gaussian release injection has the wrong shape.",
         call. = FALSE)
  }
  artifacts <- .dsvert_dp_gaussian_cross_artifacts(manifest)
  layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  for (analysis_id in names(artifacts)) {
    block <- layout$blocks[[paste("gaussian_models", analysis_id, sep = "::")]]
    result <- .dsvert_dp_gaussian_cross_result_load(
      connection, contract$capsule_id, analysis_id, secret)
    valid <- is.list(block) && is.list(result) &&
      identical(result$version,
                .DSVERT_DP_GAUSSIAN_CROSS_RESULT_VERSION) &&
      identical(result$status, "complete") &&
      identical(result$capsule_id, contract$capsule_id) &&
      identical(result$analysis_id, analysis_id) &&
      identical(result$source_contract_hash,
                .dsvert_joint_dp_hash(contract)) &&
      identical(result$artifact_sha256,
                .dsvert_joint_dp_hash(artifacts[[analysis_id]])) &&
      identical(result$private_layout_sha256,
                contract$private_layout_sha256) &&
      identical(result$transcript_sha256,
                .dsvert_joint_dp_hash(
                  artifacts[[analysis_id]]$transcript)) &&
      identical(result$numeric_certificate_sha256,
                .dsvert_joint_dp_hash(
                  artifacts[[analysis_id]]$numeric_certificate)) &&
      identical(result$release_coordinate_order_sha256,
                contract$release_coordinate_order_sha256) &&
      is.character(result$exact_transcript_sha256) &&
      grepl("^[0-9a-f]{64}$", result$exact_transcript_sha256) &&
      is.character(result$result_share_sha256) &&
      grepl("^[0-9a-f]{64}$", result$result_share_sha256) &&
      identical(as.numeric(result$coordinate_count),
                as.numeric(block$length)) &&
      identical(as.numeric(result$release_start),
                as.numeric(block$start)) &&
      identical(as.numeric(result$release_end),
                as.numeric(block$end))
    if (!isTRUE(valid)) {
      stop("The cross-owner Gaussian exact result is incomplete.",
           call. = FALSE)
    }
    result_raw <- .dsvert_dp_capsule_source_b64_raw(
      result$result_share_b64, "cross-owner Gaussian result share",
      block$length * 16L)
    if (!identical(
          digest::digest(result_raw, algo = "sha256", serialize = FALSE),
          result$result_share_sha256)) {
      stop("The cross-owner Gaussian exact result share failed authentication.",
           call. = FALSE)
    }
    global_first <- max(block$start, chunk$offset + 1L)
    global_last <- min(block$end, chunk$offset + chunk$count)
    if (global_first > global_last) next
    coordinate_count <- global_last - global_first + 1L
    chunk_first <- global_first - chunk$offset
    result_first <- global_first - block$start + 1L
    chunk_bytes <- seq.int(
      (chunk_first - 1L) * 16L + 1L,
      length.out = coordinate_count * 16L)
    result_bytes <- seq.int(
      (result_first - 1L) * 16L + 1L,
      length.out = coordinate_count * 16L)
    share[chunk_bytes] <- .dsvert_dp_capsule_source_add_ring128(
      share[chunk_bytes], result_raw[result_bytes])
  }
  share
}

.dsvert_dp_gaussian_cross_tag <- function(capsule_id, analysis_id) {
  substr(.dsvert_joint_dp_hash(list(
    protocol = "dsvert-cross-gaussian-slot-namespace-v1",
    capsule_id = capsule_id, analysis_id = analysis_id)), 1L, 20L)
}

.dsvert_dp_gaussian_cross_slot <- function(binding, kind, index = NULL) {
  suffix <- if (is.null(index)) kind else
    paste0(kind, "_", sprintf("%04d", as.integer(index)))
  .exact_gc_vecmul_validate_slot(
    paste0("dp_gauss_", binding$tag, "_", suffix),
    "cross-owner Gaussian private slot")
}

.dsvert_dp_gaussian_cross_standard_b64 <- function(raw, what) {
  if (!is.raw(raw) || !length(raw)) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  gsub("[\r\n]", "", jsonlite::base64_enc(raw))
}

.dsvert_dp_gaussian_cross_load_inputs <- function(
    policy, secret, manifest, artifact, analysis_id, ss) {
  manifest_json <- .dsvert_dp_canonical_json(manifest)
  parsed <- .dsvert_dp_capsule_source_contract_json(policy, manifest_json)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  if (!.dsvert_dp_capsule_source_cross_contract(contract) ||
      !policy$peer_name %in% .dsvert_dp_capsule_source_names(
        contract$designated_noise_peers, "noise-peer list")) {
    stop("The cross-owner Gaussian computation peer is not authorized.",
         call. = FALSE)
  }
  private_layout <- .dsvert_dp_gaussian_cross_layout(manifest)
  variables <- unname(as.character(artifact$input_variable_order))
  values <- validities <- vector("list", length(variables))
  names(values) <- names(validities) <- variables
  .dsvert_dp_alignment_mask_complete_batch(
    ss, contract$capsule_id, parsed$contract_hash)
  for (variable in variables) {
    for (kind in c("value", "validity")) {
      key <- paste(analysis_id, variable, kind, sep = "::")
      block <- private_layout$blocks[[key]]
      if (!is.list(block) || block$length != artifact$transcript$padded_units) {
        stop("The cross-owner Gaussian private input shape changed.",
             call. = FALSE)
      }
      raw <- .dsvert_dp_alignment_mask_range(
        ss, contract$capsule_id, parsed$contract_hash,
        block$start, block$length)
      encoded <- .dsvert_dp_gaussian_cross_standard_b64(
        raw, "cross-owner Gaussian masked aggregate share")
      .exact_gc_validate_residue_records(
        encoded, 128L, block$length,
        "cross-owner Gaussian masked aggregate share")
      if (identical(kind, "value")) {
        values[[variable]] <- encoded
      } else {
        validities[[variable]] <- encoded
      }
    }
  }
  list(
    contract = contract, contract_hash = parsed$contract_hash,
    private_layout = private_layout, values = values,
    validities = validities)
}

.dsvert_dp_gaussian_cross_binding_public <- function(
    binding, policy, signer = NULL) {
  unsigned <- list(
    version = .DSVERT_DP_GAUSSIAN_CROSS_BIND_VERSION,
    phase = "cross_gaussian_private_inputs_bound",
    capsule_id = binding$capsule_id,
    analysis_id = binding$analysis_id,
    artifact_sha256 = binding$artifact_sha256,
    source_contract_hash = binding$source_contract_hash,
    private_layout_sha256 = binding$private_layout_sha256,
    transcript_sha256 = binding$transcript_sha256,
    numeric_certificate_sha256 = binding$numeric_certificate_sha256,
    peer_name = policy$peer_name,
    peer_identity_pk = unname(policy$peer_pinset[[policy$peer_name]]),
    padded_units = binding$capacity,
    variable_count = binding$variable_count,
    ring_bits = 128L, frac_bits = binding$grid_bits,
    state = if (identical(binding$state, "finalized")) {
      "complete"
    } else {
      "bound"
    }, source_values_exposed = FALSE,
    alignment_hash_exposed = FALSE,
    alignment_hash_exposed_to_relay = FALSE,
    alignment_hash_exposed_to_computation_peers = FALSE,
    exact_intermediates_exposed = FALSE,
    fixed_transcript = TRUE)
  .dsvert_dp_capsule_source_sign(
    unsigned, policy, "cross-gaussian-bind", signer)
}

.dsvert_dp_gaussian_cross_bind_impl <- function(
    manifest_json, analysis_id, session_id,
    .policy = NULL, .secret = NULL, .signer = NULL, .verifier = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  analysis_id <- .dsvert_dp_capsule_id(
    analysis_id, "cross-owner Gaussian analysis id")
  session_id <- .dsvert_relay_validate_session_id(session_id)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  validated <- .dsvert_dp_capsule_materializer_manifest(.policy, manifest)
  artifact <- .dsvert_dp_gaussian_cross_artifacts(manifest)[[analysis_id]]
  if (is.null(artifact)) {
    stop("The signed capsule has no cross-owner Gaussian artifact.",
         call. = FALSE)
  }
  computation <- .dsvert_dp_gaussian_cross_names(
    artifact$computation_peers, "computation-peer list")
  ss <- .S(session_id)
  parties <- .exact_gc_vecmul_party_context(ss)
  if (!setequal(computation, c(parties$self_name, parties$peer_name)) ||
      !identical(parties$self_name, .policy$peer_name)) {
    stop("The exact-GC pinned pair does not match the signed computation peers.",
         call. = FALSE)
  }
  artifact_hash <- .dsvert_joint_dp_hash(artifact)
  tag <- .dsvert_dp_gaussian_cross_tag(
    validated$identity$capsule_id, analysis_id)
  if (is.null(ss$.dp_gaussian_cross_bindings)) {
    ss$.dp_gaussian_cross_bindings <- list()
  }
  previous <- ss$.dp_gaussian_cross_bindings[[analysis_id]]
  if (!is.null(previous)) {
    if (!identical(previous$capsule_id, validated$identity$capsule_id) ||
        !identical(previous$artifact_sha256, artifact_hash) ||
        !identical(previous$peer_binding_digest,
                   ss$.exact_gc_peer_binding_digest)) {
      stop("Conflicting cross-owner Gaussian session binding.",
           call. = FALSE)
    }
    public <- .dsvert_dp_gaussian_cross_binding_public(
      previous, .policy, .signer)
    return(.dsvert_dp_capsule_source_encode_json(public))
  }
  parsed <- .dsvert_dp_capsule_source_contract_json(.policy, manifest_json)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  release_block <- validated$layout$blocks[[paste(
    "gaussian_models", analysis_id, sep = "::")]]
  prior <- .dsvert_dp_capsule_source_with_store(
    .policy, .secret, function(connection) {
      .dsvert_dp_gaussian_cross_result_load(
        connection, contract$capsule_id, analysis_id, .secret)
    })
  if (!is.null(prior)) {
    prior <- .dsvert_dp_gaussian_cross_result_validate(
      prior, .policy, contract, artifact, release_block, .verifier)
    binding <- list(
      version = .DSVERT_DP_GAUSSIAN_CROSS_BIND_VERSION,
      capsule_id = validated$identity$capsule_id,
      analysis_id = analysis_id, artifact = artifact,
      artifact_sha256 = artifact_hash, tag = tag,
      source_contract_hash = parsed$contract_hash,
      private_layout_sha256 = contract$private_layout_sha256,
      transcript_sha256 = .dsvert_joint_dp_hash(artifact$transcript),
      numeric_certificate_sha256 =
        .dsvert_joint_dp_hash(artifact$numeric_certificate),
      peer_binding_digest = ss$.exact_gc_peer_binding_digest,
      capacity = as.integer(artifact$transcript$padded_units),
      variable_count = length(artifact$input_variable_order),
      variables = unname(as.character(artifact$input_variable_order)),
      grid_bits = as.integer(artifact$numeric_grid_bits),
      value_keys = character(), validity_keys = character(),
      stages = list(), state = "finalized",
      result_exact_transcript_sha256 = prior$exact_transcript_sha256)
    public <- .dsvert_dp_capsule_source_encode_json(
      .dsvert_dp_gaussian_cross_binding_public(
        binding, .policy, .signer))
    ss$.dp_gaussian_cross_bindings[[analysis_id]] <- binding
    return(public)
  }
  loaded <- .dsvert_dp_gaussian_cross_load_inputs(
    .policy, .secret, manifest, artifact, analysis_id, ss)
  capacity <- as.integer(artifact$transcript$padded_units)
  variables <- unname(as.character(artifact$input_variable_order))
  binding <- list(
    version = .DSVERT_DP_GAUSSIAN_CROSS_BIND_VERSION,
    capsule_id = validated$identity$capsule_id,
    analysis_id = analysis_id, artifact = artifact,
    artifact_sha256 = artifact_hash, tag = tag,
    source_contract_hash = loaded$contract_hash,
    private_layout_sha256 =
      loaded$private_layout$transport_coordinate_order_sha256,
    transcript_sha256 = .dsvert_joint_dp_hash(artifact$transcript),
    numeric_certificate_sha256 =
      .dsvert_joint_dp_hash(artifact$numeric_certificate),
    peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    capacity = capacity, variable_count = length(variables),
    variables = variables, grid_bits = as.integer(artifact$numeric_grid_bits),
    value_keys = character(length(variables)),
    validity_keys = character(length(variables)), stages = list(),
    state = "bound")
  names(binding$value_keys) <- names(binding$validity_keys) <- variables
  installed <- character()
  committed <- FALSE
  on.exit(if (!committed) {
    for (key in installed) ss[[key]] <- NULL
  }, add = TRUE)
  for (index in seq_along(variables)) {
    variable <- variables[[index]]
    value_key <- .dsvert_dp_gaussian_cross_slot(
      binding, "value", index)
    validity_key <- .dsvert_dp_gaussian_cross_slot(
      binding, "valid", index)
    if (!is.null(ss[[value_key]]) || !is.null(ss[[validity_key]])) {
      stop("A cross-owner Gaussian private input slot is already in use.",
           call. = FALSE)
    }
    ss[[value_key]] <- loaded$values[[variable]]
    ss[[validity_key]] <- loaded$validities[[variable]]
    binding$value_keys[[variable]] <- value_key
    binding$validity_keys[[variable]] <- validity_key
    installed <- c(installed, value_key, validity_key)
  }
  binding$state <- "installed"
  public <- .dsvert_dp_capsule_source_encode_json(
    .dsvert_dp_gaussian_cross_binding_public(binding, .policy, .signer))
  ss$.dp_gaussian_cross_bindings[[analysis_id]] <- binding
  committed <- TRUE
  public
}

#' Bind one signed cross-owner Gaussian private input set (AGGREGATE)
#'
#' @export
dsvertDPGaussianCrossBindDS <- function(
    manifest_json, analysis_id, session_id) {
  tryCatch({
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    policy <- .dsvert_dp_policy()
    secret <- .dsvert_dp_secret()
    .dsvert_dp_capsule_manifest_require_built(
      policy, manifest_json, secret)
    .dsvert_dp_gaussian_cross_bind_impl(
      manifest_json, analysis_id, session_id,
      .policy = policy, .secret = secret)
  }, error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_gaussian_cross_binding <- function(ss, analysis_id) {
  analysis_id <- .dsvert_dp_capsule_id(
    analysis_id, "cross-owner Gaussian analysis id")
  binding <- ss$.dp_gaussian_cross_bindings[[analysis_id]]
  if (!is.list(binding) || !identical(binding$state, "installed") ||
      !identical(binding$analysis_id, analysis_id) ||
      !identical(binding$peer_binding_digest,
                 ss$.exact_gc_peer_binding_digest)) {
    stop("The cross-owner Gaussian private binding is unavailable.",
         call. = FALSE)
  }
  binding
}

.dsvert_dp_gaussian_cross_stage_key <- function(stage, stage_index) {
  paste(stage, sprintf("%04d", as.integer(stage_index)), sep = "::")
}

.dsvert_dp_gaussian_cross_stage_complete <- function(ss, record) {
  if (!is.list(record) || !is.character(record$manifest_handle)) return(FALSE)
  producer <- if (is.character(record$producer) &&
      length(record$producer) == 1L && !is.na(record$producer)) {
    record$producer
  } else {
    .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER
  }
  manifest <- ss$.exact_gc_vecmul_manifests[[record$manifest_handle]]
  if (!is.list(manifest) || !identical(manifest$state, "consumed") ||
      !identical(manifest$producer, producer) ||
      !identical(manifest$purpose, record$purpose) ||
      !identical(manifest$output_key, record$output_key)) {
    return(FALSE)
  }
  input_stage <- ss$.exact_gc_vecmul_input_stages[[manifest$claimed_batch]]
  output <- ss[[record$output_key]]
  is.list(input_stage) && identical(input_stage$state, "complete") &&
    identical(input_stage$manifest_handle, record$manifest_handle) &&
    identical(input_stage$output_key, record$output_key) &&
    identical(input_stage$output_digest,
              .exact_gc_vecmul_value_digest(output)) &&
    !is.null(output)
}

.dsvert_dp_gaussian_cross_raw_slot <- function(
    ss, key, n, what) {
  value <- ss[[key]]
  .exact_gc_validate_residue_records(value, 128L, n, what)
}

.dsvert_dp_gaussian_cross_install_derived <- function(
    ss, key, raw, n, installed) {
  encoded <- .dsvert_dp_gaussian_cross_standard_b64(
    raw, "cross-owner Gaussian derived share")
  .exact_gc_validate_residue_records(
    encoded, 128L, n, "cross-owner Gaussian derived share")
  previous <- ss[[key]]
  if (!is.null(previous) && !identical(previous, encoded)) {
    stop("A cross-owner Gaussian derived slot has conflicting contents.",
         call. = FALSE)
  }
  ss[[key]] <- encoded
  c(installed, if (is.null(previous)) key else character())
}

.dsvert_dp_gaussian_cross_stage_spec <- function(
    ss, binding, stage, stage_index) {
  if (!is.character(stage) || length(stage) != 1L || is.na(stage) ||
      !stage %in% c("validity", "masked-values", "moments")) {
    stop("Invalid cross-owner Gaussian exact stage.", call. = FALSE)
  }
  stage_index <- as.integer(.exact_gc_integer(
    stage_index, "cross-owner Gaussian stage index", 1,
    .Machine$integer.max))
  m <- binding$variable_count
  capacity <- binding$capacity
  installed <- character()
  if (identical(stage, "validity")) {
    if (stage_index > m - 1L) {
      stop("The cross-owner Gaussian validity stage is out of range.",
           call. = FALSE)
    }
    if (stage_index > 1L) {
      prior_key <- .dsvert_dp_gaussian_cross_stage_key(
        "validity", stage_index - 1L)
      prior <- binding$stages[[prior_key]]
      if (!.dsvert_dp_gaussian_cross_stage_complete(ss, prior)) {
        stop("The preceding cross-owner Gaussian validity stage is incomplete.",
             call. = FALSE)
      }
      x_key <- prior$output_key
    } else {
      x_key <- binding$validity_keys[[binding$variables[[1L]]]]
    }
    y_key <- binding$validity_keys[[
      binding$variables[[stage_index + 1L]]]]
    output_key <- .dsvert_dp_gaussian_cross_slot(
      binding, "mask", stage_index)
    total_n <- capacity
    purpose <- paste0(
      "dp.gaussian-cross.", binding$tag, ".validity-",
      sprintf("%04d", stage_index))
  } else if (identical(stage, "masked-values")) {
    if (stage_index != 1L) {
      stop("The cross-owner Gaussian masked-value stage is out of range.",
           call. = FALSE)
    }
    prior <- binding$stages[[.dsvert_dp_gaussian_cross_stage_key(
      "validity", m - 1L)]]
    if (!.dsvert_dp_gaussian_cross_stage_complete(ss, prior)) {
      stop("The cross-owner Gaussian complete-case mask is incomplete.",
           call. = FALSE)
    }
    mask <- .dsvert_dp_gaussian_cross_raw_slot(
      ss, prior$output_key, capacity,
      "cross-owner Gaussian complete-case mask share")
    value_parts <- lapply(binding$value_keys[binding$variables], function(key) {
      .dsvert_dp_gaussian_cross_raw_slot(
        ss, key, capacity, "cross-owner Gaussian value share")
    })
    x_key <- .dsvert_dp_gaussian_cross_slot(binding, "masked_x")
    y_key <- .dsvert_dp_gaussian_cross_slot(binding, "masked_y")
    installed <- .dsvert_dp_gaussian_cross_install_derived(
      ss, x_key, rep(mask, m), capacity * m, installed)
    installed <- .dsvert_dp_gaussian_cross_install_derived(
      ss, y_key, do.call(c, value_parts), capacity * m, installed)
    output_key <- .dsvert_dp_gaussian_cross_slot(binding, "masked")
    total_n <- capacity * m
    purpose <- paste0(
      "dp.gaussian-cross.", binding$tag, ".masked-values")
  } else {
    if (stage_index != 1L) {
      stop("The cross-owner Gaussian moment stage is out of range.",
           call. = FALSE)
    }
    prior <- binding$stages[[.dsvert_dp_gaussian_cross_stage_key(
      "masked-values", 1L)]]
    if (!.dsvert_dp_gaussian_cross_stage_complete(ss, prior)) {
      stop("The cross-owner Gaussian masked values are incomplete.",
           call. = FALSE)
    }
    masked <- .dsvert_dp_gaussian_cross_raw_slot(
      ss, prior$output_key, capacity * m,
      "cross-owner Gaussian masked-value share")
    masked_parts <- lapply(seq_len(m), function(index) {
      first <- (index - 1L) * capacity * 16L + 1L
      masked[seq.int(first, length.out = capacity * 16L)]
    })
    value_parts <- lapply(binding$value_keys[binding$variables], function(key) {
      .dsvert_dp_gaussian_cross_raw_slot(
        ss, key, capacity, "cross-owner Gaussian value share")
    })
    left <- right <- list()
    pair <- 1L
    for (right_index in seq_len(m)) {
      for (left_index in seq_len(right_index)) {
        left[[pair]] <- masked_parts[[left_index]]
        right[[pair]] <- value_parts[[right_index]]
        pair <- pair + 1L
      }
    }
    pair_count <- m * (m + 1L) / 2L
    x_key <- .dsvert_dp_gaussian_cross_slot(binding, "moment_x")
    y_key <- .dsvert_dp_gaussian_cross_slot(binding, "moment_y")
    installed <- .dsvert_dp_gaussian_cross_install_derived(
      ss, x_key, do.call(c, left), capacity * pair_count, installed)
    installed <- .dsvert_dp_gaussian_cross_install_derived(
      ss, y_key, do.call(c, right), capacity * pair_count, installed)
    output_key <- .dsvert_dp_gaussian_cross_slot(binding, "moments")
    total_n <- capacity * pair_count
    purpose <- paste0(
      "dp.gaussian-cross.", binding$tag, ".moments")
  }
  if (!is.finite(total_n) || total_n != floor(total_n) || total_n < 1L ||
      total_n > 2^31 - 1) {
    for (key in installed) ss[[key]] <- NULL
    stop(structure(
      list(
        message = "The cross-owner Gaussian exact stage is not representable.",
        call = NULL,
        reason = "cross_gaussian_exact_stage_shape_unrepresentable"),
      class = c("dsvert_resource_shape_unrepresentable", "error",
                "condition")))
  }
  list(
    stage = stage, stage_index = stage_index,
    x_key = x_key, y_key = y_key, output_key = output_key,
    total_n = as.integer(total_n), purpose = purpose,
    installed = installed)
}

.dsvert_dp_gaussian_cross_stage_public <- function(
    binding, spec, minted, state) {
  c(minted, list(
    version = .DSVERT_DP_GAUSSIAN_CROSS_STAGE_VERSION,
    state = state, producer = .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER,
    purpose = spec$purpose, capsule_id = binding$capsule_id,
    analysis_id = binding$analysis_id, stage = spec$stage,
    stage_index = spec$stage_index,
    artifact_sha256 = binding$artifact_sha256,
    source_contract_hash = binding$source_contract_hash,
    transcript_sha256 = binding$transcript_sha256,
    numeric_certificate_sha256 = binding$numeric_certificate_sha256,
    exact_intermediates_exposed = FALSE,
    source_values_exposed = FALSE))
}

.dsvert_dp_gaussian_cross_prepare_impl <- function(
    analysis_id, stage, stage_index, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  binding <- .dsvert_dp_gaussian_cross_binding(ss, analysis_id)
  key <- .dsvert_dp_gaussian_cross_stage_key(stage, stage_index)
  previous <- binding$stages[[key]]
  if (!is.null(previous)) {
    manifest <- ss$.exact_gc_vecmul_manifests[[previous$manifest_handle]]
    if (!is.list(manifest)) {
      stop("The cross-owner Gaussian exact-stage manifest disappeared.",
           call. = FALSE)
    }
    .exact_gc_vecmul_validate_manifest_mac(ss, manifest)
    state <- if (.dsvert_dp_gaussian_cross_stage_complete(ss, previous)) {
      "complete"
    } else if (identical(manifest$state, "fresh")) {
      "prepared"
    } else {
      stop("The cross-owner Gaussian exact stage has an incomplete retry.",
           call. = FALSE)
    }
    return(.dsvert_dp_gaussian_cross_stage_public(
      binding, previous, previous$minted, state))
  }
  spec <- .dsvert_dp_gaussian_cross_stage_spec(
    ss, binding, stage, stage_index)
  if (!is.null(ss[[spec$output_key]])) {
    for (slot in spec$installed) ss[[slot]] <- NULL
    stop("The cross-owner Gaussian exact destination is already in use.",
         call. = FALSE)
  }
  record <- c(spec, list(
    status = "preparing", producer = .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER,
    ring_bits = 128L, frac_bits = binding$grid_bits,
    operand_bound = format(
      2^binding$grid_bits, scientific = FALSE, trim = TRUE),
    artifact_sha256 = binding$artifact_sha256))
  ss$.dp_gaussian_cross_stage <- record
  minted <- tryCatch(
    .exact_gc_vecmul_mint_manifest(
      ss = ss, session_id = session_id,
      producer = .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER,
      purpose = spec$purpose, total_n = spec$total_n),
    error = function(error) {
      for (slot in spec$installed) ss[[slot]] <- NULL
      ss$.dp_gaussian_cross_stage <- NULL
      stop(error)
    })
  record$status <- "prepared"
  record$manifest_handle <- minted$manifest_handle
  record$minted <- minted
  ss$.dp_gaussian_cross_stage <- record
  binding$stages[[key]] <- record
  ss$.dp_gaussian_cross_bindings[[binding$analysis_id]] <- binding
  .dsvert_dp_gaussian_cross_stage_public(
    binding, record, minted, "prepared")
}

#' Prepare one fixed cross-owner Gaussian exact multiplication (AGGREGATE)
#'
#' @export
dsvertDPGaussianCrossPrepareDS <- function(
    analysis_id, stage, stage_index, session_id) {
  tryCatch(
    .dsvert_dp_gaussian_cross_prepare_impl(
      analysis_id, stage, stage_index, session_id),
    error = .dsvert_dp_transcript_stop)
}

.dsvert_dp_gaussian_cross_reduce <- function(
    value, segment_length, segment_count, reducer = NULL) {
  segment_length <- as.integer(.exact_gc_integer(
    segment_length, "cross-owner Gaussian reduction segment length", 1,
    .DSVERT_DP_MAX_COORDINATES))
  segment_count <- as.integer(.exact_gc_integer(
    segment_count, "cross-owner Gaussian reduction segment count", 1,
    .DSVERT_DP_MAX_COORDINATES))
  total <- as.numeric(segment_length) * segment_count
  if (!is.finite(total) || total > 2^31 - 1) {
    stop("The cross-owner Gaussian reduction shape is not representable.",
         call. = FALSE)
  }
  decoded <- .exact_gc_validate_residue_records(
    value, 128L, as.integer(total),
    "cross-owner Gaussian reducible share")
  if (is.null(reducer)) {
    reducer <- function(input) {
      .callMpcTool("ring128-sum-records-v1", input)
    }
  }
  if (!is.function(reducer)) {
    stop("Invalid cross-owner Gaussian Ring128 reducer.", call. = FALSE)
  }
  per_batch <- max(1L, min(
    segment_count,
    floor(.DSVERT_DP_GAUSSIAN_CROSS_REDUCER_MAX_RECORDS /
            segment_length)))
  result <- raw()
  first_segment <- 1L
  while (first_segment <= segment_count) {
    count <- min(per_batch, segment_count - first_segment + 1L)
    first_byte <- (first_segment - 1L) * segment_length * 16L + 1L
    byte_count <- count * segment_length * 16L
    bytes <- decoded[seq.int(first_byte, length.out = byte_count)]
    reduced <- reducer(list(
      version = .DSVERT_DP_GAUSSIAN_CROSS_REDUCER_VERSION,
      records = .dsvert_dp_gaussian_cross_standard_b64(
        bytes, "cross-owner Gaussian reduction batch"),
      segment_lengths = rep.int(segment_length, count)))
    expected <- c("version", "segment_count", "sums")
    if (!is.list(reduced) || is.null(names(reduced)) ||
        anyNA(names(reduced)) || anyDuplicated(names(reduced)) ||
        !setequal(names(reduced), expected) ||
        !identical(reduced$version,
                   .DSVERT_DP_GAUSSIAN_CROSS_REDUCER_VERSION) ||
        !identical(as.numeric(reduced$segment_count), as.numeric(count))) {
      stop("The cross-owner Gaussian Ring128 reducer violated its contract.",
           call. = FALSE)
    }
    result <- c(result, .exact_gc_validate_residue_records(
      reduced$sums, 128L, count,
      "cross-owner Gaussian reduced share"))
    first_segment <- first_segment + count
  }
  if (length(result) != segment_count * 16L) {
    stop("The cross-owner Gaussian Ring128 reduction is incomplete.",
         call. = FALSE)
  }
  result
}

.dsvert_dp_gaussian_cross_record <- function(value, index, what) {
  if (!is.raw(value) || length(value) %% 16L != 0L) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  index <- as.integer(.exact_gc_integer(
    index, what, 1, length(value) / 16L))
  first <- (index - 1L) * 16L + 1L
  value[seq.int(first, length.out = 16L)]
}

.dsvert_dp_gaussian_cross_moment_index <- function(left, right, m) {
  left <- as.integer(.exact_gc_integer(left, "Gaussian moment left index", 1, m))
  right <- as.integer(.exact_gc_integer(
    right, "Gaussian moment right index", 1, m))
  if (left > right) {
    swap <- left
    left <- right
    right <- swap
  }
  as.integer(right * (right - 1L) / 2L + left)
}

.dsvert_dp_gaussian_cross_assemble <- function(
    binding, count, masked, moments) {
  m <- binding$variable_count
  predictor_count <- m - 1L
  pair_count <- as.integer(m * (m + 1L) / 2L)
  if (!is.raw(count) || length(count) != 16L ||
      !is.raw(masked) || length(masked) != m * 16L ||
      !is.raw(moments) || length(moments) != pair_count * 16L ||
      predictor_count < 1L) {
    stop("The cross-owner Gaussian reduced moments have the wrong shape.",
         call. = FALSE)
  }
  masked_record <- function(index) {
    .dsvert_dp_gaussian_cross_record(
      masked, index, "Gaussian masked-sum index")
  }
  moment_record <- function(left, right) {
    .dsvert_dp_gaussian_cross_record(
      moments,
      .dsvert_dp_gaussian_cross_moment_index(left, right, m),
      "Gaussian moment index")
  }

  xtx <- list()
  if (isTRUE(binding$artifact$intercept)) {
    design_count <- predictor_count + 1L
    for (right in seq_len(design_count)) {
      for (left in seq_len(right)) {
        xtx[[length(xtx) + 1L]] <- if (left == 1L && right == 1L) {
          count
        } else if (left == 1L) {
          masked_record(right - 1L)
        } else {
          moment_record(left - 1L, right - 1L)
        }
      }
    }
    xty <- c(
      list(masked_record(m)),
      lapply(seq_len(predictor_count), function(index) {
        moment_record(index, m)
      }))
  } else {
    for (right in seq_len(predictor_count)) {
      for (left in seq_len(right)) {
        xtx[[length(xtx) + 1L]] <- moment_record(left, right)
      }
    }
    xty <- lapply(seq_len(predictor_count), function(index) {
      moment_record(index, m)
    })
  }
  records <- c(
    list(count), xtx, xty, list(moment_record(m, m)))
  result <- do.call(c, records)
  if (!is.raw(result) ||
      length(result) != binding$artifact$coordinate_count * 16L) {
    stop("The signed cross-owner Gaussian release order is inconsistent.",
         call. = FALSE)
  }
  result
}

.dsvert_dp_gaussian_cross_transcript <- function(ss, binding) {
  expected <- c(
    lapply(seq_len(binding$variable_count - 1L), function(index) {
      c(stage = "validity", stage_index = index)
    }),
    list(c(stage = "masked-values", stage_index = 1L)),
    list(c(stage = "moments", stage_index = 1L)))
  records <- lapply(expected, function(item) {
    key <- .dsvert_dp_gaussian_cross_stage_key(
      unname(item[["stage"]]), as.integer(item[["stage_index"]]))
    record <- binding$stages[[key]]
    if (!.dsvert_dp_gaussian_cross_stage_complete(ss, record)) {
      stop("The fixed cross-owner Gaussian exact transcript is incomplete.",
           call. = FALSE)
    }
    manifest <- ss$.exact_gc_vecmul_manifests[[record$manifest_handle]]
    .exact_gc_vecmul_validate_manifest_mac(ss, manifest)
    input_stage <- ss$.exact_gc_vecmul_input_stages[[manifest$claimed_batch]]
    list(
      stage = record$stage, stage_index = record$stage_index,
      purpose = record$purpose,
      manifest_context_hash = manifest$context_hash,
      claimed_batch = manifest$claimed_batch,
      claim_context_hash = input_stage$context_hash,
      plan_id = manifest$plan$plan_id,
      total_n = manifest$total_n, ring_bits = manifest$plan$ring_bits,
      frac_bits = manifest$plan$frac_bits,
      backend = manifest$plan$backend)
  })
  list(
    version = "dsvert-cross-gaussian-completed-transcript-v1",
    capsule_id = binding$capsule_id,
    analysis_id = binding$analysis_id,
    peer_binding_digest = binding$peer_binding_digest,
    artifact_sha256 = binding$artifact_sha256,
    stages = records)
}

.dsvert_dp_gaussian_cross_result_validate <- function(
    record, policy, contract, artifact, block, verifier = NULL) {
  required <- c(
    "version", "status", "capsule_id", "analysis_id", "peer_name",
    "artifact_sha256", "source_contract_hash", "private_layout_sha256",
    "transcript_sha256", "numeric_certificate_sha256",
    "exact_transcript_sha256", "coordinate_count", "release_start",
    "release_end", "release_coordinate_order_sha256", "result_share_b64",
    "result_share_sha256", "receipt_json", "receipt_sha256")
  valid <- is.list(record) && !is.null(names(record)) &&
    !anyNA(names(record)) && !anyDuplicated(names(record)) &&
    setequal(names(record), required) &&
    identical(record$version, .DSVERT_DP_GAUSSIAN_CROSS_RESULT_VERSION) &&
    identical(record$status, "complete") &&
    identical(record$capsule_id, contract$capsule_id) &&
    identical(record$analysis_id, artifact$analysis_id) &&
    identical(record$peer_name, policy$peer_name) &&
    identical(record$artifact_sha256, .dsvert_joint_dp_hash(artifact)) &&
    identical(record$source_contract_hash,
              .dsvert_joint_dp_hash(contract)) &&
    identical(record$private_layout_sha256,
              contract$private_layout_sha256) &&
    identical(record$transcript_sha256,
              .dsvert_joint_dp_hash(artifact$transcript)) &&
    identical(record$numeric_certificate_sha256,
              .dsvert_joint_dp_hash(artifact$numeric_certificate)) &&
    grepl("^[0-9a-f]{64}$", record$exact_transcript_sha256) &&
    identical(as.numeric(record$coordinate_count),
              as.numeric(block$length)) &&
    identical(as.numeric(record$release_start), as.numeric(block$start)) &&
    identical(as.numeric(record$release_end), as.numeric(block$end)) &&
    identical(record$release_coordinate_order_sha256,
              contract$release_coordinate_order_sha256) &&
    grepl("^[0-9a-f]{64}$", record$result_share_sha256) &&
    grepl("^[0-9a-f]{64}$", record$receipt_sha256)
  if (!isTRUE(valid)) {
    stop("The persisted cross-owner Gaussian result contract is invalid.",
         call. = FALSE)
  }
  share <- .dsvert_dp_capsule_source_b64_raw(
    record$result_share_b64, "cross-owner Gaussian result share",
    block$length * 16L)
  if (!identical(
        digest::digest(share, algo = "sha256", serialize = FALSE),
        record$result_share_sha256) ||
      !identical(
        digest::digest(record$receipt_json, algo = "sha256",
                       serialize = FALSE),
        record$receipt_sha256)) {
    stop("The persisted cross-owner Gaussian result payload is invalid.",
         call. = FALSE)
  }
  receipt <- .dsvert_dp_capsule_source_decode_json(
    record$receipt_json, "cross-owner Gaussian result receipt", 128L * 1024L)
  receipt_required <- c(
    "version", "phase", "capsule_id", "analysis_id", "peer_name",
    "peer_identity_pk", "artifact_sha256", "source_contract_hash",
    "private_layout_sha256", "transcript_sha256",
    "numeric_certificate_sha256", "exact_transcript_sha256",
    "coordinate_count", "release_start", "release_end",
    "release_coordinate_order_sha256", "ring_bits", "frac_bits", "state",
    "fixed_transcript", "result_share_exposed",
    "exact_intermediates_exposed", "alignment_hash_exposed",
    "alignment_hash_exposed_to_relay",
    "alignment_hash_exposed_to_computation_peers", "signature")
  receipt_valid <- is.list(receipt) && !is.null(names(receipt)) &&
    !anyNA(names(receipt)) && !anyDuplicated(names(receipt)) &&
    setequal(names(receipt), receipt_required) &&
    identical(receipt$version,
              .DSVERT_DP_GAUSSIAN_CROSS_RECEIPT_VERSION) &&
    identical(receipt$phase, "cross_gaussian_result_share_persisted") &&
    identical(receipt$capsule_id, record$capsule_id) &&
    identical(receipt$analysis_id, record$analysis_id) &&
    identical(receipt$peer_name, record$peer_name) &&
    identical(receipt$peer_identity_pk,
              unname(policy$peer_pinset[[policy$peer_name]])) &&
    identical(receipt$artifact_sha256, record$artifact_sha256) &&
    identical(receipt$source_contract_hash, record$source_contract_hash) &&
    identical(receipt$private_layout_sha256,
              record$private_layout_sha256) &&
    identical(receipt$transcript_sha256, record$transcript_sha256) &&
    identical(receipt$numeric_certificate_sha256,
              record$numeric_certificate_sha256) &&
    identical(receipt$exact_transcript_sha256,
              record$exact_transcript_sha256) &&
    identical(as.numeric(receipt$coordinate_count),
              as.numeric(record$coordinate_count)) &&
    identical(as.numeric(receipt$release_start),
              as.numeric(record$release_start)) &&
    identical(as.numeric(receipt$release_end),
              as.numeric(record$release_end)) &&
    identical(receipt$release_coordinate_order_sha256,
              record$release_coordinate_order_sha256) &&
    identical(as.numeric(receipt$ring_bits), 128) &&
    identical(as.numeric(receipt$frac_bits),
              as.numeric(artifact$numeric_grid_bits)) &&
    identical(receipt$state, "complete") &&
    identical(receipt$fixed_transcript, TRUE) &&
    identical(receipt$result_share_exposed, FALSE) &&
    identical(receipt$exact_intermediates_exposed, FALSE) &&
    identical(receipt$alignment_hash_exposed, FALSE) &&
    identical(receipt$alignment_hash_exposed_to_relay, FALSE) &&
    identical(receipt$alignment_hash_exposed_to_computation_peers, FALSE) &&
    .dsvert_dp_capsule_source_verify(
      receipt, policy, "cross-gaussian-result", policy$peer_name,
      verifier)
  if (!isTRUE(receipt_valid)) {
    stop("The persisted cross-owner Gaussian result receipt is invalid.",
         call. = FALSE)
  }
  record
}

.dsvert_dp_gaussian_cross_finalize_impl <- function(
    manifest_json, analysis_id, session_id,
    .policy = NULL, .secret = NULL, .signer = NULL, .verifier = NULL,
    .reducer = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  analysis_id <- .dsvert_dp_capsule_id(
    analysis_id, "cross-owner Gaussian analysis id")
  session_id <- .dsvert_relay_validate_session_id(session_id)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  validated <- .dsvert_dp_capsule_materializer_manifest(.policy, manifest)
  artifact <- .dsvert_dp_gaussian_cross_artifacts(manifest)[[analysis_id]]
  if (is.null(artifact)) {
    stop("The signed capsule has no cross-owner Gaussian artifact.",
         call. = FALSE)
  }
  parsed <- .dsvert_dp_capsule_source_contract_json(.policy, manifest_json)
  contract <- .dsvert_dp_capsule_source_contract_validate(parsed$contract)
  layout <- validated$layout
  block <- layout$blocks[[paste("gaussian_models", analysis_id, sep = "::")]]
  if (!is.list(block) ||
      !identical(as.numeric(block$length),
                 as.numeric(artifact$coordinate_count)) ||
      !.dsvert_dp_capsule_source_cross_contract(contract) ||
      !.policy$peer_name %in% .dsvert_dp_capsule_source_names(
        contract$designated_noise_peers, "noise-peer list")) {
    stop("The cross-owner Gaussian release contract is invalid.",
         call. = FALSE)
  }

  .dsvert_dp_capsule_source_with_store(.policy, .secret, function(connection) {
    prior <- .dsvert_dp_gaussian_cross_result_load(
      connection, contract$capsule_id, analysis_id, .secret)
    if (!is.null(prior)) {
      prior <- .dsvert_dp_gaussian_cross_result_validate(
        prior, .policy, contract, artifact, block, .verifier)
      return(prior$receipt_json)
    }

    ss <- .S(session_id)
    binding <- .dsvert_dp_gaussian_cross_binding(ss, analysis_id)
    if (!identical(binding$capsule_id, contract$capsule_id) ||
        !identical(binding$source_contract_hash, parsed$contract_hash) ||
        !identical(binding$artifact_sha256,
                   .dsvert_joint_dp_hash(artifact)) ||
        !identical(binding$private_layout_sha256,
                   contract$private_layout_sha256) ||
        !isTRUE(artifact$numeric_certificate$modular_wrap_proved_absent) ||
        !identical(as.numeric(artifact$numeric_certificate$ring_bits), 128) ||
        !identical(as.numeric(artifact$numeric_certificate$frac_bits),
                   as.numeric(binding$grid_bits)) ||
        !identical(
          artifact$numeric_certificate$overflow_behavior,
          "typed_abort_before_commit")) {
      stop("The cross-owner Gaussian numeric binding is invalid.",
           call. = FALSE)
    }
    transcript <- .dsvert_dp_gaussian_cross_transcript(ss, binding)
    exact_transcript_hash <- .dsvert_joint_dp_hash(transcript)
    final_validity <- binding$stages[[
      .dsvert_dp_gaussian_cross_stage_key(
        "validity", binding$variable_count - 1L)]]
    masked_stage <- binding$stages[[
      .dsvert_dp_gaussian_cross_stage_key("masked-values", 1L)]]
    moment_stage <- binding$stages[[
      .dsvert_dp_gaussian_cross_stage_key("moments", 1L)]]
    count <- .dsvert_dp_gaussian_cross_reduce(
      ss[[final_validity$output_key]], binding$capacity, 1L, .reducer)
    masked <- .dsvert_dp_gaussian_cross_reduce(
      ss[[masked_stage$output_key]], binding$capacity,
      binding$variable_count, .reducer)
    pair_count <- as.integer(
      binding$variable_count * (binding$variable_count + 1L) / 2L)
    moments <- .dsvert_dp_gaussian_cross_reduce(
      ss[[moment_stage$output_key]], binding$capacity,
      pair_count, .reducer)
    result_share <- .dsvert_dp_gaussian_cross_assemble(
      binding, count, masked, moments)
    result_b64 <- .dsvert_dp_capsule_source_raw_b64(result_share)
    receipt_unsigned <- list(
      version = .DSVERT_DP_GAUSSIAN_CROSS_RECEIPT_VERSION,
      phase = "cross_gaussian_result_share_persisted",
      capsule_id = contract$capsule_id, analysis_id = analysis_id,
      peer_name = .policy$peer_name,
      peer_identity_pk = unname(.policy$peer_pinset[[.policy$peer_name]]),
      artifact_sha256 = binding$artifact_sha256,
      source_contract_hash = parsed$contract_hash,
      private_layout_sha256 = binding$private_layout_sha256,
      transcript_sha256 = binding$transcript_sha256,
      numeric_certificate_sha256 = binding$numeric_certificate_sha256,
      exact_transcript_sha256 = exact_transcript_hash,
      coordinate_count = block$length,
      release_start = block$start, release_end = block$end,
      release_coordinate_order_sha256 =
        contract$release_coordinate_order_sha256,
      ring_bits = 128L, frac_bits = binding$grid_bits,
      state = "complete", fixed_transcript = TRUE,
      result_share_exposed = FALSE, exact_intermediates_exposed = FALSE,
      alignment_hash_exposed = FALSE,
      alignment_hash_exposed_to_relay = FALSE,
      alignment_hash_exposed_to_computation_peers = FALSE)
    receipt_json <- .dsvert_dp_capsule_source_encode_json(
      .dsvert_dp_capsule_source_sign(
        receipt_unsigned, .policy, "cross-gaussian-result", .signer))
    record <- list(
      version = .DSVERT_DP_GAUSSIAN_CROSS_RESULT_VERSION,
      status = "complete", capsule_id = contract$capsule_id,
      analysis_id = analysis_id, peer_name = .policy$peer_name,
      artifact_sha256 = binding$artifact_sha256,
      source_contract_hash = parsed$contract_hash,
      private_layout_sha256 = binding$private_layout_sha256,
      transcript_sha256 = binding$transcript_sha256,
      numeric_certificate_sha256 = binding$numeric_certificate_sha256,
      exact_transcript_sha256 = exact_transcript_hash,
      coordinate_count = block$length,
      release_start = block$start, release_end = block$end,
      release_coordinate_order_sha256 =
        contract$release_coordinate_order_sha256,
      result_share_b64 = result_b64,
      result_share_sha256 = digest::digest(
        result_share, algo = "sha256", serialize = FALSE),
      receipt_json = receipt_json,
      receipt_sha256 = digest::digest(
        receipt_json, algo = "sha256", serialize = FALSE))
    .dsvert_dp_capsule_source_transaction(connection, {
      .dsvert_dp_capsule_source_record_insert(
        connection, "source_cross_gaussian_results",
        c("capsule_id", "analysis_id"),
        list(contract$capsule_id, analysis_id), record, .secret)
    })
    .dsvert_dp_gaussian_cross_result_validate(
      record, .policy, contract, artifact, block, .verifier)

    private_keys <- unique(c(
      unname(binding$value_keys), unname(binding$validity_keys),
      unlist(lapply(binding$stages, function(stage) {
        c(stage$installed, stage$output_key)
      }), use.names = FALSE)))
    for (key in private_keys[nzchar(private_keys)]) ss[[key]] <- NULL
    binding$state <- "finalized"
    binding$result_exact_transcript_sha256 <- exact_transcript_hash
    ss$.dp_gaussian_cross_bindings[[analysis_id]] <- binding
    receipt_json
  })
}

#' Finalize one fixed cross-owner Gaussian exact transcript (AGGREGATE)
#'
#' @export
dsvertDPGaussianCrossFinalizeDS <- function(
    manifest_json, analysis_id, session_id) {
  tryCatch({
    manifest_json <- .dsvert_dsi_text_decode(
      manifest_json, "biomedical capsule manifest",
      .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES)
    policy <- .dsvert_dp_policy()
    secret <- .dsvert_dp_secret()
    .dsvert_dp_capsule_manifest_require_built(
      policy, manifest_json, secret)
    .dsvert_dp_gaussian_cross_finalize_impl(
      manifest_json, analysis_id, session_id,
      .policy = policy, .secret = secret)
  }, error = .dsvert_dp_transcript_stop)
}
