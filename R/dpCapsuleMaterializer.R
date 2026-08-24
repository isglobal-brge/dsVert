# Internal local sufficient-statistic materializer for biomedical capsules.
#
# This file intentionally defines no DataSHIELD entry point.  Its result
# contains protected exact statistics and must move directly into a future
# secret-sharing boundary; it must never be printed, serialized to the relay,
# or returned by an aggregate method.

.DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION <-
  "dsvert-biomedical-capsule-local-material-v1"
.DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE <-
  "biomedical_capsule_secret_share_input_only"
.DSVERT_DP_CAPSULE_VALUE_BLOCK <- 65536L

.dsvert_dp_capsule_coordinate_range_abort <- function(index, upper_bound) {
  stop(structure(list(
    message = paste0(
      "A local biomedical capsule coordinate is outside its signed ",
      "manifest bound; secret sharing was not started."),
    call = NULL,
    code = "coordinate_out_of_signed_range",
    coordinate_index = as.integer(index),
    signed_upper_bound = as.character(upper_bound),
    phase = "before_secret_sharing"),
    class = c("dsvert_dp_capsule_coordinate_range_error", "error",
              "condition")))
}

.dsvert_dp_capsule_assert_signed_coordinate_bounds <- function(
    values, validated) {
  values <- .dsvert_dp_integer_vector(
    values, "local biomedical capsule coordinates")
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(validated)
  upper_text <- lattice$raw_upper_bounds
  upper <- suppressWarnings(as.numeric(upper_text))
  if (length(values) != length(upper_text) ||
      length(upper) != length(upper_text) || anyNA(upper) ||
      any(!is.finite(upper)) || any(upper < 0) ||
      any(upper != floor(upper))) {
    stop("The signed biomedical capsule coordinate bounds are invalid.",
         call. = FALSE)
  }
  invalid <- which(values < 0 | values > upper)
  if (length(invalid)) {
    index <- invalid[[1L]]
    .dsvert_dp_capsule_coordinate_range_abort(index, upper_text[[index]])
  }
  invisible(values)
}

.dsvert_dp_capsule_local_key <- function(dataset, column) {
  paste0(
    nchar(dataset, type = "bytes"), ":", dataset, "|",
    nchar(column, type = "bytes"), ":", column)
}

.dsvert_dp_capsule_sorted_names <- function(value) {
  if (!length(value)) character() else
    sort(names(value), method = "radix")
}

.dsvert_dp_capsule_coordinate_layout <- function(manifest) {
  families <- manifest$workload$families
  required <- c(
    "admitted_count", "numeric_moments", "numeric_pair_moments",
    "gaussian_models",
    "fixed_numeric_histograms", "categorical_marginals",
    "categorical_pairs", "correlation_artifacts", "describe_artifacts",
    "survival_artifacts")
  if (!is.list(families) || !all(required %in% names(families))) {
    stop("The biomedical capsule coordinate contract is invalid.",
         call. = FALSE)
  }

  cursor <- 1L
  blocks <- list()
  add <- function(family, key, length, owner_peer, dataset, descriptor) {
    if (!is.numeric(length) || length(length) != 1L || is.na(length) ||
        !is.finite(length) || length < 1 || length != floor(length) ||
        length > .DSVERT_DP_MAX_COORDINATES ||
        cursor > .DSVERT_DP_MAX_COORDINATES - length + 1L) {
      stop("The biomedical capsule coordinate layout is invalid.",
           call. = FALSE)
    }
    start <- cursor
    end <- cursor + as.integer(length) - 1L
    block_id <- paste(family, key, sep = "::")
    if (block_id %in% names(blocks)) {
      stop("The biomedical capsule coordinate layout is ambiguous.",
           call. = FALSE)
    }
    blocks[[block_id]] <<- list(
      family = family, key = key, start = start, end = end,
      length = as.integer(length), owner_peer = owner_peer,
      dataset = dataset, descriptor = descriptor)
    cursor <<- end + 1L
  }

  count <- families$admitted_count
  add("admitted_count", "canonical", 1L, count$owner_peer,
      count$dataset, count)

  numeric <- families$numeric_moments$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(numeric)) {
    artifact <- numeric[[key]]
    add("numeric_moments", key, 3L, artifact$owner_peer,
        artifact$dataset, artifact)
  }

  numeric_pairs <- families$numeric_pair_moments$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(numeric_pairs)) {
    artifact <- numeric_pairs[[key]]
    add("numeric_pair_moments", key, 6L, artifact$owner_peer,
        artifact$dataset, artifact)
  }

  gaussian <- families$gaussian_models$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(gaussian)) {
    artifact <- gaussian[[key]]
    add("gaussian_models", key, artifact$coordinate_count,
        artifact$owner_peer, artifact$dataset, artifact)
  }

  histograms <- families$fixed_numeric_histograms$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(histograms)) {
    artifact <- histograms[[key]]
    add("fixed_numeric_histograms", key,
        artifact$coordinate_count, artifact$owner_peer,
        artifact$dataset, artifact)
  }

  marginals <- families$categorical_marginals$artifacts
  for (key in .dsvert_dp_capsule_sorted_names(marginals)) {
    artifact <- marginals[[key]]
    add("categorical_marginals", key, length(artifact$levels),
        artifact$owner_peer, artifact$dataset, artifact)
  }

  pair_sets <- families$categorical_pairs$sets
  for (set_key in .dsvert_dp_capsule_sorted_names(pair_sets)) {
    set <- pair_sets[[set_key]]
    columns <- set$columns
    names(columns) <- vapply(columns, `[[`, character(1L), "column")
    for (pair in set$included_pairs) {
      pair <- unname(unlist(pair, use.names = FALSE))
      left_column <- columns[[pair[[1L]]]]
      right_column <- columns[[pair[[2L]]]]
      if (is.null(left_column) || is.null(right_column)) {
        stop("The biomedical categorical-pair scope is invalid.",
             call. = FALSE)
      }
      key <- paste(left_column$column, right_column$column, sep = "::")
      descriptor <- list(
        left = left_column, right = right_column,
        repeated_record_policy = set$repeated_record_policy,
        missingness_policy = set$missingness_policy)
      add(
        "categorical_pairs", paste(set_key, key, sep = "::"),
        as.double(length(left_column$levels)) *
          as.double(length(right_column$levels)),
        set$owner_peer, set$dataset, descriptor)
    }
  }

  cross_pairs <- families$categorical_pairs$cross_artifacts %||% list()
  for (analysis_id in .dsvert_dp_capsule_sorted_names(cross_pairs)) {
    artifact <- cross_pairs[[analysis_id]]
    add(
      "categorical_pairs", paste("cross", analysis_id, sep = "::"),
      artifact$coordinate_count, artifact$left$owner_peer,
      artifact$left$dataset, artifact)
  }

  survival <- families$survival_artifacts
  for (key in .dsvert_dp_capsule_sorted_names(survival)) {
    artifact <- survival[[key]]
    add("survival_artifacts", key, artifact$coordinate_count,
        artifact$owner_peer, artifact$dataset, artifact)
  }

  coordinate_count <- cursor - 1L
  expected <- manifest$workload$coordinate_count
  if (!is.numeric(expected) || length(expected) != 1L || is.na(expected) ||
      !is.finite(expected) || expected != floor(expected) ||
      !identical(as.numeric(coordinate_count), as.numeric(expected))) {
    stop("The biomedical capsule coordinate layout does not match its manifest.",
         call. = FALSE)
  }
  list(
    version = "dsvert-biomedical-capsule-coordinate-layout-v4",
    coordinate_count = as.integer(coordinate_count), blocks = blocks,
    sha256 = .dsvert_joint_dp_hash(list(
      version = "dsvert-biomedical-capsule-coordinate-layout-v4",
      coordinate_count = as.integer(coordinate_count),
      admitted_count = count,
      numeric_moments = families$numeric_moments,
      numeric_pair_moments = families$numeric_pair_moments,
      gaussian_models = families$gaussian_models,
      fixed_numeric_histograms = families$fixed_numeric_histograms,
      categorical_marginals = families$categorical_marginals,
      categorical_pairs = families$categorical_pairs,
      correlation_artifacts = families$correlation_artifacts,
      survival_artifacts = families$survival_artifacts)))
}

.dsvert_dp_capsule_quantized_pair_moments <- function(
    left, right, grid_bits) {
  if (!is.numeric(left) || !is.numeric(right) ||
      length(left) != length(right) || anyNA(left) || anyNA(right) ||
      any(!is.finite(left)) || any(!is.finite(right)) ||
      any(left < 0 | left > 1) || any(right < 0 | right > 1) ||
      !is.numeric(grid_bits) || length(grid_bits) != 1L ||
      is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L) {
    stop("Invalid normalized pairwise capsule values.", call. = FALSE)
  }
  scale <- 2^as.integer(grid_bits)
  if (length(left) > floor(.dsvert_dp_exact_integer_limit / scale)) {
    stop("The pairwise capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  statistics <- c(
    count = length(left),
    sum_left = sum(round(left * scale)),
    sum_right = sum(round(right * scale)),
    sumsq_left = sum(round(left^2 * scale)),
    sumsq_right = sum(round(right^2 * scale)),
    cross = sum(round(left * right * scale)))
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The quantized pairwise capsule moments are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_gaussian_stats <- function(
    design, outcome, grid_bits) {
  if (!is.list(design) || !length(design) ||
      !is.numeric(outcome) || anyNA(outcome) ||
      any(!is.finite(outcome)) || any(outcome < 0 | outcome > 1) ||
      !is.numeric(grid_bits) || length(grid_bits) != 1L ||
      is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L) {
    stop("Invalid normalized Gaussian capsule values.", call. = FALSE)
  }
  valid_design <- vapply(design, function(column) {
    is.numeric(column) && length(column) == length(outcome) &&
      !anyNA(column) && all(is.finite(column)) &&
      all(column >= 0 & column <= 1)
  }, logical(1L))
  if (!all(valid_design)) {
    stop("Invalid normalized Gaussian capsule design.", call. = FALSE)
  }
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(
        .dsvert_dp_exact_integer_limit / scale)) {
    stop("The Gaussian capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  design_count <- length(design)
  gram_count <- design_count * (design_count + 1) / 2
  statistics <- numeric(gram_count + design_count + 2)
  statistics[[1L]] <- length(outcome)
  offset <- 1
  for (right in seq_along(design)) {
    for (left in seq_len(right)) {
      offset <- offset + 1
      statistics[[offset]] <- sum(round(
        design[[left]] * design[[right]] * scale))
    }
  }
  cross <- vapply(design, function(column) {
    sum(round(column * outcome * scale))
  }, numeric(1L))
  statistics[(offset + 1):(offset + design_count)] <- cross
  statistics[[length(statistics)]] <- sum(round(outcome^2 * scale))
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The quantized Gaussian capsule statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_quantized_random_intercept_stats <- function(
    outcome, cluster, grid_bits, max_patients_per_cluster) {
  if (!is.numeric(outcome) || !is.numeric(cluster) ||
      length(outcome) != length(cluster) || anyNA(outcome) ||
      any(!is.finite(outcome)) || any(outcome < 0 | outcome > 1) ||
      anyNA(cluster) || any(!is.finite(cluster)) || any(cluster < 1) ||
      any(cluster != floor(cluster)) || !is.numeric(grid_bits) ||
      length(grid_bits) != 1L || is.na(grid_bits) || !is.finite(grid_bits) ||
      grid_bits != floor(grid_bits) || grid_bits < 8L || grid_bits > 18L ||
      !is.numeric(max_patients_per_cluster) ||
      length(max_patients_per_cluster) != 1L ||
      is.na(max_patients_per_cluster) ||
      !is.finite(max_patients_per_cluster) ||
      max_patients_per_cluster != floor(max_patients_per_cluster) ||
      max_patients_per_cluster < 2) {
    stop("Invalid normalized random-intercept capsule values.",
         call. = FALSE)
  }
  scale <- 2^as.integer(grid_bits)
  if (length(outcome) > floor(.dsvert_dp_exact_integer_limit / scale)) {
    stop("The random-intercept capsule cohort is too large for exact quantization.",
         call. = FALSE)
  }
  if (!length(outcome)) return(rep.int(0, 6L))
  sizes <- tabulate(cluster, nbins = max(cluster, 0L))
  sizes <- sizes[sizes > 0L]
  if (any(sizes > max_patients_per_cluster)) {
    stop("The protected snapshot exceeds its signed LMM cluster capacity.",
         call. = FALSE)
  }
  quantized <- round(outcome * scale)
  quantized_sq <- round(outcome^2 * scale)
  cluster_sum <- rowsum(quantized, cluster, reorder = FALSE)[, 1L]
  cluster_size <- as.numeric(rowsum(
    rep.int(1, length(cluster)), cluster, reorder = FALSE)[, 1L])
  cluster_mean_sq <- sum(round(
    cluster_sum^2 / (cluster_size * scale)))
  statistics <- c(
    n = length(outcome), clusters = length(sizes),
    cluster_size_sq = sum(sizes^2), sum_y = sum(quantized),
    sum_y_sq = sum(quantized_sq),
    sum_cluster_mean_sq = cluster_mean_sq)
  if (anyNA(statistics) || any(!is.finite(statistics)) ||
      any(statistics < 0) || any(statistics != floor(statistics)) ||
      any(statistics > .dsvert_dp_exact_integer_limit)) {
    stop("The random-intercept capsule statistics are not representable.",
         call. = FALSE)
  }
  unname(statistics)
}

.dsvert_dp_capsule_materializer_manifest <- function(policy, manifest) {
  .dsvert_dp_capsule_workload_require_materializable(manifest)
  required <- c(
    "version", "logical_snapshot", "capsule_schema", "admission", "bounds",
    "workload", "capsule_identity", "execution_state")
  if (!is.list(manifest) || is.null(names(manifest)) || anyNA(names(manifest)) ||
      anyDuplicated(names(manifest)) || !setequal(names(manifest), required) ||
      !identical(manifest$version, .DSVERT_DP_CAPSULE_WORKLOAD_VERSION) ||
      !identical(manifest$capsule_schema,
                 .DSVERT_DP_CAPSULE_WORKLOAD_VERSION) ||
      !identical(manifest$execution_state,
                 .DSVERT_DP_CAPSULE_EXECUTION_STATE) ||
      !is.list(manifest$workload) ||
      !identical(manifest$workload$workload_version,
                 .DSVERT_DP_CAPSULE_WORKLOAD_VERSION) ||
      !identical(manifest$workload$execution_state,
                 .DSVERT_DP_CAPSULE_EXECUTION_STATE) ||
      !identical(manifest$workload$declared_workload_fully_materialized,
                 TRUE) ||
      !identical(manifest$workload$package_family_coverage_complete,
                 FALSE) ||
      !identical(
        manifest$workload$registered_release_lifecycle,
        .dsvert_dp_capsule_registered_release_lifecycle())) {
    stop("The biomedical capsule is not a valid registered-lifecycle contract.",
         call. = FALSE)
  }
  logical_snapshot <- .dsvert_joint_dp_logical_snapshot(
    manifest$logical_snapshot)
  identity <- if (.dsvert_dp_synopsis_policy_is_v1(policy)) {
    .dsvert_dp_synopsis_capsule_identity_validate_v1(
      policy, logical_snapshot, manifest$capsule_identity)
  } else {
    .dsvert_joint_dp_capsule_identity_validate(
      policy, logical_snapshot, manifest$capsule_identity)
  }
  contract <- identity$contract
  if (!identical(contract$logical_snapshot, logical_snapshot) ||
      !identical(contract$admission, manifest$admission) ||
      !identical(contract$bounds, manifest$bounds) ||
      !identical(contract$workload, manifest$workload) ||
      !identical(
        .dsvert_dp_canonical_query_value(
          .dsvert_dp_admission_public(policy)),
        manifest$admission) ||
      !identical(
        manifest$workload$capsule_mechanism$source_context_hash,
        .dsvert_joint_dp_hash(list(
          version = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
          logical_snapshot = logical_snapshot,
          schema_manifest_sha256 =
            manifest$workload$schema_attestation$manifest_sha256,
          admission = manifest$admission, bounds = manifest$bounds,
          families = manifest$workload$families,
          vertical_crosses = manifest$workload$vertical_crosses,
          primitive_scope = manifest$workload$primitive_scope,
          release_lattice = manifest$workload$release_lattice,
          mechanism_selection =
            manifest$workload$mechanism_selection)))) {
    stop("The biomedical capsule materializer contract was modified.",
         call. = FALSE)
  }
  layout <- .dsvert_dp_capsule_coordinate_layout(manifest)
  if (!identical(
        as.numeric(layout$coordinate_count),
        as.numeric(manifest$workload$capsule_mechanism$coordinate_count))) {
    stop("The biomedical capsule mechanism has the wrong vector shape.",
         call. = FALSE)
  }
  list(manifest = manifest, identity = identity, layout = layout)
}

.dsvert_dp_capsule_resolved_snapshots <- function(policy, snapshots) {
  if (is.list(snapshots) && all(c("data", "dataset") %in% names(snapshots))) {
    data_name <- tryCatch(
      snapshots$dataset$public$data_name, error = function(e) NULL)
    if (!is.character(data_name) || length(data_name) != 1L ||
        is.na(data_name) || !nzchar(data_name)) {
      stop("The resolved biomedical capsule snapshot is invalid.",
           call. = FALSE)
    }
    snapshots <- stats::setNames(list(snapshots), data_name)
  }
  expected <- sort(names(policy$datasets), method = "radix")
  if (!is.list(snapshots) || is.null(names(snapshots)) ||
      anyNA(names(snapshots)) || any(!nzchar(names(snapshots))) ||
      anyDuplicated(names(snapshots)) ||
      !identical(sort(names(snapshots), method = "radix"), expected)) {
    stop("Resolved snapshots must exactly cover the local capsule datasets.",
         call. = FALSE)
  }
  snapshots <- snapshots[expected]
  for (data_name in expected) {
    snapshot <- snapshots[[data_name]]
    descriptor <- policy$datasets[[data_name]]
    if (!is.list(snapshot) || !all(c("data", "dataset") %in% names(snapshot)) ||
        !is.data.frame(snapshot$data) || !is.list(snapshot$dataset) ||
        !is.list(snapshot$dataset$public) ||
        !identical(snapshot$dataset$public$data_name, data_name) ||
        !identical(snapshot$dataset$public$id, descriptor$id) ||
        !identical(snapshot$dataset$public$version, descriptor$version) ||
        !is.character(snapshot$dataset$fingerprint) ||
        length(snapshot$dataset$fingerprint) != 1L ||
        is.na(snapshot$dataset$fingerprint) ||
        !grepl("^[0-9a-f]{64}$", snapshot$dataset$fingerprint)) {
      stop("The resolved biomedical capsule snapshot binding is invalid.",
           call. = FALSE)
    }
    invisible(.dsvert_dp_snapshot_columns(snapshot$data))
    snapshot_sha256 <- NULL
    if (!is.null(descriptor$snapshot_sha256)) {
      snapshot_sha256 <- .dsvert_dp_snapshot_digest(snapshot$data)
      if (!identical(snapshot_sha256, descriptor$snapshot_sha256)) {
        stop("The resolved biomedical capsule snapshot digest changed.",
             call. = FALSE)
      }
    }
    if (!is.null(descriptor$alignment_manifest_hash)) {
      tryCatch(
        .dsvert_dp_validate_descriptor_alignment(
          snapshot$data, descriptor, policy$patient_column,
          expected_pinset = policy$peer_pinset,
          snapshot_sha256 = snapshot_sha256),
        error = function(e) {
          stop("The resolved biomedical capsule alignment binding changed.",
               call. = FALSE)
        })
    }
  }
  snapshots
}

.dsvert_dp_capsule_bounded_category <- function(
    data, policy, column, levels, admission, strict = FALSE) {
  if (!is.character(levels) || !length(levels) || anyNA(levels) ||
      anyDuplicated(levels) || !column %in% names(data) ||
      !is.atomic(data[[column]]) || !is.logical(strict) ||
      length(strict) != 1L || is.na(strict)) {
    stop("The protected snapshot does not match its categorical capsule contract.",
         call. = FALSE)
  }
  labels <- tryCatch(
    .dsvert_dp_categorical_label_values(
      data[[column]], "protected categorical values"),
    error = function(e) {
      stop("The protected snapshot does not match its categorical capsule contract.",
           call. = FALSE)
    })
  level <- match(labels, levels)
  if (isTRUE(strict)) {
    present_rows <- admission$present[admission$group]
    unknown <- present_rows & !is.na(labels) & is.na(level)
    if (any(unknown)) {
      stop("The protected snapshot has an unknown categorical value.",
           call. = FALSE)
    }
    known_groups <- admission$group[present_rows & !is.na(level)]
    known_levels <- level[present_rows & !is.na(level)]
    if (length(known_groups)) {
      key <- paste(known_groups, known_levels, sep = "\r")
      distinct <- !duplicated(key)
      per_group <- tabulate(known_groups[distinct],
                            nbins = admission$work_units)
      if (any(per_group > 1L)) {
        stop("The protected snapshot has conflicting categorical values.",
             call. = FALSE)
      }
    }
  }
  valid_rows <- which(!is.na(level))
  selected <- rep(NA_integer_, admission$work_units)
  if (length(valid_rows)) {
    groups <- admission$group[valid_rows]
    valid_levels <- level[valid_rows]
    composite <- (as.double(groups) - 1) * length(levels) + valid_levels
    distinct <- !duplicated(composite)
    distinct_per_group <- tabulate(
      groups[distinct], nbins = admission$work_units)
    first <- !duplicated(groups)
    first_groups <- groups[first]
    first_levels <- valid_levels[first]
    consistent <- distinct_per_group[first_groups] == 1L
    selected[first_groups[consistent]] <- first_levels[consistent]
  }
  selected[!admission$present] <- NA_integer_
  list(cell = unname(selected), levels = levels)
}

.dsvert_dp_capsule_survival_spec <- function(artifact, analysis_id) {
  entry <- if (identical(artifact$entry, "none")) NULL else artifact$entry
  list(
    analysis_id = analysis_id, version = artifact$version,
    dataset = artifact$dataset, time = artifact$time,
    event = artifact$event, entry = entry, censor = artifact$censor,
    causes = artifact$causes,
    outcome_levels = c(artifact$censor, artifact$causes),
    time_grid = artifact$time_grid, time_bounds = artifact$time_bounds,
    delayed_entry = !is.null(entry),
    coordinate_count = artifact$coordinate_count,
    l1_sensitivity = artifact$l1_sensitivity,
    l2_sensitivity = artifact$l2_sensitivity)
}

.dsvert_dp_capsule_value_commitment <- function(values, binding) {
  values <- .dsvert_dp_integer_vector(values, "local capsule coordinates")
  starts <- seq.int(1L, length(values), by = .DSVERT_DP_CAPSULE_VALUE_BLOCK)
  block_hashes <- vapply(starts, function(start) {
    end <- min(length(values), start + .DSVERT_DP_CAPSULE_VALUE_BLOCK - 1L)
    digest::digest(
      unname(values[start:end]), algo = "sha256", serialize = TRUE,
      serializeVersion = 3L)
  }, character(1L))
  .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-value-blocks-v1",
    coordinate_count = length(values),
    block_size = .DSVERT_DP_CAPSULE_VALUE_BLOCK,
    block_hashes = unname(block_hashes), binding = binding))
}

.dsvert_dp_capsule_compact_bounded_numeric <- function(bounded) {
  bounded[c("unit_values", "valid")]
}

.dsvert_dp_capsule_materialize_local <- function(
    policy, manifest, resolved_snapshots) {
  contract <- .dsvert_dp_capsule_materializer_manifest(policy, manifest)
  snapshots <- .dsvert_dp_capsule_resolved_snapshots(
    policy, resolved_snapshots)
  layout <- contract$layout
  local_peer <- .dsvert_dp_capsule_id(policy$peer_name, "local peer")
  values <- numeric(layout$coordinate_count)
  admissions <- new.env(parent = emptyenv())
  bounded_numeric <- new.env(parent = emptyenv())
  admission_for <- function(data_name) {
    if (!exists(data_name, envir = admissions, inherits = FALSE)) {
      assign(
        data_name,
        .dsvert_dp_admit_units(snapshots[[data_name]]$data, policy),
        envir = admissions)
    }
    get(data_name, envir = admissions, inherits = FALSE)
  }
  bounded_for <- function(data_name, column) {
    key <- .dsvert_dp_capsule_local_key(data_name, column)
    if (!exists(key, envir = bounded_numeric, inherits = FALSE)) {
      assign(
        key,
        .dsvert_dp_bounded_numeric(
          snapshots[[data_name]]$data, policy, column,
          admission_for(data_name)),
        envir = bounded_numeric)
    }
    get(key, envir = bounded_numeric, inherits = FALSE)
  }

  local_blocks <- layout$blocks[vapply(
    layout$blocks, function(block) identical(block$owner_peer, local_peer),
    logical(1L))]
  cross_artifacts <- manifest$workload$families$gaussian_models$artifacts
  cross_artifacts <- cross_artifacts[vapply(
    cross_artifacts, function(artifact) {
      identical(
        artifact$version,
        "bounded-normalized-gaussian-cross-sufficient-statistics-v1")
    }, logical(1L))]
  owns_cross_input <- any(vapply(cross_artifacts, function(artifact) {
    local_peer %in% unlist(artifact$participating_peers, use.names = FALSE)
  }, logical(1L)))
  if (!length(local_blocks) && !isTRUE(owns_cross_input)) {
    stop("The local peer owns no coordinate in this biomedical capsule.",
         call. = FALSE)
  }
  if (any(!vapply(local_blocks, function(block) {
        block$dataset %in% names(snapshots)
      }, logical(1L)))) {
    stop("A local capsule coordinate has no resolved owner dataset.",
         call. = FALSE)
  }

  count_block <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "admitted_count"]
  if (length(count_block)) {
    block <- count_block[[1L]]
    values[block$start] <- admission_for(block$dataset)$unit_count
  }

  histogram_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") ==
      "fixed_numeric_histograms"]
  histograms_by_numeric <- list()
  for (name in names(histogram_blocks)) {
    block <- histogram_blocks[[name]]
    key <- .dsvert_dp_capsule_local_key(
      block$dataset, block$descriptor$column)
    histograms_by_numeric[[key]] <- c(histograms_by_numeric[[key]], name)
  }

  numeric_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "numeric_moments"]
  for (name in names(numeric_blocks)) {
    block <- numeric_blocks[[name]]
    artifact <- block$descriptor
    bounded <- bounded_for(block$dataset, artifact$column)
    normalised <- (bounded$values - artifact$lower) /
      (artifact$upper - artifact$lower)
    normalised <- pmin(1, pmax(0, normalised))
    moments <- .dsvert_dp_quantized_moments(
      normalised, artifact$numeric_grid_bits)$statistics
    values[block$start:block$end] <- unname(moments)

    numeric_key <- .dsvert_dp_capsule_local_key(
      block$dataset, artifact$column)
    for (histogram_name in histograms_by_numeric[[numeric_key]]) {
      histogram_block <- histogram_blocks[[histogram_name]]
      histogram <- histogram_block$descriptor
      bins <- if (length(bounded$values)) {
        as.integer(findInterval(
          bounded$values, histogram$grid, left.open = TRUE) + 1L)
      } else {
        integer()
      }
      exact <- c(
        tabulate(bins, nbins = length(histogram$grid)),
        sum(bounded$present & !bounded$valid))
      values[histogram_block$start:histogram_block$end] <- exact
      rm(bins, exact)
    }
    assign(
      numeric_key, .dsvert_dp_capsule_compact_bounded_numeric(bounded),
      envir = bounded_numeric)
    rm(bounded, normalised, moments)
  }
  filled_histograms <- unlist(histograms_by_numeric, use.names = FALSE)
  if (length(setdiff(names(histogram_blocks), filled_histograms))) {
    stop("A numeric histogram has no matching numeric capsule artifact.",
         call. = FALSE)
  }

  numeric_pair_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") ==
      "numeric_pair_moments"]
  for (name in names(numeric_pair_blocks)) {
    block <- numeric_pair_blocks[[name]]
    artifact <- block$descriptor
    left <- bounded_for(block$dataset, artifact$left$column)
    right <- bounded_for(block$dataset, artifact$right$column)
    complete <- left$valid & right$valid
    left_normalized <- (left$unit_values[complete] - artifact$left$lower) /
      (artifact$left$upper - artifact$left$lower)
    right_normalized <-
      (right$unit_values[complete] - artifact$right$lower) /
      (artifact$right$upper - artifact$right$lower)
    left_normalized <- pmin(1, pmax(0, left_normalized))
    right_normalized <- pmin(1, pmax(0, right_normalized))
    values[block$start:block$end] <-
      .dsvert_dp_capsule_quantized_pair_moments(
        left_normalized, right_normalized, artifact$numeric_grid_bits)
  }

  gaussian_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "gaussian_models"]
  for (name in names(gaussian_blocks)) {
    block <- gaussian_blocks[[name]]
    artifact <- block$descriptor
    if (identical(
          artifact$version,
          "bounded-normalized-gaussian-cross-sufficient-statistics-v1")) {
      # Cross-owner coordinates are injected only after the fixed exact-GC
      # transcript.  Every ordinary source contributes the all-zero public
      # block here, so no exact moment can enter the sampler by accident.
      next
    }
    if (identical(
          artifact$version,
          "bounded-normalized-random-intercept-moments-v1")) {
      outcome <- bounded_for(block$dataset, artifact$outcome$column)
      cluster <- .dsvert_dp_capsule_bounded_category(
        snapshots[[block$dataset]]$data, policy, artifact$cluster$column,
        artifact$cluster$levels, admission_for(block$dataset))
      complete <- outcome$valid & !is.na(cluster$cell)
      normalized_outcome <- pmin(1, pmax(
        0, (outcome$unit_values[complete] - artifact$outcome$lower) /
          (artifact$outcome$upper - artifact$outcome$lower)))
      statistics <- .dsvert_dp_capsule_quantized_random_intercept_stats(
        normalized_outcome, cluster$cell[complete],
        artifact$numeric_grid_bits, artifact$max_patients_per_cluster)
      if (length(statistics) != block$length) {
        stop("The signed random-intercept capsule coordinate shape is invalid.",
             call. = FALSE)
      }
      values[block$start:block$end] <- statistics
      next
    }
    outcome <- bounded_for(block$dataset, artifact$outcome$column)
    predictors <- lapply(artifact$predictor_order, function(variable) {
      bounded_for(block$dataset, artifact$predictors[[variable]]$column)
    })
    names(predictors) <- artifact$predictor_order
    complete <- outcome$valid
    for (predictor in predictors) complete <- complete & predictor$valid
    normalize <- function(values, lower, upper) {
      pmin(1, pmax(0, (values - lower) / (upper - lower)))
    }
    normalized_outcome <- normalize(
      outcome$unit_values[complete], artifact$outcome$lower,
      artifact$outcome$upper)
    normalized_predictors <- lapply(
      artifact$predictor_order, function(variable) {
        descriptor <- artifact$predictors[[variable]]
        normalize(
          predictors[[variable]]$unit_values[complete],
          descriptor$lower, descriptor$upper)
      })
    design <- c(
      if (isTRUE(artifact$intercept)) {
        list(rep(1, length(normalized_outcome)))
      } else {
        list()
      },
      normalized_predictors)
    statistics <- .dsvert_dp_capsule_quantized_gaussian_stats(
      design, normalized_outcome, artifact$numeric_grid_bits)
    if (length(statistics) != block$length) {
      stop("The signed Gaussian capsule coordinate shape is invalid.",
           call. = FALSE)
    }
    values[block$start:block$end] <- statistics
  }

  marginal_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") ==
      "categorical_marginals"]
  for (name in names(marginal_blocks)) {
    block <- marginal_blocks[[name]]
    artifact <- block$descriptor
    data <- snapshots[[block$dataset]]$data
    bounded <- .dsvert_dp_capsule_bounded_category(
      data, policy, artifact$column, artifact$levels,
      admission_for(block$dataset), strict = identical(
        artifact$missingness_policy,
        paste("missing_values_have_no_marginal_cell_and_unknown_or_conflicting",
              "nonmissing_values_reject_before_release_v1", sep = "_")))
    values[block$start:block$end] <- tabulate(
      bounded$cell, nbins = length(artifact$levels))
  }

  pair_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "categorical_pairs"]
  for (name in names(pair_blocks)) {
    block <- pair_blocks[[name]]
    descriptor <- block$descriptor
    if (identical(
          descriptor$version,
          "fixed-domain-categorical-cross-contingency-v1")) {
      # The public block is filled only by the authenticated exact-GC result
      # shares immediately before the one joint-DP opening.
      next
    }
    data <- snapshots[[block$dataset]]$data
    bounded <- .dsvert_dp_bounded_pairs(
      data, policy, descriptor$left$column, descriptor$right$column,
      admission_for(block$dataset))
    values[block$start:block$end] <- tabulate(
      bounded$cell, nbins = bounded$cell_count)
  }

  survival_blocks <- local_blocks[vapply(
    local_blocks, `[[`, character(1L), "family") == "survival_artifacts"]
  for (name in names(survival_blocks)) {
    block <- survival_blocks[[name]]
    spec <- .dsvert_dp_capsule_survival_spec(
      block$descriptor, block$key)
    exact <- .dsvert_dp_survival_histogram(
      snapshots[[block$dataset]]$data, policy, spec,
      admission_for(block$dataset))$exact
    values[block$start:block$end] <- exact
  }

  values <- .dsvert_dp_integer_vector(
    values, "local biomedical capsule coordinates")
  .dsvert_dp_capsule_assert_signed_coordinate_bounds(values, contract)
  snapshot_binding <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-local-snapshots-v1",
    capsule_id = contract$identity$capsule_id,
    peer_name = local_peer,
    datasets = lapply(snapshots, function(snapshot) list(
      public = snapshot$dataset$public,
      protected_fingerprint = snapshot$dataset$fingerprint))))
  binding <- list(
    version = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION,
    purpose = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE,
    capsule_id = contract$identity$capsule_id,
    peer_name = local_peer,
    logical_snapshot = manifest$logical_snapshot,
    source_context_hash =
      manifest$workload$capsule_mechanism$source_context_hash,
    coordinate_count = layout$coordinate_count,
    coordinate_order_sha256 = layout$sha256,
    snapshot_binding_sha256 = snapshot_binding)
  value_commitment <- .dsvert_dp_capsule_value_commitment(values, binding)
  authenticatable <- .dsvert_joint_dp_hash(list(
    authentication_domain =
      "dsVert/biomedical-capsule/local-secret-share-input/v1|",
    binding = binding, value_commitment_sha256 = value_commitment))
  c(binding, list(
    state = "internal_unshared_secret_share_input_never_release",
    values = values,
    value_commitment_sha256 = value_commitment,
    authenticatable_sha256 = authenticatable))
}
