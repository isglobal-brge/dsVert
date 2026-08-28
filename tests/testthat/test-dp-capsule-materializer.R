.materializer_test_b64url <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.materializer_test_noise_selector <- function(
    coordinate_count, laplace_epsilons, laplace_sensitivities,
    gaussian_epsilon, gaussian_delta, gaussian_l2_sensitivity,
    objective) {
  list(
    selector = .DSVERT_DP_NOISE_SELECTOR,
    objective = objective, coordinate_count = as.integer(coordinate_count),
    winner = "gaussian",
    laplace = list(available = TRUE, simultaneous_95_abs = 100),
    gaussian = list(available = TRUE, simultaneous_95_abs = 50))
}

.materializer_test_data <- function() {
  data.frame(
    patient_id = c("u1", "u1", "u2", "u3"),
    entry = c(0, 0, 2, Inf),
    time = c(4, 8, 10, NA_real_),
    x = c(0, 10, 20, NaN),
    cat_a = c("A", "A", "B", NA_character_),
    cat_b = c("L", "L", "R", "outside"),
    status = c("event", "event", "censor", "outside"),
    stringsAsFactors = FALSE)
}

.materializer_test_fixture <- function(
    data = .materializer_test_data(),
    adjacency = "add_remove_patient", capacity = 5L,
    max_records = 4L, duplicate_describe = FALSE,
    gaussian_specs = list(), survival_specs = NULL, workload_scope = NULL,
    binary_x = FALSE, binary_z = FALSE, multiclass_outcome = FALSE) {
  if (isTRUE(binary_z)) data$z <- c(0, 0, 1, NaN)
  if (isTRUE(multiclass_outcome)) {
    data$class3 <- c("A", "A", "B", "C")
  }
  pins <- c(
    peer_a = .materializer_test_b64url(as.raw(seq_len(32L))),
    peer_b = .materializer_test_b64url(as.raw(32L + seq_len(32L))))
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  policy <- list(
    domain = "materializer-study", cohort_id = "cohort-v1",
    peer_name = "peer_a", peer_pinset = pins,
    peer_pinset_sha256 = pin_hash, peer_count = 2L,
    designated_noise_peers = names(pins),
    lifetime_max_distinct_capsules = 8,
    global_total_epsilon = 1, global_total_delta = 1e-6,
    adjacency = adjacency, patient_column = "patient_id",
    unit_capacity = as.integer(capacity),
    fixed_cohort_size = if (identical(
      adjacency, "replace_one_fixed_cohort")) as.integer(capacity) else NULL,
    max_records_per_unit = as.integer(max_records),
    overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    numeric_grid_bits = 8L,
    numeric_bounds = list(
      entry = c(0, 10), time = c(0, 10),
      x = if (isTRUE(binary_x)) c(0, 1) else c(0, 10)),
    categorical_levels = list(
      cat_a = c("A", "B"), cat_b = c("L", "R"),
      status = c("censor", "event")),
    capsule_workload_scope = workload_scope,
    datasets = list(protected = list(
      id = "materializer-cohort", version = "v1",
      snapshot_sha256 = NULL, alignment_manifest_hash = NULL,
      alignment_manifest_version = 1L)),
    noise_root = list(epoch = 1, key_id = "materializer-test-root"),
    ledger_path = tempfile("materializer-ledger-"))
  if (isTRUE(multiclass_outcome)) {
    policy$categorical_levels$class3 <- c("A", "B", "C")
  }
  logical_snapshot <- list(
    logical_snapshot_id = "materializer-aligned-cohort",
    version = "v1", alignment_protocol_version = 1L)
  schema <- list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = pin_hash,
    datasets = list(protected = list(
      dataset_id = "materializer-cohort", dataset_version = "v1",
      schema_version = "schema-v1", alignment_group = "aligned-main",
      patient_keys = list(peer_a = "patient_id"),
      columns = list(
        entry = list(kind = "numeric", owner_peer = "peer_a",
                     lower = 0, upper = 10),
        time = list(kind = "numeric", owner_peer = "peer_a",
                    lower = 0, upper = 10),
        x = list(kind = "numeric", owner_peer = "peer_a",
                 lower = 0, upper = if (isTRUE(binary_x)) 1 else 10),
        cat_a = list(kind = "categorical", owner_peer = "peer_a",
                     levels = c("A", "B")),
        cat_b = list(kind = "categorical", owner_peer = "peer_a",
                     levels = c("L", "R")),
        status = list(kind = "categorical", owner_peer = "peer_a",
                      levels = c("censor", "event"))))),
    signatures = list(peer_a = strrep("A", 86L),
                      peer_b = strrep("B", 86L)))
  if (isTRUE(multiclass_outcome)) {
    schema$datasets$protected$columns$class3 <- list(
      kind = "categorical", owner_peer = "peer_a", levels = c("A", "B", "C"))
  }
  if (isTRUE(binary_z)) {
    policy$numeric_bounds$z <- c(0, 1)
    schema$datasets$protected$columns$z <- list(
      kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 1)
  }
  describe <- list(primary = list(
    version = "v1", dataset = "protected", variables = "x",
    histogram_grids = list(
      x = if (isTRUE(binary_x)) c(0.5, 1) else c(5, 10)),
    allocation = c(
      count = 0.2, sum = 0.3, sumsq = 0.3, histogram = 0.2)))
  if (isTRUE(duplicate_describe)) describe$duplicate <- describe$primary
  survival <- list(primary = list(
    version = "v1", dataset = "protected", time = "time",
    event = "status", censor = "censor", time_grid = c(5, 10),
    entry = "entry"))
  if (!is.null(survival_specs)) survival <- survival_specs
  manifest <- .dsvert_dp_capsule_workload_manifest(
    policy, logical_snapshot, schema,
    describe_specs = describe, survival_specs = survival,
    gaussian_specs = gaussian_specs,
    .noise_selector = .materializer_test_noise_selector,
    .signature_verifier = function(...) TRUE)
  resolved <- list(protected = list(
    data = data,
    dataset = list(
      public = list(
        data_name = "protected", id = "materializer-cohort",
        version = "v1", alignment_manifest_hash = NULL,
        alignment_manifest_version = 1L),
      fingerprint = strrep("a", 64L))))
  list(
    policy = policy, schema = schema, logical_snapshot = logical_snapshot,
    manifest = manifest, resolved = resolved, data = data,
    describe = describe, survival = survival)
}

.materializer_test_vertical_fixture <- function(
    peer, gaussian_specs = list(), capacity = 2L, padded_v3 = FALSE) {
  stopifnot(peer %in% c("peer_a", "peer_b"))
  stopifnot(length(capacity) == 1L, !is.na(capacity),
            capacity == floor(capacity), capacity >= 2L)
  capacity <- as.integer(capacity)
  pins <- c(
    peer_a = .materializer_test_b64url(as.raw(seq_len(32L))),
    peer_b = .materializer_test_b64url(as.raw(32L + seq_len(32L))))
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  local_a <- identical(peer, "peer_a")
  data_name <- if (local_a) "protected" else "remote"
  dataset_id <- if (isTRUE(padded_v3)) {
    "vertical-cohort"
  } else if (local_a) {
    "cohort-a"
  } else {
    "cohort-b"
  }
  variable <- if (local_a) "x" else "z"
  bounds <- if (local_a) c(0, 10) else c(-1, 1)
  data <- data.frame(patient_id = sprintf("u%08d", seq_len(capacity)))
  data[[variable]] <- seq(bounds[[1L]], bounds[[2L]],
                          length.out = capacity)
  policy <- list(
    domain = "vertical-materializer", cohort_id = "cohort-v1",
    peer_name = peer, peer_pinset = pins,
    peer_pinset_sha256 = pin_hash, peer_count = 2L,
    designated_noise_peers = names(pins),
    lifetime_max_distinct_capsules = 8,
    global_total_epsilon = 1, global_total_delta = 1e-6,
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = capacity, fixed_cohort_size = NULL,
    max_records_per_unit = 1L, overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    numeric_grid_bits = 8L,
    numeric_bounds = stats::setNames(list(bounds), variable),
    categorical_levels = list(),
    datasets = stats::setNames(list(list(
      id = dataset_id, version = "v1", snapshot_sha256 = NULL,
      alignment_manifest_hash = NULL,
      alignment_manifest_version = 1L)), data_name),
    noise_root = list(epoch = 1, key_id = "vertical-materializer-root"),
    ledger_path = tempfile("vertical-materializer-ledger-"))
  logical_snapshot <- list(
    logical_snapshot_id = "vertical-aligned-cohort",
    version = "v1", alignment_protocol_version = 1L)
  schema <- list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = pin_hash,
    datasets = list(
      protected = list(
        dataset_id = if (isTRUE(padded_v3)) {
          "vertical-cohort"
        } else "cohort-a", dataset_version = "v1",
        schema_version = "schema-v1", alignment_group = "aligned-main",
        patient_keys = list(peer_a = "patient_id"),
        columns = list(x = list(
          kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 10))),
      remote = list(
        dataset_id = if (isTRUE(padded_v3)) {
          "vertical-cohort"
        } else "cohort-b", dataset_version = "v1",
        schema_version = "schema-v1", alignment_group = "aligned-main",
        patient_keys = list(peer_b = "patient_id"),
        columns = list(z = list(
          kind = "numeric", owner_peer = "peer_b", lower = -1, upper = 1)))),
    signatures = list(peer_a = strrep("A", 86L),
                      peer_b = strrep("B", 86L)))
  manifest <- .dsvert_dp_capsule_workload_manifest(
    policy, logical_snapshot, schema,
    describe_specs = list(), survival_specs = list(),
    gaussian_specs = gaussian_specs,
    .noise_selector = .materializer_test_noise_selector,
    .signature_verifier = function(...) TRUE)
  if (isTRUE(padded_v3)) {
    padded <- .dsvert_test_padded_dp_binding(
      data, "patient_id", dataset_id, "v1", pins)
    data <- padded$data
    policy$datasets[[data_name]] <- padded$descriptor
  }
  resolved <- stats::setNames(list(list(
    data = data, dataset = list(
      public = list(
        data_name = data_name, id = dataset_id, version = "v1",
        alignment_manifest_hash = if (isTRUE(padded_v3)) {
          policy$datasets[[data_name]]$alignment_manifest_hash
        } else NULL,
        alignment_manifest_version = if (isTRUE(padded_v3)) {
          policy$datasets[[data_name]]$alignment_manifest_version
        } else 1L),
      fingerprint = if (local_a) strrep("a", 64L) else strrep("b", 64L)))),
    data_name)
  list(policy = policy, manifest = manifest, resolved = resolved)
}

.materializer_test_oracle <- function(fixture) {
  data <- fixture$data
  manifest <- fixture$manifest
  families <- manifest$workload$families
  ids <- enc2utf8(as.character(data$patient_id))
  unit_ids <- sort(unique(ids), method = "radix")
  unit_rows <- lapply(unit_ids, function(id) which(ids == id))
  names(unit_rows) <- unit_ids
  exact <- length(unit_rows)

  numeric_unit <- function(artifact) {
    vapply(unit_rows, function(rows) {
      values <- as.numeric(data[[artifact$column]][rows])
      values <- values[is.finite(values)]
      if (!length(values)) return(NA_real_)
      mean(pmin(artifact$upper, pmax(artifact$lower, values)))
    }, numeric(1L))
  }
  numeric_values <- list()
  numeric <- families$numeric_moments$artifacts
  for (name in sort(names(numeric), method = "radix")) {
    artifact <- numeric[[name]]
    values <- numeric_unit(artifact)
    numeric_values[[.dsvert_dp_capsule_local_key(
      artifact$dataset, artifact$column)]] <- values
    values <- values[is.finite(values)]
    z <- (values - artifact$lower) / (artifact$upper - artifact$lower)
    scale <- 2^artifact$numeric_grid_bits
    exact <- c(exact, length(z), sum(round(z * scale)),
               sum(round(z^2 * scale)))
  }

  numeric_pairs <- families$numeric_pair_moments$artifacts
  for (name in sort(names(numeric_pairs), method = "radix")) {
    artifact <- numeric_pairs[[name]]
    left <- numeric_values[[.dsvert_dp_capsule_local_key(
      artifact$dataset, artifact$left$column)]]
    right <- numeric_values[[.dsvert_dp_capsule_local_key(
      artifact$dataset, artifact$right$column)]]
    complete <- is.finite(left) & is.finite(right)
    left <- (left[complete] - artifact$left$lower) /
      (artifact$left$upper - artifact$left$lower)
    right <- (right[complete] - artifact$right$lower) /
      (artifact$right$upper - artifact$right$lower)
    scale <- 2^artifact$numeric_grid_bits
    exact <- c(
      exact, length(left), sum(round(left * scale)),
      sum(round(right * scale)), sum(round(left^2 * scale)),
      sum(round(right^2 * scale)), sum(round(left * right * scale)))
  }

  histograms <- families$fixed_numeric_histograms$artifacts
  for (name in sort(names(histograms), method = "radix")) {
    artifact <- histograms[[name]]
    values <- numeric_values[[.dsvert_dp_capsule_local_key(
      artifact$dataset, artifact$column)]]
    valid <- is.finite(values)
    bin <- findInterval(
      values[valid], artifact$grid, left.open = TRUE) + 1L
    exact <- c(exact, tabulate(bin, nbins = length(artifact$grid)),
               sum(!valid))
  }

  category <- function(column, levels) {
    vapply(unit_rows, function(rows) {
      values <- as.character(data[[column]][rows])
      values <- unique(values[!is.na(values) & values %in% levels])
      if (length(values) == 1L) values else NA_character_
    }, character(1L))
  }
  category_values <- list()
  marginals <- families$categorical_marginals$artifacts
  for (name in sort(names(marginals), method = "radix")) {
    artifact <- marginals[[name]]
    values <- category(artifact$column, artifact$levels)
    category_values[[artifact$column]] <- values
    exact <- c(exact, tabulate(
      match(values, artifact$levels), nbins = length(artifact$levels)))
  }

  pair_sets <- families$categorical_pairs$sets
  for (set_name in sort(names(pair_sets), method = "radix")) {
    set <- pair_sets[[set_name]]
    columns <- set$columns
    names(columns) <- vapply(columns, `[[`, character(1L), "column")
    for (pair in set$included_pairs) {
        pair <- unname(unlist(pair, use.names = FALSE))
        a <- columns[[pair[[1L]]]]
        b <- columns[[pair[[2L]]]]
        cell <- vapply(unit_rows, function(rows) {
          av <- as.character(data[[a$column]][rows])
          bv <- as.character(data[[b$column]][rows])
          valid <- !is.na(av) & !is.na(bv) &
            av %in% a$levels & bv %in% b$levels
          cells <- unique(match(av[valid], a$levels) +
            (match(bv[valid], b$levels) - 1L) * length(a$levels))
          if (length(cells) == 1L) cells else NA_integer_
        }, integer(1L))
        exact <- c(exact, tabulate(
          cell, nbins = length(a$levels) * length(b$levels)))
    }
  }

  survival <- families$survival_artifacts
  for (name in sort(names(survival), method = "radix")) {
    artifact <- survival[[name]]
    outcome_levels <- c(artifact$censor, artifact$causes)
    delayed <- !identical(artifact$entry, "none")
    entry_counts <- if (delayed) numeric(length(artifact$time_grid)) else NULL
    exit_counts <- numeric(length(artifact$time_grid) * length(outcome_levels))
    invalid <- 0
    for (rows in unit_rows) {
      exit <- as.numeric(data[[artifact$time]][rows])
      outcome <- as.character(data[[artifact$event]][rows])
      entry <- if (delayed) {
        as.numeric(data[[artifact$entry]][rows])
      } else {
        rep(0, length(rows))
      }
      valid <- is.finite(exit) & outcome %in% outcome_levels &
        (!delayed | (is.finite(entry) & entry <= exit))
      candidates <- which(valid)
      if (!length(candidates)) {
        invalid <- invalid + 1
        next
      }
      events <- candidates[outcome[candidates] != artifact$censor]
      candidates <- if (length(events)) events else candidates
      time_key <- if (length(events)) exit[candidates] else -exit[candidates]
      selected <- candidates[order(
        time_key, match(outcome[candidates], outcome_levels),
        entry[candidates], method = "radix")[[1L]]]
      bounded_exit <- min(artifact$time_bounds[[2L]],
                          max(artifact$time_bounds[[1L]], exit[[selected]]))
      exit_bin <- findInterval(
        bounded_exit, artifact$time_grid, left.open = TRUE) + 1L
      outcome_bin <- match(outcome[[selected]], outcome_levels)
      exit_cell <- exit_bin +
        (outcome_bin - 1L) * length(artifact$time_grid)
      exit_counts[[exit_cell]] <- exit_counts[[exit_cell]] + 1
      if (delayed) {
        bounded_entry <- min(artifact$time_bounds[[2L]],
                             max(artifact$time_bounds[[1L]], entry[[selected]]))
        entry_bin <- findInterval(
          bounded_entry, artifact$time_grid, left.open = TRUE) + 1L
        entry_counts[[entry_bin]] <- entry_counts[[entry_bin]] + 1
      }
    }
    exact <- c(exact, entry_counts, exit_counts, invalid)
  }
  unname(as.numeric(exact))
}

.materializer_test_family_delta <- function(layout, left, right, family) {
  blocks <- layout$blocks[vapply(
    layout$blocks, `[[`, character(1L), "family") == family]
  index <- unlist(lapply(blocks, function(block) block$start:block$end),
                  use.names = FALSE)
  right[index] - left[index]
}

test_that("local capsule coordinates have the exact canonical order", {
  fixture <- .materializer_test_fixture(duplicate_describe = TRUE)
  materialized <- testthat::with_mocked_bindings(
    list(
      .dsvert_dp_capsule_materialize_local(
        fixture$policy, fixture$manifest, fixture$resolved),
      .dsvert_dp_capsule_materialize_local(
        fixture$policy, fixture$manifest, fixture$resolved)),
    .dsvert_capsule_registry_lookup = function(...) {
      stop("capsule history was consulted", call. = FALSE)
    },
    .package = "dsVert")
  expect_identical(materialized[[2L]], materialized[[1L]])
  material <- materialized[[1L]]
  expected <- .materializer_test_oracle(fixture)
  expect_identical(length(expected), 56L)
  expect_identical(material$values, expected)
  expect_identical(material$coordinate_count, 56L)
  expect_identical(
    material$purpose, .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE)
  expect_identical(
    material$state, "internal_unshared_secret_share_input_never_release")
  expect_match(material$value_commitment_sha256, "^[0-9a-f]{64}$")
  expect_match(material$authenticatable_sha256, "^[0-9a-f]{64}$")
  expect_length(
    fixture$manifest$workload$families$fixed_numeric_histograms$artifacts,
    1L)
  expect_true(all(is.finite(material$values)))
  expect_true(all(material$values == trunc(material$values)))

  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  expect_identical(unname(vapply(
    layout$blocks, `[[`, character(1L), "family")), c(
      "admitted_count", rep("numeric_moments", 3L),
      rep("numeric_pair_moments", 3L),
      "fixed_numeric_histograms", rep("categorical_marginals", 3L),
      rep("categorical_pairs", 3L), "survival_artifacts"))
  expect_identical(
    fixture$manifest$workload$families$admitted_count$owner_peer,
    "peer_a")
  expect_identical(
    fixture$manifest$workload$families$admitted_count$dataset,
    "protected")

  pair_expected <- list(
    `entry::time` = c(2, 51, 410, 10, 348, 51),
    `entry::x` = c(2, 51, 384, 10, 320, 51),
    `time::x` = c(2, 410, 384, 348, 320, 333))
  pair_blocks <- layout$blocks[vapply(
    layout$blocks, `[[`, character(1L), "family") ==
      "numeric_pair_moments"]
  expect_length(pair_blocks, 3L)
  for (block in pair_blocks) {
    key <- paste(
      block$descriptor$left$column, block$descriptor$right$column,
      sep = "::")
    expect_identical(
      material$values[block$start:block$end], pair_expected[[key]])
  }
})

test_that("random-intercept LMM source coordinates are bounded patient moments", {
  lmm <- list(random_intercept = list(
    version = "random_intercept_v1", dataset = "protected",
    outcome = "time", cluster = "cat_a",
    max_patients_per_cluster = 2L))
  fixture <- .materializer_test_fixture(gaussian_specs = lmm)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$random_intercept
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::random_intercept"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)

  expect_identical(
    artifact$version, "bounded-normalized-random-intercept-moments-v1")
  expect_identical(as.numeric(artifact$coordinate_count), 6)
  expect_identical(as.numeric(artifact$statistic_maximum),
                   c(5, 5, 10, 1280, 1280, 1280))
  expect_identical(material$values[block$start:block$end],
                   c(2, 2, 2, 410, 348, 349))
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
    manifest = fixture$manifest, layout = layout))
  expect_identical(lattice$scale_shifts[block$start:block$end],
                   c(8L, 8L, 8L, 0L, 0L, 0L))
  expect_equal(
    artifact$source_raw_l1_sensitivity,
    2 * artifact$max_patients_per_cluster + 2 + 3 * 256)
  expect_equal(
    artifact$quantization_contract$
      cluster_mean_sq_max_abs_error_normalized,
    3 * 5 / (2 * 256) + 5 / (4 * 256^2))
  expect_identical(artifact$implementation_state, "same_owner_materialized")
  expect_identical(artifact$cross_owner_state, "reserved_not_materialized")
})

test_that("random-intercept LMM source rejects a cluster over its signed cap", {
  lmm <- list(random_intercept = list(
    version = "random_intercept_v1", dataset = "protected",
    outcome = "time", cluster = "cat_a",
    max_patients_per_cluster = 2L))
  fixture <- .materializer_test_fixture(gaussian_specs = lmm)
  extra <- fixture$data[rep(1L, 2L), , drop = FALSE]
  extra$patient_id <- c("u4", "u5")
  extra$time <- c(5, 7)
  extra$cat_a <- "A"
  fixture$resolved$protected$data <- rbind(fixture$data, extra)

  expect_error(
    .dsvert_dp_capsule_materialize_local(
      fixture$policy, fixture$manifest, fixture$resolved),
    "signed LMM cluster capacity")
})

test_that("random-intercept LMM source respects its one-patient sensitivity", {
  lmm <- list(random_intercept = list(
    version = "random_intercept_v1", dataset = "protected",
    outcome = "time", cluster = "cat_a",
    max_patients_per_cluster = 2L))
  empty <- .materializer_test_data()[FALSE, , drop = FALSE]
  fixture <- .materializer_test_fixture(
    data = empty, capacity = 5L, gaussian_specs = lmm)
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  one_patient <- .materializer_test_data()[1L, , drop = FALSE]
  one_patient$time <- 10
  one_patient$cat_a <- "A"
  fixture$resolved$protected$data <- one_patient
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
    manifest = fixture$manifest, layout = layout))
  delta <- .materializer_test_family_delta(
    layout, left, right, "gaussian_models")
  family <- fixture$manifest$workload$families$gaussian_models

  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
  expect_lte(sum(abs((right - left) * 2^lattice$scale_shifts)),
             fixture$manifest$workload$sensitivity$l1)

  first <- right
  second_patient <- one_patient
  second_patient$patient_id <- "u2"
  fixture$resolved$protected$data <- rbind(one_patient, second_patient)
  second <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  delta <- .materializer_test_family_delta(
    layout, first, second, "gaussian_models")
  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
})

test_that("fixed-effect random-intercept LMM emits GLS sufficient statistics", {
  lmm <- list(random_intercept_fixed = list(
    version = "random_intercept_fixed_v2", dataset = "protected",
    outcome = "time", predictors = "x", intercept = TRUE,
    cluster = "cat_a", max_patients_per_cluster = 2L,
    variance_ratio_grid = c(0, 0.5, 2)))
  fixture <- .materializer_test_fixture(gaussian_specs = lmm)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$random_intercept_fixed
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::random_intercept_fixed"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)
  # Source rows are first bounded and aggregated to patient units.  The two
  # retained units are (x, y) = (0.5, 0.6) and (1, 1) on the signed [0, 1]
  # lattice, rather than the unaggregated source rows.
  global <- c(2, 512, 384, 320, 410, 333, 348)

  expect_identical(
    artifact$version,
    "bounded-normalized-random-intercept-fixed-sufficient-statistics-v2")
  expect_identical(as.numeric(artifact$coordinate_count), 21)
  expect_identical(artifact$design_terms, c("(Intercept)", "x"))
  expect_identical(artifact$variance_ratio_grid, c(0, 0.5, 2))
  expect_identical(as.numeric(artifact$statistic_maximum),
                   c(5, rep(1280, 6L), 5, rep(2560, 6L),
                     5, rep(2560, 6L)))
  expect_identical(material$values[block$start:block$end],
                   c(global, 2, global[-1L], 0, rep(0, 6L)))
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
    manifest = fixture$manifest, layout = layout))
  expect_identical(lattice$scale_shifts[block$start:block$end],
                   c(8L, rep(0L, 6L), 8L, rep(0L, 6L),
                     8L, rep(0L, 6L)))
  expect_equal(artifact$source_raw_l1_sensitivity,
               (3 + 6 * (1 + 2 * 2^2)) * 256)
  expect_identical(artifact$implementation_state, "same_owner_materialized")
  expect_identical(artifact$cross_owner_state, "reserved_not_materialized")
})

test_that("fixed-effect REML LMM materializes the same signed statistics", {
  lmm <- list(random_intercept_fixed = list(
    version = "random_intercept_fixed_v3", dataset = "protected",
    outcome = "time", predictors = "x", intercept = TRUE,
    cluster = "cat_a", max_patients_per_cluster = 2L,
    variance_ratio_grid = c(0, 0.5, 2), estimation_profile = "reml"))
  fixture <- .materializer_test_fixture(gaussian_specs = lmm)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$random_intercept_fixed
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::random_intercept_fixed"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)

  expect_identical(
    artifact$version,
    "bounded-normalized-random-intercept-fixed-sufficient-statistics-v3")
  expect_identical(artifact$estimation_profile, "reml")
  expect_identical(material$values[block$start:block$end],
                   c(2, 512, 384, 320, 410, 333, 348,
                     2, 512, 384, 320, 410, 333, 348,
                     0, rep(0, 6L)))
})

test_that("fixed-effect random-intercept LMM source respects signed sensitivity", {
  lmm <- list(random_intercept_fixed = list(
    version = "random_intercept_fixed_v2", dataset = "protected",
    outcome = "time", predictors = "x", intercept = TRUE,
    cluster = "cat_a", max_patients_per_cluster = 2L,
    variance_ratio_grid = c(0, 1)))
  empty <- .materializer_test_data()[FALSE, , drop = FALSE]
  fixture <- .materializer_test_fixture(
    data = empty, capacity = 5L, gaussian_specs = lmm)
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  one_patient <- .materializer_test_data()[1L, , drop = FALSE]
  one_patient$time <- 10
  one_patient$x <- 10
  one_patient$cat_a <- "A"
  fixture$resolved$protected$data <- one_patient
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
    manifest = fixture$manifest, layout = layout))
  delta <- .materializer_test_family_delta(
    layout, left, right, "gaussian_models")
  family <- fixture$manifest$workload$families$gaussian_models

  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
  expect_lte(sum(abs((right - left) * 2^lattice$scale_shifts)),
             fixture$manifest$workload$sensitivity$l1)
})

test_that("binary random-intercept GLMM grid emits only bounded cluster losses", {
  glmm <- list(binary_random_intercept = list(
    version = "binary_random_intercept_grid_v1", dataset = "protected",
    outcome = "x", predictors = "entry", intercept = TRUE,
    cluster = "cat_a", max_patients_per_cluster = 2L,
    beta_grid = list(c(0, 0), c(0, 1)), variance_grid = c(0, 0.5)))
  data <- .materializer_test_data()
  data$x <- c(0, 0, 1, NA_real_)
  data$entry <- c(0, 0, 2, NA_real_)
  fixture <- .materializer_test_fixture(
    data = data, gaussian_specs = glmm, binary_x = TRUE)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$binary_random_intercept
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::binary_random_intercept"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
    manifest = fixture$manifest, layout = layout))

  expect_identical(
    artifact$version,
    "bounded-binary-random-intercept-likelihood-grid-v1")
  expect_identical(artifact$design_terms, c("(Intercept)", "entry"))
  expect_identical(as.numeric(artifact$coordinate_count), 4)
  expect_length(artifact$candidate_loss_bounds, 4L)
  expect_true(all(material$values[block$start:block$end] >= 0))
  expect_true(all(material$values[block$start:block$end] <=
                    artifact$statistic_maximum))
  expect_identical(lattice$scale_shifts[block$start:block$end],
                   rep.int(0L, 4L))
  expect_identical(artifact$implementation_state, "same_owner_materialized")
  expect_identical(artifact$cross_owner_state, "reserved_not_materialized")
})

test_that("binary random-intercept GLMM grid honours its signed sensitivity", {
  glmm <- list(binary_random_intercept = list(
    version = "binary_random_intercept_grid_v1", dataset = "protected",
    outcome = "x", predictors = "entry", intercept = TRUE,
    cluster = "cat_a", max_patients_per_cluster = 2L,
    beta_grid = list(c(0, 0), c(0, 1)), variance_grid = c(0, 0.5)))
  data <- .materializer_test_data()
  data$x <- c(0, 0, 1, NA_real_)
  data$entry <- c(0, 0, 2, NA_real_)
  fixture <- .materializer_test_fixture(
    data = data, gaussian_specs = glmm, binary_x = TRUE)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::binary_random_intercept"]]
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  changed <- data
  changed$x[changed$patient_id == "u2"] <- 0
  fixture$resolved$protected$data <- changed
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  family <- fixture$manifest$workload$families$gaussian_models
  delta <- right[block$start:block$end] - left[block$start:block$end]

  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
})

test_that("binary random-slope GLMM grid emits bounded two-effect losses", {
  glmm <- list(binary_random_slope = list(
    version = "binary_random_slope_grid_v1", dataset = "protected",
    outcome = "x", predictors = "entry", random_slopes = "entry",
    intercept = TRUE, cluster = "cat_a", max_patients_per_cluster = 2L,
    candidate_grid = list(
      list(beta = c(-1, 0), covariance = c(0.25, 0, 0, 0.25)),
      list(beta = c(-1, 1), covariance = c(0.5, 0.1, 0.1, 0.5)))))
  data <- .materializer_test_data()
  data$x <- c(0, 0, 1, NA_real_)
  data$entry <- c(0, 0, 2, NA_real_)
  fixture <- .materializer_test_fixture(
    data = data, gaussian_specs = glmm, binary_x = TRUE)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$binary_random_slope
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::binary_random_slope"]]
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  changed <- data
  changed$x[changed$patient_id == "u2"] <- 1
  fixture$resolved$protected$data <- changed
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  family <- fixture$manifest$workload$families$gaussian_models

  expect_identical(artifact$version,
                   "bounded-binary-random-slope-likelihood-grid-v1")
  expect_identical(artifact$random_effect_order, c("(Intercept)", "entry"))
  expect_identical(as.numeric(artifact$coordinate_count), 2)
  expect_true(all(left[block$start:block$end] >= 0))
  expect_true(all(left[block$start:block$end] <=
                    unlist(artifact$statistic_maximum, use.names = FALSE)))
  delta <- right[block$start:block$end] - left[block$start:block$end]
  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
})

test_that("binary GLMM grid supports two signed random slopes with 9-cubed quadrature", {
  glmm <- list(binary_random_slope = list(
    version = "binary_random_slope_grid_v1", dataset = "protected",
    outcome = "x", predictors = c("entry", "z"),
    random_slopes = c("entry", "z"), intercept = TRUE,
    cluster = "cat_a", max_patients_per_cluster = 2L,
    candidate_grid = list(
      list(beta = c(-1, 0, 0), covariance = c(
        0.25, 0, 0, 0, 0.25, 0, 0, 0, 0.25)),
      list(beta = c(-1, 1, 0.5), covariance = c(
        0.5, 0.1, 0.05, 0.1, 0.5, 0.05, 0.05, 0.05, 0.5)))))
  fixture <- .materializer_test_fixture(
    gaussian_specs = glmm, binary_x = TRUE, binary_z = TRUE)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$binary_random_slope
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::binary_random_slope"]]
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  changed <- fixture$data
  changed$x[changed$patient_id == "u2"] <- 1
  fixture$resolved$protected$data <- changed
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  family <- fixture$manifest$workload$families$gaussian_models

  expect_identical(artifact$random_effect_order,
                   c("(Intercept)", "entry", "z"))
  expect_identical(artifact$quadrature_rule,
                   "gauss_hermite_9x9x9_standard_normal_v1")
  expect_true(all(left[block$start:block$end] >= 0))
  expect_true(all(left[block$start:block$end] <=
                    unlist(artifact$statistic_maximum, use.names = FALSE)))
  delta <- right[block$start:block$end] - left[block$start:block$end]
  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
})

test_that("Gaussian random-slope LMM grid emits only clipped cluster losses", {
  lmm <- list(random_slope = list(
    version = "gaussian_random_slope_grid_v1", dataset = "protected",
    outcome = "time", predictors = "x", random_slopes = "x",
    intercept = TRUE, cluster = "cat_a", max_patients_per_cluster = 2L,
    candidate_grid = list(
      list(beta = c(0, 0), sigma2 = 1,
           covariance = c(0.5, 0.1, 0.1, 0.5)),
      list(beta = c(0.2, 0.5), sigma2 = 1,
           covariance = c(0.75, 0.2, 0.2, 0.75)))))
  fixture <- .materializer_test_fixture(gaussian_specs = lmm)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$random_slope
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::random_slope"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
    manifest = fixture$manifest, layout = layout))

  expect_identical(artifact$version,
                   "bounded-gaussian-random-slope-likelihood-grid-v1")
  expect_identical(artifact$random_effect_order, c("(Intercept)", "x"))
  expect_identical(as.numeric(artifact$coordinate_count), 2)
  expect_true(all(material$values[block$start:block$end] >= 0))
  expect_true(all(material$values[block$start:block$end] <=
                    unlist(artifact$statistic_maximum, use.names = FALSE)))
  expect_identical(lattice$scale_shifts[block$start:block$end], c(0L, 0L))
  expect_identical(artifact$implementation_state, "same_owner_materialized")
  expect_identical(artifact$cross_owner_state, "reserved_not_materialized")
})

test_that("Gaussian random-slope LMM grid honours its signed sensitivity", {
  lmm <- list(random_slope = list(
    version = "gaussian_random_slope_grid_v1", dataset = "protected",
    outcome = "time", predictors = "x", random_slopes = "x",
    intercept = TRUE, cluster = "cat_a", max_patients_per_cluster = 2L,
    candidate_grid = list(
      list(beta = c(0, 0), sigma2 = 1,
           covariance = c(0.5, 0.1, 0.1, 0.5)),
      list(beta = c(0.2, 0.5), sigma2 = 1,
           covariance = c(0.75, 0.2, 0.2, 0.75)))))
  fixture <- .materializer_test_fixture(gaussian_specs = lmm)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::random_slope"]]
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  changed <- fixture$resolved$protected$data
  changed$time[changed$patient_id == "u2"] <- 5
  fixture$resolved$protected$data <- changed
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  family <- fixture$manifest$workload$families$gaussian_models
  delta <- right[block$start:block$end] - left[block$start:block$end]

  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
})

test_that("Gaussian AR1 working-GLS grid emits only clipped cluster losses", {
  ar1 <- list(ar1 = list(
    version = "gaussian_ar1_working_gls_grid_v1", dataset = "protected",
    outcome = "time", cluster = "cat_a", order = "entry", predictors = "x",
    intercept = TRUE, max_patients_per_cluster = 2L,
    candidate_grid = list(
      list(beta = c(0, 0), rho = 0),
      list(beta = c(0.2, 0.5), rho = 0.5))))
  data <- data.frame(
    patient_id = paste0("u", 1:4), entry = 0:3, time = c(1, 3, 6, 8),
    x = c(0, 3, 7, 10), cat_a = c("A", "A", "B", "B"),
    cat_b = c("L", "L", "R", "R"), status = "censor")
  fixture <- .materializer_test_fixture(
    data = data, capacity = 4L, gaussian_specs = ar1)
  artifact <- fixture$manifest$workload$families$gaussian_models$artifacts$ar1
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::ar1"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)

  expect_identical(artifact$version, "bounded-gaussian-ar1-working-gls-grid-v1")
  expect_identical(artifact$order$column, "entry")
  expect_identical(artifact$coordinate_order,
                   "signed_candidate_grid_cluster_gaussian_ar1_working_gls_loss_v1")
  expect_true(all(material$values[block$start:block$end] >= 0))
  expect_true(all(material$values[block$start:block$end] <=
                    unlist(artifact$statistic_maximum, use.names = FALSE)))
  expect_identical(artifact$implementation_state, "same_owner_materialized")
  expect_identical(artifact$cross_owner_state, "reserved_not_materialized")
})

test_that("Gaussian AR1 working-GLS grid honours patient sensitivity and rejects ties", {
  ar1 <- list(ar1 = list(
    version = "gaussian_ar1_working_gls_grid_v1", dataset = "protected",
    outcome = "time", cluster = "cat_a", order = "entry", predictors = "x",
    intercept = TRUE, max_patients_per_cluster = 2L,
    candidate_grid = list(
      list(beta = c(0, 0), rho = 0),
      list(beta = c(0.2, 0.5), rho = 0.5))))
  data <- data.frame(
    patient_id = paste0("u", 1:4), entry = 0:3, time = c(1, 3, 6, 8),
    x = c(0, 3, 7, 10), cat_a = c("A", "A", "B", "B"),
    cat_b = c("L", "L", "R", "R"), status = "censor")
  fixture <- .materializer_test_fixture(
    data = data, capacity = 4L, gaussian_specs = ar1)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::ar1"]]
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  fixture$resolved$protected$data$time[1L] <- 10
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  family <- fixture$manifest$workload$families$gaussian_models
  delta <- right[block$start:block$end] - left[block$start:block$end]

  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
  fixture$resolved$protected$data$entry[2L] <- 0
  expect_error(.dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved), "tied order")
})

test_that("Cox partial-likelihood grid emits bounded Breslow losses", {
  cox <- list(cox_grid = list(
    version = "cox_partial_likelihood_grid_v1", dataset = "protected",
    time = "time", event = "status", censor = "censor",
    event_level = "event", time_grid = c(3, 6, 10), predictors = "x",
    intercept = FALSE, candidate_grid = list(c(0.5), c(0))))
  data <- data.frame(
    patient_id = paste0("u", 1:4), entry = 0, time = c(2, 4, 7, 9),
    x = c(0, 3, 7, 10), cat_a = c("A", "A", "B", "B"),
    cat_b = c("L", "L", "R", "R"),
    status = c("event", "censor", "event", "censor"))
  fixture <- .materializer_test_fixture(data = data, capacity = 4L,
    max_records = 1L, survival_specs = cox)
  artifact <- fixture$manifest$workload$families$survival_artifacts$cox_grid
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["survival_artifacts::cox_grid"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)

  expect_identical(artifact$version, "bounded-cox-partial-likelihood-grid-v1")
  expect_identical(artifact$intercept, FALSE)
  expect_true(all(material$values[block$start:block$end] >= 0))
  expect_true(all(material$values[block$start:block$end] <=
                    unlist(artifact$statistic_maximum, use.names = FALSE)))
  fixture$resolved$protected$data$time[[1L]] <- 10
  shifted <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  delta <- shifted[block$start:block$end] - material$values[block$start:block$end]
  family <- fixture$manifest$workload$families$survival_artifacts$cox_grid
  expect_lte(sum(abs(delta)), family$source_raw_l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$source_raw_l2_sensitivity)

  unsorted <- cox
  unsorted$cox_grid$predictors <- c("z", "x")
  unsorted$cox_grid$candidate_grid <- list(c(0.5, 0), c(0, 0))
  expect_error(.materializer_test_fixture(
    data = data, capacity = 4L, max_records = 1L,
    survival_specs = unsorted, binary_z = TRUE),
    "Invalid Cox partial-likelihood grid model terms")
})

test_that("negative-binomial grid emits only bounded candidate losses", {
  nb2 <- list(negative_binomial = list(
    version = "negative_binomial_grid_v1", dataset = "protected",
    outcome = "x", predictors = "entry", intercept = TRUE,
    max_outcome = 10L, beta_grid = list(c(0, 0), c(0, 1)),
    theta_grid = c(0.5, 2)))
  data <- .materializer_test_data()
  data$x <- c(0, 0, 3, NA_real_)
  data$entry <- c(0, 0, 2, NA_real_)
  fixture <- .materializer_test_fixture(data = data, gaussian_specs = nb2)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$negative_binomial
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::negative_binomial"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)

  expect_identical(artifact$version,
                   "bounded-negative-binomial-likelihood-grid-v1")
  expect_identical(artifact$design_terms, c("(Intercept)", "entry"))
  expect_identical(as.numeric(artifact$coordinate_count), 4)
  expect_length(artifact$candidate_loss_bounds, 4L)
  expect_true(all(material$values[block$start:block$end] >= 0))
  expect_true(all(material$values[block$start:block$end] <=
                    artifact$statistic_maximum))
  expect_identical(artifact$implementation_state, "same_owner_materialized")
  expect_identical(artifact$cross_owner_state, "reserved_not_materialized")
})

test_that("negative-binomial grid honours its signed sensitivity", {
  nb2 <- list(negative_binomial = list(
    version = "negative_binomial_grid_v1", dataset = "protected",
    outcome = "x", predictors = "entry", intercept = TRUE,
    max_outcome = 10L, beta_grid = list(c(0, 0), c(0, 1)),
    theta_grid = c(0.5, 2)))
  data <- .materializer_test_data()
  data$x <- c(0, 0, 3, NA_real_)
  data$entry <- c(0, 0, 2, NA_real_)
  fixture <- .materializer_test_fixture(data = data, gaussian_specs = nb2)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::negative_binomial"]]
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  changed <- data
  changed$x[changed$patient_id == "u2"] <- 0
  fixture$resolved$protected$data <- changed
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  family <- fixture$manifest$workload$families$gaussian_models
  delta <- right[block$start:block$end] - left[block$start:block$end]

  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
})

test_that("multinomial grid emits only signed bounded softmax losses", {
  multinomial <- list(multinomial = list(
    version = "multinomial_grid_v1", dataset = "protected",
    outcome = "class3", predictors = "entry", intercept = TRUE,
    levels = c("A", "B", "C"), reference = "A",
    beta_grid = list(c(0, 0, 0, 0), c(0, 1, 0, -1))))
  data <- .materializer_test_data()
  data$entry <- c(0, 0, 2, 4)
  fixture <- .materializer_test_fixture(
    data = data, gaussian_specs = multinomial, multiclass_outcome = TRUE)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$multinomial
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::multinomial"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)

  expect_identical(artifact$version,
                   "bounded-multinomial-likelihood-grid-v1")
  expect_identical(artifact$outcome$levels, c("A", "B", "C"))
  expect_identical(artifact$outcome$reference, "A")
  expect_identical(as.numeric(artifact$coordinate_count), 2)
  expect_true(all(material$values[block$start:block$end] >= 0))
  expect_true(all(material$values[block$start:block$end] <=
                    artifact$statistic_maximum))
  expect_identical(artifact$implementation_state, "same_owner_materialized")
  expect_identical(artifact$cross_owner_state, "reserved_not_materialized")
})

test_that("multinomial grid honours its signed sensitivity", {
  multinomial <- list(multinomial = list(
    version = "multinomial_grid_v1", dataset = "protected",
    outcome = "class3", predictors = "entry", intercept = TRUE,
    levels = c("A", "B", "C"), reference = "A",
    beta_grid = list(c(0, 0, 0, 0), c(0, 1, 0, -1))))
  data <- .materializer_test_data()
  data$entry <- c(0, 0, 2, 4)
  fixture <- .materializer_test_fixture(
    data = data, gaussian_specs = multinomial, multiclass_outcome = TRUE)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::multinomial"]]
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  changed <- fixture$data
  changed$class3[changed$patient_id == "u2"] <- "C"
  fixture$resolved$protected$data <- changed
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  family <- fixture$manifest$workload$families$gaussian_models
  delta <- right[block$start:block$end] - left[block$start:block$end]

  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
})

test_that("ordinal grid emits only signed bounded cumulative-logit losses", {
  ordinal <- list(ordinal = list(
    version = "ordinal_grid_v1", dataset = "protected",
    outcome = "class3", predictors = "entry", intercept = TRUE,
    ordered_levels = c("A", "B", "C"),
    candidate_grid = list(
      list(thresholds = c(-1, 1), beta = c(0, 0)),
      list(thresholds = c(-0.5, 0.5), beta = c(0, 1)))))
  data <- .materializer_test_data()
  data$entry <- c(0, 0, 2, 4)
  fixture <- .materializer_test_fixture(
    data = data, gaussian_specs = ordinal, multiclass_outcome = TRUE)
  artifact <- fixture$manifest$workload$families$gaussian_models$
    artifacts$ordinal
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::ordinal"]]
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)

  expect_identical(artifact$version, "bounded-ordinal-likelihood-grid-v1")
  expect_identical(artifact$outcome$ordered_levels, c("A", "B", "C"))
  expect_identical(as.numeric(artifact$coordinate_count), 2)
  expect_true(all(material$values[block$start:block$end] >= 0))
  expect_true(all(material$values[block$start:block$end] <=
                    artifact$statistic_maximum))
  expect_identical(artifact$implementation_state, "same_owner_materialized")
})

test_that("ordinal grid honours its signed sensitivity", {
  ordinal <- list(ordinal = list(
    version = "ordinal_grid_v1", dataset = "protected",
    outcome = "class3", predictors = "entry", intercept = TRUE,
    ordered_levels = c("A", "B", "C"),
    candidate_grid = list(
      list(thresholds = c(-1, 1), beta = c(0, 0)),
      list(thresholds = c(-0.5, 0.5), beta = c(0, 1)))))
  data <- .materializer_test_data()
  data$entry <- c(0, 0, 2, 4)
  fixture <- .materializer_test_fixture(
    data = data, gaussian_specs = ordinal, multiclass_outcome = TRUE)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[["gaussian_models::ordinal"]]
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  changed <- fixture$data
  changed$class3[changed$patient_id == "u2"] <- "C"
  fixture$resolved$protected$data <- changed
  right <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  family <- fixture$manifest$workload$families$gaussian_models
  delta <- right[block$start:block$end] - left[block$start:block$end]

  expect_lte(sum(abs(delta)), family$l1_sensitivity)
  expect_lte(sqrt(sum(delta^2)), family$l2_sensitivity)
})

test_that("numeric cache compaction preserves the full material byte for byte", {
  gaussian <- list(primary_gaussian = list(
    version = "v1", dataset = "protected", outcome = "time",
    predictors = c("x", "entry"), intercept = TRUE))
  fixture <- .materializer_test_fixture(gaussian_specs = gaussian)

  full_cache <- testthat::with_mocked_bindings(
    .dsvert_dp_capsule_materialize_local(
      fixture$policy, fixture$manifest, fixture$resolved),
    .dsvert_dp_capsule_compact_bounded_numeric = identity,
    .package = "dsVert")
  compact_cache <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)

  expect_identical(
    serialize(compact_cache, NULL, version = 3L),
    serialize(full_cache, NULL, version = 3L))
  expect_identical(compact_cache$values, full_cache$values)
  expect_identical(
    compact_cache$value_commitment_sha256,
    full_cache$value_commitment_sha256)
  expect_identical(
    compact_cache$authenticatable_sha256,
    full_cache$authenticatable_sha256)
})

test_that("numeric cache compaction retains only pair and Gaussian fields", {
  capacity <- 4096L
  protected <- data.frame(
    patient_id = sprintf("u%08d", seq_len(capacity)),
    x = seq(0, 1, length.out = capacity))
  policy <- list(
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = capacity, fixed_cohort_size = NULL,
    max_records_per_unit = 1L, overflow_policy = "reject_snapshot",
    numeric_bounds = list(x = c(0, 1)))
  admission <- .dsvert_dp_admit_units(protected, policy)
  full <- .dsvert_dp_bounded_numeric(
    protected, policy, "x", admission)
  compact <- .dsvert_dp_capsule_compact_bounded_numeric(full)

  expect_named(compact, c("unit_values", "valid"))
  expect_identical(compact$unit_values, full$unit_values)
  expect_identical(compact$valid, full$valid)
  expect_false(any(c("values", "present", "bounds") %in% names(compact)))
  expect_lt(as.numeric(object.size(compact)), as.numeric(object.size(full)))
})

test_that("catalog materialization emits only declared and referenced blocks", {
  fixture <- .materializer_test_fixture(workload_scope = list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(),
    categorical_pairs = list(c("cat_b", "cat_a")),
    correlations = list(c("x", "entry"))))

  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  expected <- .materializer_test_oracle(fixture)
  pair_blocks <- layout$blocks[vapply(
    layout$blocks, `[[`, character(1L), "family") ==
      "categorical_pairs"]
  correlation_blocks <- layout$blocks[vapply(
    layout$blocks, `[[`, character(1L), "family") ==
      "numeric_pair_moments"]

  expect_identical(material$values, expected)
  expect_identical(material$coordinate_count, 36L)
  expect_length(pair_blocks, 1L)
  expect_length(correlation_blocks, 1L)
  expect_identical(
    names(fixture$manifest$workload$families$categorical_marginals$artifacts),
    c("cat_a", "cat_b", "status"))
})

test_that("vertical peers fill only owned blocks and count has one owner", {
  peer_a <- .materializer_test_vertical_fixture("peer_a")
  peer_b <- .materializer_test_vertical_fixture("peer_b")
  expect_identical(
    peer_b$manifest$capsule_identity$capsule_id,
    peer_a$manifest$capsule_identity$capsule_id)
  expect_identical(
    peer_b$manifest$workload$families,
    peer_a$manifest$workload$families)
  a <- .dsvert_dp_capsule_materialize_local(
    peer_a$policy, peer_a$manifest, peer_a$resolved)
  b <- .dsvert_dp_capsule_materialize_local(
    peer_b$policy, peer_b$manifest, peer_b$resolved)
  expect_identical(a$coordinate_order_sha256, b$coordinate_order_sha256)
  expect_identical(a$values, c(2, 2, 256, 256, 0, 0, 0))
  expect_identical(b$values, c(0, 0, 0, 0, 2, 256, 256))
  expect_identical(a$values + b$values,
                   c(2, 2, 256, 256, 2, 256, 256))
  expect_identical(
    peer_a$manifest$workload$families$admitted_count$owner_peer,
    "peer_a")
  expect_identical(
    peer_a$manifest$execution_state,
    "registered_lifecycle_available_requires_runtime_preflight")
  expect_identical(
    peer_a$manifest$workload$vertical_crosses$implementation_state,
    "reserved_not_materialized")
})

test_that("fixed histogram retains exact lower and clipped upper bounds", {
  data <- data.frame(
    patient_id = c("u1", "u2"), entry = c(0, 0), time = c(1, 1),
    x = c(0, 10), cat_a = c("A", "A"), cat_b = c("L", "L"),
    status = c("censor", "censor"))
  fixture <- .materializer_test_fixture(data = data, capacity = 2L)
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  histogram <- layout$blocks[vapply(
    layout$blocks, `[[`, character(1L), "family") ==
      "fixed_numeric_histograms"][[1L]]
  expect_identical(
    material$values[histogram$start:histogram$end], c(1, 1, 0))
  expect_identical(sum(
    material$values[histogram$start:histogram$end]), 2)
})

test_that("row order repeated records and invalid values keep one fixed transcript", {
  fixture <- .materializer_test_fixture()
  baseline <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  set.seed(20260801)
  for (index in seq_len(20L)) {
    permutation <- sample(nrow(fixture$data))
    permuted <- fixture
    permuted$data <- fixture$data[permutation, , drop = FALSE]
    row.names(permuted$data) <- NULL
    permuted$resolved$protected$data <- permuted$data
    expect_identical(
      .dsvert_dp_capsule_materialize_local(
        permuted$policy, permuted$manifest, permuted$resolved)$values,
      baseline)
  }

  repeated <- fixture
  repeated$data <- fixture$data[c(seq_len(nrow(fixture$data)), 1L, 2L), ]
  row.names(repeated$data) <- NULL
  repeated$resolved$protected$data <- repeated$data
  expect_identical(
    .dsvert_dp_capsule_materialize_local(
      repeated$policy, repeated$manifest, repeated$resolved)$values,
    baseline)

  invalid <- fixture
  invalid$data <- rbind(fixture$data, data.frame(
    patient_id = "u1", entry = -Inf, time = Inf, x = NA_real_,
    cat_a = "outside", cat_b = NA_character_, status = "outside"))
  invalid$resolved$protected$data <- invalid$data
  expect_identical(
    .dsvert_dp_capsule_materialize_local(
      invalid$policy, invalid$manifest, invalid$resolved)$values,
    baseline)
  expect_equal(
    length(.dsvert_dp_capsule_materialize_local(
      invalid$policy, invalid$manifest, invalid$resolved)$values),
    fixture$manifest$workload$coordinate_count)

})

test_that("strict categorical marginals reject unknown and conflicting admitted values", {
  fixture <- .materializer_test_fixture(workload_scope = list(
    mode = "all_schema", strict_missing_categorical = "cat_a"))

  unknown <- fixture
  unknown$data$cat_a[[1L]] <- "outside"
  unknown$resolved$protected$data <- unknown$data
  expect_error(
    .dsvert_dp_capsule_materialize_local(
      unknown$policy, unknown$manifest, unknown$resolved),
    "categorical")

  conflicting <- fixture
  conflicting$data$cat_a[[2L]] <- "B"
  conflicting$resolved$protected$data <- conflicting$data
  expect_error(
    .dsvert_dp_capsule_materialize_local(
      conflicting$policy, conflicting$manifest, conflicting$resolved),
    "categorical")

  expect_silent(.dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved))
})

test_that("strict categorical pairs retain only complete joint cells", {
  fixture <- .materializer_test_fixture(workload_scope = list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(),
    categorical_pairs = list(c("cat_a", "cat_b")), correlations = list(),
    strict_missing_categorical = c("cat_a", "cat_b")))
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  pair_name <- grep("^categorical_pairs::", names(layout$blocks),
                    value = TRUE)[[1L]]
  pair <- layout$blocks[[pair_name]]
  expect_identical(pair$descriptor$missingness_policy,
                   paste("missing_values_have_no_joint_cell_and_unknown_or_conflicting",
                         "nonmissing_values_reject_before_release_v1", sep = "_"))
  fixture$data$cat_b[[4L]] <- NA_character_
  fixture$resolved$protected$data <- fixture$data
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)
  expect_identical(sum(material$values[pair$start:pair$end]), 2)

  unknown <- fixture
  unknown$data$cat_b[[1L]] <- "outside"
  unknown$resolved$protected$data <- unknown$data
  expect_error(.dsvert_dp_capsule_materialize_local(
    unknown$policy, unknown$manifest, unknown$resolved), "categorical")
})

test_that("numeric pairs use pairwise-complete admitted units", {
  fixture <- .materializer_test_fixture()
  fixture$data$x[fixture$data$patient_id == "u2"] <- NA_real_
  fixture$resolved$protected$data <- fixture$data
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  pair_blocks <- layout$blocks[vapply(
    layout$blocks, `[[`, character(1L), "family") ==
      "numeric_pair_moments"]
  pair_counts <- vapply(pair_blocks, function(block) {
    material$values[[block$start]]
  }, numeric(1L))
  pair_names <- vapply(pair_blocks, function(block) {
    paste(block$descriptor$left$column,
          block$descriptor$right$column, sep = "::")
  }, character(1L))
  names(pair_counts) <- pair_names
  expect_identical(pair_counts[["entry::time"]], 2)
  expect_identical(pair_counts[["entry::x"]], 1)
  expect_identical(pair_counts[["time::x"]], 1)
})

test_that("numeric-pair sensitivity exhausts the finite lattice boundary", {
  scale <- 256
  states <- c(0, 0.25, 0.5, 0.75, 1)
  vectors <- list(missing = rep(0, 6L))
  for (left in states) {
    for (right in states) {
      vectors[[paste(left, right, sep = "::")]] <-
        .dsvert_dp_capsule_quantized_pair_moments(
          left, right, 8L)
    }
  }

  raw_l1 <- 1 + 5 * scale
  raw_l2 <- sqrt(1 + 5 * scale^2) *
    (1 + 64 * .Machine$double.eps)
  observed_l1 <- observed_l2 <- 0
  for (first in vectors) {
    for (second in vectors) {
      difference <- second - first
      observed_l1 <- max(observed_l1, sum(abs(difference)))
      observed_l2 <- max(observed_l2, sqrt(sum(difference^2)))
    }
  }

  expect_identical(observed_l1, raw_l1)
  expect_lte(observed_l2, raw_l2)
  expect_equal(observed_l2, sqrt(1 + 5 * scale^2), tolerance = 0)
})

test_that("Gaussian model materializes one complete-case unit contribution", {
  gaussian <- list(primary_gaussian = list(
    version = "v1", dataset = "protected", outcome = "time",
    predictors = c("x", "entry"), intercept = TRUE))
  fixture <- .materializer_test_fixture(gaussian_specs = gaussian)
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  block <- layout$blocks[vapply(layout$blocks, function(block) {
    identical(block$family, "gaussian_models") &&
      identical(block$dataset, "protected") &&
      identical(block$owner_peer, "peer_a")
  }, logical(1L))][[1L]]
  # Complete admitted units are u1 and u2. Predictor order is entry,x.
  # Design rows are (1,0,.5) and (1,.2,1); normalized y is (.6,1).
  expected <- c(
    2, 512, 51, 10, 384, 51, 320, 410, 51, 333, 348)
  expect_identical(material$values[block$start:block$end], expected)
  expect_identical(block$descriptor$predictor_order, c("entry", "x"))

  repeated <- fixture
  repeated$data <- fixture$data[c(seq_len(nrow(fixture$data)), 1L, 2L), ]
  row.names(repeated$data) <- NULL
  repeated$resolved$protected$data <- repeated$data
  expect_identical(
    .dsvert_dp_capsule_materialize_local(
      repeated$policy, repeated$manifest, repeated$resolved)$values,
    material$values)

  missing <- fixture
  missing$data$x[missing$data$patient_id == "u2"] <- NA_real_
  missing$resolved$protected$data <- missing$data
  missing_material <- .dsvert_dp_capsule_materialize_local(
    missing$policy, missing$manifest, missing$resolved)
  expect_identical(missing_material$values[[block$start]], 1)
})

test_that("cross Gaussian source inputs are fixed-capacity private tail blocks", {
  gaussian <- list(cross = list(
    version = "v2", dataset = "protected", outcome = "x",
    predictors = "z", intercept = TRUE))
  peer_a <- .materializer_test_vertical_fixture(
    "peer_a", gaussian_specs = gaussian)
  peer_b <- .materializer_test_vertical_fixture(
    "peer_b", gaussian_specs = gaussian)
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(0:31)))
  bind_alignment <- function(fixture) {
    data_name <- names(fixture$resolved)[[1L]]
    aligned <- .psi_attach_alignment_manifest(
      fixture$resolved[[data_name]]$data, "patient_id", token)
    alignment <- .psi_validate_alignment_manifest(aligned)
    fixture$resolved[[data_name]]$data <- aligned
    fixture$resolved[[data_name]]$dataset$public$alignment_manifest_hash <-
      alignment$hash
    fixture$policy$datasets[[data_name]]$alignment_manifest_hash <-
      alignment$hash
    fixture$policy$datasets[[data_name]]$alignment_manifest_version <-
      alignment$version
    fixture
  }
  peer_a <- bind_alignment(peer_a)
  peer_b <- bind_alignment(peer_b)
  layout_a <- .dsvert_dp_gaussian_cross_layout(peer_a$manifest)
  layout_b <- .dsvert_dp_gaussian_cross_layout(peer_b$manifest)
  expect_identical(layout_b, layout_a)
  expect_true(layout_a$enabled)
  expect_identical(layout_a$private_start, 8193L)
  expect_identical(layout_a$transport_coordinate_count, 8200L)
  expect_identical(
    unlist(layout_a$source_peers, use.names = FALSE),
    c("peer_a", "peer_b"))
  expect_identical(
    unlist(layout_a$computation_peers, use.names = FALSE),
    c("peer_a", "peer_b"))

  material_a <- .dsvert_dp_gaussian_cross_materialize_source(
    peer_a$policy, peer_a$manifest, peer_a$resolved)
  material_b <- .dsvert_dp_gaussian_cross_materialize_source(
    peer_b$policy, peer_b$manifest, peer_b$resolved)
  expect_identical(length(material_a$values), 8200L)
  expect_identical(length(material_b$values), 8200L)
  expect_identical(
    material_a$private_alignment_consensus_hash,
    material_b$private_alignment_consensus_hash)
  release_count <- layout_a$release_coordinate_count
  release_layout <- .dsvert_dp_capsule_coordinate_layout(peer_a$manifest)
  gaussian_block <- release_layout$blocks[vapply(
    release_layout$blocks, function(block) {
      identical(block$family, "gaussian_models") &&
        identical(block$key, "cross")
    }, logical(1L))][[1L]]
  expect_true(all(material_a$values[
    gaussian_block$start:gaussian_block$end] == 0))
  expect_true(all(material_b$values[
    gaussian_block$start:gaussian_block$end] == 0))
  if (layout_a$padding_coordinates > 0L) {
    padding <- seq.int(release_count + 1L, layout_a$private_start - 1L)
    expect_true(all(material_a$values[padding] == 0))
    expect_true(all(material_b$values[padding] == 0))
  }
  blocks <- layout_a$blocks
  expect_identical(
    material_a$values[blocks[["cross::x::value"]]$start:
                        blocks[["cross::x::value"]]$end],
    c(0, 256))
  expect_identical(
    material_b$values[blocks[["cross::z::value"]]$start:
                        blocks[["cross::z::value"]]$end],
    c(0, 256))
  expect_identical(
    material_a$values[blocks[["cross::x::validity"]]$start:
                        blocks[["cross::x::validity"]]$end],
    c(256, 256))
  expect_true(all(material_a$values[
    blocks[["cross::z::value"]]$start:
      blocks[["cross::z::validity"]]$end] == 0))
  expect_true(all(material_b$values[
    blocks[["cross::x::value"]]$start:
      blocks[["cross::x::validity"]]$end] == 0))

  producer_a <- .dsvert_dp_gaussian_cross_source_producer(
    peer_a$policy, peer_a$manifest, peer_a$resolved)
  streamed_a <- unlist(lapply(
    seq.int(1L, layout_a$transport_coordinate_count, by = 3L),
    function(start) producer_a$read_range(
      start, min(3L, layout_a$transport_coordinate_count - start + 1L))),
    use.names = FALSE)
  expect_identical(streamed_a, material_a$values)
  expect_identical(
    producer_a$value_commitment_sha256,
    material_a$value_commitment_sha256)
  expect_identical(
    producer_a$authenticatable_sha256,
    material_a$authenticatable_sha256)
  expect_false("values" %in% names(producer_a))
  expect_true(is.function(producer_a$read_range))
  expect_true(is.function(producer_a$generation_chunks))
  expect_true(is.function(producer_a$reset))
  private_only_a <- .dsvert_dp_gaussian_cross_source_producer(
    peer_a$policy, peer_a$manifest, peer_a$resolved,
    compute_commitment = FALSE, include_release = FALSE)
  expect_identical(
    private_only_a$snapshot_binding_sha256,
    producer_a$snapshot_binding_sha256)
  x_block <- blocks[["cross::x::value"]]
  expect_identical(
    private_only_a$read_range(x_block$start, x_block$length),
    material_a$values[x_block$start:x_block$end])

  reordered <- peer_a
  reordered$resolved$protected$data <-
    reordered$resolved$protected$data[2:1, , drop = FALSE]
  expect_error(
    .dsvert_dp_gaussian_cross_materialize_source(
      reordered$policy, reordered$manifest, reordered$resolved),
    class = "dsvert_non_prealigned_cohort")
})

test_that("padded v4 bindings drive one cross Gaussian alignment consensus", {
  gaussian <- list(cross = list(
    version = "v2", dataset = "protected", outcome = "x",
    predictors = "z", intercept = TRUE))
  peer_a <- .materializer_test_vertical_fixture(
    "peer_a", gaussian_specs = gaussian, padded_v3 = TRUE)
  peer_b <- .materializer_test_vertical_fixture(
    "peer_b", gaussian_specs = gaussian, padded_v3 = TRUE)

  snapshot_digest <- .dsvert_dp_snapshot_digest
  digest_calls <- 0L
  validated <- testthat::with_mocked_bindings(
    .dsvert_dp_capsule_resolved_snapshots(
      peer_a$policy, peer_a$resolved),
    .dsvert_dp_snapshot_digest = function(data) {
      digest_calls <<- digest_calls + 1L
      snapshot_digest(data)
    },
    .package = "dsVert")
  expect_identical(validated, peer_a$resolved)
  expect_identical(digest_calls, 1L)

  context_a <- .dsvert_dp_gaussian_cross_source_context(
    peer_a$policy, peer_a$manifest, peer_a$resolved,
    include_release = FALSE)
  context_b <- .dsvert_dp_gaussian_cross_source_context(
    peer_b$policy, peer_b$manifest, peer_b$resolved,
    include_release = FALSE)
  expect_identical(
    context_a$private_alignment_consensus_hash,
    context_b$private_alignment_consensus_hash)
  expect_identical(
    context_a$private_alignment_consensus_hash,
    peer_a$policy$datasets$protected$alignment_manifest_hash)
  expect_identical(
    peer_a$policy$datasets$protected$alignment_manifest_version, 4L)
})

test_that("incremental commitments cross value-block boundaries exactly", {
  gaussian <- list(cross = list(
    version = "v2", dataset = "protected", outcome = "x",
    predictors = "z", intercept = TRUE))
  fixture <- .materializer_test_vertical_fixture(
    "peer_a", gaussian_specs = gaussian, capacity = 20000L)
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(0:31)))
  aligned <- .psi_attach_alignment_manifest(
    fixture$resolved$protected$data, "patient_id", token)
  alignment <- .psi_validate_alignment_manifest(aligned)
  fixture$resolved$protected$data <- aligned
  fixture$resolved$protected$dataset$public$alignment_manifest_hash <-
    alignment$hash
  fixture$policy$datasets$protected$alignment_manifest_hash <-
    alignment$hash
  fixture$policy$datasets$protected$alignment_manifest_version <-
    alignment$version
  layout <- .dsvert_dp_gaussian_cross_layout(fixture$manifest)
  expect_gt(layout$transport_coordinate_count,
            .DSVERT_DP_CAPSULE_VALUE_BLOCK)
  full <- .dsvert_dp_gaussian_cross_materialize_source(
    fixture$policy, fixture$manifest, fixture$resolved)
  producer <- .dsvert_dp_gaussian_cross_source_producer(
    fixture$policy, fixture$manifest, fixture$resolved)
  starts <- seq.int(1L, producer$coordinate_count, by = 7777L)
  streamed <- do.call(c, lapply(starts, function(start) {
    producer$read_range(
      start, min(7777L, producer$coordinate_count - start + 1L))
  }))
  expect_identical(streamed, full$values)
  expect_identical(producer$value_commitment_sha256,
                   full$value_commitment_sha256)
  expect_false("values" %in% names(producer))
})

test_that("Gaussian statistic assembly preserves the canonical byte order", {
  design <- lapply(seq_len(32L), function(index) {
    ((seq_len(17L) * (index + 2L)) %% 19L) / 18
  })
  outcome <- ((seq_len(17L) * 7L) %% 19L) / 18
  scale <- 2^10L
  reference <- length(outcome)
  for (right in seq_along(design)) {
    for (left in seq_len(right)) {
      reference <- c(reference, sum(round(
        design[[left]] * design[[right]] * scale)))
    }
  }
  reference <- c(
    reference,
    vapply(design, function(column) {
      sum(round(column * outcome * scale))
    }, numeric(1L)),
    sum(round(outcome^2 * scale)))

  actual <- .dsvert_dp_capsule_quantized_gaussian_stats(
    design, outcome, 10L)
  expect_identical(actual, unname(reference))
  expect_identical(
    serialize(actual, NULL, version = 3L),
    serialize(unname(reference), NULL, version = 3L))
})

test_that("Gaussian sensitivity bounds exhaust small neighbouring states", {
  scale <- 256
  states <- c(NA_real_, 0, 0.5, 1)
  vectors <- list(missing = rep(0, 7L))
  for (x in states[-1L]) {
    for (y in states[-1L]) {
      key <- paste(x, y, sep = "::")
      vectors[[key]] <- .dsvert_dp_capsule_quantized_gaussian_stats(
        list(1, x), y, 8L)
    }
  }
  raw_l1 <- 1 + 6 * scale
  raw_l2 <- sqrt(1 + 6 * scale^2) *
    (1 + 64 * .Machine$double.eps)
  zero <- rep(0, 7L)
  for (value in vectors) {
    delta <- value - zero
    expect_lte(sum(abs(delta)), raw_l1)
    expect_lte(sqrt(sum(delta^2)), raw_l2)
  }
  for (left in vectors) {
    for (right in vectors) {
      delta <- right - left
      expect_lte(sum(abs(delta)), raw_l1)
      expect_lte(sqrt(sum(delta^2)), raw_l2)
    }
  }

  add <- .materializer_test_fixture(
    data = .materializer_test_data()[FALSE, , drop = FALSE],
    capacity = 1L, gaussian_specs = list(model = list(
      version = "v1", dataset = "protected", outcome = "time",
      predictors = "x", intercept = TRUE)))
  replace <- .materializer_test_fixture(
    data = data.frame(
      patient_id = "u1", entry = 0, time = NA_real_, x = NA_real_,
      cat_a = "A", cat_b = "L", status = "censor"),
    adjacency = "replace_one_fixed_cohort", capacity = 1L,
    gaussian_specs = list(model = list(
      version = "v1", dataset = "protected", outcome = "time",
      predictors = "x", intercept = TRUE)))
  for (fixture in list(add, replace)) {
    artifact <- fixture$manifest$workload$families$
      gaussian_models$artifacts$model
    expect_identical(artifact$source_raw_l1_sensitivity, raw_l1)
    expect_gte(artifact$source_raw_l2_sensitivity, raw_l2)
    expect_identical(artifact$natural_l1_sensitivity, 7)
    expect_gte(artifact$natural_l2_sensitivity, sqrt(7))
  }
})

test_that("delayed-entry survival tie-breaking is row-order invariant", {
  fixture <- .materializer_test_fixture()
  fixture$data <- fixture$data[1:2, , drop = FALSE]
  fixture$data$time <- c(4, 4)
  fixture$data$entry <- c(4, 0)
  fixture$data$x <- c(5, 5)
  fixture$resolved$protected$data <- fixture$data
  first <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  fixture$data <- fixture$data[2:1, , drop = FALSE]
  row.names(fixture$data) <- NULL
  fixture$resolved$protected$data <- fixture$data
  second <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  expect_identical(second, first)
})

test_that("manifest snapshot and shape tampering fail before materialization", {
  fixture <- .materializer_test_fixture()
  tampered <- fixture$manifest
  tampered$workload$coordinate_count <-
    tampered$workload$coordinate_count + 1L
  expect_error(
    .dsvert_dp_capsule_materialize_local(
      fixture$policy, tampered, fixture$resolved),
    "identity|modified|contract")

  wrong_snapshot <- fixture$resolved
  wrong_snapshot$protected$dataset$public$version <- "v2"
  expect_error(
    .dsvert_dp_capsule_materialize_local(
      fixture$policy, fixture$manifest, wrong_snapshot),
    "snapshot binding")

  wrong_schema <- fixture$resolved
  wrong_schema$protected$data$x <- as.character(
    wrong_schema$protected$data$x)
  expect_error(
    .dsvert_dp_capsule_materialize_local(
      fixture$policy, fixture$manifest, wrong_schema),
    "configured DP query|numeric")
})

test_that("neighbour deltas satisfy every published L1 and L2 bound", {
  empty <- .materializer_test_data()[FALSE, , drop = FALSE]
  added_data <- data.frame(
    patient_id = "u1", entry = 10, time = 10, x = 10,
    cat_a = "B", cat_b = "R", status = "event")
  fixture <- .materializer_test_fixture(data = empty, capacity = 1L)
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  added <- fixture
  added$data <- added_data
  added$resolved$protected$data <- added_data
  right <- .dsvert_dp_capsule_materialize_local(
    added$policy, added$manifest, added$resolved)$values
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  bounds <- list(
    admitted_count = fixture$manifest$workload$families$admitted_count,
    numeric_moments = fixture$manifest$workload$families$numeric_moments,
    numeric_pair_moments =
      fixture$manifest$workload$families$numeric_pair_moments,
    fixed_numeric_histograms =
      fixture$manifest$workload$families$fixed_numeric_histograms,
    categorical_marginals =
      fixture$manifest$workload$families$categorical_marginals,
    categorical_pairs = fixture$manifest$workload$families$categorical_pairs,
    survival_artifacts =
      fixture$manifest$workload$families$survival_artifacts$primary)
  for (family in names(bounds)) {
    delta <- .materializer_test_family_delta(layout, left, right, family)
    expect_lte(sum(abs(delta)), bounds[[family]]$l1_sensitivity)
    expect_lte(sqrt(sum(delta^2)), bounds[[family]]$l2_sensitivity)
  }
  total <- right - left
  expect_lte(sum(abs(total)), fixture$manifest$workload$sensitivity$l1)
  expect_lte(sqrt(sum(total^2)),
             fixture$manifest$workload$sensitivity$l2)

  low_data <- data.frame(
    patient_id = "u1", entry = 0, time = 1, x = NA_real_,
    cat_a = "A", cat_b = "L", status = "censor")
  high_data <- data.frame(
    patient_id = "u2", entry = 10, time = 10, x = 10,
    cat_a = "B", cat_b = "R", status = "event")
  replacement <- .materializer_test_fixture(
    data = low_data, adjacency = "replace_one_fixed_cohort", capacity = 1L)
  low <- .dsvert_dp_capsule_materialize_local(
    replacement$policy, replacement$manifest,
    replacement$resolved)$values
  replacement$resolved$protected$data <- high_data
  high <- .dsvert_dp_capsule_materialize_local(
    replacement$policy, replacement$manifest,
    replacement$resolved)$values
  replacement_layout <- .dsvert_dp_capsule_coordinate_layout(
    replacement$manifest)
  replacement_bounds <- list(
    admitted_count =
      replacement$manifest$workload$families$admitted_count,
    numeric_moments =
      replacement$manifest$workload$families$numeric_moments,
    numeric_pair_moments =
      replacement$manifest$workload$families$numeric_pair_moments,
    fixed_numeric_histograms =
      replacement$manifest$workload$families$fixed_numeric_histograms,
    categorical_marginals =
      replacement$manifest$workload$families$categorical_marginals,
    categorical_pairs =
      replacement$manifest$workload$families$categorical_pairs,
    survival_artifacts =
      replacement$manifest$workload$families$survival_artifacts$primary)
  for (family in names(replacement_bounds)) {
    delta <- .materializer_test_family_delta(
      replacement_layout, low, high, family)
    expect_lte(sum(abs(delta)),
               replacement_bounds[[family]]$l1_sensitivity)
    expect_lte(sqrt(sum(delta^2)),
               replacement_bounds[[family]]$l2_sensitivity)
  }
  expect_identical(.materializer_test_family_delta(
    replacement_layout, low, high, "admitted_count"), 0)
})

test_that("the complete Gaussian workload satisfies common-lattice bounds", {
  gaussian <- list(model = list(
    version = "v1", dataset = "protected", outcome = "time",
    predictors = "x", intercept = TRUE))
  empty_data <- .materializer_test_data()[FALSE, , drop = FALSE]
  high_data <- data.frame(
    patient_id = "u1", entry = 10, time = 10, x = 10,
    cat_a = "B", cat_b = "R", status = "event")
  fixture <- .materializer_test_fixture(
    data = empty_data, capacity = 1L, gaussian_specs = gaussian)
  left <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)$values
  added <- fixture
  added$resolved$protected$data <- high_data
  right <- .dsvert_dp_capsule_materialize_local(
    added$policy, added$manifest, added$resolved)$values
  layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
    manifest = fixture$manifest, layout = layout))
  raw_delta <- right - left
  scaled_delta <- raw_delta * 2^lattice$scale_shifts
  gaussian_delta <- .materializer_test_family_delta(
    layout, left, right, "gaussian_models")
  gaussian_bounds <- fixture$manifest$workload$families$gaussian_models

  expect_lte(sum(abs(gaussian_delta)),
             gaussian_bounds$l1_sensitivity)
  expect_lte(sqrt(sum(gaussian_delta^2)),
             gaussian_bounds$l2_sensitivity)
  expect_lte(sum(abs(raw_delta)),
             fixture$manifest$workload$sensitivity$source_raw_l1)
  expect_lte(sqrt(sum(raw_delta^2)),
             fixture$manifest$workload$sensitivity$source_raw_l2)
  expect_lte(sum(abs(scaled_delta)),
             fixture$manifest$workload$sensitivity$l1)
  expect_lte(sqrt(sum(scaled_delta^2)),
             fixture$manifest$workload$sensitivity$l2)

  low_data <- data.frame(
    patient_id = "u1", entry = 0, time = NA_real_, x = NA_real_,
    cat_a = "A", cat_b = "L", status = "censor")
  replacement <- .materializer_test_fixture(
    data = low_data, adjacency = "replace_one_fixed_cohort",
    capacity = 1L, gaussian_specs = gaussian)
  low <- .dsvert_dp_capsule_materialize_local(
    replacement$policy, replacement$manifest,
    replacement$resolved)$values
  replacement$resolved$protected$data <- high_data
  high <- .dsvert_dp_capsule_materialize_local(
    replacement$policy, replacement$manifest,
    replacement$resolved)$values
  replacement_layout <- .dsvert_dp_capsule_coordinate_layout(
    replacement$manifest)
  replacement_lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
    manifest = replacement$manifest, layout = replacement_layout))
  replacement_delta <- (high - low) *
    2^replacement_lattice$scale_shifts
  expect_lte(sum(abs(replacement_delta)),
             replacement$manifest$workload$sensitivity$l1)
  expect_lte(sqrt(sum(replacement_delta^2)),
             replacement$manifest$workload$sensitivity$l2)
})

test_that("random complete-capsule neighbours satisfy composed bounds", {
  withr::local_seed(20260801)
  gaussian <- list(model = list(
    version = "v1", dataset = "protected", outcome = "time",
    predictors = c("entry", "x"), intercept = TRUE))
  empty <- .materializer_test_data()[FALSE, , drop = FALSE]
  add_fixture <- .materializer_test_fixture(
    data = empty, capacity = 1L, max_records = 3L,
    gaussian_specs = gaussian)
  replacement_fixture <- .materializer_test_fixture(
    data = data.frame(
      patient_id = "u0", entry = NA_real_, time = NA_real_, x = NA_real_,
      cat_a = NA_character_, cat_b = NA_character_,
      status = NA_character_),
    adjacency = "replace_one_fixed_cohort", capacity = 1L,
    max_records = 3L, gaussian_specs = gaussian)

  random_unit <- function(id) {
    rows <- sample.int(3L, 1L)
    data.frame(
      patient_id = rep(id, rows),
      entry = sample(c(NA_real_, -Inf, -1, 0, 4, 10, Inf),
                     rows, replace = TRUE),
      time = sample(c(NA_real_, -Inf, -1, 0, 5, 10, Inf),
                    rows, replace = TRUE),
      x = sample(c(NA_real_, -Inf, -1, 0, 5, 10, 11, Inf),
                 rows, replace = TRUE),
      cat_a = sample(c(NA_character_, "A", "B", "outside"),
                     rows, replace = TRUE),
      cat_b = sample(c(NA_character_, "L", "R", "outside"),
                     rows, replace = TRUE),
      status = sample(c(NA_character_, "censor", "event", "outside"),
                      rows, replace = TRUE),
      stringsAsFactors = FALSE)
  }
  materialize <- function(fixture, data) {
    fixture$resolved$protected$data <- data
    .dsvert_dp_capsule_materialize_local(
      fixture$policy, fixture$manifest, fixture$resolved)$values
  }
  within_bounds <- function(delta, fixture) {
    layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
    lattice <- .dsvert_joint_dp_vector_lattice_vectors(list(
      manifest = fixture$manifest, layout = layout))
    scaled <- delta * 2^lattice$scale_shifts
    sensitivity <- fixture$manifest$workload$sensitivity
    sum(abs(delta)) <= sensitivity$source_raw_l1 &&
      sqrt(sum(delta^2)) <= sensitivity$source_raw_l2 &&
      sum(abs(scaled)) <= sensitivity$l1 &&
      sqrt(sum(scaled^2)) <= sensitivity$l2
  }

  add_zero <- materialize(add_fixture, empty)
  valid <- logical(100L)
  for (iteration in seq_along(valid)) {
    added <- materialize(add_fixture, random_unit("u1"))
    first <- materialize(replacement_fixture, random_unit("u1"))
    second <- materialize(replacement_fixture, random_unit("u2"))
    valid[[iteration]] <-
      within_bounds(added - add_zero, add_fixture) &&
      within_bounds(second - first, replacement_fixture)
  }
  expect_true(all(valid))
})

test_that("large repeated snapshots materialize with bounded result state", {
  units <- 20000L
  records <- 4L
  data <- data.frame(
    patient_id = rep(sprintf("u%05d", seq_len(units)), each = records),
    entry = rep(c(0, 1, 2, 3), units),
    time = rep(c(5, 5, 5, 5), units),
    x = rep(c(0, 2, 8, 10), units),
    cat_a = "A", cat_b = "L", status = "censor",
    stringsAsFactors = FALSE)
  fixture <- .materializer_test_fixture(
    data = data, capacity = units, max_records = records)
  material <- .dsvert_dp_capsule_materialize_local(
    fixture$policy, fixture$manifest, fixture$resolved)
  expect_identical(material$values[[1L]], as.numeric(units))
  expect_equal(length(material$values),
               fixture$manifest$workload$coordinate_count)
  expect_lt(as.numeric(object.size(material)), 2e6)

  probe <- as.numeric(seq_len(2L * .DSVERT_DP_CAPSULE_VALUE_BLOCK + 17L))
  binding <- list(test = "blockwise")
  first <- .dsvert_dp_capsule_value_commitment(probe, binding)
  probe[[length(probe)]] <- probe[[length(probe)]] + 1
  expect_false(identical(
    first, .dsvert_dp_capsule_value_commitment(probe, binding)))
})

test_that("signed coordinate bounds reject U+1 before secret sharing", {
  fixture <- .materializer_test_fixture()
  validated <- .dsvert_dp_capsule_materializer_manifest(
    fixture$policy, fixture$manifest)
  lattice <- .dsvert_joint_dp_vector_lattice_vectors(validated)
  upper <- as.numeric(lattice$raw_upper_bounds)
  values <- numeric(length(upper))
  values[[1L]] <- upper[[1L]]
  expect_silent(.dsvert_dp_capsule_assert_signed_coordinate_bounds(
    values, validated))

  values[[1L]] <- upper[[1L]] + 1
  condition <- tryCatch(
    .dsvert_dp_capsule_assert_signed_coordinate_bounds(values, validated),
    error = identity)
  expect_s3_class(
    condition, "dsvert_dp_capsule_coordinate_range_error")
  expect_identical(condition$code, "coordinate_out_of_signed_range")
  expect_identical(condition$coordinate_index, 1L)
  expect_identical(condition$phase, "before_secret_sharing")
  expect_false(any(grepl(
    format(values[[1L]], scientific = FALSE, trim = TRUE),
    c(condition$message, names(condition)), fixed = TRUE)))
})

test_that("local materializer creates no exported or remote surface", {
  exports <- getNamespaceExports("dsVert")
  expect_false(".dsvert_dp_capsule_materialize_local" %in% exports)
  expect_false(any(grepl("capsule.*material", exports, ignore.case = TRUE)))
  remote <- .dsvert_registered_remote_methods(
    system.file("DESCRIPTION", package = "dsVert"))
  expect_false(any(grepl("capsule.*material", remote, ignore.case = TRUE)))
  expect_false(grepl("DS$", ".dsvert_dp_capsule_materialize_local"))
})

test_that("finite binomial and Poisson grid losses are bounded and exact", {
  design <- list(rep(1, 4L), c(0, 0, 1, 1))
  beta_grid <- list(c(0, 0), c(0, 1))
  binomial <- .dsvert_dp_capsule_quantized_glm_grid_losses(
    design, c(0, 0, 1, 1), "binomial", beta_grid, 8L)
  poisson <- .dsvert_dp_capsule_quantized_glm_grid_losses(
    design, c(0, 1, 2, 4), "poisson", beta_grid, 8L, 8L)
  expect_length(binomial, 2L)
  expect_length(poisson, 2L)
  expect_true(all(binomial >= 0 & binomial == floor(binomial)))
  expect_true(all(poisson >= 0 & poisson == floor(poisson)))
  expect_error(.dsvert_dp_capsule_quantized_glm_grid_losses(
    design, c(0, 2, 1, 1), "binomial", beta_grid, 8L),
    "finite GLM likelihood-grid")
  expect_error(.dsvert_dp_capsule_quantized_glm_grid_losses(
    design, c(0, 1, 2, 9), "poisson", beta_grid, 8L, 8L),
    "finite GLM likelihood-grid")
})
