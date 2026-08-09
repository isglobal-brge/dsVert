#!/usr/bin/env Rscript

# Reproducible development benchmark for the bounded-numeric cache retained by
# the biomedical capsule materializer. Run from the dsVert repository root:
#
#   Rscript experiments/capsule-materializer-memory/benchmark.R

devtools::load_all(".", quiet = TRUE)

.benchmark_b64url <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.benchmark_noise_selector <- function(
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

.benchmark_fixture <- function(n, p) {
  variables <- sprintf("x%03d", seq_len(p))
  pins <- c(
    peer_a = .benchmark_b64url(as.raw(seq_len(32L))),
    peer_b = .benchmark_b64url(as.raw(32L + seq_len(32L))))
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  bounds <- stats::setNames(rep(list(c(0, 1)), p), variables)
  policy <- list(
    domain = "materializer-memory-benchmark", cohort_id = "cohort-v1",
    peer_name = "peer_a", peer_pinset = pins,
    peer_pinset_sha256 = pin_hash, peer_count = 2L,
    designated_noise_peers = names(pins),
    global_total_epsilon = 1, global_total_delta = 1e-6,
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = as.integer(n), fixed_cohort_size = NULL,
    max_records_per_unit = 1L, overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    numeric_grid_bits = 8L, numeric_bounds = bounds,
    categorical_levels = list(),
    capsule_workload_scope = list(mode = "all_schema"),
    datasets = list(protected = list(
      id = "materializer-memory-cohort", version = "v1",
      snapshot_sha256 = NULL, alignment_manifest_hash = NULL,
      alignment_manifest_version = 1L)),
    noise_root = list(epoch = 1, key_id = "materializer-memory-root"),
    ledger_path = tempfile("materializer-memory-ledger-"))
  logical_snapshot <- list(
    logical_snapshot_id = "materializer-memory-snapshot",
    version = "v1", alignment_protocol_version = 1L)
  columns <- stats::setNames(lapply(variables, function(variable) {
    list(kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 1)
  }), variables)
  schema <- list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = pin_hash,
    datasets = list(protected = list(
      dataset_id = "materializer-memory-cohort", dataset_version = "v1",
      schema_version = "schema-v1", alignment_group = "aligned-main",
      patient_keys = list(peer_a = "patient_id"), columns = columns)),
    signatures = list(
      peer_a = strrep("A", 86L), peer_b = strrep("B", 86L)))
  describe <- stats::setNames(lapply(variables, function(variable) {
    list(
      version = "v1", dataset = "protected", variables = variable,
      histogram_grids = stats::setNames(list(c(0.25, 0.5, 0.75, 1)),
                                          variable),
      allocation = c(
        count = 0.2, sum = 0.3, sumsq = 0.3, histogram = 0.2))
  }), variables)
  manifest <- .dsvert_dp_capsule_workload_manifest(
    policy, logical_snapshot, schema, describe_specs = describe,
    survival_specs = list(), gaussian_specs = list(),
    .noise_selector = .benchmark_noise_selector,
    .signature_verifier = function(...) TRUE)
  data <- data.frame(
    patient_id = sprintf("u%09d", seq_len(n)),
    stringsAsFactors = FALSE)
  row <- seq_len(n)
  for (index in seq_along(variables)) {
    data[[variables[[index]]]] <-
      ((row * (2L * index + 1L)) %% (n + 1L)) / n
  }
  resolved <- list(protected = list(
    data = data,
    dataset = list(
      public = list(
        data_name = "protected", id = "materializer-memory-cohort",
        version = "v1", alignment_manifest_hash = NULL,
        alignment_manifest_version = 1L),
      fingerprint = strrep("a", 64L))))
  list(
    n = n, p = p, variables = variables, policy = policy,
    manifest = manifest, resolved = resolved, data = data)
}

.benchmark_case <- function(n, p) {
  fixture <- .benchmark_fixture(n, p)
  admission <- .dsvert_dp_admit_units(fixture$data, fixture$policy)
  full_cache <- lapply(fixture$variables, function(variable) {
    .dsvert_dp_bounded_numeric(
      fixture$data, fixture$policy, variable, admission)
  })
  compact_cache <- lapply(
    full_cache, .dsvert_dp_capsule_compact_bounded_numeric)
  unique_values_bytes <- sum(vapply(
    full_cache, function(column) as.numeric(object.size(column$values)),
    numeric(1L)))
  full_cache_bytes <- as.numeric(object.size(full_cache))
  compact_cache_bytes <- as.numeric(object.size(compact_cache))
  rm(full_cache, compact_cache)

  materialize_full <- function() {
    testthat::with_mocked_bindings(
      .dsvert_dp_capsule_materialize_local(
        fixture$policy, fixture$manifest, fixture$resolved),
      .dsvert_dp_capsule_compact_bounded_numeric = identity,
      .package = "dsVert")
  }
  materialize_compact <- function() {
    .dsvert_dp_capsule_materialize_local(
      fixture$policy, fixture$manifest, fixture$resolved)
  }
  # Warm both paths, then alternate their order so package loading, allocator
  # state and run order do not become a one-sided timing advantage.
  invisible(materialize_full())
  invisible(materialize_compact())
  full_times <- compact_times <- numeric(3L)
  for (iteration in seq_len(3L)) {
    gc()
    if (iteration %% 2L) {
      full_times[[iteration]] <- system.time(
        full <- materialize_full())[["elapsed"]]
      compact_times[[iteration]] <- system.time(
        compact <- materialize_compact())[["elapsed"]]
    } else {
      compact_times[[iteration]] <- system.time(
        compact <- materialize_compact())[["elapsed"]]
      full_times[[iteration]] <- system.time(
        full <- materialize_full())[["elapsed"]]
    }
  }

  list(
    n = n, p = p,
    same_owner_pairs = p * (p - 1L) / 2L,
    coordinate_count = compact$coordinate_count,
    full_cache_object_bytes = full_cache_bytes,
    compact_cache_object_bytes = compact_cache_bytes,
    object_bytes_removed = full_cache_bytes - compact_cache_bytes,
    unique_values_bytes_removed = unique_values_bytes,
    full_median_elapsed_seconds = unname(stats::median(full_times)),
    compact_median_elapsed_seconds = unname(stats::median(compact_times)),
    serialized_identical = identical(
      serialize(compact, NULL, version = 3L),
      serialize(full, NULL, version = 3L)),
    values_identical = identical(compact$values, full$values),
    commitment_identical = identical(
      compact$value_commitment_sha256, full$value_commitment_sha256),
    authenticatable_identical = identical(
      compact$authenticatable_sha256, full$authenticatable_sha256))
}

cases <- list(c(n = 2000L, p = 8L),
              c(n = 8000L, p = 16L),
              c(n = 20000L, p = 24L))
results <- lapply(cases, function(case) {
  .benchmark_case(unname(case[["n"]]), unname(case[["p"]]))
})
print(as.data.frame(do.call(rbind, lapply(results, as.data.frame))),
      row.names = FALSE)
