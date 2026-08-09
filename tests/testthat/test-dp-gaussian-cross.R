.cross_gaussian_test_b64url <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.cross_gaussian_test_signature <- function(message, pin) {
  pin_raw <- .dsvert_relay_b64url_decode(pin, "test pin")
  .cross_gaussian_test_b64url(openssl::sha512(c(message, pin_raw)))
}

.cross_gaussian_test_signer <- function(message, peer_name, pin) {
  .cross_gaussian_test_signature(message, pin)
}

.cross_gaussian_test_verifier <- function(message, pin, signature) {
  identical(signature, .cross_gaussian_test_signature(message, pin))
}

.cross_gaussian_test_selector <- function(
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

.cross_gaussian_test_fixture <- function() {
  pins <- c(
    peer_a = .cross_gaussian_test_b64url(as.raw(seq_len(32L))),
    peer_b = .cross_gaussian_test_b64url(as.raw(32L + seq_len(32L))))
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  logical_snapshot <- list(
    logical_snapshot_id = "cross-gaussian-aligned-cohort",
    version = "v1", alignment_protocol_version = 1L)
  schema <- list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = pin_hash,
    datasets = list(
      protected = list(
        dataset_id = "cohort-a", dataset_version = "v1",
        schema_version = "schema-v1", alignment_group = "aligned-main",
        patient_keys = list(peer_a = "patient_id"),
        columns = list(x = list(
          kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 10))),
      remote = list(
        dataset_id = "cohort-b", dataset_version = "v1",
        schema_version = "schema-v1", alignment_group = "aligned-main",
        patient_keys = list(peer_b = "patient_id"),
        columns = list(z = list(
          kind = "numeric", owner_peer = "peer_b", lower = -1, upper = 1)))),
    signatures = list(peer_a = strrep("A", 86L),
                      peer_b = strrep("B", 86L)))
  policy <- list(
    domain = "cross-gaussian-study", cohort_id = "cohort-v1",
    peer_name = "peer_a", peer_pinset = pins,
    peer_pinset_sha256 = pin_hash, peer_count = 2L,
    designated_noise_peers = names(pins),
    global_total_epsilon = 1, global_total_delta = 1e-6,
    lifetime_max_distinct_capsules = 8,
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = 2L, fixed_cohort_size = NULL,
    max_records_per_unit = 1L, overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    numeric_grid_bits = 8L,
    numeric_bounds = list(x = c(0, 10)), categorical_levels = list(),
    datasets = list(protected = list(
      id = "cohort-a", version = "v1", snapshot_sha256 = NULL,
      alignment_manifest_hash = NULL, alignment_manifest_version = 1L)),
    noise_root = list(epoch = 1, key_id = "cross-gaussian-test-root"),
    ledger_path = tempfile("cross-gaussian-ledger-"),
    ledger_private = FALSE, lock_timeout_ms = 30000)
  store_path <- .dsvert_dp_capsule_source_store_path(policy)
  resource_owner <- .dsvert_dp_capsule_source_resource_owner(policy)
  withr::defer({
    .dsvert_resource_external_unregister(resource_owner)
    unlink(c(
      store_path, paste0(store_path, ".lock"),
      paste0(store_path, "-wal"), paste0(store_path, "-shm")),
      force = TRUE)
  }, envir = parent.frame())
  manifest <- .dsvert_dp_capsule_workload_manifest(
    policy, logical_snapshot, schema,
    describe_specs = list(), survival_specs = list(),
    gaussian_specs = list(cross = list(
      version = "v2", dataset = "protected", outcome = "x",
      predictors = "z", intercept = TRUE)),
    .signature_verifier = function(...) TRUE,
    .noise_selector = .cross_gaussian_test_selector)
  list(
    policy = policy, secret = as.raw(1:32), manifest = manifest,
    manifest_json = .dsvert_dp_canonical_json(manifest))
}

.cross_gaussian_test_records <- function(values) {
  stopifnot(is.numeric(values), !anyNA(values),
            all(values >= 0), all(values == floor(values)),
            all(values <= 2^53 - 1))
  result <- raw(length(values) * 16L)
  for (index in seq_along(values)) {
    value <- values[[index]]
    first <- (index - 1L) * 16L + 1L
    for (byte in 0:6) {
      result[[first + byte]] <- as.raw(floor(value / 256^byte) %% 256)
    }
  }
  result
}

.cross_gaussian_test_decode <- function(value) {
  stopifnot(is.raw(value), length(value) %% 16L == 0L)
  records <- matrix(as.integer(value), nrow = 16L)
  stopifnot(all(records[8:16, , drop = FALSE] == 0L))
  unname(colSums(records[1:7, , drop = FALSE] * 256^(0:6)))
}

.cross_gaussian_test_reducer <- function(input) {
  bytes <- jsonlite::base64_dec(input$records)
  values <- .cross_gaussian_test_decode(bytes)
  lengths <- as.integer(input$segment_lengths)
  cursor <- 1L
  sums <- vapply(lengths, function(length) {
    value <- sum(values[seq.int(cursor, length.out = length)])
    cursor <<- cursor + length
    value
  }, numeric(1L))
  list(
    version = .DSVERT_DP_GAUSSIAN_CROSS_REDUCER_VERSION,
    segment_count = length(lengths),
    sums = gsub("[\r\n]", "", jsonlite::base64_enc(
      .cross_gaussian_test_records(sums))))
}

test_that("cross Gaussian Ring128 reduction is segmented and contract checked", {
  local_mocked_bindings(
    .DSVERT_DP_GAUSSIAN_CROSS_REDUCER_MAX_RECORDS = 4L,
    .package = "dsVert")
  encoded <- gsub("[\r\n]", "", jsonlite::base64_enc(
    .cross_gaussian_test_records(1:6)))
  calls <- 0L
  reducer <- function(input) {
    calls <<- calls + 1L
    .cross_gaussian_test_reducer(input)
  }
  reduced <- .dsvert_dp_gaussian_cross_reduce(
    encoded, 2L, 3L, reducer)
  expect_identical(.cross_gaussian_test_decode(reduced), c(3, 7, 11))
  expect_identical(calls, 2L)

  expect_error(.dsvert_dp_gaussian_cross_reduce(
    encoded, 2L, 3L, function(input) list(
      version = "wrong", segment_count = 3L, sums = input$records)),
    "violated its contract")
})

test_that("cross Gaussian release assembly exactly follows v2 coordinate order", {
  count <- .cross_gaussian_test_records(10)
  masked <- .cross_gaussian_test_records(c(11, 12, 13))
  moments <- .cross_gaussian_test_records(c(21, 22, 23, 24, 25, 26))
  binding <- list(
    variable_count = 3L,
    artifact = list(intercept = TRUE, coordinate_count = 11L))
  with_intercept <- .dsvert_dp_gaussian_cross_assemble(
    binding, count, masked, moments)
  expect_identical(
    .cross_gaussian_test_decode(with_intercept),
    c(10, 10, 11, 21, 12, 22, 23, 13, 24, 25, 26))

  binding$artifact$intercept <- FALSE
  binding$artifact$coordinate_count <- 7L
  without_intercept <- .dsvert_dp_gaussian_cross_assemble(
    binding, count, masked, moments)
  expect_identical(
    .cross_gaussian_test_decode(without_intercept),
    c(10, 21, 22, 23, 24, 25, 26))
})

test_that("cross Gaussian exact manifests accept only the active producer stage", {
  ss <- new.env(parent = emptyenv())
  purpose <- "dp.gaussian-cross.0123456789abcdefabcd.moments"
  ss$.dp_gaussian_cross_stage <- list(
    status = "preparing", producer = .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER,
    purpose = purpose, x_key = "gaussian_x", y_key = "gaussian_y",
    output_key = "gaussian_z", ring_bits = 128L, frac_bits = 8L,
    operand_bound = "256")
  expect_identical(
    .exact_gc_vecmul_manifest_policy(
      .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER, purpose, ss),
    list(
      x_key = "gaussian_x", y_key = "gaussian_y",
      output_key = "gaussian_z", bound_x = "256", bound_y = "256",
      ring_bits = 128L, frac_bits = 8L))
  ss$.dp_gaussian_cross_stage$status <- "prepared"
  expect_error(.exact_gc_vecmul_manifest_policy(
    .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER, purpose, ss), "provenance")
  ss$.dp_gaussian_cross_stage$status <- "preparing"
  expect_error(.exact_gc_vecmul_manifest_policy(
    .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER, paste0(purpose, "-other"), ss),
    "provenance")
})

test_that("cross Gaussian finalizer persists only an authenticated result share", {
  fixture <- .cross_gaussian_test_fixture()
  artifact <- .dsvert_dp_gaussian_cross_artifacts(
    fixture$manifest)$cross
  parsed <- .dsvert_dp_capsule_source_contract_json(
    fixture$policy, fixture$manifest_json)
  contract <- parsed$contract
  release_layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  private_layout <- .dsvert_dp_gaussian_cross_layout(fixture$manifest)
  block <- release_layout$blocks[["gaussian_models::cross"]]
  session_id <- "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  ss <- new.env(parent = emptyenv())
  ss$.exact_gc_peer_binding_digest <- strrep("d", 64L)
  ss$.exact_gc_vecmul_manifests <- list()
  ss$.exact_gc_vecmul_input_stages <- list()

  stages <- list(
    list(stage = "validity", stage_index = 1L, values = c(256, 256)),
    list(stage = "masked-values", stage_index = 1L,
         values = c(0, 256, 0, 256)),
    list(stage = "moments", stage_index = 1L,
         values = c(0, 256, 0, 256, 0, 256)))
  binding_stages <- list()
  for (index in seq_along(stages)) {
    stage <- stages[[index]]
    key <- .dsvert_dp_gaussian_cross_stage_key(
      stage$stage, stage$stage_index)
    output_key <- paste0("gaussian_output_", index)
    handle <- paste0(strrep(LETTERS[[index]], 42L), index)
    batch <- paste0("gaussian-batch-", index)
    purpose <- paste0(
      "dp.gaussian-cross.test.", stage$stage, "-", stage$stage_index)
    encoded <- gsub("[\r\n]", "", jsonlite::base64_enc(
      .cross_gaussian_test_records(stage$values)))
    ss[[output_key]] <- encoded
    ss$.exact_gc_vecmul_manifests[[handle]] <- list(
      state = "consumed", producer = .DSVERT_DP_GAUSSIAN_CROSS_PRODUCER,
      purpose = purpose, output_key = output_key,
      claimed_batch = batch, context_hash = strrep(as.character(index), 64L),
      total_n = length(stage$values),
      plan = list(
        plan_id = strrep(as.character(index + 3L), 64L),
        ring_bits = 128L, frac_bits = 8L, backend = "direct-wide"))
    ss$.exact_gc_vecmul_input_stages[[batch]] <- list(
      state = "complete", manifest_handle = handle,
      output_key = output_key,
      output_digest = .exact_gc_vecmul_value_digest(encoded),
      context_hash = strrep(as.character(index + 6L), 64L))
    binding_stages[[key]] <- list(
      stage = stage$stage, stage_index = stage$stage_index,
      purpose = purpose, output_key = output_key,
      manifest_handle = handle, installed = character())
  }
  binding <- list(
    version = .DSVERT_DP_GAUSSIAN_CROSS_BIND_VERSION,
    capsule_id = contract$capsule_id, analysis_id = "cross",
    artifact = artifact, artifact_sha256 = .dsvert_joint_dp_hash(artifact),
    source_contract_hash = parsed$contract_hash,
    private_layout_sha256 =
      private_layout$transport_coordinate_order_sha256,
    transcript_sha256 = .dsvert_joint_dp_hash(artifact$transcript),
    numeric_certificate_sha256 =
      .dsvert_joint_dp_hash(artifact$numeric_certificate),
    peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    capacity = 2L, variable_count = 2L,
    variables = c("z", "x"), grid_bits = 8L,
    value_keys = c(z = "private_z", x = "private_x"),
    validity_keys = c(z = "valid_z", x = "valid_x"),
    stages = binding_stages, state = "installed")
  ss$.dp_gaussian_cross_bindings <- list(cross = binding)

  finalize <- function(reducer = .cross_gaussian_test_reducer) {
    testthat::with_mocked_bindings(
      .dsvert_dp_gaussian_cross_finalize_impl(
        fixture$manifest_json, "cross", session_id,
        .policy = fixture$policy, .secret = fixture$secret,
        .signer = .cross_gaussian_test_signer,
        .verifier = .cross_gaussian_test_verifier,
        .reducer = reducer),
      .S = function(id) {
        expect_identical(id, session_id)
        ss
      },
      .exact_gc_vecmul_validate_manifest_mac = function(...) invisible(TRUE),
      .package = "dsVert")
  }
  receipt_json <- finalize()
  receipt <- .dsvert_dp_capsule_source_decode_json(
    receipt_json, "test Gaussian receipt", 128L * 1024L)
  expect_identical(receipt$state, "complete")
  expect_false(receipt$result_share_exposed)
  expect_false(receipt$exact_intermediates_exposed)
  expect_false(receipt$alignment_hash_exposed)
  expect_false(receipt$alignment_hash_exposed_to_relay)
  expect_false(receipt$alignment_hash_exposed_to_computation_peers)
  expect_false(any(c("share", "values", "count", "moments") %in%
                     names(receipt)))

  stored <- .dsvert_dp_capsule_source_with_store(
    fixture$policy, fixture$secret, function(connection) {
      .dsvert_dp_gaussian_cross_result_load(
        connection, contract$capsule_id, "cross", fixture$secret)
    })
  expect_identical(
    .cross_gaussian_test_decode(.dsvert_relay_b64url_decode(
      stored$result_share_b64, "stored Gaussian share")),
    c(512, 512, 256, 256, 256, 256, 256))
  expect_identical(finalize(function(...) stop("must replay")), receipt_json)

  injected <- .dsvert_dp_capsule_source_with_store(
    fixture$policy, fixture$secret, function(connection) {
      .dsvert_dp_gaussian_cross_inject_release_share_internal(
        connection, fixture$secret, fixture$manifest, contract,
        list(offset = 0L, count = release_layout$coordinate_count),
        raw(release_layout$coordinate_count * 16L))
    })
  coordinates <- seq.int(block$start, block$end)
  bytes <- unlist(lapply(coordinates, function(coordinate) {
    first <- (coordinate - 1L) * 16L + 1L
    seq.int(first, length.out = 16L)
  }), use.names = FALSE)
  expect_identical(
    .cross_gaussian_test_decode(injected[bytes]),
    c(512, 512, 256, 256, 256, 256, 256))
})
