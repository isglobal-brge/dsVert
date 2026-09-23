.frequency_exact_runtime <- function(command, input) {
  binary <- Sys.getenv("DSVERT_EXACT_TEST_BINARY")
  if (!nzchar(binary)) binary <- tryCatch(.findMpcBinary(), error = function(e) "")
  skip_if(!nzchar(binary) || !file.exists(binary), "No packaged MPC runtime")
  file <- tempfile(fileext = ".json")
  on.exit(unlink(file), add = TRUE)
  writeLines(jsonlite::toJSON(input, auto_unbox = TRUE, null = "null", digits = 17), file)
  result <- processx::run(binary, command, stdin = file, error_on_status = FALSE)
  if (result$status != 0L) stop(result$stderr, result$stdout)
  value <- jsonlite::fromJSON(result$stdout, simplifyVector = FALSE)
  if (!is.null(value$error)) stop(value$error)
  value
}

test_that("Frequency production exact fallback admits zero delta and binds utility bounds", {
  privacy <- list(adjacency = "add_remove_patient", epsilon = 1, delta = 0)
  calibration <- list(implementation_delta = 0)
  selection <- .dsvert_dp_analysis_frequency_backend_selection_v3(
    privacy, calibration, 3, 100, .selector = function(input)
      .frequency_exact_runtime("joint-dp-frequency-backend-select-v2", input))
  expect_identical(selection$summary$selected_primitive,
    "independent_full_global_draw_convolution_ring128_v4")
  expect_false(selection$summary$candidates$gaussian$available)
  expect_identical(selection$selected_plan$guarantee, "pure-dp-under-ideal-bits")
  expect_identical(selection$selected_plan$randomness, "keyed-stream-computational")
  expect_identical(selection$selected_plan$implementation_delta_bound, "0")
  config <- list(backend_selection = selection, privacy = privacy,
    calibration = calibration, factor_domain = list(dimension = 3,
      levels = as.list(c("a", "b", "c"))), coordinate_upper_bound = 100,
    transport_chunk_coordinates = 3)
  summary <- .dsvert_dp_frequency_plan_summary_v1(config)
  expect_identical(summary$version, "dsvert-frequency-plan-summary-v2")
  expect_identical(summary$maximum_noise_per_peer, "unbounded")
  expect_null(summary$no_wrap_sha256)
  expect_true(summary$wrap_certificate$wrap_bound_certified)
  expect_match(summary$wrap_certificate$representability_bound, "^1e-[1-9][0-9]*$")
  expect_false(identical(summary$wrap_certificate$sum_wrap_bound,
                         summary$wrap_certificate$representability_bound))
  expect_identical(selection$selected_accuracy_certificate$simultaneous_95_abs, "18")
  altered <- config
  altered$backend_selection$selected_plan$representability_bound <- "0"
  expect_error(.dsvert_dp_frequency_plan_summary_v1(altered), "certificate")
  for (epsilon in c(2^-101, 10001)) {
    invalid <- privacy
    invalid$epsilon <- epsilon
    expect_error(.dsvert_dp_analysis_frequency_backend_selection_v3(
      invalid, calibration, 3, 100, .selector = function(input) stop("sampler accessed")),
      "admitted ranges")
  }
})

test_that("Frequency validates production modular shares, decoding, and sticky replay", {
  oracle <- .frequency_exact_runtime("joint-dp-vector-convolution-oracle-v1", list(
    version = "dsvert-dp-statistical-noise-oracle-input-v1", epsilon = "1",
    allocated_delta = "0", sensitivity_steps = "1", coordinate_count = 3L,
    replicates = 1L, garbler_seed = strrep("1", 64), evaluator_seed = strrep("2", 64),
    release_contract_hash = strrep("3", 64), transcript_hash = strrep("4", 64)))
  draw <- oracle$draws[[1L]]
  profile <- .dsvert_dp_analysis_frequency_profile_v1(oracle$backend)
  authorization <- list(worker_static = list(selected_profile = profile,
    selected_primitive = oracle$backend, selected_plan = oracle$plan,
    raw_bound = list(upper = "1")))
  left <- .frequency_exact_runtime("joint-dp-vector-convolution-share-v4", draw$garbler_input)
  right <- .frequency_exact_runtime("joint-dp-vector-convolution-share-v4", draw$evaluator_input)
  expect_identical(left, .frequency_exact_runtime(
    "joint-dp-vector-convolution-share-v4", draw$garbler_input))
  expect_length(.dsvert_dp_frequency_execution_share_v1(
    left, draw$garbler_input, authorization), 48L)
  expect_null(left$no_wrap_headroom_certified)
  expect_true(left$wrap_bound_certified)
  expect_identical(left$maximum_noise_magnitude_per_peer, "unbounded")
  policy_fields <- c("ring_bits", "frac_bits", "total_coordinate_count",
    "chunk_start", "coordinate_count", "output_lattice_bits", "epsilon",
    "allocated_delta", "sensitivity_steps", "scale_shifts", "raw_upper_bounds",
    "release_contract_hash", "transcript_hash")
  input <- c(list(version = "dsvert-joint-dp-vector-independent-full-draw-finalizer-input-v4"),
    draw$garbler_input[policy_fields], list(left_noised_share = left$noised_share,
      right_noised_share = right$noised_share))
  final <- .frequency_exact_runtime("joint-dp-vector-convolution-finalize-v4", input)
  expect_identical(final$signed_decode, "canonical_Ring128_twos_complement_after_modular_addition")
  values <- .dsvert_dp_frequency_execution_final_v1(final, input, authorization)
  expect_equal(values, pmin(1, pmax(0, as.numeric(unlist(draw$sum)))))
  expect_identical(final, .frequency_exact_runtime("joint-dp-vector-convolution-finalize-v4", input))
  final$no_wrap_headroom_certified <- TRUE
  expect_error(.dsvert_dp_frequency_execution_final_v1(final, input, authorization), "invalid chunk")
  left$sum_wrap_bound <- "0"
  expect_error(.dsvert_dp_frequency_execution_share_v1(left, draw$garbler_input, authorization), "invalid share")
})
