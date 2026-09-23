test_that("exact production plans admit zero delta and bind the pure certificate", {
  request <- list(epsilon = "1", delta = "0", sensitivity_steps = "256",
                  total_coordinate_count = 3L)
  plan <- .callMpcTool("joint-dp-vector-convolution-plan-v4", request)
  expect_silent(.dsvert_joint_dp_pure_plan_validate(plan, request))
  expect_identical(plan$guarantee, "pure-dp-under-ideal-bits")
  expect_identical(plan$randomness, "keyed-stream-computational")
  expect_identical(plan$implementation_delta_bound, "0")
  expect_identical(plan$per_peer_implementation_delta_bound, "0")
  expect_identical(plan$maximum_noise_magnitude, "unbounded")
  expect_identical(plan$wrap_bound_certified, TRUE)
  expect_match(plan$representability_bound, "^1e-[1-9][0-9]*$")
  expect_null(plan$no_wrap_headroom_certified)
  for (field in c("guarantee", "randomness", "representability_bound",
                  "noise_commitment", "implementation_delta_numerator")) {
    altered <- plan
    altered[[field]] <- "invalid"
    expect_error(.dsvert_joint_dp_pure_plan_validate(altered, request), "certificate")
  }
  altered <- plan
  altered$admitted_ranges$ring_bits <- 127L
  expect_error(.dsvert_joint_dp_pure_plan_validate(altered, request), "certificate")

  profile <- .dsvert_joint_dp_vector_profile("discrete-laplace",
    .DSVERT_JOINT_DP_VECTOR_PURE_BACKEND)
  ring <- .dsvert_dp_synopsis_ring_certificate_v1(
    list(raw_upper_bounds = c("100", "200", "300"), scale_shifts = c(0L, 1L, 2L)),
    plan, profile)
  expect_null(ring$no_wrap_certified)
  expect_identical(ring$maximum_scaled_source_coordinate, "1200")
  expect_identical(ring$wrap_bound_certified, TRUE)
  expect_match(ring$sum_wrap_bound, "^1e-[1-9][0-9]*$")
  expect_identical(.dsvert_joint_dp_vector_public_backend_choice(1L,
    "dsvert-joint-dp-vector-pure-laplace-policy-v1")$backend,
    .DSVERT_JOINT_DP_VECTOR_PURE_BACKEND)
  expect_identical(.dsvert_joint_dp_vector_public_backend_choice(2L)$backend,
    .DSVERT_JOINT_DP_VECTOR_PURE_BACKEND)
  expect_identical(.dsvert_joint_dp_vector_public_backend_choice(2L,
    "dsvert-joint-dp-vector-exact-gc-cost-policy-v1")$backend,
    .DSVERT_JOINT_DP_VECTOR_BACKEND)
})

test_that("exact production planning enforces every admitted range", {
  base <- list(epsilon = "1", delta = "0", sensitivity_steps = "1",
               total_coordinate_count = 1L)
  for (change in list(list(epsilon = "0"), list(epsilon = "10001"),
      list(sensitivity_steps = "0"), list(sensitivity_steps = "1.5"),
      list(sensitivity_steps = "1267650600228229401496703205377"),
      list(total_coordinate_count = 0L), list(total_coordinate_count = 1000001L))) {
    request <- modifyList(base, change)
    expect_error(.callMpcTool("joint-dp-vector-convolution-plan-v4", request))
    expect_error(.dsvert_joint_dp_pure_request(request), "admitted ranges")
  }
  edge <- modifyList(base, list(sensitivity_steps = "1267650600228229401496703205376",
                               total_coordinate_count = 1000000L))
  plan <- .callMpcTool("joint-dp-vector-convolution-plan-v4", edge)
  expect_identical(plan$representability_bound, "1e-44739235")
  expect_silent(.dsvert_joint_dp_pure_plan_validate(plan, edge))
  expect_silent(.callMpcTool("joint-dp-vector-convolution-plan-v4",
    modifyList(base, list(epsilon = "10000"))))
})

test_that("legacy v3 and Gaussian plans retain positive-delta contracts", {
  input <- list(epsilon = "1", delta = "0.000001", sensitivity_steps = "1",
                total_coordinate_count = 2L)
  legacy <- .callMpcTool("joint-dp-vector-convolution-plan-v3", input)
  expect_identical(legacy$version, .DSVERT_JOINT_DP_VECTOR_PLAN_VERSION)
  expect_false(identical(legacy$implementation_delta_numerator, "0"))
  expect_null(legacy$guarantee)
  expect_error(.callMpcTool("joint-dp-vector-convolution-plan-v3",
    modifyList(input, list(delta = "0"))))
  gaussian <- list(epsilon = "1", delta = "0", l2_sensitivity_steps = "1",
                   total_coordinate_count = 2L)
  expect_error(.callMpcTool("joint-dp-vector-gaussian-plan-v2", gaussian))
})


test_that("staged validity sources reject zero delta before production sampling", {
  manifest <- list(workload = list(mechanism_selection = list(allocated_delta = 0),
    families = list(gaussian_models = list(artifacts = list(list(family = "cox"))))))
  expect_error(.dsvert_dp_glm_grid_cross_noise_policy(manifest), "positive delta.*validity gate")
  manifest$workload$families$gaussian_models$artifacts <- list()
  expect_identical(.dsvert_dp_glm_grid_cross_noise_policy(manifest),
    "dsvert-joint-dp-vector-pure-laplace-policy-v1")
})

test_that("exact production shares and fixed finalizer replay the known vector", {
  fixture <- jsonlite::read_json(.dsvert_test_package_file(
    "inst", "dsvert-mpc", "testdata", "joint-dp-vector-convolution-v4.json",
    source_only = TRUE), simplifyVector = FALSE)
  draw <- fixture$output$draws[[1L]]
  left <- .callMpcTool("joint-dp-vector-convolution-share-v4", draw$garbler_input)
  right <- .callMpcTool("joint-dp-vector-convolution-share-v4", draw$evaluator_input)
  expect_identical(left, .callMpcTool("joint-dp-vector-convolution-share-v4", draw$garbler_input))
  expect_identical(left$sampler_contract_hash, draw$garbler_sampler_contract_hash)
  expect_identical(right$sampler_contract_hash, draw$evaluator_sampler_contract_hash)
  input <- draw$garbler_input[c("ring_bits", "frac_bits", "total_coordinate_count",
    "chunk_start", "coordinate_count", "output_lattice_bits", "epsilon",
    "allocated_delta", "sensitivity_steps", "scale_shifts", "raw_upper_bounds",
    "release_contract_hash", "transcript_hash")]
  input$version <- "dsvert-joint-dp-vector-independent-full-draw-finalizer-input-v4"
  input$left_noised_share <- left$noised_share
  input$right_noised_share <- right$noised_share
  output <- .callMpcTool("joint-dp-vector-convolution-finalize-v4", input)
  expect_identical(output, .callMpcTool("joint-dp-vector-convolution-finalize-v4", input))
  profile <- .dsvert_joint_dp_vector_profile("discrete-laplace", .DSVERT_JOINT_DP_VECTOR_PURE_BACKEND)
  contract <- list(profile = profile, release_contract_hash = input$release_contract_hash,
    transcript_hash = input$transcript_hash, plan = left$plan,
    release_contract = list(backend = profile$backend, sampler = profile$sampler,
      coordinate_count = input$total_coordinate_count, output_lattice_bits = input$output_lattice_bits))
  chunk <- list(offset = input$chunk_start, count = input$coordinate_count)
  validate <- function(value) .dsvert_joint_dp_vector_finalizer_validate(value, contract,
    chunk, unlist(input$raw_upper_bounds), unlist(input$scale_shifts))
  expect_identical(validate(output), as.list(output$clamped_scaled_values))
  expect_identical(output$signed_decode, "canonical_Ring128_twos_complement_after_modular_addition")
  expect_null(output$no_wrap_headroom_certified)
  expect_error(validate(c(output, list(guarantee = "tampered"))), "certificate")
  altered <- output
  altered$sum_wrap_bound <- "0"
  expect_error(validate(altered), "certificate")
})
