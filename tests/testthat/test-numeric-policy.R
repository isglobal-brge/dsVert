test_that("numeric policy never advertises unfinished exact backends", {
  old <- options(
    dsvert.numeric.enabled = TRUE,
    dsvert.numeric.allowed_backends =
      c("ring63", "ring127", "exact_gc", "multiprecision"),
    dsvert.numeric.glm_bounds = NULL)
  on.exit(options(old), add = TRUE)

  policy <- dsvertNumericPolicyDS()

  expect_identical(policy$schema_version, 1L)
  expect_match(policy$policy_id, "^[0-9a-f]{64}$")
  expect_true(policy$capabilities$ring63$available)
  expect_true(policy$capabilities$ring127$available)
  expect_false(policy$capabilities$ring63$e2e_verified)
  expect_false(policy$capabilities$ring63$workload_adapter_e2e_verified)
  expect_false(
    policy$capabilities$ring63$public_scalar_mul_truncate_e2e_verified)
  expect_false(policy$capabilities$ring127$full_iteration_e2e_verified)
  expect_false(policy$capabilities$ring127$exact_truncation)
  expect_identical(
    policy$capabilities$exact_gc$available,
    policy$capabilities$exact_gc$runtime_probe_observed)
  expect_false(policy$capabilities$exact_gc$workload_adapter_e2e_verified)
  expect_false(policy$capabilities$multiprecision$available)
  expect_false(policy$capabilities$exact_gc$e2e_verified)
})

test_that("numeric bounds and backend allowlist are custodian options", {
  custom <- list(
    max_abs_predictor = 4,
    max_abs_response = list(
      gaussian = 8, binomial = 1, poisson = 50),
    max_abs_linear_predictor = list(
      gaussian = 16, binomial = 6, poisson = 4),
    max_abs_approximation_intermediate = list(
      gaussian = 16, binomial = 8, poisson = 512),
    max_abs_offset = 3,
    max_abs_weight = 20,
    max_observations = 5000L,
    max_predictors = 100L,
    max_iterations = 200L,
    max_numeric_error = 1e-5)
  old <- options(
    dsvert.numeric.enabled = TRUE,
    dsvert.numeric.allowed_backends = "ring127",
    dsvert.numeric.glm_bounds = custom)
  on.exit(options(old), add = TRUE)

  policy <- dsvertNumericPolicyDS()

  expect_equal(policy$bounds$max_abs_predictor, 4)
  expect_equal(policy$bounds$max_abs_response[["poisson"]], 50)
  expect_false(policy$capabilities$ring63$allowed)
  expect_true(policy$capabilities$ring127$allowed)
  expect_false(policy$capabilities$exact_gc$allowed)
})

test_that("malformed custodian numeric configuration fails closed", {
  old <- options(
    dsvert.numeric.glm_bounds = list(max_abs_predictor = Inf),
    dsvert.numeric.allowed_backends = NULL)
  on.exit(options(old), add = TRUE)

  expect_error(dsvertNumericPolicyDS(), "max_abs_predictor")

  options(dsvert.numeric.glm_bounds = NULL,
          dsvert.numeric.allowed_backends = "analyst_plaintext")
  expect_error(dsvertNumericPolicyDS(), "Unknown numeric backend")
})

test_that("zero fractional bits is a valid integer fixed-point encoding", {
  expect_invisible(.dsvert_numeric_assert_fp_encoding(
    c(-1, 0, 1), ring = 63, frac_bits = 0, what = "integer values"))

  expect_error(
    .dsvert_numeric_assert_fp_encoding(
      1, ring = 63, frac_bits = -1, what = "integer values"),
    "frac_bits")
  expect_error(
    .dsvert_numeric_assert_fp_encoding(
      1, ring = 63, frac_bits = 0.5, what = "integer values"),
    "frac_bits")
  expect_error(
    .dsvert_numeric_assert_fp_encoding(
      2^62, ring = 63, frac_bits = 0, what = "integer values"),
    "not representable")
  expect_error(
    .dsvert_numeric_assert_fp_encoding(
      c(0, Inf), ring = 63, frac_bits = 0, what = "integer values"),
    "non-finite")
  expect_error(
    .dsvert_numeric_assert_fp_encoding(
      "1", ring = 63, frac_bits = 0, what = "integer values"),
    "non-numeric")
})
