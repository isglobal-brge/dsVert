test_that("standardisation enforces raw and encoded custodian bounds", {
  withr::local_options(list(
    dsvert.numeric.enabled = TRUE,
    dsvert.numeric.allowed_backends =
      c("ring63", "ring127", "exact_gc", "multiprecision")))
  sid <- "44444444-4444-4444-8444-444444444444"
  on.exit(mpcCleanupDS(sid), add = TRUE)
  D <- data.frame(x = c(1, 2, 3, 4, 5, 100), y = 1:6)

  old <- options(dsvert.numeric.glm_bounds = list(
    max_abs_predictor_input = 10))
  on.exit(options(old), add = TRUE)
  expect_error(
    glmStandardizeDS("D", "D_std", "x", "y", session_id = sid),
    "raw predictor")

  options(dsvert.numeric.glm_bounds = list(
    max_abs_predictor_input = 1000,
    max_abs_predictor = 0.1))
  expect_error(
    glmStandardizeDS("D", "D_std", "x", "y", session_id = sid),
    "encoded predictor")
})

test_that("response domains and IEEE inputs fail closed before encoding", {
  withr::local_options(list(
    dsvert.numeric.enabled = TRUE,
    dsvert.numeric.allowed_backends =
      c("ring63", "ring127", "exact_gc", "multiprecision")))
  sid <- "55555555-5555-4555-8555-555555555555"
  on.exit(mpcCleanupDS(sid), add = TRUE)
  D <- data.frame(x = 1:6, y = c(0, 1, 0, 0.5, 1, 0))

  expect_error(
    glmStandardizeDS(
      "D", "D_std", "x", y_var = NULL, session_id = sid,
      numeric_y_var = "y", numeric_family = "binomial",
      numeric_ring = 127L),
    "DSVERT_NUMERIC_DOMAIN_FAILURE")

  D$y <- c(0, 1, 2, 3, 4, Inf)
  expect_error(
    glmStandardizeDS(
      "D", "D_std", "x", y_var = NULL, session_id = sid,
      numeric_y_var = "y", numeric_family = "poisson",
      numeric_ring = 127L),
    "DSVERT_NONFINITE_ANALYSIS_DATA")
})

test_that("input attestation is execution-bound and releases no extrema", {
  withr::local_options(list(
    dsvert.numeric.enabled = TRUE,
    dsvert.numeric.allowed_backends =
      c("ring63", "ring127", "exact_gc", "multiprecision")))
  sid <- "66666666-6666-4666-8666-666666666666"
  on.exit(mpcCleanupDS(sid), add = TRUE)
  D <- data.frame(x = 1:6, y = 2:7)

  result <- glmStandardizeDS(
    "D", "D_std", "x", "y", session_id = sid,
    numeric_family = "gaussian", numeric_ring = 63L)
  attestation <- result$numeric_attestation
  policy <- dsvertNumericPolicyDS()

  expect_identical(attestation$policy_id, policy$policy_id)
  expect_match(attestation$binding_id, "^[0-9a-f]{64}$")
  expect_true(attestation$runtime_input_bounds_enforced)
  expect_false(attestation$runtime_intermediate_bounds_enforced)
  expect_false(attestation$observed_extrema_released)
  expect_false(any(c("observed_min", "observed_max", "maximum", "minimum") %in%
                     names(attestation)))
  expect_identical(
    attestation$binding_id,
    dsVert:::.dsvert_numeric_attestation_binding(
      "glm_standardized_input", policy$policy_id, sid, "D", c("x", "y"),
      "gaussian", 63L, 6L))

  other <- dsVert:::.dsvert_numeric_attestation_binding(
    "glm_standardized_input", policy$policy_id,
    "77777777-7777-4777-8777-777777777777", "D", c("x", "y"),
    "gaussian", 63L, 6L)
  expect_false(identical(attestation$binding_id, other))
})

test_that("numeric policy id covers its complete canonical body", {
  withr::local_options(list(
    dsvert.numeric.enabled = TRUE,
    dsvert.numeric.allowed_backends =
      c("ring63", "ring127", "exact_gc", "multiprecision")))
  policy <- dsvertNumericPolicyDS()
  expect_identical(policy$policy_id,
                   dsVert:::.dsvert_numeric_policy_hash(policy))

  tampered <- policy
  tampered$bounds$max_abs_predictor <-
    tampered$bounds$max_abs_predictor + 1
  expect_false(identical(tampered$policy_id,
                         dsVert:::.dsvert_numeric_policy_hash(tampered)))
})

test_that("offset registration rejects non-finite/out-of-policy values", {
  withr::local_options(list(
    dsvert.numeric.enabled = TRUE,
    dsvert.numeric.allowed_backends =
      c("ring63", "ring127", "exact_gc", "multiprecision"),
    dsvert.numeric.glm_bounds = list(max_abs_offset = 2)))
  sid <- "88888888-8888-4888-8888-888888888888"
  on.exit(mpcCleanupDS(sid), add = TRUE)
  ss <- dsVert:::.S(sid)
  ss$k2_ring <- 127L
  ss$k2_x_n <- 6L
  D <- data.frame(offset = c(-1, -0.5, 0, 0.5, 1, 1.5))
  testthat::local_mocked_bindings(
    .callMpcTool = function(command, args) {
      expect_identical(command, "k2-float-to-fp")
      list(fp_data = "canonical-fp")
    },
    .package = "dsVert")

  result <- k2SetOffsetDS(
    "D", "offset", sid, numeric_family = "poisson")
  expect_true(result$stored)
  expect_identical(result$numeric_attestation$kind, "glm_offset")
  expect_false(result$numeric_attestation$observed_extrema_released)

  D$offset[6L] <- Inf
  expect_error(k2SetOffsetDS("D", "offset", sid), "NA, NaN, Inf")
  D$offset[6L] <- 3
  expect_error(k2SetOffsetDS("D", "offset", sid),
               "custodian-owned public bound")
})

test_that("weight registration validates the protected operand before sharing", {
  withr::local_options(list(
    dsvert.numeric.enabled = TRUE,
    dsvert.numeric.allowed_backends =
      c("ring63", "ring127", "exact_gc", "multiprecision"),
    dsvert.numeric.glm_bounds = list(max_abs_weight = 5)))
  sid <- "99999999-9999-4999-8999-999999999999"
  on.exit(mpcCleanupDS(sid), add = TRUE)
  ss <- dsVert:::.S(sid)
  ss$k2_ring <- 127L
  ss$k2_x_n <- 6L
  D <- data.frame(weight = c(0, 0.5, 1, 2, 3, 4))
  testthat::local_mocked_bindings(
    .dsvert_validate_recipient_pk = function(...) invisible(TRUE),
    .dsvert_typed_blob_mint = function(
        ss, session_id, capability_id, recipient_pk, payload, context,
        producer = NULL) {
      list(capability_id = capability_id, payload_chars = nchar(payload))
    },
    .dsvert_typed_blob_operation_replay = function(...) list(hit = FALSE),
    .dsvert_typed_blob_operation_commit = function(
        ss, producer, request, result) result,
    .callMpcTool = function(command, args) {
      switch(command,
        "k2-float-to-fp" = list(fp_data = "canonical-fp"),
        "k2-split-fp-share" = list(
          own_share = "own-share", peer_share = "peer-share"),
        "transport-encrypt" = list(sealed = "sealed-share"),
        stop("unexpected command in test: ", command))
    },
    .package = "dsVert")

  result <- k2ShareWeightsDS(
    "D", "weight", "dcf0-key", "dcf1-key", dcf_role = "dealer",
    ring = 127L, session_id = sid, numeric_family = "binomial")
  expect_identical(result$numeric_attestation$kind, "glm_weights")
  expect_true(result$numeric_attestation$runtime_input_bounds_enforced)
  expect_false(result$numeric_attestation$runtime_intermediate_bounds_enforced)

  D$weight[6L] <- Inf
  expect_error(
    k2ShareWeightsDS(
      "D", "weight", "dcf0-key", "dcf1-key", ring = 127L,
      session_id = sid),
    "NA, NaN, Inf")
  D$weight[6L] <- 6
  expect_error(
    k2ShareWeightsDS(
      "D", "weight", "dcf0-key", "dcf1-key", ring = 127L,
      session_id = sid),
    "custodian-owned public bound")
})
