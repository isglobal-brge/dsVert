test_that("family B loaded contracts bind canonical profile and analytic certificate", {
  profile <- jsonlite::fromJSON(system.file("cross-grid-family-b", "piecewise_profile_v1.json",
    package = "dsVert"), simplifyVector = FALSE)
  certificate <- jsonlite::fromJSON(system.file("cross-grid-family-b", "piecewise_certificate_v1.json",
    package = "dsVert"), simplifyVector = FALSE)
  hash <- function(value) digest::digest(charToRaw(.dsvert_dp_canonical_json(value)),
    algo = "sha256", serialize = FALSE)
  expect_identical(hash(profile$profile), profile$profile_sha256)
  expect_identical(hash(certificate$certificate), certificate$certificate_sha256)
  for (family in c("multinomial", "ordinal")) {
    numeric <- .dsvert_dp_categorical_grid_cross_numeric(family)
    expect_identical(numeric$profile_sha256, profile$profile_sha256)
    expect_identical(numeric$certificate_sha256, certificate$certificate_sha256)
    expect_identical(numeric$certified_uniform_error,
      certificate$certificate[[paste0(family, "_prequantization_error_bound")]])
  }
})

test_that("family B piecewise tables equal every independent boundary word", {
  profile <- .family_b_piecewise_profile()
  fixture <- jsonlite::fromJSON(system.file("cross-grid-family-b",
    "piecewise_boundary_fixtures_v1.json", package = "dsVert"), simplifyVector = FALSE)
  expect_identical(fixture$profile_sha256,
    "fc0d85381d6effb30776848ccf301f4b9b18fc5dc55bdc80a8503f7d8916fcef")
  for (name in names(fixture$cases)) {
    cases <- fixture$cases[[name]]
    actual <- vapply(cases, function(case) {
      if (name == "exp_kernel") return(.family_b_exp16(case$input_q16, profile))
      if (name == "log_kernel") return(.family_b_log16(case$input_q16, profile))
      .family_b_piecewise(case$input_q16, profile$tables[[name]])
    }, numeric(1L))
    expected <- vapply(cases, `[[`, numeric(1L), "output_q16")
    expect_equal(actual, expected, tolerance = 0, info = name)
  }
  expect_equal(.family_b_exp16(0, profile), 65536)
  expect_equal(.family_b_exp16(-16 * 65536 - 1, profile), 0)
  expect_error(.family_b_log16(65535, profile))
  expect_error(.family_b_soft16(16 * 65536 + 1, profile))
})

test_that("family B pure R oracle matches independent profile row fixtures", {
  fixture <- jsonlite::fromJSON(system.file("cross-grid-family-b",
    "integer_fixtures_v1.json", package = "dsVert"), simplifyVector = FALSE)
  for (case in fixture$cases) {
    predictors <- length(case$features_encoded[[1L]])
    spec <- list(family = case$family, predictor_order = seq_len(predictors),
      class_count = case$classes, class_order = as.list(as.character(seq_len(case$classes))),
      non_reference_order = as.list(as.character(seq.int(2, case$classes))),
      numeric_grid_bits = case$g, beta_encoded = case$beta_encoded,
      sensitivity = list(candidate_bounds = lapply(case$caps, function(cap) {
        list(per_patient_cap = cap)
      })))
    if (case$family == "ordinal") {
      spec$candidate_encoded <- Map(function(beta, thresholds) {
        list(beta = beta, thresholds = thresholds)
      }, case$beta_encoded, case$thresholds_encoded)
    }
    features <- lapply(case$features_encoded, function(values) {
      vapply(values, function(value) sprintf("%.0f", value), character(1L))
    })
    validity <- matrix(as.numeric(unlist(case$valid)), nrow = length(features),
      ncol = predictors + 1L)
    got <- .family_b_integer_losses(spec, features, unlist(case$outcomes), validity)
    expect_identical(got, vapply(case$expected_sums, function(value) sprintf("%.0f", value),
      character(1L)), info = case$name)
  }
})

test_that("family B predictor rounds directly from f100 at q16 halfway slack", {
  features <- lapply(c("1099511627776", "1"), .cross_parse)
  result <- vapply(c(-1, 0, 1), function(delta) {
    .family_b_eta16(features, lapply(c("0", "8796093022208", as.character(delta)), .cross_parse))
  }, numeric(1L))
  expect_identical(result, c(0, 0, 1))
  for (sign in c(-1, 1)) for (whole in 0:4) {
    for (delta in -1:1) {
      raw <- .cross_add(.cross_shift_left(.cross_small(2 * whole + 1), 83),
        .cross_small(delta))
      raw$s <- sign * raw$s
      rounded <- .cross_double(.cross_round_shift(raw, 84))
      expected <- if (delta < 0) whole else if (delta > 0) whole + 1 else {
        whole + whole %% 2
      }
      expect_equal(rounded, sign * expected)
    }
  }
})

test_that("family B declared utility envelope keeps profile error below DP scale", {
  for (family in c("multinomial", "ordinal")) {
    error <- if (family == "multinomial") 0.0011 else 0.00012
    bound <- if (family == "multinomial") 32 + log(8) else {
      16 + 2 * log1p(exp(-16)) + log(16)
    }
    cap <- ceiling(2^18 * (bound + 2 * error)) / 2^18
    for (epsilon in c(1, 4, 8)) {
      expect_lt(10000 * error / (50 * cap / epsilon), 0.06)
    }
  }
})
