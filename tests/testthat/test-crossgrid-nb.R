test_that("NB2 cross loss is the complete negative dnbinom log PMF", {
  for (theta in 2^(-3:7)) {
    y <- rep(c(0, 1, 2, 1024), each = 5L)
    eta <- rep(c(-16, -1, 0, 1, 16), 4L)
    expect_equal(.dsvert_dp_nb_grid_cross_loss(y, eta, theta),
                 -stats::dnbinom(y, size = theta, mu = exp(eta), log = TRUE),
                 tolerance = 1e-10)
  }
  expect_equal(.dsvert_dp_nb_grid_cross_loss(1, 0, 2), 1.21639532432449,
               tolerance = 1e-13)
})

test_that("NB2 caps cover outcomes, endpoint extrema and both adjacency modes", {
  beta <- list(c(-1, 2), c(0.5, -0.25))
  theta <- c(0.125, 128)
  for (g in c(8, 18)) {
    add <- .dsvert_dp_nb_grid_cross_sensitivity(beta, theta, 3, g, 2,
                                               "add_remove_patient")
    replace <- .dsvert_dp_nb_grid_cross_sensitivity(beta, theta, 3, g, 2,
                                                   "replace_one_fixed_cohort")
    caps <- vapply(seq_along(beta), function(j) ceiling(2^g * max(
      -stats::dnbinom(rep(0:3, 2), size = theta[j],
        mu = rep(exp(c(-1, 1) * sum(abs(beta[[j]]))), each = 4), log = TRUE))), numeric(1L))
    exact_caps <- caps
    caps <- vapply(add$candidate_bounds, `[[`, numeric(1L), "per_patient_cap")
    errors <- vapply(add$candidate_bounds, `[[`, numeric(1L), "certified_row_error")
    expect_true(all(caps >= exact_caps))
    expect_true(all(vapply(add$candidate_bounds, `[[`, numeric(1L), "loss_bound") >=
      exact_caps / 2^g + 2 * errors - 1 / 2^g))
    expect_equal(unlist(add$maximum_coordinates), 2 * caps)
    expect_equal(add$raw_l1_sensitivity, sum(caps))
    expect_gte(add$raw_l2_sensitivity, sqrt(sum(caps^2)))
    expect_equal(replace$raw_l1_sensitivity, 2 * add$raw_l1_sensitivity)
    expect_equal(replace$raw_l2_sensitivity, 2 * add$raw_l2_sensitivity)
    domain <- expand.grid(x = c(0, 0.5, 1), y = 0:3, valid = 0:1)
    rows <- t(vapply(seq_len(nrow(domain)), function(i) vapply(seq_along(beta), function(j) {
      loss <- -stats::dnbinom(domain$y[i], size = theta[j],
        mu = exp(beta[[j]][1] + beta[[j]][2] * domain$x[i]), log = TRUE)
      domain$valid[i] * min(caps[j], max(0, round(2^g * loss)))
    }, numeric(1L)), numeric(2L)))
    # Exhaust every one-row insertion/deletion and every possible row replacement,
    # including validity changing between absent and present.
    expect_true(all(rows >= 0 & sweep(rows, 2L, caps, "<=") ))
    for (i in seq_len(nrow(rows))) {
      expect_lte(sum(abs(rows[i, ])), add$raw_l1_sensitivity)
      expect_lte(sqrt(sum(rows[i, ]^2)), add$raw_l2_sensitivity)
      changes <- sweep(rows, 2L, rows[i, ], "-")
      expect_true(all(rowSums(abs(changes)) <= replace$raw_l1_sensitivity))
      expect_true(all(sqrt(rowSums(changes^2)) <= replace$raw_l2_sensitivity))
    }
  }
})

test_that("NB2 public numeric domains fail closed", {
  for (theta in c(0, 0.1, 0.25 + 2^-54, 3, 256, NA_real_, Inf)) {
    expect_error(.dsvert_dp_nb_grid_cross_sensitivity(list(c(0, 1)), theta, 3,
      18, 2, "add_remove_patient"), class = "dsvert_dp_public_failure")
  }
  expect_error(.dsvert_dp_nb_grid_cross_sensitivity(list(c(8, 8, 2^-60)), 2,
    3, 18, 2, "add_remove_patient"), class = "dsvert_dp_public_failure")
  expect_error(.dsvert_dp_nb_grid_cross_sensitivity(rep(list(c(8, 8)), 256),
    rep(128, 256), 1024, 18, 2^31 - 1, "add_remove_patient"),
    class = "dsvert_dp_public_failure")
})

test_that("NB2 signed contracts retain the frozen source ABI and both authorities", {
  f <- .nb_grid_cross_fixture("dsVert")
  got <- f$registration$validate_contract(f$contract, f$policy, f$schema)
  expect_identical(got$spec$version, "nb_grid_cross_v1")
  expect_identical(got$artifact$implementation_state, "cross_owner_exact_gc_materialized")
  expect_identical(got$artifact$cross_owner_state, "exact_gc_to_joint_dp_vector_v1")
  expect_true(.dsvert_dp_glm_grid_cross_equal(got$source_contract$private_layout,
                   .dsvert_dp_glm_grid_cross_layout(got$spec)))
  expect_identical(got$source_contract$recipients, as.list(c("peer_a", "peer_b")))
  expect_false(f$registration$production_release_registered)
  decoded <- jsonlite::fromJSON(.dsvert_dp_canonical_json(got), simplifyVector = FALSE)
  expect_identical(f$registration$validate_contract(decoded, f$policy, f$schema), got)
})

test_that("NB2 signed malformed contracts and missing signatures have one public error", {
  f <- .nb_grid_cross_fixture("dsVert")
  mutations <- list(
    function(x) { x$spec$theta_grid[[1]] <- 3; x },
    function(x) { x$spec$theta_grid <- rev(x$spec$theta_grid); x },
    function(x) { x$spec$beta_encoded[[1]][[2]] <- "0"; x },
    function(x) { x$spec$predictor_order <- rev(x$spec$predictor_order); x },
    function(x) { x$spec$numeric_contract$profile_sha256 <- strrep("0", 64); x },
    function(x) { x$spec$schema_sha256 <- strrep("0", 64); x },
    function(x) { x$spec$alignment$public_patient_dependent_hash <- TRUE; x },
    function(x) { x$spec$sensitivity$raw_l1_sensitivity <- 0; x },
    function(x) { x$artifact$result_evidence_required <- FALSE; x },
    function(x) { x$artifact$implementation_state <- "same_owner_materialized"; x },
    function(x) { x$source_contract$source_peers <- list("peer_a"); x },
    function(x) { x$source_contract$private_layout$padding_validity <- 1; x },
    function(x) { x$source_contract$purpose <- "ordinary_release"; x })
  for (mutate in mutations) {
    err <- tryCatch(f$registration$validate_contract(f$sign(mutate(f$unsigned)),
      f$policy, f$schema), error = identity)
    expect_s3_class(err, "dsvert_dp_public_failure")
    expect_identical(conditionMessage(err), "[dsvert_dp_public_failure:v1] Protected capsule operation failed.")
  }
  for (peer in c("peer_a", "peer_b")) {
    bad <- f$contract
    bad$signatures[[peer]] <- NULL
    expect_error(f$registration$validate_contract(bad, f$policy, f$schema),
                 class = "dsvert_dp_public_failure")
    schema <- f$schema
    schema$signatures[[peer]] <- NULL
    expect_error(f$registration$validate_contract(f$contract, f$policy, schema),
                 class = "dsvert_dp_public_failure")
  }
  schema <- f$schema
  schema$datasets$cohort$columns$x$upper <- 5
  expect_error(f$registration$validate_contract(f$contract, f$policy, schema),
               class = "dsvert_dp_public_failure")
})

test_that("NB2 candidate identities bind theta and reject encoded collisions", {
  f <- .nb_grid_cross_fixture("dsVert", beta_grid = list(c(0, 1, 0), c(0, 1, 0)),
                             theta_grid = c(1, 2))
  expect_length(unique(unlist(f$contract$spec$candidate_order)), 2L)
  raw <- f$raw
  raw$theta_grid <- c(1, 1)
  expect_error(f$registration$build_spec(raw, f$policy, f$authenticated),
               class = "dsvert_dp_public_failure")
  raw$beta_grid <- list(c(0, 1, 0), c(2^-52, 1, 0))
  expect_error(f$registration$build_spec(raw, f$policy, f$authenticated),
               class = "dsvert_dp_public_failure")
})

test_that("NB2 pure-R limb oracle exactly matches certified Go fixtures", {
  value <- jsonlite::fromJSON(system.file("cross-grid-nb", "numeric_profile_nb_v1.json",
                                         package = "dsVert"), simplifyVector = FALSE)
  for (case in value$reference_cases) {
    got <- .cross_nb_reference_row(case$eta_q64, case$outcome, case$valid,
      case$theta_exponent, case$g, sprintf("%.0f", case$cap), value$profile)
    expect_identical(got, sprintf("%.0f", case$expected))
  }
  expect_equal(length(value$profile$softplus_quadratic_q16), 64L)
  expect_identical(value$profile$nonlinear_fraction_bits, 16L)
  expect_identical(value$profile$arithmetic_width_bits, 32L)
  expect_equal(length(value$profile$theta), 11L)
  expect_lte(as.numeric(value$numeric_contract$certified_uniform_error), 0.045343)
})

test_that("NB2 limb batch sums owner partial predictors before quantization", {
  value <- jsonlite::fromJSON(system.file("cross-grid-nb", "numeric_profile_nb_v1.json",
                                         package = "dsVert"), simplifyVector = FALSE)
  features <- list(c("0", "1125899906842624"), c("562949953421312", "0"),
                   c("1125899906842624", "1125899906842624"))
  beta <- list(c("-1125899906842624", "2251799813685248", "562949953421312"))
  validity <- matrix(c(1, 1, 1, 1, 0, 1, 1, 1, 1), nrow = 3, byrow = TRUE)
  got <- .cross_nb_reference_batch(features, c(0, 1, 2), validity, beta,
    "100000000", 1, 18, value$profile)
  expected <- .cross_int()
  for (i in c(1L, 3L)) {
    eta <- .cross_eta(lapply(features[[i]], .cross_parse), lapply(beta[[1]], .cross_parse))
    expected <- .cross_add(expected, .cross_parse(.cross_nb_reference_row(
      .cross_format(eta), c(0, 1, 2)[i], TRUE, 1, 18, "100000000", value$profile)))
  }
  expect_identical(got, .cross_format(expected))
})

test_that("NB2 installed profile, proof and numeric template are independently hash pinned", {
  value <- jsonlite::fromJSON(system.file("cross-grid-nb", "numeric_profile_nb_v1.json",
                                         package = "dsVert"), simplifyVector = FALSE)
  mutations <- list(
    function(x) { x$profile$softplus_quadratic_q16[[1L]][[1L]] <- "0"; x },
    function(x) { x$profile$theta[[1L]]$constant_q64[[2L]] <- "1"; x },
    function(x) { x$certificate$loss_error_bound <- "0"; x },
    function(x) { x$numeric_contract$certified_uniform_error <- "0"; x })
  for (mutate in mutations) {
    changed <- mutate(value)
    testthat::with_mocked_bindings({
      expect_error(.dsvert_dp_nb_grid_cross_numeric(), class = "dsvert_dp_public_failure")
    }, fromJSON = function(...) changed, .package = "jsonlite")
  }
})


test_that("NB2 certified profile and public cap evaluator agree at every piece boundary", {
  value <- .dsvert_dp_nb_grid_cross_profile()
  profile <- value$profile
  for (z in c(-22, 22, seq(-16, 16, by = 0.125), -2^-17, 2^-17,
              16 - 2^-16, 16 + 2^-16)) {
    encoded <- .cross_shift_left(.cross_small(round(z * 2^17)), 47)
    integer <- .cross_nb_softplus(encoded, profile)
    got <- .cross_double(integer) / 2^64
    expect_identical(got, .dsvert_dp_nb_grid_cross_public_softplus(z, profile))
    exact <- max(z, 0) + log1p(exp(-abs(z)))
    expect_lte(abs(got - exact), 0.00003936)
  }
  expect_equal(.dsvert_dp_nb_grid_cross_constant_upper("1"), 2^-16)
  expect_equal(.dsvert_dp_nb_grid_cross_constant_upper("-1"), 0)
  expect_equal(.dsvert_dp_nb_grid_cross_constant_upper("18446744073709551616"), 1)
  expect_equal(.dsvert_dp_nb_grid_cross_constant_upper("-18446744073709551617"), -1)
})

test_that("NB2 profile caps enclose the approximate loss plus its certified error", {
  value <- .dsvert_dp_nb_grid_cross_profile()
  for (theta in 2^(-3:7)) {
    bound <- .dsvert_dp_nb_grid_cross_sensitivity(list(c(8, 8)), theta, 16,
      18, 10000, "add_remove_patient")$candidate_bounds[[1L]]
    table <- value$profile$theta[[as.integer(log2(theta)) + 4L]]
    for (eta in seq(-16, 16, by = 0.25)) {
      soft <- .dsvert_dp_nb_grid_cross_public_softplus(
        eta - as.numeric(table$log_theta_q64) / 2^64, value$profile)
      profile_loss <- vapply(table$constant_q64[1:17], as.numeric, numeric(1L)) /
        2^64 + (0:16 + theta) * soft - (0:16) * eta
      exact <- -stats::dnbinom(0:16, size = theta, mu = exp(eta), log = TRUE)
      expect_true(all(abs(profile_loss - exact) <= bound$certified_row_error + 1e-10))
      expect_lte(max(profile_loss) + bound$certified_row_error,
                 bound$per_patient_cap / 2^18)
    }
  }
})

test_that("NB2 default envelope approximation is below one percent of DP noise scale", {
  # Certified workload: N=10000, p=10, m=50, M=16, theta=2, A=16.
  # Each public candidate is distinct; Laplace whole-vector scale is Delta1/eps.
  beta <- lapply(seq_len(50L), function(j) c(8, 8 - j / 1024, rep(0, 9)))
  spec <- .dsvert_dp_nb_grid_cross_sensitivity(beta, rep(2, 50), 16, 16,
                                             10000, "add_remove_patient")
  accumulated_error <- 10000 * max(vapply(spec$candidate_bounds, `[[`, numeric(1L),
                                            "certified_row_error") + 0.5 / 2^16)
  for (epsilon in c(1, 4, 8)) {
    expect_lt(accumulated_error, 0.01 * spec$natural_l1_sensitivity / epsilon)
  }
})
