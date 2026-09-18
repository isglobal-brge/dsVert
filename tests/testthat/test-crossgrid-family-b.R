test_that("categorical cross-grid contracts authenticate both pinned authorities", {
  for (family in c("multinomial", "ordinal")) {
    fixture <- .family_b_contract_fixture(family)
    validated <- .family_b_validate(fixture)
    expect_identical(validated$spec$family, family)
    expect_identical(validated$artifact$implementation_state,
      "cross_owner_exact_gc_materialized")
    expect_identical(validated$artifact$cross_owner_state,
      "exact_gc_to_joint_dp_vector_v1")
    roundtrip <- jsonlite::fromJSON(.dsvert_dp_canonical_json(validated),
      simplifyVector = FALSE)
    expect_identical(.family_b_validate(fixture, roundtrip), validated)
    layout <- validated$source_contract$private_layout
    expect_equal(vapply(layout$blocks, `[[`, numeric(1L), "value_fraction_bits"),
      c(50, 50, 0))
    expect_equal(layout$blocks[[3L]]$value_maximum, 2)
    expect_identical(layout$release_prefix_source_rule,
      "all_zero_until_authenticated_result_injection_v1")
    missing <- fixture$contract
    missing$signatures$peer_b <- NULL
    expect_error(.family_b_validate(fixture, missing), class = "dsvert_dp_public_failure")
    forged <- fixture$contract
    forged$signatures$peer_a <- forged$signatures$peer_b
    expect_error(.family_b_validate(fixture, forged), class = "dsvert_dp_public_failure")
    unsigned_schema <- fixture$schema
    unsigned_schema$signatures$peer_b <- NULL
    expect_error(.family_b_validate(fixture, schema = unsigned_schema),
      class = "dsvert_dp_public_failure")
  }
})

test_that("categorical validators reconstruct signed semantics and fail transcript safely", {
  mutations <- list(
    function(x) { x$spec$unknown <- TRUE; x },
    function(x) { x$spec$predictor_order <- rev(x$spec$predictor_order); x },
    function(x) { x$spec$outcome$levels <- rev(x$spec$outcome$levels); x },
    function(x) { x$spec$computation_peers <- list("peer_a", "peer_a"); x },
    function(x) { x$spec$numeric_contract$profile_pieces <- 63; x },
    function(x) { x$spec$numeric_contract$profile_sha256 <- strrep("0", 64); x },
    function(x) { x$spec$numeric_contract$certificate_sha256 <- strrep("0", 64); x },
    function(x) { x$spec$numeric_contract$version <- "cross-grid-multinomial-exp32-log24-q64-v1"; x },
    function(x) { x$spec$numeric_contract$certified_uniform_error <- "0"; x },
    function(x) { x$spec$beta_encoded[[1]][[1]] <- "1"; x },
    function(x) { x$spec$alignment$public_patient_dependent_hash <- TRUE; x },
    function(x) { x$artifact$result_evidence_required <- FALSE; x },
    function(x) { x$artifact$sensitivity$raw_l1_sensitivity <- 0; x },
    function(x) { x$source_contract$source_peers <- list("peer_a"); x },
    function(x) { x$source_contract$private_layout$blocks[[3]]$value_fraction_bits <- 50; x })
  for (family in c("multinomial", "ordinal")) {
    fixture <- .family_b_contract_fixture(family)
    for (mutate in mutations) {
      invalid <- fixture$sign(mutate(fixture$unsigned))
      error <- tryCatch(.family_b_validate(fixture, invalid), error = identity)
      expect_s3_class(error, "dsvert_dp_public_failure")
      expect_identical(conditionMessage(error), .DSVERT_DP_PUBLIC_FAILURE_MESSAGE)
    }
  }
})

test_that("categorical grids enforce coefficient, threshold and canonical domains", {
  fixture <- .family_b_contract_fixture("multinomial")
  check <- function(raw) .dsvert_dp_multinomial_grid_cross_spec(raw,
    fixture$policy, fixture$authenticated)
  raw <- fixture$raw
  raw$beta_grid <- list(c(8, 8, 0, -8, -8, 0))
  expect_no_error(check(raw))
  raw$beta_grid <- list(c(8, 8, 2^-60, 0, 0, 0))
  expect_error(check(raw), class = "dsvert_dp_public_failure")
  raw$beta_grid <- list(rep(0, 6), c(2^-52, rep(0, 5)))
  expect_error(check(raw), class = "dsvert_dp_public_failure")
  raw <- fixture$raw
  raw$reference <- "c"
  spec <- check(raw)
  expect_identical(spec$class_order, as.list(c("c", "a", "b")))
  expect_identical(spec$outcome$levels, spec$class_order)
  expect_identical(.dsvert_dp_multinomial_grid_cross_spec_validate(spec,
    fixture$policy, fixture$authenticated), spec)
  for (levels in list("a", letters[1:9], c("a", "a"))) {
    raw$levels <- levels
    expect_error(check(raw), class = "dsvert_dp_public_failure")
  }
  fixture <- .family_b_contract_fixture("ordinal")
  check <- function(raw) .dsvert_dp_ordinal_grid_cross_spec(raw,
    fixture$policy, fixture$authenticated)
  raw <- fixture$raw
  raw$candidate_grid <- list(list(beta = c(0, 8, 0), thresholds = c(7.9375, 8)))
  expect_no_error(check(raw))
  for (candidate in list(
      list(beta = c(1, 0, 0), thresholds = c(-1, 1)),
      list(beta = c(0, 8, 2^-60), thresholds = c(-1, 1)),
      list(beta = c(0, 0, 0), thresholds = c(8, 8 + 1 / 16)),
      list(beta = c(0, 0, 0), thresholds = c(0, 1 / 32)),
      list(beta = c(0, 0, 0), thresholds = c(1, -1)))) {
    raw$candidate_grid <- list(candidate)
    expect_error(check(raw), class = "dsvert_dp_public_failure")
  }
})

test_that("categorical sensitivity is the capped vector sensitivity for both adjacencies", {
  for (family in c("multinomial", "ordinal")) {
    fixture <- .family_b_contract_fixture(family)
    candidates <- if (family == "multinomial") fixture$raw$beta_grid else fixture$raw$candidate_grid
    for (g in c(8, 16, 18)) {
      added <- .dsvert_dp_categorical_grid_cross_sensitivity(candidates,
        family, 3, 2, g, 2, "add_remove_patient")
      caps <- vapply(added$candidate_bounds, `[[`, numeric(1L), "per_patient_cap")
      for (j in seq_along(caps)) {
        bound <- added$candidate_bounds[[j]]
        error <- if (family == "multinomial") 0.0011 else 0.00012
        output_error <- if (g < 16) 2^(-g - 1) else 0
        expect_identical(bound$profile_error_bound, error)
        expect_identical(bound$output_rounding_error_bound, output_error)
        expect_gte(caps[j] / 2^g,
          bound$exact_loss_bound + 2 * error + output_error)
        expect_equal(caps[j], ceiling(2^g * bound$loss_bound))
      }
      expect_equal(added$raw_l1_sensitivity, sum(caps))
      expect_gte(added$raw_l2_sensitivity, sqrt(sum(caps^2)))
      expect_equal(unlist(added$maximum_coordinates), 2 * caps)
      expect_equal(added$natural_l1_sensitivity, sum(caps) / 2^g)
      replaced <- .dsvert_dp_categorical_grid_cross_sensitivity(candidates,
        family, 3, 2, g, 2, "replace_one_fixed_cohort")
      expect_equal(replaced$raw_l1_sensitivity, 2 * added$raw_l1_sensitivity)
      expect_equal(replaced$raw_l2_sensitivity, 2 * added$raw_l2_sensitivity)
      # Enumerate adjacent bounded patient contributions, including an absent row.
      vectors <- rbind(c(0, 0), expand.grid(a = c(0, caps[1]), b = c(0, caps[2])))
      for (i in seq_len(nrow(vectors))) for (j in seq_len(nrow(vectors))) {
        delta <- as.numeric(vectors[i, ] - vectors[j, ])
        expect_lte(sum(abs(delta)), added$raw_l1_sensitivity)
        expect_lte(sqrt(sum(delta^2)), added$raw_l2_sensitivity)
      }
    }
  }
})

test_that("ordinal probability floor remains positive at rare-category boundaries", {
  fixture <- .family_b_contract_fixture("ordinal", candidate_grid = list(
    list(beta = c(0, 8, 0), thresholds = c(-8, -8 + 1 / 16)),
    list(beta = c(0, -8, 0), thresholds = c(8 - 1 / 16, 8))))
  spec <- fixture$contract$spec
  for (j in seq_along(spec$candidate_grid)) {
    candidate <- spec$candidate_grid[[j]]
    thresholds <- unlist(candidate$thresholds)
    bound <- spec$sensitivity$candidate_bounds[[j]]
    expect_gte(bound$probability_lower_bound, 2^-28)
    expect_equal(bound$probability_lower_bound, exp(-bound$exact_loss_bound))
    expect_gt(bound$loss_bound, bound$exact_loss_bound)
    for (eta in seq(-8, 8, length.out = 65)) {
      cdf <- stats::plogis(thresholds - eta)
      probabilities <- diff(c(0, cdf, 1))
      expect_true(all(probabilities > 0))
      expect_gte(min(probabilities), bound$probability_lower_bound * (1 - 1e-8))
      expect_lte(max(-log(probabilities)), bound$loss_bound + 1e-8)
    }
  }
})

test_that("certified default approximation error stays below the DP noise scale", {
  # This is the public maximum-domain benchmark envelope, not a guarantee for
  # an arbitrary smaller grid. The actual small-grid DSLite utility is tested
  # separately against exact losses and the centralized fit.
  for (family in c("multinomial", "ordinal")) {
    loss <- if (family == "multinomial") 32 + log(8) else
      16 + 2 * log1p(exp(-16)) - log(1 / 16)
    error <- if (family == "multinomial") 0.0011 else 0.00012
    cap <- ceiling(2^18 * (loss + 2 * error)) / 2^18
    for (epsilon in c(1, 4, 8)) {
      noise_scale <- 50 * cap / epsilon
      expect_lt(10000 * error, 0.1 * noise_scale)
    }
  }
})

test_that("categorical caps reject unrepresentable capacity products", {
  for (family in c("multinomial", "ordinal")) {
    candidates <- if (family == "multinomial") list(as.list(c(8, 8, 0, 8, 8, 0))) else
      list(list(beta = as.list(c(0, 8, 0)), thresholds = as.list(c(-8, -8 + 1 / 16))))
    expect_error(.dsvert_dp_categorical_grid_cross_sensitivity(candidates,
      family, 3, 2, 18, 2^31 - 1, "add_remove_patient"),
      class = "dsvert_dp_public_failure")
  }
})

test_that("registration never authorizes release without the fused producer", {
  for (registration in list(.dsvert_dp_multinomial_grid_cross_register(),
                           .dsvert_dp_ordinal_grid_cross_register())) {
    expect_false(registration$release_enabled)
    expect_error(registration$release(), class = "dsvert_dp_public_failure")
    expect_true(is.function(registration$spec))
    expect_true(is.function(registration$validate))
    expect_true(is.function(registration$source_contract))
  }
})

test_that("the two custodians are exactly the two compute and noise authorities", {
  for (family in c("multinomial", "ordinal")) {
    fixture <- .family_b_contract_fixture(family)
    policy <- fixture$policy
    policy$peer_pinset <- c(policy$peer_pinset, peer_c = unname(policy$peer_pinset[1L]))
    policy$designated_noise_peers <- c("peer_a", "peer_c")
    expect_error(.dsvert_dp_categorical_grid_cross_spec(fixture$raw, policy,
      fixture$authenticated, family), class = "dsvert_dp_public_failure")
    policy$designated_noise_peers <- c("peer_a", "peer_b")
    schema <- fixture$authenticated
    schema$unsigned$datasets$cohort$columns$x$owner_peer <- "peer_c"
    raw <- fixture$raw
    raw$predictor_order <- c("peer_b$z", "peer_c$x")
    expect_error(.dsvert_dp_categorical_grid_cross_spec(raw, policy, schema, family),
      class = "dsvert_dp_public_failure")
  }
})

test_that("pure R family integer kernels cover all outcomes, masking and boundary caps", {
  for (family in c("multinomial", "ordinal")) {
    fixture <- .family_b_contract_fixture(family, capacity = 4)
    spec <- fixture$contract$spec
    x <- list(c("0", "0"), c("1125899906842624", "1125899906842624"),
      c("562949953421312", "0"), c("0", "562949953421312"))
    outcomes <- c(0, 1, 2, 1)
    valid <- matrix(1, 4, 3)
    losses <- .family_b_integer_losses(spec, x, outcomes, valid)
    expect_true(all(as.numeric(losses) >= 0))
    expect_true(all(as.numeric(losses) <= unlist(spec$sensitivity$maximum_coordinates)))
    valid[,] <- 0
    expect_identical(.family_b_integer_losses(spec, x, outcomes, valid), rep("0", 2))
    valid[,] <- 1
    spec$sensitivity$candidate_bounds <- lapply(spec$sensitivity$candidate_bounds,
      function(bound) { bound$per_patient_cap <- 1; bound })
    expect_identical(.family_b_integer_losses(spec, x, outcomes, valid), rep("4", 2))
  }
})

test_that("pure R logarithm is accurate at normalization edges and ties", {
  for (value in c(1 / 64, 0.5, 1, 2, 3, 64, 1e6)) {
    encoded <- .cross_parse(sprintf("%.0f", value * 2^50))
    result <- .family_b_logq(.cross_shift_left(encoded, 14))
    expect_lt(abs(.cross_double(result) / 2^64 - log(value)), 1e-12)
  }
  for (a in -9:9) for (b in 1:5) {
    expect_equal(.cross_double(.family_b_divround(.cross_small(a), .cross_small(b))),
      round(a / b))
  }
})
