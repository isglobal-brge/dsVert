test_that("B2 admits only the exact family, shape and numeric certificate", {
  for (family in c("binomial", "poisson")) {
    f <- .irls_producer_fixture(family, "64")
    admitted <- .dsvert_dp_irls_profile_admit(f$signed, f$pins)
    expect_identical(admitted$contract, f$spec)
    expect_identical(admitted$certificate$rows, "64")
    for (rows in c("0", "65", "200", "1000"))
      expect_error(.dsvert_dp_irls_profile_certificate(family, "3", rows))
    for (p in c("2", "5", "10"))
      expect_error(.dsvert_dp_irls_profile_certificate(family, p, "64"))
    expect_error(.dsvert_dp_irls_profile_certificate(family, "3", "64", "2"))
    bad <- f$spec; bad$numeric$approximation_certificate_sha256 <- strrep("a", 64L)
    expect_error(.dsvert_dp_irls_profile_admit(f$sign(bad), f$pins), "uncertified")
    bad <- f$spec; bad$numeric$curvature_role <- "derivative"
    expect_error(.dsvert_dp_irls_profile_admit(f$sign(bad), f$pins), "uncertified")
    bad <- f$spec; bad$numeric$compiler_version <- "unreviewed"
    expect_error(.dsvert_dp_irls_profile_admit(f$sign(bad), f$pins), "uncertified")
    bad <- f$spec; bad$privacy_source$x_bounds[[2L]]$upper <- .irls_q("1", "2")
    expect_error(.dsvert_dp_irls_profile_admit(f$sign(bad), f$pins), "uncertified")
    bad <- f$spec; bad$privacy_source$peer_pins$third_owner <- f$pins[[1L]]
    expect_error(.dsvert_dp_irls_profile_check(bad), "owner count")
  }
  f <- .irls_contract_fixture()
  expect_error(.dsvert_dp_irls_profile_admit(f$signed, f$pins), "uncertified")
})

test_that("B2 public points come only from a verified B1 predecessor", {
  f <- .irls_producer_fixture()
  base <- tempfile("irls-producer-"); dir.create(base, mode = "0700")
  on.exit(unlink(base, recursive = TRUE), add = TRUE)
  paths <- setNames(file.path(base, names(f$pins), "reservations.sqlite"), names(f$pins))
  for (peer in names(paths)) .dsvert_dp_irls_store_create(paths[[peer]], f$signed, f$pins, peer)
  pred <- .dsvert_dp_irls_start_digest(f$spec)
  plan <- .dsvert_dp_irls_stage_plan(paths[[1L]], f$signed, f$pins, "0", pred)
  expect_identical(plan$beta, list("0", "0", "0"))
  expect_true(plan$intercept); expect_identical(plan$offset_mode, "none")
  expect_identical(plan$certificate_digest, f$spec$numeric$approximation_certificate_sha256)
  alternate <- f$spec$path$start$beta; alternate[[1L]] <- .irls_q("1", "65536")
  expect_error(.dsvert_dp_irls_stage_plan(paths[[1L]], f$signed, f$pins, "0", pred, alternate), "alternate evaluation beta")
  expect_error(.dsvert_dp_irls_stage_plan(paths[[1L]], f$signed, f$pins, "1", strrep("a", 64L)), "dual-committed")
  payload <- f$payload(); payload$g[[1L]] <- as.character(as.integer(payload$g[[1L]]) + 1L)
  pair <- lapply(names(paths), function(peer) .dsvert_dp_irls_successor_prepare(
    paths[[peer]], f$signed, f$pins, "0", pred, payload, f$identities[[peer]]$identity_sk))
  committed <- lapply(paths, function(path) .dsvert_dp_irls_successor_commit(path, f$signed, f$pins, pair))[[1L]]
  next_plan <- .dsvert_dp_irls_stage_plan(paths[[1L]], f$signed, f$pins, "1", committed$body$payload_digest)
  expect_identical(next_plan$beta[[1L]], "16")
  expect_false(identical(plan$point_digest, next_plan$point_digest))
  expect_error(.dsvert_dp_irls_stage_plan(paths[[1L]], f$signed, f$pins, "1", strrep("a", 64L)), "alternate evaluation predecessor")
})

test_that("B2 admits signed offsets and doubles only replace-person calibration", {
  f <- .irls_producer_fixture("poisson")
  s <- f$spec
  s$estimand$formula <- "y ~ x + z + offset(o)"
  s$estimand$offset <- list(kind = "offset", column_id = "o", zero_exposure = "not-applicable")
  column <- s$estimand$columns[[2L]]; column$column_id <- "o"; column$role <- "offset"
  s$estimand$columns <- append(s$estimand$columns, list(column))
  s$privacy_source$offset_bounds <- list(lower = .irls_q("-1"), upper = .irls_q("1"))
  s$privacy_source$adjacency <- "replace-one-person"
  s$accounting$sensitivity <- lapply(s$accounting$sensitivity, function(v) as.character(2*gmp::as.bigz(v)))
  s$accounting$stages <- lapply(s$accounting$stages, function(stage) {
    for (lane in c("g", "H")) stage[[paste0("alpha_", lane)]] <-
      .dsvert_dp_irls_rational(.dsvert_dp_irls_bigq(stage[[lane]])/gmp::as.bigz(s$accounting$sensitivity[[lane]]))
    stage
  })
  admitted <- .dsvert_dp_irls_profile_admit(f$sign(s), f$pins)
  expect_identical(admitted$contract$accounting$sensitivity, list(H = "2703360", g = "1351680"))
  expect_identical(admitted$contract$numeric$translation, f$spec$numeric$translation)
  s$privacy_source$offset_bounds$upper <- .irls_q("1", "2")
  expect_error(.dsvert_dp_irls_profile_admit(f$sign(s), f$pins), "uncertified")
})
