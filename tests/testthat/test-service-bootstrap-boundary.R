test_that("the first production remote boundary initializes service state once", {
  calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_identity_test_mode = function() FALSE,
    .dsvert_initialize_service_state = function() {
      calls <<- calls + 1L
      invisible(NULL)
    },
    .package = "dsVert")
  rm(list = ls(.dsvert_service_bootstrap_state, all.names = TRUE),
     envir = .dsvert_service_bootstrap_state)
  on.exit(rm(
    list = ls(.dsvert_service_bootstrap_state, all.names = TRUE),
    envir = .dsvert_service_bootstrap_state), add = TRUE)

  expect_invisible(.dsvert_ensure_service_state())
  expect_invisible(.dsvert_ensure_service_state())
  expect_identical(calls, 1L)
  expect_true(isTRUE(.dsvert_service_bootstrap_state$ready))
})

test_that("a failed service bootstrap is retried and never marked ready", {
  calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_identity_test_mode = function() FALSE,
    .dsvert_initialize_service_state = function() {
      calls <<- calls + 1L
      if (calls == 1L) stop("transient bootstrap failure", call. = FALSE)
      invisible(NULL)
    },
    .package = "dsVert")
  rm(list = ls(.dsvert_service_bootstrap_state, all.names = TRUE),
     envir = .dsvert_service_bootstrap_state)
  on.exit(rm(
    list = ls(.dsvert_service_bootstrap_state, all.names = TRUE),
    envir = .dsvert_service_bootstrap_state), add = TRUE)

  expect_error(.dsvert_ensure_service_state(), "transient bootstrap failure")
  expect_false(isTRUE(.dsvert_service_bootstrap_state$ready))
  expect_false(isTRUE(.dsvert_service_bootstrap_state$initializing))
  expect_invisible(.dsvert_ensure_service_state())
  expect_identical(calls, 2L)
  expect_true(isTRUE(.dsvert_service_bootstrap_state$ready))
})

test_that("package tests do not materialize deployment service state", {
  calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_identity_test_mode = function() TRUE,
    .dsvert_initialize_service_state = function() {
      calls <<- calls + 1L
      stop("test mode must not initialize deployment secrets", call. = FALSE)
    },
    .package = "dsVert")
  rm(list = ls(.dsvert_service_bootstrap_state, all.names = TRUE),
     envir = .dsvert_service_bootstrap_state)
  on.exit(rm(
    list = ls(.dsvert_service_bootstrap_state, all.names = TRUE),
    envir = .dsvert_service_bootstrap_state), add = TRUE)

  expect_invisible(.dsvert_ensure_service_state())
  expect_identical(calls, 0L)
  expect_false(isTRUE(.dsvert_service_bootstrap_state$ready))
})

test_that("configure never materializes deployment service state", {
  skip_on_os("windows")
  root <- withr::local_tempdir(pattern = "dsvert-configure-boundary-")
  home <- file.path(root, "service-home")
  state <- file.path(root, "service-state")
  configure <- .dsvert_test_package_file("configure", source_only = TRUE)

  status <- withr::with_envvar(
    c(HOME = home, DSVERT_STATE_DIR = state),
    system2("sh", configure, stdout = TRUE, stderr = TRUE))

  expect_identical(attr(status, "status", exact = TRUE), NULL)
  expect_false(dir.exists(home))
  expect_false(dir.exists(state))
})

test_that("production bootstrap rejects an image-configured identity seed", {
  state <- withr::local_tempdir(pattern = "dsvert-baked-identity-")
  seed_path <- file.path(state, "identity.seed")
  configured <- jsonlite::base64_enc(as.raw(rep(23L, 32L)))
  recovery_calls <- 0L
  withr::local_options(list(
    dsvert.state_dir = state,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = configured,
    default.dsvert.identity_seed = NULL))
  testthat::local_mocked_bindings(
    .dsvert_dp_noise_root_for_identity_recovery = function(...) {
      recovery_calls <<- recovery_calls + 1L
      stop("recovery must not run", call. = FALSE)
    },
    .dsvert_dp_reject_ephemeral_or_library_path =
      function(...) invisible(NULL),
    .package = "dsVert")

  condition <- tryCatch(
    .dsvert_initialize_service_state(), error = identity)
  expect_s3_class(condition, "error")
  expect_match(
    conditionMessage(condition),
    "must not be configured in a package image or service profile")
  expect_false(grepl(
    configured, conditionMessage(condition), fixed = TRUE))
  expect_identical(recovery_calls, 0L)
  expect_false(file.exists(seed_path))
})

test_that("every production release gate crosses the service bootstrap", {
  calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_ensure_service_state = function() {
      calls <<- calls + 1L
      invisible(NULL)
    },
    .package = "dsVert")

  # setup-security-gate.R installs a compatibility gate for historical unit
  # tests. Exercise the saved production closure here so this assertion covers
  # the actual allowlist boundary rather than that test-wide replacement.
  expect_invisible(
    .dsvert_test_production_gate("dsvertSecurityProfileDS"))
  expect_identical(calls, 1L)
})

test_that("the first production release gate persists both deployment roots", {
  skip_on_os("windows")
  state <- withr::local_tempdir(pattern = "dsvert-first-service-call-")
  noise_path <- file.path(state, "privacy", "noise_root")
  withr::local_options(list(
    dsvert.state_dir = state,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.enabled = FALSE,
    default.dsvert.dp.enabled = NULL,
    dsvert.dp.noise_key_provider = NULL,
    default.dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = noise_path,
    default.dsvert.dp.noise_key_path = NULL,
    dsvert.dp.ledger_path = NULL,
    default.dsvert.dp.ledger_path = ""))
  testthat::local_mocked_bindings(
    .dsvert_identity_test_mode = function() FALSE,
    .dsvert_dp_reject_ephemeral_or_library_path =
      function(...) invisible(NULL),
    .package = "dsVert")
  rm(list = ls(.dsvert_service_bootstrap_state, all.names = TRUE),
     envir = .dsvert_service_bootstrap_state)
  on.exit(rm(
    list = ls(.dsvert_service_bootstrap_state, all.names = TRUE),
    envir = .dsvert_service_bootstrap_state), add = TRUE)

  expect_invisible(.dsvert_enforce_release_mode("dsvertSecurityProfileDS"))
  identity_path <- file.path(state, "identity.seed")
  expect_true(file.exists(identity_path))
  expect_true(file.exists(noise_path))
  expect_identical(as.integer(file.info(identity_path)$mode), 384L)
  expect_identical(as.integer(file.info(noise_path)$mode), 384L)
  expect_true(file.exists(.dsvert_identity_receipt_path(identity_path)))
  expect_true(file.exists(.dsvert_dp_noise_receipt_path(noise_path)))
  expect_true(file.exists(.dsvert_identity_recovery_path(identity_path)))
  expect_true(file.exists(.dsvert_dp_noise_recovery_path(noise_path)))
})
