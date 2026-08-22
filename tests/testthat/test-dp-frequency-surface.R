.frequency_surface_names <- c(
  "dsvertDPFrequencyClaimDS",
  "dsvertDPFrequencyCompileDS",
  "dsvertDPFrequencyAuthorizeDS",
  "dsvertDPFrequencySourceWindowDS",
  "dsvertDPFrequencyFinalizeWindowDS",
  "dsvertDPFrequencyReplayDS",
  "dsvertDPFrequencyCleanupDS")

.frequency_surface_json <- function(value) {
  .dsvert_dsi_text_encode(.dsvert_dp_canonical_json(
    .dsvert_dp_analysis_canonical_value_v1(value)))
}

test_that("Frequency public ABI is exact and purpose-bound", {
  namespace <- asNamespace("dsVert")
  expect_true(all(vapply(
    .frequency_surface_names, exists, logical(1L),
    envir = namespace, mode = "function", inherits = FALSE)))
  expect_identical(names(formals(get(
    "dsvertDPFrequencyClaimDS", namespace))),
    c("data_name", "variable_name"))
  expect_identical(names(formals(get(
    "dsvertDPFrequencyCompileDS", namespace))),
    c("data_name", "source_claim_json"))
  expect_identical(names(formals(get(
    "dsvertDPFrequencyAuthorizeDS", namespace))), c(
      "config_json", "receipts_json", "source_claim_json", "session_id"))
  expect_identical(names(formals(get(
    "dsvertDPFrequencySourceWindowDS", namespace))), c(
      "data_name", "session_id", "operation_id", "window_index",
      "public_authorizations_json", "source_claim_json"))
  expect_identical(names(formals(get(
    "dsvertDPFrequencyFinalizeWindowDS", namespace))), c(
      "session_id", "operation_id", "window_index",
      "public_authorizations_json"))
  expect_identical(names(formals(get(
    "dsvertDPFrequencyReplayDS", namespace))),
    c("session_id", "operation_id", "window_index"))
  expect_identical(names(formals(get(
    "dsvertDPFrequencyCleanupDS", namespace))), "session_id")

  registered <- .dsvert_registered_remote_methods(
    .dsvert_test_package_file("DESCRIPTION"))
  expect_true(all(.frequency_surface_names %in% registered))
  expect_true(all(.frequency_surface_names %in% getNamespaceExports("dsVert")))
  expect_true("mpcTypedBlobReadDS" %in% registered)
  # The formal-finalizer relay is intentionally quarantined: Frequency has a
  # closed lifecycle of its own and must not make an unrelated, incomplete
  # statistical frontdoor remotely reachable.
  expect_false("dsvertFormalFinalizerHandoffSourceDS" %in% registered)
})

test_that("Frequency settings require one explicit server-held source owner", {
  owner <- list(peer_name = "site_b", identity_pk =
    .dsvert_relay_b64url_encode(as.raw(rep(2L, 32L))))
  local_pk <- .dsvert_relay_b64url_encode(as.raw(rep(1L, 32L)))
  local_pk_standard <- .base64url_to_base64(local_pk)
  options <- list(
    dsvert.dp.frequency.source_owner = owner,
    dsvert.dp.frequency.domain = "clinical-frequency",
    dsvert.dp.frequency.cohort_id = "cohort-v1",
    dsvert.dp.frequency.coordinate_upper_bound = 64L,
    dsvert.dp.frequency.adjacency = "add_remove_patient",
    dsvert.dp.frequency.epsilon = 1,
    dsvert.dp.frequency.delta = 0.01,
    dsvert.dp.frequency.implementation_delta = 0.001)
  withr::local_options(options)
  context <- testthat::with_mocked_bindings(
    .dsvert_dp_frequency_surface_context_v1(),
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function() list(
      identity_pk = local_pk_standard, identity_sk = local_pk_standard),
    .get_trusted_peers = function() list(site_b = owner$identity_pk),
    .package = "dsVert")
  expect_identical(context$settings$source_owner, owner)
  expect_identical(context$identity$identity_pk, local_pk)
  expect_identical(context$settings$coordinate_upper_bound, 64)
  expect_identical(names(context$peer_pins), c("site_a", "site_b"))

  withr::local_options(list(dsvert.dp.frequency.source_owner = NULL))
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_frequency_surface_context_v1(),
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .get_identity_keypair = function() list(
      identity_pk = local_pk_standard, identity_sk = local_pk_standard),
    .get_trusted_peers = function() list(site_b = owner$identity_pk),
    .package = "dsVert"), "unavailable or ambiguous")
})

test_that("Frequency surface delegates one closed server lifecycle", {
  namespace <- asNamespace("dsVert")
  endpoint <- function(name) get(name, namespace, inherits = FALSE)
  session_id <- "00000000-0000-4000-8000-000000000001"
  operation_id <- "op_00000000000000000000000000000001"
  pk_a <- .dsvert_relay_b64url_encode(as.raw(rep(1L, 32L)))
  pk_b <- .dsvert_relay_b64url_encode(as.raw(rep(2L, 32L)))
  pins <- c(site_a = pk_a, site_b = pk_b)
  claim <- .dsvert_dp_analysis_canonical_value_v1(list(
    version = "claim-v1", source_peer_name = "site_a"))
  config <- list(version = "config-v1", peer_pins = pins)
  receipts <- list(
    list(peer_name = "site_a"), list(peer_name = "site_b"))
  authorizations <- list(
    list(local_authority = list(role = "source_owner")),
    list(local_authority = list(role = "secondary_noise_authority")))
  context <- list(
    peer_name = "site_a",
    identity = list(identity_pk = pk_a, identity_sk = pk_a),
    peer_pins = pins,
    settings = list(source_owner = list(
      peer_name = "site_a", identity_pk = pk_a)))
  state <- new.env(parent = emptyenv())
  state$.dp_frequency_authorization <- list(marker = "private")
  storage <- new.env(parent = emptyenv())
  storage[[session_id]] <- state
  events <- character()
  D <- data.frame(category = factor("a"))

  result <- testthat::with_mocked_bindings({
    claim_result <- endpoint("dsvertDPFrequencyClaimDS")("D", "category")
    compile_result <- endpoint("dsvertDPFrequencyCompileDS")(
      "D", .frequency_surface_json(claim))
    authorize_result <- endpoint("dsvertDPFrequencyAuthorizeDS")(
      .frequency_surface_json(config), .frequency_surface_json(receipts),
      .frequency_surface_json(claim), session_id)
    source_result <- endpoint("dsvertDPFrequencySourceWindowDS")(
      "D", session_id, operation_id, 0L,
      .frequency_surface_json(authorizations),
      .frequency_surface_json(claim))
    final_result <- endpoint("dsvertDPFrequencyFinalizeWindowDS")(
      session_id, operation_id, 0L,
      .frequency_surface_json(authorizations))
    replay_result <- endpoint("dsvertDPFrequencyReplayDS")(
      session_id, operation_id, 0L)
    cleanup_first <- endpoint("dsvertDPFrequencyCleanupDS")(session_id)
    cleanup_retry <- endpoint("dsvertDPFrequencyCleanupDS")(session_id)
    list(claim_result, compile_result, authorize_result, source_result,
         final_result, replay_result, cleanup_first, cleanup_retry)
  },
    .dsvert_dp_frequency_surface_context_v1 = function() context,
    .dsvert_dp_frequency_surface_config_v1 = function(value) config,
    .dsvert_dp_frequency_claim_v1 = function(
        data, variable_name, peer_name, identity, peer_pins, ...) {
      events <<- c(events, "claim")
      expect_identical(data, D)
      expect_identical(variable_name, "category")
      claim
    },
    .dsvert_dp_frequency_local_compile_v1 = function(
        source_claim, peer_name, peer_pins, settings, .source_resolver, ...) {
      events <<- c(events, "compile")
      expect_identical(source_claim, claim)
      expect_identical(.source_resolver(), D)
      list(config = config, receipt = receipts[[1L]])
    },
    .dsvert_dp_frequency_public_authorization_v1 = function(
        ss, session_id, config, receipts, source_claim, ...) {
      events <<- c(events, "authorize")
      expect_identical(ss, state)
      expect_identical(config$peer_pins, pins)
      list(local_authority = list(role = "source_owner"))
    },
    .dsvert_dp_frequency_execution_source_window_v1 = function(
        ss, session_id, operation_id, window_index, public_authorizations,
        claim, .source_resolver, ...) {
      events <<- c(events, "source")
      expect_identical(.source_resolver(), D)
      list(state = "issued", ciphertext_chars = "sealed")
    },
    .dsvert_dp_frequency_execution_finalize_window_v1 = function(...) {
      events <<- c(events, "finalize")
      list(state = "release_committed")
    },
    .dsvert_dp_frequency_execution_replay_window_v1 = function(...) {
      events <<- c(events, "replay")
      list(state = "release_replay")
    },
    .dsvert_dp_frequency_session_authorization_validate_v1 = function(...) {
      events <<- c(events, "cleanup_auth")
      state$.dp_frequency_authorization
    },
    .cleanup_session = function(id) {
      events <<- c(events, "cleanup")
      rm(list = id, envir = storage)
      invisible(TRUE)
    },
    .session_storage = function() storage,
    .package = "dsVert")

  expect_identical(result[[1L]], claim)
  expect_identical(result[[2L]],
                   list(config = config, receipt = receipts[[1L]]))
  expect_identical(result[[3L]]$local_authority$role, "source_owner")
  expect_identical(vapply(result[4:6], `[[`, character(1L), "state"), c(
    "issued", "release_committed", "release_replay"))
  expect_identical(result[[7L]], list(cleaned = TRUE, state = "cleaned"))
  expect_identical(
    result[[8L]], list(cleaned = TRUE, state = "already_cleaned"))
  expect_identical(events, c(
    "claim", "compile", "authorize", "source", "finalize", "replay",
    "cleanup_auth", "cleanup"))
})

test_that("Frequency cleanup rejects a foreign session shell", {
  session_id <- "00000000-0000-4000-8000-000000000001"
  storage <- new.env(parent = emptyenv())
  storage[[session_id]] <- new.env(parent = emptyenv())
  cleanup_called <- FALSE

  expect_error(testthat::with_mocked_bindings(
    dsvertDPFrequencyCleanupDS(session_id),
    .session_storage = function() storage,
    .dsvert_dp_frequency_session_authorization_validate_v1 = function(...) {
      stop("Invalid Frequency session authorization.", call. = FALSE)
    },
    .cleanup_session = function(...) cleanup_called <<- TRUE,
    .package = "dsVert"), "authorization")
  expect_true(exists(session_id, envir = storage, inherits = FALSE))
  expect_false(cleanup_called)
})

test_that("Frequency surface rejects malformed wire before protected access", {
  source_resolved <- FALSE
  expect_error(testthat::with_mocked_bindings(
    get("dsvertDPFrequencyCompileDS", asNamespace("dsVert"))(
      "D", .dsvert_dsi_text_encode("{\"b\":1,\"a\":2}")),
    .dsvert_dp_frequency_surface_context_v1 = function() stop(
      "server context reached"),
    .dsvert_dp_frequency_local_compile_v1 = function(...) {
      source_resolved <<- TRUE
    },
    .package = "dsVert"), "non-canonical")
  expect_false(source_resolved)

  pins <- c(
    site_a = .dsvert_relay_b64url_encode(as.raw(rep(1L, 32L))),
    site_b = .dsvert_relay_b64url_encode(as.raw(rep(2L, 32L))))
  decoded <- testthat::with_mocked_bindings(
    .dsvert_dp_frequency_surface_config_v1(.frequency_surface_json(list(
      version = "test-config", peer_pins = as.list(pins)))),
    .dsvert_dp_frequency_config_validate_v1 = function(value) value,
    .package = "dsVert")
  expect_identical(decoded$peer_pins, pins)
  expect_error(.dsvert_dp_frequency_surface_array_v1(
    .frequency_surface_json(list(list(role = "source_owner"))),
    "public authorization array",
    .DSVERT_DP_FREQUENCY_AUTHORIZATIONS_MAX_BYTES, length = 2L),
    "public authorization array")

  source <- paste(readLines(.dsvert_test_package_file(
    "R", "dpFrequencySurfaceDS.R", source_only = TRUE), warn = FALSE),
    collapse = "\n")
  for (forbidden in c(
      "mpcTypedBlobReadDS", "capsule", "ledger", "SQLite", "RSQLite")) {
    expect_false(grepl(forbidden, source, fixed = TRUE), info = forbidden)
  }
})
