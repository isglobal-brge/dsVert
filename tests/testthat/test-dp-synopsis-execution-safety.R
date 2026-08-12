.synopsis_execution_safety_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-execution.R"))) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_execution_safety_context <- function(fixture, peer) {
  authorized <- .synopsis_execution_safety_helpers$
    .synopsis_execution_authorize(fixture, peer)
  .dsvert_dp_synopsis_execution_context_v1(
    authorized$state, authorized$value$session_id,
    .policy = fixture$input$policies[[peer]],
    .secret = fixture$input$secrets[[peer]],
    .identity = list(identity_pk = unname(
      fixture$input$fixture$pins[[peer]])),
    .cache_get = fixture$input$cache_get)
}

test_that("Ring128 headroom covers the complete released support", {
  fixture <- .synopsis_execution_safety_helpers$
    .synopsis_execution_helpers$.synopsis_authorization_fixture(2L)
  peer <- .synopsis_execution_safety_helpers$
    .synopsis_execution_authorities(fixture)[[1L]]
  context <- .synopsis_execution_safety_context(fixture, peer)
  ring <- context$contract$value$ring
  expect_identical(as.numeric(ring$ring_bits), 128)
  expect_identical(ring$no_wrap_certified, TRUE)
  expect_true(all(grepl("^(0|[1-9][0-9]*)$", unlist(ring[c(
    "maximum_scaled_source_coordinate",
    "maximum_release_noise_magnitude", "positive_limit")]))))

  huge <- as.character((openssl::bignum(2) ^ 127L) - 1L)
  planner <- .synopsis_execution_safety_helpers$
    .synopsis_execution_helpers$.synopsis_authorization_helpers$
    .synopsis_receipt_helpers$.synopsis_artifact_planner(draw = huge)
  expect_error(
    .synopsis_execution_safety_helpers$.synopsis_execution_helpers$
      .synopsis_authorization_fixture(2L, planner),
    "Ring128|headroom|wrap")
})

test_that("Ring128 accepts its exact boundary and counts both draws", {
  limit <- (openssl::bignum(2) ^ 127L) - 1L
  lattice <- list(raw_upper_bounds = "1", scale_shifts = 0L)
  exact <- .dsvert_joint_dp_vector_profile(
    "discrete-laplace", .DSVERT_JOINT_DP_VECTOR_EXACT_BACKEND)
  exact_support <- limit - 1L
  certificate <- .dsvert_dp_synopsis_ring_certificate_v1(
    lattice, list(maximum_noise_magnitude = as.character(exact_support)),
    exact)
  expect_identical(certificate$maximum_release_noise_magnitude,
                   as.character(exact_support))
  expect_error(.dsvert_dp_synopsis_ring_certificate_v1(
    lattice, list(maximum_noise_magnitude = as.character(limit)), exact),
    "Ring128|wrap")

  convolution <- .dsvert_joint_dp_vector_profile(
    "discrete-laplace", .DSVERT_JOINT_DP_VECTOR_BACKEND)
  per_peer <- (limit - 1L) %/% 2L
  certificate <- .dsvert_dp_synopsis_ring_certificate_v1(
    lattice, list(maximum_noise_magnitude = as.character(per_peer)),
    convolution)
  expect_identical(certificate$maximum_release_noise_magnitude,
                   as.character(2L * per_peer))
  expect_error(.dsvert_dp_synopsis_ring_certificate_v1(
    lattice, list(maximum_noise_magnitude = as.character(per_peer + 1L)),
    convolution), "Ring128|wrap")
})

test_that("execution ranges do not inherit transport chunk geometry", {
  fixture <- .synopsis_execution_safety_helpers$
    .synopsis_execution_helpers$.synopsis_authorization_fixture(2L)
  peer <- .synopsis_execution_safety_helpers$
    .synopsis_execution_authorities(fixture)[[1L]]
  context <- .synopsis_execution_safety_context(fixture, peer)
  events <- list()
  contract <- context$source_contract
  contract$release_coordinate_count <- 512L
  contract$coordinate_count <- 512L
  contract$chunk_coordinates <- 8192L
  parsed <- list(
    contract = contract, manifest = list(test = TRUE),
    contract_hash = strrep("a", 64L))
  share <- as.raw(rep(0L, 128L * 16L))
  testthat::with_mocked_bindings({
    value <- .dsvert_dp_capsule_source_aggregate_release_range_internal(
      fixture$input$policies[[peer]], context$manifest_json,
      offset = 128L, count = 128L,
      secret = fixture$input$secrets[[peer]],
      source_contract = contract)
    expect_identical(value, share)
  }, .dsvert_dp_capsule_source_contract_json = function(...) parsed,
  .dsvert_dp_capsule_source_contract_validate = identity,
  .dsvert_dp_capsule_source_cross_contract = function(...) TRUE,
  .dsvert_dp_capsule_source_with_store = function(policy, secret, code) {
    code("connection")
  }, .dsvert_dp_capsule_source_incoming_load = function(...) list(
    complete = TRUE, contract_hash = parsed$contract_hash),
  .dsvert_dp_capsule_source_aggregate_range_in_store = function(
      connection, contract, capsule_id, start, count, secret) {
    events$range <<- c(start, count)
    share
  }, .dsvert_dp_gaussian_cross_inject_release_share_internal = function(
      connection, secret, manifest, contract, chunk, share) {
    events$gaussian <<- chunk
    share
  }, .dsvert_dp_categorical_cross_inject_release_share_internal = function(
      connection, secret, manifest, contract, chunk, share, policy) {
    events$categorical <<- chunk
    share
  }, .package = "dsVert")
  expect_identical(events$range, c(129, 128))
  expect_identical(events$gaussian[c("offset", "count")],
                   list(offset = 128, count = 128))
  expect_identical(events$categorical[c("offset", "count")],
                   list(offset = 128, count = 128))
})

test_that("the execution claim store authenticates rows, schema and rollback", {
  fixture <- .synopsis_execution_safety_helpers$
    .synopsis_execution_helpers$.synopsis_authorization_fixture(2L)
  peer <- .synopsis_execution_safety_helpers$
    .synopsis_execution_authorities(fixture)[[1L]]
  policy <- fixture$input$policies[[peer]]
  secret <- fixture$input$secrets[[peer]]
  path <- .dsvert_dp_synopsis_execution_store_path_v1(policy)
  paths <- c(path, paste0(path, c(".lock", "-wal", "-shm")))
  withr::defer(unlink(paths, force = TRUE), envir = parent.frame())
  artifact <- strrep("a", 64L)
  core <- strrep("b", 64L)
  attempt <- strrep("c", 64L)
  with_store <- function(code) .dsvert_dp_synopsis_execution_with_store_v1(
    policy, secret, code)
  expect_error(with_store(function(connection) {
    .dsvert_dp_synopsis_execution_transaction_v1(connection, {
      .dsvert_dp_synopsis_execution_start_claim_v1(
        connection, strrep("d", 64L), core, attempt, 1L, 1L, secret)
      stop("rollback sentinel", call. = FALSE)
    })
  }), "rollback sentinel")
  expect_null(with_store(function(connection) {
    .dsvert_dp_synopsis_execution_artifact_load_v1(
      connection, secret, strrep("d", 64L))
  }))
  with_store(function(connection) {
    .dsvert_dp_synopsis_execution_transaction_v1(connection, {
      .dsvert_dp_synopsis_execution_start_claim_v1(
        connection, artifact, core, attempt, 1L, 1L, secret)
    })
  })
  expect_error(.dsvert_dp_synopsis_execution_with_store_v1(
    policy, as.raw(rep(255L, 32L)), identity),
    "another policy|authentication")

  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, paste(
    "UPDATE synopsis_artifacts SET record_json='{}'",
    "WHERE artifact_key=?"), params = list(artifact))
  DBI::dbDisconnect(connection)
  expect_error(with_store(function(connection) {
    .dsvert_dp_synopsis_execution_artifact_load_v1(
      connection, secret, artifact)
  }), "authentication|malformed")

  unlink(paths, force = TRUE)
  with_store(identity)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, "CREATE TABLE foreign_state(value TEXT)")
  DBI::dbDisconnect(connection)
  expect_error(with_store(identity), "schema")
})
