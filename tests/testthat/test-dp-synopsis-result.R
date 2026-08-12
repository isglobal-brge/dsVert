.synopsis_result_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path("test-dp-synopsis-start.R"))) {
    if (is.call(expression) && identical(
        as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_result_require <- function() skip_if_not(exists(
  ".dsvert_dp_synopsis_execution_result_v1", mode = "function",
  inherits = TRUE), "RED: synopsis RESULT is absent")

.synopsis_result_call <- function(
    fixture, setup, peer, first = setup$encoded[[1L]],
    second = setup$encoded[[2L]], signer = fixture$input$signer,
    exact_compiler = NULL,
    exact_consume = .dsvert_joint_dp_vector_exact_gc_consume,
    session = NULL) {
  .dsvert_dp_synopsis_execution_result_v1(
    setup$authorized[[peer]]$state, setup$session_id, first, second,
    .policy = fixture$input$policies[[peer]],
    .secret = fixture$input$secrets[[peer]],
    .identity = list(
      identity_pk = unname(fixture$input$fixture$pins[[peer]]),
      identity_sk = unname(fixture$input$fixture$pins[[peer]])),
    .cache_get = fixture$input$cache_get,
    .verifier = fixture$input$verifier, .signer = signer,
    .exact_compiler = exact_compiler, .exact_consume = exact_consume,
    .session = session)
}

.synopsis_result_start_local <- function(fixture, setup, peer) {
  context <- .synopsis_result_helpers$.synopsis_start_context(
    fixture, setup, peer)
  expect_identical(as.integer(
    context$attempt$value$execution_geometry$chunk_count), 1L)
  .synopsis_result_helpers$.synopsis_start_call(
    fixture, setup, peer,
    .synopsis_result_helpers$.synopsis_start_zero_source,
    .synopsis_result_helpers$.synopsis_start_sampler(context))
}

.synopsis_result_store_row <- function(connection) {
  tables <- DBI::dbGetQuery(connection, paste(
    "SELECT name FROM sqlite_master WHERE type='table'",
    "ORDER BY name"))$name
  hits <- lapply(tables, function(table) {
    if (!all(c("record_json", "row_mac") %in%
             DBI::dbListFields(connection, table))) return(NULL)
    rows <- DBI::dbGetQuery(connection, paste(
      "SELECT record_json,row_mac FROM",
      DBI::dbQuoteIdentifier(connection, table)))
    rows <- rows[grepl(
      '"phase":"synopsis_local_result_committed"',
      rows$record_json, fixed = TRUE), , drop = FALSE]
    if (!nrow(rows)) return(NULL)
    list(table = table, rows = rows)
  })
  hits <- Filter(Negate(is.null), hits)
  expect_length(hits, 1L)
  hits[[1L]]
}

test_that("synopsis RESULT exposes only the closed authorization ABI", {
  present <- exists(
    ".dsvert_dp_synopsis_execution_result_v1", mode = "function",
    inherits = TRUE)
  expect_true(present, info = "missing dedicated synopsis RESULT")
  if (!present) skip("RED: synopsis RESULT is absent")
  expect_identical(names(formals(
    .dsvert_dp_synopsis_execution_result_v1)), c(
      "ss", "session_id", "first_prepare", "second_prepare",
      ".policy", ".secret", ".identity", ".cache_get", ".verifier",
      ".signer", ".exact_compiler", ".exact_consume", ".session"))
  defaults <- formals(.dsvert_dp_synopsis_execution_result_v1)
  expect_true(all(vapply(defaults[c(
    ".policy", ".secret", ".identity", ".signer", ".exact_compiler",
    ".session")], is.null, logical(1L))))
  expect_identical(defaults$.cache_get,
    quote(.dsvert_dp_capsule_manifest_cache_get))
  expect_identical(defaults$.verifier, quote(.dsvert_relay_verify_message))
  expect_identical(defaults$.exact_consume,
    quote(.dsvert_joint_dp_vector_exact_gc_consume))
})

test_that("non-exact RESULT is authority-only for K=2/3/5 and closed", {
  .synopsis_result_require()
  fields <- c(
    "version", "phase", "execution_id", "artifact_key",
    "contract_sha256", "attempt_sha256", "source_contract_sha256",
    "prepare_set_sha256", "local_authority", "execution_chunk_count",
    "public_chunk_count", "local_chunk_commitments",
    "local_chunk_set_root", "local_chunk_set_sha256",
    "all_chunks_durable", "intermediate_payload_exposed", "signature")
  for (k in c(2L, 3L, 5L)) {
    fixture <- .synopsis_result_helpers$
      .synopsis_start_convolution_fixture(k)
    .synopsis_result_helpers$.synopsis_start_cleanup(fixture)
    setup <- .synopsis_result_helpers$.synopsis_start_setup(fixture)
    expect_length(setup$authorities, 2L)
    for (peer in setup$authorities) {
      local <- .synopsis_result_start_local(fixture, setup, peer)
      signed <- NULL
      signer <- function(message, key) {
        signed <<- message
        fixture$input$signer(message, key)
      }
      result <- .synopsis_result_call(
        fixture, setup, peer, first = setup$encoded[[2L]],
        second = setup$encoded[[1L]], signer = signer)
      expect_named(result, fields, ignore.order = FALSE)
      expect_identical(result$version,
        "dsvert-stateless-catalog-synopsis-local-result-v1")
      expect_identical(result$phase, "synopsis_local_result_committed")
      expect_identical(result$local_authority$peer_name, peer)
      expect_identical(as.numeric(result$execution_chunk_count), 1)
      expect_identical(as.numeric(result$public_chunk_count), 1)
      commitments <- unlist(result$local_chunk_commitments,
                            use.names = FALSE)
      expect_identical(commitments, local$local_chunk_sha256)
      expect_identical(result$local_chunk_set_root,
        .dsvert_joint_dp_vector_merkle_root(commitments))
      expect_match(result$prepare_set_sha256, "^[0-9a-f]{64}$")
      expect_match(result$local_chunk_set_sha256, "^[0-9a-f]{64}$")
      expect_true(result$all_chunks_durable)
      expect_false(result$intermediate_payload_exposed)
      expect_true(fixture$input$verifier(
        signed, unname(fixture$input$fixture$pins[[peer]]),
        result$signature))
      message <- rawToChar(signed)
      expect_true(all(vapply(c(
        result$prepare_set_sha256, commitments,
        result$local_chunk_set_root, result$local_chunk_set_sha256),
        grepl, logical(1L), x = message, fixed = TRUE)))
    }
    for (peer in setdiff(fixture$peers, setup$authorities)) {
      path <- .dsvert_dp_synopsis_execution_store_path_v1(
        fixture$input$policies[[peer]])
      expect_error(.dsvert_dp_synopsis_execution_result_v1(
        new.env(parent = emptyenv()), setup$session_id,
        setup$encoded[[1L]], setup$encoded[[2L]],
        .policy = fixture$input$policies[[peer]],
        .secret = fixture$input$secrets[[peer]],
        .identity = list(identity_pk = unname(
          fixture$input$fixture$pins[[peer]])),
        .cache_get = fixture$input$cache_get,
        .verifier = fixture$input$verifier,
        .signer = fixture$input$signer),
        "authorization|noise authority")
      expect_false(file.exists(path))
    }
  }
})

test_that("RESULT is not-ready without every durable LOCAL chunk", {
  .synopsis_result_require()
  fixture <- .synopsis_result_helpers$.synopsis_start_convolution_fixture()
  .synopsis_result_helpers$.synopsis_start_cleanup(fixture)
  setup <- .synopsis_result_helpers$.synopsis_start_setup(fixture)
  peer <- setup$authorities[[1L]]
  forbidden <- function(...) stop("private dependency reached", call. = FALSE)
  observed <- tryCatch(testthat::with_mocked_bindings(
    .synopsis_result_call(
      fixture, setup, peer, signer = forbidden,
      exact_compiler = forbidden, exact_consume = forbidden),
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .dsvert_dp_capsule_source_aggregate_release_range_internal = forbidden,
    .get_identity_seed = forbidden, .callMpcTool = forbidden,
    .S = forbidden, .package = "dsVert"), error = identity)
  expect_s3_class(observed, "dsvert_phase_not_ready")
})

test_that("RESULT rejects tampered, mixed and duplicate PREPARE first", {
  .synopsis_result_require()
  fixture <- .synopsis_result_helpers$.synopsis_start_convolution_fixture()
  .synopsis_result_helpers$.synopsis_start_cleanup(fixture)
  setup <- .synopsis_result_helpers$.synopsis_start_setup(fixture)
  peer <- setup$authorities[[1L]]
  forbidden <- function(...) stop("RESULT signer reached", call. = FALSE)

  tampered <- setup$prepared[[2L]]
  tampered$seed_commitment <- strrep("f", 64L)
  tampered <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(tampered))
  expect_error(.synopsis_result_call(
    fixture, setup, peer, second = tampered, signer = forbidden),
    "PREPARE|signature")
  expect_error(.synopsis_result_call(
    fixture, setup, peer, second = setup$encoded[[1L]],
    signer = forbidden), "PREPARE|coverage|duplicate")

  planner <- .synopsis_result_helpers$.synopsis_start_helpers$
    .synopsis_execution_helpers$.synopsis_authorization_helpers$
    .synopsis_receipt_helpers$.synopsis_artifact_planner(operational = "b")
  alternate <- .synopsis_result_helpers$
    .synopsis_start_convolution_fixture(2L, planner)
  .synopsis_result_helpers$.synopsis_start_cleanup(alternate)
  other <- .synopsis_result_helpers$.synopsis_start_setup(alternate)
  expect_false(identical(
    setup$prepared[[1L]]$attempt_sha256,
    other$prepared[[1L]]$attempt_sha256))
  expect_error(.synopsis_result_call(
    fixture, setup, peer, second = other$encoded[[2L]],
    signer = forbidden), "PREPARE|agree|attempt")
  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    fixture$input$policies[[peer]])
  expect_false(file.exists(path))
})

test_that("RESULT HMAC first writer replays without private dependencies", {
  .synopsis_result_require()
  fixture <- .synopsis_result_helpers$.synopsis_start_convolution_fixture()
  .synopsis_result_helpers$.synopsis_start_cleanup(fixture)
  setup <- .synopsis_result_helpers$.synopsis_start_setup(fixture)
  peer <- setup$authorities[[1L]]
  .synopsis_result_start_local(fixture, setup, peer)
  calls <- 0L
  signer <- function(message, key) {
    calls <<- calls + 1L
    fixture$input$signer(message, key)
  }
  result <- .synopsis_result_call(fixture, setup, peer, signer = signer)
  expect_identical(calls, 1L)

  context <- .synopsis_result_helpers$.synopsis_start_context(
    fixture, setup, peer)
  prepares <- .dsvert_dp_synopsis_execution_prepare_set_v1(
    setup$encoded[[1L]], setup$encoded[[2L]], context,
    fixture$input$policies[[peer]], fixture$input$verifier)
  noncanonical <- result
  noncanonical$local_chunk_commitments <- list(
    result$local_chunk_commitments)
  noncanonical$signature <- fixture$input$signer(
    .dsvert_dp_synopsis_execution_result_message_v1(noncanonical),
    unname(fixture$input$fixture$pins[[peer]]))
  expect_error(.dsvert_dp_synopsis_execution_result_validate_v1(
    noncanonical, context, prepares, fixture$input$policies[[peer]],
    fixture$input$verifier), "Invalid durable synopsis RESULT")

  forbidden <- function(...) stop(
    "private or session dependency reran", call. = FALSE)
  replay <- testthat::with_mocked_bindings(
    .synopsis_result_call(
      fixture, setup, peer, first = setup$encoded[[2L]],
      second = setup$encoded[[1L]], signer = forbidden,
      exact_compiler = forbidden, exact_consume = forbidden),
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .dsvert_dp_capsule_source_aggregate_release_range_internal = forbidden,
    .get_identity_seed = forbidden, .callMpcTool = forbidden,
    .S = forbidden, .package = "dsVert")
  expect_identical(replay, result)

  second <- .synopsis_result_helpers$.synopsis_start_setup(
    fixture, "00000000-0000-4000-8000-000000000002")
  expect_identical(testthat::with_mocked_bindings(
    .synopsis_result_call(
      fixture, second, peer, signer = forbidden,
      exact_compiler = forbidden, exact_consume = forbidden),
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .dsvert_dp_capsule_source_aggregate_release_range_internal = forbidden,
    .get_identity_seed = forbidden, .callMpcTool = forbidden,
    .S = forbidden, .package = "dsVert"), result)

  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    fixture$input$policies[[peer]])
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  row <- .synopsis_result_store_row(connection)
  expect_identical(nrow(row$rows), 1L)
  expect_match(row$rows$row_mac[[1L]], "^[0-9a-f]{64}$")
  table <- DBI::dbQuoteIdentifier(connection, row$table)
  expect_identical(DBI::dbExecute(connection, paste(
    "UPDATE", table, "SET row_mac=? WHERE record_json LIKE ?"),
    params = list(strrep("0", 64L),
      '%"phase":"synopsis_local_result_committed"%')), 1L)
  DBI::dbDisconnect(connection)
  expect_error(.synopsis_result_call(
    fixture, setup, peer, signer = forbidden,
    exact_compiler = forbidden, exact_consume = forbidden),
    "authentication|HMAC|store")
})

test_that("exact-GC RESULT cannot invent a durable LOCAL chunk", {
  .synopsis_result_require()
  fixture <- .synopsis_result_helpers$.synopsis_start_helpers$
    .synopsis_execution_helpers$.synopsis_authorization_fixture(2L)
  .synopsis_result_helpers$.synopsis_start_cleanup(fixture)
  setup <- .synopsis_result_helpers$.synopsis_start_setup(fixture)
  peer <- setup$authorities[[1L]]
  context <- .synopsis_result_helpers$.synopsis_start_context(
    fixture, setup, peer)
  expect_true(context$vector$profile$exact_gc)
  forbidden <- function(...) stop("exact consume reached", call. = FALSE)
  expect_error(.synopsis_result_call(
    fixture, setup, peer, signer = forbidden,
    exact_compiler = forbidden, exact_consume = forbidden,
    session = new.env(parent = emptyenv())),
    "exact-GC|exact GC|RESULT adapter")
  expect_false(file.exists(.dsvert_dp_synopsis_execution_store_path_v1(
    fixture$input$policies[[peer]])))
})
