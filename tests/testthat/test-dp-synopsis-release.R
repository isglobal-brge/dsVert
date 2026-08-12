.synopsis_release_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-final-share.R"))) {
    if (is.call(expression) && identical(
        as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})
.synopsis_release_helpers$.synopsis_result_helpers <-
  .synopsis_release_helpers$.synopsis_final_share_helpers

.synopsis_release_require <- function() skip_if_not(exists(
  ".dsvert_dp_synopsis_execution_release_v1", mode = "function",
  inherits = TRUE), "RED: synopsis RELEASE is absent")

.synopsis_release_call <- function(
    built, peer, first = built$results[[1L]],
    second = built$results[[2L]], signer = built$fixture$input$signer,
    peer_share_reader = .synopsis_release_reader(built, peer),
    finalizer = NULL, session = new.env(parent = emptyenv()),
    session_id = built$setup$session_id) {
  .dsvert_dp_synopsis_execution_release_v1(
    built$setup$authorized[[peer]]$state, session_id, first, second,
    .policy = built$fixture$input$policies[[peer]],
    .secret = built$fixture$input$secrets[[peer]],
    .identity = list(
      identity_pk = unname(built$fixture$input$fixture$pins[[peer]]),
      identity_sk = unname(built$fixture$input$fixture$pins[[peer]])),
    .cache_get = built$fixture$input$cache_get,
    .verifier = built$fixture$input$verifier, .signer = signer,
    .peer_share_reader = peer_share_reader, .finalizer = finalizer,
    .session = session)
}

.synopsis_release_reader <- function(built, local_peer, observe = NULL) {
  function(session, typed_context, sender, public_chunk,
           expected_segments) {
    if (is.function(observe)) observe(
      session, typed_context, sender, public_chunk, expected_segments)
    context <- .synopsis_release_helpers$.synopsis_result_helpers$
      .synopsis_result_helpers$
      .synopsis_start_context(built$fixture, built$setup, sender)
    indices <- unlist(
      public_chunk$execution_chunk_indices, use.names = FALSE)
    records <- .dsvert_dp_synopsis_execution_with_store_v1(
      built$fixture$input$policies[[sender]],
      built$fixture$input$secrets[[sender]], function(connection) {
        lapply(indices, function(index) {
          chunk <- .dsvert_dp_synopsis_execution_chunk_v1(context, index)
          .dsvert_dp_synopsis_execution_local_load_v1(
            connection, built$fixture$input$secrets[[sender]], context,
            NULL, chunk, built$fixture$input$policies[[sender]],
            built$fixture$input$verifier)
        })
      })
    expect_false(any(vapply(records, is.null, logical(1L))))
    expect_identical(sender, setdiff(built$setup$authorities, local_peer))
    expect_identical(
      unlist(lapply(records, function(value)
        value$receipt$local_chunk_sha256), use.names = FALSE),
      unlist(lapply(expected_segments, function(value)
        value$chunk_commitment_sha256), use.names = FALSE))
    bytes <- do.call(c, lapply(records, function(value)
      jsonlite::base64_dec(value$noised_share_b64)))
    list(share_b64 = gsub(
      "[\r\n]", "", jsonlite::base64_enc(bytes)),
      encrypted = "test-ciphertext")
  }
}

.synopsis_release_public_rows <- function(policy) {
  path <- .dsvert_dp_synopsis_execution_store_path_v1(policy)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  tables <- DBI::dbGetQuery(connection, paste(
    "SELECT name FROM sqlite_master WHERE type='table'",
    "ORDER BY name"))$name
  rows <- unlist(lapply(tables, function(table) {
    if (!all(c("record_json", "row_mac") %in%
             DBI::dbListFields(connection, table))) return(list())
    values <- DBI::dbGetQuery(connection, paste(
      "SELECT record_json,row_mac FROM",
      DBI::dbQuoteIdentifier(connection, table)))
    values <- values[grepl(
      '"version":"dsvert-stateless-catalog-synopsis-public-chunk-v1"',
      values$record_json, fixed = TRUE), , drop = FALSE]
    lapply(seq_len(nrow(values)), function(index) list(
      value = jsonlite::fromJSON(
        values$record_json[[index]], simplifyVector = FALSE),
      row_mac = values$row_mac[[index]]))
  }), recursive = FALSE)
  rows
}

.synopsis_release_setup <- function(k = 2L, gaussian = FALSE) {
  result <- .synopsis_release_helpers$.synopsis_result_helpers
  start <- result$.synopsis_result_helpers
  planner <- if (isTRUE(gaussian)) NULL else function(input) {
    .callMpcTool("joint-dp-vector-convolution-plan-v3", input)
  }
  fixture <- start$.synopsis_start_convolution_fixture(
    k, planner = planner, gaussian = gaussian)
  start$.synopsis_start_cleanup(fixture, envir = parent.frame())
  setup <- start$.synopsis_start_setup(fixture)
  results <- lapply(setup$authorities, function(peer) {
    start$.synopsis_start_call(
      fixture, setup, peer, start$.synopsis_start_zero_source,
      function(command, input) .callMpcTool(command, input))
    result$.synopsis_result_call(fixture, setup, peer)
  })
  names(results) <- setup$authorities
  list(fixture = fixture, setup = setup, results = results)
}

.synopsis_release_deterministic <- function() {
  result <- .synopsis_release_helpers$.synopsis_result_helpers
  start <- result$.synopsis_result_helpers
  planner <- function(input) .callMpcTool(
    "joint-dp-vector-convolution-plan-v3", input)
  fixture <- start$.synopsis_start_convolution_fixture(planner = planner)
  start$.synopsis_start_cleanup(fixture, envir = parent.frame())
  setup <- start$.synopsis_start_setup(fixture)
  context <- start$.synopsis_start_context(
    fixture, setup, setup$authorities[[1L]])
  dimension <- context$contract$value$geometry$coordinate_count
  modulus <- openssl::bignum(2) ^ 128L
  sign <- openssl::bignum(2) ^ 127L
  left <- c("5", as.character(modulus - 3L),
            as.character(sign - 2L), as.character(sign - 1L),
            rep("9", dimension - 4L))
  right <- c("7", "2", "1", "1", rep("4", dimension - 4L))
  sources <- list(
    rep("3", dimension), rep("6", dimension))
  shares <- list(left, right)
  observed_sources <- character()
  for (position in seq_along(setup$authorities)) {
    peer <- setup$authorities[[position]]
    local_context <- start$.synopsis_start_context(fixture, setup, peer)
    source_b64 <- .exact_gc_decimal_residues_b64(sources[[position]], 128L)
    start$.synopsis_start_call(
      fixture, setup, peer,
      function(policy, manifest_json, offset, count, secret,
               source_contract) jsonlite::base64_dec(source_b64),
      function(command, input) {
        observed_sources <<- c(observed_sources, input$source_share)
        output <- .callMpcTool(command, input)
        output$noised_share <- .exact_gc_decimal_residues_b64(
          shares[[position]], 128L)
        output
      })
  }
  results <- lapply(setup$authorities, function(peer)
    result$.synopsis_result_call(fixture, setup, peer))
  names(results) <- setup$authorities
  list(
    fixture = fixture, setup = setup, results = results,
    expected = c("12", "0",
      as.character(openssl::bignum(
        context$vector$lattice$raw_upper_bounds[[3L]]) *
          (openssl::bignum(2) ^
             context$vector$lattice$scale_shifts[[3L]])),
      "0", rep("13", dimension - 4L)),
    observed_sources = observed_sources, context = context)
}

test_that("synopsis RELEASE exposes only the closed authorization ABI", {
  present <- exists(
    ".dsvert_dp_synopsis_execution_release_v1", mode = "function",
    inherits = TRUE)
  expect_true(present, info = "missing dedicated synopsis RELEASE")
  if (!present) skip("RED: synopsis RELEASE is absent")
  expect_identical(names(formals(
    .dsvert_dp_synopsis_execution_release_v1)), c(
      "ss", "session_id", "first_result", "second_result",
      ".policy", ".secret", ".identity", ".cache_get", ".verifier",
      ".signer", ".peer_share_reader", ".finalizer", ".session"))
})

test_that("RELEASE reconstructs Ring128 exactly and commits one public root", {
  .synopsis_release_require()
  built <- .synopsis_release_deterministic()
  expect_gt(length(unique(built$context$vector$lattice$scale_shifts)), 1L)
  expect_true(all(vapply(built$observed_sources, function(value)
    any(jsonlite::base64_dec(value) != as.raw(0L)), logical(1L))))
  peer <- built$setup$authorities[[1L]]
  calls <- 0L
  release <- .synopsis_release_call(
    built, peer, finalizer = function(input) {
      calls <<- calls + 1L
      .callMpcTool(
        built$context$vector$profile$finalizer_command, input)
    })
  fields <- c(
    "version", "phase", "execution_id", "artifact_key",
    "contract_sha256", "attempt_sha256", "source_contract_sha256",
    "result_set_sha256", "local_authority", "public_chunk_count",
    "final_chunk_hashes", "final_vector_root", "output_lattice_bits",
    "output_lattice_scale", "mechanism", "epsilon", "delta",
    "implementation_delta_numerator", "implementation_delta_denominator",
    "delta_aggregation", "postprocessing",
    "all_public_chunks_durable", "intermediate_payload_exposed",
    "durable_replay", "capability_available", "signature")
  expect_named(release, fields, ignore.order = FALSE)
  expect_identical(release$phase, "synopsis_released")
  expect_identical(release$output_lattice_scale, "256")
  expect_identical(calls, 1L)
  expect_true(release$all_public_chunks_durable)
  expect_false(release$intermediate_payload_exposed)
  expect_identical(release$final_vector_root,
    .dsvert_joint_dp_vector_merkle_root(unlist(
      release$final_chunk_hashes, use.names = FALSE)))
  rows <- .synopsis_release_public_rows(
    built$fixture$input$policies[[peer]])
  expect_length(rows, 1L)
  expect_match(rows[[1L]]$row_mac, "^[0-9a-f]{64}$")
  expect_identical(
    unlist(rows[[1L]]$value$public_chunk$scaled_values,
           use.names = FALSE), built$expected)

  wide <- built$context
  wide$vector$release_contract$output_lattice_bits <- 62L
  wide_release <- release
  wide_release$output_lattice_bits <- 62L
  wide_release$output_lattice_scale <-
    as.character(openssl::bignum(2) ^ 62L)
  unsigned <- wide_release[setdiff(names(wide_release), "signature")]
  wide_release$signature <- .dsvert_dp_synopsis_signature_v1(
    built$fixture$input$signer(
      .dsvert_dp_synopsis_execution_release_message_v1(unsigned),
      unname(built$fixture$input$fixture$pins[[peer]])))
  expect_silent(.dsvert_dp_synopsis_execution_release_validate_v1(
    wide_release, wide, release$result_set_sha256,
    built$fixture$input$policies[[peer]], built$fixture$input$verifier))

  forbidden <- function(...) stop("release dependency reran", call. = FALSE)
  replay <- .synopsis_release_call(
    built, peer, first = built$results[[2L]],
    second = built$results[[1L]], signer = forbidden,
    peer_share_reader = forbidden, finalizer = forbidden,
    session = NULL)
  expect_identical(replay, release)
})

test_that("RELEASE runs convolution/Gaussian and routes K=2/3/5 authorities", {
  .synopsis_release_require()
  for (k in c(2L, 3L, 5L)) {
    built <- .synopsis_release_setup(k)
    peer <- built$setup$authorities[[1L]]
    context <- .synopsis_release_helpers$.synopsis_result_helpers$
      .synopsis_result_helpers$
      .synopsis_start_context(built$fixture, built$setup, peer)
    release <- .synopsis_release_call(
      built, peer, finalizer = function(input)
        .callMpcTool(context$vector$profile$finalizer_command, input))
    expect_identical(release$local_authority$peer_name, peer)
    for (witness in setdiff(built$fixture$peers,
                            built$setup$authorities)) {
      expect_error(.dsvert_dp_synopsis_execution_release_v1(
        built$setup$authorized[[peer]]$state, built$setup$session_id,
        built$results[[1L]], built$results[[2L]],
        .policy = built$fixture$input$policies[[witness]],
        .secret = built$fixture$input$secrets[[witness]],
        .identity = list(identity_pk = unname(
          built$fixture$input$fixture$pins[[witness]])),
        .cache_get = built$fixture$input$cache_get,
        .verifier = built$fixture$input$verifier),
        "authorization|noise authority")
    }
  }

  gaussian <- .synopsis_release_setup(gaussian = TRUE)
  peer <- gaussian$setup$authorities[[1L]]
  context <- .synopsis_release_helpers$.synopsis_result_helpers$
    .synopsis_result_helpers$
    .synopsis_start_context(gaussian$fixture, gaussian$setup, peer)
  expect_true(context$vector$profile$gaussian)
  expect_silent(.synopsis_release_call(
    gaussian, peer, finalizer = function(input)
      .callMpcTool(context$vector$profile$finalizer_command, input)))
})

test_that("RELEASE rejects malformed RESULT sets before dependencies", {
  .synopsis_release_require()
  built <- .synopsis_release_helpers$.synopsis_final_share_setup()
  peer <- built$setup$authorities[[1L]]
  forbidden <- function(...) stop("release dependency reached", call. = FALSE)
  expect_error(.synopsis_release_call(
    built, peer, second = built$results[[1L]], signer = forbidden,
    peer_share_reader = forbidden, finalizer = forbidden),
    "RESULT|authority|coverage|duplicate")
  mixed <- built$results[[2L]]
  mixed$result_set_sha256 <- strrep("f", 64L)
  expect_error(.synopsis_release_call(
    built, peer, second = mixed, signer = forbidden,
    peer_share_reader = forbidden, finalizer = forbidden),
    "RESULT|agree|signature")
  wrong_share <- function(
      session, typed_context, sender, public_chunk, expected_segments) {
    list(share_b64 = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(1L, public_chunk$count * 16L)))), encrypted = "wrong")
  }
  expect_error(.synopsis_release_call(
    built, peer, signer = forbidden, peer_share_reader = wrong_share,
    finalizer = forbidden), "share.*RESULT|authentication|commitment")

  exact <- .synopsis_release_helpers$.synopsis_result_helpers$
    .synopsis_result_helpers$
    .synopsis_start_helpers$.synopsis_execution_helpers$
    .synopsis_authorization_fixture(2L)
  .synopsis_release_helpers$.synopsis_result_helpers$
    .synopsis_result_helpers$
    .synopsis_start_cleanup(exact)
  setup <- .synopsis_release_helpers$.synopsis_result_helpers$
    .synopsis_result_helpers$
    .synopsis_start_setup(exact)
  peer <- setup$authorities[[1L]]
  expect_error(.dsvert_dp_synopsis_execution_release_v1(
    setup$authorized[[peer]]$state, setup$session_id, list(), list(),
    .policy = exact$input$policies[[peer]],
    .secret = exact$input$secrets[[peer]],
    .identity = list(identity_pk = unname(
      exact$input$fixture$pins[[peer]])),
    .cache_get = exact$input$cache_get,
    .verifier = exact$input$verifier, .signer = forbidden,
    .peer_share_reader = forbidden, .finalizer = forbidden,
    .session = new.env(parent = emptyenv())),
  "RESULT records do not agree")
})

test_that("RELEASE public geometry fixes D=1 and D=8193", {
  .synopsis_release_require()
  geometry <- function(dimension, index) {
    context <- list(
      contract = list(value = list(geometry = list(
        coordinate_count = dimension,
        public_chunk_coordinates = min(8192L, dimension),
        public_chunk_count = ceiling(dimension / min(8192L, dimension))))),
      attempt = list(value = list(execution_geometry = list(
        chunk_coordinates = min(8192L, dimension),
        chunk_count = ceiling(dimension / min(8192L, dimension))))))
    .dsvert_dp_synopsis_execution_public_chunk_v1(context, index)
  }
  expect_identical(geometry(1L, 0L)[c("offset", "count")],
                   list(offset = 0L, count = 1L))
  expect_identical(geometry(8193L, 0L)[c("offset", "count")],
                   list(offset = 0L, count = 8192L))
  expect_identical(geometry(8193L, 1L)[c("offset", "count")],
                   list(offset = 8192L, count = 1L))
})
