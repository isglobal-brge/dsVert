.synopsis_exact_downstream_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-exact-gc.R"))) {
    if (is.call(expression) && identical(
        as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_exact_downstream_setup <- function(k = 2L) {
  h <- .synopsis_exact_downstream_helpers
  fixture <- h$.synopsis_exact_fixture(k)
  h$.synopsis_exact_cleanup(fixture, envir = parent.frame())
  setup <- h$.synopsis_exact_setup(fixture)
  shares <- c(
    as.character(openssl::bignum(2) ^ 128L - 5L), "12")
  validities <- c(0L, 1L)
  results <- locals <- sessions <- list()
  for (position in seq_along(setup$authorities)) {
    peer <- setup$authorities[[position]]
    context <- h$.synopsis_exact_context(fixture, setup, peer)
    session <- h$.synopsis_exact_session(fixture, setup, peer)
    compiler <- h$.synopsis_exact_compiler(context)
    h$.synopsis_exact_start(
      fixture, setup, peer, session, compiler,
      function(ss, session_id, binding, ...) h$.synopsis_exact_started(
        binding))
    noised <- .exact_gc_decimal_residues_b64(shares[[position]], 128L)
    validity <- gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(validities[[position]])))
    noised_hash <- digest::digest(
      jsonlite::base64_dec(noised), algo = "sha256", serialize = FALSE)
    validity_hash <- digest::digest(
      jsonlite::base64_dec(validity), algo = "sha256", serialize = FALSE)
    consumer <- function(ss, binding, worker_contract, .commit) {
      internal <- list(
        noised_share_b64 = noised, validity_share_b64 = validity,
        noised_share_sha256 = noised_hash,
        validity_share_sha256 = validity_hash,
        binding_sha256 = binding$binding_sha256,
        purpose = binding$purpose, operation_id = binding$operation_id,
        backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND)
      expect_true(.commit(internal))
      list(
        version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_COMMIT_VERSION,
        backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND,
        binding_sha256 = binding$binding_sha256,
        operation_id = binding$operation_id, purpose = binding$purpose,
        noised_share_sha256 = noised_hash,
        validity_share_sha256 = validity_hash, durable = TRUE,
        intermediate_payload_exposed = FALSE,
        source_share_exposed = FALSE, private_seed_exposed = FALSE,
        preclamp_values_exposed = FALSE)
    }
    results[[peer]] <- h$.synopsis_exact_result(
      fixture, setup, peer, session, compiler, consumer)
    locals[[peer]] <- .dsvert_dp_synopsis_execution_with_store_v1(
      fixture$input$policies[[peer]], fixture$input$secrets[[peer]],
      function(connection) .dsvert_dp_synopsis_execution_local_load_v1(
        connection, fixture$input$secrets[[peer]], context, NULL,
        .dsvert_dp_synopsis_execution_chunk_v1(context, 0L),
        fixture$input$policies[[peer]], fixture$input$verifier))
    sessions[[peer]] <- session
  }
  list(fixture = fixture, setup = setup, results = results,
       locals = locals, sessions = sessions)
}

.synopsis_exact_downstream_session <- function(built, peer) {
  ss <- built$setup$authorized[[peer]]$state
  exact <- built$sessions[[peer]]
  for (field in ls(exact, all.names = TRUE)) {
    ss[[field]] <- exact[[field]]
  }
  others <- setdiff(built$setup$authorities, peer)
  ss$.session_id <- built$setup$session_id
  ss$peer_transport_pks <- stats::setNames(lapply(seq_along(others),
    function(index) gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(index + 20L, 32L))))), others)
  ss$.typed_blob_self_name <- peer
  ss$.typed_blob_peer_identity_pks <- as.list(
    built$fixture$input$fixture$pins[others])
  ss$.typed_blob_peer_binding_digest <- strrep("a", 64L)
  ss
}

.synopsis_exact_downstream_reader <- function(built, local_peer) {
  function(session, typed_context, sender, public_chunk,
           expected_segments) {
    value <- built$locals[[sender]]
    descriptor <- expected_segments[[1L]]
    list(segments = list(c(descriptor[c(
      "execution_chunk_index", "coordinate_offset", "coordinate_count")],
      list(noised_share_b64 = value$noised_share_b64,
           noised_share_sha256 = value$noised_share_sha256,
           validity_share_b64 = value$validity_share_b64,
           validity_share_sha256 = value$validity_share_sha256,
           binding_sha256 = value$binding_sha256,
           chunk_commitment_sha256 =
             value$output_commitment_sha256))), encrypted = "ciphertext")
  }
}

test_that("exact synopsis FINAL_SHARE transports validity and binding", {
  built <- .synopsis_exact_downstream_setup()
  peer <- built$setup$authorities[[1L]]
  recipient <- built$setup$authorities[[2L]]
  ss <- .synopsis_exact_downstream_session(built, peer)
  observed <- new.env(parent = emptyenv())
  result <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_final_share_v1(
      ss, built$setup$session_id, built$results[[1L]],
      built$results[[2L]], 0L,
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(identity_pk = unname(
        built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier,
      .encryptor = function(plaintext, recipient_pk) {
        observed$payload <- jsonlite::fromJSON(
          rawToChar(plaintext), simplifyVector = FALSE)
        jsonlite::base64_enc(raw(32L))
      }),
    .S = function(...) ss,
    .exact_gc_validate_bound_peer_context = function(ss, session_id) {
      ss$.exact_gc_peer_binding_digest
    },
    .dsvert_typed_blob_operation_replay = function(...) list(hit = FALSE),
    .dsvert_typed_blob_mint = function(...) list(transfer_id = "ok"),
    .dsvert_typed_blob_operation_commit = function(
        ss, producer, request, result) result, .package = "dsVert")
  expect_true(result$capability_available)
  expect_identical(observed$payload$context$share_format,
    "ring128-exact-gc-local-chunk-segments-v1")
  segment <- observed$payload$segments[[1L]]
  expect_named(segment, c(
    "execution_chunk_index", "coordinate_offset", "coordinate_count",
    "noised_share_b64", "noised_share_sha256", "validity_share_b64",
    "validity_share_sha256", "binding_sha256",
    "chunk_commitment_sha256"), ignore.order = TRUE)
  expect_identical(segment$binding_sha256,
                   built$locals[[peer]]$binding_sha256)
  expect_identical(recipient, result$transfer$recipient_name %||% recipient)
  context <- .synopsis_exact_downstream_helpers$.synopsis_exact_context(
    built$fixture, built$setup, peer)
  public_chunk <- .dsvert_dp_synopsis_execution_public_chunk_v1(
    context, 0L)
  expected <- list(segment[c(
    "execution_chunk_index", "coordinate_offset", "coordinate_count",
    "chunk_commitment_sha256")])
  reader <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_default_peer_reader_v1(
      ss, observed$payload$context, peer, public_chunk, expected),
    .dsvert_typed_blob_consume = function(...) "ciphertext",
    .key_get = function(...) raw(32L),
    .callMpcTool = function(command, input) {
      expect_identical(command, "transport-decrypt")
      list(data = gsub("[\r\n]", "", jsonlite::base64_enc(charToRaw(
        .dsvert_dp_canonical_json(
          .dsvert_dp_canonical_query_value(observed$payload))))))
    }, .package = "dsVert")
  expect_identical(reader$segments[[1L]]$binding_sha256,
                   built$locals[[peer]]$binding_sha256)
  altered_context <- observed$payload$context
  altered_context$execution_chunk_coordinates <- "64"
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    altered_context, peer), "geometry")
  altered_context <- observed$payload$context
  altered_context$share_format <- "ring128-local-chunk-segments-v2"
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    altered_context, peer), "binding")
  altered_context$share_format <- list(
    "ring128-exact-gc-local-chunk-segments-v1")
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    altered_context, peer), "binding")
  altered_context$share_format <- factor(
    "ring128-exact-gc-local-chunk-segments-v1")
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    altered_context, peer), "binding")
})

test_that("exact synopsis segments and final certificates fail closed", {
  built <- .synopsis_exact_downstream_setup()
  peer <- built$setup$authorities[[1L]]
  other <- built$setup$authorities[[2L]]
  context <- .synopsis_exact_downstream_helpers$.synopsis_exact_context(
    built$fixture, built$setup, peer)
  chunk <- .dsvert_dp_synopsis_execution_chunk_v1(context, 0L)
  local <- built$locals[[peer]]
  expected <- list(
    execution_chunk_index = chunk$index,
    coordinate_offset = chunk$offset,
    coordinate_count = chunk$count,
    chunk_commitment_sha256 = local$output_commitment_sha256)
  segment <- c(expected[c(
    "execution_chunk_index", "coordinate_offset", "coordinate_count")],
  list(
    noised_share_b64 = local$noised_share_b64,
    noised_share_sha256 = local$noised_share_sha256,
    validity_share_b64 = local$validity_share_b64,
    validity_share_sha256 = local$validity_share_sha256,
    binding_sha256 = local$binding_sha256,
    chunk_commitment_sha256 = local$output_commitment_sha256))
  expect_silent(
    .dsvert_dp_synopsis_execution_exact_segment_v1(segment, expected))
  altered <- segment; altered$extra <- TRUE
  expect_error(.dsvert_dp_synopsis_execution_exact_segment_v1(
    altered, expected), "segment")
  altered <- segment; altered$noised_share_sha256 <- strrep("f", 64L)
  expect_error(.dsvert_dp_synopsis_execution_exact_segment_v1(
    altered, expected), "authentication")
  altered <- segment
  altered$validity_share_b64 <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(2L)))
  expect_error(.dsvert_dp_synopsis_execution_exact_segment_v1(
    altered, expected), "validity")
  altered <- segment; altered$binding_sha256 <- strrep("f", 64L)
  expect_error(.dsvert_dp_synopsis_execution_exact_segment_v1(
    altered, expected), "authentication")

  remote <- built$locals[[other]]
  output <- .dsvert_joint_dp_vector_exact_gc_finalize(
    own = local, peer = remote, scaled_upper_bounds = "512",
    binding_sha256 = local$binding_sha256)
  expect_identical(
    .dsvert_dp_synopsis_execution_exact_final_values_v1(
      output, local$binding_sha256, "512"), list("7"))
  altered <- output; altered$validity <- FALSE
  expect_error(.dsvert_dp_synopsis_execution_exact_final_values_v1(
    altered, local$binding_sha256, "512"), "certificate")
  altered <- output; altered$clamped_scaled_values <- list("513")
  expect_error(.dsvert_dp_synopsis_execution_exact_final_values_v1(
    altered, local$binding_sha256, "512"), "certificate")
})

test_that("exact FINAL_SHARE excludes K3 and K5 witnesses", {
  for (k in c(3L, 5L)) {
    built <- .synopsis_exact_downstream_setup(k)
    peer <- built$setup$authorities[[1L]]
    recipient <- built$setup$authorities[[2L]]
    ss <- .synopsis_exact_downstream_session(built, peer)
    expect_identical(names(ss$peer_transport_pks), recipient)
    expect_identical(names(ss$.typed_blob_peer_identity_pks), recipient)
    binding_checks <- 0L
    result <- testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_execution_final_share_v1(
        ss, built$setup$session_id, built$results[[1L]],
        built$results[[2L]], 0L,
        .policy = built$fixture$input$policies[[peer]],
        .secret = built$fixture$input$secrets[[peer]],
        .identity = list(identity_pk = unname(
          built$fixture$input$fixture$pins[[peer]])),
        .cache_get = built$fixture$input$cache_get,
        .verifier = built$fixture$input$verifier,
        .encryptor = function(...) jsonlite::base64_enc(raw(32L))),
      .S = function(...) ss,
      .exact_gc_validate_bound_peer_context = function(ss, session_id) {
        binding_checks <<- binding_checks + 1L
        ss$.exact_gc_peer_binding_digest
      },
      .dsvert_typed_blob_operation_replay = function(...) list(hit = FALSE),
      .dsvert_typed_blob_mint = function(...) list(transfer_id = "ok"),
      .dsvert_typed_blob_operation_commit = function(
          ss, producer, request, result) result, .package = "dsVert")
    expect_true(result$capability_available)
    expect_identical(binding_checks, 1L)
  }
})

test_that("exact synopsis RELEASE finalizes binding and validity", {
  built <- .synopsis_exact_downstream_setup()
  forged_peer <- built$setup$authorities[[1L]]
  expect_error(.dsvert_dp_synopsis_execution_release_v1(
    built$setup$authorized[[forged_peer]]$state,
    built$setup$session_id, built$results[[1L]], built$results[[2L]],
    .policy = built$fixture$input$policies[[forged_peer]],
    .secret = built$fixture$input$secrets[[forged_peer]],
    .identity = list(
      identity_pk = unname(
        built$fixture$input$fixture$pins[[forged_peer]]),
      identity_sk = unname(
        built$fixture$input$fixture$pins[[forged_peer]])),
    .cache_get = built$fixture$input$cache_get,
    .verifier = built$fixture$input$verifier,
    .signer = built$fixture$input$signer,
    .peer_share_reader = .synopsis_exact_downstream_reader(
      built, forged_peer),
    .finalizer = function(input) {
      output <- do.call(
        .dsvert_joint_dp_vector_exact_gc_finalize, input)
      output$clamped_scaled_values <- list("8")
      output
    }, .session = new.env(parent = emptyenv())), "exact result")
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), .dsvert_dp_synopsis_execution_store_path_v1(
      built$fixture$input$policies[[forged_peer]]))
  expect_identical(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM synopsis_public_chunks")$n,
    0L)
  DBI::dbDisconnect(connection)
  releases <- list()
  for (peer in built$setup$authorities) {
    releases[[peer]] <- .dsvert_dp_synopsis_execution_release_v1(
      built$setup$authorized[[peer]]$state, built$setup$session_id,
      built$results[[2L]], built$results[[1L]],
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(
        identity_pk = unname(built$fixture$input$fixture$pins[[peer]]),
        identity_sk = unname(built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier,
      .signer = built$fixture$input$signer,
      .peer_share_reader = .synopsis_exact_downstream_reader(built, peer),
      .finalizer = function(input) do.call(
        .dsvert_joint_dp_vector_exact_gc_finalize, input),
      .session = new.env(parent = emptyenv()))
  }
  expect_identical(releases[[1L]]$final_vector_root,
                   releases[[2L]]$final_vector_root)
  forbidden <- function(...) stop("private dependency reached", call. = FALSE)
  replayed <- .dsvert_dp_synopsis_execution_release_v1(
    built$setup$authorized[[forged_peer]]$state,
    built$setup$session_id, built$results[[2L]], built$results[[1L]],
    .policy = built$fixture$input$policies[[forged_peer]],
    .secret = built$fixture$input$secrets[[forged_peer]],
    .identity = list(identity_pk = unname(
      built$fixture$input$fixture$pins[[forged_peer]])),
    .cache_get = built$fixture$input$cache_get,
    .verifier = built$fixture$input$verifier,
    .peer_share_reader = forbidden, .finalizer = forbidden,
    .session = new.env(parent = emptyenv()))
  expect_identical(replayed, releases[[forged_peer]])
  for (peer in built$setup$authorities) {
    path <- .dsvert_dp_synopsis_execution_store_path_v1(
      built$fixture$input$policies[[peer]])
    connection <- DBI::dbConnect(RSQLite::SQLite(), path)
    row <- DBI::dbGetQuery(connection,
      "SELECT record_json FROM synopsis_public_chunks")
    DBI::dbDisconnect(connection)
    public <- jsonlite::fromJSON(
      row$record_json[[1L]], simplifyVector = FALSE)$public_chunk
    expect_identical(public$scaled_values, list("7"))
  }
})

test_that("exact synopsis REPLAY is public-only", {
  built <- .synopsis_exact_downstream_setup()
  releases <- lapply(built$setup$authorities, function(peer)
    .dsvert_dp_synopsis_execution_release_v1(
      built$setup$authorized[[peer]]$state, built$setup$session_id,
      built$results[[1L]], built$results[[2L]],
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(
        identity_pk = unname(built$fixture$input$fixture$pins[[peer]]),
        identity_sk = unname(built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier,
      .signer = built$fixture$input$signer,
      .peer_share_reader = .synopsis_exact_downstream_reader(built, peer),
      .finalizer = function(input) do.call(
        .dsvert_joint_dp_vector_exact_gc_finalize, input),
      .session = new.env(parent = emptyenv())))
  forbidden <- function(...) stop("private dependency reached", call. = FALSE)
  peer <- built$setup$authorities[[1L]]
  replay <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_replay_v1(
      built$setup$authorized[[peer]]$state, built$setup$session_id,
      releases[[2L]], releases[[1L]], 0L,
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(identity_pk = unname(
        built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier),
    .S = forbidden, .dsvert_typed_blob_consume = forbidden,
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .dsvert_joint_dp_vector_exact_gc_finalize = forbidden,
    .package = "dsVert")
  expect_identical(replay$chunk$scaled_values, list("7"))
  expect_true(replay$durable_replay)
})
