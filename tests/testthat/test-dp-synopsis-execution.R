.synopsis_execution_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-authorization.R"))) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_execution_required <- c(
  ".dsvert_dp_synopsis_execution_context_v1",
  ".dsvert_dp_synopsis_execution_prepare_v1",
  ".dsvert_dp_synopsis_execution_store_path_v1",
  ".dsvert_dp_synopsis_execution_with_store_v1",
  ".dsvert_dp_synopsis_execution_transaction_v1",
  ".dsvert_dp_synopsis_execution_artifact_load_v1",
  ".dsvert_dp_synopsis_execution_start_claim_v1")

.synopsis_execution_require <- function() {
  missing <- .synopsis_execution_required[!vapply(
    .synopsis_execution_required, exists, logical(1L),
    mode = "function", inherits = TRUE)]
  if (length(missing)) skip(paste("RED: missing", paste(missing, collapse = ", ")))
}

.synopsis_execution_authorities <- function(fixture) {
  pins <- fixture$input$fixture$pins
  ids <- unlist(
    fixture$artifact$semantic$noise_authority_roles$authority_ids,
    use.names = FALSE)
  unname(names(pins)[match(ids, unname(pins))])
}

.synopsis_execution_authorize <- function(
    fixture, peer, session_id = "00000000-0000-4000-8000-000000000001") {
  .synopsis_execution_helpers$.synopsis_authorize_test(
    fixture, peer, session_id = session_id)
}

.synopsis_execution_prepare <- function(
    fixture, authorized, peer,
    session_id = "00000000-0000-4000-8000-000000000001",
    signer = fixture$input$signer) {
  pin <- unname(fixture$input$fixture$pins[[peer]])
  testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_prepare_v1(
      authorized$state, session_id,
      .policy = fixture$input$policies[[peer]],
      .secret = fixture$input$secrets[[peer]],
      .identity = list(identity_pk = pin, identity_sk = pin),
      .cache_get = fixture$input$cache_get, .signer = signer),
    .get_identity_seed = function() {
      gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(61L, 32L))))
    }, .package = "dsVert")
}

test_that("the dedicated synopsis execution API is explicit and minimal", {
  present <- vapply(
    .synopsis_execution_required, exists, logical(1L),
    mode = "function", inherits = TRUE)
  expect_true(all(present), info = paste(
    "missing", paste(.synopsis_execution_required[!present], collapse = ", ")))
  if (!all(present)) skip("RED: dedicated synopsis execution API is absent")
  prepare <- formals(.dsvert_dp_synopsis_execution_prepare_v1)
  expect_identical(names(prepare), c(
    "ss", "session_id", ".policy", ".secret", ".identity",
    ".cache_get", ".signer"))
  expect_identical(prepare$.policy, quote(NULL))
  expect_identical(prepare$.secret, quote(NULL))
  expect_identical(prepare$.identity, quote(NULL))
  expect_identical(
    prepare$.cache_get, quote(.dsvert_dp_capsule_manifest_cache_get))
  expect_identical(prepare$.signer, quote(NULL))
})

test_that("PREPARE is authority-only for K=2/3/5 and signs a closed receipt", {
  .synopsis_execution_require()
  receipt_fields <- c(
    "version", "execution_id", "artifact_key", "contract_sha256",
    "attempt_sha256", "local_authority", "commitment_context",
    "seed_commitment", "signature")
  for (k in c(2L, 3L, 5L)) {
    fixture <- .synopsis_execution_helpers$.synopsis_authorization_fixture(k)
    authorities <- .synopsis_execution_authorities(fixture)
    expect_length(authorities, 2L)
    signed <- vector("list", 2L)
    prepared <- unname(Map(function(peer, index) {
      authorized <- .synopsis_execution_authorize(fixture, peer)
      signer <- function(message, key) {
        signed[[index]] <<- message
        fixture$input$signer(message, key)
      }
      .synopsis_execution_prepare(fixture, authorized, peer, signer = signer)
    }, authorities, seq_along(authorities)))
    expect_true(all(vapply(prepared, function(value) {
      identical(names(value), receipt_fields) &&
        all(grepl("^[0-9a-f]{64}$", unlist(value[c(
          "execution_id", "artifact_key", "contract_sha256",
          "attempt_sha256", "commitment_context", "seed_commitment")])) )
    }, logical(1L))))
    expect_identical(
      vapply(prepared, `[[`, character(1L), "execution_id"),
      rep(prepared[[1L]]$execution_id, 2L))
    expect_identical(
      vapply(prepared, `[[`, character(1L), "contract_sha256"),
      rep(prepared[[1L]]$contract_sha256, 2L))
    expect_identical(
      vapply(prepared, `[[`, character(1L), "attempt_sha256"),
      rep(prepared[[1L]]$attempt_sha256, 2L))
    expect_identical(
      vapply(prepared, function(x) x$local_authority$role, character(1L)),
      unlist(fixture$artifact$semantic$noise_authority_roles$role_order,
             use.names = FALSE))
    expect_false(identical(
      prepared[[1L]]$seed_commitment, prepared[[2L]]$seed_commitment))
    for (index in seq_along(prepared)) {
      message <- rawToChar(signed[[index]])
      expect_true(all(vapply(c(
        prepared[[index]]$contract_sha256,
        prepared[[index]]$attempt_sha256,
        prepared[[index]]$seed_commitment), grepl, logical(1L),
        x = message, fixed = TRUE)))
    }
  }
})

test_that("PREPARE reads installed auth but no evidence, source, store or RNG", {
  .synopsis_execution_require()
  fixture <- .synopsis_execution_helpers$.synopsis_authorization_fixture(3L)
  peer <- .synopsis_execution_authorities(fixture)[[1L]]
  authorized <- .synopsis_execution_authorize(fixture, peer)
  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    fixture$input$policies[[peer]])
  expect_false(file.exists(path))
  forbidden <- function(...) stop("forbidden PREPARE dependency", call. = FALSE)
  value <- testthat::with_mocked_bindings(
    .synopsis_execution_prepare(fixture, authorized, peer),
    .dsvert_dp_synopsis_compile_v1 = forbidden,
    .dsvert_dp_synopsis_artifact_v1 = forbidden,
    .dsvert_dp_synopsis_source_claim_set_v1 = forbidden,
    .dsvert_dp_synopsis_source_claim_set_validate_v1 = forbidden,
    .dsvert_dp_synopsis_source_transport_prepare_v1 = forbidden,
    .dsvert_dp_capsule_source_aggregate_chunk_internal = forbidden,
    .dsvert_dp_synopsis_execution_with_store_v1 = forbidden,
    .dsvert_dp_synopsis_execution_start_claim_v1 = forbidden,
    .dsvert_secure_random_bytes = forbidden,
    .dsvert_dp_noise_root = forbidden,
    .package = "dsVert")
  expect_identical(value$artifact_key, fixture$artifact$artifact_key)
  expect_false(file.exists(path))

  witness <- setdiff(fixture$peers, .synopsis_execution_authorities(fixture))[[1L]]
  witness_path <- .dsvert_dp_synopsis_execution_store_path_v1(
    fixture$input$policies[[witness]])
  expect_error(.dsvert_dp_synopsis_execution_prepare_v1(
    new.env(parent = emptyenv()),
    "00000000-0000-4000-8000-000000000001",
    .policy = fixture$input$policies[[witness]],
    .secret = fixture$input$secrets[[witness]],
    .identity = list(
      identity_pk = unname(fixture$input$fixture$pins[[witness]]),
      identity_sk = unname(fixture$input$fixture$pins[[witness]])),
    .cache_get = fixture$input$cache_get,
    .signer = fixture$input$signer), "authorization|noise authority")
  expect_false(file.exists(witness_path))
})

test_that("sticky contract survives sessions and operational replanning", {
  .synopsis_execution_require()
  fixture <- .synopsis_execution_helpers$.synopsis_authorization_fixture(2L)
  peer <- .synopsis_execution_authorities(fixture)[[1L]]
  first_auth <- .synopsis_execution_authorize(fixture, peer)
  first <- .synopsis_execution_prepare(fixture, first_auth, peer)
  second_id <- "00000000-0000-4000-8000-000000000002"
  second_auth <- .synopsis_execution_authorize(
    fixture, peer, session_id = second_id)
  second <- .synopsis_execution_prepare(
    fixture, second_auth, peer, session_id = second_id)
  expect_identical(
    first[c("execution_id", "contract_sha256", "attempt_sha256",
            "commitment_context", "seed_commitment")],
    second[c("execution_id", "contract_sha256", "attempt_sha256",
             "commitment_context", "seed_commitment")])

  planner <- .synopsis_execution_helpers$.synopsis_authorization_helpers$
    .synopsis_receipt_helpers$.synopsis_artifact_planner(
      operational = "b", threat_model = "alternate planner prose",
      threshold_scalar = TRUE)
  alternate <- .synopsis_execution_helpers$.synopsis_authorization_fixture(
    2L, planner)
  alternate_auth <- .synopsis_execution_authorize(alternate, peer)
  replanned <- .synopsis_execution_prepare(
    alternate, alternate_auth, peer)
  expect_identical(first$execution_id, replanned$execution_id)
  expect_identical(first$contract_sha256, replanned$contract_sha256)
  expect_identical(first$seed_commitment, replanned$seed_commitment)
  expect_false(identical(first$attempt_sha256, replanned$attempt_sha256))

  identity <- list(identity_pk = unname(fixture$input$fixture$pins[[peer]]))
  context <- .dsvert_dp_synopsis_execution_context_v1(
    first_auth$state, first_auth$value$session_id,
    fixture$input$policies[[peer]], fixture$input$secrets[[peer]], identity,
    fixture$input$cache_get)
  alternate_context <- .dsvert_dp_synopsis_execution_context_v1(
    alternate_auth$state, alternate_auth$value$session_id,
    alternate$input$policies[[peer]], alternate$input$secrets[[peer]],
    identity, alternate$input$cache_get)
  expect_identical(context$contract$sha256,
                   alternate_context$contract$sha256)
  expect_false(identical(context$attempt$sha256,
                         alternate_context$attempt$sha256))
  expect_identical(
    as.numeric(context$contract$value$geometry$public_chunk_coordinates),
    min(8192, as.numeric(
      context$contract$value$geometry$coordinate_count)))
})

test_that("the two signed PREPARE records form one closed authority set", {
  fixture <- .synopsis_execution_helpers$.synopsis_authorization_fixture(3L)
  authorities <- .synopsis_execution_authorities(fixture)
  prepared <- lapply(authorities, function(peer) {
    authorized <- .synopsis_execution_authorize(fixture, peer)
    .synopsis_execution_prepare(fixture, authorized, peer)
  })
  local <- .synopsis_execution_authorize(fixture, authorities[[1L]])
  context <- .dsvert_dp_synopsis_execution_context_v1(
    local$state, local$value$session_id,
    fixture$input$policies[[authorities[[1L]]]],
    fixture$input$secrets[[authorities[[1L]]]],
    list(identity_pk = unname(
      fixture$input$fixture$pins[[authorities[[1L]]]])),
    fixture$input$cache_get)
  encode <- function(value) .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(value))
  first <- encode(prepared[[1L]])
  second <- encode(prepared[[2L]])
  verified <- .dsvert_dp_synopsis_execution_prepare_set_v1(
    first, second, context, fixture$input$policies[[authorities[[1L]]]],
    fixture$input$verifier)
  expect_identical(names(verified), authorities)
  expect_identical(
    .dsvert_dp_synopsis_execution_prepare_set_v1(
      second, first, context,
      fixture$input$policies[[authorities[[1L]]]],
      fixture$input$verifier), verified)

  tampered <- prepared[[2L]]
  tampered$attempt_sha256 <- strrep("f", 64L)
  expect_error(.dsvert_dp_synopsis_execution_prepare_set_v1(
    first, encode(tampered), context,
    fixture$input$policies[[authorities[[1L]]]],
    fixture$input$verifier), "PREPARE|signature|agree")
  expect_error(.dsvert_dp_synopsis_execution_prepare_set_v1(
    first, first, context, fixture$input$policies[[authorities[[1L]]]],
    fixture$input$verifier), "PREPARE|coverage|duplicate")
  extra <- prepared[[2L]]
  extra$unexpected <- TRUE
  expect_error(.dsvert_dp_synopsis_execution_prepare_set_v1(
    first, encode(extra), context,
    fixture$input$policies[[authorities[[1L]]]],
    fixture$input$verifier), "PREPARE")
})

test_that("the dedicated START claim is first-win and attempt-bound", {
  .synopsis_execution_require()
  fixture <- .synopsis_execution_helpers$.synopsis_authorization_fixture(2L)
  peer <- .synopsis_execution_authorities(fixture)[[1L]]
  authorized <- .synopsis_execution_authorize(fixture, peer)
  prepare <- .synopsis_execution_prepare(fixture, authorized, peer)
  policy <- fixture$input$policies[[peer]]
  secret <- fixture$input$secrets[[peer]]
  path <- .dsvert_dp_synopsis_execution_store_path_v1(policy)
  withr::defer(unlink(c(path, paste0(path, c(".lock", "-wal", "-shm"))),
                      force = TRUE), envir = parent.frame())
  claim <- function(attempt = prepare$attempt_sha256) {
    .dsvert_dp_synopsis_execution_with_store_v1(
      policy, secret, function(connection) {
        .dsvert_dp_synopsis_execution_transaction_v1(connection, {
          .dsvert_dp_synopsis_execution_start_claim_v1(
            connection, prepare$artifact_key, prepare$contract_sha256,
            attempt, 1L, 1L, secret)
        })
      })
  }
  first <- claim()
  expect_identical(claim(), first)
  expect_error(claim(strrep("f", 64L)), "conflict|attempt|first|claimed")
  stored <- .dsvert_dp_synopsis_execution_with_store_v1(
    policy, secret, function(connection) {
      .dsvert_dp_synopsis_execution_artifact_load_v1(
        connection, secret, prepare$artifact_key)
    })
  expect_identical(stored$artifact_key, prepare$artifact_key)
  expect_identical(stored$sticky_core_sha256, prepare$contract_sha256)
  expect_identical(stored$run_binding_sha256, prepare$attempt_sha256)
  expect_identical(as.numeric(stored$execution_chunk_count), 1)
  expect_identical(as.numeric(stored$public_chunk_count), 1)
  expect_identical(stored$state, "STARTED")
})
