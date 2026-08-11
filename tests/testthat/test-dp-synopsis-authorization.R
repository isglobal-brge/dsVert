.synopsis_authorization_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-receipts.R"))) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_authorization_fixture <- function(k = 2L, planner = NULL) {
  input <- .synopsis_authorization_helpers$.synopsis_receipt_fixture(k)
  if (is.null(planner)) planner <- input$planner
  peers <- names(input$fixture$pins)
  local <- lapply(peers, input$mint, planner = planner)
  list(
    input = input, peers = peers, artifact = local[[1L]]$artifact,
    receipts = lapply(local, `[[`, "receipt"))
}

.synopsis_authorize_test <- function(
    fixture, peer, ss = new.env(parent = emptyenv()),
    session_id = "00000000-0000-4000-8000-000000000001",
    artifact = fixture$artifact, claim_set = fixture$input$claim_set,
    receipts = fixture$receipts,
    cache_get = fixture$input$cache_get) {
  value <- .dsvert_dp_synopsis_authorize_session_v1(
    ss, session_id, fixture$input$manifest_sha256, artifact,
    claim_set, receipts,
    .policy = fixture$input$policies[[peer]],
    .secret = fixture$input$secrets[[peer]],
    .identity = list(identity_pk = unname(
      fixture$input$fixture$pins[[peer]])),
    .cache_get = cache_get, .verifier = fixture$input$verifier)
  list(state = ss, value = value)
}

.synopsis_seed_test <- function(
    fixture, authorized, peer,
    session_id = "00000000-0000-4000-8000-000000000001",
    seed = as.raw(rep(61L, 32L)), lane = "final_noise") {
  policy <- fixture$input$policies[[peer]]
  secret <- fixture$input$secrets[[peer]]
  identity_pk <- unname(fixture$input$fixture$pins[[peer]])
  testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_sticky_subseed_v1(
      authorized$state, session_id, lane),
    .dsvert_dp_policy = function() policy,
    .dsvert_dp_secret = function() secret,
    .dsvert_dp_capsule_manifest_cache_get = fixture$input$cache_get,
    .get_identity_keypair = function() list(identity_pk = identity_pk),
    .get_identity_seed = function() jsonlite::base64_enc(seed),
    .dsvert_dp_noise_root = function(...) {
      stop("noise root must not be called", call. = FALSE)
    },
    .package = "dsVert")
}

test_that("only the two synopsis noise authorities install session state", {
  for (k in c(2L, 3L, 5L)) {
    fixture <- .synopsis_authorization_fixture(k)
    pins <- fixture$input$fixture$pins
    roles <- fixture$artifact$semantic$noise_authority_roles
    authority_ids <- unlist(roles$authority_ids, use.names = FALSE)
    authorities <- names(pins)[match(authority_ids, unname(pins))]
    expect_length(authorities, 2L)

    authorized <- lapply(authorities, function(peer) {
      .synopsis_authorize_test(fixture, peer)
    })
    expect_identical(
      vapply(authorized, function(value) {
        value$value$local_authority$role
      }, character(1L)),
      unlist(roles$role_order, use.names = FALSE))
    expect_true(all(vapply(authorized, function(value) {
      identical(value$state$.dp_synopsis_authorization, value$value)
    }, logical(1L))))
    expect_true(all(vapply(authorized, function(value) {
      identical(value$value$artifact_key, fixture$artifact$artifact_key)
    }, logical(1L))))
    expect_named(authorized[[1L]]$value, c(
      "version", "session_id", "manifest_sha256", "artifact",
      "artifact_key", "source_claim_set_sha256", "receipt_peers",
      "receipt_set_sha256", "local_authority", "authorization_sha256"),
      ignore.order = FALSE)
    expect_false(any(c(
      "claims", "receipts", "signature", "manifest_json", "seed") %in%
      names(authorized[[1L]]$value)))

    seeds <- Map(function(value, peer) {
      .synopsis_seed_test(fixture, value, peer)
    }, authorized, authorities)
    expect_true(all(grepl("^[0-9a-f]{64}$", unlist(seeds))))
    expect_false(identical(seeds[[1L]], seeds[[2L]]))
    expect_identical(
      seeds[[1L]], .synopsis_seed_test(
        fixture, authorized[[1L]], authorities[[1L]]))

    for (peer in setdiff(fixture$peers, authorities)) {
      empty <- new.env(parent = emptyenv())
      expect_error(
        .synopsis_authorize_test(fixture, peer, ss = empty),
        "not a synopsis noise authority")
      expect_null(empty$.dp_synopsis_authorization)
    }
  }
})

test_that("synopsis authorization is idempotent and conflict preserving", {
  fixture <- .synopsis_authorization_fixture(3L)
  pins <- fixture$input$fixture$pins
  authority_pk <- fixture$artifact$semantic$noise_authority_roles$
    authority_ids[[1L]]
  authority <- names(pins)[match(authority_pk, unname(pins))]
  first <- .synopsis_authorize_test(fixture, authority)
  before <- first$value

  replay <- .synopsis_authorize_test(
    fixture, authority, ss = first$state)
  expect_identical(replay$value, before)

  resigned <- lapply(
    fixture$receipts,
    .synopsis_authorization_helpers$.synopsis_receipt_resign,
    signer = fixture$input$alternate_signer)
  expect_identical(
    .synopsis_authorize_test(
      fixture, authority, ss = first$state,
      receipts = resigned)$value,
    before)

  resigned_claim_set <- fixture$input$claim_set
  resigned_claim_set$claims <- lapply(
    resigned_claim_set$claims, function(claim) {
      unsigned <- claim[setdiff(names(claim), "signature")]
      c(unsigned, list(signature = fixture$input$alternate_signer(
        .dsvert_dp_synopsis_source_vector_claim_message_v1(unsigned),
        unsigned$source_identity_pk)))
    })
  expect_identical(.synopsis_authorize_test(
    fixture, authority, ss = first$state,
    claim_set = resigned_claim_set)$value, before)

  alternate_planner <- .synopsis_authorization_helpers$
    .synopsis_receipt_helpers$.synopsis_artifact_planner(
      operational = "b", threat_model = "alternate planner prose",
      threshold_scalar = TRUE)
  alternate <- .synopsis_authorization_fixture(3L, alternate_planner)
  expect_identical(
    alternate$artifact$artifact_key, fixture$artifact$artifact_key)
  expect_false(identical(
    alternate$artifact$physical_plan$full_plan_sha256,
    fixture$artifact$physical_plan$full_plan_sha256))
  expect_error(.synopsis_authorize_test(
    fixture, authority, ss = first$state,
    artifact = alternate$artifact, receipts = alternate$receipts),
    "Conflicting synopsis session authorization")
  expect_identical(first$state$.dp_synopsis_authorization, before)

  tampered <- first$state$.dp_synopsis_authorization
  first$state$.dp_synopsis_authorization$artifact_key <- strrep("f", 64L)
  expect_error(.dsvert_dp_synopsis_session_authorization_validate_v1(
    first$state, before$session_id,
    .policy = fixture$input$policies[[authority]],
    .secret = fixture$input$secrets[[authority]],
    .identity = list(identity_pk = authority_pk),
    .cache_get = fixture$input$cache_get), "Invalid synopsis")
  first$state$.dp_synopsis_authorization <- tampered

  forged <- tampered
  forged$receipt_set_sha256 <- strrep("0", 64L)
  forged$authorization_sha256 <-
    .dsvert_dp_synopsis_authorization_hash_v1(
      forged, as.raw(rep(0L, 32L)))
  first$state$.dp_synopsis_authorization <- forged
  expect_error(.dsvert_dp_synopsis_session_authorization_validate_v1(
    first$state, before$session_id,
    .policy = fixture$input$policies[[authority]],
    .secret = fixture$input$secrets[[authority]],
    .identity = list(identity_pk = authority_pk),
    .cache_get = fixture$input$cache_get), "Invalid synopsis")
  first$state$.dp_synopsis_authorization <- tampered
})

test_that("synopsis authorization rejects foreign state before cache access", {
  fixture <- .synopsis_authorization_fixture(2L)
  authority <- fixture$peers[[1L]]
  foreign_fields <- c(
    ".dp_count_authorization", ".dp_frequency_authorization",
    ".exact_gc_peer_binding_digest", ".exact_gc_analysis_binding",
    ".typed_blob_peer_binding_digest", ".future_protocol_state")
  for (field in foreign_fields) {
    ss <- new.env(parent = emptyenv())
    ss[[field]] <- list(version = paste0("foreign-", field))
    events <- character()
    expect_error(.synopsis_authorize_test(
      fixture, authority, ss = ss,
      cache_get = function(...) {
        events <<- c(events, "cache")
        stop("cache reached")
      }), "existing session state")
    expect_identical(events, character())
    expect_null(ss$.dp_synopsis_authorization)
    expect_identical(ss[[field]], list(version = paste0("foreign-", field)))
  }
})

test_that("synopsis authorization leaves no state after invalid evidence", {
  fixture <- .synopsis_authorization_fixture(3L)
  peer <- fixture$peers[[1L]]
  missing <- new.env(parent = emptyenv())
  expect_error(.synopsis_authorize_test(
    fixture, peer, ss = missing,
    receipts = fixture$receipts[-1L]), "exactly one receipt")
  expect_null(missing$.dp_synopsis_authorization)

  preexisting_null <- new.env(parent = emptyenv())
  preexisting_null$.dp_synopsis_authorization <- NULL
  expect_error(.synopsis_authorize_test(
    fixture, peer, ss = preexisting_null), "Invalid synopsis")
  expect_true(exists(
    ".dp_synopsis_authorization", envir = preexisting_null,
    inherits = FALSE))
  expect_null(preexisting_null$.dp_synopsis_authorization)

  cache_miss <- new.env(parent = emptyenv())
  events <- character()
  expect_error(.synopsis_authorize_test(
    fixture, peer, ss = cache_miss,
    cache_get = function(...) {
      events <<- c(events, "cache")
      NULL
    }), "not emitted|authorized")
  expect_identical(events, "cache")
  expect_null(cache_miss$.dp_synopsis_authorization)

  post_install <- new.env(parent = emptyenv())
  cache_calls <- 0L
  expect_error(.synopsis_authorize_test(
    fixture, peer, ss = post_install,
    cache_get = function(...) {
      cache_calls <<- cache_calls + 1L
      if (cache_calls == 1L) fixture$input$cache_get(...) else NULL
    }), "not emitted|authorized")
  expect_identical(cache_calls, 2L)
  expect_false(exists(
    ".dp_synopsis_authorization", envir = post_install, inherits = FALSE))
})

test_that("synopsis sticky seed excludes sessions, signatures and full plans", {
  fixture <- .synopsis_authorization_fixture(2L)
  peer <- fixture$peers[[1L]]
  first <- .synopsis_authorize_test(fixture, peer)
  seed <- .synopsis_seed_test(fixture, first, peer)

  second_session <- "00000000-0000-4000-8000-000000000002"
  second <- .synopsis_authorize_test(
    fixture, peer, session_id = second_session)
  expect_false(identical(
    first$value$authorization_sha256,
    second$value$authorization_sha256))
  expect_identical(
    seed, .synopsis_seed_test(
      fixture, second, peer, session_id = second_session))

  alternate_planner <- .synopsis_authorization_helpers$
    .synopsis_receipt_helpers$.synopsis_artifact_planner(
      operational = "b", threat_model = "alternate planner prose",
      threshold_scalar = TRUE)
  alternate <- .synopsis_authorization_fixture(2L, alternate_planner)
  alternate_authorized <- .synopsis_authorize_test(alternate, peer)
  expect_identical(
    alternate$artifact$artifact_key, fixture$artifact$artifact_key)
  expect_false(identical(
    alternate_authorized$value$receipt_set_sha256,
    first$value$receipt_set_sha256))
  expect_identical(
    seed,
    .synopsis_seed_test(alternate, alternate_authorized, peer))

  changed <- .synopsis_authorization_fixture(
    2L, .synopsis_authorization_helpers$.synopsis_receipt_helpers$
      .synopsis_artifact_planner(draw = "101"))
  changed_authorized <- .synopsis_authorize_test(changed, peer)
  expect_false(identical(
    changed$artifact$artifact_key, fixture$artifact$artifact_key))
  expect_false(identical(
    seed, .synopsis_seed_test(changed, changed_authorized, peer)))
  expect_error(
    .synopsis_seed_test(fixture, first, peer, lane = "undeclared"),
    "not declared")
})
