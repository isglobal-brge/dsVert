.synopsis_exact_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-result.R"))) {
    if (is.call(expression) && identical(
        as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})
.synopsis_exact_required <- c(".dsvert_dp_synopsis_execution_exact_gc_roles_v1",
  ".dsvert_dp_synopsis_execution_exact_gc_operation_v1")
.synopsis_exact_require <- function() {
  present <- vapply(.synopsis_exact_required, exists, logical(1L), mode = "function", inherits = TRUE)
  skip_if_not(all(present), paste("RED: missing", paste(
    .synopsis_exact_required[!present], collapse = ", ")))
}
.synopsis_exact_fixture <- function(k = 2L, planner = NULL) {
  .synopsis_exact_helpers$.synopsis_result_helpers$.synopsis_start_helpers$.synopsis_execution_helpers$
    .synopsis_authorization_fixture(k, planner)
}
.synopsis_exact_setup <- function(fixture) .synopsis_exact_helpers$
  .synopsis_result_helpers$.synopsis_start_setup(fixture)
.synopsis_exact_context <- function(fixture, setup, peer)
  .synopsis_exact_helpers$.synopsis_result_helpers$.synopsis_start_context(fixture, setup, peer)
.synopsis_exact_cleanup <- function(fixture, envir = parent.frame())
  .synopsis_exact_helpers$.synopsis_result_helpers$.synopsis_start_cleanup(fixture, envir)
.synopsis_exact_session <- function(fixture, setup, peer) {
  value <- new.env(parent = emptyenv())
  value$session_id <- setup$session_id
  others <- setdiff(setup$authorities, peer)
  value$peer_transport_pks <- stats::setNames(
    as.list(paste0("transport-", others)), others)
  designated <- sort(setup$authorities, method = "radix")
  value$.exact_gc_self_name <- peer
  value$.exact_gc_designated_peers <- designated
  value$.exact_gc_full_peer_pinset_sha256 <-
    fixture$input$policies[[peer]]$peer_pinset_sha256
  value$.exact_gc_peer_binding_contract <- list(
    version = "dsvert-exact-gc-designated-binding-v2",
    session_id = setup$session_id,
    full_peer_pinset_sha256 = value$.exact_gc_full_peer_pinset_sha256,
    designated_peers = as.list(designated))
  value$.exact_gc_peer_binding_digest <- .exact_gc_peer_binding_contract_digest(
    value$.exact_gc_peer_binding_contract)
  value
}
.synopsis_exact_validate_binding <- function(ss, session_id) {
  expect_identical(ss$session_id, session_id); expect_length(ss$peer_transport_pks, 1L)
  ss$.exact_gc_peer_binding_digest
}
.synopsis_exact_compiler <- function(context, observe = NULL) {
  function(input) {
    if (is.function(observe)) observe(input)
    forbidden <- c("source_share", "private_seed", "seed", "share")
    recursive_names <- function(value) if (!is.list(value)) character() else
      c(names(value), unlist(lapply(value, recursive_names), use.names = FALSE))
    expect_length(intersect(recursive_names(input), forbidden), 0L)
    circuit <- digest::digest(
      .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(input)),
      algo = "sha256", serialize = FALSE)
    list(
      version = "dsvert-joint-dp-vector-worker-contract-v3",
      capability_id = "joint_dp_biomedical_vector_exact_gc_v1",
      operation = "joint-dp-vector-laplace-v3",
      purpose = paste0("joint-dp-vector-laplace-v3/", circuit),
      circuit_digest = circuit,
      input_contract = "public-data-free-biomedical-vector-chunk-v1",
      protected_inputs_accepted = FALSE,
      private_seed_accepted = FALSE,
      worker_policy = list(circuit_digest = circuit,
        coordinate_count = input$coordinate_count,
        chunk_start = input$chunk_start,
        total_coordinate_count = input$total_coordinate_count,
        transcript_hash = input$transcript_hash),
      plan = context$vector$plan,
      capability_available = TRUE)
  }
}
.synopsis_exact_started <- function(binding) list(
  version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_START_VERSION,
  backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND,
  binding_sha256 = binding$binding_sha256,
  operation_id = binding$operation_id, purpose = binding$purpose,
  initialization = list(state = "running", stored = FALSE),
  intermediate_payload_exposed = FALSE, source_share_exposed = FALSE,
  private_seed_exposed = FALSE, preclamp_values_exposed = FALSE)
.synopsis_exact_operation <- function(
    fixture, setup, peer, context, session, compiler,
    prepares = setup$prepared) {
  .dsvert_dp_synopsis_execution_exact_gc_operation_v1(
    session, setup$session_id, context, prepares,
    .dsvert_dp_synopsis_execution_chunk_v1(context, 0L),
    fixture$input$policies[[peer]], fixture$input$secrets[[peer]],
    list(
      identity_pk = unname(fixture$input$fixture$pins[[peer]]),
      identity_sk = unname(fixture$input$fixture$pins[[peer]])),
    compiler)
}
.synopsis_exact_start <- function(
    fixture, setup, peer, session, compiler, starter, signer = NULL,
    source_reader = NULL, binding_validator = .synopsis_exact_validate_binding,
    identity_seed = NULL) {
  if (is.null(signer)) signer <- fixture$input$signer; if (is.null(identity_seed)) identity_seed <- function()
    gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(61L, 32L))))
  if (is.null(source_reader)) source_reader <- function(
      policy, manifest_json, offset, count, secret, source_contract) {
    raw(count * 16L)
  }
  forbidden <- function(...) stop("convolution dependency reached",
                                  call. = FALSE)
  testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_start_v1(
      setup$authorized[[peer]]$state, setup$session_id,
      setup$encoded[[2L]], setup$encoded[[1L]], 0L,
      .policy = fixture$input$policies[[peer]],
      .secret = fixture$input$secrets[[peer]],
      .identity = list(
        identity_pk = unname(fixture$input$fixture$pins[[peer]]),
        identity_sk = unname(fixture$input$fixture$pins[[peer]])),
      .cache_get = fixture$input$cache_get,
      .verifier = fixture$input$verifier, .signer = signer,
      .source_reader = source_reader, .sampler = forbidden,
      .exact_compiler = compiler, .exact_start = starter,
      .session = session),
    .get_identity_seed = identity_seed,
    .exact_gc_validate_bound_peer_context = binding_validator,
    .dsvert_joint_dp_vector_exact_gc_role_bindings = forbidden,
    .get_trusted_peers = forbidden, .package = "dsVert")
}
.synopsis_exact_result <- function(
    fixture, setup, peer, session, compiler, consumer,
    signer = fixture$input$signer,
    binding_validator = .synopsis_exact_validate_binding) {
  testthat::with_mocked_bindings(.dsvert_dp_synopsis_execution_result_v1(
    setup$authorized[[peer]]$state, setup$session_id,
    setup$encoded[[2L]], setup$encoded[[1L]],
    .policy = fixture$input$policies[[peer]],
    .secret = fixture$input$secrets[[peer]],
    .identity = list(
      identity_pk = unname(fixture$input$fixture$pins[[peer]]),
      identity_sk = unname(fixture$input$fixture$pins[[peer]])),
    .cache_get = fixture$input$cache_get,
    .verifier = fixture$input$verifier, .signer = signer,
    .exact_compiler = compiler, .exact_consume = consumer,
    .session = session),
    .exact_gc_validate_bound_peer_context = binding_validator,
    .package = "dsVert")
}
test_that("synopsis exact-GC adds only dedicated internal adapters", {
  present <- vapply(.synopsis_exact_required, exists, logical(1L),
    mode = "function", inherits = TRUE)
  expect_true(all(present), info = paste(
    "missing", paste(.synopsis_exact_required[!present], collapse = ", ")))
  if (all(present)) {
    expect_identical(names(formals(
      .dsvert_dp_synopsis_execution_exact_gc_roles_v1)),
      c("context", "prepares"))
    expect_identical(names(formals(
      .dsvert_dp_synopsis_execution_exact_gc_operation_v1)), c(
        "ss", "session_id", "context", "prepares", "chunk",
        ".policy", ".secret", ".identity", ".exact_compiler"))
  }
  expect_identical(names(formals(
    .dsvert_dp_synopsis_execution_start_v1)), c(
      "ss", "session_id", "first_prepare", "second_prepare",
      "chunk_index", ".policy", ".secret", ".identity", ".cache_get",
      ".verifier", ".signer", ".source_reader", ".sampler",
      ".exact_compiler", ".exact_start", ".session"))
  expect_identical(names(formals(
    .dsvert_dp_synopsis_execution_result_v1)), c(
      "ss", "session_id", "first_prepare", "second_prepare",
      ".policy", ".secret", ".identity", ".cache_get", ".verifier",
      ".signer", ".exact_compiler", ".exact_consume", ".session"))
})
test_that("synopsis execution migrates authenticated v2 stores to v3", {
  fixture <- .synopsis_exact_fixture(2L)
  .synopsis_exact_cleanup(fixture)
  peer <- fixture$peers[[1L]]
  policy <- fixture$input$policies[[peer]]
  secret <- fixture$input$secrets[[peer]]
  path <- .dsvert_dp_synopsis_execution_store_path_v1(policy)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  for (statement in
       .dsvert_dp_synopsis_execution_schema_statements_v1(FALSE)) {
    DBI::dbExecute(connection, statement)
  }
  binding <- .dsvert_dp_synopsis_execution_store_binding_v1(
    policy, "dsvert-stateless-catalog-synopsis-execution-store-v2")
  mac <- .dsvert_dp_synopsis_execution_store_mac_v1(
    secret, "meta", "policy_binding", binding)
  DBI::dbExecute(connection, paste(
    "INSERT INTO synopsis_meta(key,value,row_mac)",
    "VALUES('policy_binding',?,?)"), params = list(binding, mac))
  artifact_key <- digest::digest(
    "migration-artifact", algo = "sha256", serialize = FALSE)
  original <- .dsvert_dp_synopsis_execution_start_claim_v1(
    connection, artifact_key,
    digest::digest("migration-contract", algo = "sha256",
                   serialize = FALSE),
    digest::digest("migration-attempt", algo = "sha256",
                   serialize = FALSE),
    1L, 1L, secret)
  DBI::dbDisconnect(connection)
  migrated <- .dsvert_dp_synopsis_execution_with_store_v1(
    policy, secret, function(connection) list(
      claim = .dsvert_dp_synopsis_execution_artifact_load_v1(
        connection, secret, artifact_key),
      exact_tables = DBI::dbGetQuery(connection, paste(
        "SELECT COUNT(*) n FROM sqlite_master",
        "WHERE type='table' AND name='synopsis_exact_starts'"))$n[[1L]]))
  expect_identical(migrated$claim, original)
  expect_identical(migrated$exact_tables, 1L)
  .synopsis_exact_cleanup(fixture)
})
test_that("pinned exact-GC roles and operation are authority-only for K=2/3/5", {
  .synopsis_exact_require()
  forbidden <- function(...) stop("legacy exact role helper reached",
                                  call. = FALSE)
  for (k in c(2L, 3L, 5L)) {
    fixture <- .synopsis_exact_fixture(k)
    .synopsis_exact_cleanup(fixture)
    setup <- .synopsis_exact_setup(fixture)
    peer <- setup$authorities[[1L]]
    context <- .synopsis_exact_context(fixture, setup, peer)
    expect_true(context$vector$profile$exact_gc)
    ids <- vapply(setup$authorities, function(name)
      .dsvert_relay_peer_id(unname(fixture$input$fixture$pins[[name]])),
      character(1L))
    expected <- names(sort(ids, method = "radix"))
    roles <- testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_execution_exact_gc_roles_v1(
        context, rev(setup$prepared)),
      .dsvert_joint_dp_vector_exact_gc_role_bindings = forbidden,
      .get_trusted_peers = forbidden, .package = "dsVert")
    expect_identical(roles$garbler_peer_name, expected[[1L]])
    expect_identical(roles$evaluator_peer_name, expected[[2L]])
    expect_setequal(c(roles$garbler_peer_name,
                      roles$evaluator_peer_name), setup$authorities)
    expect_false(any(setdiff(fixture$peers, setup$authorities) %in%
                     unlist(roles, use.names = FALSE)))
    expect_false(roles$analyst_selected_roles)
    session <- .synopsis_exact_session(fixture, setup, peer)
    events <- character()
    validator <- function(ss, session_id) {
      events <<- c(events, "binding")
      .synopsis_exact_validate_binding(ss, session_id)
    }
    compiler <- .synopsis_exact_compiler(context, function(input) {
      events <<- c(events, "compile")
      expect_identical(input$transcript_hash, context$attempt$sha256)
    })
    operation <- testthat::with_mocked_bindings(
      .synopsis_exact_operation(
        fixture, setup, peer, context, session, compiler,
        rev(setup$prepared)),
      .exact_gc_validate_bound_peer_context = validator,
      .dsvert_joint_dp_vector_exact_gc_role_bindings = forbidden,
      .get_trusted_peers = forbidden, .package = "dsVert")
    retry <- testthat::with_mocked_bindings(
      .synopsis_exact_operation(
        fixture, setup, peer, context, session, compiler),
      .exact_gc_validate_bound_peer_context = validator,
      .dsvert_joint_dp_vector_exact_gc_role_bindings = forbidden,
      .get_trusted_peers = forbidden, .package = "dsVert")
    expect_identical(operation, retry)
    expect_named(operation, c("selection", "roles", "worker", "binding"),
                 ignore.order = FALSE)
    expect_identical(operation$roles, roles)
    expect_identical(operation$selection$backend,
                     .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND)
    expect_identical(operation$binding$operation_id,
                     retry$binding$operation_id)
    expect_identical(operation$binding$release_contract_hash,
                     context$contract$sha256)
    expect_identical(operation$binding$transcript_hash,
                     context$attempt$sha256)
    expect_identical(events,
                     c("binding", "compile", "binding", "compile"))
    expect_false(any(c("source_share", "private_seed") %in%
                     names(operation$worker)))
    witness <- setdiff(fixture$peers, setup$authorities)
    if (length(witness)) {
      witness <- witness[[1L]]
      expect_error(
        .dsvert_dp_synopsis_execution_exact_gc_operation_v1(
          session, setup$session_id, context, setup$prepared,
          .dsvert_dp_synopsis_execution_chunk_v1(context, 0L),
          fixture$input$policies[[witness]],
          fixture$input$secrets[[witness]],
          list(identity_pk = unname(
            fixture$input$fixture$pins[[witness]])), forbidden),
        "designated|authority|identity|authorization|context")
    }
  }
})
test_that("productive exact-GC worker preserves its signed plan shape", {
  skip_if_not(file.exists(.findMpcBinary()),
              "packaged dsvert-mpc binary is unavailable")
  planner <- list(
    `joint-dp-vector-laplace-plan-v3` = function(input) {
      .callMpcTool("joint-dp-vector-laplace-plan-v3", input)
    },
    `joint-dp-vector-convolution-plan-v3` = function(input) {
      .callMpcTool("joint-dp-vector-convolution-plan-v3", input)
    })
  fixture <- .synopsis_exact_fixture(2L, planner)
  .synopsis_exact_cleanup(fixture)
  setup <- .synopsis_exact_setup(fixture)
  peer <- setup$authorities[[1L]]
  context <- .synopsis_exact_context(fixture, setup, peer)
  session <- .synopsis_exact_session(fixture, setup, peer)
  operation <- testthat::with_mocked_bindings(
    .synopsis_exact_operation(
      fixture, setup, peer, context, session,
      function(input) .callMpcTool(
        "joint-dp-vector-worker-contract-v3", input)),
    .exact_gc_validate_bound_peer_context =
      .synopsis_exact_validate_binding, .package = "dsVert")
  expect_identical(operation$worker$plan, context$vector$plan)
  expect_identical(.dsvert_joint_dp_hash(operation$worker$plan),
                   context$vector$plan_sha256)
})
test_that("exact-GC START initializes after CAS and never writes LOCAL", {
  .synopsis_exact_require()
  fixture <- .synopsis_exact_fixture(3L)
  .synopsis_exact_cleanup(fixture)
  setup <- .synopsis_exact_setup(fixture)
  peer <- setup$authorities[[1L]]
  context <- .synopsis_exact_context(fixture, setup, peer)
  session <- .synopsis_exact_session(fixture, setup, peer)
  events <- character()
  observed <- new.env(parent = emptyenv())
  compiler <- .synopsis_exact_compiler(context, function(input) {
    events <<- c(events, "compile")
  })
  source <- function(policy, manifest_json, offset, count, secret,
                     source_contract) { events <<- c(events, "source"); raw(16L) }
  starter <- function(ss, session_id, binding, selection, manifest_sha256,
      release_contract_hash, transcript_hash, chunk_index,
      worker_contract, source_share, private_seed) {
    events <<- c(events, "start")
    observed$binding <- binding
    observed$selection <- selection
    observed$worker <- worker_contract
    .synopsis_exact_started(binding)
  }
  validator <- function(ss, session_id) { events <<- c(events, "binding")
    .synopsis_exact_validate_binding(ss, session_id) }
  claim <- .dsvert_dp_synopsis_execution_start_claim_v1
  .dsvert_dp_synopsis_execution_with_store_v1(
    fixture$input$policies[[peer]], fixture$input$secrets[[peer]],
    function(connection) invisible(TRUE))
  compiled <- FALSE
  expect_error(testthat::with_mocked_bindings(
    .synopsis_exact_start(
      fixture, setup, peer, session, function(...) {
        compiled <<- TRUE
        stop("compiler reached", call. = FALSE)
      }, function(...) stop("starter reached", call. = FALSE)),
    .dsvert_dp_synopsis_execution_artifact_load_v1 = function(...) list(
      sticky_core_sha256 = strrep("0", 64L),
      run_binding_sha256 = context$attempt$sha256,
      execution_chunk_count =
        context$attempt$value$execution_geometry$chunk_count,
      public_chunk_count =
        context$contract$value$geometry$public_chunk_count),
    .package = "dsVert"), "conflicting durable claim")
  expect_false(compiled)
  expect_error(.synopsis_exact_start(
    fixture, setup, peer, session, compiler,
    function(ss, session_id, binding, ...) {
      value <- .synopsis_exact_started(binding)
      value$initialization <- list(
        state = "failed", stored = FALSE, retryable = FALSE)
      value
    }, NULL, source, validator), "initialization")
  events <- character()
  receipt <- testthat::with_mocked_bindings(
    .synopsis_exact_start(
      fixture, setup, peer, session, compiler, starter, NULL, source,
      validator),
    .dsvert_dp_synopsis_execution_start_claim_v1 = function(...) {
      events <<- c(events, "cas")
      claim(...)
    }, .package = "dsVert")
  expect_identical(events,
                   c("binding", "compile", "cas", "source", "start"))
  expect_named(receipt, c(
    "version", "phase", "execution_id", "artifact_key",
    "contract_sha256", "attempt_sha256", "source_contract_sha256",
    "local_authority", "chunk_index", "coordinate_offset",
    "coordinate_count", "backend_selection_sha256",
    "worker_contract_sha256", "binding_sha256", "operation_id",
    "purpose", "local_chunk_durable", "intermediate_payload_exposed",
    "source_share_exposed", "private_seed_exposed",
    "preclamp_values_exposed", "signature"), ignore.order = FALSE)
  expect_identical(receipt$version,
    "dsvert-stateless-catalog-synopsis-exact-gc-start-v1")
  expect_identical(receipt$phase, "synopsis_exact_gc_initialized")
  expect_identical(receipt$backend_selection_sha256,
                   observed$selection$selection_sha256)
  expect_identical(receipt$worker_contract_sha256,
                   .dsvert_joint_dp_hash(observed$worker))
  expect_identical(receipt$binding_sha256,
                   observed$binding$binding_sha256)
  expect_false(receipt$local_chunk_durable)
  expect_true(all(!unlist(receipt[c(
    "intermediate_payload_exposed", "source_share_exposed",
    "private_seed_exposed", "preclamp_values_exposed")],
    use.names = FALSE)))
  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    fixture$input$policies[[peer]])
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  expect_identical(DBI::dbGetQuery(connection,
    "SELECT COUNT(*) n FROM synopsis_artifacts")$n[[1L]], 1L)
  expect_identical(DBI::dbGetQuery(connection,
    "SELECT COUNT(*) n FROM synopsis_chunks")$n[[1L]], 0L)
  DBI::dbDisconnect(connection)
  live <- new.env(parent = emptyenv())
  live$session_id <- setup$session_id
  live$operation_id <- observed$binding$operation_id
  live$peer_binding_digest <- session$.exact_gc_peer_binding_digest
  live$operation <- observed$binding$operation
  live$purpose <- observed$binding$purpose
  live$source_key <- observed$binding$source_key
  live$output_key <- observed$binding$output_key
  live$output_kind <- observed$binding$output_kind
  live$source_producer <- observed$binding$source_producer
  live$ring_bits <- 128
  live$frac_bits <- 0
  live$vector_len <- 1
  live$status <- "running"
  live$retryable <- FALSE
  ops <- .exact_gc_ops(session)
  ops[[observed$binding$operation_id]] <- live
  forbidden <- function(...) stop("exact START replay touched private state",
                                  call. = FALSE)
  replay <- .synopsis_exact_start(
    fixture, setup, peer, session, compiler, forbidden,
    signer = forbidden, source_reader = forbidden,
    identity_seed = forbidden)
  expect_identical(replay, receipt)
  replacement_state <- new.env(parent = emptyenv())
  replacement_state$.dp_synopsis_authorization <-
    setup$authorized[[peer]]$state$.dp_synopsis_authorization
  reinitialized <- 0L
  fresh <- .synopsis_exact_session(fixture, setup, peer)
  rehydrated <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_start_v1(
      replacement_state, setup$session_id,
      setup$encoded[[2L]], setup$encoded[[1L]], 0L,
      .policy = fixture$input$policies[[peer]],
      .secret = fixture$input$secrets[[peer]],
      .identity = list(
        identity_pk = unname(fixture$input$fixture$pins[[peer]]),
        identity_sk = unname(fixture$input$fixture$pins[[peer]])),
      .cache_get = fixture$input$cache_get,
      .verifier = fixture$input$verifier,
      .signer = fixture$input$signer, .source_reader = source,
      .sampler = forbidden, .exact_compiler = compiler,
      .exact_start = function(
          ss, session_id, binding, selection, manifest_sha256,
          release_contract_hash, transcript_hash, chunk_index,
          worker_contract, source_share, private_seed) {
        reinitialized <<- reinitialized + 1L
        .synopsis_exact_started(binding)
      }, .session = NULL),
    .S = function(session_id) fresh,
    .get_identity_seed = function() gsub(
      "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(61L, 32L)))),
    .exact_gc_validate_bound_peer_context =
      .synopsis_exact_validate_binding, .package = "dsVert")
  expect_identical(reinitialized, 1L)
  expect_identical(rehydrated, receipt)
  operation <- testthat::with_mocked_bindings(
    .synopsis_exact_operation(
      fixture, setup, peer, context, fresh, compiler),
    .exact_gc_validate_bound_peer_context =
      .synopsis_exact_validate_binding, .package = "dsVert")
  state <- new.env(parent = emptyenv())
  state$session_id <- setup$session_id
  state$operation_id <- operation$binding$operation_id
  state$peer_binding_digest <- fresh$.exact_gc_peer_binding_digest
  state$operation <- operation$binding$operation
  state$purpose <- operation$binding$purpose
  state$source_key <- operation$binding$source_key
  state$output_key <- operation$binding$output_key
  state$output_kind <- operation$binding$output_kind
  state$source_producer <- operation$binding$source_producer
  state$ring_bits <- 128
  state$frac_bits <- 0
  state$vector_len <- 1
  state$status <- "failed"
  state$retryable <- FALSE
  ops <- .exact_gc_ops(fresh)
  ops[[operation$binding$operation_id]] <- state
  expect_error(.synopsis_exact_start(
    fixture, setup, peer, fresh, compiler, forbidden,
    fixture$input$signer, forbidden), "failed permanently")
})
test_that("exact-GC RESULT commits authenticated LOCAL before consume", {
  .synopsis_exact_require()
  fixture <- .synopsis_exact_fixture(2L)
  .synopsis_exact_cleanup(fixture)
  setup <- .synopsis_exact_setup(fixture)
  peer <- setup$authorities[[1L]]
  context <- .synopsis_exact_context(fixture, setup, peer)
  session <- .synopsis_exact_session(fixture, setup, peer)
  compiler <- .synopsis_exact_compiler(context)
  starter <- function(
      ss, session_id, binding, selection, manifest_sha256,
      release_contract_hash, transcript_hash, chunk_index,
      worker_contract, source_share, private_seed)
    .synopsis_exact_started(binding)
  start_receipt <- .synopsis_exact_start(
    fixture, setup, peer, session, compiler, starter)
  path <- .dsvert_dp_synopsis_execution_store_path_v1(
    fixture$input$policies[[peer]])
  share <- gsub("[\r\n]", "", jsonlite::base64_enc(raw(16L)))
  validity <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(1L)))
  events <- character()
  stored <- operation <- NULL
  consumer <- function(ss, binding, worker_contract, .commit) {
    operation <<- list(binding = binding, worker = worker_contract)
    transport <- function(..., consume) {
      events <<- c(events, if (consume) "consume" else "peek")
      if (consume) {
        connection <- DBI::dbConnect(RSQLite::SQLite(), path)
        row <- DBI::dbGetQuery(connection, paste(
          "SELECT record_json FROM synopsis_chunks",
          "WHERE kind='LOCAL' AND chunk_index=0"))
        DBI::dbDisconnect(connection)
        expect_identical(nrow(row), 1L)
        stored <<- jsonlite::fromJSON(
          row$record_json[[1L]], simplifyVector = FALSE)
      }
      list(share = share, validity_share = validity)
    }
    .dsvert_joint_dp_vector_exact_gc_consume(
      ss, binding, worker_contract, .commit, .consume = transport)
  }
  result <- testthat::with_mocked_bindings(
    .synopsis_exact_result(
      fixture, setup, peer, session, compiler, consumer),
    .dsvert_joint_dp_vector_exact_gc_role_bindings = function(...)
      stop("legacy exact role helper reached", call. = FALSE),
    .get_trusted_peers = function(...)
      stop("trusted-peer discovery reached", call. = FALSE),
    .get_identity_seed = function(...)
      stop("seed reached from RESULT", call. = FALSE),
    .callMpcTool = function(...)
      stop("sampler reached from RESULT", call. = FALSE),
    .package = "dsVert")
  expect_identical(events, c("peek", "consume"))
  expect_false(is.null(stored))
  expect_identical(stored$noised_share_sha256,
    digest::digest(raw(16L), algo = "sha256", serialize = FALSE))
  expect_identical(stored$validity_share_sha256,
    digest::digest(as.raw(1L), algo = "sha256", serialize = FALSE))
  expect_identical(stored$binding_sha256,
                   operation$binding$binding_sha256)
  expect_identical(stored$worker_contract_sha256,
                   .dsvert_joint_dp_hash(operation$worker))
  expect_identical(stored$operation_id, operation$binding$operation_id)
  expect_identical(stored$purpose, operation$binding$purpose)
  expect_identical(stored$receipt$local_chunk_sha256,
    unlist(result$local_chunk_commitments, use.names = FALSE)[[1L]])
  expect_false(identical(stored$receipt$local_chunk_sha256,
                         stored$noised_share_sha256))
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  reloaded <- .dsvert_dp_synopsis_execution_local_load_v1(
    connection, fixture$input$secrets[[peer]], context, NULL,
    .dsvert_dp_synopsis_execution_chunk_v1(context, 0L),
    fixture$input$policies[[peer]], fixture$input$verifier)
  DBI::dbDisconnect(connection)
  expect_identical(reloaded$receipt$local_chunk_sha256,
                   stored$receipt$local_chunk_sha256)
  expect_true(result$all_chunks_durable)
  forbidden <- function(...) stop("durable LOCAL replay touched private state",
                                  call. = FALSE)
  replay <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_start_v1(
      setup$authorized[[peer]]$state, setup$session_id,
      setup$encoded[[2L]], setup$encoded[[1L]], 0L,
      .policy = fixture$input$policies[[peer]],
      .secret = fixture$input$secrets[[peer]],
      .identity = list(
        identity_pk = unname(fixture$input$fixture$pins[[peer]])),
      .cache_get = fixture$input$cache_get,
      .verifier = fixture$input$verifier, .signer = forbidden,
      .source_reader = forbidden, .sampler = forbidden,
      .exact_compiler = forbidden, .exact_start = forbidden,
      .session = NULL),
    .S = forbidden, .get_identity_seed = forbidden,
    .package = "dsVert")
  expect_identical(replay, start_receipt)
})
