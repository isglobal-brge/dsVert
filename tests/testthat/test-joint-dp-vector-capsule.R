.vector_capsule_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  expressions <- parse(testthat::test_path(
    "test-dp-capsule-source-transport.R"))
  for (expression in expressions) {
    if (is.call(expression) &&
        identical(as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.vector_capsule_binary <- local({
  binary <- NULL
  function() {
    if (!is.null(binary) && file.exists(binary)) return(binary)
    source_candidates <- file.path(
      .dsvert_test_source_roots(), "inst", "dsvert-mpc")
    source_candidates <- source_candidates[
      file.exists(file.path(source_candidates, "main.go"))]
    if (!length(source_candidates)) {
      binary <<- .findMpcBinary()
      return(binary)
    }
    go <- Sys.which("go")
    testthat::skip_if(!nzchar(go), "Go is required for vector integration")
    source <- source_candidates[[1L]]
    binary <<- tempfile("dsvert-mpc-vector-test-")
    output <- withr::with_dir(source, system2(
      go, c("build", "-o", binary, "."), stdout = TRUE, stderr = TRUE))
    status <- attr(output, "status")
    testthat::skip_if(!is.null(status) && status != 0L,
                      paste(output, collapse = "\n"))
    Sys.chmod(binary, mode = "0700")
    binary
  }
})

.vector_capsule_run <- function(command, value) {
  input <- tempfile("vector-input-")
  output <- tempfile("vector-output-")
  error <- tempfile("vector-error-")
  on.exit(unlink(c(input, output, error), force = TRUE), add = TRUE)
  writeLines(.dsvert_mpc_encode_json(value), input, useBytes = TRUE)
  status <- system2(
    .vector_capsule_binary(), command, stdin = input,
    stdout = output, stderr = error)
  if (status != 0L) {
    stop(paste(readLines(c(output, error), warn = FALSE), collapse = "\n"),
         call. = FALSE)
  }
  jsonlite::read_json(output, simplifyVector = TRUE)
}

.vector_capsule_fixture <- function(
    gaussian = FALSE, k = 2L, count_only = FALSE) {
  selector <- if (isTRUE(gaussian)) function(
      coordinate_count, laplace_epsilons, laplace_sensitivities,
      gaussian_epsilon, gaussian_delta, gaussian_l2_sensitivity,
      objective) {
    list(
      selector = .DSVERT_DP_NOISE_SELECTOR,
      objective = objective, coordinate_count = as.integer(coordinate_count),
      winner = "laplace",
      laplace = list(
        available = TRUE,
        simultaneous_95_abs = .dsvert_dp_exact_integer_limit),
      gaussian = list(available = FALSE, simultaneous_95_abs = 0))
  } else .vector_capsule_helpers$.capsule_source_test_selector
  gaussian_planner <- if (isTRUE(gaussian)) {
    function(value) .vector_capsule_run(
      "joint-dp-vector-gaussian-plan-v2", value)
  } else {
    function(...) stop("test exact-Gaussian backend unavailable", call. = FALSE)
  }
  fixture <- .vector_capsule_helpers$.capsule_source_test_fixture(
    k, noise_selector = selector, gaussian_planner = gaussian_planner,
    count_only = count_only)
  for (peer in fixture$peers) {
    key <- fixture$secrets[[peer]]
    fixture$policies[[peer]]$lifetime_max_distinct_capsules <- 8
    fixture$policies[[peer]]$noise_root <- list(
      protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
      provider_id = "joint_dp_vector_test_provider", epoch = 1,
      key_id = paste0("test_", substr(digest::digest(
        key, "sha256", serialize = FALSE), 1L, 32L)),
      hmac = local({
        private_key <- key
        function(message) digest::hmac(
          key = private_key, object = message,
          algo = "sha256", serialize = FALSE)
      }))
  }
  fixture$release_domains <- stats::setNames(lapply(
    seq_along(fixture$peers), function(index) {
      peer <- fixture$peers[[index]]
      .dsvert_joint_dp_release_domain_current(
        fixture$policies[[peer]], fixture$secrets[[peer]],
        random_bytes = function(size) {
          as.raw(rep(index %% 256L, size))
        })
    }), fixture$peers)
  designated <- sort(fixture$peers[1:2], method = "radix")
  release_instance <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_VECTOR_RELEASE_INSTANCE_VERSION,
    capsule_id = fixture$manifests[[1L]]$capsule_identity$capsule_id,
    peer_noise_roots = stats::setNames(lapply(designated, function(peer) {
      list(
        privacy_epoch = as.numeric(
          fixture$policies[[peer]]$noise_root$epoch),
        noise_key_id = fixture$policies[[peer]]$noise_root$key_id,
        provider_id = fixture$policies[[peer]]$noise_root$provider_id,
        release_domain_generation = as.numeric(
          fixture$release_domains[[peer]]$generation),
        release_domain_id =
          fixture$release_domains[[peer]]$domain_id)
    }), designated)))
  fixture$release_instance <- release_instance
  fixture$release_instance_json <- .dsvert_dp_canonical_json(
    release_instance)
  split <- .dsvert_dp_capsule_source_split_ring128(
    fixture$expected,
    function(n) as.raw(rep(0:255, length.out = n)))
  fixture$source_shares <- list(peer_a = split$left, peer_b = split$right)
  fixture$planner <- if (isTRUE(gaussian)) gaussian_planner else list(
    `joint-dp-vector-laplace-plan-v3` = function(value) {
      .vector_capsule_run("joint-dp-vector-laplace-plan-v3", value)
    },
    `joint-dp-vector-convolution-plan-v3` = function(value) {
      .vector_capsule_run("joint-dp-vector-convolution-plan-v3", value)
    })
  fixture$sampler <- if (isTRUE(gaussian)) {
    function(value) .vector_capsule_run(
      "joint-dp-vector-gaussian-share-v2", value)
  } else {
    function(value) .vector_capsule_run(
      "joint-dp-vector-convolution-share-v3", value)
  }
  fixture$finalizer <- if (isTRUE(gaussian)) {
    function(value) .vector_capsule_run(
      "joint-dp-vector-gaussian-finalize-v2", value)
  } else {
    function(value) .vector_capsule_run(
      "joint-dp-vector-convolution-finalize-v3", value)
  }
  fixture$signer <- .vector_capsule_helpers$.capsule_source_test_signer
  fixture$verifier <- function(message, pin, signature, ...) {
    .vector_capsule_helpers$.capsule_source_test_verifier(
      message, pin, signature)
  }
  fixture
}

.vector_capsule_public_names <- function(value) {
  if (!is.list(value)) return(character())
  c(names(value), unlist(lapply(
    value, .vector_capsule_public_names), use.names = FALSE))
}

.vector_capsule_allocation_local <- function(
    policy, manifest_json, secret = NULL, verifier = NULL) {
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  list(
    version = .DSVERT_JOINT_DP_VECTOR_ALLOCATION_VERSION,
    capsule_id = manifest$capsule_identity$capsule_id,
    allocation_index = "0", registry_sequence = "0",
    authorized = TRUE)
}

.vector_capsule_allocation_observer <- function(
    policy, manifest_json, first_opening_json, second_opening_json,
    secret = NULL, verifier = NULL) {
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  list(
    version = .DSVERT_JOINT_DP_VECTOR_ALLOCATION_VERSION,
    capsule_id = manifest$capsule_identity$capsule_id,
    allocation_index = "0", opening_set_hash = strrep("9", 64L),
    authorized = TRUE)
}

test_that("RESULT phase misses require an intact prepared capsule and no session", {
  fixture <- .vector_capsule_fixture(count_only = TRUE)
  gate <- function(...) invisible(TRUE)
  prepares <- testthat::with_mocked_bindings(
    lapply(fixture$peers[1:2], function(peer) {
      .dsvert_joint_dp_vector_prepare_impl(
        fixture$manifest_json, fixture$release_instance_json,
        .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = fixture$signer, .planner = fixture$planner)
    }),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .dsvert_joint_dp_vector_allocation_require =
      .vector_capsule_allocation_local,
    .dsvert_joint_dp_vector_allocation_observer_require =
      .vector_capsule_allocation_observer,
    .package = "dsVert")
  call_result <- function(session_id = NULL) {
    testthat::with_mocked_bindings(
      tryCatch(.dsvert_joint_dp_vector_result_impl(
        fixture$manifest_json, prepares[[1L]], prepares[[2L]],
        session_id = session_id,
        .policy = fixture$policies$peer_a,
        .secret = fixture$secrets$peer_a,
        .signer = fixture$signer, .verifier = fixture$verifier,
        .planner = fixture$planner), error = identity),
      .dsvert_dp_capsule_manifest_require_built = gate,
      .package = "dsVert")
  }
  miss <- call_result()
  expect_s3_class(miss, "dsvert_phase_not_ready")
  expect_identical(conditionMessage(miss),
                   "[dsvert_phase_not_ready:v1]")
  expect_identical(miss$code, "phase_not_ready")
  expect_identical(miss$retryable, FALSE)
  cold_claim_count <- .dsvert_joint_dp_vector_with_store(
    fixture$policies$peer_a, fixture$secrets$peer_a,
    function(connection) DBI::dbGetQuery(
      connection,
      "SELECT COUNT(*) AS n FROM vector_instance_claims")$n[[1L]])
  expect_identical(as.numeric(cold_claim_count), 0)

  invalid_session <- call_result("invalid-session")
  expect_s3_class(invalid_session, "error")
  expect_false(inherits(invalid_session, "dsvert_phase_not_ready"))

  for (state in c("released", "acked")) {
    .dsvert_joint_dp_vector_with_store(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      function(connection) {
        current <- .dsvert_joint_dp_vector_capsule_load(
          connection,
          .dsvert_joint_dp_hash(fixture$release_instance),
          fixture$secrets$peer_a)
        expect_true(is.list(current))
        old <- current
        current$state <- state
        current$compacted <- identical(state, "acked")
        current$local_result_json <- NULL
        current$release_receipt_json <- NULL
        current$ack_receipt_json <- NULL
        .dsvert_joint_dp_vector_capsule_put(
          connection, current, fixture$secrets$peer_a, existing = old)
      })
    hard <- call_result()
    expect_s3_class(hard, "error")
    expect_false(inherits(hard, "dsvert_phase_not_ready"), info = state)
  }
})

test_that("RELEASE phase miss requires a genuinely absent typed transfer", {
  session <- new.env(parent = emptyenv())
  context <- list(
    capsule_id = strrep("1", 64L),
    release_contract_hash = strrep("2", 64L),
    result_set_hash = strrep("3", 64L),
    chunk_index = "0", chunk_count = "1", coordinate_count = "1",
    ring = "128", noised_share_sha256 = strrep("4", 64L))
  call_reader <- function() {
    tryCatch(.dsvert_joint_dp_vector_default_peer_reader(
      session, context, "peer_b", list(), strrep("3", 64L),
      list(index = 0L, count = 1L), strrep("4", 64L)),
      error = identity)
  }

  absent <- call_reader()
  expect_s3_class(absent, "dsvert_phase_not_ready")
  expect_identical(conditionMessage(absent),
                   "[dsvert_phase_not_ready:v1]")

  destination <- .dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_VECTOR_TYPED_CAPABILITY, "peer_b", context)$slot
  session$blobs <- stats::setNames(list("unprovenanced"), destination)
  unprovenanced <- call_reader()
  expect_s3_class(unprovenanced, "error")
  expect_false(inherits(unprovenanced, "dsvert_phase_not_ready"))
  expect_match(conditionMessage(unprovenanced), "unprovenanced")
})

test_that("the vector store rejects linked SQLite files and sidecars", {
  skip_on_os("windows")
  fixture <- .vector_capsule_fixture()
  policy <- fixture$policies$peer_a
  policy$ledger_private <- TRUE
  secret <- fixture$secrets$peer_a
  path <- .dsvert_joint_dp_vector_store_path(policy)
  lock_path <- paste0(path, ".lock")
  Sys.chmod(c(path, lock_path), mode = "0600")

  hardlink <- tempfile("vector-store-hardlink-", tmpdir = dirname(path))
  on.exit(unlink(hardlink, force = TRUE), add = TRUE)
  expect_true(file.link(path, hardlink))
  expect_error(
    .dsvert_joint_dp_vector_with_store(policy, secret, function(...) TRUE),
    "hard links")
  unlink(hardlink, force = TRUE)

  target <- tempfile("vector-store-link-target-", tmpdir = dirname(path))
  on.exit(unlink(target, force = TRUE), add = TRUE)
  expect_true(file.create(target))
  linked_policy <- policy
  linked_policy$ledger_path <- tempfile(
    "vector-store-linked-main-", tmpdir = dirname(path))
  linked_main <- paste0(
    linked_policy$ledger_path, ".joint-dp-vector-v4.sqlite")
  on.exit(unlink(linked_main, force = TRUE), add = TRUE)
  Sys.chmod(target, mode = "0644")
  expect_true(file.symlink(target, linked_main))
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      linked_policy, secret, function(...) TRUE),
    "symbolic link")
  expect_identical(as.integer(file.info(target)$mode),
                   strtoi("644", base = 8L))
  unlink(linked_main, force = TRUE)

  for (sidecar in c(lock_path, paste0(path, "-wal"), paste0(path, "-shm"))) {
    unlink(sidecar, force = TRUE)
    Sys.chmod(target, mode = "0644")
    expect_true(file.symlink(target, sidecar))
    expect_error(
      .dsvert_joint_dp_vector_with_store(policy, secret, function(...) TRUE),
      "symbolic link")
    expect_identical(as.integer(file.info(target)$mode),
                     strtoi("644", base = 8L))
    unlink(sidecar, force = TRUE)
  }
})

test_that("published-state loss denies rematerialization without rotation", {
  fixture <- .vector_capsule_fixture()
  peer <- "peer_a"
  policy <- fixture$policies[[peer]]
  secret <- fixture$secrets[[peer]]
  gate <- function(...) invisible(TRUE)
  old_contract <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_contract(
      policy, fixture$manifest_json, fixture$release_instance_json,
      fixture$planner, secret = secret),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .package = "dsVert")
  public <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(list(
      version = .DSVERT_JOINT_DP_VECTOR_RELEASE_VERSION,
      phase = "vector_released", peer_name = peer,
      capsule_id = fixture$release_instance$capsule_id,
      release_instance_id = old_contract$release_instance_id,
      final_vector_root = strrep("d", 64L),
      epsilon = old_contract$release_contract$epsilon,
      delta = old_contract$release_contract$allocated_delta,
      signature = strrep("e", 128L))))
  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
    claim <- .dsvert_joint_dp_vector_instance_claim_material(
      old_contract$release_contract$capsule_id,
      old_contract$release_instance_id,
      old_contract$release_contract_hash)
    .dsvert_joint_dp_vector_transaction(connection, {
      .dsvert_joint_dp_vector_instance_claim_insert_connection(
        connection, secret, claim)
      .dsvert_joint_dp_release_ledger_commit_connection(
        connection, config, secret, fixture$release_instance_json, public)
    })
  })
  before <- .dsvert_joint_dp_release_domain_current(policy, secret)
  protected_calls <- character()

  condition <- testthat::with_mocked_bindings(
    tryCatch(.dsvert_joint_dp_vector_prepare_impl(
      fixture$manifest_json, fixture$release_instance_json,
      .policy = policy, .secret = secret,
      .signer = fixture$signer, .planner = fixture$planner),
    error = identity),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .dsvert_joint_dp_vector_allocation_require = function(...) {
      protected_calls <<- c(protected_calls, "allocation")
      stop("allocation must not run", call. = FALSE)
    },
    .dsvert_joint_dp_vector_allocation_observer_require = function(...) {
      protected_calls <<- c(protected_calls, "allocation_observer")
      stop("allocation observer must not run", call. = FALSE)
    },
    .dsvert_dp_noise_seed = function(...) {
      protected_calls <<- c(protected_calls, "seed")
      stop("seed must not be derived", call. = FALSE)
    },
    .dsvert_dp_resolve_snapshot = function(...) {
      protected_calls <<- c(protected_calls, "source")
      stop("source must not be resolved", call. = FALSE)
    },
    .package = "dsVert")
  expect_s3_class(condition, "dsvert_dp_lifetime_budget_exhausted")
  expect_identical(
    conditionMessage(condition),
    .DSVERT_DP_LIFETIME_BUDGET_EXHAUSTED_MESSAGE)
  expect_identical(protected_calls, character())
  after <- .dsvert_joint_dp_release_domain_current(policy, secret)
  expect_identical(after, before)
})

test_that("opening a v5 vector store rejects without mutating its schema", {
  fixture <- .vector_capsule_fixture()
  policy <- fixture$policies$peer_a
  policy$ledger_path <- tempfile("dsvert-vector-v5-read-only-rejection-")
  secret <- fixture$secrets$peer_a
  path <- .dsvert_joint_dp_vector_store_path(policy)
  sidecars <- c(path, paste0(path, c(".lock", "-wal", "-shm")))
  on.exit(unlink(sidecars, force = TRUE), add = TRUE)

  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  legacy_statements <- c(
    paste("CREATE TABLE vector_meta (",
          "key TEXT PRIMARY KEY, value TEXT NOT NULL, row_mac TEXT NOT NULL)"),
    paste("CREATE TABLE vector_capsules (",
          "release_instance_id TEXT PRIMARY KEY, state TEXT NOT NULL,",
          "compacted INTEGER NOT NULL, record_json TEXT NOT NULL,",
          "row_mac TEXT NOT NULL)"),
    paste("CREATE TABLE vector_noised_chunks (",
          "release_instance_id TEXT NOT NULL, chunk_index INTEGER NOT NULL,",
          "payload_chars INTEGER NOT NULL, record_json TEXT NOT NULL,",
          "row_mac TEXT NOT NULL,",
          "PRIMARY KEY(release_instance_id, chunk_index))"),
    paste("CREATE TABLE vector_final_chunks (",
          "release_instance_id TEXT NOT NULL, chunk_index INTEGER NOT NULL,",
          "chunk_hash TEXT NOT NULL, record_json TEXT NOT NULL,",
          "row_mac TEXT NOT NULL,",
          "PRIMARY KEY(release_instance_id, chunk_index))"))
  for (statement in legacy_statements) DBI::dbExecute(connection, statement)
  legacy_binding <- .dsvert_joint_dp_vector_record_json(list(
    version = "dsvert-joint-dp-vector-store-v5",
    domain = policy$domain, cohort_id = policy$cohort_id,
    peer_name = policy$peer_name,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    privacy_epoch_scope = "per_peer_signed_release_instance_v1"))
  DBI::dbExecute(connection, paste(
    "INSERT INTO vector_meta(key,value,row_mac)",
    "VALUES('policy_binding',?,?)"), params = list(
      legacy_binding,
      .dsvert_joint_dp_vector_row_mac(secret, "meta", legacy_binding)))
  schema <- function(connection) DBI::dbGetQuery(connection, paste(
    "SELECT name,sql FROM sqlite_master WHERE type='table'",
    "ORDER BY name"))
  before_schema <- schema(connection)
  DBI::dbDisconnect(connection)
  Sys.chmod(path, mode = "0600")
  before_hash <- digest::digest(file = path, algo = "sha256")

  condition <- tryCatch(
    .dsvert_joint_dp_vector_with_store(
      policy, secret, function(connection) invisible(connection)),
    error = identity)
  expect_s3_class(condition, "error")
  expect_match(conditionMessage(condition),
               "belongs to another policy or failed authentication")
  expect_identical(digest::digest(file = path, algo = "sha256"),
                   before_hash)
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), path, flags = RSQLite::SQLITE_RO)
  after_schema <- schema(connection)
  DBI::dbDisconnect(connection)
  expect_identical(after_schema, before_schema)
  expect_false("vector_instance_claims" %in% after_schema$name)
})

test_that("a release-table view masquerade is rejected without mutation", {
  fixture <- .vector_capsule_fixture()
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  path <- .dsvert_joint_dp_vector_store_path(policy)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  DBI::dbExecute(connection,
    "DROP TABLE vector_release_ledger_records")
  DBI::dbExecute(connection,
    "DROP TABLE vector_release_ledger_state")
  DBI::dbExecute(connection,
    "DROP TABLE vector_release_ledger_meta")
  DBI::dbExecute(connection, paste(
    "DELETE FROM vector_meta",
    "WHERE key='release_ledger_backfill'"))
  DBI::dbExecute(connection, paste(
    "CREATE VIEW vector_release_ledger_state AS",
    "SELECT 1 AS singleton"))
  DBI::dbExecute(connection, "COMMIT")
  DBI::dbDisconnect(connection)
  Sys.chmod(path, mode = "0600")

  schema <- function() {
    connection <- DBI::dbConnect(
      RSQLite::SQLite(), path, flags = RSQLite::SQLITE_RO)
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    DBI::dbGetQuery(connection, paste(
      "SELECT type,name,tbl_name,sql FROM sqlite_master",
      "ORDER BY type,tbl_name,name"))
  }
  before_schema <- schema()
  before_hash <- digest::digest(file = path, algo = "sha256")
  condition <- tryCatch(
    .dsvert_joint_dp_vector_with_store(
      policy, secret, function(connection) invisible(connection)),
    error = identity)
  expect_s3_class(condition, "error")
  expect_match(conditionMessage(condition), "store schema is invalid")
  expect_identical(digest::digest(file = path, algo = "sha256"),
                   before_hash)
  after_schema <- schema()
  expect_identical(after_schema, before_schema)
  expect_true(any(
    after_schema$type == "view" &
      after_schema$name == "vector_release_ledger_state"))
  expect_false(any(
    after_schema$type == "table" & after_schema$name %in% c(
      "vector_release_ledger_meta", "vector_release_ledger_records",
      "vector_release_ledger_state")))
  expect_false(any(
    after_schema$type == "index" &
      after_schema$name == "vector_release_ledger_capsule_id_unique"))
})

test_that("the authenticated vector schema fixes constraints and indexes", {
  fixture <- .vector_capsule_fixture(k = 3L)
  policies <- fixture$policies[fixture$peers[1:3]]
  secrets <- fixture$secrets[fixture$peers[1:3]]

  cache_probe <- .dsvert_joint_dp_vector_with_store(
    policies[[1L]], secrets[[1L]], function(connection) {
      config <- .dsvert_joint_dp_release_ledger_config_from_policy(
        policies[[1L]])
      before <- .dsvert_joint_dp_vector_release_ledger_cache_key(
        connection, config)
      DBI::dbExecute(connection, paste(
        "CREATE INDEX vector_capsules_state_unexpected",
        "ON vector_capsules(state)"))
      after <- .dsvert_joint_dp_vector_release_ledger_cache_key(
        connection, config)
      list(before = before, after = after)
    })
  expect_false(identical(cache_probe$before, cache_probe$after))
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      policies[[1L]], secrets[[1L]], function(connection) TRUE),
    "store schema is invalid")

  constraint_path <- .dsvert_joint_dp_vector_store_path(policies[[2L]])
  connection <- DBI::dbConnect(RSQLite::SQLite(), constraint_path)
  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  DBI::dbExecute(connection, paste(
    "ALTER TABLE vector_instance_claims",
    "RENAME TO vector_instance_claims_original"))
  DBI::dbExecute(connection, paste(
    "CREATE TABLE vector_instance_claims (",
    "capsule_id TEXT PRIMARY KEY, release_instance_id TEXT NOT NULL,",
    "release_contract_hash TEXT NOT NULL,",
    "record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"))
  DBI::dbExecute(connection, "DROP TABLE vector_instance_claims_original")
  DBI::dbExecute(connection, "COMMIT")
  DBI::dbDisconnect(connection)
  Sys.chmod(constraint_path, mode = "0600")
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      policies[[2L]], secrets[[2L]], function(connection) TRUE),
    "store schema is invalid")

  index_path <- .dsvert_joint_dp_vector_store_path(policies[[3L]])
  connection <- DBI::dbConnect(RSQLite::SQLite(), index_path)
  DBI::dbExecute(connection,
    "DROP INDEX vector_release_ledger_capsule_id_unique")
  DBI::dbExecute(connection, paste(
    "CREATE UNIQUE INDEX vector_release_ledger_capsule_id_unique ON",
    "vector_release_ledger_records(release_instance_id,capsule_id)"))
  DBI::dbDisconnect(connection)
  Sys.chmod(index_path, mode = "0600")
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      policies[[3L]], secrets[[3L]], function(connection) TRUE),
    "store schema is invalid")
})

test_that("the authenticated vector schema rejects an extra table", {
  fixture <- .vector_capsule_fixture()
  .dsvert_joint_dp_vector_with_store(
    fixture$policies$peer_a, fixture$secrets$peer_a,
    function(connection) DBI::dbExecute(connection, paste(
      "CREATE TABLE vector_unexpected_persistent_table (",
      "value TEXT NOT NULL)")))
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      function(connection) TRUE),
    "store schema is invalid")
})

test_that("the authenticated vector schema rejects an extra view", {
  fixture <- .vector_capsule_fixture()
  .dsvert_joint_dp_vector_with_store(
    fixture$policies$peer_a, fixture$secrets$peer_a,
    function(connection) DBI::dbExecute(connection, paste(
      "CREATE VIEW vector_unexpected_persistent_view AS",
      "SELECT capsule_id FROM vector_instance_claims")))
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      function(connection) TRUE),
    "store schema is invalid")
})

test_that("release-domain corruption without a durable release regenerates", {
  fixture <- .vector_capsule_fixture()
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  before <- .dsvert_joint_dp_release_domain_current(policy, secret)
  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    changed <- DBI::dbExecute(connection, paste(
      "UPDATE vector_meta SET value=?,row_mac=?",
      "WHERE key='release_domain'"),
      params = list("{\"corrupt\":true}", strrep("0", 64L)))
    expect_identical(as.integer(changed), 1L)
  })
  after <- .dsvert_joint_dp_release_domain_current(
    policy, secret, random_bytes = function(size) as.raw(rep(9L, size)))
  expect_false(identical(after$domain_id, before$domain_id))
  expect_identical(after$generation, 1)
  expect_identical(after$rotation_count, 0)
  expect_identical(after$reason, "corrupt_record_recovery")
})

test_that("authenticated recovery preserves a published later generation", {
  recovered <- list(
    version = .DSVERT_JOINT_DP_RELEASE_DOMAIN_VERSION,
    generation = 3,
    domain_id = paste0("rd_", strrep("a", 64L)),
    previous_domain_id = NULL,
    rotation_count = 2,
    reason = "authenticated_release_recovery")
  expect_identical(
    .dsvert_joint_dp_release_domain_validate(recovered)$generation, 3)
  unsupported <- recovered
  unsupported$reason <- "corrupt_record_recovery"
  expect_error(
    .dsvert_joint_dp_release_domain_validate(unsupported),
    "record is invalid")
})

test_that("exact Gaussian calibration is conservative and request-bound", {
  fixture <- .vector_capsule_fixture(gaussian = TRUE)
  selection <- fixture$manifests[[1L]]$workload$mechanism_selection
  request <- selection$gaussian_calibration_request
  plan <- fixture$planner(request)
  policy <- fixture$policies$peer_a
  coordinate_count <- fixture$manifests[[1L]]$workload$coordinate_count

  expect_lt(as.numeric(request$epsilon), policy$global_total_epsilon)
  expect_lt(as.numeric(request$delta), policy$global_total_delta)
  expect_gt(
    as.numeric(request$l2_sensitivity_steps),
    fixture$manifests[[1L]]$workload$sensitivity$l2)
  expect_lte(
    as.numeric(plan$epsilon_numerator) /
      as.numeric(plan$epsilon_denominator),
    policy$global_total_epsilon)
  expect_lte(
    as.numeric(plan$allocated_delta_numerator) /
      as.numeric(plan$allocated_delta_denominator),
    policy$global_total_delta)
  expect_gte(
    as.numeric(plan$l2_sensitivity_numerator) /
      as.numeric(plan$l2_sensitivity_denominator),
    fixture$manifests[[1L]]$workload$sensitivity$l2)
  expect_silent(.dsvert_dp_capsule_exact_gaussian_plan_validate(
    plan, coordinate_count, request))
  expect_identical(plan$sampler_full_scan_steps,
                   plan$sampler_magnitude_count)
  expect_identical(
    plan$sampler_cdf_table_bytes,
    plan$sampler_magnitude_count * plan$sampler_random_bytes_per_coordinate)
  expect_identical(plan$nominal_variance_multiplier, 2L)
  expect_identical(plan$nominal_standard_deviation_factor,
                   "sqrt(2)_relative_to_one_full_draw")
  expect_true(plan$at_least_one_honest_noise_peer)
  expect_identical(plan$maximum_colluding_noise_peers, 1L)
  expect_false(plan$sampler_branches_on_private_randomness)
  expect_false(plan$host_constant_time_claim)
  expect_true(plan$transcript_dp_claim)
  expect_true(plan$logical_transcript_fixed_shape)
  expect_false(plan$physical_timing_dp_claim)

  semantic_tamper <- list(
    sampler_full_scan_steps = plan$sampler_full_scan_steps - 1L,
    sampler_cdf_table_bytes = plan$sampler_cdf_table_bytes + 1L,
    nominal_variance_multiplier = 1L,
    nominal_standard_deviation_factor = "unknown",
    at_least_one_honest_noise_peer = FALSE,
    maximum_colluding_noise_peers = 2L,
    adversary_view = "analyst_only",
    adversary_view_privacy_argument = "unsupported",
    source_share_hiding_precondition = "none",
    sampler_branches_on_private_randomness = TRUE,
    transcript_dp_claim = FALSE,
    logical_transcript_fixed_shape = FALSE,
    physical_timing_dp_claim = TRUE)
  for (field in names(semantic_tamper)) {
    changed_plan <- plan
    changed_plan[[field]] <- semantic_tamper[[field]]
    expect_error(
      .dsvert_dp_capsule_exact_gaussian_plan_validate(
        changed_plan, coordinate_count, request),
      "invalid certificate", fixed = TRUE,
      info = paste("tampered Gaussian semantic field", field))
  }

  for (field in c("epsilon", "delta", "l2_sensitivity_steps")) {
    changed_request <- request
    changed_request[[field]] <- paste0(request[[field]], "0")
    expect_error(
      .dsvert_dp_capsule_exact_gaussian_plan_validate(
        plan, coordinate_count, changed_request),
      "invalid certificate", fixed = TRUE)
  }
  for (field in c(
      "epsilon_numerator", "allocated_delta_numerator",
      "l2_sensitivity_numerator")) {
    changed_plan <- plan
    changed_plan[[field]] <- if (identical(plan[[field]], "1")) "2" else "1"
    expect_error(
      .dsvert_dp_capsule_exact_gaussian_plan_validate(
        changed_plan, coordinate_count, request),
      "invalid certificate", fixed = TRUE)
  }
  denominators <- grep("_denominator$", names(plan), value = TRUE)
  expect_gt(length(denominators), 0L)
  for (field in denominators) {
    changed_plan <- plan
    changed_plan[[field]] <- "0"
    expect_error(
      .dsvert_dp_capsule_exact_gaussian_plan_validate(
        changed_plan, coordinate_count, request),
      "invalid certificate", fixed = TRUE)
  }
})

test_that("the scalable vector lifecycle is sticky, final-only and restart-safe", {
 for (gaussian in c(FALSE, TRUE)) {
  fixture <- .vector_capsule_fixture(
    gaussian = gaussian, k = if (gaussian) 2L else 3L,
    count_only = !gaussian)
  expect_identical(
    fixture$manifests[[1L]]$workload$capsule_mechanism$mechanism,
    if (gaussian) "dyadic_discrete_gaussian_truncated_tv_bounded" else
      "discrete-laplace")
  if (!gaussian) {
    expect_error(.dsvert_joint_dp_vector_sign(
      list(version = .DSVERT_JOINT_DP_VECTOR_RESULT_VERSION,
           phase = "vector_local_result_committed"),
      fixture$policies[[fixture$peers[[3L]]]], fixture$signer,
      require_designated = FALSE),
    "Only a vector finalization acknowledgement")
  }
  gate <- function(...) invisible(TRUE)
  session_id <- "00000000-0000-4000-8000-000000000001"
  exact_session <- new.env(parent = emptyenv())
  exact_session$session_id <- session_id
  sampler_calls <- stats::setNames(integer(2L), fixture$peers[1:2])
  allocation_require_calls <- 0L
  exact_start <- function(...) list(initialization = list(state = "ready"))
  exact_operation <- function(ss, contract, prepares, chunk, policy, ...) {
    circuit_digest <- strrep("7", 64L)
    worker <- list(
      operation = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION,
      purpose = paste0(
        .DSVERT_JOINT_DP_VECTOR_EXACT_GC_OPERATION, "/", circuit_digest),
      circuit_digest = circuit_digest,
      worker_policy = list(
        coordinate_count = chunk$count,
        transcript_hash = contract$transcript_hash),
      plan = contract$plan)
    binding <- .dsvert_joint_dp_vector_exact_gc_binding(
      contract$release_contract$backend_selection,
      contract$release_contract$manifest_sha256,
      contract$release_contract_hash, contract$transcript_hash,
      chunk$index, worker)
    list(selection = contract$release_contract$backend_selection,
         worker = worker, binding = binding)
  }
  tickets <- .vector_capsule_helpers$.capsule_source_test_tickets(fixture)
  source_contract <- .dsvert_dp_capsule_source_contract_json(
    fixture$policies[[1L]], fixture$manifest_json)$contract
  source_peers <- .dsvert_dp_capsule_source_names(
    source_contract$source_peers, "test source peer list")
  summaries <- lapply(source_peers, function(source) {
    .dsvert_dp_capsule_source_prepare_impl(
      fixture$manifest_json, tickets[[1L]], tickets[[2L]],
      fixture$openings[[1L]], fixture$openings[[2L]],
      .policy = fixture$policies[[source]],
      .secret = fixture$secrets[[source]],
      .resolved_snapshots = fixture$resolved[[source]],
      .signer = fixture$signer, .verifier = fixture$verifier,
      .allocation_observer =
        .vector_capsule_helpers$.capsule_source_test_allocation_observer)
  })
  for (recipient in fixture$peers[1:2]) {
    for (source in source_peers) {
      source_contract <- .dsvert_dp_capsule_source_contract_json(
        fixture$policies[[source]], fixture$manifest_json)$contract
      for (chunk in seq.int(0, source_contract$chunk_count - 1L)) {
        envelope <- .vector_capsule_helpers$.capsule_source_test_envelope(
          fixture, summaries, source, recipient, chunk)
        .vector_capsule_helpers$.capsule_source_test_accept(
          fixture, recipient, envelope)
      }
    }
  }
  lifecycle <- testthat::with_mocked_bindings({
    prepares <- lapply(fixture$peers[1:2], function(peer) {
      .dsvert_joint_dp_vector_prepare_impl(
        fixture$manifest_json, fixture$release_instance_json,
        .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = fixture$signer, .planner = fixture$planner)
    })
    starts <- lapply(fixture$peers[1:2], function(peer) {
      sampled <- function(value) {
        sampler_calls[[peer]] <<- sampler_calls[[peer]] + 1L
        fixture$sampler(value)
      }
      .dsvert_joint_dp_vector_start_impl(
        fixture$manifest_json, prepares[[1L]], prepares[[2L]], 0L,
        .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = fixture$signer, .verifier = fixture$verifier,
        .planner = fixture$planner, .sampler = sampled,
        session_id = session_id, .session = exact_session,
        .exact_start = exact_start,
        .source_reader = function(...) fixture$source_shares[[peer]])
    })
    start_replay <- .dsvert_joint_dp_vector_start_impl(
      fixture$manifest_json, prepares[[1L]], prepares[[2L]], 0L,
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .signer = fixture$signer, .verifier = fixture$verifier,
      .planner = fixture$planner,
      .sampler = function(...) stop("sampler must not rerun"),
      session_id = session_id, .session = exact_session,
      .exact_start = exact_start,
      .source_reader = function(...) fixture$source_shares$peer_a)
    results <- lapply(fixture$peers[1:2], function(peer) {
      exact_consume <- function(ss, binding, worker_contract, .commit, ...) {
        share <- as.raw(rep(0L, worker_contract$worker_policy$coordinate_count *
                              16L))
        validity <- as.raw(if (identical(peer, fixture$peers[[1L]])) 0L else 1L)
        internal <- list(
          noised_share_b64 = gsub("[\r\n]", "", jsonlite::base64_enc(share)),
          validity_share_b64 = gsub(
            "[\r\n]", "", jsonlite::base64_enc(validity)),
          noised_share_sha256 = digest::digest(
            share, algo = "sha256", serialize = FALSE),
          validity_share_sha256 = digest::digest(
            validity, algo = "sha256", serialize = FALSE),
          binding_sha256 = binding$binding_sha256,
          operation_id = binding$operation_id,
          purpose = binding$purpose,
          backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND)
        expect_true(.commit(internal))
        invisible(list(durable = TRUE))
      }
      .dsvert_joint_dp_vector_result_impl(
        fixture$manifest_json, prepares[[1L]], prepares[[2L]],
        session_id = session_id,
        .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = fixture$signer, .verifier = fixture$verifier,
        .planner = fixture$planner, .session = exact_session,
        .exact_consume = exact_consume)
    })
    sender_session <- new.env(parent = emptyenv())
    sender_session$.session_id <- session_id
    sender_session$keys <- list(
      identity_pk = unname(fixture$policies$peer_a$peer_pinset[["peer_a"]]),
      transport_sk = "test-transport-secret")
    peer_transport <- gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw((seq_len(32L) + 91L) %% 256L)))
    sender_session$peer_transport_pks <- list(peer_b = peer_transport)
    sender_session$.typed_blob_self_name <- "peer_a"
    sender_session$.typed_blob_peer_identity_pks <- list(
      peer_b = unname(fixture$policies$peer_a$peer_pinset[["peer_b"]]))
    sender_session$.typed_blob_peer_binding_digest <- strrep("a", 64L)
    final_share <- testthat::with_mocked_bindings(
      .dsvert_joint_dp_vector_final_share_impl(
        session_id, fixture$manifest_json,
        results[[1L]], results[[2L]], 0L,
        .policy = fixture$policies$peer_a,
        .secret = fixture$secrets$peer_a,
        .verifier = fixture$verifier, .planner = fixture$planner,
        .session = sender_session,
        .encryptor = function(plaintext, recipient_pk) {
          expect_true(is.raw(plaintext))
          gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(77L, 96L))))
        }),
      .S = function(...) sender_session,
      .get_identity_keypair = function() list(
        identity_pk = unname(
          fixture$policies$peer_a$peer_pinset[["peer_a"]]),
        identity_sk = "test-identity-secret"),
      .sign_transport_pk = function(...) gsub(
        "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(55L, 64L)))),
      .dsvert_secure_random_bytes = function(n) {
        as.raw(rep(1:255, length.out = n))
      },
      .package = "dsVert")
    peer_reader <- function(session, context, sender, contract,
                            result_set_hash, chunk, expected_hash) {
      row <- .dsvert_joint_dp_vector_with_store(
        fixture$policies[[sender]], fixture$secrets[[sender]],
        function(connection) .dsvert_joint_dp_vector_noised_load(
          connection, contract$release_contract$release_instance_id,
          chunk$index, fixture$secrets[[sender]]))
      expect_identical(
        .dsvert_joint_dp_vector_local_chunk_commitment(row, contract),
        expected_hash)
      c(list(
        share_b64 = row$noised_share_b64,
        validity_share_b64 = row$validity_share_b64,
        binding_sha256 = row$binding_sha256),
        list(encrypted = NULL))
    }
    allocation_require_before_release <- allocation_require_calls
    releases <- lapply(fixture$peers[1:2], function(peer) {
      .dsvert_joint_dp_vector_release_impl(
        session_id, fixture$manifest_json, results[[1L]], results[[2L]],
        .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = fixture$signer, .verifier = fixture$verifier,
        .planner = fixture$planner, .finalizer = fixture$finalizer,
        .peer_share_reader = peer_reader,
        .session = new.env(parent = emptyenv()))
    })
    expect_identical(
      allocation_require_calls, allocation_require_before_release + 2L)
    sampler_calls_before_domain_recovery <- sampler_calls
    domain_before_recovery <- .dsvert_joint_dp_release_domain_current(
      fixture$policies$peer_a, fixture$secrets$peer_a)
    .dsvert_joint_dp_vector_with_store(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      function(connection) {
        changed <- DBI::dbExecute(connection, paste(
          "UPDATE vector_meta SET value=?,row_mac=?",
          "WHERE key='release_domain'"),
          params = list("{\"corrupt\":true}", strrep("0", 64L)))
        expect_identical(as.integer(changed), 1L)
      })
    recovered_domain <- .dsvert_joint_dp_release_domain_current(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      random_bytes = function(...) {
        stop("a published domain must be recovered, not regenerated")
      })
    release_after_domain_recovery <- .dsvert_joint_dp_vector_release_impl(
      "invalid-session", fixture$manifest_json,
      results[[1L]], results[[2L]],
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .planner = function(...) stop("planner must not rerun"))
    .dsvert_joint_dp_vector_with_store(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      function(connection) {
        changed <- DBI::dbExecute(connection,
          "DELETE FROM vector_meta WHERE key='release_domain'")
        expect_identical(as.integer(changed), 1L)
      })
    recovered_domain_after_loss <-
      .dsvert_joint_dp_release_domain_current(
        fixture$policies$peer_a, fixture$secrets$peer_a,
        random_bytes = function(...) {
          stop("a published domain must be recovered, not regenerated")
        })
    release_after_domain_loss <- .dsvert_joint_dp_vector_release_impl(
      "invalid-session", fixture$manifest_json,
      results[[1L]], results[[2L]],
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .planner = function(...) stop("planner must not rerun"))
    ledger_after_domain_recovery <- .dsvert_joint_dp_vector_with_store(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      function(connection) {
        config <- .dsvert_joint_dp_release_ledger_config_from_policy(
          fixture$policies$peer_a)
        .dsvert_joint_dp_release_ledger_status(
          connection, config, fixture$secrets$peer_a)
      })
    # Valid signed result receipts identify the release instance. Durable
    # replay must then win before session lookup, source access or sampling.
    allocation_require_before_replay <- allocation_require_calls
    release_replay <- .dsvert_joint_dp_vector_release_impl(
      "invalid-session", fixture$manifest_json,
      results[[1L]], results[[2L]],
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .planner = function(...) stop("planner must not rerun"))
    expect_identical(allocation_require_calls,
                     allocation_require_before_replay)
    replay <- .dsvert_joint_dp_vector_replay_impl(
      fixture$manifest_json, releases[[1L]], releases[[2L]], 0L,
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .verifier = fixture$verifier)
    acks <- lapply(fixture$peers, function(peer) {
      .dsvert_joint_dp_vector_ack_impl(
        fixture$manifest_json, releases[[1L]], releases[[2L]],
        .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = fixture$signer, .verifier = fixture$verifier,
        .planner = fixture$planner)
    })
    ack_replay <- .dsvert_joint_dp_vector_ack_impl(
      fixture$manifest_json, releases[[1L]], releases[[2L]],
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .signer = fixture$signer, .verifier = fixture$verifier,
      .planner = fixture$planner)
    result_replays_after_ack <- lapply(fixture$peers[1:2], function(peer) {
      .dsvert_joint_dp_vector_result_impl(
        fixture$manifest_json, prepares[[1L]], prepares[[2L]],
        session_id = "invalid-session",
        .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = function(...) stop("result must not be signed again"),
        .verifier = fixture$verifier, .planner = fixture$planner,
        .exact_consume = function(...) stop("sampler must not rerun"))
    })
    replay_after_ack <- .dsvert_joint_dp_vector_replay_impl(
      fixture$manifest_json, releases[[1L]], releases[[2L]], 0L,
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .verifier = fixture$verifier)
    rotated_policies <- fixture$policies
    for (peer in fixture$peers[1:2]) {
      rotated_policies[[peer]]$noise_root$epoch <- 2
      rotated_policies[[peer]]$noise_root$key_id <-
        paste0("rotated-vector-root-", peer)
    }
    rotated_release_replays <- lapply(fixture$peers[1:2], function(peer) {
      .dsvert_joint_dp_vector_release_impl(
        "invalid-session", fixture$manifest_json,
        results[[1L]], results[[2L]],
        .policy = rotated_policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .planner = function(...) stop("historical planner must not rerun"))
    })
    rotated_chunk_replays <- lapply(fixture$peers[1:2], function(peer) {
      .dsvert_joint_dp_vector_replay_impl(
        fixture$manifest_json, releases[[1L]], releases[[2L]], 0L,
        .policy = rotated_policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .verifier = fixture$verifier)
    })
    list(
      prepares = prepares, starts = starts, start_replay = start_replay,
      results = results, final_share = final_share, releases = releases,
      release_replay = release_replay, replay = replay,
      acks = acks, ack_replay = ack_replay,
      result_replays_after_ack = result_replays_after_ack,
      replay_after_ack = replay_after_ack,
      rotated_policies = rotated_policies,
      rotated_release_replays = rotated_release_replays,
      rotated_chunk_replays = rotated_chunk_replays,
      sampler_calls_before_domain_recovery =
        sampler_calls_before_domain_recovery,
      sampler_calls_after_domain_recovery = sampler_calls,
      domain_before_recovery = domain_before_recovery,
      recovered_domain = recovered_domain,
      recovered_domain_after_loss = recovered_domain_after_loss,
      release_after_domain_recovery = release_after_domain_recovery,
      release_after_domain_loss = release_after_domain_loss,
      ledger_after_domain_recovery = ledger_after_domain_recovery)
  },
  .dsvert_dp_capsule_manifest_require_built = gate,
  .dsvert_joint_dp_vector_allocation_require = function(...) {
    allocation_require_calls <<- allocation_require_calls + 1L
    .vector_capsule_allocation_local(...)
  },
  .dsvert_joint_dp_vector_allocation_observer_require =
    .vector_capsule_allocation_observer,
  .dsvert_joint_dp_vector_exact_gc_operation = exact_operation,
  .dsvert_ensure_identity_recovery = function(...) TRUE,
  .package = "dsVert")

  expect_identical(lifecycle$start_replay, lifecycle$starts[[1L]])
  expect_identical(
    lifecycle$release_after_domain_recovery, lifecycle$releases[[1L]])
  expect_identical(
    lifecycle$release_after_domain_loss, lifecycle$releases[[1L]])
  expect_identical(
    lifecycle$recovered_domain$generation,
    lifecycle$domain_before_recovery$generation)
  expect_identical(
    lifecycle$recovered_domain$domain_id,
    lifecycle$domain_before_recovery$domain_id)
  expect_identical(
    lifecycle$recovered_domain_after_loss$generation,
    lifecycle$domain_before_recovery$generation)
  expect_identical(
    lifecycle$recovered_domain_after_loss$domain_id,
    lifecycle$domain_before_recovery$domain_id)
  expect_identical(
    lifecycle$sampler_calls_after_domain_recovery,
    lifecycle$sampler_calls_before_domain_recovery)
  expect_identical(
    unname(lifecycle$sampler_calls_before_domain_recovery),
    if (gaussian) c(1L, 1L) else c(0L, 0L))
  expect_identical(
    lifecycle$ledger_after_domain_recovery$release_instance_count, 1)
  expect_identical(lifecycle$release_replay, lifecycle$releases[[1L]])
  expect_identical(lifecycle$ack_replay, lifecycle$acks[[1L]])
  expect_identical(lifecycle$result_replays_after_ack, lifecycle$results)
  expect_identical(lifecycle$replay_after_ack, lifecycle$replay)
  expect_identical(lifecycle$rotated_release_replays, lifecycle$releases)
  expect_true(all(vapply(
    lifecycle$rotated_chunk_replays, identical, logical(1L),
    lifecycle$replay)))
  expect_setequal(vapply(lifecycle$acks, function(value) {
    .dsvert_joint_dp_vector_decode_json(
      value, "test finalization acknowledgement")$peer_name
  }, character(1L)), fixture$peers)
  expect_identical(
    names(fixture$release_instance$peer_noise_roots), fixture$peers[1:2])
  if (!gaussian) {
    roleless_peer <- fixture$peers[[3L]]
    expect_identical(source_peers, fixture$peers[[1L]])
    expect_false(roleless_peer %in% fixture$peers[1:2])
    roleless_source <- .dsvert_dp_capsule_source_with_store(
      fixture$policies[[roleless_peer]], fixture$secrets[[roleless_peer]],
      function(connection) {
        list(
          receipt = .dsvert_dp_capsule_source_compaction_load(
            connection,
            fixture$manifests[[1L]]$capsule_identity$capsule_id,
            fixture$secrets[[roleless_peer]]),
          state = .dsvert_dp_capsule_source_store_state(
            connection, fixture$secrets[[roleless_peer]]),
          active_rows = sum(vapply(c(
            "source_recipient_keys", "source_outbound",
            "source_outbound_chunks", "source_incoming_state",
            "source_aggregate_chunks", "source_incoming_receipts",
            "source_cross_gaussian_results",
            "source_cross_categorical_results"), function(table) {
              DBI::dbGetQuery(connection, paste(
                "SELECT COUNT(*) AS n FROM", table))$n[[1L]]
            }, numeric(1L))))
      })
    expect_identical(roleless_source$active_rows, 0)
    expect_identical(
      as.numeric(roleless_source$receipt$active_reservation_bytes),
      as.numeric(.DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES))
    expect_identical(as.numeric(roleless_source$receipt$released_bytes), 0)
    expect_identical(
      as.numeric(roleless_source$state$reserved_bytes),
      as.numeric(.DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES))
    roleless_ack <- .dsvert_joint_dp_vector_decode_json(
      lifecycle$acks[[3L]], "roleless K3 acknowledgement")
    roleless_vector <- .dsvert_joint_dp_vector_with_store(
      fixture$policies[[roleless_peer]], fixture$secrets[[roleless_peer]],
      function(connection) .dsvert_joint_dp_vector_capsule_load(
        connection, roleless_ack$release_instance_id,
        fixture$secrets[[roleless_peer]]))
    expect_identical(roleless_vector$state, "acked")
    expect_true(roleless_vector$compacted)
    expect_null(roleless_vector$prepare_receipt_json)
    expect_null(roleless_vector$local_result_json)
    expect_null(roleless_vector$release_receipt_json)
    expect_identical(roleless_vector$ack_receipt_json,
                     lifecycle$acks[[3L]])
  }

  releases <- lapply(lifecycle$releases,
                     .dsvert_joint_dp_vector_decode_json,
                     what = "test release")
  prepares <- lapply(lifecycle$prepares,
                     .dsvert_joint_dp_vector_decode_json,
                     what = "test prepare")
  profile <- .dsvert_joint_dp_vector_profile(
    fixture$manifests[[1L]]$workload$capsule_mechanism$mechanism,
    prepares[[1L]]$backend)
  expect_identical(releases[[1L]]$final_vector_root,
                   releases[[2L]]$final_vector_root)
  expect_identical(releases[[1L]]$mechanism,
                   profile$release_mechanism)
  expect_identical(prepares[[1L]]$backend, profile$backend)
  expect_identical(prepares[[1L]]$sampler, profile$sampler)
  expect_identical(
    .dsvert_joint_dp_hash(prepares[[1L]]$mechanism_plan),
    prepares[[1L]]$plan_sha256)
  if (gaussian) {
    expect_identical(prepares[[1L]]$mechanism_plan$mechanism,
                     .DSVERT_JOINT_DP_GAUSSIAN_MECHANISM)
    expect_match(prepares[[1L]]$sensitivity_steps, "[.eE]")
  }
  replay <- .dsvert_joint_dp_vector_decode_json(
    lifecycle$replay, "test replay")
  expect_length(replay$chunk$scaled_values, length(fixture$expected))
  expect_true(replay$durable_replay)
  expect_false(replay$source_store_read)
  expect_false(replay$sampler_invoked)

  public <- lapply(c(
    lifecycle$prepares, lifecycle$starts, lifecycle$results,
    lifecycle$releases, lifecycle$acks, lifecycle$replay), function(json) {
      .dsvert_joint_dp_vector_decode_json(json, "public transcript")
    })
  public <- c(public, list(lifecycle$final_share))
  expect_setequal(names(lifecycle$final_share), c(
    "ciphertext", "transfer", "capsule_id", "release_contract_hash",
    "result_set_hash", "chunk_index", "intermediate_payload_exposed",
    "capability_available"))
  expect_false(lifecycle$final_share$intermediate_payload_exposed)
  public_names <- unique(unlist(lapply(
    public, .vector_capsule_public_names), use.names = FALSE))
  expect_true(all(vapply(public, function(value) {
    is.null(value$history_gate) || identical(value$history_gate, TRUE)
  }, logical(1L))))
  expect_true(all(vapply(public, function(value) {
    is.null(value$request_limit) || identical(value$request_limit, FALSE)
  }, logical(1L))))
  expect_true(all(vapply(public, function(value) {
    is.null(value$operation_limit) || identical(value$operation_limit, TRUE)
  }, logical(1L))))
  forbidden <- c(
    "private_seed", "noise_root", "noise_root_key", "identity_sk",
    "transport_sk", "source_share", "aggregate_b64", "noised_share",
    "noised_share_b64", "noise_values", "preclamp_values")
  expect_false(any(public_names %in% forbidden))
  public_text <- paste(unlist(public, use.names = FALSE), collapse = "\n")
  private_seed <- .dsvert_joint_dp_vector_seed(
    fixture$policies$peer_a,
    testthat::with_mocked_bindings(
      .dsvert_joint_dp_vector_contract(
        fixture$policies$peer_a, fixture$manifest_json,
        fixture$release_instance_json, fixture$planner,
        secret = fixture$secrets$peer_a),
      .dsvert_dp_capsule_manifest_require_built = function(...) TRUE,
      .package = "dsVert"))
  expect_false(grepl(private_seed, public_text, fixed = TRUE))
  expect_false(any(vapply(fixture$source_shares, function(share) {
    encoded <- gsub("[\r\n]", "", jsonlite::base64_enc(share))
    grepl(encoded, public_text, fixed = TRUE)
  }, logical(1L))))

  for (peer in fixture$peers[1:2]) {
    durable <- .dsvert_joint_dp_vector_with_store(
      fixture$policies[[peer]], fixture$secrets[[peer]],
      function(connection) {
        config <- .dsvert_joint_dp_release_ledger_config_from_policy(
          fixture$policies[[peer]])
        list(
          counts = c(
            noised = DBI::dbGetQuery(connection,
              "SELECT COUNT(*) AS n FROM vector_noised_chunks")$n[[1L]],
            final = DBI::dbGetQuery(connection,
              "SELECT COUNT(*) AS n FROM vector_final_chunks")$n[[1L]]),
          release = .dsvert_joint_dp_release_ledger_status(
            connection, config, fixture$secrets[[peer]]),
          marker = DBI::dbGetQuery(connection, paste(
            "SELECT value FROM vector_meta",
            "WHERE key='release_ledger_backfill'")))
      })
    counts <- durable$counts
    expect_identical(as.numeric(counts[["noised"]]), 0)
    expect_identical(as.numeric(counts[["final"]]), 1)
    expect_identical(durable$release$release_instance_count, 1)
    expect_true(durable$release$operation_limit)
    expect_false(durable$release$request_limit)
    expect_true(durable$release$history_can_deny_operation)
    expect_identical(nrow(durable$marker), 1L)
  }

  .dsvert_joint_dp_vector_with_store(
    fixture$policies$peer_a, fixture$secrets$peer_a,
    function(connection) {
      DBI::dbExecute(connection, paste(
        "UPDATE vector_meta SET value=?,row_mac=?",
        "WHERE key='release_domain'"),
        params = list("{\"corrupt\":true}", strrep("0", 64L)))
      DBI::dbExecute(connection, paste(
        "UPDATE vector_final_chunks SET row_mac=?",
        "WHERE release_instance_id=?"), params = list(
          strrep("0", 64L),
          .dsvert_joint_dp_hash(fixture$release_instance)))
    })
  expect_error(
    .dsvert_joint_dp_release_domain_current(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      random_bytes = function(...) {
        stop("tampered durable evidence must not cause regeneration")
      }),
    "failed private-store authentication")

  .dsvert_joint_dp_vector_with_store(
    fixture$policies$peer_b, fixture$secrets$peer_b,
    function(connection) {
      DBI::dbExecute(connection, paste(
        "UPDATE vector_meta SET value=?,row_mac=?",
        "WHERE key='release_domain'"),
        params = list("{\"corrupt\":true}", strrep("0", 64L)))
      DBI::dbExecute(connection,
        "UPDATE vector_release_ledger_records SET row_mac=?",
        params = list(strrep("0", 64L)))
    })
  expect_error(
    .dsvert_joint_dp_release_domain_current(
      fixture$policies$peer_b, fixture$secrets$peer_b,
      random_bytes = function(...) {
        stop("tampered ledger evidence must not cause regeneration")
      }),
    "authentication")

  vector_path <- .dsvert_joint_dp_vector_store_path(
    lifecycle$rotated_policies$peer_a)
  unlink(c(vector_path, paste0(vector_path, c("-wal", "-shm"))),
         force = TRUE)
  missing_condition <- testthat::with_mocked_bindings(
    tryCatch(.dsvert_joint_dp_vector_replay_impl(
      fixture$manifest_json,
      lifecycle$releases[[1L]], lifecycle$releases[[2L]], 0L,
      .policy = lifecycle$rotated_policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .verifier = fixture$verifier), error = identity),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .package = "dsVert")
  expect_s3_class(
    missing_condition, "dsvert_dp_release_retry_current_instance")
  expect_identical(
    missing_condition$code,
    .DSVERT_JOINT_DP_VECTOR_RETRY_CURRENT_INSTANCE_TOKEN)
  expect_identical(
    missing_condition$retry_action, "new_release_instance")
  rematerialize_condition <- testthat::with_mocked_bindings(
    tryCatch(.dsvert_joint_dp_vector_release_impl(
      "invalid-session", fixture$manifest_json,
      lifecycle$results[[1L]], lifecycle$results[[2L]],
      .policy = lifecycle$rotated_policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .verifier = fixture$verifier,
      .planner = function(...) stop("historical planner must not rerun")),
    error = identity),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .dsvert_joint_dp_vector_allocation_require =
      .vector_capsule_allocation_local,
    .package = "dsVert")
  expect_s3_class(
    rematerialize_condition, "dsvert_dp_release_retry_current_instance")
  expect_identical(
    rematerialize_condition$code,
    .DSVERT_JOINT_DP_VECTOR_RETRY_CURRENT_INSTANCE_TOKEN)
  expect_identical(
    rematerialize_condition$retry_action, "new_release_instance")
 }
})

test_that("PREPARE crosses manifest, sticky-root and persistent identity barriers", {
  fixture <- .vector_capsule_fixture()
  events <- character()
  peer <- "peer_a"
  receipt <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_prepare_impl(
      fixture$manifest_json, fixture$release_instance_json,
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .planner = fixture$planner),
    .dsvert_dp_capsule_manifest_require_built = function(...) {
      events <<- c(events, "manifest")
      invisible(TRUE)
    },
    .dsvert_joint_dp_vector_allocation_require = function(...) {
      events <<- c(events, "allocation_local")
      .vector_capsule_allocation_local(...)
    },
    .dsvert_joint_dp_vector_allocation_observer_require = function(...) {
      events <<- c(events, "allocation_openings")
      .vector_capsule_allocation_observer(...)
    },
    .dsvert_dp_noise_seed = function(...) {
      events <<- c(events, "sticky_seed")
      strrep("1", 64L)
    },
    .get_identity_keypair = function() {
      events <<- c(events, "persistent_identity")
      list(identity_pk = unname(fixture$policies[[peer]]$peer_pinset[[peer]]),
           identity_sk = "test-private-identity-handle")
    },
    .dsvert_relay_sign_message = function(...) {
      events <<- c(events, "signed")
      strrep("A", 86L)
    },
    .dsvert_secure_random_bytes = function(...) {
      stop("PREPARE must not create an ephemeral identity or seed")
    },
    .package = "dsVert")
  expect_identical(
    events, c(
      "manifest", "allocation_local", "allocation_openings",
      "sticky_seed", "persistent_identity", "signed"))
  replay <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_prepare_impl(
      fixture$manifest_json, fixture$release_instance_json,
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .planner = function(...) stop("planner must not rerun")),
    .dsvert_dp_capsule_manifest_require_built = function(...) {
      stop("manifest gate must not rerun")
    },
    .dsvert_joint_dp_vector_allocation_require = function(...) {
      stop("allocation must not rerun")
    },
    .dsvert_joint_dp_vector_allocation_observer_require = function(...) {
      stop("allocation observer must not rerun")
    },
    .dsvert_dp_noise_seed = function(...) stop("seed must not rerun"),
    .get_identity_keypair = function(...) stop("signer must not rerun"),
    .package = "dsVert")
  expect_identical(replay, receipt)
  decoded <- .dsvert_joint_dp_vector_decode_json(receipt, "prepare test")
  expect_true(grepl("^[0-9a-f]{64}$", decoded$seed_commitment))
  expect_false("private_seed" %in% names(decoded))
})

test_that("unilateral rotation permits prepares but atomically claims one START", {
  fixture <- .vector_capsule_fixture()
  gate <- function(...) invisible(TRUE)
  prepare <- function(policy, instance_json, peer) {
    .dsvert_joint_dp_vector_prepare_impl(
      fixture$manifest_json, instance_json,
      .policy = policy, .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .planner = fixture$planner)
  }
  values <- testthat::with_mocked_bindings({
    old <- stats::setNames(lapply(fixture$peers[1:2], function(peer) {
      prepare(fixture$policies[[peer]], fixture$release_instance_json, peer)
    }), fixture$peers[1:2])
    replay <- prepare(
      fixture$policies$peer_a, fixture$release_instance_json, "peer_a")

    rotated_policies <- fixture$policies
    rotated_policies$peer_b$noise_root$epoch <- 2
    rotated_policies$peer_b$noise_root$key_id <- "test_rotated_peer_b"
    rotated <- fixture$release_instance
    rotated$peer_noise_roots$peer_b <- list(
      privacy_epoch = 2,
      noise_key_id = rotated_policies$peer_b$noise_root$key_id,
      provider_id = rotated_policies$peer_b$noise_root$provider_id,
      release_domain_generation = as.numeric(
        fixture$release_domains$peer_b$generation),
      release_domain_id =
        fixture$release_domains$peer_b$domain_id)
    rotated_json <- .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(rotated))
    fresh <- stats::setNames(lapply(fixture$peers[1:2], function(peer) {
      prepare(rotated_policies[[peer]], rotated_json, peer)
    }), fixture$peers[1:2])
    list(old = old, replay = replay, fresh = fresh,
         rotated = rotated, rotated_json = rotated_json,
         rotated_policies = rotated_policies)
  }, .dsvert_dp_capsule_manifest_require_built = gate,
  .dsvert_joint_dp_vector_allocation_require =
    .vector_capsule_allocation_local,
  .dsvert_joint_dp_vector_allocation_observer_require =
    .vector_capsule_allocation_observer,
  .package = "dsVert")

  old <- lapply(values$old, .dsvert_joint_dp_vector_decode_json,
                what = "old prepare")
  fresh <- lapply(values$fresh, .dsvert_joint_dp_vector_decode_json,
                  what = "fresh prepare")
  expect_identical(values$replay, values$old$peer_a)
  expect_length(unique(vapply(old, `[[`, character(1L),
                              "release_instance_id")), 1L)
  expect_length(unique(vapply(fresh, `[[`, character(1L),
                              "release_instance_id")), 1L)
  expect_false(identical(old[[1L]]$release_instance_id,
                         fresh[[1L]]$release_instance_id))
  expect_identical(old[[1L]]$capsule_id, fresh[[1L]]$capsule_id)
  for (peer in fixture$peers[1:2]) {
    count <- .dsvert_joint_dp_vector_with_store(
      values$rotated_policies[[peer]], fixture$secrets[[peer]],
      function(connection) DBI::dbGetQuery(
        connection, "SELECT COUNT(*) AS n FROM vector_capsules")$n[[1L]])
    expect_identical(as.numeric(count), 2)
  }

  candidates <- list(
    old = list(prepares = values$old,
               instance_json = fixture$release_instance_json),
    fresh = list(prepares = values$fresh,
                 instance_json = values$rotated_json))
  run_start <- function(candidate) {
    source_calls <- 0L
    sampler_calls <- 0L
    outcome <- testthat::with_mocked_bindings(
      tryCatch({
        receipt <- .dsvert_joint_dp_vector_start_impl(
          fixture$manifest_json,
          candidate$prepares$peer_a, candidate$prepares$peer_b, 0L,
          .policy = values$rotated_policies$peer_a,
          .secret = fixture$secrets$peer_a,
          .signer = fixture$signer, .verifier = fixture$verifier,
          .planner = fixture$planner,
          .source_reader = function(...) {
            source_calls <<- source_calls + 1L
            fixture$source_shares$peer_a
          },
          .sampler = function(value) {
            sampler_calls <<- sampler_calls + 1L
            fixture$sampler(value)
          })
        list(ok = TRUE, receipt = receipt, classes = character(),
             message = "")
      }, error = function(error) list(
        ok = FALSE, receipt = NULL, classes = class(error),
        message = conditionMessage(error))),
      .dsvert_dp_capsule_manifest_require_built = gate,
      .package = "dsVert")
    c(outcome, list(source_calls = source_calls,
                    sampler_calls = sampler_calls))
  }
  starts <- if (.Platform$OS.type == "windows") {
    lapply(candidates, run_start)
  } else {
    parallel::mclapply(
      candidates, run_start, mc.cores = 2L, mc.preschedule = FALSE)
  }
  succeeded <- vapply(starts, `[[`, logical(1L), "ok")
  expect_identical(sum(succeeded), 1L)
  expect_identical(sum(vapply(
    starts, `[[`, integer(1L), "source_calls")), 1L)
  expect_identical(sum(vapply(
    starts, `[[`, integer(1L), "sampler_calls")), 1L)
  denied <- starts[[which(!succeeded)]]
  expect_true("dsvert_dp_lifetime_budget_exhausted" %in% denied$classes)
  expect_identical(denied$message,
                   .DSVERT_DP_LIFETIME_BUDGET_EXHAUSTED_MESSAGE)

  winner_name <- names(candidates)[[which(succeeded)]]
  winner <- candidates[[winner_name]]
  sibling <- candidates[[setdiff(names(candidates), winner_name)]]
  replay <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_start_impl(
      fixture$manifest_json,
      winner$prepares$peer_a, winner$prepares$peer_b, 0L,
      .policy = values$rotated_policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .signer = fixture$signer, .verifier = fixture$verifier,
      .planner = fixture$planner,
      .source_reader = function(...) stop("source must not rerun"),
      .sampler = function(...) stop("sampler must not rerun")),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .package = "dsVert")
  expect_identical(replay, starts[[which(succeeded)]]$receipt)

  locally_rotated <- values$rotated_policies$peer_a
  locally_rotated$noise_root$epoch <-
    locally_rotated$noise_root$epoch + 1
  locally_rotated$noise_root$key_id <- "test_rotated_local_after_claim"
  stale_claimed <- tryCatch(.dsvert_joint_dp_vector_start_impl(
    fixture$manifest_json,
    winner$prepares$peer_a, winner$prepares$peer_b, 0L,
    .policy = locally_rotated, .secret = fixture$secrets$peer_a,
    .planner = function(...) stop("planner must not run after rotation"),
    .source_reader = function(...) stop("source must not run after rotation"),
    .sampler = function(...) stop("sampler must not run after rotation")),
    error = identity)
  expect_s3_class(
    stale_claimed, "dsvert_dp_lifetime_budget_exhausted")

  sibling_prepare <- tryCatch(.dsvert_joint_dp_vector_prepare_impl(
    fixture$manifest_json, sibling$instance_json,
    .policy = values$rotated_policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .planner = function(...) stop("planner must not run"),
    .allocation_local = function(...) stop("allocation must not run"),
    .allocation_observer = function(...) {
      stop("allocation observer must not run")
    }), error = identity)
  expect_s3_class(sibling_prepare, "dsvert_dp_lifetime_budget_exhausted")

  tamper <- .dsvert_joint_dp_vector_with_store(
    values$rotated_policies$peer_a, fixture$secrets$peer_a,
    function(connection) {
      config <- .dsvert_joint_dp_release_ledger_config_from_policy(
        values$rotated_policies$peer_a)
      baseline <- .dsvert_joint_dp_vector_release_ledger_cache_key(
        connection, config)
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT row_mac FROM vector_instance_claims WHERE capsule_id=?"),
        params = list(fixture$release_instance$capsule_id))
      expect_identical(nrow(row), 1L)
      DBI::dbExecute(connection, paste(
        "UPDATE vector_instance_claims SET row_mac=? WHERE capsule_id=?"),
        params = list(strrep("0", 64L),
                      fixture$release_instance$capsule_id))
      changed <- .dsvert_joint_dp_vector_release_ledger_cache_key(
        connection, config)
      condition <- tryCatch(
        .dsvert_joint_dp_vector_instance_claim_load(
          connection, fixture$release_instance$capsule_id,
          fixture$secrets$peer_a),
        error = identity)
      DBI::dbExecute(connection, paste(
        "UPDATE vector_instance_claims SET row_mac=? WHERE capsule_id=?"),
        params = list(row$row_mac[[1L]],
                      fixture$release_instance$capsule_id))
      claim <- .dsvert_joint_dp_vector_instance_claim_load(
        connection, fixture$release_instance$capsule_id,
        fixture$secrets$peer_a)
      DBI::dbExecute(connection,
        "DELETE FROM vector_instance_claims WHERE capsule_id=?",
        params = list(claim$capsule_id))
      deleted_key <- .dsvert_joint_dp_vector_release_ledger_cache_key(
        connection, config)
      deletion_condition <- tryCatch(
        .dsvert_joint_dp_vector_instance_claim_state_validate_connection(
          connection, fixture$secrets$peer_a),
        error = identity)
      .dsvert_joint_dp_vector_record_insert(
        connection, "vector_instance_claims",
        c("capsule_id", "release_instance_id", "release_contract_hash"),
        list(claim$capsule_id, claim$release_instance_id,
             claim$release_contract_hash), claim,
        fixture$secrets$peer_a)
      .dsvert_joint_dp_vector_instance_claim_state_validate_connection(
        connection, fixture$secrets$peer_a)
      list(cache_changed = !identical(changed, baseline),
           deletion_cache_changed = !identical(deleted_key, baseline),
           condition = condition,
           deletion_condition = deletion_condition)
    })
  expect_true(tamper$cache_changed)
  expect_s3_class(tamper$condition, "error")
  expect_match(conditionMessage(tamper$condition),
               "claim failed private-store authentication")
  expect_true(tamper$deletion_cache_changed)
  expect_s3_class(tamper$deletion_condition, "error")
  expect_match(conditionMessage(tamper$deletion_condition),
               "claim state is inconsistent")
})

test_that("bilateral split claims cannot form a release pair", {
  fixture <- .vector_capsule_fixture()
  gate <- function(...) invisible(TRUE)
  rotated_policies <- fixture$policies
  rotated_policies$peer_b$noise_root$epoch <- 2
  rotated_policies$peer_b$noise_root$key_id <- "test_split_peer_b"
  fresh_instance <- fixture$release_instance
  fresh_instance$peer_noise_roots$peer_b <- list(
    privacy_epoch = 2,
    noise_key_id = rotated_policies$peer_b$noise_root$key_id,
    provider_id = rotated_policies$peer_b$noise_root$provider_id,
    release_domain_generation = as.numeric(
      fixture$release_domains$peer_b$generation),
    release_domain_id = fixture$release_domains$peer_b$domain_id)
  fresh_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(fresh_instance))
  prepare <- function(policy, secret, instance_json) {
    .dsvert_joint_dp_vector_prepare_impl(
      fixture$manifest_json, instance_json,
      .policy = policy, .secret = secret,
      .signer = fixture$signer, .planner = fixture$planner)
  }
  prepared <- testthat::with_mocked_bindings({
    old <- stats::setNames(lapply(fixture$peers[1:2], function(peer) {
      prepare(fixture$policies[[peer]], fixture$secrets[[peer]],
              fixture$release_instance_json)
    }), fixture$peers[1:2])
    fresh <- stats::setNames(lapply(fixture$peers[1:2], function(peer) {
      prepare(rotated_policies[[peer]], fixture$secrets[[peer]], fresh_json)
    }), fixture$peers[1:2])
    list(old = old, fresh = fresh)
  }, .dsvert_dp_capsule_manifest_require_built = gate,
  .dsvert_joint_dp_vector_allocation_require =
    .vector_capsule_allocation_local,
  .dsvert_joint_dp_vector_allocation_observer_require =
    .vector_capsule_allocation_observer,
  .package = "dsVert")

  source_calls <- stats::setNames(integer(2L), fixture$peers[1:2])
  sampler_calls <- stats::setNames(integer(2L), fixture$peers[1:2])
  start <- function(peer, receipts, policy) {
    .dsvert_joint_dp_vector_start_impl(
      fixture$manifest_json,
      receipts$peer_a, receipts$peer_b, 0L,
      .policy = policy, .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .verifier = fixture$verifier,
      .planner = fixture$planner,
      .source_reader = function(...) {
        source_calls[[peer]] <<- source_calls[[peer]] + 1L
        fixture$source_shares[[peer]]
      },
      .sampler = function(value) {
        sampler_calls[[peer]] <<- sampler_calls[[peer]] + 1L
        fixture$sampler(value)
      })
  }
  testthat::with_mocked_bindings({
    start("peer_a", prepared$old, fixture$policies$peer_a)
    start("peer_b", prepared$fresh, rotated_policies$peer_b)
  }, .dsvert_dp_capsule_manifest_require_built = gate,
  .package = "dsVert")
  expect_identical(unname(source_calls), c(1L, 1L))
  expect_identical(unname(sampler_calls), c(1L, 1L))

  blocked_source <- 0L
  blocked_sampler <- 0L
  blocked_start <- function(peer, receipts, policy) {
    testthat::with_mocked_bindings(
      tryCatch(.dsvert_joint_dp_vector_start_impl(
        fixture$manifest_json,
        receipts$peer_a, receipts$peer_b, 0L,
        .policy = policy, .secret = fixture$secrets[[peer]],
        .planner = fixture$planner,
        .source_reader = function(...) {
          blocked_source <<- blocked_source + 1L
          stop("blocked source must not run")
        },
        .sampler = function(...) {
          blocked_sampler <<- blocked_sampler + 1L
          stop("blocked sampler must not run")
        }), error = identity),
      .dsvert_dp_capsule_manifest_require_built = gate,
      .package = "dsVert")
  }
  blocked_a <- blocked_start(
    "peer_a", prepared$fresh, rotated_policies$peer_a)
  blocked_b <- blocked_start(
    "peer_b", prepared$old, fixture$policies$peer_b)
  expect_s3_class(blocked_a, "dsvert_dp_lifetime_budget_exhausted")
  expect_s3_class(blocked_b, "dsvert_dp_lifetime_budget_exhausted")
  expect_identical(blocked_source, 0L)
  expect_identical(blocked_sampler, 0L)

  result <- function(peer, receipts, policy) {
    testthat::with_mocked_bindings(
      .dsvert_joint_dp_vector_result_impl(
        fixture$manifest_json, receipts$peer_a, receipts$peer_b,
        .policy = policy, .secret = fixture$secrets[[peer]],
        .signer = fixture$signer, .verifier = fixture$verifier,
        .planner = fixture$planner),
      .dsvert_dp_capsule_manifest_require_built = gate,
      .package = "dsVert")
  }
  local_results <- list(
    peer_a = result("peer_a", prepared$old, fixture$policies$peer_a),
    peer_b = result("peer_b", prepared$fresh, rotated_policies$peer_b))
  opposite_a <- tryCatch(
    result("peer_a", prepared$fresh, rotated_policies$peer_a),
    error = identity)
  opposite_b <- tryCatch(
    result("peer_b", prepared$old, fixture$policies$peer_b),
    error = identity)
  expect_s3_class(opposite_a, "dsvert_dp_lifetime_budget_exhausted")
  expect_s3_class(opposite_b, "dsvert_dp_lifetime_budget_exhausted")

  session_id <- "00000000-0000-4000-8000-000000000099"
  session <- new.env(parent = emptyenv())
  session$session_id <- session_id
  encryptor_calls <- 0L
  mixed_share <- tryCatch(.dsvert_joint_dp_vector_final_share_impl(
    session_id, fixture$manifest_json,
    local_results$peer_a, local_results$peer_b, 0L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .planner = fixture$planner, .session = session,
    .encryptor = function(...) {
      encryptor_calls <<- encryptor_calls + 1L
      stop("encryptor must not run")
    }), error = identity)
  expect_s3_class(mixed_share, "error")
  expect_identical(encryptor_calls, 0L)

  finalizer_calls <- 0L
  mixed_release <- tryCatch(.dsvert_joint_dp_vector_release_impl(
    session_id, fixture$manifest_json,
    local_results$peer_a, local_results$peer_b,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .planner = fixture$planner, .session = session,
    .finalizer = function(...) {
      finalizer_calls <<- finalizer_calls + 1L
      stop("finalizer must not run")
    }), error = identity)
  expect_s3_class(mixed_release, "error")
  expect_identical(finalizer_calls, 0L)
})

test_that("claim insertion rejects delete triggers and verifies its row", {
  fixture <- .vector_capsule_fixture()
  gate <- function(...) invisible(TRUE)
  testthat::with_mocked_bindings(
    lapply(fixture$peers[1:2], function(peer) {
      .dsvert_joint_dp_vector_prepare_impl(
        fixture$manifest_json, fixture$release_instance_json,
        .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = fixture$signer, .planner = fixture$planner)
    }),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .dsvert_joint_dp_vector_allocation_require =
      .vector_capsule_allocation_local,
    .dsvert_joint_dp_vector_allocation_observer_require =
      .vector_capsule_allocation_observer,
    .package = "dsVert")
  contracts <- testthat::with_mocked_bindings(
    lapply(fixture$peers[1:2], function(peer) {
      .dsvert_joint_dp_vector_contract(
        fixture$policies[[peer]], fixture$manifest_json,
        fixture$release_instance_json, fixture$planner,
        secret = fixture$secrets[[peer]])
    }),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .package = "dsVert")

  persistent_path <- .dsvert_joint_dp_vector_store_path(
    fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), persistent_path)
  state_before <- DBI::dbGetQuery(connection, paste(
    "SELECT value,row_mac FROM vector_meta",
    "WHERE key='release_instance_claim_state'"))
  DBI::dbExecute(connection, paste(
    "CREATE TRIGGER vector_claim_delete_after_insert",
    "AFTER INSERT ON vector_instance_claims BEGIN",
    "DELETE FROM vector_instance_claims",
    "WHERE capsule_id=NEW.capsule_id; END"))
  DBI::dbDisconnect(connection)
  Sys.chmod(persistent_path, mode = "0600")
  persistent <- tryCatch(
    .dsvert_joint_dp_vector_instance_claim_contract(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      contracts[[1L]], create = TRUE),
    error = identity)
  expect_s3_class(persistent, "error")
  expect_match(conditionMessage(persistent), "store schema is invalid")
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), persistent_path, flags = RSQLite::SQLITE_RO)
  persistent_after <- list(
    claims = DBI::dbGetQuery(connection,
      "SELECT COUNT(*) AS n FROM vector_instance_claims")$n[[1L]],
    state = DBI::dbGetQuery(connection, paste(
      "SELECT value,row_mac FROM vector_meta",
      "WHERE key='release_instance_claim_state'")),
    triggers = DBI::dbGetQuery(connection,
      "SELECT COUNT(*) AS n FROM sqlite_master WHERE type='trigger'")$n[[1L]])
  DBI::dbDisconnect(connection)
  expect_identical(as.numeric(persistent_after$claims), 0)
  expect_identical(as.numeric(persistent_after$triggers), 1)
  expect_identical(persistent_after$state, state_before)

  temporary <- .dsvert_joint_dp_vector_with_store(
    fixture$policies$peer_b, fixture$secrets$peer_b,
    function(connection) {
      config <- .dsvert_joint_dp_release_ledger_config_from_policy(
        fixture$policies$peer_b)
      state_before <- DBI::dbGetQuery(connection, paste(
        "SELECT value,row_mac FROM vector_meta",
        "WHERE key='release_instance_claim_state'"))
      DBI::dbExecute(connection, paste(
        "CREATE TEMP TRIGGER vector_claim_temp_delete_after_insert",
        "AFTER INSERT ON vector_instance_claims BEGIN",
        "DELETE FROM vector_instance_claims",
        "WHERE capsule_id=NEW.capsule_id; END"))
      condition <- tryCatch(
        .dsvert_joint_dp_vector_transaction(connection, {
          .dsvert_joint_dp_vector_instance_claim_acquire_connection(
            connection, config, fixture$secrets$peer_b,
            contracts[[2L]]$release_contract$capsule_id,
            contracts[[2L]]$release_contract$release_instance_id,
            contracts[[2L]]$release_contract_hash)
        }), error = identity)
      state_after <- DBI::dbGetQuery(connection, paste(
        "SELECT value,row_mac FROM vector_meta",
        "WHERE key='release_instance_claim_state'"))
      claims <- DBI::dbGetQuery(connection,
        "SELECT COUNT(*) AS n FROM vector_instance_claims")$n[[1L]]
      DBI::dbExecute(connection,
        "DROP TRIGGER vector_claim_temp_delete_after_insert")
      list(condition = condition, claims = claims,
           state_before = state_before, state_after = state_after)
    })
  expect_s3_class(temporary$condition, "error")
  expect_match(conditionMessage(temporary$condition),
               "has no durable capsule claim")
  expect_identical(as.numeric(temporary$claims), 0)
  expect_identical(temporary$state_after, temporary$state_before)
})

test_that("a published sibling is rejected at admission before any finalizer", {
  fixture <- .vector_capsule_fixture()
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  gate <- function(...) invisible(TRUE)
  testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_prepare_impl(
      fixture$manifest_json, fixture$release_instance_json,
      .policy = policy, .secret = secret,
      .signer = fixture$signer, .planner = fixture$planner),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .dsvert_joint_dp_vector_allocation_require =
      .vector_capsule_allocation_local,
    .dsvert_joint_dp_vector_allocation_observer_require =
      .vector_capsule_allocation_observer,
    .package = "dsVert")
  contract <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_contract(
      policy, fixture$manifest_json, fixture$release_instance_json,
      fixture$planner, secret = secret),
    .dsvert_dp_capsule_manifest_require_built = gate,
    .package = "dsVert")
  .dsvert_joint_dp_vector_instance_claim_contract(
    policy, secret, contract, create = TRUE)

  sibling <- fixture$release_instance
  sibling$peer_noise_roots$peer_b$privacy_epoch <- 2
  sibling$peer_noise_roots$peer_b$noise_key_id <-
    "test_published_sibling_peer_b"
  sibling <- .dsvert_dp_canonical_query_value(sibling)
  sibling_json <- .dsvert_dp_canonical_json(sibling)
  sibling_id <- .dsvert_joint_dp_hash(sibling)
  sibling_release <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(list(
      version = .DSVERT_JOINT_DP_VECTOR_RELEASE_VERSION,
      phase = "vector_released", peer_name = policy$peer_name,
      capsule_id = sibling$capsule_id,
      release_instance_id = sibling_id,
      final_vector_root = strrep("d", 64L),
      epsilon = contract$release_contract$epsilon,
      delta = contract$release_contract$allocated_delta)))
  finalizer_calls <- 0L
  observed <- .dsvert_joint_dp_vector_with_store(
    policy, secret, function(connection) {
      config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
      condition <- .dsvert_joint_dp_vector_transaction(connection, {
        .dsvert_joint_dp_release_ledger_commit_connection(
          connection, config, secret, sibling_json, sibling_release)
        tryCatch({
          .dsvert_joint_dp_vector_release_admit_connection(
            connection, policy, secret, contract)
          finalizer_calls <<- finalizer_calls + 1L
          NULL
        }, error = identity)
      })
      list(
        condition = condition,
        ledger_count = DBI::dbGetQuery(connection, paste(
          "SELECT COUNT(*) AS n FROM vector_release_ledger_records"))$n[[1L]])
    })
  expect_identical(as.numeric(observed$ledger_count), 1)
  expect_s3_class(
    observed$condition, "dsvert_dp_lifetime_budget_exhausted")
  expect_identical(finalizer_calls, 0L)
})

test_that("legacy public vector releases are backfilled exactly once", {
  fixture <- .vector_capsule_fixture()
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  instance <- .dsvert_dp_canonical_query_value(fixture$release_instance)
  instance_id <- .dsvert_joint_dp_hash(instance)
  release_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(list(
      version = .DSVERT_JOINT_DP_VECTOR_RELEASE_VERSION,
      phase = "vector_released", peer_name = "peer_a",
      capsule_id = instance$capsule_id,
      release_instance_id = instance_id,
      final_vector_root = strrep("d", 64L),
      epsilon = .dsvert_joint_dp_decimal(
        policy$global_total_epsilon, "legacy vector epsilon",
        open_minimum = TRUE),
      delta = .dsvert_joint_dp_decimal(
        policy$global_total_delta, "legacy vector delta"))))
  legacy <- list(
    version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
    capsule_id = instance$capsule_id,
    release_instance_id = instance_id,
    release_contract_hash = .dsvert_joint_dp_hash(list(
      test = "legacy-public-vector-release-contract")),
    state = "released", compacted = FALSE,
    release_contract = list(release_instance = instance),
    release_receipt_json = release_json)

  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    .dsvert_joint_dp_vector_transaction(connection, {
      DBI::dbExecute(connection, paste(
        "DELETE FROM vector_meta",
        "WHERE key='release_ledger_backfill'"))
      DBI::dbExecute(connection,
        "DROP TABLE vector_release_ledger_state")
      DBI::dbExecute(connection,
        "DROP TABLE vector_release_ledger_records")
      DBI::dbExecute(connection,
        "DROP TABLE vector_release_ledger_meta")
      .dsvert_joint_dp_vector_capsule_put(
        connection, legacy, secret, existing = NULL)
    })
  })

  legacy_history <- .dsvert_joint_dp_release_ledger_history_from_path(
    .dsvert_joint_dp_vector_store_path(policy), secret)
  expect_identical(legacy_history$status, "used")
  expect_identical(legacy_history$source,
                   "vector_release_instances_legacy")
  expect_identical(legacy_history$count, 1L)
  expect_identical(legacy_history$privacy_epoch, 1)
  expect_identical(
    legacy_history$noise_key_id,
    instance$peer_noise_roots$peer_a$noise_key_id)

  observed <- .dsvert_joint_dp_vector_with_store(
    policy, secret, function(connection) {
      config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
      list(
        status = .dsvert_joint_dp_release_ledger_status(
          connection, config, secret),
        marker = DBI::dbGetQuery(connection, paste(
          "SELECT value,row_mac FROM vector_meta",
          "WHERE key='release_ledger_backfill'")))
    })
  expect_identical(observed$status$release_instance_count, 1)
  expect_identical(nrow(observed$marker), 1L)

  replay <- .dsvert_joint_dp_vector_with_store(
    policy, secret, function(connection) {
      config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
      .dsvert_joint_dp_release_ledger_status(connection, config, secret)
    })
  expect_identical(replay$release_instance_count, 1)

  valid_marker <- observed$marker
  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    DBI::dbExecute(connection, paste(
      "UPDATE vector_meta SET row_mac=?",
      "WHERE key='release_ledger_backfill'"),
      params = list(strrep("0", 64L)))
  })
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      policy, secret, function(connection) invisible(connection)),
    "backfill marker failed authentication")
  path <- .dsvert_joint_dp_vector_store_path(policy)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, paste(
    "UPDATE vector_meta SET value=?,row_mac=?",
    "WHERE key='release_ledger_backfill'"),
    params = unname(as.list(valid_marker[1L, c("value", "row_mac")])))
  DBI::dbDisconnect(connection)
  Sys.chmod(path, mode = "0600")

  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    DBI::dbExecute(connection, paste(
      "UPDATE vector_meta SET value=?,row_mac=?",
      "WHERE key='release_domain'"),
      params = list("{\"corrupt\":true}", strrep("0", 64L)))
  })
  legacy_domain <- .dsvert_joint_dp_release_domain_current(
    policy, secret, random_bytes = function(size) as.raw(rep(8L, size)))
  expect_identical(legacy_domain$reason, "corrupt_record_recovery")

  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    .dsvert_joint_dp_vector_transaction(connection, {
      DBI::dbExecute(connection,
        "DROP TABLE vector_release_ledger_state")
    })
  })
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      policy, secret, function(connection) invisible(connection)),
    "removed after migration")

  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, "DROP TABLE vector_release_ledger_records")
  DBI::dbExecute(connection, "DROP TABLE vector_release_ledger_meta")
  DBI::dbDisconnect(connection)
  Sys.chmod(path, mode = "0600")
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      policy, secret, function(connection) invisible(connection)),
    "removed after migration")
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), path, flags = RSQLite::SQLITE_RO)
  release_tables <- DBI::dbGetQuery(connection, paste(
    "SELECT name FROM sqlite_master WHERE type='table'",
    "AND name LIKE 'vector_release_ledger_%'"))$name
  DBI::dbDisconnect(connection)
  expect_length(release_tables, 0L)
  expect_error(
    .dsvert_joint_dp_release_ledger_history_from_path(
      path, secret),
    "removed after migration")
})

test_that("selective release-ledger rollback cannot erase capsule accounting", {
  fixture <- .vector_capsule_fixture()
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  first <- .dsvert_dp_canonical_query_value(fixture$release_instance)
  second <- first
  second$capsule_id <- strrep("b", 64L)
  second <- .dsvert_dp_canonical_query_value(second)
  make_release <- function(instance, root) {
    instance_json <- .dsvert_dp_canonical_json(instance)
    instance_id <- .dsvert_joint_dp_hash(instance)
    release_json <- .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(list(
        version = .DSVERT_JOINT_DP_VECTOR_RELEASE_VERSION,
        phase = "vector_released", peer_name = policy$peer_name,
        capsule_id = instance$capsule_id,
        release_instance_id = instance_id,
        final_vector_root = root,
        epsilon = .dsvert_joint_dp_decimal(
          policy$global_total_epsilon, "rollback-test epsilon",
          open_minimum = TRUE),
        delta = .dsvert_joint_dp_decimal(
          policy$global_total_delta, "rollback-test delta"))))
    list(
      instance_json = instance_json, release_json = release_json,
      record = list(
        version = .DSVERT_JOINT_DP_VECTOR_STORE_VERSION,
        capsule_id = instance$capsule_id,
        release_instance_id = instance_id, state = "released",
        release_contract_hash = .dsvert_joint_dp_hash(list(
          test = "rollback-release-contract",
          release_instance_id = instance_id)),
        compacted = FALSE,
        release_contract = list(release_instance = instance),
        release_receipt_json = release_json))
  }
  releases <- list(
    make_release(first, strrep("d", 64L)),
    make_release(second, strrep("e", 64L)))
  suffixes <- c("meta", "records", "state")
  snapshots <- list()
  snapshot <- function(connection, name) {
    value <- stats::setNames(lapply(suffixes, function(suffix) {
      DBI::dbReadTable(
        connection, paste0("vector_release_ledger_", suffix))
    }), suffixes)
    snapshots[[name]] <<- value
    invisible(value)
  }

  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
    .dsvert_joint_dp_vector_transaction(connection, {
      snapshot(connection, "rollback0")
      first_claim <- .dsvert_joint_dp_vector_instance_claim_material(
        releases[[1L]]$record$capsule_id,
        releases[[1L]]$record$release_instance_id,
        releases[[1L]]$record$release_contract_hash)
      .dsvert_joint_dp_vector_instance_claim_insert_connection(
        connection, secret, first_claim)
      .dsvert_joint_dp_vector_capsule_put(
        connection, releases[[1L]]$record, secret, existing = NULL)
      .dsvert_joint_dp_release_ledger_commit_connection(
        connection, config, secret, releases[[1L]]$instance_json,
        releases[[1L]]$release_json)
      snapshot(connection, "rollback1")
      second_claim <- .dsvert_joint_dp_vector_instance_claim_material(
        releases[[2L]]$record$capsule_id,
        releases[[2L]]$record$release_instance_id,
        releases[[2L]]$record$release_contract_hash)
      .dsvert_joint_dp_vector_instance_claim_insert_connection(
        connection, secret, second_claim)
      .dsvert_joint_dp_vector_capsule_put(
        connection, releases[[2L]]$record, secret, existing = NULL)
      .dsvert_joint_dp_release_ledger_commit_connection(
        connection, config, secret, releases[[2L]]$instance_json,
        releases[[2L]]$release_json)
      invisible(NULL)
    })
  })
  healthy <- .dsvert_joint_dp_vector_with_store(
    policy, secret, function(connection) {
      .dsvert_joint_dp_release_ledger_status(
        connection,
        .dsvert_joint_dp_release_ledger_config_from_policy(policy),
        secret)
    })
  expect_identical(healthy$release_instance_count, 2)

  path <- .dsvert_joint_dp_vector_store_path(policy)
  expect_silent(testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_with_store(
      policy, secret, function(connection) invisible(connection)),
    .dsvert_joint_dp_vector_release_ledger_cross_audit = function(...) {
      stop("unchanged store missed its cross-audit cache", call. = FALSE)
    },
    .package = "dsVert"))
  config <- .dsvert_joint_dp_release_ledger_config_from_policy(policy)
  omitted_column_checks <- .dsvert_joint_dp_vector_with_store(
    policy, secret, function(connection) {
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT capsule_id,local_privacy_epoch,local_noise_key_id,",
        "previous_chain FROM vector_release_ledger_records",
        "WHERE sequence=0"))
      stopifnot(nrow(row) == 1L)
      replacements <- list(
        capsule_id = strrep("f", 64L),
        local_privacy_epoch = as.numeric(row$local_privacy_epoch[[1L]]) + 7,
        local_noise_key_id = paste0(
          row$local_noise_key_id[[1L]], "_tampered"),
        previous_chain = strrep("f", 64L))
      lapply(names(replacements), function(column) {
        baseline <- .dsvert_joint_dp_vector_release_ledger_cache_key(
          connection, config)
        changed <- DBI::dbExecute(connection, sprintf(
          paste("UPDATE vector_release_ledger_records SET %s=?",
                "WHERE sequence=0"), column),
          params = list(replacements[[column]]))
        tampered <- .dsvert_joint_dp_vector_release_ledger_cache_key(
          connection, config)
        condition <- tryCatch(
          .dsvert_joint_dp_vector_store_initialize(
            connection, policy, secret,
            .dsvert_joint_dp_vector_store_path(policy)),
          error = identity)
        DBI::dbExecute(connection, sprintf(
          paste("UPDATE vector_release_ledger_records SET %s=?",
                "WHERE sequence=0"), column),
          params = list(row[[column]][[1L]]))
        list(
          column = column, changed = changed,
          key_changed = !identical(tampered, baseline),
          condition = condition,
          restored = identical(
            .dsvert_joint_dp_vector_release_ledger_cache_key(
              connection, config), baseline))
      })
    })
  expect_identical(
    vapply(omitted_column_checks, `[[`, character(1L), "column"),
    c("capsule_id", "local_privacy_epoch", "local_noise_key_id",
      "previous_chain"))
  expect_true(all(vapply(
    omitted_column_checks, function(value) value$changed == 1L,
    logical(1L))))
  expect_true(all(vapply(
    omitted_column_checks, `[[`, logical(1L), "key_changed")))
  expect_true(all(vapply(
    omitted_column_checks, function(value) inherits(value$condition, "error"),
    logical(1L))))
  expect_true(all(vapply(
    omitted_column_checks, function(value) grepl(
      "integrity or authentication", conditionMessage(value$condition)),
    logical(1L))))
  expect_true(all(vapply(
    omitted_column_checks, `[[`, logical(1L), "restored")))
  ledger_only <- .dsvert_joint_dp_vector_with_store(
    policy, secret, function(connection) {
      baseline <- .dsvert_joint_dp_vector_release_ledger_cache_key(
        connection, config)
      first_id <- DBI::dbGetQuery(connection, paste(
        "SELECT release_instance_id FROM vector_release_ledger_records",
        "WHERE sequence=0"))$release_instance_id[[1L]]
      deleted <- DBI::dbExecute(connection, paste(
        "DELETE FROM vector_capsules WHERE release_instance_id=?"),
        params = list(first_id))
      changed <- .dsvert_joint_dp_vector_release_ledger_cache_key(
        connection, config)
      list(deleted = deleted, key_changed = !identical(changed, baseline))
    })
  expect_identical(as.integer(ledger_only$deleted), 1L)
  expect_true(ledger_only$key_changed)
  audited_ledger_only <- FALSE
  cross_audit <- .dsvert_joint_dp_vector_release_ledger_cross_audit
  retained <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_vector_with_store(
      policy, secret, function(connection) list(
        status = .dsvert_joint_dp_release_ledger_status(
          connection, config, secret),
        capsule_count = DBI::dbGetQuery(
          connection, "SELECT COUNT(*) AS n FROM vector_capsules")$n[[1L]])),
    .dsvert_joint_dp_vector_release_ledger_cross_audit = function(...) {
      audited_ledger_only <<- TRUE
      cross_audit(...)
    },
    .package = "dsVert")
  expect_true(audited_ledger_only)
  expect_identical(retained$status$release_instance_count, 2)
  expect_identical(as.numeric(retained$capsule_count), 1)
  restore <- function(name) {
    connection <- DBI::dbConnect(RSQLite::SQLite(), path)
    DBI::dbExecute(connection, "BEGIN IMMEDIATE")
    for (suffix in suffixes) {
      DBI::dbExecute(
        connection, sprintf("DELETE FROM vector_release_ledger_%s", suffix))
      rows <- snapshots[[name]][[suffix]]
      if (nrow(rows)) {
        DBI::dbAppendTable(
          connection, paste0("vector_release_ledger_", suffix), rows)
      }
    }
    DBI::dbExecute(connection, "COMMIT")
    DBI::dbDisconnect(connection)
    Sys.chmod(path, mode = "0600")
  }
  count <- function() {
    connection <- DBI::dbConnect(
      RSQLite::SQLite(), path, flags = RSQLite::SQLITE_RO)
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    as.numeric(DBI::dbGetQuery(connection,
      "SELECT COUNT(*) AS n FROM vector_release_ledger_records")$n[[1L]])
  }

  restore("rollback1")
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      policy, secret, function(connection) invisible(connection)),
    "diverges from durable release capsules")
  expect_identical(count(), 1)

  restore("rollback0")
  if (exists(path, envir = .dsvert_joint_dp_vector_release_audit_cache,
             inherits = FALSE)) {
    rm(list = path, envir = .dsvert_joint_dp_vector_release_audit_cache)
  }
  expect_error(
    .dsvert_joint_dp_vector_with_store(
      policy, secret, function(connection) invisible(connection)),
    "diverges from durable release capsules")
  expect_identical(count(), 0)
})

test_that("duplicate designated noise roots fail with an actionable typed error", {
  fixture <- .vector_capsule_fixture()
  duplicated <- fixture$release_instance
  duplicated$peer_noise_roots$peer_b$noise_key_id <-
    duplicated$peer_noise_roots$peer_a$noise_key_id
  condition <- tryCatch(
    .dsvert_joint_dp_vector_release_instance(
      fixture$policies$peer_a, fixture$manifests[[1L]],
      fixture$peers[1:2], .dsvert_dp_canonical_json(duplicated)),
    error = identity)
  expect_s3_class(condition, "dsvert_noise_root_not_independent")
  expect_identical(condition$code, "noise_root_not_independent")
  expect_match(condition$message, "regenerate only")
})

test_that("the vector typed capability fixes producer, consumer and Ring128 shape", {
  context <- list(
    capsule_id = strrep("1", 64L),
    release_contract_hash = strrep("2", 64L),
    result_set_hash = strrep("3", 64L),
    chunk_index = "0", chunk_count = "2", coordinate_count = "8192",
    ring = "128", noised_share_sha256 = strrep("4", 64L))
  resolved <- .dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_VECTOR_TYPED_CAPABILITY, "peer_a", context)
  expect_identical(
    resolved$producer, .DSVERT_JOINT_DP_VECTOR_TRANSFER_PRODUCER)
  expect_identical(
    resolved$consumer, .DSVERT_JOINT_DP_VECTOR_TRANSFER_CONSUMER)
  expect_identical(resolved$shape,
                   "encrypted-ring128-noised-vector-chunk")
  expect_identical(as.numeric(resolved$count), 8192)
  bad <- context
  bad$ring <- "127"
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_VECTOR_TYPED_CAPABILITY, "peer_a", bad), "Ring128")
  bad <- context
  bad$unexpected <- "field"
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_VECTOR_TYPED_CAPABILITY, "peer_a", bad), "context")
})

.vector_capsule_source_compaction_authorization <- function(
    fixture, peer) {
  contract <- .dsvert_dp_capsule_source_contract_json(
    fixture$policies[[peer]], fixture$manifest_json)$contract
  unsigned <- list(
    version = .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_AUTH_VERSION,
    capsule_id = contract$capsule_id,
    source_contract_hash = .dsvert_joint_dp_hash(contract),
    release_instance_id = .dsvert_joint_dp_hash(
      list(test = "durable-release-instance")),
    release_contract_hash = .dsvert_joint_dp_hash(
      list(test = "release-contract")),
    final_vector_root = .dsvert_joint_dp_hash(
      list(test = "final-vector-root")),
    result_set_hash = .dsvert_joint_dp_hash(list(test = "result-set")),
    final_chunk_commitments_sha256 = .dsvert_joint_dp_hash(
      list(test = "final-chunk-commitments")),
    release_receipts_sha256 = .dsvert_joint_dp_hash(
      list(test = "two-pinned-release-receipts")),
    durable_release_receipts_verified = TRUE,
    public_release_memoized = TRUE,
    final_chunks_retained = TRUE)
  .dsvert_dp_capsule_source_compaction_authorization_seal(
    .dsvert_dp_canonical_query_value(unsigned), fixture$secrets[[peer]])
}

test_that("roleless K3 finalization reserves one durable source tombstone", {
  fixture <- .vector_capsule_fixture(k = 3L, count_only = TRUE)
  roleless_peer <- fixture$peers[[3L]]
  contract <- .dsvert_dp_capsule_source_contract_json(
    fixture$policies[[roleless_peer]], fixture$manifest_json)$contract
  expect_identical(
    .dsvert_dp_capsule_source_names(
      contract$source_peers, "test source peer list"),
    fixture$peers[[1L]])
  expect_false(roleless_peer %in% unlist(
    contract$designated_noise_peers, use.names = FALSE))
  authorization <- .vector_capsule_source_compaction_authorization(
    fixture, roleless_peer)

  expect_error(
    .dsvert_dp_capsule_source_compact_after_vector_release_internal(
      fixture$policies[[roleless_peer]], fixture$manifest_json,
      authorization, fixture$secrets[[roleless_peer]],
      .phase_hook = function(phase) {
        if (identical(phase, "before_source_compaction_commit")) {
          stop("simulated roleless pre-commit crash", call. = FALSE)
        }
      }),
    "simulated roleless pre-commit crash")
  rolled_back <- .dsvert_dp_capsule_source_with_store(
    fixture$policies[[roleless_peer]], fixture$secrets[[roleless_peer]],
    function(connection) list(
      receipt = .dsvert_dp_capsule_source_compaction_load(
        connection, contract$capsule_id, fixture$secrets[[roleless_peer]]),
      state = .dsvert_dp_capsule_source_store_state(
        connection, fixture$secrets[[roleless_peer]])))
  expect_null(rolled_back$receipt)
  expect_identical(as.numeric(rolled_back$state$reserved_bytes), 0)

  first <- .dsvert_dp_capsule_source_compact_after_vector_release_internal(
    fixture$policies[[roleless_peer]], fixture$manifest_json,
    authorization, fixture$secrets[[roleless_peer]])
  second <- .dsvert_dp_capsule_source_compact_after_vector_release_internal(
    fixture$policies[[roleless_peer]], fixture$manifest_json,
    authorization, fixture$secrets[[roleless_peer]])
  expect_identical(second, first)
  expect_identical(
    as.numeric(first$active_reservation_bytes),
    as.numeric(.DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES))
  expect_identical(as.numeric(first$released_bytes), 0)
  retained <- .dsvert_dp_capsule_source_with_store(
    fixture$policies[[roleless_peer]], fixture$secrets[[roleless_peer]],
    function(connection) .dsvert_dp_capsule_source_store_state(
      connection, fixture$secrets[[roleless_peer]]))
  expect_identical(
    as.numeric(retained$reserved_bytes),
    as.numeric(.DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES))

  roleful_authorization <- .vector_capsule_source_compaction_authorization(
    fixture, fixture$peers[[1L]])
  expect_error(
    .dsvert_dp_capsule_source_compact_after_vector_release_internal(
      fixture$policies[[1L]], fixture$manifest_json,
      roleful_authorization, fixture$secrets[[1L]]),
    "compaction reservation is inconsistent")

  unexpected <- .vector_capsule_fixture(k = 3L, count_only = TRUE)
  unexpected_peer <- unexpected$peers[[3L]]
  unexpected_contract <- .dsvert_dp_capsule_source_contract_json(
    unexpected$policies[[unexpected_peer]],
    unexpected$manifest_json)$contract
  .dsvert_dp_capsule_source_with_store(
    unexpected$policies[[unexpected_peer]],
    unexpected$secrets[[unexpected_peer]], function(connection) {
      .dsvert_dp_capsule_source_record_insert(
        connection, "source_cross_gaussian_results",
        c("capsule_id", "analysis_id"),
        list(unexpected_contract$capsule_id, "unexpected-role-state"),
        list(version = "authenticated-unexpected-role-state-v1"),
        unexpected$secrets[[unexpected_peer]])
    })
  expect_error(
    .dsvert_dp_capsule_source_compact_after_vector_release_internal(
      unexpected$policies[[unexpected_peer]], unexpected$manifest_json,
      .vector_capsule_source_compaction_authorization(
        unexpected, unexpected_peer),
      unexpected$secrets[[unexpected_peer]]),
    "compaction role state is inconsistent")

  limited <- .vector_capsule_fixture(k = 3L, count_only = TRUE)
  limited_peer <- limited$peers[[3L]]
  terminal <- tryCatch(testthat::with_mocked_bindings(
    .dsvert_dp_capsule_source_compact_after_vector_release_internal(
      limited$policies[[limited_peer]], limited$manifest_json,
      .vector_capsule_source_compaction_authorization(
        limited, limited_peer), limited$secrets[[limited_peer]]),
    .dsvert_dp_capsule_source_spool_max_bytes = function() {
      .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES - 1
    },
    .package = "dsVert"), error = identity)
  expect_s3_class(terminal, "dsvert_resource_oversize")
  limited_state <- .dsvert_dp_capsule_source_with_store(
    limited$policies[[limited_peer]], limited$secrets[[limited_peer]],
    function(connection) list(
      receipt = .dsvert_dp_capsule_source_compaction_load(
        connection,
        limited$manifests[[1L]]$capsule_identity$capsule_id,
        limited$secrets[[limited_peer]]),
      state = .dsvert_dp_capsule_source_store_state(
        connection, limited$secrets[[limited_peer]])))
  expect_null(limited_state$receipt)
  expect_identical(as.numeric(limited_state$state$reserved_bytes), 0)
})

test_that("final vector compaction is authorized, crash-safe and replay-sticky", {
  fixture <- .vector_capsule_fixture(k = 3L)
  tickets <- .vector_capsule_helpers$.capsule_source_test_tickets(fixture)
  summaries <- .vector_capsule_helpers$.capsule_source_test_prepare(
    fixture, tickets)
  premature_authorization <-
    .vector_capsule_source_compaction_authorization(fixture, "peer_a")
  expect_error(
    .dsvert_dp_capsule_source_compact_after_vector_release_internal(
      fixture$policies$peer_a, fixture$manifest_json,
      premature_authorization, fixture$secrets$peer_a),
    "before every outbound chunk is durably complete")
  expect_identical(.vector_capsule_helpers$.capsule_source_test_prepare(
    fixture, tickets)[[1L]], summaries[[1L]])
  replay_envelope <- NULL
  for (recipient in fixture$peers[1:2]) {
    for (source in fixture$peers) {
      contract <- .dsvert_dp_capsule_source_contract_json(
        fixture$policies[[source]], fixture$manifest_json)$contract
      for (chunk in seq.int(0, contract$chunk_count - 1L)) {
        envelope <- .vector_capsule_helpers$.capsule_source_test_envelope(
          fixture, summaries, source, recipient, chunk)
        if (is.null(replay_envelope) && identical(recipient, "peer_a")) {
          replay_envelope <- envelope
        }
        .vector_capsule_helpers$.capsule_source_test_accept(
          fixture, recipient, envelope)
      }
    }
  }
  tables <- c(
    "source_outbound", "source_outbound_chunks", "source_incoming_state",
    "source_aggregate_chunks", "source_incoming_receipts",
    "source_recipient_keys", "source_cross_gaussian_results",
    "source_cross_categorical_results")
  for (peer in fixture$peers) {
    policy <- fixture$policies[[peer]]
    secret <- fixture$secrets[[peer]]
    authorization <- .vector_capsule_source_compaction_authorization(
      fixture, peer)
    before <- .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) list(
        counts = vapply(tables, function(table) {
          DBI::dbGetQuery(connection, paste(
            "SELECT COUNT(*) AS n FROM", table))$n[[1L]]
        }, numeric(1L)),
        state = .dsvert_dp_capsule_source_store_state(connection, secret)))

    # A caller cannot delete source state without the MAC-bound proof that the
    # two pinned final releases have already been verified and memoized.
    expect_error(
      .dsvert_dp_capsule_source_compact_after_vector_release_internal(
        policy, fixture$manifest_json, NULL, secret),
      "durable public-release authorization")
    unchanged <- .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) list(
        counts = vapply(tables, function(table) {
          DBI::dbGetQuery(connection, paste(
            "SELECT COUNT(*) AS n FROM", table))$n[[1L]]
        }, numeric(1L)),
        state = .dsvert_dp_capsule_source_store_state(connection, secret)))
    expect_identical(unchanged, before)

    # Failure before COMMIT rolls back tombstone, deletes and accounting as one
    # unit. This is the recoverable pre-crash state.
    expect_error(
      .dsvert_dp_capsule_source_compact_after_vector_release_internal(
        policy, fixture$manifest_json, authorization, secret,
        .phase_hook = function(phase) {
          if (identical(phase, "before_source_compaction_commit")) {
            stop("simulated pre-commit crash", call. = FALSE)
          }
        }), "simulated pre-commit crash")
    rolled_back <- .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) list(
        counts = vapply(tables, function(table) {
          DBI::dbGetQuery(connection, paste(
            "SELECT COUNT(*) AS n FROM", table))$n[[1L]]
        }, numeric(1L)),
        state = .dsvert_dp_capsule_source_store_state(connection, secret)))
    expect_identical(rolled_back, before)

    owner <- .dsvert_dp_capsule_source_resource_owner(policy)
    concurrent <- NULL
    if (.Platform$OS.type != "windows" && identical(peer, "peer_b")) {
      concurrent <- parallel::mclapply(seq_len(2L), function(index) {
        .dsvert_dp_capsule_source_compact_after_vector_release_internal(
          policy, fixture$manifest_json, authorization, secret)
      }, mc.cores = 2L)
      failures <- vapply(concurrent, inherits, logical(1L), "try-error")
      if (any(failures)) {
        stop("Concurrent source compaction failed: ",
             paste(vapply(concurrent[failures], as.character, character(1L)),
                   collapse = " | "), call. = FALSE)
      }
      expect_identical(concurrent[[1L]], concurrent[[2L]])
    } else {
      expect_error(
        .dsvert_dp_capsule_source_compact_after_vector_release_internal(
          policy, fixture$manifest_json, authorization, secret,
          .phase_hook = function(phase) {
            if (identical(phase, "after_source_compaction_commit")) {
              stop("simulated post-commit process crash", call. = FALSE)
            }
          }), "simulated post-commit process crash")
    }
    # A fresh worker authenticates the committed capacity row and tombstone;
    # it never relies on the stale in-memory head of the crashed worker.
    .dsvert_resource_external_unregister(owner)
    restarted <- .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) list(
        receipt = .dsvert_dp_capsule_source_compaction_load(
          connection,
          .dsvert_dp_capsule_source_contract_json(
            policy, fixture$manifest_json)$contract$capsule_id,
          secret),
        state = .dsvert_dp_capsule_source_store_state(connection, secret),
        vacuum_mode = DBI::dbGetQuery(
          connection, "PRAGMA auto_vacuum")[[1L]][[1L]]))
    first <- restarted$receipt
    if (!is.null(concurrent)) expect_identical(first, concurrent[[1L]])
    second <- .dsvert_dp_capsule_source_compact_after_vector_release_internal(
      policy, fixture$manifest_json, authorization, secret)
    expect_identical(second, first)
    expect_true(first$compacted)
    expect_gt(as.numeric(first$released_bytes), 0)
    expect_identical(
      as.numeric(first$active_reservation_bytes),
      as.numeric(before$state$reserved_bytes))
    expect_identical(as.numeric(restarted$state$reserved_bytes),
                     as.numeric(first$retained_receipt_bytes))
    expect_identical(
      .dsvert_resource_registry$external[[owner]]$bytes,
      as.numeric(first$retained_receipt_bytes))
    expect_identical(as.numeric(restarted$vacuum_mode), 2)
    .dsvert_dp_capsule_source_with_store(
      policy, secret,
      function(connection) {
        counts <- vapply(tables, function(table) {
          DBI::dbGetQuery(connection, paste(
            "SELECT COUNT(*) AS n FROM", table))$n[[1L]]
        }, numeric(1L))
        expect_true(all(counts == 0))
        expect_equal(DBI::dbGetQuery(connection, paste(
          "SELECT COUNT(*) AS n FROM source_compaction_receipts"))$n[[1L]],
          1)
        state <- .dsvert_dp_capsule_source_store_state(
          connection, secret)
        expect_identical(
          as.numeric(state$reserved_bytes),
          as.numeric(.DSVERT_DP_CAPSULE_SOURCE_COMPACTION_RECEIPT_BYTES))
      })
  }

  # A delayed valid ciphertext cannot resurrect a compacted aggregate.
  expect_error(.vector_capsule_helpers$.capsule_source_test_accept(
    fixture, "peer_a", replay_envelope), "durably finalized")
  expect_error(.dsvert_dp_capsule_source_prepare_impl(
    fixture$manifest_json, tickets[[1L]], tickets[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .materializer = function(...) stop("must not rematerialize"),
    .signer = .vector_capsule_helpers$.capsule_source_test_signer,
    .verifier = .vector_capsule_helpers$.capsule_source_test_verifier,
    .allocation_observer = function(...) invisible(TRUE)),
    "durably finalized")
})
