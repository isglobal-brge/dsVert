.capsule_registry_fixture <- function(
    path = tempfile("dsvert-capsule-registry-"), epsilon = 0.75,
    delta = 0.02, epoch = 7, lifetime_max = 8) {
  pinset_hash <- strrep("3", 64L)
  lifetime_epsilon <- .dsvert_joint_dp_release_ledger_exact_total(
    .dsvert_capsule_registry_decimal(
      epsilon, "capsule epsilon", open_minimum = TRUE),
    lifetime_max, "lifetime epsilon")
  lifetime_delta <- .dsvert_joint_dp_release_ledger_exact_total(
    .dsvert_capsule_registry_decimal(delta, "capsule delta"),
    lifetime_max, "lifetime delta")
  policy_contract <- list(
    protocol = "dsvert-joint-dp-control-v3",
    peer_pinset_sha256 = pinset_hash,
    epsilon_capsule = epsilon, delta_capsule = delta,
    lifetime_max_distinct_capsules = as.numeric(lifetime_max),
    lifetime_epsilon_upper_bound = lifetime_epsilon,
    lifetime_delta_upper_bound = lifetime_delta,
    adjacency = "add_remove_patient")
  list(
    config = .dsvert_capsule_registry_config(
      registry_path = path,
      consortium_id = paste0("jdpc1_", strrep("1", 64L)),
      policy_contract = policy_contract,
      peer_pinset_sha256 = pinset_hash,
      capsule_epsilon = epsilon, capsule_delta = delta,
      lifetime_max_distinct_capsules = lifetime_max,
      require_private = TRUE,
      lock_timeout_ms = 30000L),
    secret = as.raw(seq_len(32L)))
}

.capsule_registry_identity <- function(config, index = 1L) {
  .dsvert_capsule_registry_identity(
    config,
    logical_snapshot = list(
      logical_snapshot_id = paste0("cohort-", index),
      version = paste0("v", index), alignment_protocol_version = 1L),
    capsule_schema = "bounded-sufficient-statistics-v1",
    admission = list(
      adjacency = "add_remove_patient", max_records_per_unit = 1L),
    bounds = list(lower = 0L, upper = 100L),
    workload = list(
      representation = "bounded-count-vector", coordinate_count = 1L))
}

.capsule_registry_file_hash <- function(path) {
  digest::digest(file = path, algo = "sha256", serialize = FALSE)
}

.capsule_registry_encode_key <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.capsule_registry_capture_db_get_queries <- function(code) {
  tracker_name <- ".dsvert_capsule_registry_query_tracker"
  tracker <- new.env(parent = emptyenv())
  tracker$statements <- character()
  assign(tracker_name, tracker, envir = .GlobalEnv)
  on.exit(if (exists(tracker_name, envir = .GlobalEnv, inherits = FALSE)) {
    rm(list = tracker_name, envir = .GlobalEnv)
  }, add = TRUE)
  suppressMessages(trace(
    "dbGetQuery", signature = c("DBIConnection", "character"),
    where = asNamespace("DBI"), print = FALSE,
    tracer = quote({
      tracker <- get(
        ".dsvert_capsule_registry_query_tracker", envir = .GlobalEnv,
        inherits = FALSE)
      tracker$statements <- c(
        tracker$statements, as.character(statement))
    })))
  on.exit(suppressMessages(untrace(
    "dbGetQuery", signature = c("DBIConnection", "character"),
    where = asNamespace("DBI"))), add = TRUE)
  value <- force(code)
  list(value = value, statements = tracker$statements)
}

.capsule_registry_policy <- function(root = tempfile("capsule-policy-"),
                                     epsilon = 0.75, delta = 0.02,
                                     epoch = 7, lifetime_max = 8) {
  dir.create(root)
  pins <- c(
    peer_a = .capsule_registry_encode_key(as.raw(seq_len(32L))),
    peer_b = .capsule_registry_encode_key(
      as.raw(32L + seq_len(32L))))
  pinset_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  list(
    domain = "capsule-registry-study", cohort_id = "cohort-v1",
    peer_name = "peer_a", peer_pinset = pins,
    peer_pinset_sha256 = pinset_hash, peer_count = 2L,
    designated_noise_peers = names(pins),
    global_total_epsilon = epsilon, global_total_delta = delta,
    lifetime_max_distinct_capsules = as.numeric(lifetime_max),
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = 100L, max_records_per_unit = 1L,
    overflow_policy = "reject_snapshot",
    noise_root = list(epoch = epoch, key_id = "capsule-policy-key"),
    ledger_path = file.path(root, "local.sqlite"),
    ledger_private = FALSE, lock_timeout_ms = 30000L)
}

test_that("canonical privacy decimals ignore the display decimal option", {
  previous <- options(OutDec = ",")
  on.exit(options(previous), add = TRUE)

  expect_identical(
    .dsvert_joint_dp_decimal(0.125, "test decimal"), "1.25e-01")
  expect_identical(
    .dsvert_capsule_registry_decimal(0.125, "test decimal"), "1.25e-01")
})

test_that("registry config and identity exactly match the joint control plane", {
  policy <- .capsule_registry_policy()
  context <- .dsvert_joint_dp_policy_context(policy)
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  expect_identical(config$policy_contract, context$common)
  expect_identical(config$consortium_id, context$consortium_id)
  expect_identical(config$peer_pinset_sha256,
                   context$common$peer_pinset_sha256)
  expect_identical(config$capsule_epsilon,
                   context$common$epsilon_capsule)
  expect_identical(config$capsule_delta,
                   context$common$delta_capsule)
  expect_identical(
    config$privacy_epoch_scope, "per_peer_signed_receipts_v1")
  expect_false(identical(
    config$registry_path, .dsvert_joint_dp_ledger_path(policy)))
  expect_error(.dsvert_capsule_registry_config_from_policy(
    policy, .dsvert_joint_dp_ledger_path(policy)), "separate")

  snapshot <- list(
    logical_snapshot_id = "parity-cohort", version = "v1",
    alignment_protocol_version = 1L)
  admission <- list(
    adjacency = policy$adjacency,
    max_records_per_unit = policy$max_records_per_unit)
  bounds <- list(lower = 0L, upper = 100L)
  workload <- list(
    representation = "bounded-count-vector", coordinate_count = 4L)
  registry_identity <- .dsvert_capsule_registry_identity(
    config, snapshot, "bounded-statistics-v1",
    admission, bounds, workload)
  control_identity <- .dsvert_joint_dp_capsule_identity(
    policy, snapshot, "bounded-statistics-v1",
    admission, bounds, workload)
  expect_identical(registry_identity, control_identity)
  expect_identical(
    charToRaw(.dsvert_dp_canonical_json(registry_identity)),
    charToRaw(.dsvert_dp_canonical_json(control_identity)))

  changed_snapshot <- utils::modifyList(snapshot, list(version = "v2"))
  changed_registry <- .dsvert_capsule_registry_identity(
    config, changed_snapshot, "bounded-statistics-v1",
    admission, bounds, workload)
  changed_control <- .dsvert_joint_dp_capsule_identity(
    policy, changed_snapshot, "bounded-statistics-v1",
    admission, bounds, workload)
  expect_identical(changed_registry, changed_control)
  expect_false(identical(
    registry_identity$capsule_id, changed_registry$capsule_id))

  changed_policy <- policy
  changed_policy$global_total_epsilon <- 0.5
  changed_config <- .dsvert_capsule_registry_config_from_policy(
    changed_policy,
    tempfile("capsule-policy-changed-", tmpdir = dirname(
      changed_policy$ledger_path)))
  changed_registry <- .dsvert_capsule_registry_identity(
    changed_config, snapshot, "bounded-statistics-v1",
    admission, bounds, workload)
  changed_control <- .dsvert_joint_dp_capsule_identity(
    changed_policy, snapshot, "bounded-statistics-v1",
    admission, bounds, workload)
  expect_identical(changed_registry, changed_control)
  expect_false(identical(
    registry_identity$capsule_id, changed_registry$capsule_id))

  policy_k3 <- policy
  policy_k3$peer_pinset <- c(
    policy$peer_pinset,
    peer_c = .capsule_registry_encode_key(
      as.raw(64L + seq_len(32L))))
  policy_k3$peer_count <- 3L
  policy_k3$peer_pinset_sha256 <- digest::digest(
    .dsvert_dp_canonical_json(as.list(policy_k3$peer_pinset)),
    algo = "sha256", serialize = FALSE)
  policy_k3_c <- policy_k3
  policy_k3_c$peer_name <- "peer_c"
  policy_k3_c$ledger_path <- file.path(
    dirname(policy$ledger_path), "peer-c-local.sqlite")
  expect_error(.dsvert_joint_dp_policy_context(policy_k3_c), "designated")
  config_k3_a <- .dsvert_capsule_registry_config_from_policy(
    policy_k3, tempfile("capsule-k3-a-", tmpdir = dirname(
      policy_k3$ledger_path)))
  config_k3_c <- .dsvert_capsule_registry_config_from_policy(
    policy_k3_c, tempfile("capsule-k3-c-", tmpdir = dirname(
      policy_k3_c$ledger_path)))
  registry_k3_a <- .dsvert_capsule_registry_identity(
    config_k3_a, snapshot, "bounded-statistics-v1",
    admission, bounds, workload)
  registry_k3_c <- .dsvert_capsule_registry_identity(
    config_k3_c, snapshot, "bounded-statistics-v1",
    admission, bounds, workload)
  control_k3_c <- .dsvert_joint_dp_capsule_identity(
    policy_k3_c, snapshot, "bounded-statistics-v1",
    admission, bounds, workload)
  expect_identical(registry_k3_a, registry_k3_c)
  expect_identical(registry_k3_c, control_k3_c)

  small_delta_policy <- .capsule_registry_policy(delta = 1e-6)
  small_delta_config <- .dsvert_capsule_registry_config_from_policy(
    small_delta_policy)
  expect_identical(
    small_delta_config$capsule_delta,
    small_delta_policy$global_total_delta)
})

test_that("capsule identity is canonical, policy-bound and operation-independent", {
  fixture <- .capsule_registry_fixture()
  identity <- .capsule_registry_identity(fixture$config)
  reordered <- .dsvert_capsule_registry_identity(
    fixture$config,
    logical_snapshot = list(
      version = "v1", alignment_protocol_version = 1,
      logical_snapshot_id = "cohort-1"),
    capsule_schema = "bounded-sufficient-statistics-v1",
    admission = list(
      max_records_per_unit = 1, adjacency = "add_remove_patient"),
    bounds = list(upper = 100, lower = 0),
    workload = list(
      coordinate_count = 1, representation = "bounded-count-vector"))
  expect_identical(identity, reordered)
  expect_identical(identity$capsule_id,
    .dsvert_capsule_registry_hash(identity$contract))
  expect_identical(identity$contract$policy_contract_hash,
                   .dsvert_capsule_registry_hash(
                     fixture$config$policy_contract))
  expect_identical(fixture$config$policy_contract$epsilon_capsule,
                   fixture$config$capsule_epsilon)
  expect_identical(fixture$config$policy_contract$delta_capsule,
                   fixture$config$capsule_delta)
  expect_identical(
    identity$contract$privacy_epoch_scope,
    "per_peer_signed_receipts_v1")

  changed_snapshot <- .capsule_registry_identity(fixture$config, 2L)
  expect_false(identical(identity$capsule_id, changed_snapshot$capsule_id))
  changed_policy <- .capsule_registry_fixture(
    path = tempfile("dsvert-capsule-registry-policy-"), epoch = 8)
  expect_identical(identity$capsule_id,
    .capsule_registry_identity(changed_policy$config)$capsule_id)
  expect_error(.dsvert_capsule_registry_config(
    tempfile("dsvert-capsule-registry-policy-mismatch-"),
    fixture$config$consortium_id, fixture$config$policy_contract,
    fixture$config$peer_pinset_sha256, 0.5, fixture$config$capsule_delta,
    fixture$config$lifetime_max_distinct_capsules,
    require_private = TRUE), "does not bind")

  expect_error(.dsvert_capsule_registry_identity(
    fixture$config,
    list(logical_snapshot_id = "cohort-1", version = "v1",
         alignment_protocol_version = 1L),
    "bounded-sufficient-statistics-v1",
    admission = list(adjacency = "add_remove_patient"),
    bounds = list(lower = 0L, upper = 100L),
    workload = list(method = "glm")),
    "operation-independent")
  expect_error(.dsvert_capsule_registry_identity(
    fixture$config,
    list(logical_snapshot_id = "cohort-1", version = "v1",
         alignment_protocol_version = 1L),
    "bounded-sufficient-statistics-v1",
    admission = list(adjacency = "add_remove_patient"),
    bounds = list(lower = 0L, upper = 100L),
    workload = list(nested = list(arguments = list(alpha = 1)))),
    "operation-independent")
})

test_that("ten thousand logical uses do not access or mutate registry state", {
  fixture <- .capsule_registry_fixture()
  identity <- .capsule_registry_identity(fixture$config)
  created <- .dsvert_capsule_registry_register(
    fixture$config, identity, fixture$secret)
  expect_true(created$created)
  expect_false(created$record$capability_available)
  before <- .dsvert_capsule_registry_snapshot(
    fixture$config, fixture$secret)
  before_hash <- .capsule_registry_file_hash(fixture$config$registry_path)

  record <- created$record
  for (unused in seq_len(10000L)) {
    record <- .dsvert_capsule_registry_reuse(
      record, fixture$secret, fixture$config$registry_id)
  }
  expect_identical(record, created$record)
  roundtrip <- unserialize(serialize(record, NULL, version = 3L))
  expect_identical(.dsvert_capsule_registry_reuse(
    roundtrip, fixture$secret, fixture$config$registry_id), record)
  expect_identical(
    .capsule_registry_file_hash(fixture$config$registry_path), before_hash)
  after <- .dsvert_capsule_registry_snapshot(
    fixture$config, fixture$secret)
  expect_identical(after, before)
  expect_identical(after$summary$capsule_count, 1)
  expect_identical(
    after$summary$operation_accounting,
    "one_per_distinct_capsule_allocator_commit")
  expect_true(after$summary$operation_limit)
  expect_true(after$summary$history_can_deny_operation)
  expect_false("..." %in% names(formals(.dsvert_capsule_registry_reuse)))
  expect_identical(names(formals(.dsvert_capsule_registry_reuse)),
                   c("record", "secret", "expected_registry_id"))
  forged <- record
  forged$capsule_epsilon <- 0.1
  expect_error(.dsvert_capsule_registry_reuse(
    forged, fixture$secret, fixture$config$registry_id),
    "failed authentication")
  expect_error(.dsvert_capsule_registry_reuse(
    record, rev(fixture$secret), fixture$config$registry_id),
               "failed authentication")
  other <- .capsule_registry_fixture(
    path = tempfile("dsvert-capsule-registry-other-"), epoch = 8)
  expect_identical(.dsvert_capsule_registry_reuse(
    record, fixture$secret, other$config$registry_id), record)
})

test_that("registry admits its lifetime boundary and exact replay remains free", {
  capsule_total <- 101L
  fixture <- .capsule_registry_fixture(
    epsilon = 0.05, delta = 0.001, lifetime_max = capsule_total)
  results <- vector("list", capsule_total)
  for (index in seq_len(capsule_total)) {
    results[[index]] <- .dsvert_capsule_registry_register(
      fixture$config,
      .capsule_registry_identity(fixture$config, index), fixture$secret)
    expect_true(results[[index]]$created)
    expect_identical(results[[index]]$record$capsule_epsilon, 0.05)
    expect_identical(results[[index]]$record$capsule_delta, 0.001)
    expect_identical(results[[index]]$summary$capsule_count,
                     as.numeric(index))
  }
  fast_status <- local({
    testthat::local_mocked_bindings(
      .dsvert_capsule_registry_audit = function(...) {
        stop("full audit must not run")
      },
      .package = "dsVert")
    .dsvert_capsule_registry_status(fixture$config, fixture$secret)
  })
  expect_identical(fast_status$capsule_count, as.numeric(capsule_total))
  expect_identical(fast_status$composition_role,
                   "basic_composition_authenticated_lifetime_bound")
  expect_identical(fast_status$remaining_distinct_capsules, 0)
  expect_true(fast_status$operation_limit)
  expect_true(fast_status$history_can_deny_operation)
  fast_path_source <- paste(c(
    deparse(body(.dsvert_capsule_registry_status)),
    deparse(body(.dsvert_capsule_registry_validate_head))), collapse = "\n")
  expect_false(grepl("COUNT\\s*\\(", fast_path_source, perl = TRUE))
  snapshot <- .dsvert_capsule_registry_snapshot(
    fixture$config, fixture$secret)
  expect_identical(snapshot$summary$capsule_count,
                   as.numeric(capsule_total))
  expect_identical(snapshot$summary$cumulative_epsilon,
                   capsule_total * 0.05)
  expect_identical(snapshot$summary$cumulative_delta,
                   capsule_total * 0.001)
  expect_identical(snapshot$summary$composition_role,
                   "basic_composition_authenticated_lifetime_bound")
  expect_false(snapshot$summary$cumulative_delta_vacuous)
  expect_identical(snapshot$summary$registration_policy,
                   paste0("allocator_admitted_distinct_capsules_up_to_",
                          "lifetime_limit"))
  expect_true(snapshot$summary$operation_limit)
  expect_true(snapshot$summary$history_can_deny_operation)
  expect_true(all(vapply(snapshot$records, function(record) {
    identical(record$capsule_epsilon, 0.05) &&
      identical(record$capsule_delta, 0.001)
  }, logical(1L))))

  replay <- .dsvert_capsule_registry_register(
    fixture$config, .capsule_registry_identity(fixture$config, 1L),
    fixture$secret)
  expect_false(replay$created)
  expect_identical(replay$record, results[[1L]]$record)
  expect_identical(replay$summary$capsule_count,
                   as.numeric(capsule_total))
  exhausted <- tryCatch(.dsvert_capsule_registry_register(
    fixture$config,
    .capsule_registry_identity(fixture$config, capsule_total + 1L),
    fixture$secret), error = identity)
  expect_s3_class(exhausted, "dsvert_dp_lifetime_budget_exhausted")

  forbidden <- c("queries_remaining", "request_quota", "decay")
  encoded <- .dsvert_dp_canonical_json(list(
    status = fast_status, snapshot = snapshot))
  expect_false(any(vapply(forbidden, grepl, logical(1L),
                          x = encoded, fixed = TRUE)))
  schema <- DBI::dbConnect(RSQLite::SQLite(), fixture$config$registry_path)
  on.exit(DBI::dbDisconnect(schema), add = TRUE)
  columns <- DBI::dbGetQuery(
    schema, "PRAGMA table_info(capsule_registry_records)")$name
  expect_false(any(columns %in% c(
    "method", "arguments", "operation_id", "query_id")))
})

test_that("allocator-bound registry enforces its authenticated boundary", {
  capsule_total <- 128L
  fixture <- .capsule_registry_fixture(
    epsilon = 0.05, delta = 0.001, lifetime_max = capsule_total)
  last_identity <- NULL
  for (index in seq_len(capsule_total)) {
    identity <- .capsule_registry_identity(fixture$config, index)
    admission <- .dsvert_capsule_registry_allocator_admission(
      fixture$config, identity, index - 1L,
      digest::digest(
        paste0("joint-record-", index), algo = "sha256", serialize = FALSE),
      digest::digest(
        paste0("prepare-set-", index), algo = "sha256", serialize = FALSE),
      digest::digest(
        paste0("own-commit-", index), algo = "sha256", serialize = FALSE),
      fixture$secret)
    registered <- .dsvert_capsule_registry_register_bound(
      fixture$config, identity, admission, fixture$secret)
    expect_true(registered$created)
    expect_identical(registered$summary$capsule_count, as.numeric(index))
    expect_true(registered$summary$operation_limit)
    expect_true(registered$summary$history_can_deny_operation)
    last_identity <- identity
  }

  fast <- testthat::with_mocked_bindings(
    .dsvert_capsule_registry_bound_state_entry(
      fixture$config, fixture$secret, last_identity$capsule_id),
    .dsvert_capsule_registry_audit = function(...) {
      stop("full registry audit entered", call. = FALSE)
    },
    .package = "dsVert")
  expect_identical(fast$summary$capsule_count, as.numeric(capsule_total))
  expect_identical(fast$entry$record$capsule_id, last_identity$capsule_id)
  expect_true(fast$summary$operation_limit)
  expect_true(fast$summary$history_can_deny_operation)
  looked_up <- testthat::with_mocked_bindings(
    .dsvert_capsule_registry_lookup(
      fixture$config, last_identity$capsule_id, fixture$secret),
    .dsvert_capsule_registry_audit = function(...) {
      stop("full registry audit entered", call. = FALSE)
    },
    .package = "dsVert")
  expect_identical(looked_up$capsule_id, last_identity$capsule_id)
  overflow_identity <- .capsule_registry_identity(
    fixture$config, capsule_total + 1L)
  expect_error(.dsvert_capsule_registry_allocator_admission(
    fixture$config, overflow_identity, capsule_total,
    digest::digest(
      "overflow-joint-record", algo = "sha256", serialize = FALSE),
    digest::digest(
      "overflow-prepare-set", algo = "sha256", serialize = FALSE),
    digest::digest(
      "overflow-own-commit", algo = "sha256", serialize = FALSE),
    fixture$secret), "Invalid cross-signed allocator admission")

  small <- .capsule_registry_fixture(
    path = tempfile("dsvert-capsule-registry-small-fast-"),
    epsilon = 0.5, delta = 0.01)
  small_identity <- .capsule_registry_identity(small$config, 1L)
  small_admission <- .dsvert_capsule_registry_allocator_admission(
    small$config, small_identity, 0,
    digest::digest("small-joint-record", algo = "sha256", serialize = FALSE),
    digest::digest("small-prepare-set", algo = "sha256", serialize = FALSE),
    digest::digest("small-own-commit", algo = "sha256", serialize = FALSE),
    small$secret)
  .dsvert_capsule_registry_register_bound(
    small$config, small_identity, small_admission, small$secret)
  small_fast <- .capsule_registry_capture_db_get_queries(
    .dsvert_capsule_registry_bound_state_entry(
      small$config, small$secret, small_identity$capsule_id))
  large_fast <- .capsule_registry_capture_db_get_queries(
    .dsvert_capsule_registry_bound_state_entry(
      fixture$config, fixture$secret, last_identity$capsule_id))
  expect_identical(
    length(small_fast$statements), length(large_fast$statements))
  expect_lte(length(large_fast$statements), 12L)
  unbounded <- paste(large_fast$statements, collapse = "\n")
  expect_false(grepl(
    "SELECT \\* FROM capsule_registry_records ORDER BY sequence$",
    unbounded, perl = TRUE))

  connection <- DBI::dbConnect(RSQLite::SQLite(), fixture$config$registry_path)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  plan <- DBI::dbGetQuery(connection, paste(
    "EXPLAIN QUERY PLAN SELECT * FROM capsule_registry_records",
    "WHERE capsule_id = ?"), params = list(last_identity$capsule_id))
  expect_true(any(grepl("USING INDEX", plan$detail, fixed = TRUE)))
  state_columns <- DBI::dbGetQuery(
    connection, "PRAGMA table_info(capsule_registry_allocator_state)")$name
  expect_false(any(grepl(
    "max|remaining|quota|limit|exhaust", state_columns,
    ignore.case = TRUE)))
})

test_that("bound registration requires the next allocator sequence", {
  fixture <- .capsule_registry_fixture()
  first <- .capsule_registry_identity(fixture$config, 1L)
  admission <- function(identity, sequence) {
    .dsvert_capsule_registry_allocator_admission(
      fixture$config, identity, sequence,
      digest::digest(
        paste0("sequence-record-", sequence),
        algo = "sha256", serialize = FALSE),
      digest::digest(
        paste0("sequence-prepare-", sequence),
        algo = "sha256", serialize = FALSE),
      digest::digest(
        paste0("sequence-own-commit-", sequence),
        algo = "sha256", serialize = FALSE),
      fixture$secret)
  }
  expect_error(.dsvert_capsule_registry_register_bound(
    fixture$config, first, admission(first, 1), fixture$secret),
    "not the next registry sequence")
  expect_identical(.dsvert_capsule_registry_status(
    fixture$config, fixture$secret)$capsule_count, 0)

  expect_true(.dsvert_capsule_registry_register_bound(
    fixture$config, first, admission(first, 0), fixture$secret)$created)
  second <- .capsule_registry_identity(fixture$config, 2L)
  expect_error(.dsvert_capsule_registry_register_bound(
    fixture$config, second, admission(second, 0), fixture$secret),
    "not the next registry sequence")
  expect_identical(.dsvert_capsule_registry_status(
    fixture$config, fixture$secret)$capsule_count, 1)
})

test_that("registry detects tamper, wrong key and conflicting row replay", {
  fixture <- .capsule_registry_fixture()
  first <- .dsvert_capsule_registry_register(
    fixture$config, .capsule_registry_identity(fixture$config, 1L),
    fixture$secret)
  second <- .dsvert_capsule_registry_register(
    fixture$config, .capsule_registry_identity(fixture$config, 2L),
    fixture$secret)
  expect_true(first$created)
  expect_true(second$created)
  expect_error(.dsvert_capsule_registry_snapshot(
    fixture$config, rev(fixture$secret)), "policy or authentication")

  connection <- DBI::dbConnect(
    RSQLite::SQLite(), fixture$config$registry_path)
  DBI::dbExecute(connection, paste(
    "UPDATE capsule_registry_records SET capsule_delta = '0e+00'",
    "WHERE sequence = 1"))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_capsule_registry_status(
    fixture$config, fixture$secret), "row integrity")
  expect_error(.dsvert_capsule_registry_snapshot(
    fixture$config, fixture$secret), "row integrity")

  replay_fixture <- .capsule_registry_fixture(
    path = tempfile("dsvert-capsule-registry-replay-"))
  one <- .dsvert_capsule_registry_register(
    replay_fixture$config,
    .capsule_registry_identity(replay_fixture$config, 1L),
    replay_fixture$secret)
  two <- .dsvert_capsule_registry_register(
    replay_fixture$config,
    .capsule_registry_identity(replay_fixture$config, 2L),
    replay_fixture$secret)
  expect_true(one$created && two$created)
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), replay_fixture$config$registry_path)
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT sequence, identity_json FROM capsule_registry_records",
    "ORDER BY sequence"))
  DBI::dbExecute(connection, paste(
    "UPDATE capsule_registry_records SET identity_json = ?",
    "WHERE sequence = 1"), params = list(rows$identity_json[[1L]]))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_capsule_registry_snapshot(
    replay_fixture$config, replay_fixture$secret),
    "invalid identity|row integrity")
})

test_that("fast-state migration is one-time and later state loss fails closed", {
  fixture <- .capsule_registry_fixture()
  identity <- .capsule_registry_identity(fixture$config, 1L)
  admission <- .dsvert_capsule_registry_allocator_admission(
    fixture$config, identity, 0,
    digest::digest("migration-joint-record", algo = "sha256",
                   serialize = FALSE),
    digest::digest("migration-prepare-set", algo = "sha256",
                   serialize = FALSE),
    digest::digest("migration-own-commit", algo = "sha256",
                   serialize = FALSE),
    fixture$secret)
  .dsvert_capsule_registry_register_bound(
    fixture$config, identity, admission, fixture$secret)

  connection <- DBI::dbConnect(
    RSQLite::SQLite(), fixture$config$registry_path)
  legacy <- .dsvert_capsule_registry_meta(
    fixture$config, fixture$secret, fast_state = FALSE)
  DBI::dbExecute(connection,
    "DELETE FROM capsule_registry_meta WHERE key = 'fast_state_version'")
  DBI::dbExecute(connection, paste(
    "UPDATE capsule_registry_meta SET value = ? WHERE key = 'registry_auth'"),
    params = list(unname(legacy[["registry_auth"]])))
  DBI::dbDisconnect(connection)

  rebuilds <- 0L
  original_rebuild <- .dsvert_capsule_registry_rebuild_allocator_state
  migrated <- testthat::with_mocked_bindings(
    .dsvert_capsule_registry_bound_integrity_state(
      fixture$config, fixture$secret),
    .dsvert_capsule_registry_rebuild_allocator_state = function(...) {
      rebuilds <<- rebuilds + 1L
      original_rebuild(...)
    },
    .package = "dsVert")
  expect_identical(rebuilds, 1L)
  expect_identical(migrated$summary$capsule_count, 1)
  expect_silent(testthat::with_mocked_bindings(
    .dsvert_capsule_registry_bound_integrity_state(
      fixture$config, fixture$secret),
    .dsvert_capsule_registry_rebuild_allocator_state = function(...) {
      stop("unexpected repeated full migration", call. = FALSE)
    },
    .package = "dsVert"))

  connection <- DBI::dbConnect(
    RSQLite::SQLite(), fixture$config$registry_path)
  marker <- DBI::dbGetQuery(connection, paste(
    "SELECT value FROM capsule_registry_meta",
    "WHERE key = 'fast_state_version'"))$value[[1L]]
  expect_identical(
    marker, .DSVERT_CAPSULE_REGISTRY_FAST_STATE_VERSION)
  DBI::dbExecute(connection,
    "DELETE FROM capsule_registry_allocator_state")
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_capsule_registry_bound_integrity_state(
    fixture$config, fixture$secret),
    "missing authenticated allocator state")
})

test_that("allocator-bound registry updates record and head atomically", {
  fixture <- .capsule_registry_fixture()
  .dsvert_capsule_registry_bound_integrity_state(
    fixture$config, fixture$secret)
  identity <- .capsule_registry_identity(fixture$config, 1L)
  admission <- .dsvert_capsule_registry_allocator_admission(
    fixture$config, identity, 0,
    digest::digest("atomic-joint-record", algo = "sha256",
                   serialize = FALSE),
    digest::digest("atomic-prepare-set", algo = "sha256",
                   serialize = FALSE),
    digest::digest("atomic-own-commit", algo = "sha256",
                   serialize = FALSE),
    fixture$secret)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_capsule_registry_register_bound(
      fixture$config, identity, admission, fixture$secret),
    .dsvert_capsule_registry_write_allocator_state = function(...) {
      stop("injected registry-state write failure", call. = FALSE)
    },
    .package = "dsVert"), "injected registry-state write failure")

  connection <- DBI::dbConnect(
    RSQLite::SQLite(), fixture$config$registry_path)
  expect_identical(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM capsule_registry_records")$n[[1L]],
    0L)
  expect_identical(DBI::dbGetQuery(connection, paste(
    "SELECT COUNT(*) AS n FROM capsule_registry_allocator_bindings"))$n[[1L]],
    0L)
  state <- .dsvert_capsule_registry_read_state(
    connection, fixture$config, fixture$secret)
  allocator <- .dsvert_capsule_registry_read_allocator_state(
    connection, fixture$config, fixture$secret)
  DBI::dbDisconnect(connection)
  expect_identical(state$capsule_count, 0)
  expect_identical(allocator$binding_count, 0)

  registered <- .dsvert_capsule_registry_register_bound(
    fixture$config, identity, admission, fixture$secret)
  expect_true(registered$created)
  expect_identical(registered$summary$capsule_count, 1)
})

test_that("concurrent registration has one memoized capsule and a valid chain", {
  skip_on_os("windows")
  fixture <- .capsule_registry_fixture(
    path = tempfile("dsvert-capsule-registry-concurrent-"),
    epsilon = 0.5, delta = 0.01, lifetime_max = 13)
  capsule_identity <- .capsule_registry_identity(fixture$config)
  results <- parallel::mclapply(seq_len(8L), function(unused) {
    tryCatch(.dsvert_capsule_registry_register(
      fixture$config, capsule_identity, fixture$secret),
      error = function(error) error)
  }, mc.cores = 4L)
  expect_false(any(vapply(results, inherits, logical(1L), "error")))
  expect_identical(sum(vapply(results, `[[`, logical(1L), "created")), 1L)
  expect_true(all(vapply(results, function(value) {
    identical(value$record$capsule_id, capsule_identity$capsule_id)
  }, logical(1L))))

  distinct <- parallel::mclapply(seq_len(12L), function(index) {
    tryCatch(.dsvert_capsule_registry_register(
      fixture$config,
      .capsule_registry_identity(fixture$config, index + 1L),
      fixture$secret), error = function(error) error)
  }, mc.cores = 4L)
  expect_false(any(vapply(distinct, inherits, logical(1L), "error")))
  snapshot <- .dsvert_capsule_registry_snapshot(
    fixture$config, fixture$secret)
  expect_identical(snapshot$summary$capsule_count, 13)
  expect_identical(vapply(
    snapshot$records, `[[`, numeric(1L), "sequence"), as.numeric(0:12))
  expect_s3_class(tryCatch(.dsvert_capsule_registry_register(
    fixture$config, .capsule_registry_identity(fixture$config, 14L),
    fixture$secret), error = identity),
    "dsvert_dp_lifetime_budget_exhausted")
})

test_that("capsule registry remains internal and does not alter legacy surfaces", {
  exports <- getNamespaceExports("dsVert")
  expect_false(any(grepl("capsule.registry", exports, ignore.case = TRUE)))
  description <- readLines(
    .dsvert_test_package_file("DESCRIPTION"), warn = FALSE)
  aggregate <- description[grep("^(AggregateMethods|AssignMethods):", description)]
  expect_false(any(grepl("capsule", aggregate, ignore.case = TRUE)))
})
