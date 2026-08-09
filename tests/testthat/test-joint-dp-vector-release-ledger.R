.release_ledger_secret <- function() as.raw(seq_len(32L) - 1L)

.release_ledger_config <- function(
    peers = c("peer_a", "peer_b"),
    lifetime_max_distinct_capsules = 10,
    release_epsilon = 0.75, release_delta = 1e-6) {
  .dsvert_joint_dp_release_ledger_config(
    domain = "biomedical-test",
    cohort_id = "cohort_1",
    local_peer_name = "peer_a",
    consortium_peer_names = peers,
    peer_pinset_sha256 = paste(rep("a", 64L), collapse = ""),
    release_epsilon = release_epsilon,
    release_delta = release_delta,
    lifetime_max_distinct_capsules = lifetime_max_distinct_capsules)
}

.release_ledger_roots <- function(epoch_a = 1, epoch_b = 1) {
  list(
    peer_a = list(
      privacy_epoch = as.numeric(epoch_a),
      noise_key_id = paste0("file_", paste(rep("1", 64L), collapse = "")),
      provider_id = "owner_only_file_v2",
      release_domain_generation = as.numeric(epoch_a),
      release_domain_id = paste0(
        "rd_", paste(rep(if (epoch_a == 1) "4" else "5", 64L),
                      collapse = ""))),
    peer_b = list(
      privacy_epoch = as.numeric(epoch_b),
      noise_key_id = paste0(
        "file_", paste(rep(if (epoch_b == 1) "2" else "3", 64L),
                        collapse = "")),
      provider_id = "owner_only_file_v2",
      release_domain_generation = as.numeric(epoch_b),
      release_domain_id = paste0(
        "rd_", paste(rep(if (epoch_b == 1) "6" else "7", 64L),
                      collapse = ""))))
}

.release_ledger_instance <- function(
    capsule_id = paste(rep("c", 64L), collapse = ""),
    roots = .release_ledger_roots()) {
  value <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_VECTOR_RELEASE_INSTANCE_VERSION,
    capsule_id = capsule_id,
    peer_noise_roots = roots))
  list(value = value, json = .dsvert_dp_canonical_json(value),
       id = .dsvert_joint_dp_hash(value))
}

.release_ledger_public <- function(
    instance = .release_ledger_instance(),
    root = paste(rep("d", 64L), collapse = "")) {
  value <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_VECTOR_RELEASE_VERSION,
    phase = "vector_released",
    peer_name = "peer_a",
    capsule_id = instance$value$capsule_id,
    release_instance_id = instance$id,
    final_vector_root = root,
    epsilon = .dsvert_joint_dp_decimal(
      0.75, "test epsilon", open_minimum = TRUE),
    delta = .dsvert_joint_dp_decimal(
      1e-6, "test delta", open_minimum = TRUE),
    signature = paste(rep("e", 128L), collapse = "")))
  .dsvert_dp_canonical_json(value)
}

.release_ledger_connection <- function(config = .release_ledger_config()) {
  path <- tempfile(fileext = ".sqlite")
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, "PRAGMA busy_timeout=30000")
  .dsvert_joint_dp_release_ledger_initialize(
    connection, config, .release_ledger_secret())
  list(connection = connection, path = path, config = config)
}

.release_ledger_commit <- function(fixture, instance, public, ...) {
  .dsvert_joint_dp_release_ledger_commit(
    fixture$connection, fixture$config, .release_ledger_secret(),
    instance$json, public, ...)
}

.release_ledger_decimal_fraction <- function(value) {
  parts <- .dsvert_joint_dp_release_ledger_decimal_parts(
    value, "test exact decimal")
  coefficient <- openssl::bignum(parts$coefficient)
  if (parts$exponent >= 0) {
    list(
      numerator = coefficient * openssl::bignum(10)^parts$exponent,
      denominator = openssl::bignum(1))
  } else {
    list(
      numerator = coefficient,
      denominator = openssl::bignum(10)^(-parts$exponent))
  }
}

.release_ledger_double_fraction <- function(value) {
  expect_true(is.numeric(value) && length(value) == 1L &&
                is.finite(value) && value > 0)
  text <- sprintf("%a", value)
  match <- regexec(
    "^0x([0-9a-f])(?:\\.([0-9a-f]+))?p([+-]?[0-9]+)$",
    text, perl = TRUE)
  parts <- regmatches(text, match)[[1L]]
  expect_length(parts, 4L)
  fractional <- parts[[3L]]
  digits <- strsplit(paste0(parts[[2L]], fractional), "", fixed = TRUE)[[1L]]
  alphabet <- c(as.character(0:9), letters[1:6])
  coefficient <- openssl::bignum(0)
  for (digit in digits) {
    coefficient <- coefficient * openssl::bignum(16) +
      openssl::bignum(match(digit, alphabet) - 1L)
  }
  exponent <- as.integer(parts[[4L]]) - 4L * nchar(fractional)
  if (exponent >= 0L) {
    list(
      numerator = coefficient * openssl::bignum(2)^exponent,
      denominator = openssl::bignum(1))
  } else {
    list(
      numerator = coefficient,
      denominator = openssl::bignum(2)^(-exponent))
  }
}

.release_ledger_expect_double_gte_decimal <- function(value, decimal) {
  exact <- .release_ledger_decimal_fraction(decimal)
  if (exact$numerator == openssl::bignum(0)) {
    expect_identical(value, 0)
    return(invisible(TRUE))
  }
  projected <- .release_ledger_double_fraction(value)
  expect_true(
    projected$numerator * exact$denominator >=
      exact$numerator * projected$denominator)
}

.release_ledger_rewrite_state_v1 <- function(fixture) {
  secret <- .release_ledger_secret()
  state <- .dsvert_joint_dp_release_ledger_read_state(
    fixture$connection, fixture$config, secret)
  epsilon <- .dsvert_joint_dp_release_ledger_decimal(
    0, "legacy test epsilon")
  delta <- .dsvert_joint_dp_release_ledger_decimal(
    0, "legacy test delta")
  if (state$release_count) for (index in seq_len(state$release_count)) {
    epsilon <- .dsvert_joint_dp_release_ledger_decimal(
      as.numeric(epsilon) + as.numeric(fixture$config$release_epsilon),
      "legacy test epsilon")
    delta <- .dsvert_joint_dp_release_ledger_decimal(
      as.numeric(delta) + as.numeric(fixture$config$release_delta),
      "legacy test delta")
  }
  value <- .dsvert_joint_dp_release_ledger_state_material(
    fixture$config, state$release_count, epsilon, delta,
    state$head_chain, state$tail_release_instance_id, state$tail_row_mac,
    version = .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)
  mac <- .dsvert_joint_dp_release_ledger_hmac(secret, "state", value)
  DBI::dbExecute(fixture$connection, paste(
    "UPDATE vector_release_ledger_state SET cumulative_epsilon=?,",
    "cumulative_delta=?,state_mac=? WHERE singleton=1"),
    params = list(epsilon, delta, mac))
  value$state_mac <- mac
  value
}

test_that("a public release instance is counted exactly once", {
  fixture <- .release_ledger_connection()
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  instance <- .release_ledger_instance()
  public <- .release_ledger_public(instance)

  first <- .release_ledger_commit(fixture, instance, public)
  replay <- .release_ledger_commit(fixture, instance, public)
  status <- .dsvert_joint_dp_release_ledger_status(
    fixture$connection, fixture$config, .release_ledger_secret())

  expect_true(first$created)
  expect_false(replay$created)
  expect_identical(first$record, replay$record)
  expect_equal(status$release_instance_count, 1)
  expect_equal(status$lifetime_max_distinct_capsules, 10)
  expect_equal(status$remaining_distinct_capsules, 9)
  expect_equal(status$cumulative_epsilon, 0.75)
  expect_equal(status$cumulative_delta, 1e-6)
  expect_identical(
    status$composition_role,
    "basic_composition_authenticated_lifetime_bound")
  expect_true(status$operation_limit)
  expect_false(status$request_limit)
  expect_true(status$history_can_deny_operation)
})

test_that("release-ledger audit matches persisted exact decimal totals", {
  fixture <- .release_ledger_connection()
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  checkpoints <- c(3L, 7L, 10L)
  for (index in seq_len(max(checkpoints))) {
    instance <- .release_ledger_instance(
      capsule_id = sprintf("%064x", index))
    .release_ledger_commit(
      fixture, instance, .release_ledger_public(instance))
    if (index %in% checkpoints) {
      audit <- .dsvert_joint_dp_release_ledger_audit(
        fixture$connection, fixture$config, .release_ledger_secret())
      expect_identical(
        audit$state$cumulative_epsilon,
        .dsvert_joint_dp_release_ledger_exact_total(
          fixture$config$release_epsilon, index,
          "checkpoint cumulative epsilon"))
      expect_identical(
        audit$state$cumulative_delta,
        .dsvert_joint_dp_release_ledger_exact_total(
          fixture$config$release_delta, index,
          "checkpoint cumulative delta"))
      expect_identical(audit$summary$release_instance_count,
                       as.numeric(index))
      expect_equal(audit$summary$cumulative_epsilon, 0.75 * index)
      expect_equal(audit$summary$cumulative_delta, 1e-6 * index)
    }
  }

  tail <- DBI::dbGetQuery(fixture$connection, paste(
    "SELECT release_instance_id,row_mac FROM vector_release_ledger_records",
    "WHERE sequence=9"))
  tampered <- tail$row_mac[[1L]]
  substr(tampered, 1L, 1L) <-
    if (startsWith(tampered, "0")) "1" else "0"
  DBI::dbExecute(fixture$connection, paste(
    "UPDATE vector_release_ledger_records SET row_mac=?",
    "WHERE release_instance_id=?"),
    params = list(tampered, tail$release_instance_id[[1L]]))
  expect_error(
    .dsvert_joint_dp_release_ledger_audit(
      fixture$connection, fixture$config, .release_ledger_secret()),
    "integrity or authentication")
})

test_that("v2 accounting is exact internally and outward-rounded publicly", {
  cases <- list(
    list(value = "0", count = 2^53 - 1),
    list(value = "0.1", count = 2^53 - 1),
    list(value = "9.9999999999999995e-07", count = 100),
    list(value = "1e-320", count = 2^53 - 1),
    list(value = "8", count = 2^53 - 1))
  for (case in cases) {
    exact <- .dsvert_joint_dp_release_ledger_exact_total(
      case$value, case$count, "adversarial exact total")
    input <- .release_ledger_decimal_fraction(case$value)
    total <- .release_ledger_decimal_fraction(exact)
    expect_true(
      total$numerator * input$denominator ==
        input$numerator * openssl::bignum(sprintf("%.0f", case$count)) *
          total$denominator,
      info = paste(case$value, case$count))
    projection <- .dsvert_joint_dp_release_ledger_upper_numeric(
      exact, "adversarial exact total")
    .release_ledger_expect_double_gte_decimal(projection, exact)
  }
  expect_identical(
    .dsvert_joint_dp_release_ledger_exact_sum(
      c("0.1", "0.2"), "adversarial exact sum"),
    "3e-1")
  expect_identical(
    .dsvert_joint_dp_release_ledger_exact_sum(
      rep("9.9999999999999995e-07", 100L),
      "adversarial repeated exact sum"),
    .dsvert_joint_dp_release_ledger_exact_total(
      "9.9999999999999995e-07", 100L,
      "adversarial repeated exact total"))

  fixture <- .release_ledger_connection()
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  instance <- .release_ledger_instance()
  .release_ledger_commit(fixture, instance, .release_ledger_public(instance))
  state <- .dsvert_joint_dp_release_ledger_read_state(
    fixture$connection, fixture$config, .release_ledger_secret())
  status <- .dsvert_joint_dp_release_ledger_status(
    fixture$connection, fixture$config, .release_ledger_secret())
  expect_identical(
    state$version, .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION)
  .release_ledger_expect_double_gte_decimal(
    status$release_epsilon, fixture$config$release_epsilon)
  .release_ledger_expect_double_gte_decimal(
    status$release_delta, fixture$config$release_delta)
  .release_ledger_expect_double_gte_decimal(
    status$cumulative_epsilon, state$cumulative_epsilon)
  .release_ledger_expect_double_gte_decimal(
    status$cumulative_delta, state$cumulative_delta)
})

test_that("lifetime epsilon and delta borders use exact decimal arithmetic", {
  expect_no_error(.release_ledger_config(
    lifetime_max_distinct_capsules = 10,
    release_epsilon = "0.8",
    release_delta = "0.09999999999999999"))
  expect_error(.release_ledger_config(
    lifetime_max_distinct_capsules = 10,
    release_epsilon = "0.8000000000000001",
    release_delta = 0), "lifetime privacy bound")
  expect_error(.release_ledger_config(
    lifetime_max_distinct_capsules = 10,
    release_epsilon = "0.8",
    release_delta = "0.1"), "lifetime privacy bound")
  expect_error(.release_ledger_config(
    lifetime_max_distinct_capsules = 0),
    "lifetime maximum distinct capsules")
  expect_error(.release_ledger_config(
    lifetime_max_distinct_capsules = 1.5),
    "lifetime maximum distinct capsules")

  withr::local_options(list(OutDec = ","))
  expect_identical(
    .dsvert_joint_dp_release_ledger_decimal(0.8, "locale-safe epsilon"),
    "8.0000000000000004e-01")
  expect_error(.release_ledger_config(
    lifetime_max_distinct_capsules = 10,
    release_epsilon = 0.8, release_delta = 0),
    "lifetime privacy bound")
})

test_that("authenticated v1 state migrates only after a full legacy audit", {
  fixture <- .release_ledger_connection()
  for (index in seq_len(7L)) {
    instance <- .release_ledger_instance(
      capsule_id = sprintf("%064x", index))
    .release_ledger_commit(
      fixture, instance, .release_ledger_public(instance))
  }
  legacy <- .release_ledger_rewrite_state_v1(fixture)
  exact_delta <- .dsvert_joint_dp_release_ledger_exact_total(
    fixture$config$release_delta, 7, "migration test delta")
  expect_false(identical(legacy$cumulative_delta, exact_delta))
  DBI::dbDisconnect(fixture$connection)

  readonly <- DBI::dbConnect(
    RSQLite::SQLite(), fixture$path, flags = RSQLite::SQLITE_RO)
  recovered <- .dsvert_joint_dp_release_ledger_audit(
    readonly, fixture$config, .release_ledger_secret())
  .release_ledger_expect_double_gte_decimal(
    recovered$summary$cumulative_delta, exact_delta)
  expect_identical(
    .dsvert_joint_dp_release_ledger_read_state(
      readonly, fixture$config, .release_ledger_secret())$version,
    .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)
  DBI::dbDisconnect(readonly)

  fixture$connection <- DBI::dbConnect(RSQLite::SQLite(), fixture$path)
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  .dsvert_joint_dp_release_ledger_status(
    fixture$connection, fixture$config, .release_ledger_secret())
  migrated <- .dsvert_joint_dp_release_ledger_read_state(
    fixture$connection, fixture$config, .release_ledger_secret())
  expect_identical(
    migrated$version, .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION)
  expect_identical(migrated$cumulative_delta, exact_delta)

  DBI::dbDisconnect(fixture$connection)
  fixture$connection <- DBI::dbConnect(RSQLite::SQLite(), fixture$path)
  expect_identical(
    .dsvert_joint_dp_release_ledger_audit(
      fixture$connection, fixture$config,
      .release_ledger_secret())$state$cumulative_delta,
    exact_delta)
})

test_that("an empty authenticated v1 state audits read-only and migrates", {
  fixture <- .release_ledger_connection()
  secret <- .release_ledger_secret()
  state <- .dsvert_joint_dp_release_ledger_read_state(
    fixture$connection, fixture$config, secret)
  legacy <- .dsvert_joint_dp_release_ledger_state_material(
    fixture$config, 0, "0", "0", "GENESIS", "", "",
    version = .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)
  legacy_mac <- .dsvert_joint_dp_release_ledger_hmac(
    secret, "state", legacy)
  DBI::dbExecute(fixture$connection, paste(
    "UPDATE vector_release_ledger_state SET cumulative_epsilon='0',",
    "cumulative_delta='0',state_mac=? WHERE singleton=1"),
    params = list(legacy_mac))
  expect_identical(state$release_count, 0)
  DBI::dbDisconnect(fixture$connection)

  readonly <- DBI::dbConnect(
    RSQLite::SQLite(), fixture$path, flags = RSQLite::SQLITE_RO)
  before <- DBI::dbGetQuery(
    readonly, "SELECT * FROM vector_release_ledger_state")
  audit <- .dsvert_joint_dp_release_ledger_audit(
    readonly, fixture$config, secret)
  after <- DBI::dbGetQuery(
    readonly, "SELECT * FROM vector_release_ledger_state")
  expect_identical(audit$summary$release_instance_count, 0)
  expect_identical(audit$summary$cumulative_epsilon, 0)
  expect_identical(audit$summary$cumulative_delta, 0)
  expect_identical(after, before)
  expect_identical(
    .dsvert_joint_dp_release_ledger_read_state(
      readonly, fixture$config, secret)$version,
    .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)
  DBI::dbDisconnect(readonly)

  fixture$connection <- DBI::dbConnect(RSQLite::SQLite(), fixture$path)
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  status <- .dsvert_joint_dp_release_ledger_status(
    fixture$connection, fixture$config, secret)
  migrated <- .dsvert_joint_dp_release_ledger_read_state(
    fixture$connection, fixture$config, secret)
  expect_identical(status$release_instance_count, 0)
  expect_identical(migrated$version,
                   .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION)
  expect_identical(migrated$cumulative_epsilon, "0")
  expect_identical(migrated$cumulative_delta, "0")
})

test_that("tampered v1 history is never migrated", {
  fixture <- .release_ledger_connection()
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  instance <- .release_ledger_instance()
  .release_ledger_commit(fixture, instance, .release_ledger_public(instance))
  .release_ledger_rewrite_state_v1(fixture)
  config_mac <- DBI::dbGetQuery(fixture$connection, paste(
    "SELECT value FROM vector_release_ledger_meta",
    "WHERE key='config_mac'"))$value[[1L]]
  DBI::dbExecute(fixture$connection, paste(
    "UPDATE vector_release_ledger_meta SET value=?",
    "WHERE key='config_mac'"), params = list(strrep("0", 64L)))
  expect_error(
    .dsvert_joint_dp_release_ledger_audit(
      fixture$connection, fixture$config, .release_ledger_secret()),
    "metadata authentication")
  DBI::dbExecute(fixture$connection, paste(
    "UPDATE vector_release_ledger_meta SET value=?",
    "WHERE key='config_mac'"), params = list(config_mac))
  DBI::dbExecute(fixture$connection, paste(
    "UPDATE vector_release_ledger_records SET row_mac=?",
    "WHERE release_instance_id=?"), params = list(strrep("0", 64L), instance$id))
  expect_error(
    .dsvert_joint_dp_release_ledger_status(
      fixture$connection, fixture$config, .release_ledger_secret()),
    "integrity or authentication")
  expect_identical(
    .dsvert_joint_dp_release_ledger_read_state(
      fixture$connection, fixture$config,
      .release_ledger_secret())$version,
    .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)
})

test_that("a capsule cannot publish a second release instance", {
  fixture <- .release_ledger_connection()
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  old <- .release_ledger_instance()
  rotated <- .release_ledger_instance(roots = .release_ledger_roots(
    epoch_a = 1, epoch_b = 2))

  first <- .release_ledger_commit(
    fixture, old, .release_ledger_public(old))
  condition <- tryCatch(.release_ledger_commit(
    fixture, rotated, .release_ledger_public(
      rotated, paste(rep("f", 64L), collapse = ""))), error = identity)
  replay <- .release_ledger_commit(
    fixture, old, .release_ledger_public(old))
  status <- .dsvert_joint_dp_release_ledger_status(
    fixture$connection, fixture$config, .release_ledger_secret())

  expect_true(first$created)
  expect_s3_class(condition, "dsvert_dp_lifetime_budget_exhausted")
  expect_identical(
    conditionMessage(condition),
    .DSVERT_DP_LIFETIME_BUDGET_EXHAUSTED_MESSAGE)
  expect_false(replay$created)
  expect_equal(status$release_instance_count, 1)
})

test_that("a conflicting replay is rejected without changing telemetry", {
  fixture <- .release_ledger_connection()
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  instance <- .release_ledger_instance()
  .release_ledger_commit(fixture, instance, .release_ledger_public(instance))

  expect_error(
    .release_ledger_commit(
      fixture, instance, .release_ledger_public(
        instance, paste(rep("0", 64L), collapse = ""))),
    "conflicting public release")
  expect_equal(.dsvert_joint_dp_release_ledger_status(
    fixture$connection, fixture$config,
    .release_ledger_secret())$release_instance_count, 1)
})

test_that("commit crash phases are atomic and response loss replays", {
  phases <- c("after_record_insert", "after_state_update")
  for (phase in phases) {
    fixture <- .release_ledger_connection()
    instance <- .release_ledger_instance()
    expect_error(.release_ledger_commit(
      fixture, instance, .release_ledger_public(instance),
      phase_hook = function(observed) {
        if (identical(observed, phase)) stop("simulated crash")
      }), "simulated crash")
    expect_equal(.dsvert_joint_dp_release_ledger_status(
      fixture$connection, fixture$config,
      .release_ledger_secret())$release_instance_count, 0)
    DBI::dbDisconnect(fixture$connection)
  }

  fixture <- .release_ledger_connection()
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  instance <- .release_ledger_instance()
  expect_error(.release_ledger_commit(
    fixture, instance, .release_ledger_public(instance),
    phase_hook = function(observed) {
      if (identical(observed, "after_commit")) stop("response lost")
    }), "response lost")
  replay <- .release_ledger_commit(
    fixture, instance, .release_ledger_public(instance))
  expect_false(replay$created)
  expect_equal(replay$summary$release_instance_count, 1)
})

test_that("tamper, row deletion and anchored rollback are detected", {
  fixture <- .release_ledger_connection()
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  one <- .release_ledger_instance()
  two <- .release_ledger_instance(
    capsule_id = paste(rep("b", 64L), collapse = ""))
  .release_ledger_commit(fixture, one, .release_ledger_public(one))
  anchor_one <- .dsvert_joint_dp_release_ledger_anchor(
    fixture$connection, fixture$config, .release_ledger_secret())
  snapshot <- tempfile(fileext = ".sqlite")
  RSQLite::sqliteCopyDatabase(fixture$connection, snapshot)
  .release_ledger_commit(fixture, two, .release_ledger_public(
    two, paste(rep("9", 64L), collapse = "")))
  anchor_two <- .dsvert_joint_dp_release_ledger_anchor(
    fixture$connection, fixture$config, .release_ledger_secret())

  .dsvert_joint_dp_release_ledger_assert_not_rolled_back(
    fixture$connection, fixture$config, .release_ledger_secret(),
    anchor_one)
  DBI::dbDisconnect(fixture$connection)
  snapshot_connection <- DBI::dbConnect(RSQLite::SQLite(), snapshot)
  RSQLite::sqliteCopyDatabase(snapshot_connection, fixture$path)
  DBI::dbDisconnect(snapshot_connection)
  fixture$connection <- DBI::dbConnect(RSQLite::SQLite(), fixture$path)
  expect_error(.dsvert_joint_dp_release_ledger_assert_not_rolled_back(
    fixture$connection, fixture$config, .release_ledger_secret(),
    anchor_two), "rolled back below")

  .release_ledger_commit(fixture, two, .release_ledger_public(
    two, paste(rep("9", 64L), collapse = "")))

  DBI::dbExecute(fixture$connection, paste(
    "DELETE FROM vector_release_ledger_records",
    "WHERE release_instance_id = ?"), params = list(two$id))
  expect_error(.dsvert_joint_dp_release_ledger_audit(
    fixture$connection, fixture$config, .release_ledger_secret()),
    "count|tail|chain")

  DBI::dbDisconnect(fixture$connection)
  fixture <- .release_ledger_connection()
  instance <- .release_ledger_instance()
  .release_ledger_commit(fixture, instance, .release_ledger_public(instance))
  DBI::dbExecute(fixture$connection, paste(
    "UPDATE vector_release_ledger_records",
    "SET record_json = replace(record_json, 'peer_a', 'peer_x')"))
  expect_error(.dsvert_joint_dp_release_ledger_audit(
    fixture$connection, fixture$config, .release_ledger_secret()),
    "authentication|integrity")
})

test_that("K=2 and K>=3 use the same two-noise-peer accounting path", {
  summaries <- lapply(list(
    c("peer_a", "peer_b"), c("peer_a", "peer_b", "peer_c")),
    function(peers) {
      fixture <- .release_ledger_connection(.release_ledger_config(peers))
      on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
      instance <- .release_ledger_instance()
      committed <- .release_ledger_commit(
        fixture, instance, .release_ledger_public(instance))
      committed$summary
    })

  expect_equal(vapply(summaries, `[[`, numeric(1L),
                      "release_instance_count"), c(1, 1))
  expect_equal(vapply(summaries, `[[`, numeric(1L),
                      "designated_noise_peer_count"), c(2, 2))
  expect_equal(vapply(summaries, `[[`, numeric(1L),
                      "consortium_peer_count"), c(2, 3))
})

test_that("the lifetime bound admits N releases and exact replay is free", {
  config <- .release_ledger_config(
    lifetime_max_distinct_capsules = 3,
    release_epsilon = 2, release_delta = 0.1)
  fixture <- .release_ledger_connection(config)
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)

  instances <- lapply(seq_len(4L), function(index) {
    capsule <- digest::digest(
      paste0("capsule-", index), algo = "sha256", serialize = FALSE)
    .release_ledger_instance(capsule_id = capsule)
  })
  for (index in seq_len(3L)) {
    instance <- instances[[index]]
    root <- digest::digest(
      paste0("root-", index), algo = "sha256", serialize = FALSE)
    expect_true(.release_ledger_commit(
      fixture, instance, .release_ledger_public(instance, root))$created)
    checkpoint <- .dsvert_joint_dp_release_ledger_status(
      fixture$connection, fixture$config, .release_ledger_secret())
    expect_identical(checkpoint$release_instance_count, as.numeric(index))
    expect_identical(checkpoint$lifetime_max_distinct_capsules, 3)
    expect_identical(
      checkpoint$remaining_distinct_capsules, as.numeric(3L - index))
  }
  denied <- tryCatch(.release_ledger_commit(
    fixture, instances[[4L]], .release_ledger_public(
      instances[[4L]], digest::digest(
        "root-4", algo = "sha256", serialize = FALSE))), error = identity)
  expect_s3_class(denied, "dsvert_dp_lifetime_budget_exhausted")

  replay_instance <- instances[[3L]]
  replay_public <- .release_ledger_public(
    replay_instance, digest::digest(
      "root-3", algo = "sha256", serialize = FALSE))
  DBI::dbExecute(fixture$connection, "BEGIN IMMEDIATE")
  committed <- FALSE
  on.exit(if (!committed) try(
    DBI::dbExecute(fixture$connection, "ROLLBACK"), silent = TRUE),
    add = TRUE)
  replay_created <- logical(10000L)
  for (index in seq_len(10000L)) {
    replay_created[[index]] <-
      .dsvert_joint_dp_release_ledger_commit_connection(
      fixture$connection, fixture$config, .release_ledger_secret(),
      replay_instance$json, replay_public)$created
  }
  expect_false(any(replay_created))
  DBI::dbExecute(fixture$connection, "COMMIT")
  committed <- TRUE
  summary <- .dsvert_joint_dp_release_ledger_status(
    fixture$connection, fixture$config, .release_ledger_secret())
  expect_equal(summary$release_instance_count, 3)
  expect_equal(summary$lifetime_max_distinct_capsules, 3)
  expect_equal(summary$remaining_distinct_capsules, 0)
  expect_equal(summary$cumulative_epsilon, 6)
  expect_true(summary$operation_limit)
  expect_false(summary$request_limit)
  expect_true(summary$history_can_deny_operation)
})

test_that("history replays final state and denies post-publication rerolls", {
  fixture <- .release_ledger_connection()
  on.exit(DBI::dbDisconnect(fixture$connection), add = TRUE)
  instance <- .release_ledger_instance()
  .release_ledger_commit(fixture, instance, .release_ledger_public(instance))

  history <- .dsvert_joint_dp_release_ledger_history(
    fixture$connection, fixture$config, .release_ledger_secret())
  expect_identical(history$status, "used")
  expect_equal(history$count, 1)
  expect_equal(history$privacy_epoch, 1)
  expect_identical(
    history$noise_key_id,
    instance$value$peer_noise_roots$peer_a$noise_key_id)
  expect_identical(
    .dsvert_joint_dp_release_recovery_route(
      instance$json, .release_ledger_roots(), final_available = TRUE)$action,
    "replay_final")
  for (roots in list(
      .release_ledger_roots(),
      .release_ledger_roots(epoch_a = 1, epoch_b = 2))) {
    condition <- tryCatch(.dsvert_joint_dp_release_recovery_route(
      instance$json, roots, final_available = FALSE), error = identity)
    expect_s3_class(condition, "dsvert_dp_lifetime_budget_exhausted")
    expect_identical(
      conditionMessage(condition),
      .DSVERT_DP_LIFETIME_BUDGET_EXHAUSTED_MESSAGE)
  }
})

test_that("the root-recovery history provider authenticates stored config", {
  fixture <- .release_ledger_connection()
  instance <- .release_ledger_instance()
  .release_ledger_commit(fixture, instance, .release_ledger_public(instance))
  direct <- .dsvert_joint_dp_release_ledger_history(
    fixture$connection, fixture$config, .release_ledger_secret())
  automatic <- .dsvert_joint_dp_release_ledger_history_from_connection(
    fixture$connection, .release_ledger_secret())
  expect_identical(automatic, direct)
  expect_error(
    .dsvert_joint_dp_release_ledger_history_from_connection(
      fixture$connection, as.raw(rep(7L, 32L))),
    "identity authentication")
  DBI::dbDisconnect(fixture$connection)
  Sys.chmod(fixture$path, mode = "0600")

  expect_identical(
    .dsvert_joint_dp_release_ledger_history_from_path(
      fixture$path, .release_ledger_secret()),
    direct)
  missing_path <- tempfile(fileext = ".sqlite")
  expect_null(.dsvert_joint_dp_release_ledger_history_from_path(
    missing_path, .release_ledger_secret()))
  empty_path <- tempfile(fileext = ".sqlite")
  empty <- DBI::dbConnect(RSQLite::SQLite(), empty_path)
  DBI::dbDisconnect(empty)
  Sys.chmod(empty_path, mode = "0600")
  expect_error(.dsvert_joint_dp_release_ledger_history_from_path(
    empty_path, .release_ledger_secret()), "empty or invalid")
})

test_that("direct vector-history reads reject links, sidecars and audit races", {
  skip_on_os("windows")
  fixture <- .release_ledger_connection()
  instance <- .release_ledger_instance()
  .release_ledger_commit(fixture, instance, .release_ledger_public(instance))
  DBI::dbDisconnect(fixture$connection)
  Sys.chmod(fixture$path, mode = "0600")
  secret <- .release_ledger_secret()

  alias <- tempfile("vector-history-symlink-")
  on.exit(unlink(alias, force = TRUE), add = TRUE)
  expect_true(file.symlink(fixture$path, alias))
  expect_error(
    .dsvert_joint_dp_release_ledger_history_from_path(alias, secret),
    "symbolic link")
  unlink(alias, force = TRUE)

  hardlink <- tempfile("vector-history-hardlink-")
  on.exit(unlink(hardlink, force = TRUE), add = TRUE)
  expect_true(file.link(fixture$path, hardlink))
  expect_error(
    .dsvert_joint_dp_release_ledger_history_from_path(
      fixture$path, secret),
    "hard links")
  unlink(hardlink, force = TRUE)

  Sys.chmod(fixture$path, mode = "0644")
  expect_error(
    .dsvert_joint_dp_release_ledger_history_from_path(
      fixture$path, secret),
    "mode 0600")
  Sys.chmod(fixture$path, mode = "0600")

  orphan <- tempfile("vector-history-orphan-")
  orphan_wal <- paste0(orphan, "-wal")
  on.exit(unlink(orphan_wal, force = TRUE), add = TRUE)
  expect_true(file.create(orphan_wal))
  Sys.chmod(orphan_wal, mode = "0600")
  expect_error(
    .dsvert_joint_dp_release_ledger_history_from_path(orphan, secret),
    "orphan SQLite sidecars")

  changing <- tempfile("vector-history-changing-", fileext = ".sqlite")
  on.exit(unlink(changing, force = TRUE), add = TRUE)
  expect_true(file.copy(fixture$path, changing))
  Sys.chmod(changing, mode = "0600")
  changed <- FALSE
  condition <- testthat::with_mocked_bindings(
    tryCatch(.dsvert_joint_dp_release_ledger_history_from_path(
      changing, secret), error = identity),
    .dsvert_joint_dp_release_ledger_history_from_connection =
      function(connection, secret) {
        stream <- file(changing, open = "ab")
        on.exit(close(stream), add = TRUE)
        writeBin(as.raw(0L), stream)
        flush(stream)
        changed <<- TRUE
        list(status = "used")
      },
    .package = "dsVert")
  expect_true(changed)
  expect_s3_class(condition, "error")
  expect_match(condition$message, "changed during its recovery audit")
})

test_that("inactive root recovery composes vector release instances", {
  base <- tempfile("dp-ledger-")
  path <- paste0(base, ".joint-dp-vector-v4.sqlite")
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  config <- .release_ledger_config()
  secret <- .release_ledger_secret()
  .dsvert_joint_dp_release_ledger_initialize(connection, config, secret)
  instance <- .release_ledger_instance()
  .dsvert_joint_dp_release_ledger_commit(
    connection, config, secret, instance$json,
    .release_ledger_public(instance))
  DBI::dbDisconnect(connection)
  Sys.chmod(path, mode = "0600")

  history <- testthat::with_mocked_bindings(
    .dsvert_dp_inactive_noise_history(base),
    .dsvert_dp_secret = function() secret,
    .package = "dsVert")
  expect_identical(history$privacy_epoch, 1)
  expect_identical(
    history$noise_key_id,
    instance$value$peer_noise_roots$peer_a$noise_key_id)
  expect_identical(history$composition_audit$source, "vector")
  expect_identical(history$composition_audit$release_count, "1")

  probe <- testthat::with_mocked_bindings(
    .dsvert_dp_noise_history_probe(list(
      ledger_path = base,
      history_provider = function() history)),
    .dsvert_dp_secret = function() secret,
    .package = "dsVert")
  expect_false(probe$authenticated_empty)
  expect_identical(probe$history$composition_audit$release_count, "1")
})

test_that("concurrent identical commits have one winner and one replay", {
  skip_on_os("windows")
  fixture <- .release_ledger_connection()
  DBI::dbDisconnect(fixture$connection)
  instance <- .release_ledger_instance()
  public <- .release_ledger_public(instance)
  results <- parallel::mclapply(seq_len(2L), function(index) {
    connection <- DBI::dbConnect(RSQLite::SQLite(), fixture$path)
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    DBI::dbExecute(connection, "PRAGMA busy_timeout=30000")
    .dsvert_joint_dp_release_ledger_commit(
      connection, fixture$config, .release_ledger_secret(),
      instance$json, public)$created
  }, mc.cores = 2L)
  expect_identical(sort(unlist(results)), c(FALSE, TRUE))
  connection <- DBI::dbConnect(RSQLite::SQLite(), fixture$path)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  expect_equal(.dsvert_joint_dp_release_ledger_status(
    connection, fixture$config,
    .release_ledger_secret())$release_instance_count, 1)
})
