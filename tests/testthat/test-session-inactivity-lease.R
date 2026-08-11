test_that("session lifetime is based on durable progress, not total age", {
  storage <- new.env(parent = emptyenv())
  session <- new.env(parent = emptyenv())
  session$.session_id <- "lease_active"
  session$.created_at <- 100
  session$.last_activity <- 100
  storage$lease_active <- session
  clock <- 100

  testthat::with_mocked_bindings({
    # Each update is durable protocol progress.  The total lifetime exceeds
    # the lease, but no idle interval does.
    clock <- clock + .SESSION_TTL_SECONDS - 1
    .session_progress(session)
    .reap_expired_sessions(storage)
    expect_true(exists("lease_active", envir = storage, inherits = FALSE))

    clock <- clock + .SESSION_TTL_SECONDS - 1
    .session_progress(session)
    .reap_expired_sessions(storage)
    expect_gt(clock - session$.created_at, .SESSION_TTL_SECONDS)
    expect_true(exists("lease_active", envir = storage, inherits = FALSE))

    # Resolving/polling an existing session is deliberately read-only and
    # cannot renew the lease.
    progress_at <- session$.last_activity
    clock <- clock + .SESSION_TTL_SECONDS
    expect_identical(.S("lease_active"), session)
    expect_identical(session$.last_activity, progress_at)
    .reap_expired_sessions(storage)
    expect_true(exists("lease_active", envir = storage, inherits = FALSE))

    clock <- clock + 1
    .reap_expired_sessions(storage)
    expect_false(exists("lease_active", envir = storage, inherits = FALSE))
  },
  .session_now = function() clock,
  .session_storage = function() storage,
  .package = "dsVert")
})

test_that("session progress timestamps cannot roll the lease backwards", {
  session <- new.env(parent = emptyenv())
  session$.last_activity <- 200

  expect_identical(.session_progress(session, 199), 200)
  expect_identical(session$.last_activity, 200)
  expect_error(.session_progress(session, NA_real_), "timestamp")
  expect_error(.session_progress(list(), 201), "target")
})

test_that("resource registry releases many expired session owners", {
  storage <- new.env(parent = emptyenv())
  baseline <- names(.dsvert_resource_registry$sessions)
  clock <- 1000
  ids <- vapply(seq_len(100L), function(index) {
    sprintf("%08x-0000-4000-8000-%012x", index, index)
  }, character(1L))
  terminal_id <- "ffffffff-ffff-4fff-8fff-ffffffffffff"

  testthat::with_mocked_bindings({
    for (session_id in ids) .S(session_id)
    registered <- setdiff(
      names(.dsvert_resource_registry$sessions), baseline)
    expect_length(registered, length(ids))

    clock <- clock + .SESSION_TTL_SECONDS + 1
    terminal <- .S(terminal_id)
    expect_true(is.environment(terminal))
    expect_false(any(ids %in% ls(storage, all.names = TRUE)))
    expect_length(setdiff(
      names(.dsvert_resource_registry$sessions), baseline), 1L)

    .cleanup_session(terminal_id)
    expect_setequal(names(.dsvert_resource_registry$sessions), baseline)
  },
  .session_now = function() clock,
  .session_storage = function() storage,
  .package = "dsVert")
})

test_that("global accounting includes relay, typed, and exact-gc bytes", {
  spool <- tempfile("resource-exact-spool-")
  dir.create(spool, mode = "0700")
  on.exit(unlink(spool, recursive = TRUE), add = TRUE)
  session <- new.env(parent = emptyenv())
  session$.dsvert_dsi_relay <- new.env(parent = emptyenv())
  session$.dsvert_dsi_relay$retained_bytes <- 101
  session$.typed_blob_retained_head <- list(total = 202)
  session$.exact_gc_ops <- new.env(parent = emptyenv())
  operation <- new.env(parent = emptyenv())
  operation$spool <- spool
  operation$status <- "running"
  operation$resource_reservation_bytes <- 303
  session$.exact_gc_ops$op_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa <- operation
  baseline <- .dsvert_resource_retained_bytes()
  .dsvert_resource_register(session)
  on.exit(.dsvert_resource_unregister(session), add = TRUE)
  external <- .dsvert_resource_external_owner(
    "capsule-source", tempfile("combined-resource-store-", fileext = ".sqlite"))
  .dsvert_resource_external_reconcile(external, 404, "capsule-source")
  on.exit(.dsvert_resource_external_unregister(external), add = TRUE)

  totals <- testthat::with_mocked_bindings(list(
    session = .dsvert_resource_session_bytes(session),
    global = .dsvert_resource_retained_bytes()),
    .dsvert_typed_blob_accounting_authentic = function(...) TRUE,
    .package = "dsVert")
  expect_identical(totals$session, 606)
  expect_identical(totals$global, baseline + 606 + 404)
})

test_that("Frequency persistent estimates are fixed, bounded, and role exact", {
  for (role in c("source_owner", "secondary_noise_authority")) {
    expect_identical(
      .dsvert_dp_frequency_resource_estimate_v1(1L, 65536L, role),
      8)
    expect_identical(
      .dsvert_dp_frequency_resource_estimate_v1(1000000L, 65536L, role),
      8000000)
  }
  expect_identical(
    .dsvert_dp_frequency_resource_estimate_v1(
      1000000L, 65536L, "witness"), 0)
  expect_error(.dsvert_dp_frequency_resource_estimate_v1(
    0, 65536L, "source_owner"), "geometry")
  expect_error(.dsvert_dp_frequency_resource_estimate_v1(
    1000001, 65536L, "source_owner"), "geometry")
  expect_error(.dsvert_dp_frequency_resource_estimate_v1(
    1L, 65535L, "source_owner"), "geometry")
  expect_error(.dsvert_dp_frequency_resource_estimate_v1(
    1L, 65536L, "source"), "role")
})

test_that("Frequency reservations bind once and generic cleanup releases", {
  storage <- new.env(parent = emptyenv())
  session_id <- "11111111-1111-4111-8111-111111111111"
  artifact <- strrep("a", 64L)
  session <- new.env(parent = emptyenv())
  session$.session_id <- session_id
  storage[[session_id]] <- session
  baseline <- .dsvert_resource_retained_bytes()

  testthat::with_mocked_bindings({
    reservation <- .dsvert_dp_frequency_resource_reserve_v1(
      session, session_id, artifact, "source_owner", 3L, 65536L)
    expect_identical(reservation$bytes, 24)
    expect_identical(reservation[c("session_id", "artifact_key", "role")],
                     list(session_id = session_id, artifact_key = artifact,
                          role = "source_owner"))
    expect_identical(.dsvert_resource_session_bytes(session),
                     reservation$bytes)
    expect_identical(.dsvert_resource_retained_bytes(),
                     baseline + reservation$bytes)
    session$.typed_blob_retained_head <- list(total = 1409104)
    combined <- testthat::with_mocked_bindings(
      .dsvert_resource_session_bytes(session),
      .dsvert_typed_blob_accounting_authentic = function(...) TRUE,
      .package = "dsVert")
    session$.typed_blob_retained_head <- NULL
    expect_identical(combined, reservation$bytes + 1409104)
    expect_identical(.dsvert_dp_frequency_resource_reserve_v1(
      session, session_id, artifact, "source_owner", 3L, 65536L),
      reservation)
    expect_error(.dsvert_dp_frequency_resource_reserve_v1(
      session, session_id, strrep("b", 64L), "source_owner", 3L, 65536L),
      "Conflicting Frequency resource reservation")

    .cleanup_session(session_id)
    expect_identical(.dsvert_resource_retained_bytes(), baseline)
    expect_false(exists(session_id, envir = storage, inherits = FALSE))
  }, .session_storage = function() storage, .package = "dsVert")
})
