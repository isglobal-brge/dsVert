.formal_cox_worker_control_selector <- function() {
  list(plan_sha256 = strrep("a", 64L), attempt_id = strrep("b", 64L))
}

.formal_cox_worker_control_host <- function(replayed = FALSE) {
  list(
    version = "dsvert-formal-cox-blockwise-worker-host-status-v1",
    peer_name = "site_a", plan_sha256 = strrep("a", 64L),
    attempt_id = strrep("b", 64L), replayed = replayed,
    production_ready = FALSE)
}

test_that("formal Cox worker host is an exact burned-selector replay", {
  selector <- .formal_cox_worker_control_selector()
  starts <- 0L
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_start = function(plan_sha256, attempt_id) {
      starts <<- starts + 1L
      expect_identical(plan_sha256, selector$plan_sha256)
      expect_identical(attempt_id, selector$attempt_id)
      .formal_cox_worker_control_host(FALSE)
    },
    .package = "dsVert")

  result <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "host_start",
    structure(list(), names = character()))
  expect_identical(starts, 1L)
  expect_identical(names(result), c(
    "version", "action", "payload", "production_ready"))
  expect_identical(result$version, "dsvert-formal-cox-worker-control-response-v1")
  expect_identical(result$action, "host_start")
  expect_false(result$production_ready)
  expect_false(any(grepl("key|secret|path|source|config|pid",
                         names(result$payload), ignore.case = TRUE)))
})

test_that("formal Cox worker control carries only a bounded opaque frame", {
  selector <- .formal_cox_worker_control_selector()
  seen <- NULL
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(
        plan_sha256, attempt_id, action, payload) {
      seen <<- list(plan_sha256 = plan_sha256, attempt_id = attempt_id,
                     action = action, payload = payload)
      list(version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
           payload = list(version = "opaque-control", chunk = "ciphertext"))
    },
    .package = "dsVert")

  result <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "relay",
    list(chunk = list(version = "opaque-control", ciphertext = "AQ==")))
  expect_identical(seen$plan_sha256, selector$plan_sha256)
  expect_identical(seen$attempt_id, selector$attempt_id)
  expect_identical(seen$action, "relay")
  expect_identical(result$payload$chunk, "ciphertext")
  expect_false(result$production_ready)
})

test_that("formal Cox worker opening exposes only a signed public header", {
  selector <- .formal_cox_worker_control_selector()
  seen <- NULL
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(
        plan_sha256, attempt_id, action, payload) {
      seen <<- list(plan_sha256 = plan_sha256, attempt_id = attempt_id,
                     action = action, payload = payload)
      list(version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
           payload = list(
             header = list(
               artifact_id = strrep("c", 64L), plan_sha256 = plan_sha256,
               peer_name = "site_a", local_beta_validity_sha256 = strrep("d", 64L),
               signature = "AQ=="),
             replayed = FALSE))
    },
    .package = "dsVert")

  result <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "opening",
    structure(list(), names = character()))
  expect_identical(seen$action, "opening")
  expect_identical(seen$payload, structure(list(), names = character()))
  expect_false(result$production_ready)
  expect_false(any(grepl("share|key|secret|path|storage",
                         names(result$payload$header), ignore.case = TRUE)))
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "opening", list(extra = TRUE)),
    class = "dsvert_formal_cox_error")
})

test_that("formal Cox worker relays only public finalizer handoff records", {
  selector <- .formal_cox_worker_control_selector()
  seen <- NULL
  headers <- list(
    list(artifact_id = strrep("c", 64L), plan_sha256 = selector$plan_sha256,
         signature = "AQ=="),
    list(artifact_id = strrep("c", 64L), plan_sha256 = selector$plan_sha256,
         signature = "Ag=="))
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(
        plan_sha256, attempt_id, action, payload) {
      seen <<- list(plan_sha256 = plan_sha256, attempt_id = attempt_id,
                    action = action, payload = payload)
      list(version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
           payload = list(ticket = list(
             artifact_id = strrep("c", 64L), plan_sha256 = plan_sha256,
             recipient_x25519_public_key = "AQ==", signature = "Ag=="),
             replayed = FALSE))
    },
    .package = "dsVert")

  result <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_ticket",
    list(headers = headers))
  expect_identical(seen$action, "finalizer_ticket")
  expect_identical(seen$payload, list(headers = headers))
  expect_false(result$production_ready)
  expect_false(any(grepl("share|secret|storage|path|source", names(result$payload),
                         ignore.case = TRUE)))
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_ticket",
    list(secret = "unsafe")), class = "dsvert_formal_cox_error")
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_ticket",
    list(headers = headers[[1L]])), class = "dsvert_formal_cox_error")
})

test_that("formal Cox worker controller rejects widened calls before host I/O", {
  selector <- .formal_cox_worker_control_selector()
  calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_start = function(...) {
      calls <<- calls + 1L
      .formal_cox_worker_control_host(FALSE)
    },
    .dsvert_formal_cox_worker_host_control = function(...) {
      calls <<- calls + 1L
      list(version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
           payload = list())
    },
    .package = "dsVert")
  expect_error(dsvertFormalCoxWorkerControlDS(
    "not-a-digest", selector$attempt_id, "host_start",
    structure(list(), names = character())), class = "dsvert_formal_cox_error")
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "host_start", list(extra = TRUE)),
    class = "dsvert_formal_cox_error")
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "completion", list(extra = TRUE)),
    class = "dsvert_formal_cox_error")
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "relay", list(private_key = "x")),
    class = "dsvert_formal_cox_error")
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "root_claim", list()),
    class = "dsvert_formal_cox_error")
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "accept", list(step = 0L)),
    class = "dsvert_formal_cox_error")
  expect_identical(calls, 0L)
})

test_that("formal Cox worker host start polls a live daemon and never respawns it", {
  selector <- .formal_cox_worker_control_selector()
  calls <- 0L
  spawns <- 0L
  binary <- tempfile("formal-cox-worker-")
  file.create(binary)
  on.exit(unlink(binary), add = TRUE)
  process <- new.env(parent = emptyenv())
  process$is_alive <- function() TRUE
  process$kill <- function(...) invisible(NULL)
  process$wait <- function(...) invisible(NULL)
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(...) {
      calls <<- calls + 1L
      if (calls == 1L) stop("socket absent", call. = FALSE)
      list(version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
           payload = list(receipt = list(), done = FALSE))
    },
    .dsvert_formal_cox_worker_host_spawn = function(...) {
      spawns <<- spawns + 1L
      process
    },
    .findMpcBinary = function() binary,
    .dsvert_require_configured_local_peer_name = function() "site_a",
    .package = "dsVert")
  started <- .dsvert_formal_cox_worker_host_start(
    selector$plan_sha256, selector$attempt_id)
  expect_identical(spawns, 1L)
  expect_false(started$replayed)

  replayed <- .dsvert_formal_cox_worker_host_start(
    selector$plan_sha256, selector$attempt_id)
  expect_identical(spawns, 1L)
  expect_true(replayed$replayed)
})
