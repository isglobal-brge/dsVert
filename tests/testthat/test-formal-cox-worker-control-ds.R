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
      if (identical(action, "finalizer_prepare")) {
        return(list(
          version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
          payload = list(
            intent = list(
              version = "dsvert-formal-cox-blockwise-sticky-opening-v1",
              purpose = "formal_cox_one_public_beta_validity_opening_v1",
              artifact_id = strrep("c", 64L), candidate_sha256 = strrep("e", 64L),
              final_pair_root_sha256 = strrep("f", 64L),
              opening_mode = "dual_authority_additive_ring_and_xor_validity_v1",
              exp_postprocess_mode = "certified_dyadic_interval_midpoint_v1"),
            finalized = FALSE, certificate_sha256 = "", replayed = FALSE)))
      }
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

  envelopes <- list(
    list(ticket_sha256 = strrep("d", 64L), ciphertext = "AQ=="),
    list(ticket_sha256 = strrep("d", 64L), ciphertext = "Ag=="))
  result <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_prepare",
    list(ticket = seen$payload$headers[[1L]], headers = headers,
         envelopes = envelopes))
  expect_identical(seen$action, "finalizer_prepare")
  expect_false(result$production_ready)
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_prepare",
    list(ticket = list(), headers = headers, envelopes = list(envelopes[[1L]]))),
    class = "dsvert_formal_cox_error")

  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(
        plan_sha256, attempt_id, action, payload) {
      seen <<- list(plan_sha256 = plan_sha256, attempt_id = attempt_id,
                    action = action, payload = payload)
      list(version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
           payload = list(
             artifact_id = strrep("c", 64L), candidate_sha256 = strrep("e", 64L),
             local_role = "garbler", production_ready = FALSE))
    },
    .package = "dsVert")
  staged <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_stage",
    list(ticket = list(), headers = headers, envelopes = envelopes))
  expect_identical(seen$action, "finalizer_stage")
  expect_false(staged$production_ready)

  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(
        plan_sha256, attempt_id, action, payload) {
      seen <<- list(plan_sha256 = plan_sha256, attempt_id = attempt_id,
                    action = action, payload = payload)
      list(version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
           payload = list(
             artifact_id = strrep("c", 64L), state = "publication_ready",
             certificate_sha256 = strrep("f", 64L), production_ready = FALSE))
    },
    .package = "dsVert")
  advanced <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_advance",
    list(headers = headers))
  expect_identical(seen$action, "finalizer_advance")
  expect_identical(seen$payload, list(headers = headers))
  expect_false(advanced$production_ready)
  expect_identical(advanced$payload$state, "publication_ready")
  expect_false(any(grepl("candidate|share|secret|storage|path|source",
                         names(advanced$payload), ignore.case = TRUE)))
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_advance",
    list(headers = headers[[1L]])), class = "dsvert_formal_cox_error")
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(...) list(
      version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
      payload = list(
        artifact_id = strrep("c", 64L), state = "publication_ready",
        certificate_sha256 = "unsafe", production_ready = FALSE)),
    .package = "dsVert")
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_advance",
    list(headers = headers)), class = "dsvert_formal_cox_error")

  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(...) list(
      version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
      payload = list(artifact_id = strrep("c", 64L), candidate_sha256 = "unsafe",
                     local_role = "garbler", production_ready = FALSE)),
    .package = "dsVert")
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_stage",
    list(ticket = list(), headers = headers, envelopes = envelopes)),
    class = "dsvert_formal_cox_error")

  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(...) list(
      version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
      payload = list(
        intent = list(candidate = "unsafe"), finalized = FALSE,
        certificate_sha256 = "", replayed = FALSE)),
    .package = "dsVert")
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_prepare",
    list(ticket = list(), headers = headers, envelopes = envelopes)),
    class = "dsvert_formal_cox_error")
})

test_that("formal Cox worker relays finalizer control without recipient secrets", {
  selector <- .formal_cox_worker_control_selector()
  headers <- list(
    list(artifact_id = strrep("c", 64L), plan_sha256 = selector$plan_sha256,
         signature = "AQ=="),
    list(artifact_id = strrep("c", 64L), plan_sha256 = selector$plan_sha256,
         signature = "Ag=="))
  seen <- list()
  receipt <- list(
    version = "dsvert-formal-cox-control-relay-receipt-v1",
    artifact_id = strrep("c", 64L), execution_sha256 = strrep("d", 64L),
    record_type = "preflight", sender_role = "garbler",
    record_sha256 = strrep("e", 64L), envelope_sha256 = strrep("f", 64L),
    recipient_peer_name = "site_b", recipient_peer_id = "peer-b",
    recipient_role = "evaluator", signature = paste0(strrep("A", 86L), "=="),
    production_ready = FALSE)
  testthat::local_mocked_bindings(
    .dsvert_formal_cox_worker_host_control = function(
        plan_sha256, attempt_id, action, payload) {
      seen[[action]] <<- list(
        plan_sha256 = plan_sha256, attempt_id = attempt_id, payload = payload)
      response <- switch(
        action,
        finalizer_relay_recipient = list(
          transport_public = paste0(strrep("A", 43L), "="),
          transport_signature = paste0(strrep("A", 86L), "=="),
          production_ready = FALSE),
        finalizer_relay_source = list(
          available = TRUE, envelope_base64url = strrep("A", 80L),
          envelope_sha256 = strrep("e", 64L), production_ready = FALSE),
        finalizer_relay_import = receipt,
        finalizer_relay_delivery = list(
          version = "dsvert-formal-cox-control-delivery-v1", state = "delivered",
          artifact_id = strrep("c", 64L), record_type = "preflight",
          envelope_sha256 = strrep("f", 64L), replayed = FALSE))
      list(version = "dsvert-formal-cox-blockwise-worker-host-control-v1",
           payload = response)
    },
    .package = "dsVert")

  recipient <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_relay_recipient",
    list(headers = headers))
  expect_false(recipient$production_ready)
  expect_false(any(grepl("private|secret|path", names(recipient$payload),
                         ignore.case = TRUE)))

  source <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_relay_source",
    list(headers = headers,
         recipient_transport_public = recipient$payload$transport_public,
         recipient_transport_signature = recipient$payload$transport_signature))
  expect_true(source$payload$available)
  expect_false(any(grepl("record|candidate|private|secret|path", names(source$payload),
                         ignore.case = TRUE)))

  imported <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_relay_import",
    list(headers = headers, envelope_base64url = source$payload$envelope_base64url))
  expect_false(imported$production_ready)
  expect_identical(imported$payload$envelope_sha256, receipt$envelope_sha256)

  delivered <- dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_relay_delivery",
    list(headers = headers, receipt = imported$payload))
  expect_false(delivered$production_ready)
  expect_identical(delivered$payload$state, "delivered")
  expect_identical(seen$finalizer_relay_delivery$payload$receipt,
                   imported$payload)
  expect_error(dsvertFormalCoxWorkerControlDS(
    selector$plan_sha256, selector$attempt_id, "finalizer_relay_source",
    list(headers = headers, recipient_transport_public = "unsafe",
         recipient_transport_signature = recipient$payload$transport_signature)),
  class = "dsvert_formal_cox_error")
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
