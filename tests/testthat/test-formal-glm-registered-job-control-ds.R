.formal_glm_registered_job_control_receipt <- function() {
  list(
    version = "dsvert-formal-glm-registered-phase20-job-host-provision-v1",
    peer = "site_a", artifact_id = strrep("a", 64L),
    receipt_set_sha256 = strrep("b", 64L), config_sha256 = strrep("c", 64L),
    replayed = TRUE, production_ready = FALSE)
}

test_that("registered formal GLM job control relays only a provisioned host", {
  receipt <- .formal_glm_registered_job_control_receipt()
  seen <- NULL
  testthat::local_mocked_bindings(
    .callMpcTool = function(command, input_data, simplify_output = TRUE) {
      seen <<- list(command = command, input = input_data,
                    simplify_output = simplify_output)
      list(
        version = "dsvert-formal-glm-registered-phase20-job-control-v1",
        payload = list(state = "running", outbound = "AQ==",
                       inspect_only = FALSE, production_ready = FALSE))
    },
    .package = "dsVert")
  output <- dsvertFormalGLMRegisteredJobControlDS(
    receipt, "start", structure(list(), names = character()))
  expect_identical(seen, list(
    command = "formal-glm-job-control",
    input = list(
      version = "dsvert-formal-glm-registered-phase20-job-control-v1",
      peer = "site_a", artifact_id = strrep("a", 64L),
      receipt_set_sha256 = strrep("b", 64L), action = "start",
      payload = structure(list(), names = character())),
    simplify_output = FALSE))
  expect_identical(output, list(
    version = "dsvert-formal-glm-registered-phase20-job-control-response-v1",
    action = "start",
    payload = list(state = "running", outbound = "AQ==",
                   inspect_only = FALSE, production_ready = FALSE),
    production_ready = FALSE))
  expect_false(any(c("config", "path", "key", "secret", "socket") %in%
                   names(output)))
})

test_that("registered formal GLM job control admits only opaque task status", {
  receipt <- .formal_glm_registered_job_control_receipt()
  seen <- NULL
  testthat::local_mocked_bindings(
    .callMpcTool = function(command, input_data, simplify_output = TRUE) {
      seen <<- list(command = command, input = input_data,
                    simplify_output = simplify_output)
      list(
        version = "dsvert-formal-glm-registered-phase20-job-control-v1",
        payload = list(state = "running", production_ready = FALSE))
    },
    .package = "dsVert")
  output <- dsvertFormalGLMRegisteredJobControlDS(
    receipt, "compute_status", structure(list(), names = character()))
  expect_identical(seen, list(
    command = "formal-glm-job-control",
    input = list(
      version = "dsvert-formal-glm-registered-phase20-job-control-v1",
      peer = "site_a", artifact_id = strrep("a", 64L),
      receipt_set_sha256 = strrep("b", 64L), action = "compute_status",
      payload = structure(list(), names = character())),
    simplify_output = FALSE))
  expect_identical(output, list(
    version = "dsvert-formal-glm-registered-phase20-job-control-response-v1",
    action = "compute_status",
    payload = list(state = "running", production_ready = FALSE),
    production_ready = FALSE))
})

test_that("registered formal GLM job control relays opaque Phase21 lifecycle frames", {
  receipt <- .formal_glm_registered_job_control_receipt()
  seen <- NULL
  testthat::local_mocked_bindings(
    .callMpcTool = function(command, input_data, simplify_output = TRUE) {
      seen <<- list(command = command, input = input_data,
                    simplify_output = simplify_output)
      list(
        version = "dsvert-formal-glm-registered-phase20-job-control-v1",
        payload = list(frame = "eyJyZWNlaXB0Ijp7fX0="))
    },
    .package = "dsVert")
  output <- dsvertFormalGLMRegisteredJobControlDS(
    receipt, "phase21_preflight", list(frame = "e30="))
  expect_identical(seen$input$action, "phase21_preflight")
  expect_identical(output$payload, list(frame = "eyJyZWNlaXB0Ijp7fX0="))
  expect_false(any(grepl("secret|share|path|key", names(output$payload),
                         ignore.case = TRUE)))
  output <- dsvertFormalGLMRegisteredJobControlDS(
    receipt, "phase21_preflight_bind",
    list(frame = "eyJmcmFtZSI6ImV5SnlaV05sYVhCMElqcDdmWDA9In0="))
  expect_identical(seen$input$action, "phase21_preflight_bind")
  expect_identical(seen$input$payload, list(
    frame = "eyJmcmFtZSI6ImV5SnlaV05sYVhCMElqcDdmWDA9In0="))
  expect_identical(output$payload, list(frame = "eyJyZWNlaXB0Ijp7fX0="))

  output <- dsvertFormalGLMRegisteredJobControlDS(
    receipt, "phase21_ack_import", list(frame = "eyJyZWNvcmQiOnt9fQ=="))
  expect_identical(seen$input$action, "phase21_ack_import")
  expect_identical(seen$input$payload,
                   list(frame = "eyJyZWNvcmQiOnt9fQ=="))
  expect_identical(output$payload, list(frame = "eyJyZWNlaXB0Ijp7fX0="))
})

test_that("registered formal GLM job control validates its closed envelope", {
  receipt <- .formal_glm_registered_job_control_receipt()
  calls <- 0L
  testthat::local_mocked_bindings(
    .callMpcTool = function(...) {
      calls <<- calls + 1L
      list(version = "dsvert-formal-glm-registered-phase20-job-control-v1",
           payload = structure(list(), names = character()))
    },
    .package = "dsVert")
  expect_error(dsvertFormalGLMRegisteredJobControlDS(
    receipt, "unknown", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_job_control_error")
  expect_error(dsvertFormalGLMRegisteredJobControlDS(
    receipt, "start", list(extra = TRUE)),
    class = "dsvert_formal_glm_registered_job_control_error")
  expect_error(dsvertFormalGLMRegisteredJobControlDS(
    receipt, "bind", list(frame = "not base64")),
    class = "dsvert_formal_glm_registered_job_control_error")
  expect_error(dsvertFormalGLMRegisteredJobControlDS(
    receipt, "phase21_commit", list(publication = list())),
    class = "dsvert_formal_glm_registered_job_control_error")
  expect_error(dsvertFormalGLMRegisteredJobControlDS(
    utils::modifyList(receipt, list(config_sha256 = "wrong")),
    "start", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_job_control_error")
  expect_identical(calls, 0L)
})

test_that("registered formal GLM job control rejects unsafe host replies", {
  receipt <- .formal_glm_registered_job_control_receipt()
  testthat::local_mocked_bindings(
    .callMpcTool = function(...) list(
      version = "dsvert-formal-glm-registered-phase20-job-control-v1",
      payload = list(state = "running", storage_key = "must-not-leak")),
    .package = "dsVert")
  expect_error(dsvertFormalGLMRegisteredJobControlDS(
    receipt, "health", structure(list(), names = character())),
    class = "dsvert_formal_glm_registered_job_control_error")
})
