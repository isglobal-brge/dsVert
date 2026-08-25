# Closed relay for a provisioned registered formal-GLM job host.
#
# This is not a model endpoint: the analyst may carry only signed control
# frames and authenticated encrypted relay chunks between already-provisioned
# peers.  The local command reopens the private Rock bootstrap itself.

.DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_VERSION <-
  "dsvert-formal-glm-registered-phase20-job-control-response-v1"
.DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_MAX_BYTES <- 2L * 1024L * 1024L
.DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_EMPTY_ACTIONS <- c(
  "start", "health", "job_ref", "heartbeat", "compute", "terminal",
  "compute_start", "compute_status", "terminal_start", "terminal_status")
.DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_ACTIONS <- c(
  "negotiate", .DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_EMPTY_ACTIONS,
  "bind", "phase21_preflight_bind", "poll", "relay",
  "phase21_preflight",
  "phase21_stage_start", "phase21_stage_status", "phase21_ticket",
  "phase21_seal", "phase21_candidate", "phase21_candidate_verify",
  "phase21_base_certificate", "phase21_authorization",
  "phase21_publication", "phase21_ack",
  "phase21_stage_poll", "phase21_stage_relay", "phase21_stage_import",
  "phase21_ticket_import", "phase21_seal_import",
  "phase21_candidate_import", "phase21_local_release_import",
  "phase21_base_certificate_import", "phase21_authorization_import",
  "phase21_commit", "phase21_commit_import", "phase21_ack_import",
  "phase21_cleanup", "phase21_cleanup_import")

.dsvert_formal_glm_registered_job_control_abort <- function(
    message = "The registered formal-GLM job control request is unavailable.",
    code = "formal_glm_registered_job_control_unavailable") {
  stop(structure(
    list(message = message, call = NULL, code = code),
    class = c("dsvert_formal_glm_registered_job_control_error", "error",
              "condition")))
}

.dsvert_formal_glm_registered_job_control_receipt <- function(receipt) {
  value <- tryCatch(
    .dsvert_formal_glm_registered_source_job_host_receipt(receipt),
    error = function(error) NULL)
  if (is.null(value)) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM host selector is invalid.",
      "invalid_formal_glm_registered_job_selector")
  }
  value
}

.dsvert_formal_glm_registered_job_control_base64 <- function(
    value, field, allow_empty = FALSE) {
  valid <- is.character(value) && length(value) == 1L && !is.na(value) &&
    nchar(value, type = "bytes") <=
      .DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_MAX_BYTES &&
    (isTRUE(allow_empty) || nzchar(value)) &&
    grepl("^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
          value, perl = TRUE)
  if (!isTRUE(valid)) {
    .dsvert_formal_glm_registered_job_control_abort(
      paste0("The registered formal-GLM ", field, " is invalid."),
      "invalid_formal_glm_registered_job_frame")
  }
  enc2utf8(value)
}

.dsvert_formal_glm_registered_job_control_payload <- function(action, payload) {
  attributes <- attributes(payload)
  if (!is.list(payload) || (!is.null(attributes) &&
      length(setdiff(names(attributes), "names")))) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM job payload is invalid.",
      "invalid_formal_glm_registered_job_payload")
  }
  fields <- names(payload)
  if (is.null(fields) || anyNA(fields) || anyDuplicated(fields)) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM job payload is invalid.",
      "invalid_formal_glm_registered_job_payload")
  }
  phase21 <- startsWith(action, "phase21_")
  expected <- if (phase21) "frame" else switch(action,
    negotiate = "inbound", bind = "frame",
    poll = c("ref", "acknowledged"), relay = c("ref", "chunk"),
    character())
  if (!identical(fields, expected)) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM job payload is invalid.",
      "invalid_formal_glm_registered_job_payload")
  }
  if (identical(action, "negotiate")) {
    payload$inbound <- .dsvert_formal_glm_registered_job_control_base64(
      payload$inbound, "negotiation frame", allow_empty = TRUE)
  } else if (identical(action, "bind")) {
    payload$frame <- .dsvert_formal_glm_registered_job_control_base64(
      payload$frame, "binding frame")
  } else if (identical(action, "poll")) {
    valid_ack <- is.numeric(payload$acknowledged) &&
      length(payload$acknowledged) == 1L && !is.na(payload$acknowledged) &&
      is.finite(payload$acknowledged) && payload$acknowledged >= 0 &&
      payload$acknowledged <= (2^53 - 1) &&
      payload$acknowledged == floor(payload$acknowledged) &&
      is.list(payload$ref)
    if (!isTRUE(valid_ack)) {
      .dsvert_formal_glm_registered_job_control_abort(
        "The registered formal-GLM poll payload is invalid.",
        "invalid_formal_glm_registered_job_payload")
    }
  } else if (identical(action, "relay") &&
             (!is.list(payload$ref) || !is.list(payload$chunk))) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM relay payload is invalid.",
        "invalid_formal_glm_registered_job_payload")
  }
  if (phase21) {
    payload$frame <- .dsvert_formal_glm_registered_job_control_base64(
      payload$frame, "Phase21 lifecycle frame")
  }
  encoded <- tryCatch(jsonlite::toJSON(
    payload, auto_unbox = TRUE, null = "null", digits = 17),
    error = function(error) NULL)
  if (!is.character(encoded) || length(encoded) != 1L || is.na(encoded) ||
      nchar(encoded, type = "bytes") < 2L ||
      nchar(encoded, type = "bytes") >
        .DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_MAX_BYTES) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM job payload is invalid.",
      "invalid_formal_glm_registered_job_payload")
  }
  payload
}

.dsvert_formal_glm_registered_job_control_safe_payload <- function(payload) {
  if (!is.list(payload)) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM job control reply is invalid.",
      "invalid_formal_glm_registered_job_reply")
  }
  encoded <- tryCatch(jsonlite::toJSON(
    payload, auto_unbox = TRUE, null = "null", digits = 17),
    error = function(error) NULL)
  if (!is.character(encoded) || length(encoded) != 1L || is.na(encoded) ||
      nchar(encoded, type = "bytes") >
        .DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_MAX_BYTES) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM job control reply is invalid.",
      "invalid_formal_glm_registered_job_reply")
  }
  forbidden <- paste0(
    "\\\"[^\\\"]*(?:config|path|key|secret|socket|storage|backend|",
    "share|plan|context|token|capsule|run_id|opening)[^\\\"]*\\\"\\s*:")
  if (grepl(forbidden, encoded, perl = TRUE, ignore.case = TRUE)) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM job control reply is invalid.",
      "invalid_formal_glm_registered_job_reply")
  }
  payload
}

#' Relay one closed registered-formal-GLM job-control action
#'
#' The host is selected only by a previously issued public provision receipt.
#' This method relays canonical signed control frames and encrypted chunks.
#' Phase21 lifecycle records remain opaque frames: it never accepts a Rock
#' path, a key, raw source data or a private model result.
#'
#' @param receipt Public host-provision receipt issued by the local custodian.
#' @param action One closed host action.
#' @param payload Action-specific canonical control payload.
#' @return A bounded, non-production control reply.
#' @export
dsvertFormalGLMRegisteredJobControlDS <- function(receipt, action, payload) {
  receipt <- .dsvert_formal_glm_registered_job_control_receipt(receipt)
  if (!is.character(action) || length(action) != 1L || is.na(action) ||
      !action %in% .DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_ACTIONS) {
    .dsvert_formal_glm_registered_job_control_abort(
      "The registered formal-GLM job action is invalid.",
      "invalid_formal_glm_registered_job_action")
  }
  payload <- .dsvert_formal_glm_registered_job_control_payload(action, payload)
  response <- tryCatch(.callMpcTool("formal-glm-job-control", list(
    version = "dsvert-formal-glm-registered-phase20-job-control-v1",
    peer = receipt$peer, artifact_id = receipt$artifact_id,
    receipt_set_sha256 = receipt$receipt_set_sha256,
    action = action, payload = payload), simplify_output = FALSE),
    error = function(error) NULL)
  if (!is.list(response) || !identical(names(response), c("version", "payload")) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase20-job-control-v1")) {
    .dsvert_formal_glm_registered_job_control_abort()
  }
  list(
    version = .DSVERT_FORMAL_GLM_REGISTERED_JOB_CONTROL_VERSION,
    action = action,
    payload = .dsvert_formal_glm_registered_job_control_safe_payload(
      response$payload),
    production_ready = FALSE)
}
