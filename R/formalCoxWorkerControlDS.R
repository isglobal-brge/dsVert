# Closed relay for a provisioned formal-Cox blockwise worker.
#
# A worker is selected only by the non-secret plan/attempt pair written by the
# provisioner.  The host owns the live exact-GC spool in Go; R only starts that
# burned host once and relays bounded authenticated control frames.

.DSVERT_FORMAL_COX_WORKER_CONTROL_DS_VERSION <-
  "dsvert-formal-cox-worker-control-response-v1"
.DSVERT_FORMAL_COX_WORKER_HOST_CONTROL_VERSION <-
  "dsvert-formal-cox-blockwise-worker-host-control-v1"
.DSVERT_FORMAL_COX_WORKER_CONTROL_DS_MAX_BYTES <- 2L * 1024L * 1024L
.DSVERT_FORMAL_COX_WORKER_CONTROL_DS_ACTIONS <- c(
  "host_start", "bind", "offer", "accept", "confirm", "poll", "relay", "result",
  "completion", "opening", "finalizer_ticket", "finalizer_seal", "finalizer_prepare",
  "finalizer_stage",
  "commit")

.dsvert_formal_cox_worker_control_ds_sha256 <- function(value, field) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_cox_abort(paste0("The formal Cox worker ", field, " is invalid."))
  }
  value
}

.dsvert_formal_cox_worker_control_ds_json <- function(value, field) {
  encoded <- tryCatch(as.character(jsonlite::toJSON(
    value, auto_unbox = TRUE, null = "null", digits = 17)),
                      error = function(error) NULL)
  forbidden <- paste0(
    "\\\"[^\\\"]*(?:private|signing_key|secret|storage|path|config|",
    "source|rows|values|master|pid)[^\\\"]*\\\"\\s*:")
  if (!is.character(encoded) || length(encoded) != 1L || is.na(encoded) ||
      nchar(encoded, type = "bytes") < 2L ||
      nchar(encoded, type = "bytes") > .DSVERT_FORMAL_COX_WORKER_CONTROL_DS_MAX_BYTES ||
      grepl(forbidden, encoded, perl = TRUE, ignore.case = TRUE)) {
    .dsvert_formal_cox_abort(paste0("The formal Cox worker ", field, " is invalid."))
  }
  encoded
}

.dsvert_formal_cox_worker_control_ds_payload <- function(action, payload) {
  if (!is.list(payload) || (!is.null(attributes(payload)) &&
      length(setdiff(names(attributes(payload)), "names")))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  fields <- names(payload)
  if (is.null(fields)) fields <- character()
  if (anyNA(fields) || anyDuplicated(fields) ||
      (action %in% c("host_start", "offer", "completion", "opening") && length(fields))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  if (action %in% c("accept", "confirm") &&
      (!identical(fields, "frame") || !is.character(payload$frame) ||
       length(payload$frame) != 1L || is.na(payload$frame) ||
       nchar(payload$frame, type = "bytes") < 4L ||
       nchar(payload$frame, type = "bytes") >
         .DSVERT_FORMAL_COX_WORKER_CONTROL_DS_MAX_BYTES ||
       !grepl("^[A-Za-z0-9+/]+={0,2}$", payload$frame))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  if (identical(action, "finalizer_ticket") &&
      (!identical(fields, "headers") || !is.list(payload$headers) ||
       length(payload$headers) != 2L || any(vapply(payload$headers, is.null,
                                                    logical(1L))))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  if (identical(action, "finalizer_seal") &&
      (!identical(fields, c("ticket", "headers")) || !is.list(payload$ticket) ||
       !is.list(payload$headers) || length(payload$headers) != 2L ||
       any(vapply(payload$headers, is.null, logical(1L))))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  if (action %in% c("finalizer_prepare", "finalizer_stage") &&
      (!identical(fields, c("ticket", "headers", "envelopes")) ||
       !is.list(payload$ticket) || !is.list(payload$headers) ||
       !is.list(payload$envelopes) || length(payload$headers) != 2L ||
       length(payload$envelopes) != 2L ||
       any(vapply(payload$headers, is.null, logical(1L))) ||
       any(vapply(payload$envelopes, is.null, logical(1L))))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  if (!identical(action, "host_start")) {
    .dsvert_formal_cox_worker_control_ds_json(payload, "control payload")
  }
  payload
}

.dsvert_formal_cox_worker_host_selector <- function(plan_sha256, attempt_id) {
  list(
    plan_sha256 = .dsvert_formal_cox_worker_control_ds_sha256(
      plan_sha256, "plan selector"),
    attempt_id = .dsvert_formal_cox_worker_control_ds_sha256(
      attempt_id, "attempt selector"))
}

.dsvert_formal_cox_worker_host_control <- function(
    plan_sha256, attempt_id, action, payload) {
  selector <- .dsvert_formal_cox_worker_host_selector(plan_sha256, attempt_id)
  if (!is.character(action) || length(action) != 1L || is.na(action) ||
      !action %in% setdiff(.DSVERT_FORMAL_COX_WORKER_CONTROL_DS_ACTIONS,
                           "host_start")) {
    .dsvert_formal_cox_abort("The formal Cox worker control action is invalid.")
  }
  payload <- .dsvert_formal_cox_worker_control_ds_payload(action, payload)
  identity <- tryCatch(.get_identity_keypair(), error = function(error) NULL)
  if (!is.list(identity) || !identical(names(identity),
                                       c("identity_pk", "identity_sk")) ||
      !is.character(identity$identity_sk) || length(identity$identity_sk) != 1L ||
      is.na(identity$identity_sk) || !nzchar(identity$identity_sk)) {
    .dsvert_formal_cox_abort("The local formal Cox worker identity is unavailable.")
  }
  peer <- tryCatch(.dsvert_require_configured_local_peer_name(),
                   error = function(error) NULL)
  if (!is.character(peer) || length(peer) != 1L || is.na(peer) || !nzchar(peer)) {
    .dsvert_formal_cox_abort("The local formal Cox worker peer is unavailable.")
  }
  command <- list(
    version = .DSVERT_FORMAL_COX_WORKER_HOST_CONTROL_VERSION,
    peer_name = peer, plan_sha256 = selector$plan_sha256,
    attempt_id = selector$attempt_id,
    recipient_signing_key = identity$identity_sk,
    action = action, payload = payload)
  on.exit({
    command$recipient_signing_key <- NULL
    identity$identity_sk <- NULL
  }, add = TRUE)
  response <- tryCatch(.callMpcTool("formal-cox-worker-control", command),
                       error = function(error) NULL)
  if (!is.list(response) || !identical(names(response), c("version", "payload")) ||
      !identical(response$version, .DSVERT_FORMAL_COX_WORKER_HOST_CONTROL_VERSION) ||
      !is.list(response$payload)) {
    .dsvert_formal_cox_abort("The formal Cox worker control is unavailable.")
  }
  .dsvert_formal_cox_worker_control_ds_json(response$payload, "control reply")
  response
}

.dsvert_formal_cox_worker_host_spawn <- function(binary, arguments) {
  processx::process$new(
    binary, arguments, stdout = FALSE, stderr = FALSE,
    cleanup = FALSE, cleanup_tree = FALSE)
}

.dsvert_formal_cox_worker_host_start <- function(plan_sha256, attempt_id) {
  selector <- .dsvert_formal_cox_worker_host_selector(plan_sha256, attempt_id)
  alive <- tryCatch(
    .dsvert_formal_cox_worker_host_control(
      selector$plan_sha256, selector$attempt_id, "result",
      structure(list(), names = character())),
    error = function(error) NULL)
  peer <- tryCatch(.dsvert_require_configured_local_peer_name(),
                   error = function(error) NULL)
  if (!is.character(peer) || length(peer) != 1L || is.na(peer) || !nzchar(peer)) {
    .dsvert_formal_cox_abort("The local formal Cox worker peer is unavailable.")
  }
  if (!is.null(alive)) {
    return(list(
      version = "dsvert-formal-cox-blockwise-worker-host-status-v1",
      peer_name = peer, plan_sha256 = selector$plan_sha256,
      attempt_id = selector$attempt_id, replayed = TRUE,
      production_ready = FALSE))
  }
  binary <- tryCatch(.findMpcBinary(), error = function(error) NULL)
  if (!is.character(binary) || length(binary) != 1L || is.na(binary) || !file.exists(binary)) {
    .dsvert_formal_cox_abort("The formal Cox worker host binary is unavailable.")
  }
  process <- tryCatch(.dsvert_formal_cox_worker_host_spawn(
    binary, c("formal-cox-worker-host", peer, selector$plan_sha256,
              selector$attempt_id)), error = function(error) NULL)
  if (is.null(process) || !is.function(process$is_alive)) {
    .dsvert_formal_cox_abort("The formal Cox worker host could not start.")
  }
  started <- FALSE
  on.exit(if (!started) {
    tryCatch(process$kill(), error = function(error) NULL)
    tryCatch(process$wait(timeout = 1000), error = function(error) NULL)
  }, add = TRUE)
  for (poll in seq_len(100L)) {
    alive <- tryCatch(
      .dsvert_formal_cox_worker_host_control(
        selector$plan_sha256, selector$attempt_id, "result",
        structure(list(), names = character())),
      error = function(error) NULL)
    if (!is.null(alive)) {
      started <- TRUE
      return(list(
        version = "dsvert-formal-cox-blockwise-worker-host-status-v1",
        peer_name = peer, plan_sha256 = selector$plan_sha256,
        attempt_id = selector$attempt_id, replayed = FALSE,
        production_ready = FALSE))
    }
    if (!isTRUE(tryCatch(process$is_alive(), error = function(error) FALSE))) break
    Sys.sleep(0.05)
  }
  .dsvert_formal_cox_abort("The formal Cox worker host failed before readiness.")
}

.dsvert_formal_cox_worker_control_ds_finalizer_prepare_reply <- function(payload) {
  fields <- c("intent", "finalized", "certificate_sha256", "replayed")
  valid_common <- is.list(payload) && !is.null(names(payload)) &&
    !anyNA(names(payload)) && !anyDuplicated(names(payload)) &&
    identical(names(payload), fields) && is.logical(payload$finalized) &&
    length(payload$finalized) == 1L && !is.na(payload$finalized) &&
    is.logical(payload$replayed) && length(payload$replayed) == 1L &&
    !is.na(payload$replayed) && is.character(payload$certificate_sha256) &&
    length(payload$certificate_sha256) == 1L && !is.na(payload$certificate_sha256)
  if (!isTRUE(valid_common)) return(FALSE)
  if (isTRUE(payload$finalized)) {
    return(is.null(payload$intent) &&
      grepl("^[0-9a-f]{64}$", payload$certificate_sha256))
  }
  intent_fields <- c("version", "purpose", "artifact_id", "candidate_sha256",
                     "final_pair_root_sha256", "opening_mode", "exp_postprocess_mode")
  intent <- payload$intent
  is.list(intent) && !is.null(names(intent)) && !anyNA(names(intent)) &&
    !anyDuplicated(names(intent)) && identical(names(intent), intent_fields) &&
    identical(intent$version, "dsvert-formal-cox-blockwise-sticky-opening-v1") &&
    identical(intent$purpose, "formal_cox_one_public_beta_validity_opening_v1") &&
    all(vapply(c("artifact_id", "candidate_sha256", "final_pair_root_sha256"),
               function(field) is.character(intent[[field]]) &&
                 length(intent[[field]]) == 1L && !is.na(intent[[field]]) &&
                 grepl("^[0-9a-f]{64}$", intent[[field]]), logical(1L))) &&
    identical(intent$opening_mode,
              "dual_authority_additive_ring_and_xor_validity_v1") &&
    identical(intent$exp_postprocess_mode,
              "certified_dyadic_interval_midpoint_v1") &&
    identical(payload$certificate_sha256, "")
}

.dsvert_formal_cox_worker_control_ds_finalizer_stage_reply <- function(payload) {
  fields <- c("artifact_id", "candidate_sha256", "local_role", "production_ready")
  valid_sha256 <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^[0-9a-f]{64}$", value)
  }
  valid <- is.list(payload) && !is.null(names(payload)) && !anyNA(names(payload)) &&
    !anyDuplicated(names(payload)) && identical(names(payload), fields) &&
    valid_sha256(payload$artifact_id) &&
    is.character(payload$candidate_sha256) && length(payload$candidate_sha256) == 1L &&
    !is.na(payload$candidate_sha256) &&
    is.character(payload$local_role) && length(payload$local_role) == 1L &&
    !is.na(payload$local_role) && payload$local_role %in% c("garbler", "evaluator") &&
    is.logical(payload$production_ready) && length(payload$production_ready) == 1L &&
    !is.na(payload$production_ready) && identical(payload$production_ready, FALSE)
  if (!isTRUE(valid)) return(FALSE)
  if (identical(payload$local_role, "garbler")) {
    return(valid_sha256(payload$candidate_sha256))
  }
  identical(payload$candidate_sha256, "")
}

.dsvert_formal_cox_worker_control_ds_reply <- function(action, payload) {
  encoded <- .dsvert_formal_cox_worker_control_ds_json(payload, "control reply")
  if (!is.list(payload) ||
      (identical(action, "finalizer_prepare") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_prepare_reply(payload))) ||
      (identical(action, "finalizer_stage") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_stage_reply(payload)))) {
    .dsvert_formal_cox_abort("The formal Cox worker control reply is invalid.")
  }
  list(version = .DSVERT_FORMAL_COX_WORKER_CONTROL_DS_VERSION,
       action = action, payload = payload, production_ready = FALSE)
}

#' Relay a provisioned formal-Cox worker control frame
#'
#' The endpoint starts only the immutable worker selected by a prior encrypted
#' source provision, or relays one bounded authenticated exact-GC frame to it.
#' It never accepts a path, table, model control, key, source value or raw
#' opening. The closed \code{opening} action returns only a signed,
#' share-free handoff header.
#'
#' @param plan_sha256,attempt_id Non-secret selectors emitted by provision.
#' @param action One closed worker lifecycle action.
#' @param payload An action-specific encrypted/authenticated control frame.
#' @return A non-production opaque control response.
#' @export
dsvertFormalCoxWorkerControlDS <- function(
    plan_sha256, attempt_id, action, payload) {
  selector <- .dsvert_formal_cox_worker_host_selector(plan_sha256, attempt_id)
  if (!is.character(action) || length(action) != 1L || is.na(action) ||
      !action %in% .DSVERT_FORMAL_COX_WORKER_CONTROL_DS_ACTIONS) {
    .dsvert_formal_cox_abort("The formal Cox worker control action is invalid.")
  }
  payload <- .dsvert_formal_cox_worker_control_ds_payload(action, payload)
  response <- if (identical(action, "host_start")) {
    .dsvert_formal_cox_worker_host_start(selector$plan_sha256, selector$attempt_id)
  } else {
    .dsvert_formal_cox_worker_host_control(
      selector$plan_sha256, selector$attempt_id, action, payload)$payload
  }
  .dsvert_formal_cox_worker_control_ds_reply(action, response)
}
