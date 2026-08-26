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
  "finalizer_stage", "finalizer_advance", "finalizer_public", "finalizer_relay_recipient",
  "finalizer_relay_source", "finalizer_relay_import", "finalizer_relay_delivery",
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
  if (action %in% c("finalizer_advance", "finalizer_public") &&
      (!identical(fields, "headers") || !is.list(payload$headers) ||
       length(payload$headers) != 2L ||
       any(vapply(payload$headers, is.null, logical(1L))))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  if (identical(action, "finalizer_relay_recipient") &&
      (!identical(fields, "headers") || !is.list(payload$headers) ||
       length(payload$headers) != 2L ||
       any(vapply(payload$headers, is.null, logical(1L))))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  if (identical(action, "finalizer_relay_source") &&
      (!identical(fields, c("headers", "recipient_transport_public",
                             "recipient_transport_signature")) ||
       !is.list(payload$headers) || length(payload$headers) != 2L ||
       any(vapply(payload$headers, is.null, logical(1L))) ||
       !is.character(payload$recipient_transport_public) ||
       length(payload$recipient_transport_public) != 1L ||
       is.na(payload$recipient_transport_public) ||
       nchar(payload$recipient_transport_public, type = "bytes") < 40L ||
       nchar(payload$recipient_transport_public, type = "bytes") > 48L ||
       !grepl("^[A-Za-z0-9+/]+={0,2}$", payload$recipient_transport_public) ||
       !is.character(payload$recipient_transport_signature) ||
       length(payload$recipient_transport_signature) != 1L ||
       is.na(payload$recipient_transport_signature) ||
       nchar(payload$recipient_transport_signature, type = "bytes") < 80L ||
       nchar(payload$recipient_transport_signature, type = "bytes") > 96L ||
       !grepl("^[A-Za-z0-9+/]+={0,2}$", payload$recipient_transport_signature))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  if (identical(action, "finalizer_relay_import") &&
      (!identical(fields, c("headers", "envelope_base64url")) ||
       !is.list(payload$headers) || length(payload$headers) != 2L ||
       any(vapply(payload$headers, is.null, logical(1L))) ||
       !is.character(payload$envelope_base64url) ||
       length(payload$envelope_base64url) != 1L || is.na(payload$envelope_base64url) ||
       nchar(payload$envelope_base64url, type = "bytes") < 80L ||
       nchar(payload$envelope_base64url, type = "bytes") >
         .DSVERT_FORMAL_COX_WORKER_CONTROL_DS_MAX_BYTES ||
       !grepl("^[A-Za-z0-9_-]+$", payload$envelope_base64url))) {
    .dsvert_formal_cox_abort("The formal Cox worker control payload is invalid.")
  }
  if (identical(action, "finalizer_relay_delivery") &&
      (!identical(fields, c("headers", "receipt")) ||
       !is.list(payload$headers) || length(payload$headers) != 2L ||
       any(vapply(payload$headers, is.null, logical(1L))) ||
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_relay_receipt_reply(
         payload$receipt)))) {
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

.dsvert_formal_cox_worker_control_ds_finalizer_advance_reply <- function(payload) {
  fields <- c("artifact_id", "state", "certificate_sha256", "production_ready")
  valid_sha256 <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^[0-9a-f]{64}$", value)
  }
  valid <- is.list(payload) && !is.null(names(payload)) && !anyNA(names(payload)) &&
    !anyDuplicated(names(payload)) && identical(names(payload), fields) &&
    valid_sha256(payload$artifact_id) && is.character(payload$state) &&
    length(payload$state) == 1L && !is.na(payload$state) &&
    payload$state %in% c(
      "awaiting_candidate", "awaiting_evaluator_envelope",
      "awaiting_garbler_authorization", "awaiting_evaluator_authorization",
      "awaiting_publication", "publication_ready", "commit_ready") &&
    is.character(payload$certificate_sha256) &&
    length(payload$certificate_sha256) == 1L && !is.na(payload$certificate_sha256) &&
    is.logical(payload$production_ready) && length(payload$production_ready) == 1L &&
    !is.na(payload$production_ready) && identical(payload$production_ready, FALSE)
  if (!isTRUE(valid)) return(FALSE)
  if (payload$state %in% c("publication_ready", "commit_ready")) {
    return(valid_sha256(payload$certificate_sha256))
  }
  identical(payload$certificate_sha256, "")
}

.dsvert_formal_cox_worker_control_ds_finalizer_public_reply <- function(payload) {
  fields <- c("version", "artifact_id", "certificate_sha256", "valid",
              "coefficients", "production_ready")
  coefficient_fields <- c("index", "beta_steps", "fraction_bits", "beta",
                          "hazard_ratio_lower", "hazard_ratio_upper",
                          "hazard_ratio_midpoint")
  valid_coefficient <- function(value, index) {
    is.list(value) && !is.null(names(value)) && !anyNA(names(value)) &&
      !anyDuplicated(names(value)) && identical(names(value), coefficient_fields) &&
      is.numeric(value$index) && length(value$index) == 1L &&
      !is.na(value$index) && is.finite(value$index) && value$index == index - 1L &&
      is.character(value$beta_steps) && length(value$beta_steps) == 1L &&
      !is.na(value$beta_steps) && grepl("^(0|-[1-9][0-9]*|[1-9][0-9]*)$", value$beta_steps) &&
      is.numeric(value$fraction_bits) && length(value$fraction_bits) == 1L &&
      is.finite(value$fraction_bits) && value$fraction_bits >= 8L &&
      value$fraction_bits <= 60L && value$fraction_bits == floor(value$fraction_bits) &&
      all(vapply(c("beta", "hazard_ratio_lower", "hazard_ratio_upper",
                   "hazard_ratio_midpoint"), function(field) {
        is.numeric(value[[field]]) && length(value[[field]]) == 1L &&
          !is.na(value[[field]]) && is.finite(value[[field]])
      }, logical(1L))) && value$hazard_ratio_lower > 0 &&
      value$hazard_ratio_upper >= value$hazard_ratio_lower &&
      value$hazard_ratio_midpoint >= value$hazard_ratio_lower &&
      value$hazard_ratio_midpoint <= value$hazard_ratio_upper
  }
  is.list(payload) && !is.null(names(payload)) && !anyNA(names(payload)) &&
    !anyDuplicated(names(payload)) && identical(names(payload), fields) &&
    identical(payload$version, "dsvert-formal-cox-public-result-v1") &&
    is.character(payload$artifact_id) && length(payload$artifact_id) == 1L &&
    grepl("^[0-9a-f]{64}$", payload$artifact_id) &&
    is.character(payload$certificate_sha256) && length(payload$certificate_sha256) == 1L &&
    grepl("^[0-9a-f]{64}$", payload$certificate_sha256) &&
    identical(payload$valid, TRUE) && identical(payload$production_ready, FALSE) &&
    is.list(payload$coefficients) && length(payload$coefficients) > 0L &&
    all(vapply(seq_along(payload$coefficients), function(index)
      valid_coefficient(payload$coefficients[[index]], index), logical(1L)))
}

.dsvert_formal_cox_worker_control_ds_finalizer_relay_recipient_reply <- function(payload) {
  identical(names(payload), c("transport_public", "transport_signature",
                               "production_ready")) &&
    is.character(payload$transport_public) && length(payload$transport_public) == 1L &&
    !is.na(payload$transport_public) && nchar(payload$transport_public) >= 40L &&
    nchar(payload$transport_public) <= 48L &&
    grepl("^[A-Za-z0-9+/]+={0,2}$", payload$transport_public) &&
    is.character(payload$transport_signature) && length(payload$transport_signature) == 1L &&
    !is.na(payload$transport_signature) && nchar(payload$transport_signature) >= 80L &&
    nchar(payload$transport_signature) <= 96L &&
    grepl("^[A-Za-z0-9+/]+={0,2}$", payload$transport_signature) &&
    identical(payload$production_ready, FALSE)
}

.dsvert_formal_cox_worker_control_ds_finalizer_relay_source_reply <- function(payload) {
  fields <- c("available", "envelope_base64url", "envelope_sha256", "production_ready")
  valid <- is.list(payload) && !is.null(names(payload)) && !anyNA(names(payload)) &&
    !anyDuplicated(names(payload)) && identical(names(payload), fields) &&
    is.logical(payload$available) && length(payload$available) == 1L &&
    !is.na(payload$available) && identical(payload$production_ready, FALSE) &&
    is.character(payload$envelope_base64url) && length(payload$envelope_base64url) == 1L &&
    !is.na(payload$envelope_base64url) && is.character(payload$envelope_sha256) &&
    length(payload$envelope_sha256) == 1L && !is.na(payload$envelope_sha256)
  if (!isTRUE(valid)) return(FALSE)
  if (!isTRUE(payload$available)) {
    return(identical(payload$envelope_base64url, "") &&
             identical(payload$envelope_sha256, ""))
  }
  nchar(payload$envelope_base64url, type = "bytes") >= 80L &&
    nchar(payload$envelope_base64url, type = "bytes") <=
      .DSVERT_FORMAL_COX_WORKER_CONTROL_DS_MAX_BYTES &&
    grepl("^[A-Za-z0-9_-]+$", payload$envelope_base64url) &&
    grepl("^[0-9a-f]{64}$", payload$envelope_sha256)
}

.dsvert_formal_cox_worker_control_ds_finalizer_relay_receipt_reply <- function(payload) {
  fields <- c("version", "artifact_id", "execution_sha256", "record_type", "sender_role",
              "record_sha256", "envelope_sha256", "recipient_peer_name", "recipient_peer_id",
              "recipient_role", "signature", "production_ready")
  is.list(payload) && !is.null(names(payload)) && !anyNA(names(payload)) &&
    !anyDuplicated(names(payload)) && identical(names(payload), fields) &&
    is.character(payload$version) && length(payload$version) == 1L &&
    is.character(payload$artifact_id) && length(payload$artifact_id) == 1L &&
    grepl("^[0-9a-f]{64}$", payload$artifact_id) &&
    is.character(payload$execution_sha256) && length(payload$execution_sha256) == 1L &&
    grepl("^[0-9a-f]{64}$", payload$execution_sha256) &&
    is.character(payload$record_type) && length(payload$record_type) == 1L &&
    is.character(payload$sender_role) && length(payload$sender_role) == 1L &&
    payload$sender_role %in% c("garbler", "evaluator") &&
    is.character(payload$record_sha256) && length(payload$record_sha256) == 1L &&
    grepl("^[0-9a-f]{64}$", payload$record_sha256) &&
    is.character(payload$envelope_sha256) && length(payload$envelope_sha256) == 1L &&
    grepl("^[0-9a-f]{64}$", payload$envelope_sha256) &&
    is.character(payload$recipient_peer_name) && length(payload$recipient_peer_name) == 1L &&
    is.character(payload$recipient_peer_id) && length(payload$recipient_peer_id) == 1L &&
    is.character(payload$recipient_role) && length(payload$recipient_role) == 1L &&
    payload$recipient_role %in% c("garbler", "evaluator") &&
    is.character(payload$signature) && length(payload$signature) == 1L &&
    nchar(payload$signature) >= 80L && nchar(payload$signature) <= 96L &&
    grepl("^[A-Za-z0-9+/]+={0,2}$", payload$signature) &&
    identical(payload$production_ready, FALSE)
}

.dsvert_formal_cox_worker_control_ds_finalizer_relay_delivery_reply <- function(payload) {
  fields <- c("version", "state", "artifact_id", "record_type", "envelope_sha256", "replayed")
  is.list(payload) && !is.null(names(payload)) && !anyNA(names(payload)) &&
    !anyDuplicated(names(payload)) && identical(names(payload), fields) &&
    is.character(payload$version) && length(payload$version) == 1L &&
    is.character(payload$state) && length(payload$state) == 1L &&
    is.character(payload$artifact_id) && length(payload$artifact_id) == 1L &&
    grepl("^[0-9a-f]{64}$", payload$artifact_id) &&
    is.character(payload$record_type) && length(payload$record_type) == 1L &&
    is.character(payload$envelope_sha256) && length(payload$envelope_sha256) == 1L &&
    grepl("^[0-9a-f]{64}$", payload$envelope_sha256) &&
    is.logical(payload$replayed) && length(payload$replayed) == 1L &&
    !is.na(payload$replayed)
}

.dsvert_formal_cox_worker_control_ds_reply <- function(action, payload) {
  encoded <- .dsvert_formal_cox_worker_control_ds_json(payload, "control reply")
  if (!is.list(payload) ||
      (identical(action, "finalizer_prepare") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_prepare_reply(payload))) ||
      (identical(action, "finalizer_stage") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_stage_reply(payload))) ||
      (identical(action, "finalizer_advance") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_advance_reply(payload))) ||
      (identical(action, "finalizer_public") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_public_reply(payload))) ||
      (identical(action, "finalizer_relay_recipient") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_relay_recipient_reply(payload))) ||
      (identical(action, "finalizer_relay_source") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_relay_source_reply(payload))) ||
      (identical(action, "finalizer_relay_import") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_relay_receipt_reply(payload))) ||
      (identical(action, "finalizer_relay_delivery") &&
       !isTRUE(.dsvert_formal_cox_worker_control_ds_finalizer_relay_delivery_reply(payload)))) {
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
