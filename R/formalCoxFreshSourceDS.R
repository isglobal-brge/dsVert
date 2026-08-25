# Closed DataSHIELD relay for one configured formal-Cox source.
#
# This is a transport-only boundary.  The registered analysis selects the
# signed schema and the server configuration selects the sole local snapshot.
# It returns only signed tickets, receipts and encrypted source envelopes; it
# never accepts a table, peer, path, key, source row or Cox control from a
# caller.

.DSVERT_FORMAL_COX_FRESH_SOURCE_DS_VERSION <-
  "dsvert-formal-cox-fresh-source-response-v1"
.DSVERT_FORMAL_COX_FRESH_SOURCE_DS_MAX_BYTES <- 4L * 1024L * 1024L
.DSVERT_FORMAL_COX_FRESH_SOURCE_DS_ACTIONS <- c(
  "shape", "ticket", "produce", "delivery", "import", "provision")

.dsvert_formal_cox_fresh_source_ds_abort <- function(
    message = "The configured formal Cox source request is unavailable.",
    code = "formal_cox_fresh_source_unavailable") {
  stop(structure(
    list(message = message, call = NULL, code = code, openings_performed = 0L),
    class = c("dsvert_formal_cox_fresh_source_ds_error", "error", "condition")))
}

.dsvert_formal_cox_fresh_source_ds_label <- function(value, field) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)) {
    .dsvert_formal_cox_fresh_source_ds_abort(
      paste0("The configured formal Cox ", field, " is invalid."),
      "invalid_formal_cox_fresh_source_selector")
  }
  enc2utf8(value)
}

.dsvert_formal_cox_fresh_source_ds_sha256 <- function(value, field) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_cox_fresh_source_ds_abort(
      paste0("The configured formal Cox ", field, " is invalid."),
      "invalid_formal_cox_fresh_source_selector")
  }
  value
}

.dsvert_formal_cox_fresh_source_ds_payload <- function(action, payload) {
  attributes <- attributes(payload)
  if (!is.list(payload) || (!is.null(attributes) &&
      length(setdiff(names(attributes), "names")))) {
    .dsvert_formal_cox_fresh_source_ds_abort(
      "The configured formal Cox source payload is invalid.",
      "invalid_formal_cox_fresh_source_payload")
  }
  fields <- names(payload)
  if (is.null(fields)) fields <- character()
  expected <- switch(action,
    shape = character(), ticket = character(),
    produce = c("recipient_tickets", "block_index"),
    delivery = c("recipient_tickets", "block_index", "recipient_peer_name"),
    import = c("recipient_tickets", "delivery"),
    provision = c("recipient_tickets", "delivery"))
  if (anyNA(fields) || anyDuplicated(fields) || !identical(fields, expected)) {
    .dsvert_formal_cox_fresh_source_ds_abort(
      "The configured formal Cox source payload is invalid.",
      "invalid_formal_cox_fresh_source_payload")
  }
  if ("recipient_tickets" %in% fields &&
      (!is.list(payload$recipient_tickets) ||
       length(payload$recipient_tickets) != 2L ||
       !is.null(names(payload$recipient_tickets)))) {
    .dsvert_formal_cox_fresh_source_ds_abort(
      "The configured formal Cox recipient ticket set is invalid.",
      "invalid_formal_cox_fresh_source_payload")
  }
  if ("block_index" %in% fields) {
    block_index <- suppressWarnings(as.integer(payload$block_index))
    if (!is.numeric(payload$block_index) || length(payload$block_index) != 1L ||
        is.na(payload$block_index) || !is.finite(payload$block_index) ||
        payload$block_index != floor(payload$block_index) || is.na(block_index) ||
        block_index < 0L) {
      .dsvert_formal_cox_fresh_source_ds_abort(
        "The configured formal Cox source block selector is invalid.",
        "invalid_formal_cox_fresh_source_payload")
    }
    payload$block_index <- block_index
  }
  if ("recipient_peer_name" %in% fields) {
    payload$recipient_peer_name <- .dsvert_formal_cox_fresh_source_ds_label(
      payload$recipient_peer_name, "recipient peer")
  }
  if ("delivery" %in% fields) {
    encoded <- tryCatch(jsonlite::toJSON(
      payload$delivery, auto_unbox = TRUE, null = "null", digits = 17),
      error = function(error) NULL)
    if (!is.list(payload$delivery) || !is.character(encoded) ||
        length(encoded) != 1L || is.na(encoded) ||
        nchar(encoded, type = "bytes") < 2L ||
        nchar(encoded, type = "bytes") >
          .DSVERT_FORMAL_COX_FRESH_SOURCE_DS_MAX_BYTES) {
      .dsvert_formal_cox_fresh_source_ds_abort(
        "The configured formal Cox encrypted delivery is invalid.",
        "invalid_formal_cox_fresh_source_payload")
    }
  }
  payload
}

.dsvert_formal_cox_fresh_source_ds_shape <- function(plan, schema, source,
                                                       block_capacity) {
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  capacity <- suppressWarnings(as.integer(numeric$capacity))
  custodians <- names(schema$unsigned$peer_pinset)
  if (is.na(capacity) || capacity < 1L ||
      !is.character(custodians) || length(custodians) < 2L ||
      anyNA(custodians) || anyDuplicated(custodians) ||
      !source %in% custodians || block_capacity < 1L ||
      block_capacity > capacity) {
    .dsvert_formal_cox_fresh_source_ds_abort(
      "The configured formal Cox source shape is invalid.",
      "invalid_formal_cox_fresh_source_shape")
  }
  compute <- .dsvert_formal_cox_compute_peers(schema$unsigned$peer_pinset)
  if (!is.character(compute) || length(compute) != 2L || anyNA(compute) ||
      anyDuplicated(compute) || !all(compute %in% custodians)) {
    .dsvert_formal_cox_fresh_source_ds_abort(
      "The configured formal Cox source shape is invalid.",
      "invalid_formal_cox_fresh_source_shape")
  }
  list(
    version = "dsvert-formal-cox-fresh-source-shape-v1",
    analysis_id = plan$analysis_id, schema_sha256 = plan$schema_sha256,
    source = source, custodian_peers = unname(custodians),
    designated_compute_peers = unname(compute),
    total_blocks = as.integer(ceiling(capacity / block_capacity)),
    production_ready = FALSE)
}

.dsvert_formal_cox_fresh_source_ds_reply <- function(action, payload) {
  expected <- switch(action,
    shape = c("version", "analysis_id", "schema_sha256", "source",
              "custodian_peers", "designated_compute_peers", "total_blocks",
              "production_ready"),
    ticket = "ticket",
    produce = c("receipt", "receipt_sha256", "replayed"),
    delivery = c("version", "purpose", "receipt", "receipt_sha256",
                 "recipient_peer_name", "envelope", "binding"),
    import = c("version", "purpose", "receipt_sha256", "recipient_peer_name",
               "replayed"),
    provision = c("version", "peer_name", "plan_sha256", "attempt_id",
                  "replayed", "production_ready"))
  fields <- names(payload)
  encoded <- tryCatch(jsonlite::toJSON(
    payload, auto_unbox = TRUE, null = "null", digits = 17),
    error = function(error) NULL)
  forbidden <- paste0(
    "\\\"(recipient_signing_key|source_signing_key|canonical_input_base64|",
    "rows|private_key|storage_root|path|secret|config)\\\"\\s*:")
  if (!is.list(payload) || is.null(fields) || anyNA(fields) ||
      anyDuplicated(fields) || !setequal(fields, expected) ||
      !is.character(encoded) || length(encoded) != 1L || is.na(encoded) ||
      nchar(encoded, type = "bytes") > .DSVERT_FORMAL_COX_FRESH_SOURCE_DS_MAX_BYTES ||
      grepl(forbidden, encoded, perl = TRUE, ignore.case = TRUE)) {
    .dsvert_formal_cox_fresh_source_ds_abort(
      "The configured formal Cox source reply is invalid.",
      "invalid_formal_cox_fresh_source_reply")
  }
  list(
    version = .DSVERT_FORMAL_COX_FRESH_SOURCE_DS_VERSION,
    action = action, payload = payload, production_ready = FALSE)
}

#' Relay one configured fresh formal-Cox source action
#'
#' This closed DataSHIELD endpoint selects a preconfigured signed Cox schema
#' and private immutable source snapshot. It accepts only protocol tickets,
#' encrypted envelopes and bounded block selectors. It cannot start an
#' analytical run, expose a source value or return a fitted Cox result.
#'
#' @param analysis_id,data_name,formula_sha256 Fixed custodian-owned selectors.
#' @param action One closed ingress action.
#' @param payload Action-specific opaque protocol material.
#' @return A bounded non-production transport reply.
#' @export
dsvertFormalCoxFreshSourceDS <- function(
    analysis_id, data_name, formula_sha256, action, payload) {
  analysis_id <- .dsvert_formal_cox_fresh_source_ds_label(
    analysis_id, "analysis id")
  data_name <- .dsvert_formal_cox_fresh_source_ds_label(data_name, "data selector")
  formula_sha256 <- .dsvert_formal_cox_fresh_source_ds_sha256(
    formula_sha256, "formula selector")
  if (!is.character(action) || length(action) != 1L || is.na(action) ||
      !action %in% .DSVERT_FORMAL_COX_FRESH_SOURCE_DS_ACTIONS) {
    .dsvert_formal_cox_fresh_source_ds_abort(
      "The configured formal Cox source action is invalid.",
      "invalid_formal_cox_fresh_source_action")
  }
  payload <- .dsvert_formal_cox_fresh_source_ds_payload(action, payload)
  response <- tryCatch({
    plan <- .dsvert_formal_cox_run_plan(analysis_id, data_name, formula_sha256)
    spec <- .dsvert_formal_cox_run_spec(analysis_id)
    schema <- spec$schema
    if (!identical(plan$analysis_id, analysis_id) ||
        !identical(plan$data_name, data_name) ||
        !identical(plan$formula_sha256, formula_sha256) ||
        !identical(plan$schema_sha256, schema$schema_sha256)) {
      stop("configured run-plan mismatch")
    }
    source <- .dsvert_require_configured_local_peer_name()
    source_spec <- .dsvert_formal_cox_server_source_spec(schema, source)
    if (!identical(source_spec$data_name, plan$data_name)) {
      stop("configured data selector mismatch")
    }
    run_id <- .dsvert_formal_cox_run_id(schema)
    switch(action,
      shape = {
        context <- .dsvert_formal_cox_server_source_open(schema, parent.frame())
        if (!identical(context$source_name, source) ||
            !identical(context$block_capacity, source_spec$block_capacity)) {
          stop("configured source context mismatch")
        }
        .dsvert_formal_cox_fresh_source_ds_shape(
          plan, schema, source, source_spec$block_capacity)
      },
      ticket = list(ticket = .dsvert_formal_cox_server_source_recipient_ticket(
        schema, source_spec$block_capacity, run_id)),
      produce = {
        context <- .dsvert_formal_cox_server_source_open(schema, parent.frame())
        .dsvert_formal_cox_server_source_produce_block(
          context, run_id, payload$recipient_tickets, payload$block_index)
      },
      delivery = {
        context <- .dsvert_formal_cox_server_source_open(schema, parent.frame())
        .dsvert_formal_cox_server_source_deliver_block(
          context, run_id, payload$recipient_tickets, payload$block_index,
          payload$recipient_peer_name)
      },
      import = .dsvert_formal_cox_server_source_import_block(
        schema, source_spec$block_capacity, run_id,
        payload$recipient_tickets, payload$delivery),
      provision = .dsvert_formal_cox_worker_provision(
        schema, source_spec$block_capacity, run_id,
        payload$recipient_tickets, payload$delivery))
  }, error = function(error) NULL)
  if (is.null(response)) .dsvert_formal_cox_fresh_source_ds_abort()
  .dsvert_formal_cox_fresh_source_ds_reply(action, response)
}
