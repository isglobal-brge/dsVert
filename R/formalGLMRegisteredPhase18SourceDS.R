# Closed DataSHIELD relay for a configured registered formal-GLM source.
#
# The signed source contract selects no data object: the server configuration
# fixes the sole local snapshot.  This endpoint only moves signed receipts and
# bounded opaque ingress frames between peers.  It never returns source rows,
# plaintext coordinates, a full encrypted pair, a key or a fitted result.

.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_VERSION <-
  "dsvert-formal-glm-registered-phase18-source-response-v1"
.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_MAX_BYTES <- 4L * 1024L * 1024L
.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_MAX_CONTRACT_BYTES <- 1024L * 1024L
.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_ACTIONS <- c(
  "ticket", "ticket_set", "seal_block", "chunk", "import_chunk",
  "local_receipt", "receipt_commit", "receipt_set", "binding",
  "host_provision")
.DSVERT_FORMAL_GLM_REGISTERED_FRESH_SOURCE_DS_ACTIONS <- c(
  "shape", .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_ACTIONS)
.DSVERT_FORMAL_GLM_REGISTERED_FRESH_SOURCE_DS_VERSION <-
  "dsvert-formal-glm-registered-fresh-source-response-v1"
.DSVERT_FORMAL_GLM_REGISTERED_ANALYSIS_SPECS_OPTION <-
  "dsvert.formal_glm.registered_analysis_specs"
.DSVERT_FORMAL_GLM_REGISTERED_ANALYSIS_SPEC_VERSION <-
  "dsvert-formal-glm-registered-analysis-spec-v1"

.dsvert_formal_glm_registered_source_ds_abort <- function(
    message = "The registered formal-GLM source request is unavailable.",
    code = "formal_glm_registered_source_unavailable") {
  stop(structure(
    list(message = message, call = NULL, code = code, openings_performed = 0L),
    class = c("dsvert_formal_glm_registered_source_ds_error", "error",
              "condition")))
}

.dsvert_formal_glm_registered_source_ds_contract <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      nchar(value, type = "bytes") < 2L ||
      nchar(value, type = "bytes") >
        .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_MAX_CONTRACT_BYTES ||
      !identical(enc2utf8(value), value)) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM source contract is invalid.",
      "invalid_formal_glm_registered_source_contract")
  }
  value
}

.dsvert_formal_glm_registered_source_ds_payload <- function(action, payload) {
  attributes <- attributes(payload)
  if (!is.list(payload) || (!is.null(attributes) &&
      length(setdiff(names(attributes), "names")))) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM source payload is invalid.",
      "invalid_formal_glm_registered_source_payload")
  }
  fields <- names(payload)
  if (is.null(fields)) fields <- character()
  expected <- switch(action,
    shape = character(), ticket = character(), receipt_set = character(),
    host_provision = character(),
    ticket_set = "recipient_tickets", seal_block = c("recipient_tickets", "block_index"),
    chunk = c("recipient_tickets", "block_index", "offset"),
    import_chunk = c("recipient_tickets", "chunk_receipt", "pair_chunk_base64"),
    local_receipt = "recipient_tickets", receipt_commit = "local_receipt_json",
    binding = "recipient_tickets")
  if (anyNA(fields) || anyDuplicated(fields) || !identical(fields, expected)) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM source payload is invalid.",
      "invalid_formal_glm_registered_source_payload")
  }
  has_tickets <- "recipient_tickets" %in% fields
  if (has_tickets && (!is.list(payload$recipient_tickets) ||
      length(payload$recipient_tickets) != 2L ||
      !is.null(names(payload$recipient_tickets)))) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM recipient ticket set is invalid.",
      "invalid_formal_glm_registered_source_payload")
  }
  if ("block_index" %in% fields) {
    block_index <- suppressWarnings(as.integer(payload$block_index))
    if (!is.numeric(payload$block_index) || length(payload$block_index) != 1L ||
        is.na(payload$block_index) || !is.finite(payload$block_index) ||
        payload$block_index != floor(payload$block_index) || is.na(block_index) ||
        block_index < 0L) {
      .dsvert_formal_glm_registered_source_ds_abort(
        "The registered formal-GLM source block selector is invalid.",
        "invalid_formal_glm_registered_source_payload")
    }
    payload$block_index <- block_index
  }
  if ("offset" %in% fields) {
    offset <- suppressWarnings(as.integer(payload$offset))
    if (!is.numeric(payload$offset) || length(payload$offset) != 1L ||
        is.na(payload$offset) || !is.finite(payload$offset) ||
        payload$offset != floor(payload$offset) || is.na(offset) || offset < 0L ||
        offset > 32L * 1024L^2) {
      .dsvert_formal_glm_registered_source_ds_abort(
        "The registered formal-GLM source chunk selector is invalid.",
        "invalid_formal_glm_registered_source_payload")
    }
    payload$offset <- offset
  }
  if (identical(action, "import_chunk")) {
    encoded <- payload$pair_chunk_base64
    chunk <- tryCatch(jsonlite::base64_dec(encoded), error = function(error) raw())
    canonical <- gsub("[\\r\\n]", "", jsonlite::base64_enc(chunk))
    if (!is.list(payload$chunk_receipt) || !is.character(encoded) ||
        length(encoded) != 1L || is.na(encoded) ||
        nchar(encoded, type = "bytes") >
          .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_MAX_BYTES ||
        !length(chunk) || length(chunk) > 1024L^2 ||
        !identical(canonical, encoded)) {
      if (is.raw(chunk) && length(chunk)) chunk[] <- as.raw(0L)
      .dsvert_formal_glm_registered_source_ds_abort(
        "The registered formal-GLM source chunk is invalid.",
        "invalid_formal_glm_registered_source_payload")
    }
    if (length(chunk)) chunk[] <- as.raw(0L)
  }
  if (identical(action, "receipt_commit") &&
      (!is.character(payload$local_receipt_json) ||
       length(payload$local_receipt_json) != 1L ||
       is.na(payload$local_receipt_json) ||
       nchar(payload$local_receipt_json, type = "bytes") < 2L ||
       nchar(payload$local_receipt_json, type = "bytes") >
         .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_MAX_BYTES)) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM local receipt is invalid.",
      "invalid_formal_glm_registered_source_payload")
  }
  payload
}

.dsvert_formal_glm_registered_fresh_source_shape <- function(context) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  authorization <- context$authorization
  geometry <- authorization$geometry
  custodians <- authorization$custodian_peers
  compute <- authorization$designated_compute_peers
  blocks <- suppressWarnings(as.integer(geometry$total_blocks))
  valid <- is.list(authorization) && is.list(geometry) &&
    is.character(authorization$artifact_id) &&
    length(authorization$artifact_id) == 1L &&
    grepl("^[0-9a-f]{64}$", authorization$artifact_id) &&
    is.character(authorization$source_contract_sha256) &&
    length(authorization$source_contract_sha256) == 1L &&
    grepl("^[0-9a-f]{64}$", authorization$source_contract_sha256) &&
    is.character(context$source_name) && length(context$source_name) == 1L &&
    !is.na(context$source_name) &&
    grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", context$source_name) &&
    is.character(custodians) && length(custodians) >= 2L &&
    !anyNA(custodians) && !anyDuplicated(custodians) &&
    is.character(compute) && length(compute) == 2L && !anyNA(compute) &&
    !anyDuplicated(compute) && all(compute %in% custodians) &&
    length(blocks) == 1L && !is.na(blocks) && blocks >= 1L &&
    is.logical(authorization$production_ready) &&
    length(authorization$production_ready) == 1L &&
    !is.na(authorization$production_ready) && !authorization$production_ready
  if (!isTRUE(valid)) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM fresh source shape is invalid.",
      "invalid_formal_glm_registered_fresh_shape")
  }
  list(
    version = "dsvert-formal-glm-registered-fresh-source-shape-v1",
    artifact_id = authorization$artifact_id,
    source_contract_sha256 = authorization$source_contract_sha256,
    source = context$source_name,
    custodian_peers = unname(custodians),
    designated_compute_peers = unname(compute), total_blocks = blocks,
    production_ready = FALSE)
}

.dsvert_formal_glm_registered_source_ds_safe <- function(payload) {
  encoded <- tryCatch(jsonlite::toJSON(
    payload, auto_unbox = TRUE, null = "null", digits = 17),
    error = function(error) NULL)
  forbidden <- paste0(
    "\\\"[^\\\"]*(?:rows|values|validity|private_consensus|alignment_consensus|",
    "authorization_json|local_signing_key|pair_json|storage|path|secret|",
    "backend|context|token|capsule|run_id|opening)[^\\\"]*\\\"\\s*:")
  if (!is.character(encoded) || length(encoded) != 1L || is.na(encoded) ||
      nchar(encoded, type = "bytes") >
        .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_MAX_BYTES ||
      grepl(forbidden, encoded, perl = TRUE, ignore.case = TRUE)) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM source reply is invalid.",
      "invalid_formal_glm_registered_source_reply")
  }
  payload
}

.dsvert_formal_glm_registered_fresh_source_selector <- function(
    analysis_id, data_name, family, formula_sha256) {
  valid_label <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)
  }
  if (!valid_label(analysis_id) || !valid_label(data_name) ||
      !is.character(family) || length(family) != 1L || is.na(family) ||
      !family %in% c("binomial", "poisson") ||
      !is.character(formula_sha256) || length(formula_sha256) != 1L ||
      is.na(formula_sha256) || !grepl("^[0-9a-f]{64}$", formula_sha256)) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM fresh-analysis selector is invalid.",
      "invalid_formal_glm_registered_fresh_selector")
  }
  list(
    analysis_id = enc2utf8(analysis_id), data_name = enc2utf8(data_name),
    family = family, formula_sha256 = formula_sha256)
}

.dsvert_formal_glm_registered_fresh_source_spec <- function(selector) {
  specs <- getOption(.DSVERT_FORMAL_GLM_REGISTERED_ANALYSIS_SPECS_OPTION)
  if (!is.list(specs) || is.null(names(specs)) || anyNA(names(specs)) ||
      any(!nzchar(names(specs))) || anyDuplicated(names(specs))) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM fresh-analysis registry is invalid.",
      "invalid_formal_glm_registered_fresh_registry")
  }
  valid_names <- vapply(names(specs), function(value) {
    is.character(value) && length(value) == 1L &&
      grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)
  }, logical(1L))
  if (!all(valid_names)) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM fresh-analysis registry is invalid.",
      "invalid_formal_glm_registered_fresh_registry")
  }
  value <- specs[[selector$analysis_id]]
  fields <- c("version", "analysis_id", "data_name", "family",
              "formula_sha256", "source_contract_json")
  if (is.null(value) || !is.list(value) || is.null(names(value)) ||
      anyNA(names(value)) || anyDuplicated(names(value)) ||
      !identical(names(value), fields) ||
      !identical(value$version, .DSVERT_FORMAL_GLM_REGISTERED_ANALYSIS_SPEC_VERSION) ||
      !identical(value$analysis_id, selector$analysis_id) ||
      !identical(value$data_name, selector$data_name) ||
      !identical(value$family, selector$family) ||
      !identical(value$formula_sha256, selector$formula_sha256) ||
      !is.character(value$source_contract_json) ||
      length(value$source_contract_json) != 1L ||
      is.na(value$source_contract_json) ||
      nchar(value$source_contract_json, type = "bytes") < 2L ||
      nchar(value$source_contract_json, type = "bytes") >
        .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_MAX_CONTRACT_BYTES ||
      !identical(enc2utf8(value$source_contract_json),
                 value$source_contract_json)) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The requested registered formal-GLM fresh analysis is unavailable.",
      "invalid_formal_glm_registered_fresh_registry")
  }
  value
}

.dsvert_formal_glm_registered_source_ds_dispatch <- function(
    context, action, payload) {
  switch(action,
    shape = .dsvert_formal_glm_registered_fresh_source_shape(context),
    ticket = .dsvert_formal_glm_registered_source_issue_ticket(context),
    ticket_set = .dsvert_formal_glm_registered_source_persist_ticket_set(
      context, payload$recipient_tickets),
    seal_block = .dsvert_formal_glm_registered_source_seal_block(
      context, payload$recipient_tickets, payload$block_index),
    chunk = {
      result <- .dsvert_formal_glm_registered_source_read_block_chunk(
        context, payload$recipient_tickets, payload$block_index, payload$offset)
      list(chunk_receipt = result$chunk_receipt,
           pair_chunk_base64 = gsub("[\\r\\n]", "",
             jsonlite::base64_enc(result$pair_chunk)), replayed = result$replayed)
    },
    import_chunk = {
      chunk <- jsonlite::base64_dec(payload$pair_chunk_base64)
      on.exit(if (length(chunk)) chunk[] <- as.raw(0L), add = TRUE)
      .dsvert_formal_glm_registered_source_import_block_chunk(
        context, payload$recipient_tickets, payload$chunk_receipt, chunk)
    },
    local_receipt = .dsvert_formal_glm_registered_source_seal_local_receipt(
      context, payload$recipient_tickets),
    receipt_commit = .dsvert_formal_glm_registered_source_commit_local_receipt(
      context, payload$local_receipt_json),
    receipt_set = .dsvert_formal_glm_registered_source_seal_receipt_set(context),
    binding = .dsvert_formal_glm_registered_source_commit_binding(
      context, payload$recipient_tickets),
    host_provision = .dsvert_formal_glm_registered_source_provision_job_host(context))
}

#' Relay one closed registered-formal-GLM source action
#'
#' The configured server snapshot is selected only by the signed source
#' contract.  This method relays bounded encrypted ingress frames and signed
#' protocol receipts; it is not an analyst-facing model or data endpoint.
#'
#' @param source_contract_json Canonical signed registered source contract.
#' @param action One closed source action.
#' @param payload Action-specific protocol payload.
#' @return A bounded non-production protocol reply.
#' @export
dsvertFormalGLMRegisteredSourceDS <- function(
    source_contract_json, action, payload) {
  source_contract_json <- .dsvert_formal_glm_registered_source_ds_contract(
    source_contract_json)
  if (!is.character(action) || length(action) != 1L || is.na(action) ||
      !action %in% .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_ACTIONS) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM source action is invalid.",
      "invalid_formal_glm_registered_source_action")
  }
  payload <- .dsvert_formal_glm_registered_source_ds_payload(action, payload)
  response <- tryCatch({
    context <- .dsvert_formal_glm_registered_source_open(
      source_contract_json, parent.frame())
    .dsvert_formal_glm_registered_source_ds_dispatch(context, action, payload)
  }, error = function(error) NULL)
  if (is.null(response)) .dsvert_formal_glm_registered_source_ds_abort()
  list(
    version = .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_DS_VERSION,
    action = action,
    payload = .dsvert_formal_glm_registered_source_ds_safe(response),
    production_ready = FALSE)
}

#' Relay one configured fresh registered-formal-GLM source action
#'
#' The analyst supplies only the fixed registered analysis selector.  The
#' signed source contract remains solely in the custodian's Rock-local
#' configuration; this endpoint never return it, a source row, a key, or a
#' full encrypted pair.
#'
#' @param analysis_id Custodian-configured registered analysis id.
#' @param data_name Fixed configured data selector.
#' @param family Either `"binomial"` or `"poisson"`.
#' @param formula_sha256 Canonical formula selector.
#' @param action One closed source action.
#' @param payload Action-specific protocol payload.
#' @return A bounded non-production protocol reply.
#' @export
dsvertFormalGLMRegisteredFreshSourceDS <- function(
    analysis_id, data_name, family, formula_sha256, action, payload) {
  selector <- .dsvert_formal_glm_registered_fresh_source_selector(
    analysis_id, data_name, family, formula_sha256)
  spec <- .dsvert_formal_glm_registered_fresh_source_spec(selector)
  if (!is.character(action) || length(action) != 1L || is.na(action) ||
      !action %in% .DSVERT_FORMAL_GLM_REGISTERED_FRESH_SOURCE_DS_ACTIONS) {
    .dsvert_formal_glm_registered_source_ds_abort(
      "The registered formal-GLM fresh source action is invalid.",
      "invalid_formal_glm_registered_fresh_action")
  }
  payload <- .dsvert_formal_glm_registered_source_ds_payload(action, payload)
  response <- tryCatch({
    context <- .dsvert_formal_glm_registered_source_open(
      spec$source_contract_json, parent.frame())
    .dsvert_formal_glm_registered_source_ds_dispatch(context, action, payload)
  }, error = function(error) NULL)
  if (is.null(response)) .dsvert_formal_glm_registered_source_ds_abort()
  list(
    version = .DSVERT_FORMAL_GLM_REGISTERED_FRESH_SOURCE_DS_VERSION,
    action = action,
    payload = .dsvert_formal_glm_registered_source_ds_safe(response),
    production_ready = FALSE)
}
