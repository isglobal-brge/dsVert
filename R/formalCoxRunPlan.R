# Registered formal-Cox run planning.
#
# This is an internal, server-owned boundary for the future live Cox route.
# It resolves only a unanimously signed schema already configured by the
# custodian.  It never reads source rows, starts a worker, or returns the
# schema, pinset, source configuration, path, key, or privacy controls.

.DSVERT_FORMAL_COX_RUN_SPEC_VERSION <- "dsvert-formal-cox-run-spec-v1"
.DSVERT_FORMAL_COX_RUN_PLAN_VERSION <- "dsvert-formal-cox-run-plan-v1"
.DSVERT_FORMAL_COX_RUN_DOMAIN <- "dsVert/formal-cox/registered-run/v1|"

.dsvert_formal_cox_run_abort <- function(
    message = "The requested formal Cox run is unavailable.",
    code = "formal_cox_run_unavailable") {
  stop(structure(
    list(message = message, call = NULL, code = code),
    class = c("dsvert_formal_cox_run_error", "error", "condition")))
}

.dsvert_formal_cox_run_label <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)) {
    .dsvert_formal_cox_run_abort(
      paste0("The formal Cox ", what, " is invalid."),
      "invalid_formal_cox_run_selector")
  }
  enc2utf8(value)
}

.dsvert_formal_cox_run_sha256 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_cox_run_abort(
      paste0("The formal Cox ", what, " is invalid."),
      "invalid_formal_cox_run_selector")
  }
  value
}

# A signed schema fixes the complete protected computation, including its
# bounds, source layout, pinned peers and one declared optimiser transcript.
# It therefore also fixes the only admissible source/recipient run id.  This
# prevents an internal caller from manufacturing a second encrypted ingress
# or sticky opening for the same analysis by choosing a fresh nonce-like id.
.dsvert_formal_cox_run_id <- function(schema) {
  .dsvert_formal_cox_schema_validate(schema)
  .dsvert_formal_cox_hash(
    .DSVERT_FORMAL_COX_RUN_DOMAIN,
    list(schema_sha256 = schema$schema_sha256))
}

.dsvert_formal_cox_run_spec <- function(
    analysis_id,
    specs = .dsvert_dp_option("formal_cox_run_specs", list())) {
  analysis_id <- .dsvert_formal_cox_run_label(analysis_id, "analysis id")
  fields <- c("version", "analysis_id", "data_name", "formula_sha256",
              "schema")
  if (!is.list(specs) || is.null(names(specs)) || anyNA(names(specs)) ||
      any(!nzchar(names(specs))) || anyDuplicated(names(specs))) {
    .dsvert_formal_cox_run_abort(
      "The custodian formal Cox run registry is invalid.",
      "invalid_formal_cox_run_registry")
  }
  value <- specs[[analysis_id]]
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(value$version, .DSVERT_FORMAL_COX_RUN_SPEC_VERSION) ||
      !identical(value$analysis_id, analysis_id)) {
    .dsvert_formal_cox_run_abort(
      "The requested formal Cox run is unavailable.",
      "invalid_formal_cox_run_registry")
  }
  value$data_name <- .dsvert_formal_cox_run_label(
    value$data_name, "data selector")
  value$formula_sha256 <- .dsvert_formal_cox_run_sha256(
    value$formula_sha256, "formula selector")
  if (!isTRUE(tryCatch({
    .dsvert_formal_cox_schema_validate(value$schema)
    TRUE
  }, error = function(error) FALSE))) {
    .dsvert_formal_cox_run_abort(
      "The requested formal Cox run is unavailable.",
      "invalid_formal_cox_run_registry")
  }
  value
}

.dsvert_formal_cox_run_plan <- function(analysis_id, data_name,
                                         formula_sha256) {
  spec <- .dsvert_formal_cox_run_spec(analysis_id)
  data_name <- .dsvert_formal_cox_run_label(data_name, "data selector")
  formula_sha256 <- .dsvert_formal_cox_run_sha256(
    formula_sha256, "formula selector")
  if (!identical(data_name, spec$data_name) ||
      !identical(formula_sha256, spec$formula_sha256)) {
    .dsvert_formal_cox_run_abort(
      "The requested formal Cox run is unavailable.",
      "invalid_formal_cox_run_selector")
  }
  peers <- unlist(spec$schema$unsigned$compute_peers, use.names = FALSE)
  if (!is.character(peers) || length(peers) != 2L || anyNA(peers) ||
      any(!nzchar(peers)) || anyDuplicated(peers)) {
    .dsvert_formal_cox_run_abort(
      "The requested formal Cox run is unavailable.",
      "invalid_formal_cox_run_registry")
  }
  list(
    version = .DSVERT_FORMAL_COX_RUN_PLAN_VERSION,
    analysis_id = spec$analysis_id, data_name = data_name,
    formula_sha256 = formula_sha256,
    schema_sha256 = spec$schema$schema_sha256,
    run_id = .dsvert_formal_cox_run_id(spec$schema),
    compute_peers = unname(peers),
    production_ready = FALSE)
}
