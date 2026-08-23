# Read-only endpoint for a completed formal discrete-time hazard release.
#
# A discrete-time hazard model is a binomial GLM over a custodian-owned,
# pre-expanded person-period design.  Its public certificate therefore uses
# the formal GLM verifier, while this registry binds that design back to the
# caller's Surv() formula and to the fixed time grid.  It cannot start an
# expansion, choose bins, or expose the expanded rows.

.DSVERT_FORMAL_COX_DISCRETE_PUBLIC_RESULT_SPEC_VERSION <-
  "dsvert-formal-cox-discrete-public-result-spec-v1"
.DSVERT_FORMAL_COX_DISCRETE_PUBLIC_RESULT_RESPONSE_VERSION <-
  "dsvert-formal-cox-discrete-public-result-v1"

.dsvert_formal_cox_discrete_public_abort <- function(
    message = "The requested formal discrete-time hazard analysis is unavailable.",
    code = "formal_cox_discrete_public_release_unavailable") {
  stop(structure(
    list(message = message, call = NULL, code = code),
    class = c("dsvert_formal_cox_discrete_public_error", "error", "condition")))
}

.dsvert_formal_cox_discrete_public_sha256 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_cox_discrete_public_abort(
      paste0("The formal discrete-time ", what, " is invalid."),
      "invalid_formal_cox_discrete_selector")
  }
  value
}

.dsvert_formal_cox_discrete_public_names <- function(value) {
  if (!is.character(value) || !length(value) || anyNA(value) ||
      anyDuplicated(value) || any(!nzchar(value)) ||
      any(nchar(value, type = "bytes") > 1024L) ||
      any(!grepl("^[[:print:]]+$", value))) {
    .dsvert_formal_cox_discrete_public_abort(
      "The custodian discrete-time coefficient registry is invalid.",
      "invalid_formal_cox_discrete_registry")
  }
  enc2utf8(value)
}

.dsvert_formal_cox_discrete_public_spec <- function(
    analysis_id,
    specs = .dsvert_dp_option("formal_cox_discrete_public_results", list())) {
  analysis_id <- .dsvert_formal_glm_frontdoor_label(
    analysis_id, "analysis id")
  fields <- c(
    "version", "analysis_id", "data_name", "target",
    "source_formula_sha256", "model_formula_sha256", "time_grid_sha256",
    "coefficient_names", "certificate_json", "pins")
  if (!is.list(specs) || is.null(names(specs)) || anyNA(names(specs)) ||
      any(!nzchar(names(specs))) || anyDuplicated(names(specs))) {
    .dsvert_formal_cox_discrete_public_abort(
      "The custodian formal discrete-time registry is invalid.",
      "invalid_formal_cox_discrete_registry")
  }
  value <- specs[[analysis_id]]
  if (is.null(value) || !is.list(value) || is.null(names(value)) ||
      anyNA(names(value)) || anyDuplicated(names(value)) ||
      !setequal(names(value), fields) ||
      !identical(value$version,
                 .DSVERT_FORMAL_COX_DISCRETE_PUBLIC_RESULT_SPEC_VERSION) ||
      !identical(value$analysis_id, analysis_id) ||
      !identical(value$target, "discrete_logit") ||
      !is.character(value$certificate_json) ||
      length(value$certificate_json) != 1L || is.na(value$certificate_json) ||
      nchar(value$certificate_json, type = "bytes") < 2L ||
      nchar(value$certificate_json, type = "bytes") >
        .DSVERT_FORMAL_GLM_PUBLIC_RESULT_MAX_BYTES ||
      !is.list(value$pins) || is.null(names(value$pins)) ||
      length(value$pins) < 2L || anyNA(names(value$pins)) ||
      any(!nzchar(names(value$pins))) || anyDuplicated(names(value$pins)) ||
      !all(vapply(value$pins, function(pin) {
        is.character(pin) && length(pin) == 1L && !is.na(pin) &&
          grepl("^[A-Za-z0-9_-]{43}$", pin)
      }, logical(1L)))) {
    .dsvert_formal_cox_discrete_public_abort(
      "The requested formal discrete-time analysis is unavailable.",
      "invalid_formal_cox_discrete_registry")
  }
  value$data_name <- .dsvert_formal_glm_frontdoor_label(
    value$data_name, "data selector")
  for (field in c("source_formula_sha256", "model_formula_sha256",
                  "time_grid_sha256")) {
    value[[field]] <- .dsvert_formal_cox_discrete_public_sha256(
      value[[field]], field)
  }
  value$coefficient_names <- .dsvert_formal_cox_discrete_public_names(
    value$coefficient_names)
  if (!all(vapply(names(value$pins), function(peer) {
    identical(.dsvert_formal_glm_frontdoor_label(peer, "pin peer"), peer)
  }, logical(1L)))) {
    .dsvert_formal_cox_discrete_public_abort(
      "The custodian formal discrete-time registry is invalid.",
      "invalid_formal_cox_discrete_registry")
  }
  value
}

.dsvert_formal_cox_discrete_public_response <- function(
    value, spec, analysis_id, data_name, source_formula_sha256) {
  model <- tryCatch(.dsvert_formal_glm_public_result_response(
    value,
    list(data_name = spec$data_name, family = "binomial",
         formula_sha256 = spec$model_formula_sha256),
    analysis_id, data_name, "binomial", spec$model_formula_sha256),
    error = function(error) NULL)
  if (is.null(model) || !identical(
      vapply(model$coefficients, `[[`, character(1L), "coefficient"),
      spec$coefficient_names) ||
      !identical(data_name, spec$data_name) ||
      !identical(source_formula_sha256, spec$source_formula_sha256)) {
    .dsvert_formal_cox_discrete_public_abort(
      "The requested formal discrete-time public release is invalid.",
      "invalid_formal_cox_discrete_public_release")
  }
  list(
    version = .DSVERT_FORMAL_COX_DISCRETE_PUBLIC_RESULT_RESPONSE_VERSION,
    analysis_id = analysis_id, artifact_id = model$artifact_id,
    certificate_sha256 = model$certificate_sha256,
    target = spec$target, source_formula_sha256 = source_formula_sha256,
    model_formula_sha256 = spec$model_formula_sha256,
    time_grid_sha256 = spec$time_grid_sha256,
    coefficients = model$coefficients, production_ready = FALSE)
}

dsvertFormalCoxDiscretePublicResultDS <- function(
    analysis_id, data_name, source_formula_sha256) {
  spec <- .dsvert_formal_cox_discrete_public_spec(analysis_id)
  data_name <- .dsvert_formal_glm_frontdoor_label(data_name, "data selector")
  source_formula_sha256 <- .dsvert_formal_cox_discrete_public_sha256(
    source_formula_sha256, "source formula selector")
  if (!identical(data_name, spec$data_name) ||
      !identical(source_formula_sha256, spec$source_formula_sha256)) {
    .dsvert_formal_cox_discrete_public_abort(
      "The requested formal discrete-time analysis is unavailable.",
      "invalid_formal_cox_discrete_selector")
  }
  decoded <- tryCatch(
    .callMpcTool("formal-glm-public-result", list(
      certificate_json = spec$certificate_json, pins = spec$pins),
      simplify_output = FALSE),
    error = function(error) NULL)
  if (is.null(decoded)) {
    .dsvert_formal_cox_discrete_public_abort()
  }
  .dsvert_formal_cox_discrete_public_response(
    decoded, spec, analysis_id, data_name, source_formula_sha256)
}
