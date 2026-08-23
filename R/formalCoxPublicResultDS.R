# Read-only server endpoint for a completed, signed formal Cox publication.
#
# The custodian owns the registry, certificate and pinset. Analysts can name
# only a registered analysis, data selector and canonical formula digest; this
# endpoint cannot start a Cox worker, choose privacy settings, or read Rock.

.DSVERT_FORMAL_COX_PUBLIC_RESULT_SPEC_VERSION <-
  "dsvert-formal-cox-public-result-spec-v1"
.DSVERT_FORMAL_COX_PUBLIC_RESULT_RESPONSE_VERSION <-
  "dsvert-formal-cox-public-result-v1"
.DSVERT_FORMAL_COX_PUBLIC_RESULT_MAX_BYTES <- 16L * 1024L^2

.dsvert_formal_cox_public_abort <- function(
    message = "The requested formal Cox analysis is unavailable.",
    code = "formal_cox_public_release_unavailable") {
  stop(structure(
    list(message = message, call = NULL, code = code),
    class = c("dsvert_formal_cox_public_error", "error", "condition")))
}

.dsvert_formal_cox_public_label <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)) {
    .dsvert_formal_cox_public_abort(
      paste0("The formal Cox ", what, " is invalid."),
      "invalid_formal_cox_selector")
  }
  enc2utf8(value)
}

.dsvert_formal_cox_public_sha256 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_cox_public_abort(
      paste0("The formal Cox ", what, " is invalid."),
      "invalid_formal_cox_selector")
  }
  value
}

.dsvert_formal_cox_public_spec <- function(
    analysis_id,
    specs = .dsvert_dp_option("formal_cox_public_results", list())) {
  analysis_id <- .dsvert_formal_cox_public_label(analysis_id, "analysis id")
  fields <- c("version", "analysis_id", "data_name", "formula_sha256",
              "coefficient_names", "certificate_json", "pins")
  if (!is.list(specs) || is.null(names(specs)) || anyNA(names(specs)) ||
      any(!nzchar(names(specs))) || anyDuplicated(names(specs))) {
    .dsvert_formal_cox_public_abort(
      "The custodian formal Cox public-release registry is invalid.",
      "invalid_formal_cox_registry")
  }
  value <- specs[[analysis_id]]
  if (is.null(value) || !is.list(value) || is.null(names(value)) ||
      anyNA(names(value)) || anyDuplicated(names(value)) ||
      !setequal(names(value), fields) ||
      !identical(value$version, .DSVERT_FORMAL_COX_PUBLIC_RESULT_SPEC_VERSION) ||
      !identical(value$analysis_id, analysis_id) ||
      !is.character(value$certificate_json) ||
      length(value$certificate_json) != 1L || is.na(value$certificate_json) ||
      nchar(value$certificate_json, type = "bytes") < 2L ||
      nchar(value$certificate_json, type = "bytes") >
        .DSVERT_FORMAL_COX_PUBLIC_RESULT_MAX_BYTES ||
      !is.character(value$coefficient_names) || !length(value$coefficient_names) ||
      anyNA(value$coefficient_names) || anyDuplicated(value$coefficient_names) ||
      any(!grepl("^[A-Za-z][A-Za-z0-9_.]{0,127}$",
                 value$coefficient_names)) ||
      !is.list(value$pins) || is.null(names(value$pins)) ||
      length(value$pins) < 2L || anyNA(names(value$pins)) ||
      any(!nzchar(names(value$pins))) || anyDuplicated(names(value$pins)) ||
      !all(vapply(value$pins, function(pin) {
        is.character(pin) && length(pin) == 1L && !is.na(pin) &&
          grepl("^[A-Za-z0-9_-]{43}$", pin)
      }, logical(1L)))) {
    .dsvert_formal_cox_public_abort(
      "The requested formal Cox analysis is unavailable.",
      "invalid_formal_cox_registry")
  }
  value$data_name <- .dsvert_formal_cox_public_label(
    value$data_name, "data selector")
  value$formula_sha256 <- .dsvert_formal_cox_public_sha256(
    value$formula_sha256, "formula selector")
  if (!all(vapply(names(value$pins), function(peer) {
    identical(.dsvert_formal_cox_public_label(peer, "pin peer"), peer)
  }, logical(1L)))) {
    .dsvert_formal_cox_public_abort(
      "The custodian formal Cox public-release registry is invalid.",
      "invalid_formal_cox_registry")
  }
  value$coefficient_names <- enc2utf8(value$coefficient_names)
  value
}

.dsvert_formal_cox_public_response <- function(
    value, spec, analysis_id, data_name, formula_sha256) {
  fields <- c("version", "artifact_id", "certificate_sha256", "valid",
              "coefficients", "production_ready")
  invalid <- !is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
    anyDuplicated(names(value)) || !setequal(names(value), fields) ||
    !identical(value$version, .DSVERT_FORMAL_COX_PUBLIC_RESULT_RESPONSE_VERSION) ||
    !identical(value$valid, TRUE) || !identical(value$production_ready, FALSE) ||
    !is.character(value$artifact_id) || length(value$artifact_id) != 1L ||
    !is.character(value$certificate_sha256) ||
    length(value$certificate_sha256) != 1L ||
    !is.list(value$coefficients) ||
    length(value$coefficients) != length(spec$coefficient_names)
  if (isTRUE(invalid)) {
    .dsvert_formal_cox_public_abort(
      "The requested formal Cox public release is invalid.",
      "invalid_formal_cox_public_release")
  }
  artifact_id <- .dsvert_formal_cox_public_sha256(
    value$artifact_id, "public artifact")
  certificate_sha256 <- .dsvert_formal_cox_public_sha256(
    value$certificate_sha256, "public certificate")
  coefficients <- lapply(seq_along(value$coefficients), function(index) {
    coefficient <- value$coefficients[[index]]
    coefficient_fields <- c(
      "index", "beta_steps", "fraction_bits", "beta",
      "hazard_ratio_lower", "hazard_ratio_upper", "hazard_ratio_midpoint")
    if (!is.list(coefficient) || is.null(names(coefficient)) ||
        anyNA(names(coefficient)) || anyDuplicated(names(coefficient)) ||
        !setequal(names(coefficient), coefficient_fields) ||
        !is.numeric(coefficient$index) || length(coefficient$index) != 1L ||
        is.na(coefficient$index) || !is.finite(coefficient$index) ||
        coefficient$index != index - 1L ||
        !is.character(coefficient$beta_steps) ||
        length(coefficient$beta_steps) != 1L || is.na(coefficient$beta_steps) ||
        !grepl("^(0|-[1-9][0-9]*|[1-9][0-9]*)$", coefficient$beta_steps) ||
        !is.numeric(coefficient$fraction_bits) ||
        length(coefficient$fraction_bits) != 1L ||
        is.na(coefficient$fraction_bits) || !is.finite(coefficient$fraction_bits) ||
        coefficient$fraction_bits < 8L || coefficient$fraction_bits > 60L ||
        coefficient$fraction_bits != floor(coefficient$fraction_bits) ||
        !all(vapply(c("beta", "hazard_ratio_lower", "hazard_ratio_upper",
                      "hazard_ratio_midpoint"), function(field) {
          is.numeric(coefficient[[field]]) && length(coefficient[[field]]) == 1L &&
            !is.na(coefficient[[field]]) && is.finite(coefficient[[field]])
        }, logical(1L))) ||
        coefficient$hazard_ratio_lower <= 0 ||
        coefficient$hazard_ratio_upper < coefficient$hazard_ratio_lower ||
        coefficient$hazard_ratio_midpoint < coefficient$hazard_ratio_lower ||
        coefficient$hazard_ratio_midpoint > coefficient$hazard_ratio_upper) {
      .dsvert_formal_cox_public_abort(
        "The requested formal Cox public release is invalid.",
        "invalid_formal_cox_public_release")
    }
    list(
      coefficient = spec$coefficient_names[[index]],
      beta_steps = coefficient$beta_steps,
      fraction_bits = as.integer(coefficient$fraction_bits),
      beta = as.numeric(coefficient$beta),
      hazard_ratio_lower = as.numeric(coefficient$hazard_ratio_lower),
      hazard_ratio_upper = as.numeric(coefficient$hazard_ratio_upper),
      hazard_ratio_midpoint = as.numeric(coefficient$hazard_ratio_midpoint))
  })
  if (!identical(data_name, spec$data_name) ||
      !identical(formula_sha256, spec$formula_sha256)) {
    .dsvert_formal_cox_public_abort(
      "The requested formal Cox analysis is unavailable.",
      "invalid_formal_cox_selector")
  }
  list(
    version = value$version, analysis_id = analysis_id,
    artifact_id = artifact_id, certificate_sha256 = certificate_sha256,
    formula_sha256 = formula_sha256, coefficients = coefficients,
    production_ready = FALSE)
}

dsvertFormalCoxPublicResultDS <- function(analysis_id, data_name,
                                          formula_sha256) {
  spec <- .dsvert_formal_cox_public_spec(analysis_id)
  data_name <- .dsvert_formal_cox_public_label(data_name, "data selector")
  formula_sha256 <- .dsvert_formal_cox_public_sha256(
    formula_sha256, "formula selector")
  if (!identical(data_name, spec$data_name) ||
      !identical(formula_sha256, spec$formula_sha256)) {
    .dsvert_formal_cox_public_abort(
      "The requested formal Cox analysis is unavailable.",
      "invalid_formal_cox_selector")
  }
  decoded <- tryCatch(
    .callMpcTool("formal-cox-public-result", list(
      certificate_json = spec$certificate_json, pins = spec$pins),
      simplify_output = FALSE),
    error = function(error) NULL)
  if (is.null(decoded)) {
    .dsvert_formal_cox_public_abort(
      "The requested formal Cox public release is unavailable.",
      "formal_cox_public_release_unavailable")
  }
  .dsvert_formal_cox_public_response(
    decoded, spec, analysis_id, data_name, formula_sha256)
}
