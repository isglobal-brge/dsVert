# Read-only server endpoint for a completed, signed formal GLM publication.
#
# It deliberately does not start a GLM computation.  Custodians configure a
# completed public certificate or a completed durable Phase21 terminal and its
# pinset; the analyst can name only the registered analysis, data, family, and
# canonical formula digest.

.DSVERT_FORMAL_GLM_PUBLIC_RESULT_SPEC_VERSION <-
  "dsvert-formal-glm-public-result-spec-v1"
.DSVERT_FORMAL_GLM_PHASE21_PUBLIC_TERMINAL_SPEC_VERSION <-
  "dsvert-formal-glm-phase21-public-terminal-spec-v1"
.DSVERT_FORMAL_GLM_PUBLIC_RESULT_RESPONSE_VERSION <-
  "dsvert-formal-glm-public-result-v1"
.DSVERT_FORMAL_GLM_PUBLIC_RESULT_MAX_BYTES <- 16L * 1024L^2

.dsvert_formal_glm_public_result_spec <- function(
    analysis_id,
    specs = .dsvert_dp_option("formal_glm_public_results", list())) {
  analysis_id <- .dsvert_formal_glm_frontdoor_label(
    analysis_id, "analysis id")
  if (!is.list(specs) || is.null(names(specs)) || anyNA(names(specs)) ||
      any(!nzchar(names(specs))) || anyDuplicated(names(specs))) {
    .dsvert_formal_glm_frontdoor_abort(
      "The custodian formal GLM public-release registry is invalid.",
      "invalid_formal_glm_registry")
  }
  value <- specs[[analysis_id]]
  legacy_fields <- c("version", "analysis_id", "data_name", "family",
                     "formula_sha256", "certificate_json", "pins")
  phase21_fields <- c("version", "analysis_id", "data_name", "family",
                      "formula_sha256", "authority_peer", "contract_json",
                      "resolution_json", "pins")
  version <- if (is.list(value)) value$version else NULL
  fields <- if (identical(version, .DSVERT_FORMAL_GLM_PUBLIC_RESULT_SPEC_VERSION)) {
    legacy_fields
  } else if (identical(version,
                       .DSVERT_FORMAL_GLM_PHASE21_PUBLIC_TERMINAL_SPEC_VERSION)) {
    phase21_fields
  } else {
    character()
  }
  if (is.null(value) || !is.list(value) || is.null(names(value)) ||
      anyNA(names(value)) || anyDuplicated(names(value)) ||
      !setequal(names(value), fields) ||
      !identical(value$analysis_id, analysis_id) ||
      !is.character(value$family) || length(value$family) != 1L ||
      is.na(value$family) || !value$family %in% c("binomial", "poisson") ||
      !is.list(value$pins) || is.null(names(value$pins)) ||
      length(value$pins) < 2L || anyNA(names(value$pins)) ||
      any(!nzchar(names(value$pins))) || anyDuplicated(names(value$pins)) ||
      !all(vapply(value$pins, function(pin) {
        is.character(pin) && length(pin) == 1L && !is.na(pin) &&
          grepl("^[A-Za-z0-9_-]{43}$", pin)
      }, logical(1L)))) {
    .dsvert_formal_glm_frontdoor_abort(
      "The requested formal GLM analysis is unavailable.",
      "invalid_formal_glm_registry")
  }
  if (identical(value$version, .DSVERT_FORMAL_GLM_PUBLIC_RESULT_SPEC_VERSION)) {
    if (!is.character(value$certificate_json) ||
        length(value$certificate_json) != 1L || is.na(value$certificate_json) ||
        nchar(value$certificate_json, type = "bytes") < 2L ||
        nchar(value$certificate_json, type = "bytes") >
          .DSVERT_FORMAL_GLM_PUBLIC_RESULT_MAX_BYTES) {
      .dsvert_formal_glm_frontdoor_abort(
        "The requested formal GLM analysis is unavailable.",
        "invalid_formal_glm_registry")
    }
  } else {
    value$authority_peer <- .dsvert_formal_glm_frontdoor_label(
      value$authority_peer, "authority peer")
    if (!is.character(value$contract_json) || length(value$contract_json) != 1L ||
        is.na(value$contract_json) ||
        nchar(value$contract_json, type = "bytes") < 2L ||
        nchar(value$contract_json, type = "bytes") >
          .DSVERT_FORMAL_GLM_PUBLIC_RESULT_MAX_BYTES ||
        !is.character(value$resolution_json) ||
        length(value$resolution_json) != 1L || is.na(value$resolution_json) ||
        nchar(value$resolution_json, type = "bytes") < 2L ||
        nchar(value$resolution_json, type = "bytes") >
          .DSVERT_FORMAL_GLM_PUBLIC_RESULT_MAX_BYTES) {
      .dsvert_formal_glm_frontdoor_abort(
        "The requested formal GLM analysis is unavailable.",
        "invalid_formal_glm_registry")
    }
  }
  value$data_name <- .dsvert_formal_glm_frontdoor_label(
    value$data_name, "data selector")
  value$formula_sha256 <- .dsvert_formal_glm_frontdoor_sha256(
    value$formula_sha256, "formula selector")
  if (!all(vapply(names(value$pins), function(peer) {
    identical(.dsvert_formal_glm_frontdoor_label(peer, "pin peer"), peer)
  }, logical(1L)))) {
    .dsvert_formal_glm_frontdoor_abort(
      "The custodian formal GLM public-release registry is invalid.",
      "invalid_formal_glm_registry")
  }
  value
}

.dsvert_formal_glm_public_result_response <- function(
    value, spec, analysis_id, data_name, family, formula_sha256) {
  fields <- c("version", "artifact_id", "certificate_sha256", "family",
              "formula_sha256", "coefficients", "production_ready")
  invalid <- !is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
    anyDuplicated(names(value)) || !setequal(names(value), fields) ||
    !identical(value$version, .DSVERT_FORMAL_GLM_PUBLIC_RESULT_RESPONSE_VERSION) ||
    !identical(value$family, family) ||
    !identical(value$formula_sha256, formula_sha256) ||
    !identical(value$production_ready, FALSE) ||
    !is.character(value$artifact_id) || length(value$artifact_id) != 1L ||
    !is.character(value$certificate_sha256) ||
    length(value$certificate_sha256) != 1L ||
    !is.list(value$coefficients) || !length(value$coefficients)
  if (isTRUE(invalid)) {
    .dsvert_formal_glm_frontdoor_abort(
      "The requested formal GLM public release is invalid.",
      "invalid_formal_glm_public_release")
  }
  artifact_id <- .dsvert_formal_glm_frontdoor_sha256(
    value$artifact_id, "public artifact")
  certificate_sha256 <- .dsvert_formal_glm_frontdoor_sha256(
    value$certificate_sha256, "public certificate")
  coefficients <- lapply(value$coefficients, function(coefficient) {
    coefficient_fields <- c(
      "coefficient", "signed_steps", "output_lattice_bits", "value")
    if (!is.list(coefficient) || is.null(names(coefficient)) ||
        anyNA(names(coefficient)) || anyDuplicated(names(coefficient)) ||
        !setequal(names(coefficient), coefficient_fields) ||
        !is.character(coefficient$coefficient) ||
        length(coefficient$coefficient) != 1L || is.na(coefficient$coefficient) ||
        !nzchar(coefficient$coefficient) ||
        nchar(coefficient$coefficient, type = "bytes") > 1024L ||
        !is.character(coefficient$signed_steps) ||
        length(coefficient$signed_steps) != 1L || is.na(coefficient$signed_steps) ||
        !grepl("^(0|-[1-9][0-9]*|[1-9][0-9]*)$", coefficient$signed_steps) ||
        !is.numeric(coefficient$output_lattice_bits) ||
        length(coefficient$output_lattice_bits) != 1L ||
        is.na(coefficient$output_lattice_bits) ||
        !is.finite(coefficient$output_lattice_bits) ||
        coefficient$output_lattice_bits < 0 ||
        coefficient$output_lattice_bits > 127 ||
        coefficient$output_lattice_bits != floor(coefficient$output_lattice_bits) ||
        !is.numeric(coefficient$value) || length(coefficient$value) != 1L ||
        is.na(coefficient$value) || !is.finite(coefficient$value)) {
      .dsvert_formal_glm_frontdoor_abort(
        "The requested formal GLM public release is invalid.",
        "invalid_formal_glm_public_release")
    }
    list(
      coefficient = enc2utf8(coefficient$coefficient),
      signed_steps = coefficient$signed_steps,
      output_lattice_bits = as.integer(coefficient$output_lattice_bits),
      value = as.numeric(coefficient$value))
  })
  names(coefficients) <- NULL
  coefficient_names <- vapply(coefficients, `[[`, character(1L), "coefficient")
  if (anyDuplicated(coefficient_names) ||
      !identical(data_name, spec$data_name) ||
      !identical(family, spec$family) ||
      !identical(formula_sha256, spec$formula_sha256)) {
    .dsvert_formal_glm_frontdoor_abort(
      "The requested formal GLM analysis is unavailable.",
      "invalid_formal_glm_selector")
  }
  list(
    version = value$version, analysis_id = analysis_id,
    artifact_id = artifact_id, certificate_sha256 = certificate_sha256,
    family = family, formula_sha256 = formula_sha256,
    coefficients = coefficients, production_ready = FALSE)
}

dsvertFormalGLMPublicResultDS <- function(
    analysis_id, data_name, family, formula_sha256) {
  spec <- .dsvert_formal_glm_public_result_spec(analysis_id)
  data_name <- .dsvert_formal_glm_frontdoor_label(data_name, "data selector")
  formula_sha256 <- .dsvert_formal_glm_frontdoor_sha256(
    formula_sha256, "formula selector")
  if (!is.character(family) || length(family) != 1L || is.na(family) ||
      !family %in% c("binomial", "poisson")) {
    .dsvert_formal_glm_frontdoor_abort(
      "The requested formal GLM analysis is unavailable.",
      "invalid_formal_glm_selector")
  }
  if (!identical(data_name, spec$data_name) ||
      !identical(family, spec$family) ||
      !identical(formula_sha256, spec$formula_sha256)) {
    .dsvert_formal_glm_frontdoor_abort()
  }
  command <- if (identical(
    spec$version, .DSVERT_FORMAL_GLM_PHASE21_PUBLIC_TERMINAL_SPEC_VERSION)) {
    "formal-glm-phase21-public-terminal"
  } else {
    "formal-glm-public-result"
  }
  payload <- if (identical(
    spec$version, .DSVERT_FORMAL_GLM_PHASE21_PUBLIC_TERMINAL_SPEC_VERSION)) {
    list(authority_peer = spec$authority_peer, contract_json = spec$contract_json,
         resolution_json = spec$resolution_json, pins = spec$pins)
  } else {
    list(certificate_json = spec$certificate_json, pins = spec$pins)
  }
  decoded <- tryCatch(
    .callMpcTool(command, payload, simplify_output = FALSE),
    error = function(error) NULL)
  if (is.null(decoded)) {
    .dsvert_formal_glm_frontdoor_abort(
      "The requested formal GLM public release is unavailable.",
      "formal_glm_public_release_unavailable")
  }
  .dsvert_formal_glm_public_result_response(
    decoded, spec, analysis_id, data_name, family, formula_sha256)
}
