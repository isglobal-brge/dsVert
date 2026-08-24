# Strict shared selectors for completed formal GLM and Cox public results.
#
# These helpers deliberately do not define a candidate analysis route, launch
# a worker, or create a release.  New formal-GLM execution is owned by the
# Rock-backed job lifecycle; completed results use these checks before they
# read a certificate.

.dsvert_formal_glm_frontdoor_abort <- function(
    message = "The requested formal GLM analysis is unavailable.",
    code = "formal_glm_analysis_unavailable") {
  stop(structure(list(
    message = message, call = NULL, code = code,
    openings_performed = 0L, production_ready = FALSE),
    class = c("dsvert_formal_glm_frontdoor_error", "error", "condition")))
}

.dsvert_formal_glm_frontdoor_label <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)) {
    .dsvert_formal_glm_frontdoor_abort(
      paste0("Invalid formal GLM ", what, "."),
      "invalid_formal_glm_selector")
  }
  enc2utf8(value)
}

.dsvert_formal_glm_frontdoor_sha256 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_glm_frontdoor_abort(
      paste0("Invalid formal GLM ", what, "."),
      "invalid_formal_glm_registry")
  }
  value
}

.dsvert_formal_glm_frontdoor_formula <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > 4096L) {
    .dsvert_formal_glm_frontdoor_abort(
      "Invalid formal GLM registry formula.",
      "invalid_formal_glm_registry")
  }
  formula <- tryCatch(stats::as.formula(value, env = baseenv()),
                      error = function(error) NULL)
  if (is.null(formula) || length(formula) != 3L ||
      !is.symbol(formula[[2L]]) ||
      "." %in% all.names(formula[[3L]], functions = FALSE)) {
    .dsvert_formal_glm_frontdoor_abort(
      "Invalid formal GLM registry formula.",
      "invalid_formal_glm_registry")
  }
  terms <- tryCatch(stats::terms(formula), error = function(error) NULL)
  labels <- if (is.null(terms)) NULL else attr(terms, "term.labels")
  orders <- if (is.null(terms)) NULL else attr(terms, "order")
  plain <- if (is.null(labels)) FALSE else vapply(labels, function(label) {
    expression <- tryCatch(parse(text = label, keep.source = FALSE),
                           error = function(error) NULL)
    length(expression) == 1L && is.symbol(expression[[1L]]) &&
      identical(as.character(expression[[1L]]), label) &&
      grepl("^[A-Za-z][A-Za-z0-9_.]{0,127}$", label)
  }, logical(1L))
  response <- as.character(formula[[2L]])
  if (is.null(terms) ||
      !grepl("^[A-Za-z][A-Za-z0-9_.]{0,127}$", response) ||
      any(!plain) || any(orders != 1L) || anyDuplicated(labels)) {
    .dsvert_formal_glm_frontdoor_abort(
      "Invalid formal GLM registry formula.",
      "invalid_formal_glm_registry")
  }
  predictors <- sort(enc2utf8(labels), method = "radix")
  intercept <- identical(as.integer(attr(terms, "intercept")), 1L)
  canonical <- paste(
    enc2utf8(response), "~",
    paste(c(if (intercept) "1" else "0", predictors), collapse = " + "))
  list(
    canonical = canonical,
    sha256 = digest::digest(
      paste0("dsVert/formal-glm/frontdoor-formula/v1|", canonical),
      algo = "sha256", serialize = FALSE))
}
