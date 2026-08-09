# Internal policy and authenticated alignment helpers shared by the promoted
# fixed-capacity pinned PSI route and downstream aligned-data checks. The
# former variable-shape PSI remote protocol was deliberately removed.

.psi_option <- function(name, default = NULL) {
  value <- getOption(name)
  if (is.null(value)) value <- getOption(paste0("default.", name))
  if (is.null(value)) default else value
}

.psi_scalar_option <- function(name, default = NULL) {
  value <- .psi_option(name, default)
  if (is.null(value) || length(value) == 0L) return("")
  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    stop(name, " must be one non-missing character value", call. = FALSE)
  }
  value
}

.psi_bool_option <- function(name, default = FALSE) {
  .dsvert_security_boolean(.psi_option(name, default), name, default)
}

.psi_int_option <- function(name, default) {
  value <- .psi_option(name, default)
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) || value < 1 ||
      value > .Machine$integer.max) {
    stop(name, " must be one positive integer", call. = FALSE)
  }
  as.integer(value)
}

.psi_policy <- function(session_id) {
  key <- .psi_scalar_option("dsvert.psi.pseudonym_key", "")
  mode <- .psi_scalar_option("dsvert.psi.pseudonym_mode", "auto")
  if (!nzchar(mode) || identical(mode, "auto")) {
    mode <- if (nzchar(key)) "shared_key" else "none"
  }
  mode <- match.arg(mode, c("none", "shared_key", "threshold"))
  if (identical(mode, "threshold")) {
    stop(
      "PSI threshold-OPRF key custody is not implemented in this build. ",
      "Use dsvert.psi.pseudonym_mode='shared_key' with pinned peers, or ",
      "disable the threshold policy for this profile.", call. = FALSE)
  }
  if (.psi_bool_option("dsvert.psi.require_keyed_pseudonyms", FALSE) &&
      identical(mode, "none")) {
    stop("PSI keyed pseudonymisation is required by server policy.",
         call. = FALSE)
  }
  if (identical(mode, "shared_key") && !nzchar(key)) {
    stop("PSI pseudonym_mode='shared_key' requires dsvert.psi.pseudonym_key.",
         call. = FALSE)
  }
  study_id <- .psi_scalar_option("dsvert.psi.study_id", "")
  if (!nzchar(study_id)) study_id <- session_id
  key_custody <- .psi_scalar_option("dsvert.psi.key_custody", "")
  if (!nzchar(key_custody)) {
    key_custody <- if (identical(mode, "shared_key")) "shared_key" else "none"
  }
  if (!identical(mode, "shared_key")) key_custody <- "none"
  key_id <- if (identical(mode, "shared_key")) {
    digest::hmac(
      key, paste0("dsVert-PSI-key-id-v1|", study_id), algo = "sha256")
  } else {
    ""
  }
  list(
    pseudonym_mode = mode,
    pseudonym_key = key,
    key_custody = key_custody,
    study_id = study_id,
    study_id_hash = digest::digest(study_id, algo = "sha256"),
    key_id = key_id,
    max_input_ids = .psi_int_option("dsvert.psi.max_input_ids", 1000000L))
}

.psi_public_policy <- function(policy) {
  list(
    pseudonym_mode = policy$pseudonym_mode,
    key_custody = policy$key_custody,
    study_id_hash = policy$study_id_hash,
    key_id = policy$key_id,
    max_input_ids = policy$max_input_ids)
}

.psi_valid_id_rows <- function(ids) {
  which(!is.na(ids) & nzchar(ids))
}

.psi_analysis_rows <- function(
    data, id_col, na_action = c("na.omit", "na.fail", "none")) {
  if (!is.data.frame(data) || !is.character(id_col) || length(id_col) != 1L ||
      is.na(id_col) || !id_col %in% names(data)) {
    stop("Invalid PSI data or identifier column", call. = FALSE)
  }
  if (!is.character(na_action) || length(na_action) != 1L ||
      is.na(na_action) || !na_action %in% c("na.omit", "na.fail", "none")) {
    stop("na_action must be one of 'na.omit', 'na.fail' or 'none'",
         call. = FALSE)
  }
  ids <- .dsvert_canonical_label_values(
    data[[id_col]], "PSI identifiers", allow_na = TRUE, allow_blank = TRUE)
  valid_id <- !is.na(ids) & nzchar(ids)
  if (identical(na_action, "na.fail")) {
    if (any(!stats::complete.cases(data))) {
      stop("PSI na.fail: missing values are present in the input data",
           call. = FALSE)
    }
    if (any(!valid_id)) {
      stop("PSI na.fail: missing identifiers are present", call. = FALSE)
    }
    rows <- seq_len(nrow(data))
  } else if (identical(na_action, "na.omit")) {
    rows <- which(stats::complete.cases(data) & valid_id)
  } else {
    rows <- which(valid_id)
  }
  if (anyDuplicated(ids[rows])) {
    stop("PSI identifiers must be unique within each server", call. = FALSE)
  }
  as.integer(rows)
}

.PSI_ALIGNMENT_ATTRIBUTE <- "dsvert.psi.alignment"
.PSI_ALIGNMENT_VERSION <- 2L

.psi_validate_alignment_token <- function(token) {
  if (!is.character(token) || length(token) != 1L || is.na(token) ||
      !grepl("^[A-Za-z0-9_-]{43}$", token)) {
    stop("Invalid PSI alignment token", call. = FALSE)
  }
  decoded <- tryCatch(
    jsonlite::base64_dec(.base64url_to_base64(token)),
    error = function(e) raw(0L))
  if (!is.raw(decoded) || length(decoded) != 32L) {
    stop("Invalid PSI alignment token", call. = FALSE)
  }
  invisible(TRUE)
}

.psi_alignment_order_binding <- function(ids, token) {
  .psi_validate_alignment_token(token)
  ids <- .dsvert_canonical_label_values(
    ids, "PSI alignment identifiers", allow_na = FALSE, allow_blank = FALSE)
  if (anyNA(ids) || any(!nzchar(ids)) || anyDuplicated(ids)) {
    stop("PSI alignment identifiers must be present and unique",
         call. = FALSE)
  }
  digest::hmac(
    token, serialize(ids, connection = NULL, ascii = FALSE, version = 3L),
    algo = "sha256", serialize = FALSE)
}

.psi_alignment_public_hash <- function(token, order_binding) {
  .psi_validate_alignment_token(token)
  if (!is.character(order_binding) || length(order_binding) != 1L ||
      is.na(order_binding) || !grepl("^[0-9a-f]{64}$", order_binding)) {
    stop("Invalid PSI alignment order binding", call. = FALSE)
  }
  digest::hmac(
    token, paste0("dsVert-PSI-alignment-manifest-v2|", order_binding),
    algo = "sha256", serialize = FALSE)
}

.psi_attach_alignment_manifest <- function(data, id_col, token) {
  if (!is.data.frame(data) || !is.character(id_col) || length(id_col) != 1L ||
      is.na(id_col) || !id_col %in% names(data)) {
    stop("Cannot attach PSI alignment manifest", call. = FALSE)
  }
  order_binding <- .psi_alignment_order_binding(data[[id_col]], token)
  attr(data, .PSI_ALIGNMENT_ATTRIBUTE) <- list(
    version = .PSI_ALIGNMENT_VERSION,
    token = token,
    id_col = id_col,
    n = as.integer(nrow(data)),
    order_binding = order_binding,
    hash = .psi_alignment_public_hash(token, order_binding))
  data
}

.psi_validate_alignment_manifest <- function(data) {
  if (!is.data.frame(data)) {
    stop("Object is not a PSI-aligned data frame", call. = FALSE)
  }
  manifest <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  required <- c("version", "token", "id_col", "n", "order_binding", "hash")
  version <- if (is.list(manifest) && length(manifest$version) == 1L) {
    tryCatch(suppressWarnings(as.numeric(manifest$version)),
             error = function(e) NA_real_)
  } else {
    NA_real_
  }
  if (!is.list(manifest) || length(manifest) != length(required) ||
      !setequal(names(manifest), required) || is.na(version) ||
      !is.finite(version) || version != .PSI_ALIGNMENT_VERSION ||
      !is.character(manifest$id_col) || length(manifest$id_col) != 1L ||
      is.na(manifest$id_col) || !manifest$id_col %in% names(data)) {
    stop("Object is not PSI-aligned: a valid manifest is absent",
         call. = FALSE)
  }
  .psi_validate_alignment_token(manifest$token)
  manifest_n <- tryCatch(suppressWarnings(as.numeric(manifest$n)),
                         error = function(e) NA_real_)
  if (length(manifest_n) != 1L || is.na(manifest_n) ||
      !is.finite(manifest_n) || manifest_n != nrow(data) ||
      manifest_n != as.integer(manifest_n)) {
    stop("PSI alignment manifest row count does not match the data",
         call. = FALSE)
  }
  expected_binding <- .psi_alignment_order_binding(
    data[[manifest$id_col]], manifest$token)
  if (!is.character(manifest$order_binding) ||
      length(manifest$order_binding) != 1L ||
      !identical(manifest$order_binding, expected_binding)) {
    stop("PSI alignment manifest is not bound to the current row order",
         call. = FALSE)
  }
  expected_hash <- .psi_alignment_public_hash(manifest$token, expected_binding)
  if (!is.character(manifest$hash) || length(manifest$hash) != 1L ||
      !identical(manifest$hash, expected_hash)) {
    stop("PSI alignment manifest authentication failed", call. = FALSE)
  }
  list(
    version = .PSI_ALIGNMENT_VERSION,
    hash = expected_hash,
    n = as.integer(nrow(data)),
    id_col = manifest$id_col)
}

.psi_text_to_b64 <- function(text) {
  if (!is.character(text) || length(text) != 1L) {
    stop("PSI payload must be a single character string", call. = FALSE)
  }
  jsonlite::base64_enc(charToRaw(text))
}

.psi_b64_to_text <- function(data_b64) {
  rawToChar(jsonlite::base64_dec(data_b64))
}
