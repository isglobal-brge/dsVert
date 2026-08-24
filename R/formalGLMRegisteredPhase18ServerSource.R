# Private Rock-local source resolver for the registered formal-GLM ingress.
#
# This is intentionally not a DataSHIELD entry point.  The K-signed source
# contract chooses a source binding; the server-owned specification chooses the
# only immutable local snapshot that may satisfy it.  The resulting environment
# is a private carrier for the later encrypted block producer, never a wire
# value or an analyst-selectable data source.

.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_SPECS_OPTION <-
  "dsvert.formal_glm.registered_source_specs"
.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_CONTEXT_CLASS <-
  "dsvert_formal_glm_registered_source_context"
.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_PROJECT_VERSION <-
  "dsvert-formal-glm-phase18-source-project-response-v1"
.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_PRIVATE_CARRIER <-
  "rock_local_nonserialized_materializer_inputs_required_v1"

.dsvert_formal_glm_registered_source_abort <- function(message) {
  stop(structure(
    list(message = message, call = NULL, openings_performed = 0L),
    class = c("dsvert_formal_glm_registered_source_error", "error",
              "condition")))
}

.dsvert_formal_glm_registered_source_label <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", value)) {
    .dsvert_formal_glm_registered_source_abort(
      paste0("Invalid configured formal-GLM ", what, "."))
  }
  enc2utf8(value)
}

.dsvert_formal_glm_registered_source_sha256 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_glm_registered_source_abort(
      paste0("Invalid configured formal-GLM ", what, "."))
  }
  value
}

.dsvert_formal_glm_registered_source_specs <- function() {
  specs <- getOption(.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_SPECS_OPTION)
  if (!is.list(specs) || !length(specs) || is.null(names(specs)) ||
      anyNA(names(specs)) || any(!nzchar(names(specs))) ||
      anyDuplicated(names(specs))) {
    .dsvert_formal_glm_registered_source_abort(
      "The server has no unambiguous registered formal-GLM source configuration.")
  }
  names(specs) <- vapply(
    names(specs), .dsvert_formal_glm_registered_source_label,
    character(1L), what = "source name")
  if (anyDuplicated(names(specs))) {
    .dsvert_formal_glm_registered_source_abort(
      "The server has ambiguous registered formal-GLM source configuration.")
  }
  specs
}

.dsvert_formal_glm_registered_source_descriptor <- function(value) {
  fields <- c(
    "id", "version", "snapshot_sha256", "alignment_manifest_hash",
    "alignment_manifest_version")
  if (!is.list(value) || !identical(names(value), fields)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM source dataset is invalid.")
  }
  value$id <- .dsvert_formal_glm_registered_source_label(value$id, "dataset id")
  value$version <- .dsvert_formal_glm_registered_source_label(
    value$version, "dataset version")
  value$snapshot_sha256 <- .dsvert_formal_glm_registered_source_sha256(
    value$snapshot_sha256, "snapshot digest")
  value$alignment_manifest_hash <- .dsvert_formal_glm_registered_source_sha256(
    value$alignment_manifest_hash, "alignment digest")
  version <- suppressWarnings(as.integer(value$alignment_manifest_version))
  if (length(version) != 1L || is.na(version) || version < 1L) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM alignment version is invalid.")
  }
  value$alignment_manifest_version <- version
  value
}

.dsvert_formal_glm_registered_source_pins <- function(value) {
  if (!is.list(value) || length(value) < 2L || is.null(names(value)) ||
      anyNA(names(value)) || any(!nzchar(names(value))) ||
      anyDuplicated(names(value))) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM peer pinset is invalid.")
  }
  names(value) <- vapply(
    names(value), .dsvert_formal_glm_registered_source_label,
    character(1L), what = "pinned peer")
  pins <- vapply(value, function(pin) {
    if (!is.character(pin) || length(pin) != 1L || is.na(pin)) return(NA_character_)
    raw <- tryCatch(jsonlite::base64_dec(pin), error = function(error) raw())
    valid <- is.raw(raw) && length(raw) == 32L && identical(
      gsub("[\r\n]", "", jsonlite::base64_enc(raw)), pin)
    if (is.raw(raw) && length(raw)) raw[] <- as.raw(0L)
    if (!valid) return(NA_character_)
    pin
  }, character(1L), USE.NAMES = TRUE)
  if (anyNA(pins) || anyDuplicated(names(pins))) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM peer pinset is invalid.")
  }
  as.list(pins)
}

.dsvert_formal_glm_registered_source_b64url <- function(value) {
  sub("=+$", "", chartr("+/", "-_", value), perl = TRUE)
}

.dsvert_formal_glm_registered_source_spec <- function(source) {
  fields <- c(
    "source_name", "source_contract_sha256", "authorization_sha256",
    "logical_snapshot_sha256", "pins", "dataset", "data_name",
    "patient_column", "columns")
  spec <- .dsvert_formal_glm_registered_source_specs()[[source]]
  if (!is.list(spec) || !identical(names(spec), fields)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured registered formal-GLM source is invalid.")
  }
  spec$source_name <- .dsvert_formal_glm_registered_source_label(
    spec$source_name, "source name")
  spec$source_contract_sha256 <- .dsvert_formal_glm_registered_source_sha256(
    spec$source_contract_sha256, "source-contract digest")
  spec$authorization_sha256 <- .dsvert_formal_glm_registered_source_sha256(
    spec$authorization_sha256, "authorization digest")
  spec$logical_snapshot_sha256 <- .dsvert_formal_glm_registered_source_sha256(
    spec$logical_snapshot_sha256, "logical-snapshot digest")
  spec$pins <- .dsvert_formal_glm_registered_source_pins(spec$pins)
  spec$dataset <- .dsvert_formal_glm_registered_source_descriptor(spec$dataset)
  spec$data_name <- .dsvert_formal_glm_registered_source_label(
    spec$data_name, "data binding")
  spec$patient_column <- .dsvert_formal_glm_registered_source_label(
    spec$patient_column, "patient column")
  if (!is.list(spec$columns) || !length(spec$columns) ||
      is.null(names(spec$columns)) || anyNA(names(spec$columns)) ||
      any(!nzchar(names(spec$columns))) || anyDuplicated(names(spec$columns))) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM column map is invalid.")
  }
  names(spec$columns) <- vapply(
    names(spec$columns), .dsvert_formal_glm_registered_source_label,
    character(1L), what = "source column")
  spec$columns <- stats::setNames(vapply(
    spec$columns, .dsvert_formal_glm_registered_source_label,
    character(1L), what = "physical column"), names(spec$columns))
  if (!identical(spec$source_name, source) ||
      anyDuplicated(unname(spec$columns)) ||
      spec$patient_column %in% unname(spec$columns) ||
      !source %in% names(spec$pins)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM source does not match its local peer.")
  }
  spec
}

.dsvert_formal_glm_registered_source_project <- function(
    source_contract_json, spec, source) {
  if (!is.character(source_contract_json) || length(source_contract_json) != 1L ||
      is.na(source_contract_json) || !nzchar(source_contract_json) ||
      nchar(source_contract_json, type = "bytes") > 32L * 1024L^2) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM source contract is invalid.")
  }
  response <- tryCatch(.callMpcTool("formal-glm-phase18-source-project", list(
    source_contract_json = source_contract_json, pins = spec$pins,
    local_peer_name = source)), error = function(error) NULL)
  fields <- c("version", "authorization_json", "authorization_sha256")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version, .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_PROJECT_VERSION) ||
      !is.character(response$authorization_json) ||
      length(response$authorization_json) != 1L ||
      !is.character(response$authorization_sha256) ||
      length(response$authorization_sha256) != 1L ||
      !identical(response$authorization_sha256, spec$authorization_sha256)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM source projection is invalid.")
  }
  authorization <- tryCatch(jsonlite::fromJSON(
    response$authorization_json, simplifyVector = FALSE),
    error = function(error) NULL)
  if (!is.list(authorization)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM authorization is invalid.")
  }
  list(json = response$authorization_json, value = authorization)
}

.dsvert_formal_glm_registered_source_authorization <- function(
    projected, spec, source) {
  authorization <- projected$value
  source_record <- authorization$local_source
  columns <- authorization$local_columns
  geometry <- authorization$geometry
  if (!identical(authorization$authorization_sha256,
                 spec$authorization_sha256) ||
      !identical(authorization$source_contract_sha256,
                 spec$source_contract_sha256) ||
      !identical(authorization$logical_snapshot_sha256,
                 spec$logical_snapshot_sha256) ||
      !identical(authorization$private_carrier_requirement,
                 .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_PRIVATE_CARRIER) ||
      !identical(authorization$openings_performed, 0L) ||
      !identical(authorization$production_ready, FALSE) ||
      !is.list(source_record) ||
      !identical(source_record$signer_peer_name, source) ||
      !identical(source_record$dataset_id, spec$dataset$id) ||
      !identical(source_record$dataset_version, spec$dataset$version) ||
      !is.list(columns) || !length(columns) || !is.list(geometry) ||
      length(geometry$total_capacity) != 1L ||
      is.na(suppressWarnings(as.integer(geometry$total_capacity))) ||
      as.integer(geometry$total_capacity) < 1L) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM authorization does not match its source.")
  }
  identity <- authorization$local_peer_identity
  if (!is.list(identity) || !identical(identity$peer_name, source) ||
      !identical(identity$identity_pk,
                 .dsvert_formal_glm_registered_source_b64url(
                   spec$pins[[source]]))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM authorization has the wrong source identity.")
  }
  logical_columns <- vapply(columns, function(column) {
    if (!is.list(column) || !identical(column$owner, source) ||
        !identical(column$dataset_id, spec$dataset$id) ||
        !identical(column$dataset_version, spec$dataset$version) ||
        !is.character(column$column) || length(column$column) != 1L ||
        is.na(column$column)) return(NA_character_)
    column$column
  }, character(1L))
  if (anyNA(logical_columns) || anyDuplicated(logical_columns) ||
      !identical(logical_columns, names(spec$columns))) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM column map differs from the authorization.")
  }
  as.integer(geometry$total_capacity)
}

.dsvert_formal_glm_registered_source_snapshot <- function(
    spec, expected_rows, source_environment) {
  if (!is.environment(source_environment)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM source environment is invalid.")
  }
  environment <- tryCatch(
    .dsvert_dp_binding_environment(spec$data_name, source_environment),
    error = function(error) NULL)
  if (is.null(environment) || bindingIsActive(spec$data_name, environment) ||
      !bindingIsLocked(spec$data_name, environment)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM snapshot must be immutable.")
  }
  data <- tryCatch(get(spec$data_name, envir = environment, inherits = FALSE),
                   error = function(error) NULL)
  if (!is.data.frame(data)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM snapshot is unavailable.")
  }
  digest <- .dsvert_dp_snapshot_digest(data)
  if (!identical(digest, spec$dataset$snapshot_sha256)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM snapshot has changed.")
  }
  data <- tryCatch(.dsvert_dp_freeze_snapshot_frame(data),
                   error = function(error) NULL)
  aligned <- tryCatch({
    .dsvert_dp_validate_descriptor_alignment(
      data, spec$dataset, patient_column = spec$patient_column,
      expected_pinset = unlist(spec$pins, use.names = TRUE),
      snapshot_sha256 = digest)
    .dsvert_dp_padded_alignment_binding(data, snapshot_sha256 = digest)
  }, error = function(error) NULL)
  if (is.null(data) || is.null(aligned) ||
      !identical(aligned$descriptor, spec$dataset) || nrow(data) != expected_rows ||
      !all(c(spec$patient_column, unname(spec$columns)) %in% names(data))) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM snapshot is not the pinned PSI source.")
  }
  rows <- data[, unname(spec$columns), drop = FALSE]
  names(rows) <- names(spec$columns)
  rows
}

# Opens one configured registered source.  The resulting environment is kept
# deliberately non-serializable and contains only the authenticated public
# authorization plus the frozen private rows needed by the block producer.
.dsvert_formal_glm_registered_source_open <- function(
    source_contract_json, source_environment = parent.frame()) {
  source <- tryCatch(.dsvert_require_configured_local_peer_name(),
                     error = function(error) NULL)
  if (is.null(source)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured local peer is unavailable for formal-GLM source work.")
  }
  source <- .dsvert_formal_glm_registered_source_label(source, "local peer")
  spec <- .dsvert_formal_glm_registered_source_spec(source)
  identity <- tryCatch(.get_identity_keypair(), error = function(error) NULL)
  if (!is.list(identity) || !identical(names(identity),
                                       c("identity_pk", "identity_sk")) ||
      !is.character(identity$identity_pk) ||
      length(identity$identity_pk) != 1L ||
      !identical(identity$identity_pk, spec$pins[[source]])) {
    .dsvert_formal_glm_registered_source_abort(
      "The local formal-GLM source identity does not match its pinned peer.")
  }
  projected <- .dsvert_formal_glm_registered_source_project(
    source_contract_json, spec, source)
  capacity <- .dsvert_formal_glm_registered_source_authorization(
    projected, spec, source)
  context <- new.env(parent = emptyenv())
  context$authorization <- projected$value
  context$authorization_json <- projected$json
  context$contract_json <- source_contract_json
  context$source_name <- source
  context$rows <- .dsvert_formal_glm_registered_source_snapshot(
    spec, capacity, source_environment)
  class(context) <- .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_CONTEXT_CLASS
  context
}
