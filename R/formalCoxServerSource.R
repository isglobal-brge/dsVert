# Private server-owned source resolver for the formal Cox capsule.
#
# This is deliberately not a DataSHIELD entry point.  The signed schema names
# the logical owners, while the server configuration fixes the only local
# protected snapshot and column projection that may feed the encrypted Go
# producer.  Callers cannot supply a data frame, table name, peer name, column
# map, or physical block size.

.DSVERT_FORMAL_COX_SOURCE_SPECS_OPTION <-
  "dsvert.formal_cox.source_specs"
.DSVERT_FORMAL_COX_SOURCE_CONTEXT_CLASS <-
  "dsvert_formal_cox_server_source_context"

.dsvert_formal_cox_server_source_descriptor <- function(value) {
  fields <- c(
    "id", "version", "snapshot_sha256", "alignment_manifest_hash",
    "alignment_manifest_version")
  if (!is.list(value) || !identical(names(value), fields)) {
    .dsvert_formal_cox_abort("The configured Cox source dataset is invalid.")
  }
  value$id <- .dsvert_formal_cox_label(value$id, "Cox source dataset id")
  value$version <- .dsvert_formal_cox_label(
    value$version, "Cox source dataset version")
  value$snapshot_sha256 <- .dsvert_formal_cox_sha256(
    value$snapshot_sha256, "Cox source snapshot digest")
  value$alignment_manifest_hash <- .dsvert_formal_cox_sha256(
    value$alignment_manifest_hash, "Cox source alignment digest")
  value$alignment_manifest_version <- as.integer(
    .dsvert_formal_cox_integer(
      value$alignment_manifest_version,
      "Cox source alignment manifest version", 1L, 2^31 - 1L))
  value
}

.dsvert_formal_cox_server_source_required_columns <- function(schema, source) {
  required <- "valid"
  if (identical(source, schema$unsigned$outcome_owner)) {
    required <- c(
      required,
      if (identical(schema$unsigned$entry_mode, "single_interval")) {
        "entry_tick"
      },
      "stop_tick", "status")
  }
  owners <- unlist(schema$unsigned$covariate_owners, use.names = TRUE)
  c(required, names(owners)[owners == source])
}

.dsvert_formal_cox_server_source_specs <- function() {
  specs <- getOption(.DSVERT_FORMAL_COX_SOURCE_SPECS_OPTION)
  if (!is.list(specs) || !length(specs) || is.null(names(specs)) ||
      anyNA(names(specs)) || any(!nzchar(names(specs))) ||
      anyDuplicated(names(specs))) {
    .dsvert_formal_cox_abort(
      "The server has no unambiguous formal Cox source configuration.")
  }
  names(specs) <- vapply(
    names(specs), .dsvert_formal_cox_label, character(1L),
    what = "configured Cox source name")
  if (anyDuplicated(names(specs))) {
    .dsvert_formal_cox_abort(
      "The server has ambiguous formal Cox source configuration.")
  }
  specs
}

.dsvert_formal_cox_server_source_spec <- function(schema, source) {
  fields <- c(
    "source_name", "schema_sha256", "logical_snapshot_id", "dataset",
    "data_name", "patient_column", "block_capacity", "columns")
  spec <- .dsvert_formal_cox_server_source_specs()[[source]]
  if (!is.list(spec) || !identical(names(spec), fields)) {
    .dsvert_formal_cox_abort("The configured formal Cox source is invalid.")
  }
  spec$source_name <- .dsvert_formal_cox_label(
    spec$source_name, "configured Cox source name")
  spec$schema_sha256 <- .dsvert_formal_cox_sha256(
    spec$schema_sha256, "configured Cox schema digest")
  spec$logical_snapshot_id <- .dsvert_formal_cox_label(
    spec$logical_snapshot_id, "configured Cox logical snapshot")
  spec$dataset <- .dsvert_formal_cox_server_source_descriptor(spec$dataset)
  spec$data_name <- .dsvert_formal_cox_label(
    spec$data_name, "configured Cox data name")
  spec$patient_column <- .dsvert_formal_cox_label(
    spec$patient_column, "configured Cox patient column")
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  spec$block_capacity <- .dsvert_formal_cox_integer(
    spec$block_capacity, "configured Cox block capacity", 1L,
    numeric$capacity)
  if (!is.list(spec$columns) || is.null(names(spec$columns)) ||
      anyNA(names(spec$columns)) || any(!nzchar(names(spec$columns))) ||
      anyDuplicated(names(spec$columns))) {
    .dsvert_formal_cox_abort("The configured Cox column map is invalid.")
  }
  names(spec$columns) <- vapply(
    names(spec$columns), .dsvert_formal_cox_label, character(1L),
    what = "configured Cox field")
  mapped <- vapply(
    spec$columns, .dsvert_formal_cox_label, character(1L),
    what = "configured Cox column")
  required <- .dsvert_formal_cox_server_source_required_columns(schema, source)
  if (!identical(spec$source_name, source) ||
      !identical(spec$schema_sha256, schema$schema_sha256) ||
      !identical(spec$logical_snapshot_id,
                 schema$unsigned$logical_snapshot_id) ||
      !identical(names(mapped), required) || anyDuplicated(mapped) ||
      spec$patient_column %in% unname(mapped)) {
    .dsvert_formal_cox_abort(
      "The configured Cox source does not match the signed schema.")
  }
  spec$columns <- unname(mapped)
  names(spec$columns) <- required
  spec
}

.dsvert_formal_cox_server_source_snapshot <- function(
    schema, spec, source_environment) {
  if (!is.environment(source_environment)) {
    .dsvert_formal_cox_abort("The configured Cox source environment is invalid.")
  }
  environment <- tryCatch(
    .dsvert_dp_binding_environment(spec$data_name, source_environment),
    error = function(error) NULL)
  if (is.null(environment) ||
      bindingIsActive(spec$data_name, environment) ||
      !bindingIsLocked(spec$data_name, environment)) {
    .dsvert_formal_cox_abort(
      "The configured Cox snapshot must be an immutable server binding.")
  }
  data <- tryCatch(
    get(spec$data_name, envir = environment, inherits = FALSE),
    error = function(error) NULL)
  if (!is.data.frame(data)) {
    .dsvert_formal_cox_abort("The configured Cox snapshot is unavailable.")
  }
  snapshot_sha256 <- .dsvert_dp_snapshot_digest(data)
  if (!identical(snapshot_sha256, spec$dataset$snapshot_sha256)) {
    .dsvert_formal_cox_abort("The configured Cox snapshot has changed.")
  }
  data <- tryCatch(
    .dsvert_dp_freeze_snapshot_frame(data), error = function(error) NULL)
  if (is.null(data) ||
      !identical(.dsvert_dp_snapshot_digest(data), snapshot_sha256)) {
    .dsvert_formal_cox_abort("The configured Cox snapshot is inconsistent.")
  }
  aligned <- tryCatch({
    .dsvert_dp_validate_descriptor_alignment(
      data, spec$dataset, patient_column = spec$patient_column,
      expected_pinset = schema$unsigned$peer_pinset,
      snapshot_sha256 = snapshot_sha256)
    .dsvert_dp_padded_alignment_binding(
      data, snapshot_sha256 = snapshot_sha256)
  }, error = function(error) NULL)
  if (is.null(aligned) || !identical(aligned$descriptor, spec$dataset)) {
    .dsvert_formal_cox_abort(
      "The configured Cox snapshot is not the pinned PSI-aligned dataset.")
  }
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  if (nrow(data) != numeric$capacity ||
      !all(c(spec$patient_column, unname(spec$columns)) %in% names(data))) {
    .dsvert_formal_cox_abort(
      "The configured Cox snapshot does not have the signed physical shape.")
  }
  rows <- data[, unname(spec$columns), drop = FALSE]
  names(rows) <- names(spec$columns)
  rows
}

.dsvert_formal_cox_server_source_context <- function(value) {
  fields <- c("schema", "source_name", "rows", "block_capacity")
  if (!is.environment(value) ||
      !inherits(value, .DSVERT_FORMAL_COX_SOURCE_CONTEXT_CLASS) ||
      !identical(sort(ls(value, all.names = TRUE)), sort(fields)) ||
      !is.data.frame(value$rows)) {
    .dsvert_formal_cox_abort("The private Cox source context is invalid.")
  }
  .dsvert_formal_cox_schema_validate(value$schema)
  value
}

# Opens one configured source once.  Its context is an environment so it is
# neither a wire DTO nor JSON-serialisable; callers can request only bounded,
# canonical local decimal lanes through the block function below.
.dsvert_formal_cox_server_source_open <- function(
    schema, source_environment = parent.frame()) {
  .dsvert_formal_cox_schema_validate(schema)
  source <- tryCatch(
    .dsvert_require_configured_local_peer_name(), error = function(error) NULL)
  if (is.null(source) || !source %in% names(schema$unsigned$peer_pinset)) {
    .dsvert_formal_cox_abort(
      "The configured local peer is outside the signed Cox consortium.")
  }
  spec <- .dsvert_formal_cox_server_source_spec(schema, source)
  context <- new.env(parent = emptyenv())
  context$schema <- schema
  context$source_name <- source
  context$rows <- .dsvert_formal_cox_server_source_snapshot(
    schema, spec, source_environment)
  context$block_capacity <- spec$block_capacity
  class(context) <- .DSVERT_FORMAL_COX_SOURCE_CONTEXT_CLASS
  context
}

.dsvert_formal_cox_server_source_block <- function(context, block_index) {
  context <- .dsvert_formal_cox_server_source_context(context)
  .dsvert_formal_cox_source_block_decimal_lines(
    context$schema, context$source_name, context$rows, block_index,
    context$block_capacity)
}
