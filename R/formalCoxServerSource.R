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

.dsvert_formal_cox_server_source_require_private_rock <- function() {
  if (isTRUE(.dsvert_identity_test_mode())) return(invisible(NULL))
  root <- tryCatch(.dsvert_state_root(), error = function(error) NULL)
  if (!is.character(root) || length(root) != 1L || is.na(root) ||
      !nzchar(root) || !grepl("^/", path.expand(root))) {
    .dsvert_formal_cox_abort(
      "The formal Cox source bridge requires one private Rock root.")
  }
  root <- path.expand(root)
  .dsvert_dp_reject_ephemeral_or_library_path(root, "formal Cox Rock root")
  if (!dir.exists(root) && !dir.create(
      root, recursive = TRUE, showWarnings = FALSE, mode = "0700")) {
    .dsvert_formal_cox_abort(
      "The formal Cox source bridge could not create its private Rock root.")
  }
  if (.dsvert_dp_path_is_link(root)) {
    .dsvert_formal_cox_abort(
      "The formal Cox source bridge requires a non-symbolic private Rock root.")
  }
  Sys.chmod(root, mode = "0700")
  if (!.dsvert_dp_private_mode(root, directory = TRUE)) {
    .dsvert_formal_cox_abort(
      "The formal Cox source bridge requires an owner-only Rock root.")
  }
  root <- normalizePath(root, winslash = "/", mustWork = TRUE)
  .dsvert_dp_reject_ephemeral_or_library_path(root, "formal Cox Rock root")
  invisible(root)
}

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

.dsvert_formal_cox_server_source_command_input <- function(
    context, run_id, recipient_tickets, block_index) {
  .dsvert_formal_cox_server_source_require_private_rock()
  context <- .dsvert_formal_cox_server_source_context(context)
  run_id <- .dsvert_formal_cox_sha256(run_id, "Cox source run id")
  if (!identical(run_id, .dsvert_formal_cox_run_id(context$schema))) {
    .dsvert_formal_cox_abort(
      "The Cox source run id does not match the signed schema.")
  }
  numeric <- .dsvert_formal_cox_schema_numeric(context$schema)
  blocks <- as.integer(ceiling(numeric$capacity / context$block_capacity))
  block_index <- .dsvert_formal_cox_integer(
    block_index, "Cox source block index", 0L, blocks - 1L)
  if (!is.list(recipient_tickets) || length(recipient_tickets) != 2L ||
      !is.null(names(recipient_tickets))) {
    .dsvert_formal_cox_abort(
      "The formal Cox source recipient manifest is invalid.")
  }

  identity <- .get_identity_keypair()
  if (!is.list(identity) || !identical(names(identity),
                                       c("identity_pk", "identity_sk"))) {
    .dsvert_formal_cox_abort("The local Cox source identity is invalid.")
  }
  peer_pinset <- context$schema$unsigned$peer_pinset
  source_pin <- tryCatch(
    .dsvert_normalize_crypto_b64(
      .base64url_to_base64(peer_pinset[[context$source_name]]), 32L,
      "configured Cox source identity"), error = function(error) NULL)
  if (is.null(source_pin) || !identical(identity$identity_pk, source_pin)) {
    .dsvert_formal_cox_abort(
      "The local Cox source identity is not the signed source peer.")
  }
  pins <- vapply(peer_pinset[order(names(peer_pinset), method = "radix")],
                 function(value) {
    .dsvert_normalize_crypto_b64(
      .base64url_to_base64(value), 32L, "signed Cox peer identity")
  }, character(1L), USE.NAMES = TRUE)

  list(
    version = "dsvert-formal-cox-blockwise-source-producer-command-v1",
    schema = context$schema,
    block_capacity = context$block_capacity,
    run_id = run_id,
    pins = as.list(pins),
    recipient_tickets = recipient_tickets,
    source_peer_name = context$source_name,
    source_signing_key = identity$identity_sk,
    block_index = block_index)
}

# Server-internal R-to-Go bridge for one already-authorized source block. The
# two recipient tickets are opaque signed protocol records; this function
# neither creates them nor accepts a peer, path, data frame, key or block size
# from a DataSHIELD caller. Go validates their exact K=2 manifest before any
# durable ciphertext is committed.
.dsvert_formal_cox_server_source_produce_block <- function(
    context, run_id, recipient_tickets, block_index) {
  command <- .dsvert_formal_cox_server_source_command_input(
    context, run_id, recipient_tickets, block_index)
  context <- .dsvert_formal_cox_server_source_context(context)
  lines <- .dsvert_formal_cox_server_source_block(context, block_index)
  payload <- paste0(paste(lines, collapse = "\n"), "\n")
  command$canonical_input_base64 <- gsub(
      "[\r\n[:space:]]", "", jsonlite::base64_enc(charToRaw(payload)))
  response <- .callMpcTool("formal-cox-source-produce", command)
  fields <- c("receipt", "receipt_sha256", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !is.list(response$receipt) ||
      !is.character(response$receipt_sha256) ||
      length(response$receipt_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", response$receipt_sha256) ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_cox_abort("The formal Cox source producer returned invalid output.")
  }
  response
}

# Returns only the already-committed recipient-encrypted source envelope for
# one designated compute peer. It deliberately cannot accept a path, source
# rows or recipient key; import remains a separate recipient-owned step.
.dsvert_formal_cox_server_source_deliver_block <- function(
    context, run_id, recipient_tickets, block_index, recipient_peer_name) {
  command <- .dsvert_formal_cox_server_source_command_input(
    context, run_id, recipient_tickets, block_index)
  context <- .dsvert_formal_cox_server_source_context(context)
  recipient_peer_name <- .dsvert_formal_cox_label(
    recipient_peer_name, "Cox source delivery recipient")
  if (!recipient_peer_name %in%
      .dsvert_formal_cox_compute_peers(context$schema$unsigned$peer_pinset)) {
    .dsvert_formal_cox_abort(
      "The Cox source delivery recipient is not a designated compute peer.")
  }
  command$version <- "dsvert-formal-cox-blockwise-source-delivery-command-v1"
  command$recipient_peer_name <- recipient_peer_name
  response <- .callMpcTool("formal-cox-source-deliver", command)
  fields <- c(
    "version", "purpose", "receipt", "receipt_sha256",
    "recipient_peer_name", "envelope", "binding")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-cox-blockwise-source-delivery-v1") ||
      !identical(response$purpose,
                 "formal-cox-recipient-encrypted-source-delivery-v1") ||
      !is.list(response$receipt) ||
      !is.character(response$receipt_sha256) ||
      length(response$receipt_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", response$receipt_sha256) ||
      !identical(response$recipient_peer_name, recipient_peer_name) ||
      !is.list(response$envelope) || !length(response$envelope) ||
      !is.list(response$binding) || !length(response$binding)) {
    .dsvert_formal_cox_abort(
      "The formal Cox source delivery returned invalid output.")
  }
  response
}

# Builds the private command fields common to local Cox recipient ticket
# issuance and ingress. The identity secret remains in this server process and
# is passed only to the closed local MPC command; it never enters a DSI DTO.
.dsvert_formal_cox_server_source_recipient_command_input <- function(
    schema, block_capacity, run_id) {
  .dsvert_formal_cox_server_source_require_private_rock()
  .dsvert_formal_cox_schema_validate(schema)
  recipient <- tryCatch(
    .dsvert_require_configured_local_peer_name(), error = function(error) NULL)
  compute_peers <- .dsvert_formal_cox_compute_peers(
    schema$unsigned$peer_pinset)
  if (is.null(recipient) || !recipient %in% compute_peers) {
    .dsvert_formal_cox_abort(
      "The configured local peer is not a designated Cox recipient.")
  }
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  block_capacity <- as.integer(.dsvert_formal_cox_integer(
    block_capacity, "Cox recipient block capacity", 1L, numeric$capacity))
  run_id <- .dsvert_formal_cox_sha256(run_id, "Cox recipient run id")
  if (!identical(run_id, .dsvert_formal_cox_run_id(schema))) {
    .dsvert_formal_cox_abort(
      "The Cox recipient run id does not match the signed schema.")
  }
  identity <- .get_identity_keypair()
  if (!is.list(identity) || !identical(names(identity),
                                       c("identity_pk", "identity_sk"))) {
    .dsvert_formal_cox_abort("The local Cox recipient identity is invalid.")
  }
  peer_pinset <- schema$unsigned$peer_pinset
  recipient_pin <- tryCatch(
    .dsvert_normalize_crypto_b64(
      .base64url_to_base64(peer_pinset[[recipient]]), 32L,
      "configured Cox recipient identity"), error = function(error) NULL)
  if (is.null(recipient_pin) || !identical(identity$identity_pk, recipient_pin)) {
    .dsvert_formal_cox_abort(
      "The local Cox recipient identity is not the signed recipient peer.")
  }
  pins <- vapply(
    peer_pinset[order(names(peer_pinset), method = "radix")],
    function(value) {
      .dsvert_normalize_crypto_b64(
        .base64url_to_base64(value), 32L, "signed Cox peer identity")
    }, character(1L), USE.NAMES = TRUE)
  list(
    schema = schema, block_capacity = block_capacity, run_id = run_id,
    pins = as.list(pins), recipient = recipient,
    recipient_signing_key = identity$identity_sk)
}

# Creates or reopens the recipient's Rock-local X25519 key and returns only
# the signed public ticket needed by the configured source peer. It has no
# public/DSI surface.
.dsvert_formal_cox_server_source_recipient_ticket <- function(
    schema, block_capacity, run_id) {
  input <- .dsvert_formal_cox_server_source_recipient_command_input(
    schema, block_capacity, run_id)
  command <- list(
    version = "dsvert-formal-cox-blockwise-source-recipient-key-command-v1",
    schema = input$schema,
    block_capacity = input$block_capacity,
    run_id = input$run_id,
    pins = input$pins,
    recipient_peer_name = input$recipient,
    recipient_signing_key = input$recipient_signing_key)
  response <- .callMpcTool("formal-cox-source-recipient-key", command)
  fields <- c(
    "version", "purpose", "plan_sha256", "run_id", "pinset_sha256",
    "recipient_peer_name", "recipient_peer_id", "recipient_role",
    "transport_key_sha256", "transport_public_key", "signature")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-cox-blockwise-source-recipient-ticket-v1") ||
      !identical(response$purpose, "formal-cox-blockwise-source-v1") ||
      !identical(response$run_id, input$run_id) ||
      !identical(response$recipient_peer_name, input$recipient) ||
      !identical(response$recipient_role,
                 if (identical(input$recipient,
                               .dsvert_formal_cox_compute_peers(
                                 input$schema$unsigned$peer_pinset)[[1L]])) {
                   "garbler"
                 } else {
                   "evaluator"
                 }) ||
      !is.character(response$plan_sha256) ||
      length(response$plan_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", response$plan_sha256) ||
      !is.character(response$pinset_sha256) ||
      length(response$pinset_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", response$pinset_sha256) ||
      !is.character(response$recipient_peer_id) ||
      length(response$recipient_peer_id) != 1L ||
      !grepl("^dsv1_[0-9a-f]{64}$", response$recipient_peer_id) ||
      !is.character(response$transport_key_sha256) ||
      length(response$transport_key_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", response$transport_key_sha256) ||
      is.null(tryCatch(.dsvert_normalize_crypto_b64(
        response$transport_public_key, 32L, "Cox recipient transport key"),
        error = function(error) NULL)) ||
      is.null(tryCatch(.dsvert_normalize_crypto_b64(
        response$signature, 64L, "Cox recipient ticket signature"),
        error = function(error) NULL))) {
    .dsvert_formal_cox_abort("The formal Cox recipient ticket is invalid.")
  }
  response
}

# Builds the closed, recipient-local command for one already committed source
# delivery.  It is intentionally private: the recipient signing key is passed
# directly to the local Go process and never appears in a DSI request or a
# return value.  Worker provisioning reuses this exact command, avoiding a
# second schema/ticket validation path.
.dsvert_formal_cox_server_source_import_command <- function(
    schema, block_capacity, run_id, recipient_tickets, delivery) {
  input <- .dsvert_formal_cox_server_source_recipient_command_input(
    schema, block_capacity, run_id)
  if (!is.list(recipient_tickets) || length(recipient_tickets) != 2L ||
      !is.null(names(recipient_tickets))) {
    .dsvert_formal_cox_abort(
      "The formal Cox recipient ticket manifest is invalid.")
  }
  delivery_fields <- c(
    "version", "purpose", "receipt", "receipt_sha256",
    "recipient_peer_name", "envelope", "binding")
  if (!is.list(delivery) || !identical(names(delivery), delivery_fields) ||
      !identical(delivery$version,
                 "dsvert-formal-cox-blockwise-source-delivery-v1") ||
      !identical(delivery$purpose,
                 "formal-cox-recipient-encrypted-source-delivery-v1") ||
      !is.list(delivery$receipt) ||
      !is.character(delivery$receipt_sha256) ||
      length(delivery$receipt_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", delivery$receipt_sha256) ||
      !identical(delivery$recipient_peer_name, input$recipient) ||
      !is.list(delivery$envelope) || !length(delivery$envelope) ||
      !is.list(delivery$binding) || !length(delivery$binding)) {
    .dsvert_formal_cox_abort("The formal Cox recipient delivery is invalid.")
  }
  list(
    version = "dsvert-formal-cox-blockwise-source-import-command-v2",
    schema = input$schema,
    block_capacity = input$block_capacity,
    run_id = input$run_id,
    pins = input$pins,
    recipient_tickets = recipient_tickets,
    recipient_peer_name = input$recipient,
    recipient_signing_key = input$recipient_signing_key,
    delivery = delivery)
}

# Server-internal recipient ingress for one delivery already committed by a
# configured source. It receives no source frame, producer key or X25519
# secret: Go reopens the recipient's ticket-bound Rock key and authenticates
# the opaque delivery before accepting it.
.dsvert_formal_cox_server_source_import_block <- function(
    schema, block_capacity, run_id, recipient_tickets, delivery) {
  command <- .dsvert_formal_cox_server_source_import_command(
    schema, block_capacity, run_id, recipient_tickets, delivery)
  response <- .callMpcTool("formal-cox-source-import", command)
  fields <- c(
    "version", "purpose", "receipt_sha256", "recipient_peer_name",
    "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-cox-blockwise-source-import-receipt-v1") ||
      !identical(response$purpose,
                 "formal-cox-recipient-encrypted-source-delivery-v1") ||
      !identical(response$receipt_sha256, delivery$receipt_sha256) ||
      !identical(response$recipient_peer_name, command$recipient_peer_name) ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_cox_abort("The formal Cox recipient import returned invalid output.")
  }
  response
}
