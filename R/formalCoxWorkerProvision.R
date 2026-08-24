# Private provisioning boundary for one formal-Cox worker.
#
# The caller supplies only records already fixed by the signed schema and the
# recipient's opaque delivery.  Go derives the Rock slot from that material;
# no path, peer, run nonce, or secret can be selected by a DataSHIELD caller.

.DSVERT_FORMAL_COX_WORKER_PROVISION_VERSION <-
  "dsvert-formal-cox-blockwise-worker-provision-v1"
.DSVERT_FORMAL_COX_WORKER_HOST_VERSION <-
  "dsvert-formal-cox-blockwise-worker-host-v1"
.DSVERT_FORMAL_COX_WORKER_BOOTSTRAP_VERSION <-
  "dsvert-formal-cox-blockwise-worker-bootstrap-v1"
.DSVERT_FORMAL_COX_WORKER_ATTEMPT_DOMAIN <-
  "dsVert/formal-cox/blockwise-worker-attempt/v1|"

.dsvert_formal_cox_worker_attempt_id <- function(schema, run_id) {
  .dsvert_formal_cox_schema_validate(schema)
  run_id <- .dsvert_formal_cox_sha256(run_id, "Cox worker run id")
  if (!identical(run_id, .dsvert_formal_cox_run_id(schema))) {
    .dsvert_formal_cox_abort(
      "The Cox worker run id does not match the signed schema.")
  }
  .dsvert_formal_cox_hash(
    .DSVERT_FORMAL_COX_WORKER_ATTEMPT_DOMAIN,
    list(schema_sha256 = schema$schema_sha256, run_id = run_id))
}

.dsvert_formal_cox_worker_provision_command <- function(
    schema, block_capacity, run_id, recipient_tickets, delivery) {
  source <- .dsvert_formal_cox_server_source_import_command(
    schema, block_capacity, run_id, recipient_tickets, delivery)
  list(
    version = .DSVERT_FORMAL_COX_WORKER_PROVISION_VERSION,
    config = list(
      version = .DSVERT_FORMAL_COX_WORKER_HOST_VERSION,
      bootstrap = list(
        version = .DSVERT_FORMAL_COX_WORKER_BOOTSTRAP_VERSION,
        source = source,
        attempt_id = .dsvert_formal_cox_worker_attempt_id(schema, run_id))))
}

# Writes the sealed, recipient-local bootstrap for one worker and returns only
# its non-secret selector.  Starting, polling and relaying that worker remain
# separate durable operations: provision alone cannot release an analysis.
.dsvert_formal_cox_worker_provision <- function(
    schema, block_capacity, run_id, recipient_tickets, delivery) {
  # The imported envelope must be durably accepted before its bootstrap can be
  # recorded.  Replays are exact and harmless; a failed import never leaves a
  # worker configuration that could later start against absent source state.
  .dsvert_formal_cox_server_source_import_block(
    schema, block_capacity, run_id, recipient_tickets, delivery)
  command <- .dsvert_formal_cox_worker_provision_command(
    schema, block_capacity, run_id, recipient_tickets, delivery)
  on.exit({
    command$config$bootstrap$source$recipient_signing_key <- NULL
    command <- NULL
  }, add = TRUE)
  response <- .callMpcTool("formal-cox-worker-provision", command)
  fields <- c("version", "peer_name", "plan_sha256", "attempt_id", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version, .DSVERT_FORMAL_COX_WORKER_PROVISION_VERSION) ||
      !identical(response$peer_name,
                 command$config$bootstrap$source$recipient_peer_name) ||
      !is.character(response$plan_sha256) || length(response$plan_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", response$plan_sha256) ||
      !identical(response$attempt_id, command$config$bootstrap$attempt_id) ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_cox_abort("The formal Cox worker provision is invalid.")
  }
  list(
    version = response$version,
    peer_name = response$peer_name,
    plan_sha256 = response$plan_sha256,
    attempt_id = response$attempt_id,
    replayed = response$replayed,
    production_ready = FALSE)
}
