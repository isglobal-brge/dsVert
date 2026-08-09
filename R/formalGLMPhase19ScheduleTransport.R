# Internal R/DSI bridge for the protected formal-GLM Phase-1.9 schedule.
#
# Nothing in this file is exported or registered as a DataSHIELD method.  The
# candidate bridge may be promoted only together with the durable joint-DP
# finalizer: its Ring128 result is a private additive share, not a releasable
# statistic.

.DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_OPERATION <-
  "formal-glm-phase19-schedule-v1"
.DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_WORKER_KIND <-
  "formal-glm-phase19-schedule-v1"
.DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_WORKER_VERSION <-
  "dsvert-formal-glm-phase19-durable-schedule-worker-v1"
.DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_RESULT_VERSION <-
  "dsvert-formal-glm-phase19-durable-schedule-result-v1"
.DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_RESULT_KIND <-
  "formal-glm-phase19-ring128-dp-bridge-share-v1"
.DSVERT_FORMAL_GLM_PHASE20_HANDOFF_MAX_BYTES <- 4L * 1024L^2
.DSVERT_FORMAL_GLM_PHASE19_RECIPIENT_KEY_VERSION <-
  "dsvert-formal-glm-phase19-recipient-x25519-v1"
.DSVERT_FORMAL_GLM_PHASE19_DP_BRIDGE_VERSION <-
  "dsvert-formal-glm-phase15-dp-bridge-v1"
.DSVERT_FORMAL_GLM_PHASE19_DP_BRIDGE_DOMAIN <-
  "dsVert/formal-glm/phase15/dp-bridge/v1"
.DSVERT_FORMAL_GLM_PHASE19_RECEIPT_VERSION <-
  "dsvert-formal-glm-phase15-step-receipt-v2"
.DSVERT_FORMAL_GLM_PHASE19_RECEIPT_PAIR_DOMAIN <-
  "dsVert/formal-glm/phase15/final-receipt-pair/v1"
.DSVERT_FORMAL_GLM_PHASE19_POST_TOKEN_VERSION <-
  "dsvert-formal-glm-phase19-post-execution-token-v1"
.DSVERT_FORMAL_GLM_PHASE19_POST_TOKEN_DOMAIN <-
  "dsVert/formal-glm/phase19/post-execution-token/v1|"
.DSVERT_FORMAL_GLM_PHASE19_EXECUTION_PAIR_VERSION <-
  "dsvert-formal-glm-phase19-execution-seal-v2-receipt-pair"
.DSVERT_FORMAL_GLM_PHASE19_DP_STATUS <-
  "blocked_until_joint_dp_release_consumes_hidden_execution_validity_v1"
.DSVERT_FORMAL_GLM_PHASE19_BLOCKERS <- c(
  "registered_r_dsi_lifecycle_and_real_multiprocess_e2e_unavailable_v1",
  "joint_dp_release_consuming_hidden_execution_validity_v1")

.dsvert_formal_glm_phase19_abort <- function(message, code) {
  .dsvert_formal_glm_phase18_abort(message, code)
}

.dsvert_formal_glm_phase19_root <- function(
    root = file.path(.dsvert_state_root(), "formal-glm-phase19-v1")) {
  if (!is.character(root) || length(root) != 1L || is.na(root) ||
      !nzchar(root)) {
    .dsvert_formal_glm_phase19_abort(
      "The Phase-1.9 durable state root is unavailable.",
      "durable_state_unavailable")
  }
  root <- path.expand(root)
  if (!grepl("^/", root)) {
    .dsvert_formal_glm_phase19_abort(
      "The Phase-1.9 durable state root must be absolute.",
      "durable_state_unavailable")
  }
  .dsvert_formal_glm_phase18_private_dir(root)
}

.dsvert_formal_glm_phase19_standard_b64 <- function(value, bytes, what) {
  value <- .dsvert_formal_glm_phase18_scalar(
    value, what, maximum_bytes = 4L * as.integer(bytes) + 16L)
  raw <- tryCatch(jsonlite::base64_dec(value), error = function(error) raw())
  canonical <- if (is.raw(raw)) {
    gsub("[\r\n]", "", jsonlite::base64_enc(raw))
  } else ""
  if (length(raw) != as.integer(bytes) || !identical(value, canonical)) {
    .dsvert_formal_glm_phase19_abort(
      paste0("The ", what, " is not canonical Base64."),
      "unsafe_durable_state")
  }
  value
}

.dsvert_formal_glm_phase19_recipient_key_path <- function(root) {
  file.path(root, "recipient-x25519.json")
}

.dsvert_formal_glm_phase19_recipient_key_id <- function(public_key) {
  digest::digest(
    charToRaw(paste0(
      "dsVert/formal-glm/phase19/recipient-x25519-key-id/v1|", public_key)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_formal_glm_phase19_validate_recipient_key <- function(
    path, derive = .callMpcTool) {
  encoded <- .dsvert_formal_glm_phase18_private_file(
    path, minimum_bytes = 128L, maximum_bytes = 1024L)
  text <- rawToChar(encoded)
  value <- tryCatch(jsonlite::fromJSON(
    text, simplifyVector = FALSE), error = function(error) NULL)
  fields <- c("version", "public_key", "secret_key", "key_id")
  canonical <- tryCatch(.dsvert_dp_canonical_json(value),
                        error = function(error) NULL)
  if (!is.function(derive) || !is.list(value) ||
      !setequal(names(value), fields) ||
      !identical(value$version,
                 .DSVERT_FORMAL_GLM_PHASE19_RECIPIENT_KEY_VERSION) ||
      !identical(canonical, text)) {
    .dsvert_formal_glm_phase19_abort(
      "The persistent Phase-1.9 recipient key record is invalid.",
      "unsafe_durable_state")
  }
  public_key <- .dsvert_formal_glm_phase19_standard_b64(
    value$public_key, 32L, "Phase-1.9 recipient public key")
  secret_key <- .dsvert_formal_glm_phase19_standard_b64(
    value$secret_key, 32L, "Phase-1.9 recipient secret key")
  key_id <- .dsvert_formal_glm_phase18_scalar(
    value$key_id, "Phase-1.9 recipient key id",
    pattern = "^[0-9a-f]{64}$", maximum_bytes = 64L)
  if (!identical(key_id,
                 .dsvert_formal_glm_phase19_recipient_key_id(public_key))) {
    .dsvert_formal_glm_phase19_abort(
      "The persistent Phase-1.9 recipient key id is invalid.",
      "unsafe_durable_state")
  }
  check <- tryCatch(derive("exact-gc-derive-master", list(
    local_secret = secret_key, local_public = public_key,
    peer_public = public_key,
    session_id = digest::digest(charToRaw(paste0(
      "dsVert/formal-glm/phase19/recipient-key-check/v1|", key_id)),
      algo = "sha256", serialize = FALSE),
    garbler_id = "formal-glm-key-check-garbler",
    evaluator_id = "formal-glm-key-check-evaluator",
    purpose = "formal-glm/phase19/recipient-key-check",
    operation = "truncate-floor", ring_bits = 63L, frac_bits = 1L,
    vector_len = 1L)), error = function(error) NULL)
  if (!is.list(check) || !is.character(check$context_hash) ||
      length(check$context_hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", check$context_hash)) {
    .dsvert_formal_glm_phase19_abort(
      "The persistent Phase-1.9 recipient X25519 keypair is inconsistent.",
      "unsafe_durable_state")
  }
  list(public_key = public_key, secret_key = secret_key, key_id = key_id)
}

.dsvert_formal_glm_phase19_init_recipient_key <- function(
    root = .dsvert_formal_glm_phase19_root(),
    keygen = .callMpcTool, derive = .callMpcTool) {
  root <- .dsvert_formal_glm_phase19_root(root)
  path <- .dsvert_formal_glm_phase19_recipient_key_path(root)
  if (file.exists(path)) {
    return(.dsvert_formal_glm_phase19_validate_recipient_key(path, derive))
  }
  if (!is.function(keygen) || .dsvert_dp_path_is_link(path) ||
      .dsvert_dp_path_is_link(paste0(path, ".lock"))) {
    .dsvert_formal_glm_phase19_abort(
      "The Phase-1.9 recipient-key slot is unsafe.",
      "unsafe_durable_state")
  }
  .dsvert_formal_glm_phase18_with_lock(
    paste0(path, ".lock"), function() {
      if (file.exists(path)) {
        return(.dsvert_formal_glm_phase19_validate_recipient_key(path, derive))
      }
      generated <- tryCatch(
        keygen("transport-keygen", list()), error = function(error) NULL)
      if (!is.list(generated) ||
          !setequal(names(generated), c("public_key", "secret_key"))) {
        .dsvert_formal_glm_phase19_abort(
          "Secure X25519 recipient-key generation failed.",
          "durable_state_unavailable")
      }
      public_key <- .dsvert_formal_glm_phase19_standard_b64(
        generated$public_key, 32L, "generated Phase-1.9 public key")
      secret_key <- .dsvert_formal_glm_phase19_standard_b64(
        generated$secret_key, 32L, "generated Phase-1.9 secret key")
      value <- .dsvert_dp_canonical_query_value(list(
        version = .DSVERT_FORMAL_GLM_PHASE19_RECIPIENT_KEY_VERSION,
        public_key = public_key, secret_key = secret_key,
        key_id = .dsvert_formal_glm_phase19_recipient_key_id(public_key)))
      payload <- charToRaw(.dsvert_dp_canonical_json(value))
      committed <- .dsvert_formal_glm_phase18_atomic_cas(
        path, payload, 1024L,
        ".phase18-phase19-recipient-key-tmp-")
      invisible(committed)
      .dsvert_formal_glm_phase19_validate_recipient_key(path, derive)
    })
}

.dsvert_formal_glm_phase19_recipient_ticket <- function(
    authorization,
    root = .dsvert_formal_glm_phase19_root(),
    signer = NULL, verifier = .dsvert_relay_verify_message,
    keygen = .callMpcTool, derive = .callMpcTool) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  recipient <- authorization$policy$peer_name
  if (!recipient %in% authorization$designated) {
    .dsvert_formal_glm_phase19_abort(
      "Only a designated compute peer can mint a Phase-1.9 recipient ticket.",
      "invalid_recipient_ticket")
  }
  key <- .dsvert_formal_glm_phase19_init_recipient_key(
    root = root, keygen = keygen, derive = derive)
  unsigned <- .dsvert_formal_glm_phase18_ticket_unsigned(
    authorization, recipient, key$public_key)
  signed <- .dsvert_formal_glm_phase18_sign(
    unsigned, authorization$policy,
    .DSVERT_FORMAL_GLM_PHASE18_TICKET_DOMAIN, signer = signer)
  json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(signed))
  invisible(.dsvert_formal_glm_phase18_ticket_validate(
    json, authorization, verifier = verifier))
  list(ticket_json = json, key_id = key$key_id,
       recipient_name = recipient)
}

.dsvert_formal_glm_phase19_ticket_set <- function(
    ticket_jsons, authorization,
    verifier = .dsvert_relay_verify_message) {
  if (!is.list(ticket_jsons) || length(ticket_jsons) != 2L) {
    .dsvert_formal_glm_phase19_abort(
      "Exactly two signed compute-peer recipient tickets are required.",
      "invalid_recipient_ticket")
  }
  tickets <- lapply(
    ticket_jsons, .dsvert_formal_glm_phase18_ticket_validate,
    authorization = authorization, verifier = verifier)
  recipients <- vapply(tickets, function(ticket) {
    ticket$value$recipient_name
  }, character(1L))
  if (anyDuplicated(recipients) ||
      !setequal(recipients, authorization$designated)) {
    .dsvert_formal_glm_phase19_abort(
      "The signed recipient tickets do not cover exactly both compute peers.",
      "invalid_recipient_ticket")
  }
  tickets[match(authorization$designated, recipients)]
}

.dsvert_formal_glm_phase19_inbox_blocks <- function(
    authorization, receipt_set,
    manifest_path,
    phase18_root = .dsvert_formal_glm_phase18_durable_root()) {
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  recipient <- authorization$policy$peer_name
  if (!recipient %in% authorization$designated ||
      !is.list(receipt_set) ||
      !is.character(receipt_set$global_materialization_root_sha256) ||
      !grepl("^[0-9a-f]{64}$",
             receipt_set$global_materialization_root_sha256)) {
    .dsvert_formal_glm_phase19_abort(
      "The complete Phase-1.8 inbox context is unavailable.",
      "incomplete_materialization_receipt_set")
  }
  root <- .dsvert_formal_glm_phase18_private_dir(
    .dsvert_formal_glm_phase18_durable_root(phase18_root))
  key <- .dsvert_formal_glm_phase18_init_key(root)
  key_id <- .dsvert_formal_glm_phase18_key_id(key)
  global_root <- receipt_set$global_materialization_root_sha256
  total_blocks <- as.numeric(authorization$pre$total_blocks)
  if (length(total_blocks) != 1L || is.na(total_blocks) ||
      !is.finite(total_blocks) || total_blocks < 1 ||
      total_blocks > 2^31 - 1 || total_blocks != floor(total_blocks)) {
    .dsvert_formal_glm_phase19_abort(
      "The Phase-1.9 block count is outside the supported exact range.",
      "numeric_backend_unavailable")
  }
  if (!is.character(manifest_path) || length(manifest_path) != 1L ||
      is.na(manifest_path) || !grepl("^/", manifest_path) ||
      file.exists(manifest_path) ||
      !dir.exists(dirname(manifest_path)) ||
      nzchar(Sys.readlink(dirname(manifest_path)))) {
    .dsvert_formal_glm_phase19_abort(
      "The private Phase-1.9 block manifest path is unsafe.",
      "unsafe_durable_state")
  }
  connection <- file(manifest_path, open = "wb")
  committed <- FALSE
  on.exit({
    tryCatch(close(connection), error = function(error) NULL)
    if (!committed) unlink(manifest_path)
  }, add = TRUE)
  block_index <- 0
  while (block_index < total_blocks) {
    paths <- vapply(authorization$peers, function(source_name) {
      slot <- .dsvert_formal_glm_phase18_hash_object(
        "dsVert/formal-glm/phase18/recipient-inbox-slot/v2|", list(
          capsule_sha256 = authorization$pre$capsule_id,
          plan_sha256 = authorization$pre$plan_sha256,
          pre_execution_sha256 = authorization$pre_execution_sha256,
          global_materialization_root = global_root,
          run_id = authorization$pre$run_id,
          source_name = source_name, recipient_name = recipient,
          block_index = block_index))
      path <- .dsvert_formal_glm_phase18_sharded_path(
        root, "recipient-inbox-v2", key_id, slot)
      encoded <- .dsvert_formal_glm_phase18_private_file(
        path, minimum_bytes = 64L,
        maximum_bytes = .DSVERT_FORMAL_GLM_PHASE18_MAX_FRAME_BYTES)
      invisible(.dsvert_formal_glm_phase18_frame_verify(encoded, key))
      normalizePath(path, winslash = "/", mustWork = TRUE)
    }, character(1L), USE.NAMES = FALSE)
    record <- charToRaw(paste0(as.character(jsonlite::toJSON(
      list(block_index = block_index,
           ingress_paths = unname(paths)),
      auto_unbox = TRUE, null = "null", digits = 17)), "\n"))
    writeBin(record, connection, useBytes = TRUE)
    block_index <- block_index + 1
  }
  close(connection)
  committed <- TRUE
  Sys.chmod(manifest_path, mode = "0600")
  manifest_path <- normalizePath(
    manifest_path, winslash = "/", mustWork = TRUE)
  info <- file.info(manifest_path)
  if (nrow(info) != 1L || is.na(info$size) || info$size < 2 ||
      info$size > 2^53 || nzchar(Sys.readlink(manifest_path))) {
    .dsvert_formal_glm_phase19_abort(
      "The private Phase-1.9 block manifest is unsafe.",
      "unsafe_durable_state")
  }
  list(manifest_path = manifest_path,
       manifest_sha256 = digest::digest(
         file = manifest_path, algo = "sha256", serialize = FALSE),
       manifest_bytes = as.numeric(info$size),
       key = key, key_id = key_id, root = root,
       global_materialization_root = global_root)
}

.dsvert_formal_glm_phase19_backend <- function(
    authorization, tickets, recipient_key, semantic_root,
    derive = .callMpcTool) {
  recipient <- authorization$policy$peer_name
  local_index <- match(recipient, authorization$designated)
  peer_index <- match(setdiff(authorization$designated, recipient),
                      authorization$designated)
  if (is.na(local_index) || length(peer_index) != 1L || is.na(peer_index)) {
    .dsvert_formal_glm_phase19_abort(
      "The local server has no designated formal-GLM compute role.",
      "invalid_pinned_consortium")
  }
  local_public <- .dsvert_normalize_crypto_b64(
    tickets[[local_index]]$transport_pk, 32L,
    "local formal-GLM recipient public key")
  if (!identical(local_public, recipient_key$public_key)) {
    .dsvert_formal_glm_phase19_abort(
      paste0("The active recipient key differs from the signed Phase-1.8 ",
             "ticket; rematerialize this analysis after key rotation."),
      "recipient_key_epoch_changed")
  }
  peer_public <- .dsvert_normalize_crypto_b64(
    tickets[[peer_index]]$transport_pk, 32L,
    "peer formal-GLM recipient public key")
  ids <- vapply(authorization$designated, function(peer) {
    .dsvert_formal_glm_phase18_peer_id(
      unname(authorization$policy$peer_pinset[[peer]]))
  }, character(1L), USE.NAMES = FALSE)
  purpose <- paste0("formal-glm/phase19/", semantic_root)
  derived <- tryCatch(derive("exact-gc-derive-master", list(
    local_secret = recipient_key$secret_key,
    local_public = recipient_key$public_key,
    peer_public = peer_public,
    session_id = semantic_root,
    garbler_id = ids[[1L]], evaluator_id = ids[[2L]], purpose = purpose,
    operation = "formal-glm-one-iteration-v1",
    ring_bits = as.integer(authorization$plan$ring_bits),
    frac_bits = as.integer(authorization$plan$kernel$frac_bits),
    vector_len = as.integer(authorization$plan$kernel$coefficient_count))),
    error = function(error) NULL)
  if (!is.list(derived) ||
      !is.character(derived$context_hash) ||
      !grepl("^[0-9a-f]{64}$", derived$context_hash)) {
    .dsvert_formal_glm_phase19_abort(
      "The pinned Phase-1.9 compute peers could not derive a common backend.",
      "numeric_backend_unavailable")
  }
  derived$master_key <- .dsvert_formal_glm_phase19_standard_b64(
    derived$master_key, 32L, "Phase-1.9 backend key")
  derived$purpose <- purpose
  derived
}

.dsvert_formal_glm_phase19_semantic_root <- function(
    authorization, ticket_set, receipt_set) {
  ticket_hashes <- lapply(ticket_set, `[[`, "sha256")
  names(ticket_hashes) <- authorization$designated
  .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase19/durable-schedule-semantic-root/v1|", list(
      pre_execution_sha256 = authorization$pre_execution_sha256,
      plan_sha256 = authorization$pre$plan_sha256,
      run_id = authorization$pre$run_id,
      pinset_sha256 = authorization$pre$pinset_sha256,
      global_materialization_root_sha256 =
        receipt_set$global_materialization_root_sha256,
      local_receipt_set_sha256 = receipt_set$receipt_set_sha256,
      recipient_ticket_sha256 = ticket_hashes))
}

.dsvert_formal_glm_phase19_init_spool <- function(
    ss, operation_id, reservation = TRUE, additional_bytes = 0) {
  chunk_bytes <- .exact_gc_chunk_bytes()
  spool_max <- .exact_gc_spool_max_bytes(chunk_bytes)
  request_max <- .exact_gc_request_max_bytes(chunk_bytes)
  ttl <- .exact_gc_ttl_seconds()
  max_runtime <- .exact_gc_max_runtime_seconds(ttl)
  additional_bytes <- suppressWarnings(as.numeric(additional_bytes))
  if (length(additional_bytes) != 1L || is.na(additional_bytes) ||
      !is.finite(additional_bytes) || additional_bytes < 0 ||
      additional_bytes != floor(additional_bytes) ||
      additional_bytes > 2^53) {
    stop("Invalid formal-GLM private-store reservation.", call. = FALSE)
  }
  resource_reservation <- 2 * spool_max + 16 * 1024^2 + additional_bytes
  if (isTRUE(reservation)) {
    .dsvert_resource_admit(ss, resource_reservation)
  }
  spool <- normalizePath(
    .exact_gc_spool_dir(ss, operation_id, create = TRUE), mustWork = TRUE)
  if (length(list.files(spool, all.files = TRUE, no.. = TRUE))) {
    stop("The formal-GLM operation spool is not empty.", call. = FALSE)
  }
  for (name in c(
      "inbound.bin", "outbound.bin", "exchange.hb", "worker.hb")) {
    .exact_gc_private_file(
      file.path(spool, name),
      if (name %in% c("exchange.hb", "worker.hb")) charToRaw(".") else raw())
  }
  for (name in c("inbound.segments", "outbound.segments")) {
    path <- file.path(spool, name)
    if (!dir.create(path, mode = "0700", showWarnings = FALSE)) {
      stop("Could not create the formal-GLM segment spool.", call. = FALSE)
    }
    Sys.chmod(path, mode = "0700")
  }
  .exact_gc_private_file(
    file.path(spool, "inbound.state"), charToRaw(paste(
      .DSVERT_EXACT_GC_INBOUND_STATE_VERSION, "0", "-", "-", "-",
      sep = "|")))
  for (name in c("inbound.ack", "outbound.head", "outbound.ack")) {
    .exact_gc_private_file(file.path(spool, name), charToRaw("0"))
  }
  list(
    spool = spool, chunk_bytes = chunk_bytes, spool_max = spool_max,
    request_max = request_max, ttl = ttl, max_runtime = max_runtime,
    resource_reservation = resource_reservation)
}

.dsvert_formal_glm_phase19_block_store_bytes <- function(plan) {
  coefficient_count <- as.numeric(plan$kernel$coefficient_count)
  block_capacity <- as.numeric(plan$block_capacity)
  container_bits <- as.numeric(plan$container_bits)
  total_blocks <- as.numeric(plan$total_blocks)
  values <- c(coefficient_count, block_capacity, container_bits, total_blocks)
  if (anyNA(values) || any(!is.finite(values)) || any(values != floor(values)) ||
      coefficient_count < 1 || coefficient_count > 4 || block_capacity < 1 ||
      container_bits < 128 || container_bits > 4096 ||
      container_bits %% 8 != 0 || total_blocks < 1) {
    .dsvert_formal_glm_phase19_abort(
      "The formal-GLM private-store shape is invalid.",
      "numeric_backend_unavailable")
  }
  record_bytes <- block_capacity * (coefficient_count + 3) *
    (container_bits / 8) + 101
  required <- record_bytes * total_blocks
  if (!is.finite(required) || required < 1 || required > 2^53 ||
      required != floor(required)) {
    .dsvert_formal_glm_phase19_abort(
      "The formal-GLM private-store size exceeds the numeric resource range.",
      "numeric_backend_unavailable")
  }
  as.numeric(required)
}

.dsvert_formal_glm_phase19_public_state <- function(state) {
  result <- .exact_gc_public_state(state)
  # This state reports transport liveness only.  In particular, it never
  # returns the private Ring128 share or post-execution evidence.
  result$release_ready <- FALSE
  result
}

.dsvert_formal_glm_phase19_schedule_start <- function(
    ss, session_id, authorization, recipient_ticket_jsons,
    local_receipt_jsons,
    verifier = .dsvert_relay_verify_message,
    phase18_root = .dsvert_formal_glm_phase18_durable_root(),
    phase19_root = .dsvert_formal_glm_phase19_root(),
    binary = .findMpcBinary(), derive = .callMpcTool,
    process_new = processx::process$new) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  .dsvert_formal_glm_phase18_pre_validate(authorization)
  if (!is.environment(ss) || !is.function(verifier) ||
      !is.function(derive) || !is.function(process_new)) {
    stop("Invalid formal-GLM schedule runtime.", call. = FALSE)
  }
  recipient <- authorization$policy$peer_name
  if (!recipient %in% authorization$designated) {
    .dsvert_formal_glm_phase19_abort(
      "Only a designated compute peer can execute the formal-GLM schedule.",
      "invalid_pinned_consortium")
  }
  peer_binding <- .exact_gc_validate_bound_peer_context(ss, session_id)
  if (!identical(ss$.exact_gc_self_name, recipient) ||
      !identical(sort(ss$.exact_gc_designated_peers, method = "radix"),
                 authorization$designated)) {
    .dsvert_formal_glm_phase19_abort(
      "The live DSI peer binding differs from the formal-GLM authorization.",
      "invalid_pinned_consortium")
  }
  tickets <- .dsvert_formal_glm_phase19_ticket_set(
    recipient_ticket_jsons, authorization, verifier)
  receipt_set <- .dsvert_formal_glm_phase18_local_receipt_set(
    local_receipt_jsons, authorization, verifier)
  semantic_root <- .dsvert_formal_glm_phase19_semantic_root(
    authorization, tickets, receipt_set)
  operation_id <- .dsvert_relay_validate_operation_id(paste0(
    "op_", substr(semantic_root, 1L, 32L)))
  requested_spec <- list(
    session_id = session_id, operation_id = operation_id,
    operation = .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_OPERATION,
    semantic_root_sha256 = semantic_root,
    peer_binding_sha256 = peer_binding,
    pre_execution_sha256 = authorization$pre_execution_sha256,
    plan_sha256 = authorization$pre$plan_sha256,
    global_materialization_root_sha256 =
      receipt_set$global_materialization_root_sha256)
  previous <- .exact_gc_operation_state(ss, operation_id, required = FALSE)
  attempt <- 1L
  if (!is.null(previous)) {
    if (!identical(previous$requested_spec, requested_spec) ||
        !identical(previous$worker_kind,
                   .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_WORKER_KIND)) {
      stop("Conflicting retry for the formal-GLM schedule.", call. = FALSE)
    }
    tryCatch(.exact_gc_refresh(ss, previous), error = function(error) {
      .exact_gc_record_private_error(previous, conditionMessage(error))
    })
    retryable <- identical(previous$status, "aborted") ||
      (identical(previous$status, "failed") && isTRUE(previous$retryable))
    if (!retryable) {
      return(.dsvert_formal_glm_phase19_public_state(previous))
    }
    attempt <- as.integer(.exact_gc_integer(
      (previous$attempt %||% 1L) + 1L,
      "formal-GLM schedule attempt", 2, 2^31 - 1))
    .exact_gc_reset_retryable_state(ss, previous)
  }
  recipient_key <- .dsvert_formal_glm_phase19_init_recipient_key(
    phase19_root, derive = derive)
  backend <- .dsvert_formal_glm_phase19_backend(
    authorization, tickets, recipient_key, semantic_root, derive)
  attempt_id <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase19/transport-attempt/v1|", list(
      semantic_root_sha256 = semantic_root, attempt = attempt))
  runtime_root <- .dsvert_formal_glm_phase18_hash_object(
    "dsVert/formal-glm/phase19/runtime-root/v1|", list(
      semantic_root_sha256 = semantic_root, attempt_sha256 = attempt_id))
  phase19_root <- .dsvert_formal_glm_phase19_root(phase19_root)
  handoff_dir <- .dsvert_formal_glm_phase18_private_dir(file.path(
    phase19_root, "phase20-handoff-v1", recipient, semantic_root))
  finalizer_dir <- .dsvert_formal_glm_phase18_private_dir(file.path(
    phase19_root, "local-finalizer-v1", recipient, semantic_root))
  checkpoint_dir <- .dsvert_formal_glm_phase18_private_dir(file.path(
    phase19_root, "phase15-checkpoints-v1", recipient, semantic_root))
  checkpoint_key_root <- .dsvert_formal_glm_phase18_private_dir(file.path(
    phase19_root, "phase15-checkpoint-key-v1", recipient))
  checkpoint_key <- .dsvert_formal_glm_phase18_init_key(checkpoint_key_root)
  identity <- .get_identity_keypair()
  identity_pk <- .dsvert_normalize_crypto_b64(
    identity$identity_pk, 32L, "local formal-GLM Ed25519 public key")
  expected_pk <- .dsvert_normalize_crypto_b64(
    unname(authorization$policy$peer_pinset[[recipient]]), 32L,
    "pinned formal-GLM Ed25519 public key")
  if (!identical(identity_pk, expected_pk)) {
    .dsvert_formal_glm_phase19_abort(
      "The runtime identity differs from the formal-GLM compute-peer pin.",
      "local_identity_mismatch")
  }
  identity_sk <- .dsvert_normalize_crypto_b64(
    identity$identity_sk, 64L, "local formal-GLM Ed25519 private key")
  pins <- vapply(authorization$peers, function(peer) {
    .dsvert_normalize_crypto_b64(
      unname(authorization$policy$peer_pinset[[peer]]), 32L,
      paste0("formal-GLM Ed25519 pin for ", peer))
  }, character(1L), USE.NAMES = TRUE)
  names(pins) <- authorization$peers
  heartbeat <- .dsvert_secure_random_bytes(32L)
  if (!is.raw(heartbeat) || length(heartbeat) != 32L) {
    .dsvert_formal_glm_phase19_abort(
      "Secure Phase-1.9 heartbeat-key generation failed.",
      "durable_state_unavailable")
  }
  heartbeat_b64 <- gsub("[\r\n]", "", jsonlite::base64_enc(heartbeat))
  block_store_bytes <- .dsvert_formal_glm_phase19_block_store_bytes(
    authorization$plan)
  spool_state <- .dsvert_formal_glm_phase19_init_spool(
    ss, operation_id, additional_bytes =
      block_store_bytes + .DSVERT_FORMAL_GLM_PHASE20_HANDOFF_MAX_BYTES)
  spool <- spool_state$spool
  spool_retained <- FALSE
  on.exit(if (!spool_retained) unlink(spool, recursive = TRUE), add = TRUE)
  inbox <- .dsvert_formal_glm_phase19_inbox_blocks(
    authorization, receipt_set,
    manifest_path = file.path(spool, "formal-block-manifest-v1.jsonl"),
    phase18_root = phase18_root)
  spool_state$resource_reservation <-
    spool_state$resource_reservation + inbox$manifest_bytes
  .dsvert_resource_admit(ss, spool_state$resource_reservation)
  role <- if (identical(recipient, authorization$designated[[1L]])) {
    "garbler"
  } else "evaluator"
  local_template <- list(
    version = "dsvert-formal-glm-phase19-runtime-prepare-v1",
    plan = authorization$plan,
    pre_execution_token_sha256 = authorization$pre_execution_sha256,
    global_materialization_root =
      receipt_set$global_materialization_root_sha256,
    recipient = recipient, finalizer_dir = finalizer_dir,
    ingress_paths = list(),
    local_ingress_key = gsub(
      "[\r\n]", "", jsonlite::base64_enc(inbox$key)),
    recipient_transport_secret_key = recipient_key$secret_key,
    backend_key = backend$master_key, block_index = -1L)
  config <- list(
    version = .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_WORKER_VERSION,
    role = role, local_template = local_template,
    block_manifest_path = inbox$manifest_path,
    block_manifest_sha256 = inbox$manifest_sha256,
    block_manifest_bytes = inbox$manifest_bytes,
    max_block_store_bytes = block_store_bytes,
    semantic_root_sha256 = semantic_root,
    schedule_root_sha256 = runtime_root, attempt_id = attempt_id,
    handoff_dir = handoff_dir,
    spool_dir = spool, max_spool_bytes = spool_state$spool_max,
    ttl_seconds = spool_state$ttl, heartbeat_key = heartbeat_b64,
    durable = list(
      checkpoint_dir = checkpoint_dir,
      checkpoint_key = gsub(
        "[\r\n]", "", jsonlite::base64_enc(checkpoint_key)),
      signing_secret_key = identity_sk,
      pinned_public_keys = as.list(pins),
      output_lattice_bits = as.integer(
        authorization$plan$kernel$frac_bits)))
  config_json <- as.character(jsonlite::toJSON(
    config, auto_unbox = TRUE, null = "null", digits = 17))
  if (nchar(config_json, type = "bytes") > 64L * 1024L^2) {
    unlink(spool, recursive = TRUE)
    .dsvert_resource_oversize(
      nchar(config_json, type = "bytes"), 64L * 1024L^2,
      "formal-GLM private schedule manifest")
  }
  config_path <- file.path(spool, "formal-schedule-config.json")
  .private_write_lines(config_json, config_path)
  config$local_template$local_ingress_key <- NULL
  config$local_template$recipient_transport_secret_key <- NULL
  config$local_template$backend_key <- NULL
  config$durable$checkpoint_key <- NULL
  config$durable$signing_secret_key <- NULL
  config_json <- NULL
  backend$master_key <- NULL
  identity_sk <- NULL
  heartbeat_b64 <- NULL
  binary <- normalizePath(binary, winslash = "/", mustWork = TRUE)
  log_path <- file.path(spool, "formal-schedule-private.log")
  process <- NULL
  committed <- FALSE
  on.exit(if (!committed) {
    if (!is.null(process)) {
      tryCatch(process$kill(), error = function(error) NULL)
      tryCatch(process$wait(timeout = 1000), error = function(error) NULL)
    }
    unlink(spool, recursive = TRUE)
  }, add = TRUE)
  process <- process_new(
    binary, c("formal-glm-phase19-schedule-worker", config_path),
    env = "current", stdout = log_path, stderr = "2>&1",
    cleanup = FALSE, cleanup_tree = FALSE)
  ready <- FALSE
  for (ready_poll in seq_len(100L)) {
    if (!isTRUE(tryCatch(process$is_alive(),
                         error = function(error) FALSE))) break
    if (file.exists(file.path(spool, "ready"))) {
      ready <- TRUE
      break
    }
    Sys.sleep(0.05)
  }
  if (!ready || !isTRUE(tryCatch(
        process$is_alive(), error = function(error) FALSE))) {
    .exact_gc_record_private_error(
      list(spool = spool),
      "The formal-GLM schedule worker failed before readiness.")
    stop("The formal-GLM worker failed to become ready.", call. = FALSE)
  }
  state <- new.env(parent = emptyenv())
  state$worker_kind <- .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_WORKER_KIND
  state$session_id <- session_id
  state$operation_id <- operation_id
  state$attempt <- attempt
  state$requested_spec <- requested_spec
  state$public_spec <- requested_spec
  state$self_peer_id <- .dsvert_relay_peer_id(identity_pk)
  peer_name <- setdiff(authorization$designated, recipient)
  state$peer_id <- .dsvert_relay_peer_id(
    unname(authorization$policy$peer_pinset[[peer_name]]))
  state$peer_identity_pk <-
    unname(authorization$policy$peer_pinset[[peer_name]])
  state$role <- role
  state$context_hash <- backend$context_hash
  state$peer_binding_digest <- peer_binding
  state$operation <- .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_OPERATION
  state$output_kind <- .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_RESULT_KIND
  state$purpose <- backend$purpose
  state$source_producer <- "formal-glm-phase18-protected-inbox-v2"
  state$ring_bits <- 128L
  state$frac_bits <- 0L
  state$vector_len <- as.integer(
    authorization$plan$kernel$coefficient_count)
  state$threshold <- ""
  state$mul_plan <- NULL
  state$source_key <- paste0("formal_phase19_", semantic_root)
  state$output_key <- paste0("formal_phase19_", semantic_root)
  state$chunk_bytes <- spool_state$chunk_bytes
  state$spool_max_bytes <- spool_state$spool_max
  state$formal_block_store_bytes <- block_store_bytes
  state$formal_block_manifest_bytes <- inbox$manifest_bytes
  state$resource_reservation_bytes <- spool_state$resource_reservation
  state$request_max_bytes <- spool_state$request_max
  state$ttl_seconds <- spool_state$ttl
  state$max_runtime_seconds <- spool_state$max_runtime
  state$spool <- spool
  state$process <- process
  state$worker_pid <- suppressWarnings(as.numeric(process$get_pid()))
  if (length(state$worker_pid) != 1L || is.na(state$worker_pid) ||
      !is.finite(state$worker_pid) || state$worker_pid < 1 ||
      state$worker_pid != floor(state$worker_pid)) {
    stop("The formal-GLM worker returned an invalid PID.", call. = FALSE)
  }
  state$worker_heartbeat_session <- attempt_id
  state$worker_heartbeat_key <- heartbeat
  state$out_cache <- NULL
  state$outbound_ack_offset <- .exact_gc_offset_read(
    file.path(spool, "outbound.ack"),
    "formal-GLM acknowledged outbound offset")
  state$status <- "running"
  state$failure_code <- NULL
  state$retryable <- FALSE
  state$formal_semantic_root_sha256 <- semantic_root
  state$formal_handoff_dir <- handoff_dir
  state$formal_runtime_root_sha256 <- runtime_root
  state$formal_pre_execution_sha256 <- authorization$pre_execution_sha256
  state$formal_plan_sha256 <- authorization$pre$plan_sha256
  state$formal_kernel_spec_sha256 <- authorization$pre$kernel_spec_sha256
  state$formal_capsule_sha256 <- authorization$pre$capsule_id
  state$formal_snapshot_sha256 <- authorization$pre$snapshot_sha256
  state$formal_garbler_peer_name <- authorization$pre$garbler_peer_name
  state$formal_garbler_peer_id <- authorization$pre$garbler_peer_id
  state$formal_evaluator_peer_name <- authorization$pre$evaluator_peer_name
  state$formal_evaluator_peer_id <- authorization$pre$evaluator_peer_id
  state$formal_adjacency <- authorization$pre$adjacency
  state$formal_source_ring_bits <- as.integer(authorization$plan$ring_bits)
  state$formal_source_frac_bits <-
    as.integer(authorization$plan$kernel$frac_bits)
  state$formal_final_step_index <-
    as.integer(authorization$plan$schedule_steps) - 1L
  state$formal_recipient <- recipient
  state$formal_global_materialization_root <-
    receipt_set$global_materialization_root_sha256
  state$formal_run_id <- authorization$pre$run_id
  state$formal_pinset_sha256 <- authorization$pre$pinset_sha256
  state$formal_compute_peers <- authorization$designated
  state$formal_custodian_count <- length(authorization$peers)
  started_at <- .exact_gc_now()
  state$started_at <- started_at
  state$relay_heartbeat_at <- started_at
  state$worker_heartbeat_seen_at <- started_at
  state$worker_heartbeat_counter <-
    .exact_gc_worker_heartbeat_record(state)$counter
  .exact_gc_touch(state, now = started_at, ss = ss)
  operations <- .exact_gc_ops(ss)
  operations[[operation_id]] <- state
  spool_retained <- TRUE
  committed <- TRUE
  .dsvert_formal_glm_phase19_public_state(state)
}

.dsvert_formal_glm_phase19_hex <- function(value, what) {
  .dsvert_formal_glm_phase18_scalar(
    value, what, pattern = "^[0-9a-f]{64}$", maximum_bytes = 64L)
}

.dsvert_formal_glm_phase19_integer <- function(
    value, what, minimum = 0, maximum = 2^31 - 1) {
  as.integer(.dsvert_formal_glm_phase18_integer(
    value, what, minimum, maximum))
}

.dsvert_formal_glm_phase19_prefixed_json_sha256 <- function(domain, value) {
  .dsvert_formal_glm_phase18_sha256(c(
    charToRaw(domain),
    charToRaw(.dsvert_formal_glm_phase18_json(value))))
}

.dsvert_formal_glm_phase19_receipt_pair_sha256 <- function(
    receipts, state) {
  fields <- c(
    "version", "plan_sha256", "peer", "step_index", "attempt_id",
    "state_sha256", "transcript_sha256", "signature")
  if (!is.list(receipts) || length(receipts) != 2L ||
      !all(vapply(receipts, function(receipt) {
        is.list(receipt) && identical(names(receipt), fields)
      }, logical(1L)))) {
    stop("Invalid final formal-GLM receipt pair.", call. = FALSE)
  }
  peers <- vapply(receipts, `[[`, character(1L), "peer")
  plan_hashes <- vapply(receipts, `[[`, character(1L), "plan_sha256")
  attempts <- vapply(receipts, `[[`, character(1L), "attempt_id")
  states <- vapply(receipts, `[[`, character(1L), "state_sha256")
  transcripts <- vapply(
    receipts, `[[`, character(1L), "transcript_sha256")
  steps <- vapply(receipts, function(receipt) {
    .dsvert_formal_glm_phase19_integer(
      receipt$step_index, "final Phase-1.5 receipt step",
      state$formal_final_step_index, state$formal_final_step_index)
  }, integer(1L))
  signatures <- vapply(receipts, function(receipt) {
    .dsvert_formal_glm_phase19_standard_b64(
      receipt$signature, 64L, "final Phase-1.5 receipt signature")
  }, character(1L))
  if (!identical(unname(sort(peers, method = "radix")),
                 state$formal_compute_peers) ||
      anyDuplicated(peers) ||
      any(vapply(receipts, function(receipt) {
        !identical(receipt$version,
                   .DSVERT_FORMAL_GLM_PHASE19_RECEIPT_VERSION)
      }, logical(1L))) ||
      !all(plan_hashes == state$formal_plan_sha256) ||
      length(unique(attempts)) != 1L ||
      length(unique(transcripts)) != 1L ||
      any(!grepl("^[0-9a-f]{64}$", attempts)) ||
      any(!grepl("^[0-9a-f]{64}$", states)) ||
      any(!grepl("^[0-9a-f]{64}$", transcripts)) ||
      any(steps != state$formal_final_step_index) ||
      length(signatures) != 2L) {
    stop("The final formal-GLM receipts bind different executions.",
         call. = FALSE)
  }
  ordered <- receipts[order(peers, method = "radix")]
  .dsvert_formal_glm_phase18_domain_sha256(
    .DSVERT_FORMAL_GLM_PHASE19_RECEIPT_PAIR_DOMAIN, ordered)
}

.dsvert_formal_glm_phase19_bridge_projection <- function(state, bridge) {
  hashes <- c(
    bridge$phase15_plan_sha256, bridge$final_receipt_pair_sha256,
    bridge$execution_transcript_sha256, bridge$snapshot_sha256,
    bridge$pinset_sha256,
    bridge$selected_sensitivity_certificate_sha256)
  if (length(hashes) != 6L || anyNA(hashes) ||
      any(!grepl("^[0-9a-f]{64}$", hashes)) ||
      !identical(bridge$version,
                 .DSVERT_FORMAL_GLM_PHASE19_DP_BRIDGE_VERSION) ||
      !identical(bridge$phase15_plan_sha256, state$formal_plan_sha256) ||
      !identical(bridge$snapshot_sha256, state$formal_snapshot_sha256) ||
      !identical(bridge$pinset_sha256, state$formal_pinset_sha256) ||
      !identical(bridge$garbler_peer_name,
                 state$formal_garbler_peer_name) ||
      !identical(bridge$garbler_peer_id, state$formal_garbler_peer_id) ||
      !identical(bridge$evaluator_peer_name,
                 state$formal_evaluator_peer_name) ||
      !identical(bridge$evaluator_peer_id,
                 state$formal_evaluator_peer_id) ||
      !identical(bridge$role_selection,
                 "lexicographic_pinned_cryptographic_peer_id_v1") ||
      !identical(bridge$adjacency, state$formal_adjacency) ||
      !identical(bridge$sensitivity_selection,
                 "minimum_of_machine_proven_bounds_only_v1") ||
      !identical(bridge$quantization,
                 "signed_floor_then_public_box_translation_inside_exact_gc_v1") ||
      !identical(bridge$intermediate_output,
                 "sealed_nonnegative_ring128_additive_shares_only_v1") ||
      !identical(bridge$authenticated_opening,
                 "blocked_until_common_glm_release_capsule_e2e_v1") ||
      !identical(bridge$production_ready, FALSE)) {
    stop("Invalid private formal-GLM DP bridge binding.", call. = FALSE)
  }
  source_ring_bits <- .dsvert_formal_glm_phase19_integer(
    bridge$source_ring_bits, "formal-GLM source ring",
    state$formal_source_ring_bits, state$formal_source_ring_bits)
  source_frac_bits <- .dsvert_formal_glm_phase19_integer(
    bridge$source_frac_bits, "formal-GLM source fractional precision",
    state$formal_source_frac_bits, state$formal_source_frac_bits)
  output_lattice_bits <- .dsvert_formal_glm_phase19_integer(
    bridge$output_lattice_bits, "formal-GLM output lattice", 1L, 62L)
  quantization_shift <- .dsvert_formal_glm_phase19_integer(
    bridge$quantization_shift, "formal-GLM quantization shift", 0L, 4095L)
  if (source_ring_bits != state$formal_source_ring_bits ||
      source_frac_bits != state$formal_source_frac_bits ||
      output_lattice_bits > source_frac_bits ||
      quantization_shift != source_frac_bits - output_lattice_bits) {
    stop("The private formal-GLM DP bridge changed its numeric lattice.",
         call. = FALSE)
  }
  sensitivity_fields <- c(
    "version", "status", "proof", "bound_steps", "theorem_sha256")
  universal <- bridge$universal_sensitivity
  tight <- bridge$tight_sensitivity
  if (!is.list(universal) || !identical(names(universal), sensitivity_fields) ||
      !is.list(tight) || !identical(names(tight), sensitivity_fields) ||
      !identical(universal$version,
                 "dsvert-formal-glm-phase15-dp-sensitivity-v1") ||
      !identical(tight$version,
                 "dsvert-formal-glm-phase15-dp-sensitivity-v1") ||
      !identical(universal$status, "machine_proven") ||
      !identical(tight$status, "machine_proven") ||
      !identical(universal$proof,
                 .DSVERT_FORMAL_GLM_PHASE16_UNIVERSAL_PROOF) ||
      !identical(tight$proof,
                 .DSVERT_FORMAL_GLM_PHASE16_RECURRENCE_PROOF) ||
      !identical(universal$theorem_sha256, tight$theorem_sha256) ||
      any(!grepl("^[0-9a-f]{64}$", c(
        universal$theorem_sha256, tight$theorem_sha256)))) {
    stop("Invalid formal-GLM sensitivity summary.", call. = FALSE)
  }
  certificate <- bridge$selected_sensitivity_certificate
  if (!is.list(certificate) ||
      !identical(certificate$policy_sha256,
                 state$formal_kernel_spec_sha256) ||
      !identical(certificate$phase15_plan_sha256,
                 state$formal_plan_sha256) ||
      !identical(certificate$theorem_sha256,
                 universal$theorem_sha256) ||
      !identical(certificate$adjacency, state$formal_adjacency) ||
      !identical(as.numeric(certificate$source_frac_bits),
                 as.numeric(source_frac_bits)) ||
      !identical(as.numeric(certificate$output_lattice_bits),
                 as.numeric(output_lattice_bits)) ||
      !identical(as.numeric(certificate$quantization_shift),
                 as.numeric(quantization_shift)) ||
      !identical(certificate$quantization, paste0(
        "clip_box_then_coordinatewise_signed_floor_then_",
        "public_translation_v1")) ||
      !identical(certificate$universal_bound_steps,
                 universal$bound_steps) ||
      !identical(certificate$recurrence_bound_steps,
                 tight$bound_steps)) {
    stop("The formal-GLM sensitivity certificate changed its plan.",
         call. = FALSE)
  }
  certificate_sha256 <- .dsvert_formal_glm_phase19_prefixed_json_sha256(
    "dsVert/joint-dp/machine-proven-integer-lattice-l2-certificate/v1|",
    certificate)
  if (!identical(certificate_sha256,
                 bridge$selected_sensitivity_certificate_sha256)) {
    stop("The formal-GLM sensitivity certificate digest changed.",
         call. = FALSE)
  }
  bridge_sha256 <- .dsvert_formal_glm_phase18_domain_sha256(
    .DSVERT_FORMAL_GLM_PHASE19_DP_BRIDGE_DOMAIN, bridge)
  upper <- unlist(bridge$shifted_upper_bounds, use.names = FALSE)
  if (!is.character(upper) || length(upper) != state$vector_len ||
      anyNA(upper) || any(nchar(upper, type = "bytes") > 39L) ||
      any(!grepl("^[1-9][0-9]*$", upper))) {
    stop("Invalid formal-GLM translated bridge range.", call. = FALSE)
  }
  ring128_max <- openssl::bignum(2) ^ 127L - openssl::bignum(1)
  selected_sensitivity <- bridge$selected_sensitivity_steps
  if (!is.character(selected_sensitivity) ||
      length(selected_sensitivity) != 1L || is.na(selected_sensitivity) ||
      nchar(selected_sensitivity, type = "bytes") > 39L ||
      !grepl("^[1-9][0-9]*$", selected_sensitivity) ||
      openssl::bignum(selected_sensitivity) > ring128_max) {
    stop("Invalid formal-GLM selected Ring128 sensitivity.", call. = FALSE)
  }
  centers <- vapply(upper, function(value) {
    value <- openssl::bignum(value)
    if (value <= 0 || value > ring128_max ||
        value %% openssl::bignum(2) != 0) {
      stop("Invalid formal-GLM translated bridge range.", call. = FALSE)
    }
    as.character(value %/% openssl::bignum(2))
  }, character(1L))
  release_projection <- list(
    version = .DSVERT_FORMAL_GLM_PHASE16_RELEASE_VERSION,
    binding_sha256 = bridge_sha256,
    common_ring_bits = bridge$output_ring_bits,
    output_lattice_bits = output_lattice_bits,
    coordinate_count = bridge$coordinate_count,
    shifted_upper_bounds = as.list(upper),
    signed_lower_bounds = as.list(paste0("-", centers)),
    signed_upper_bounds = as.list(centers),
    sensitivity_steps = bridge$selected_sensitivity_steps,
    mechanism = .DSVERT_FORMAL_GLM_PHASE16_MECHANISM,
    allocation = .DSVERT_FORMAL_GLM_PHASE16_ALLOCATION,
    sensitivity_norm = "l2",
    sensitivity_proof = bridge$selected_sensitivity_proof,
    sensitivity_certificate_kind = certificate$kind,
    sensitivity_certificate_sha256 = certificate_sha256,
    sensitivity_certificate = certificate,
    tight_sensitivity_status = tight$status,
    quantization =
      "signed_floor_inside_exact_gc_then_public_translation_v1",
    signed_decode =
      "subtract_public_quantized_box_after_single_dp_opening_v1",
    quantization_error = paste0(
      "0<=exact_coefficient-released_lattice_coefficient<",
      "2^-output_lattice_bits_before_dp_noise_v1"),
    range_certificate = paste0(
      "translated_coordinate_in_[0,2Bq]_and_signed_release_",
      "in_[-Bq,Bq]_v1"),
    no_wrap_certificate = paste0(
      "bridge_coordinates_l2_sensitivity_and_common_gaussian_",
      "saturating_clamp_ring128_checked_v1"),
    opening_count = 1L, production_ready = FALSE)
  .dsvert_formal_glm_phase16_binding_projection(release_projection)
  list(bridge_sha256 = bridge_sha256,
       release_projection = release_projection)
}

.dsvert_formal_glm_phase19_phase15_binding_unchecked <- function(
    result, bridge_sha256) {
  bridge <- result$dp_bridge
  peer_ids <- c(
    stats::setNames(bridge$garbler_peer_id, bridge$garbler_peer_name),
    stats::setNames(bridge$evaluator_peer_id, bridge$evaluator_peer_name))
  binding <- .dsvert_formal_glm_phase15_dsi_binding(
    plan_sha256 = bridge$phase15_plan_sha256,
    final_receipt_pair_sha256 = bridge$final_receipt_pair_sha256,
    execution_transcript_sha256 = bridge$execution_transcript_sha256,
    bridge_sha256 = bridge_sha256,
    snapshot_sha256 = bridge$snapshot_sha256,
    pinset_sha256 = bridge$pinset_sha256,
    peer_ids = peer_ids)
  .dsvert_formal_glm_phase15_dsi_binding_validate(binding)
  if (!identical(binding$garbler_peer_name, bridge$garbler_peer_name) ||
      !identical(binding$evaluator_peer_name, bridge$evaluator_peer_name)) {
    stop("The Phase-1.9 result changed the pinned Phase-1.5 roles.",
         call. = FALSE)
  }
  binding
}

.dsvert_formal_glm_phase19_validate_result <- function(state, result) {
  top_fields <- c(
    "version", "kind", "context_sha256", "plan_sha256",
    "semantic_root_sha256", "schedule_root_sha256", "peer", "attempt_id",
    "final_receipts",
    "dp_bridge", "dp_share", "post_execution_token",
    "post_execution_token_seal", "execution_receipt_pair",
    "execution_receipt_pair_seal", "handoff_sha256", "handoff_bytes",
    "handoff_replayed", "execution_valid_sealed",
    "execution_validity_opened", "openings_performed", "production_ready")
  state_fields <- c(
    "vector_len", "formal_plan_sha256", "formal_kernel_spec_sha256",
    "formal_semantic_root_sha256", "formal_runtime_root_sha256",
    "formal_recipient", "worker_heartbeat_session",
    "formal_pre_execution_sha256", "formal_capsule_sha256",
    "formal_snapshot_sha256", "formal_garbler_peer_name",
    "formal_garbler_peer_id", "formal_evaluator_peer_name",
    "formal_evaluator_peer_id", "formal_adjacency",
    "formal_source_ring_bits", "formal_source_frac_bits",
    "formal_final_step_index", "formal_global_materialization_root",
    "formal_run_id", "formal_pinset_sha256", "formal_compute_peers",
    "formal_custodian_count")
  if (!is.environment(state) || !is.list(result) ||
      !all(vapply(state_fields, exists, logical(1L), envir = state,
                  inherits = FALSE)) ||
      !identical(names(result), top_fields) ||
      !identical(result$version,
                 .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_RESULT_VERSION) ||
      !identical(result$kind,
                 .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_RESULT_KIND) ||
      !identical(result$plan_sha256, state$formal_plan_sha256) ||
      !identical(result$semantic_root_sha256,
                 state$formal_semantic_root_sha256) ||
      !identical(result$schedule_root_sha256,
                 state$formal_runtime_root_sha256) ||
      !identical(result$peer, state$formal_recipient) ||
      !identical(result$attempt_id, state$worker_heartbeat_session) ||
      !is.logical(result$handoff_replayed) ||
      length(result$handoff_replayed) != 1L ||
      is.na(result$handoff_replayed) ||
      !identical(result$execution_valid_sealed, TRUE) ||
      !identical(result$execution_validity_opened, FALSE) ||
      .dsvert_formal_glm_phase19_integer(
        result$openings_performed, "Phase-1.9 result openings", 0, 0) != 0L ||
      !identical(result$production_ready, FALSE)) {
    stop("Invalid private formal-GLM schedule result.", call. = FALSE)
  }
  context_sha256 <- .dsvert_formal_glm_phase19_hex(
    result$context_sha256, "Phase-1.9 result context")
  .dsvert_formal_glm_phase19_hex(
    result$handoff_sha256, "Phase-2.0 handoff")
  .dsvert_formal_glm_phase19_integer(
    result$handoff_bytes, "Phase-2.0 handoff bytes", 64,
    .DSVERT_FORMAL_GLM_PHASE20_HANDOFF_MAX_BYTES)
  .dsvert_formal_glm_phase19_hex(
    result$post_execution_token_seal, "Phase-1.9 post-token seal")
  .dsvert_formal_glm_phase19_hex(
    result$execution_receipt_pair_seal,
    "Phase-1.9 execution-receipt-pair seal")
  .exact_gc_validate_residue_records(
    result$dp_share, 128L, state$vector_len,
    "private formal-GLM Ring128 DP-bridge share")
  if (!is.list(result$final_receipts) ||
      length(result$final_receipts) != 2L ||
      !is.list(result$dp_bridge) ||
      !is.list(result$post_execution_token) ||
      !is.list(result$execution_receipt_pair)) {
    stop("Incomplete private formal-GLM schedule result.", call. = FALSE)
  }
  bridge <- result$dp_bridge
  bridge_fields <- c(
    "version", "phase15_plan_sha256", "final_receipt_pair_sha256",
    "execution_transcript_sha256", "snapshot_sha256", "pinset_sha256",
    "garbler_peer_name", "garbler_peer_id", "evaluator_peer_name",
    "evaluator_peer_id", "role_selection", "adjacency",
    "source_ring_bits", "source_frac_bits", "output_ring_bits",
    "output_lattice_bits", "quantization_shift", "coordinate_count",
    "shifted_upper_bounds", "universal_sensitivity", "tight_sensitivity",
    "selected_sensitivity_steps", "selected_sensitivity_proof",
    "selected_sensitivity_certificate",
    "selected_sensitivity_certificate_sha256", "sensitivity_selection",
    "quantization", "intermediate_output", "authenticated_opening",
    "production_ready")
  if (!identical(names(bridge), bridge_fields) ||
      !identical(bridge$phase15_plan_sha256, state$formal_plan_sha256) ||
      .dsvert_formal_glm_phase19_integer(
        bridge$output_ring_bits, "formal-GLM DP bridge output ring",
        128, 128) != 128L ||
      .dsvert_formal_glm_phase19_integer(
        bridge$coordinate_count, "formal-GLM DP bridge coordinate count",
        state$vector_len, state$vector_len) != state$vector_len ||
      !identical(bridge$production_ready, FALSE)) {
    stop("Invalid private formal-GLM DP bridge.", call. = FALSE)
  }
  final_receipt_pair_sha256 <-
    .dsvert_formal_glm_phase19_receipt_pair_sha256(
      result$final_receipts, state)
  if (!identical(final_receipt_pair_sha256,
                 bridge$final_receipt_pair_sha256)) {
    stop("The private formal-GLM bridge changed its final receipt pair.",
         call. = FALSE)
  }
  bridge_projection <- .dsvert_formal_glm_phase19_bridge_projection(
    state, bridge)
  token <- result$post_execution_token
  token_fields <- c(
    "version", "context_sha256", "capsule_sha256",
    "phase15_plan_sha256", "pre_execution_token_sha256", "run_id",
    "pinset_sha256", "global_materialization_root",
    "fan_in_transcript_sha256", "block_commitment_root_sha256",
    "block_receipt_root_sha256", "accumulator_root",
    "execution_receipt_pair_sha256", "final_receipt_set_seal",
    "checkpoint_evidence_seal", "phase15_execution_transcript_sha256",
    "final_checkpoint_transcript_sha256", "worker_transcript_sha256",
    "post_execution_root_sha256", "token_sha256", "custodian_count",
    "compute_peers", "fan_in_executed", "exact_all_k_validity_inside_gc",
    "consensus_compared_inside_gc", "full_tuple_mask_inside_gc",
    "execution_valid_sealed", "execution_validity_opened",
    "patient_dependent_digests_exposed", "protected_data_e2e_verified",
    "opening_authorized", "openings_performed", "dp_release_status",
    "remaining_blockers", "production_ready")
  token_hash_fields <- c(
    "context_sha256", "capsule_sha256", "phase15_plan_sha256",
    "pre_execution_token_sha256", "pinset_sha256",
    "global_materialization_root", "fan_in_transcript_sha256",
    "block_commitment_root_sha256", "block_receipt_root_sha256",
    "accumulator_root", "execution_receipt_pair_sha256",
    "final_receipt_set_seal", "checkpoint_evidence_seal",
    "phase15_execution_transcript_sha256",
    "final_checkpoint_transcript_sha256", "worker_transcript_sha256",
    "post_execution_root_sha256", "token_sha256")
  if (!identical(names(token), token_fields) ||
      !all(vapply(token[token_hash_fields], function(value) {
        is.character(value) && length(value) == 1L && !is.na(value) &&
          grepl("^[0-9a-f]{64}$", value)
      }, logical(1L))) ||
      !identical(token$version,
                 .DSVERT_FORMAL_GLM_PHASE19_POST_TOKEN_VERSION) ||
      !identical(token$context_sha256, context_sha256) ||
      !identical(token$capsule_sha256, state$formal_capsule_sha256) ||
      !identical(token$phase15_plan_sha256, state$formal_plan_sha256) ||
      !identical(token$pre_execution_token_sha256,
                 state$formal_pre_execution_sha256) ||
      !identical(token$global_materialization_root,
                 state$formal_global_materialization_root) ||
      !identical(token$run_id, state$formal_run_id) ||
      !identical(token$pinset_sha256, state$formal_pinset_sha256) ||
      !identical(token$phase15_execution_transcript_sha256,
                 bridge$execution_transcript_sha256) ||
      !identical(token$final_checkpoint_transcript_sha256,
                 bridge$execution_transcript_sha256) ||
      !identical(unname(unlist(token$compute_peers, use.names = FALSE)),
                 state$formal_compute_peers) ||
      .dsvert_formal_glm_phase19_integer(
        token$custodian_count, "formal-GLM token custodian count",
        state$formal_custodian_count,
        state$formal_custodian_count) != state$formal_custodian_count ||
      !identical(token$fan_in_executed, TRUE) ||
      !identical(token$exact_all_k_validity_inside_gc, TRUE) ||
      !identical(token$consensus_compared_inside_gc, TRUE) ||
      !identical(token$full_tuple_mask_inside_gc, TRUE) ||
      !identical(token$execution_valid_sealed, TRUE) ||
      !identical(token$execution_validity_opened, FALSE) ||
      !identical(token$patient_dependent_digests_exposed, FALSE) ||
      !identical(token$protected_data_e2e_verified, FALSE) ||
      !identical(token$opening_authorized, FALSE) ||
      .dsvert_formal_glm_phase19_integer(
        token$openings_performed, "formal-GLM token openings", 0, 0) != 0L ||
      !identical(token$dp_release_status,
                 .DSVERT_FORMAL_GLM_PHASE19_DP_STATUS) ||
      !identical(unname(unlist(
        token$remaining_blockers, use.names = FALSE)),
        .DSVERT_FORMAL_GLM_PHASE19_BLOCKERS) ||
      !identical(token$production_ready, FALSE)) {
    stop("Invalid private formal-GLM post-execution token.", call. = FALSE)
  }
  token_preimage <- token
  token_preimage$token_sha256 <- ""
  if (!identical(token$token_sha256,
      .dsvert_formal_glm_phase19_prefixed_json_sha256(
        .DSVERT_FORMAL_GLM_PHASE19_POST_TOKEN_DOMAIN,
        token_preimage))) {
    stop("The private formal-GLM post-execution token digest changed.",
         call. = FALSE)
  }
  pair <- result$execution_receipt_pair
  pair_fields <- c(
    "version", "context_sha256", "accumulator_root",
    "garbler_receipt_sha256", "evaluator_receipt_sha256",
    "execution_receipt_pair_sha256", "execution_valid_sealed",
    "execution_validity_opened", "openings_performed", "production_ready")
  if (!identical(names(pair), pair_fields) ||
      !identical(pair$version,
                 .DSVERT_FORMAL_GLM_PHASE19_EXECUTION_PAIR_VERSION) ||
      !identical(pair$context_sha256, context_sha256) ||
      !identical(pair$accumulator_root, token$accumulator_root) ||
      !identical(pair$execution_receipt_pair_sha256,
                 token$execution_receipt_pair_sha256) ||
      !identical(pair$execution_valid_sealed, TRUE) ||
      !identical(pair$execution_validity_opened, FALSE) ||
      .dsvert_formal_glm_phase19_integer(
        pair$openings_performed, "formal-GLM execution-pair openings",
        0, 0) != 0L ||
      !identical(pair$production_ready, FALSE)) {
    stop("Invalid private formal-GLM execution receipt pair.", call. = FALSE)
  }
  invisible(.dsvert_formal_glm_phase19_phase15_binding_unchecked(
    result, bridge_projection$bridge_sha256))
  invisible(result)
}

.dsvert_formal_glm_phase19_phase15_binding <- function(state, result) {
  .dsvert_formal_glm_phase19_validate_result(state, result)
  bridge_sha256 <- .dsvert_formal_glm_phase18_domain_sha256(
    .DSVERT_FORMAL_GLM_PHASE19_DP_BRIDGE_DOMAIN, result$dp_bridge)
  .dsvert_formal_glm_phase19_phase15_binding_unchecked(
    result, bridge_sha256)
}

.dsvert_formal_glm_phase19_private_outputs <- function(ss) {
  if (!is.environment(ss$.formal_glm_phase19_outputs)) {
    ss$.formal_glm_phase19_outputs <- new.env(parent = emptyenv())
  }
  ss$.formal_glm_phase19_outputs
}

.dsvert_formal_glm_phase19_drop_output <- function(ss, operation_id) {
  if (is.environment(ss$.formal_glm_phase19_outputs) &&
      is.character(operation_id) && length(operation_id) == 1L) {
    ss$.formal_glm_phase19_outputs[[operation_id]] <- NULL
  }
  invisible(TRUE)
}

.dsvert_formal_glm_phase20_file_seal <- function(path, bytes, sha256) {
  if (!is.character(path) || length(path) != 1L || is.na(path) ||
      !is.numeric(bytes) || length(bytes) != 1L || is.na(bytes) ||
      !is.character(sha256) || length(sha256) != 1L || is.na(sha256) ||
      !grepl("^[0-9a-f]{64}$", sha256)) {
    stop("The private Phase-2.0 handoff seal is invalid.", call. = FALSE)
  }
  snapshot <- function() {
    info <- tryCatch(
      fs::file_info(path, follow = FALSE), error = function(error) NULL)
    if (is.null(info) || nrow(info) != 1L || is.na(info$type) ||
        !identical(as.character(info$type[[1L]]), "file") ||
        anyNA(c(info$size, info$device_id, info$inode, info$hard_links,
                info$modification_time, info$change_time))) {
      stop("The private Phase-2.0 handoff metadata is invalid.",
           call. = FALSE)
    }
    links <- as.numeric(info$hard_links[[1L]])
    permissions <- as.character(info$permissions[[1L]])
    owner <- Sys.info()[["user"]]
    observed_owner <- as.character(info$user[[1L]])
    if (as.numeric(info$size[[1L]]) != as.numeric(bytes) ||
        (.Platform$OS.type == "unix" &&
         (!identical(links, 1) || !identical(permissions, "rw-------") ||
          !is.character(owner) || length(owner) != 1L || !nzchar(owner) ||
          !identical(observed_owner, owner)))) {
      stop("The private Phase-2.0 handoff is not an owner-only single link.",
           call. = FALSE)
    }
    list(
      device_id = as.numeric(info$device_id[[1L]]),
      inode = as.numeric(info$inode[[1L]]),
      size = as.numeric(info$size[[1L]]), hard_links = links,
      permissions = permissions,
      modification_time = as.numeric(info$modification_time[[1L]]))
  }
  before <- snapshot()
  observed <- digest::digest(
    file = path, algo = "sha256", serialize = FALSE)
  after <- snapshot()
  if (!identical(before, after) || !identical(observed, sha256)) {
    stop("The private Phase-2.0 handoff changed while it was authenticated.",
         call. = FALSE)
  }
  c(before, list(sha256 = observed))
}

.dsvert_formal_glm_phase20_handoff_handle <- function(state, result) {
  if (!is.environment(state) ||
      !exists("formal_handoff_dir", envir = state, inherits = FALSE) ||
      !is.character(state$formal_handoff_dir) ||
      length(state$formal_handoff_dir) != 1L ||
      is.na(state$formal_handoff_dir) ||
      !dir.exists(state$formal_handoff_dir) ||
      nzchar(Sys.readlink(state$formal_handoff_dir))) {
    stop("The private Phase-2.0 handoff directory is unavailable.",
         call. = FALSE)
  }
  root <- normalizePath(
    state$formal_handoff_dir, winslash = "/", mustWork = TRUE)
  paths <- list.files(
    root, pattern = "^slot-[0-9a-f]{64}\\.bin$",
    recursive = TRUE, full.names = TRUE, all.files = TRUE,
    no.. = TRUE)
  if (length(paths) != 1L || nzchar(Sys.readlink(paths))) {
    stop("The private Phase-2.0 handoff slot is incomplete.", call. = FALSE)
  }
  path <- normalizePath(paths, winslash = "/", mustWork = TRUE)
  if (!startsWith(path, paste0(root, "/"))) {
    stop("The private Phase-2.0 handoff escaped its durable root.",
         call. = FALSE)
  }
  bytes <- .dsvert_formal_glm_phase19_integer(
    result$handoff_bytes, "Phase-2.0 handoff bytes", 64,
    .DSVERT_FORMAL_GLM_PHASE20_HANDOFF_MAX_BYTES)
  file_seal <- .dsvert_formal_glm_phase20_file_seal(
    path, bytes, result$handoff_sha256)
  owner <- .dsvert_resource_external_owner("formal-glm-handoff", path)
  list(
    version = "dsvert-formal-glm-phase20-handoff-handle-v1",
    semantic_root_sha256 = state$formal_semantic_root_sha256,
    peer = state$formal_recipient, sha256 = result$handoff_sha256,
    bytes = bytes, replayed = result$handoff_replayed,
    path = path, file_seal = file_seal, resource_owner = owner,
    releasable = FALSE, openings_performed = 0L,
    production_ready = FALSE)
}

.dsvert_formal_glm_phase20_account_handoff <- function(handle) {
  if (!is.list(handle) ||
      !identical(handle$version,
                 "dsvert-formal-glm-phase20-handoff-handle-v1") ||
      !is.character(handle$resource_owner) ||
      !grepl("^external-[0-9a-f]{64}$", handle$resource_owner) ||
      !is.numeric(handle$bytes) || length(handle$bytes) != 1L) {
    stop("The private Phase-2.0 handoff handle is invalid.", call. = FALSE)
  }
  current <- .dsvert_resource_registry$external[[handle$resource_owner]]
  retained <- if (is.list(current) && is.numeric(current$bytes) &&
      length(current$bytes) == 1L && !is.na(current$bytes)) {
    as.numeric(current$bytes)
  } else 0
  additional <- max(0, as.numeric(handle$bytes) - retained)
  .dsvert_resource_admit_external(
    handle$resource_owner, retained, additional, "formal-glm-handoff")
  .dsvert_resource_external_reconcile(
    handle$resource_owner, handle$bytes, "formal-glm-handoff")
  invisible(handle$resource_owner)
}

.dsvert_formal_glm_phase20_cleanup_handoff <- function(handle) {
  if (!is.list(handle) ||
      !identical(handle$version,
                 "dsvert-formal-glm-phase20-handoff-handle-v1") ||
      !is.character(handle$path) || length(handle$path) != 1L ||
      is.na(handle$path) || !file.exists(handle$path) ||
      nzchar(Sys.readlink(handle$path)) ||
      !is.list(handle$file_seal) ||
      !is.character(handle$sha256) ||
      !grepl("^[0-9a-f]{64}$", handle$sha256) ||
      !is.numeric(handle$bytes) || length(handle$bytes) != 1L ||
      is.na(handle$bytes) || !is.character(handle$resource_owner) ||
      length(handle$resource_owner) != 1L ||
      !grepl("^external-[0-9a-f]{64}$", handle$resource_owner)) {
    stop("The private Phase-2.0 cleanup handle is invalid.", call. = FALSE)
  }
  observed <- .dsvert_formal_glm_phase20_file_seal(
    handle$path, handle$bytes, handle$sha256)
  if (!identical(observed, handle$file_seal)) {
    stop("The private Phase-2.0 cleanup identity does not match its slot.",
         call. = FALSE)
  }
  token <- paste(sprintf("%02x", as.integer(
    .dsvert_secure_random_bytes(16L))), collapse = "")
  quarantine <- file.path(
    dirname(handle$path), paste0(".phase20-consume-", token, ".bin"))
  quarantine_link <- Sys.readlink(quarantine)
  if (file.exists(quarantine) || dir.exists(quarantine) ||
      (!is.na(quarantine_link) && nzchar(quarantine_link)) ||
      !isTRUE(file.rename(handle$path, quarantine))) {
    stop("The private Phase-2.0 handoff could not be removed.", call. = FALSE)
  }
  quarantined <- tryCatch(
    .dsvert_formal_glm_phase20_file_seal(
      quarantine, handle$bytes, handle$sha256),
    error = function(error) error)
  if (inherits(quarantined, "error") ||
      !identical(quarantined, handle$file_seal)) {
    stop("The private Phase-2.0 handoff changed before quarantine cleanup.",
         call. = FALSE)
  }
  if (!isTRUE(unlink(quarantine) == 0L) || file.exists(quarantine)) {
    stop("The private Phase-2.0 handoff quarantine could not be removed.",
         call. = FALSE)
  }
  .dsvert_resource_external_unregister(handle$resource_owner)
  invisible(TRUE)
}

.dsvert_formal_glm_phase19_finish <- function(ss, state) {
  result_path <- file.path(state$spool, "result.json")
  bytes <- tryCatch(.dsvert_formal_glm_phase18_private_file(
    result_path, minimum_bytes = 2L, maximum_bytes = 16L * 1024L^2),
    error = function(error) NULL)
  result_json <- if (is.raw(bytes)) rawToChar(bytes) else NULL
  result <- if (is.character(result_json)) tryCatch(
    jsonlite::fromJSON(result_json, simplifyVector = FALSE),
    error = function(error) NULL) else NULL
  output <- tryCatch({
    .dsvert_formal_glm_phase19_validate_result(state, result)
    bridge_sha256 <- .dsvert_formal_glm_phase18_domain_sha256(
      .DSVERT_FORMAL_GLM_PHASE19_DP_BRIDGE_DOMAIN, result$dp_bridge)
    phase15_binding <-
      .dsvert_formal_glm_phase19_phase15_binding_unchecked(
        result, bridge_sha256)
    handoff <- .dsvert_formal_glm_phase20_handoff_handle(state, result)
    list(
      version = .DSVERT_FORMAL_GLM_PHASE19_SCHEDULE_RESULT_VERSION,
      operation_id = state$operation_id,
      semantic_root_sha256 = state$formal_semantic_root_sha256,
      handoff = handoff,
      phase15_binding = phase15_binding,
      phase16_release_available = FALSE,
      phase16_release_blocker = .DSVERT_FORMAL_GLM_PHASE15_DP_BLOCKER,
      releasable = FALSE, openings_performed = 0L,
      production_ready = FALSE)
  }, error = function(error) {
    .exact_gc_mark_failed(ss, state, "infrastructure_unavailable")
    stop(error)
  })
  .exact_gc_compact_resource_reservation(state)
  tryCatch(
    .dsvert_formal_glm_phase20_account_handoff(output$handoff),
    error = function(error) {
      .exact_gc_mark_failed(ss, state, "infrastructure_unavailable")
      stop(error)
    })
  outputs <- .dsvert_formal_glm_phase19_private_outputs(ss)
  existing <- outputs[[state$operation_id]]
  if (!is.null(existing) && !identical(existing, output)) {
    .exact_gc_mark_failed(ss, state, "infrastructure_unavailable")
    stop("Conflicting private formal-GLM result.", call. = FALSE)
  }
  outputs[[state$operation_id]] <- output
  unlink(result_path)
  state$status <- "complete"
  state$worker_heartbeat_key <- raw()
  .session_progress(ss)
  state$status
}
