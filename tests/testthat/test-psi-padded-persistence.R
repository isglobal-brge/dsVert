test_that("padded PSI journal is encrypted, authenticated and restart-durable", {
  root <- tempfile("dsvert-psi-padded-state-")
  dir.create(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  seed <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(91L, 32L))))
  old <- options(
    dsvert.state_dir = root,
    dsvert.identity_seed = seed,
    dsvert.psi.padded.persist_in_tests = TRUE,
    dsvert.psi.pseudonym_mode = "none",
    dsvert.psi.require_keyed_pseudonyms = FALSE,
    dsvert.psi.max_input_ids = 64L,
    dsvert.psi.padded_missing_policy = "id_only")
  on.exit(options(old), add = TRUE)
  data <- data.frame(
    patient_id = c("patient-secret-alpha", "patient-secret-beta"),
    value = 1:2, stringsAsFactors = FALSE)
  withr::local_options(.psi_padded_test_source_options(
    data, id_col = "patient_id"))
  session_id <- "32345678-1234-4234-9234-123456789abc"
  operation_id <- paste0("op_", strrep("d", 32L))
  ss <- new.env(parent = emptyenv())
  offer <- .psi_padded_init_impl(
    ss, data, "D", "patient_id", session_id, operation_id)
  state <- ss$.psi_padded_state
  path <- .psi_padded_journal_path(
    session_id, state$self_peer_id, allow_test_path = TRUE)
  expect_true(file.exists(path))
  encoded <- readBin(path, "raw", n = file.size(path))
  needle <- charToRaw("patient-secret")
  contains <- any(vapply(
    seq_len(length(encoded) - length(needle) + 1L), function(index) {
      identical(encoded[seq.int(index, length.out = length(needle))], needle)
    }, logical(1L)))
  expect_false(contains)

  restarted <- new.env(parent = emptyenv())
  expect_true(.psi_padded_state_restore(restarted, session_id))
  expect_identical(restarted$.psi_padded_state$bootstrap, offer)
  expect_identical(restarted$.psi_padded_state$selected_ids,
                   data$patient_id)
  expect_true(is.environment(restarted$.psi_padded_state$replay_cache))

  tampered <- encoded
  tampered[[length(tampered)]] <- as.raw(bitwXor(
    as.integer(tampered[[length(tampered)]]), 1L))
  connection <- file(path, open = "wb")
  writeBin(tampered, connection)
  close(connection)
  Sys.chmod(path, mode = "0600")
  expect_error(
    .psi_padded_journal_read(
      session_id, state$self_peer_id, allow_test_path = TRUE),
    "authentication failed")

  .psi_padded_journal_write(state, allow_test_path = TRUE)
  expect_silent(.psi_padded_journal_read(
    session_id, state$self_peer_id, allow_test_path = TRUE))
  expect_true(.psi_padded_state_delete(state))
  expect_false(file.exists(path))
})

test_that("padded PSI journals share the process-wide byte cap", {
  root <- tempfile("dsvert-psi-padded-cap-")
  dir.create(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  seed <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(93L, 32L))))
  old <- options(
    dsvert.state_dir = root,
    dsvert.identity_seed = seed,
    dsvert.psi.padded.persist_in_tests = TRUE,
    dsvert.psi.padded.journal_max_bytes = 1024^2,
    dsvert.transport.global_spool_max_bytes = 1024^2)
  on.exit(options(old), add = TRUE)
  identity <- .get_identity_keypair()
  peer_id <- .dsvert_relay_peer_id(identity$identity_pk)
  make_state <- function(index, payload_bytes = 600L * 1024L) list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = sprintf("%08d-0000-4000-8000-%012d", index, index),
    operation_id = paste0("op_", sprintf("%032x", index)),
    self_peer_id = peer_id,
    identity_pk = identity$identity_pk,
    phase = "initialized",
    replay_cache = new.env(parent = emptyenv()),
    byte_payload = raw(payload_bytes))
  baseline <- .dsvert_resource_retained_bytes()
  small <- lapply(10:41, make_state, payload_bytes = 0L)
  expect_silent(lapply(
    small, .psi_padded_journal_write, allow_test_path = TRUE))
  expect_true(all(vapply(small, .psi_padded_state_delete, logical(1L))))
  expect_identical(.dsvert_resource_retained_bytes(), baseline)

  first <- make_state(1L)
  second <- make_state(2L)

  expect_silent(.psi_padded_journal_write(first, allow_test_path = TRUE))
  first_path <- .psi_padded_journal_path(
    first$session_id, peer_id, allow_test_path = TRUE)
  first_owner <- .psi_padded_journal_resource_owner(first_path)
  expect_identical(
    .dsvert_resource_registry$external[[first_owner]]$bytes,
    as.numeric(file.size(first_path)))
  expect_identical(
    .dsvert_resource_retained_bytes(),
    baseline + as.numeric(file.size(first_path)))
  expect_error(
    .psi_padded_journal_write(second, allow_test_path = TRUE),
    "resource_backpressure", class = "dsvert_resource_backpressure")
  expect_false(file.exists(.psi_padded_journal_path(
    second$session_id, peer_id, allow_test_path = TRUE)))

  expect_true(.psi_padded_state_delete(first))
  expect_silent(.psi_padded_journal_write(second, allow_test_path = TRUE))
  expect_true(.psi_padded_state_delete(second))
})

test_that("identity rotation retires stale PSI journals without byte debt", {
  root <- tempfile("dsvert-psi-padded-rotation-")
  dir.create(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  seed_a <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(101L, 32L))))
  seed_b <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(103L, 32L))))
  retained_before <- .dsvert_resource_retained_bytes()
  old <- options(
    dsvert.state_dir = root,
    dsvert.identity_seed = seed_a,
    dsvert.psi.padded.persist_in_tests = TRUE,
    dsvert.psi.padded.journal_max_bytes = 1024^2,
    dsvert.transport.global_spool_max_bytes = retained_before + 1024^2)
  on.exit(options(old), add = TRUE)

  identity_a <- .get_identity_keypair()
  peer_a <- .dsvert_relay_peer_id(identity_a$identity_pk)
  state_a <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = "62345678-1234-4234-9234-123456789abc",
    operation_id = paste0("op_", strrep("6", 32L)),
    self_peer_id = peer_a,
    identity_pk = identity_a$identity_pk,
    phase = "initialized",
    replay_cache = new.env(parent = emptyenv()),
    byte_payload = raw(600L * 1024L))
  on.exit(try(.psi_padded_state_delete(state_a), silent = TRUE), add = TRUE)
  .psi_padded_journal_write(state_a, allow_test_path = TRUE)
  path_a <- .psi_padded_journal_path(
    state_a$session_id, peer_a, allow_test_path = TRUE)
  owner_a <- .psi_padded_journal_resource_owner(path_a)
  expect_true(file.exists(path_a))
  expect_true(owner_a %in% names(.dsvert_resource_registry$external))

  options(dsvert.identity_seed = seed_b)
  identity_b <- .get_identity_keypair()
  peer_b <- .dsvert_relay_peer_id(identity_b$identity_pk)
  expect_false(identical(peer_a, peer_b))
  state_b <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = "72345678-1234-4234-9234-123456789abc",
    operation_id = paste0("op_", strrep("7", 32L)),
    self_peer_id = peer_b,
    identity_pk = identity_b$identity_pk,
    phase = "initialized",
    replay_cache = new.env(parent = emptyenv()),
    byte_payload = raw(600L * 1024L))
  on.exit(try(.psi_padded_state_delete(state_b), silent = TRUE), add = TRUE)

  # The write's first-use sweep retires the previous identity namespace before
  # byte admission, so the old encrypted state cannot cause backpressure.
  expect_silent(.psi_padded_journal_write(
    state_b, allow_test_path = TRUE))
  expect_false(file.exists(path_a))
  expect_false(owner_a %in% names(.dsvert_resource_registry$external))
  expect_true(.psi_padded_state_delete(state_b))
})

test_that("restart sweep authenticates TTL expiry and never follows links", {
  skip_if_not(identical(.Platform$OS.type, "unix"))
  root <- tempfile("dsvert-psi-padded-ttl-")
  dir.create(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  seed <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(95L, 32L))))
  old <- options(
    dsvert.state_dir = root,
    dsvert.identity_seed = seed,
    dsvert.psi.padded.persist_in_tests = TRUE,
    dsvert.psi.padded.journal_ttl_seconds = 10L)
  on.exit(options(old), add = TRUE)
  identity <- .get_identity_keypair()
  peer_id <- .dsvert_relay_peer_id(identity$identity_pk)
  state <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = "42345678-1234-4234-9234-123456789abc",
    operation_id = paste0("op_", strrep("4", 32L)),
    self_peer_id = peer_id,
    identity_pk = identity$identity_pk,
    phase = "initialized",
    replay_cache = new.env(parent = emptyenv()))
  testthat::with_mocked_bindings(
    .psi_padded_journal_write(state, allow_test_path = TRUE),
    .session_now = function() 100,
    .package = "dsVert")
  path <- .psi_padded_journal_path(
    state$session_id, peer_id, allow_test_path = TRUE)
  owner <- .psi_padded_journal_resource_owner(path)
  expect_true(file.exists(path))

  # Emulate a fresh worker: its in-memory registry and first-use marker have
  # not yet seen the durable journal.
  .dsvert_resource_external_unregister(owner)
  rm(list = ls(.psi_padded_journal_swept, all.names = TRUE),
     envir = .psi_padded_journal_swept)
  active <- .psi_padded_journal_sweep(
    peer_id, now = 110, force = TRUE, allow_test_path = TRUE)
  expect_identical(active$scanned, 1L)
  expect_identical(active$expired, 0L)
  expect_true(file.exists(path))
  expect_identical(
    .dsvert_resource_registry$external[[owner]]$bytes,
    as.numeric(file.size(path)))
  swept <- .psi_padded_journal_sweep(
    peer_id, now = 111, force = TRUE, allow_test_path = TRUE)
  expect_identical(swept$scanned, 1L)
  expect_identical(swept$expired, 1L)
  expect_false(file.exists(path))
  expect_false(owner %in% names(.dsvert_resource_registry$external))

  sentinel <- tempfile("dsvert-psi-sweep-sentinel-")
  writeLines("must-survive", sentinel, useBytes = TRUE)
  on.exit(unlink(sentinel, force = TRUE), add = TRUE)
  linked_session <- "52345678-1234-4234-9234-123456789abc"
  linked_path <- file.path(dirname(path), paste0(linked_session, ".state"))
  expect_true(file.symlink(sentinel, linked_path))
  linked <- .psi_padded_journal_sweep(
    peer_id, now = 112, force = TRUE, allow_test_path = TRUE)
  expect_gte(linked$invalid, 1L)
  expect_identical(readLines(sentinel, warn = FALSE), "must-survive")
  expect_true(file.exists(sentinel))
})

test_that("successful PSI attestation retains only a compact replay receipt", {
  root <- tempfile("dsvert-psi-padded-compact-")
  dir.create(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE, force = TRUE), add = TRUE)
  seed <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(97L, 32L))))
  old <- options(
    dsvert.state_dir = root,
    dsvert.identity_seed = seed,
    dsvert.psi.padded.persist_in_tests = TRUE)
  on.exit(options(old), add = TRUE)
  identity <- .get_identity_keypair()
  peer_id <- .dsvert_relay_peer_id(identity$identity_pk)
  token <- base64_to_base64url(jsonlite::base64_enc(as.raw(0:31)))
  source <- .psi_padded_test_source_public("patient_id")
  contract <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = "62345678-1234-4234-9234-123456789abc",
    operation_id = paste0("op_", strrep("6", 32L)),
    contract_hash = strrep("a", 64L),
    attestation_id = paste0("attest_", strrep("b", 64L)),
    policy_id = paste0("policy_", strrep("c", 64L)),
    alignment_purpose = source$alignment_purpose,
    dataset_id = source$dataset_id,
    dataset_version = source$dataset_version,
    id_column = source$id_column,
    source_binding_id = source$source_binding_id,
    pinset_id = paste0("pinset_", strrep("d", 64L)),
    capacity = 64L,
    relay_frame_bytes = 65536L,
    inline_max_bytes = 65536L,
    peer_names = c("site_a", "site_b"),
    reference_peer = "site_a",
    compute_peers = c("site_a", "site_b"))
  aligned <- .psi_attach_alignment_manifest(data.frame(
    patient_id = sprintf("private-patient-%02d", 1:6),
    value = seq_len(6L), stringsAsFactors = FALSE), "patient_id", token)
  aligned <- .psi_padded_attach_attestation(aligned, contract)
  transport_secret <- paste0("secret-transport-", strrep("z", 128L))
  ss <- new.env(parent = emptyenv())
  ss$keys <- list(
    transport_sk = transport_secret,
    transport_pk = "ephemeral-public-key",
    identity_pk = identity$identity_pk)
  exact_chunk <- .psi_padded_and_chunk_contract(contract, 1L)
  exact_spool <- file.path(root, "completed-exact-gc-spool")
  dir.create(exact_spool, mode = "0700")
  exact_operation <- new.env(parent = emptyenv())
  exact_operation$operation_id <- exact_chunk$operation_id
  exact_operation$status <- "complete"
  exact_operation$source_key <- exact_chunk$source_key
  exact_operation$output_key <- exact_chunk$output_key
  exact_operation$worker_kind <- ""
  exact_operation$process <- NULL
  exact_operation$spool <- exact_spool
  exact_operation$resource_reservation_bytes <- 4096
  ss$.exact_gc_ops <- new.env(parent = emptyenv())
  ss$.exact_gc_ops[[exact_chunk$operation_id]] <- exact_operation
  ss$.exact_gc_inputs <- stats::setNames(list(list(
    claimed_by = exact_chunk$operation_id,
    private_share = "must-be-purged")), exact_chunk$source_key)
  ss$.exact_gc_outputs <- stats::setNames(
    list("must-be-purged"), exact_chunk$output_key)
  ss$.psi_padded_state <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = contract$session_id,
    operation_id = contract$operation_id,
    self_peer_id = peer_id,
    self_peer = "site_a",
    identity_pk = identity$identity_pk,
    contract = contract,
    phase = "complete",
    selected_rows = seq_len(6L),
    selected_ids = aligned$patient_id,
    transport_sk = transport_secret,
    transport_pk = "ephemeral-public-key",
    slot_rows = seq_len(64L),
    slot_valid = rep(c(TRUE, FALSE), 32L),
    masked_points = rep("masked", 64L),
    scalar = "private-scalar",
    pairwise = list(site_b = list(target_slot_by_ref = seq_len(64L))),
    membership_received = list(site_b = list(payload_sha256 = strrep("e", 64L))),
    membership_sum_share = rep(0L, 64L),
    global_membership_chunks = list(`1` = rep(0L, 64L)),
    final_plan = list(bits = rep(0L, 64L), ranks = seq_len(64L)),
    alignment_token = token,
    final_exports = list(site_b = "sealed-final-envelope"),
    completed_manifest = attr(aligned, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE),
    replay_cache = new.env(parent = emptyenv()))
  forbidden <- c(
    "selected_rows", "selected_ids", "transport_sk", "transport_pk",
    "slot_rows", "slot_valid", "masked_points", "scalar", "pairwise",
    "membership_received", "membership_sum_share",
    "global_membership_chunks", "final_plan", "alignment_token",
    "final_exports", "completed_manifest", "replay_cache")
  nested_names <- function(value) {
    if (!is.list(value)) return(character())
    c(names(value), unlist(lapply(value, nested_names), use.names = FALSE))
  }
  expect_true(.psi_padded_state_commit(ss))
  path <- .psi_padded_journal_path(
    contract$session_id, peer_id, allow_test_path = TRUE)
  before_size <- file.size(path)
  attestation <- .psi_padded_attestation_impl(ss, aligned)
  expect_identical(attestation, .psi_padded_public_attestation(contract))
  compact <- ss$.psi_padded_state
  expect_identical(compact$phase, "attested")
  expect_false(any(forbidden %in% nested_names(compact)))
  expect_false(transport_secret %in% as.character(
    unlist(compact, recursive = TRUE, use.names = FALSE)))
  expect_null(ss$keys)
  expect_false(dir.exists(exact_spool))
  expect_length(ls(ss$.exact_gc_ops, all.names = TRUE), 0L)
  expect_null(ss$.exact_gc_inputs[[exact_chunk$source_key]])
  expect_null(ss$.exact_gc_outputs[[exact_chunk$output_key]])
  expect_lt(file.size(path), before_size)
  owner <- .psi_padded_journal_resource_owner(path)
  expect_identical(
    .dsvert_resource_registry$external[[owner]]$bytes,
    as.numeric(file.size(path)))
  restarted <- new.env(parent = emptyenv())
  expect_true(.psi_padded_state_restore(restarted, compact$session_id))
  durable <- restarted$.psi_padded_state
  expect_identical(durable$phase, "attested")
  expect_false(any(forbidden %in% nested_names(durable)))
  expect_false(transport_secret %in% as.character(
    unlist(durable, recursive = TRUE, use.names = FALSE)))
  expect_identical(
    .psi_padded_attestation_impl(restarted, aligned), attestation)
  expect_identical(.psi_padded_attestation_impl(ss, aligned), attestation)
  expect_true(.psi_padded_state_delete(compact))
})
