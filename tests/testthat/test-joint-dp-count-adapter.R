.joint_count_test_source_row <- function(query_id = strrep("a", 64L)) {
  list(
    version = .DSVERT_JOINT_DP_COUNT_SOURCE_ROW_VERSION,
    query_id = query_id,
    capsule_release_id = strrep("b", 64L),
    allocation_index = "7",
    source_contract_hash = strrep("c", 64L),
    mask_contract_hash = strrep("d", 64L),
    source_peer = "peer_a", recipient_peer = "peer_b",
    role = "source", ring_bits = 128L, coordinate_count = 1L,
    local_share = "340282366920938463463374607431768211451",
    peer_share = "78", state = "split_committed")
}

.joint_count_test_stage_row <- function(query_id = strrep("a", 64L)) {
  payload <- charToRaw("durable-post-clamp-share")
  list(
    version = .DSVERT_JOINT_DP_COUNT_STAGE_ROW_VERSION,
    query_id = query_id,
    capsule_release_id = strrep("b", 64L),
    allocation_index = "7",
    opening_set_hash = strrep("e", 64L),
    result_contract_hash = strrep("f", 64L),
    operation_id = paste0("op_", strrep("1", 32L)),
    output_key = paste0("exact_gc_out_", strrep("2", 32L)),
    payload_b64 = gsub("[\r\n]", "", jsonlite::base64_enc(payload)),
    payload = payload)
}

.joint_count_test_release_row <- function(query_id = strrep("a", 64L)) {
  list(
    version = .DSVERT_JOINT_DP_COUNT_RELEASE_VERSION,
    phase = "count_released", consortium_id = paste0(
      "jdpc1_", strrep("1", 64L)),
    peer_name = "peer_a", peer_identity_pk = "pinned-peer-a-key",
    capsule_id = query_id, query_id = query_id, allocation_index = "7",
    capsule_release_id = query_id,
    source_contract_hash = strrep("c", 64L),
    result_contract_hash = strrep("d", 64L),
    result_set_hash = strrep("e", 64L),
    delivery_commit_set_hash = strrep("f", 64L),
    value = "73", lower_bound = "0", upper_bound = "1000",
    mechanism = "discrete-laplace-geometric-tv-v2",
    sampler = .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2,
    epsilon = "1e+00", delta = "7.888609052210118e-31",
    accuracy_95_abs = "7",
    accuracy_accounting =
      "one-draw-marginal-95-mechanism-noise-only",
    implementation_delta = "7.888609052210118e-31",
    backend = "exact-gc-joint-dp-laplace-ring127-v2",
    postprocessing =
      "one-joint-noise-draw-and-one-clamp-inside-exact-gc",
    replay_contract = "durable-byte-identical-query-bound-v1",
    intermediate_values_exposed = FALSE,
    payload_delivery_available = TRUE, capability_available = TRUE,
    signature = "test-signature")
}

.joint_count_test_policy <- function(peer = "peer_a") {
  pins <- c(
    peer_a = base64_to_base64url(gsub(
      "[\r\n]", "", jsonlite::base64_enc(as.raw(seq_len(32L))))),
    peer_b = base64_to_base64url(gsub(
      "[\r\n]", "", jsonlite::base64_enc(as.raw(32L + seq_len(32L))))))
  list(
    domain = "count-test-study", cohort_id = "count-test-cohort",
    peer_name = peer, peer_pinset = pins,
    peer_pinset_sha256 = digest::digest(
      .dsvert_dp_canonical_json(as.list(pins)),
      algo = "sha256", serialize = FALSE),
    peer_count = 2L,
    designated_noise_peers = c("peer_a", "peer_b"),
    global_total_epsilon = 1, global_total_delta = 1e-6,
    lifetime_max_distinct_capsules = 8,
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = 1000L, fixed_cohort_size = NULL,
    max_records_per_unit = 2L, overflow_policy = "reject_snapshot",
    noise_root = list(epoch = 1, key_id = paste0("count-key-", peer)),
    ledger_path = tempfile("count-contract-ledger-"))
}

test_that("Count uses one non-circular operation-independent capsule identity", {
  dataset <- list(
    data_name = "D", id = "aligned-count-cohort", version = "v1",
    alignment_manifest_hash = strrep("a", 64L),
    alignment_manifest_version = 1L)
  first <- .dsvert_joint_dp_count_contracts(
    .joint_count_test_policy("peer_a"), dataset)
  second <- .dsvert_joint_dp_count_contracts(
    .joint_count_test_policy("peer_b"), dataset)

  expect_identical(first$capsule_identity, second$capsule_identity)
  expect_identical(first$source$capsule_release_id,
                   first$capsule_identity$capsule_id)
  expect_identical(
    first$mechanism$clipping_hash,
    .dsvert_joint_dp_hash(first$backend_source))
  expect_equal(first$mechanism$ring_bits, 127L)
  expect_equal(first$source$ring_bits, 128L)
  expect_identical(
    first$capsule_identity$contract$workload$capsule_scope,
    "transitional_single_admitted_count_coordinate")
  expect_false(first$capsule_identity$contract$workload$whole_biomedical_workload)
  expect_false(any(c("method", "arguments") %in%
                     names(first$capsule_identity$contract$workload)))

  proposal <- .dsvert_joint_dp_proposal(
    .joint_count_test_policy("peer_a"), first$logical_snapshot,
    "unit_count", first$arguments, strrep("b", 64L), first$mechanism,
    capsule_identity = first$capsule_identity,
    .secret = as.raw(seq_len(32L)))
  expect_identical(proposal$query_id, first$source$capsule_release_id)

  changed <- dataset
  changed$version <- "v2"
  expect_false(identical(
    first$capsule_identity$capsule_id,
    .dsvert_joint_dp_count_contracts(
      .joint_count_test_policy("peer_a"), changed)$capsule_identity$capsule_id))

  fixed <- .joint_count_test_policy("peer_a")
  fixed$adjacency <- "replace_one_fixed_cohort"
  fixed$fixed_cohort_size <- 100L
  expect_error(.dsvert_joint_dp_count_contracts(fixed, dataset),
               "zero-cost public policy value")
})

test_that("Count exact-GC purpose binds every release identity", {
  values <- list(
    query_id = strrep("1", 64L),
    capsule_release_id = strrep("2", 64L),
    allocation_index = "7",
    source_contract_hash = strrep("3", 64L),
    result_contract_hash = strrep("4", 64L))
  make <- function(value = values) do.call(
    .dsvert_joint_dp_count_purpose, value)
  purposes <- c(make())
  for (field in c(
      "query_id", "capsule_release_id", "source_contract_hash",
      "result_contract_hash")) {
    changed <- values
    changed[[field]] <- strrep("9", 64L)
    purposes <- c(purposes, make(changed))
  }
  changed <- values
  changed$allocation_index <- "8"
  purposes <- c(purposes, make(changed))

  expect_length(unique(purposes), length(purposes))
  expect_true(all(grepl("^joint\\.dp\\.count\\.[0-9a-f]{64}$", purposes)))
  expect_true(all(nchar(purposes, type = "bytes") <= 128L))
})

test_that("typed Count shares are capability- and capsule-bound", {
  context <- list(
    query_id = strrep("1", 64L),
    capsule_release_id = strrep("2", 64L),
    allocation_index = "7",
    source_contract_hash = strrep("3", 64L),
    purpose_hash = strrep("4", 64L), ring = "128")
  first <- .dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_COUNT_TYPED_CAPABILITY, "peer_a", context)
  expect_identical(first$family, "joint-dp")
  expect_identical(first$producer,
                   ".dsvert_joint_dp_count_mint_transfer")
  expect_identical(first$consumer,
                   ".dsvert_joint_dp_count_receive_transfer")
  expect_identical(first$shape, "encrypted-ring128-scalar-share")

  changed <- context
  changed$capsule_release_id <- strrep("5", 64L)
  second <- .dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_COUNT_TYPED_CAPABILITY, "peer_a", changed)
  expect_false(identical(first$slot, second$slot))
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_COUNT_TYPED_CAPABILITY, "peer_a",
    context[setdiff(names(context), "capsule_release_id")]),
    "context")
  malformed <- context
  malformed$capsule_release_id <- strrep("A", 64L)
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_COUNT_TYPED_CAPABILITY, "peer_a", malformed),
    "context")

  final_context <- c(context, list(
    result_contract_hash = strrep("5", 64L),
    result_set_hash = strrep("6", 64L),
    delivery_commit_set_hash = strrep("7", 64L)))
  final_context$ring <- "127"
  final <- .dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY,
    "peer_a", final_context)
  expect_identical(final$producer,
                   .DSVERT_JOINT_DP_COUNT_FINAL_TRANSFER_PRODUCER)
  expect_identical(final$consumer, ".dsvert_joint_dp_count_release")
  expect_identical(final$shape, "encrypted-post-clamp-ring127-share")
  for (field in setdiff(names(final_context), "ring")) {
    changed <- final_context
    changed[[field]] <- if (identical(field, "allocation_index")) {
      "8"
    } else {
      strrep("8", 64L)
    }
    expect_false(identical(final$slot, .dsvert_typed_blob_destination(
      .DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY,
      "peer_a", changed)$slot), info = field)
  }
  wrong_ring <- final_context
  wrong_ring$ring <- "128"
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY,
    "peer_a", wrong_ring), "Ring127")
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY, "peer_a",
    final_context[setdiff(names(final_context), "result_set_hash")]),
    "context")
  extra <- final_context
  extra$payload_b64 <- "forbidden"
  expect_error(.dsvert_typed_blob_destination(
    .DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY, "peer_a", extra),
    "context")
})

test_that("Count private rows and signed release survive reopen and fail on tamper", {
  secret <- as.raw(seq_len(32L))
  database <- tempfile(fileext = ".sqlite")
  source <- .joint_count_test_source_row()
  stage <- .joint_count_test_stage_row()
  release <- .joint_count_test_release_row()

  connection <- DBI::dbConnect(RSQLite::SQLite(), database)
  on.exit(try(DBI::dbDisconnect(connection), silent = TRUE), add = TRUE)
  .dsvert_joint_dp_count_install_tables(connection)
  .dsvert_joint_dp_count_source_insert(connection, source, secret)
  .dsvert_joint_dp_count_stage_insert(connection, stage, secret)
  .dsvert_joint_dp_count_release_insert(connection, release, secret)
  expect_identical(.dsvert_joint_dp_count_source_load(
    connection, source$query_id, secret),
    .dsvert_dp_canonical_query_value(source))
  loaded_stage <- .dsvert_joint_dp_count_stage_load(
    connection, stage$query_id, secret)
  expect_identical(loaded_stage$payload, stage$payload)
  expect_identical(loaded_stage[setdiff(names(loaded_stage), "payload")],
    .dsvert_dp_canonical_query_value(
      stage[setdiff(names(stage), "payload")]))
  expect_identical(.dsvert_joint_dp_count_release_load(
    connection, release$query_id, secret),
    .dsvert_dp_canonical_query_value(release))
  DBI::dbDisconnect(connection)

  connection <- DBI::dbConnect(RSQLite::SQLite(), database)
  expect_identical(.dsvert_joint_dp_count_source_load(
    connection, source$query_id, secret),
    .dsvert_dp_canonical_query_value(source))
  loaded_stage <- .dsvert_joint_dp_count_stage_load(
    connection, stage$query_id, secret)
  expect_identical(loaded_stage$payload, stage$payload)
  expect_identical(loaded_stage[setdiff(names(loaded_stage), "payload")],
    .dsvert_dp_canonical_query_value(
      stage[setdiff(names(stage), "payload")]))
  expect_identical(.dsvert_joint_dp_count_release_load(
    connection, release$query_id, secret),
    .dsvert_dp_canonical_query_value(release))

  DBI::dbExecute(connection, paste(
    "UPDATE joint_count_sources SET source_json = source_json || ' '",
    "WHERE query_id = ?"), params = list(source$query_id))
  expect_error(.dsvert_joint_dp_count_source_load(
    connection, source$query_id, secret), "integrity check")
  DBI::dbExecute(connection,
    "UPDATE joint_count_final_stage SET row_mac = ? WHERE query_id = ?",
    params = list(strrep("0", 64L), stage$query_id))
  expect_error(.dsvert_joint_dp_count_stage_load(
    connection, stage$query_id, secret), "integrity check")
  DBI::dbExecute(connection,
    "UPDATE joint_count_releases SET row_mac = ? WHERE query_id = ?",
    params = list(strrep("0", 64L), release$query_id))
  expect_error(.dsvert_joint_dp_count_release_load(
    connection, release$query_id, secret), "integrity check")
})

test_that("Count final release is durable across lost ACK and volatile restart", {
  secret <- as.raw(seq_len(32L))
  session_id <- "12345678-1234-4234-9234-123456789abc"
  query_id <- strrep("a", 64L)
  source_hash <- strrep("c", 64L)
  result_hash <- strrep("d", 64L)
  result_set_hash <- strrep("e", 64L)
  delivery_hash <- strrep("f", 64L)
  own_payload <- .dsvert_joint_dp_count_result_payload(
    .exact_gc_decimal_residues_b64(
      "170141183460469231731687303715884105723", 127L),
    gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(0L))),
    query_id, query_id, "7", source_hash, result_hash,
    "7", 2^-100)
  peer_payload <- .dsvert_joint_dp_count_result_payload(
    .exact_gc_decimal_residues_b64("78", 127L),
    gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(1L))),
    query_id, query_id, "7", source_hash, result_hash,
    "7", 2^-100)
  delivery <- list(
    context = list(
      consortium_id = paste0("jdpc1_", strrep("1", 64L)),
      peer_name = "peer_a", pins = c(peer_a = "pinned-peer-a-key"),
      common = list(designated_noise_peers = c("peer_a", "peer_b"))),
    contract = list(
      capsule_id = query_id, query_id = query_id, allocation_index = "7",
      result_contract_hash = result_hash, result_set_hash = result_set_hash,
      delivery_commit_set_hash = delivery_hash),
    state = list(
      secret = secret,
      record = list(query_id = query_id, allocation_index = "7",
                    epsilon = "1e+00",
                    delta = "7.888609052210118e-31"),
      source = list(capsule_release_id = query_id),
      source_hash = source_hash),
    binding = list(result_contract = list(release_upper_bound = "1000")),
    output = list(payload = own_payload))
  database <- tempfile(fileext = ".sqlite")
  open_ledger <- function(...) list(
    connection = DBI::dbConnect(RSQLite::SQLite(), database))
  close_ledger <- function(handle) {
    DBI::dbDisconnect(handle$connection)
    invisible(NULL)
  }
  session <- new.env(parent = emptyenv())
  encrypted <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(charToRaw("opaque-ciphertext"))))
  decrypt_calls <- 0L
  signer_calls <- 0L
  expected_token <- list(token = "delivery-token")

  testthat::local_mocked_bindings(
    .S = function(...) session,
    .dsvert_joint_dp_count_delivery_state = function(
        policy, own_delivery_token, peer_delivery_token, ...) {
      if (!identical(own_delivery_token, expected_token) ||
          !identical(peer_delivery_token, list(token = "peer-token"))) {
        stop("delivery token authentication failed", call. = FALSE)
      }
      delivery
    },
    .dsvert_joint_dp_open_ledger = open_ledger,
    .dsvert_joint_dp_close_ledger = close_ledger,
    .dsvert_joint_dp_initialize_validate = function(...) invisible(TRUE),
    .dsvert_typed_blob_consume = function(...) encrypted,
    .key_get = function(...) "private-transport-key",
    .callMpcTool = function(...) {
      decrypt_calls <<- decrypt_calls + 1L
      list(data = gsub("[\r\n]", "", jsonlite::base64_enc(peer_payload)))
    },
    .dsvert_joint_dp_sign = function(unsigned, ...) {
      signer_calls <<- signer_calls + 1L
      c(unsigned, list(signature = "test-signature"))
    },
    .package = "dsVert")

  invoke <- function(ss = session, hook = NULL, own = expected_token) {
    .dsvert_joint_dp_count_release(
      ss, session_id, policy = list(), own,
      list(token = "peer-token"), .secret = secret, .phase_hook = hook)
  }
  expect_error(invoke(hook = function(phase) {
    if (identical(phase, "after_count_release_commit")) {
      stop("simulated lost acknowledgement", call. = FALSE)
    }
  }), "lost acknowledgement")

  connection <- DBI::dbConnect(RSQLite::SQLite(), database)
  persisted <- .dsvert_joint_dp_count_release_load(
    connection, query_id, secret)
  DBI::dbDisconnect(connection)
  expected_json <- .dsvert_dp_canonical_json(persisted)
  replay <- invoke(ss = new.env(parent = emptyenv()))
  expect_identical(replay, expected_json)
  replay_started <- proc.time()[["elapsed"]]
  for (index in seq_len(128L)) {
    expect_identical(invoke(ss = new.env(parent = emptyenv())), expected_json)
  }
  replay_elapsed <- proc.time()[["elapsed"]] - replay_started
  expect_lt(replay_elapsed, 30)
  expect_identical(decrypt_calls, 1L)
  expect_identical(signer_calls, 1L)
  expect_identical(jsonlite::fromJSON(replay)$value, "73")
  expect_false(any(c(
    "share", "share_raw", "payload", "payload_b64", "plaintext") %in%
      names(jsonlite::fromJSON(replay, simplifyVector = FALSE))))

  expect_error(invoke(own = list(token = "altered")),
               "token authentication")
  delivery$contract$result_set_hash <- strrep("9", 64L)
  expect_error(invoke(), "conflicts with its authorization")
  delivery$contract$result_set_hash <- result_set_hash
  delivery$context$peer_name <- "peer_b"
  expect_error(invoke(), "conflicts with its authorization")
})

test_that("each pinned Count peer encrypts its final share only to the other", {
  peers <- c("peer_a", "peer_b")
  for (sender in peers) {
    recipient <- setdiff(peers, sender)
    session_id <- "12345678-1234-4234-9234-123456789abc"
    query_id <- strrep("a", 64L)
    peer_pk <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(seq_len(32L))))
    session <- new.env(parent = emptyenv())
    session$peer_transport_pks <- stats::setNames(list(peer_pk), recipient)
    delivery <- list(
      context = list(
        peer_name = sender,
        common = list(designated_noise_peers = peers)),
      contract = list(
        query_id = query_id, result_contract_hash = strrep("b", 64L),
        result_set_hash = strrep("c", 64L),
        delivery_commit_set_hash = strrep("d", 64L)),
      state = list(
        record = list(query_id = query_id, allocation_index = "7"),
        source = list(capsule_release_id = query_id),
        source_hash = strrep("e", 64L)),
      output = list(payload = charToRaw("private-final-share")))
    observed <- new.env(parent = emptyenv())

    value <- testthat::with_mocked_bindings(
      .dsvert_joint_dp_count_mint_final_transfer(
        session, session_id, list(), list(), list()),
      .S = function(...) session,
      .dsvert_joint_dp_count_delivery_state = function(...) delivery,
      .dsvert_typed_blob_operation_replay = function(...) list(hit = FALSE),
      .dsvert_joint_dp_count_decode_result_payload = function(...) list(),
      .callMpcTool = function(command, args) {
        expect_identical(command, "transport-encrypt")
        expect_identical(args$recipient_pk, peer_pk)
        list(sealed = gsub(
          "[\r\n]", "", jsonlite::base64_enc(charToRaw("ciphertext"))))
      },
      .dsvert_typed_blob_mint = function(
          ss, session_id, capability_id, recipient_pk, payload, context,
          producer) {
        observed$recipient_pk <- recipient_pk
        observed$capability_id <- capability_id
        list(
          ticket = "opaque-ticket", transfer_id = paste0("tb1_", strrep("1", 32L)),
          capability_id = capability_id, sender_name = sender,
          recipient_name = recipient, payload_chars = nchar(payload),
          payload_sha256 = strrep("f", 64L))
      },
      .dsvert_typed_blob_operation_commit = function(
          ss, producer, request, result) result,
      .package = "dsVert")
    expect_identical(value$transfer$sender_name, sender)
    expect_identical(value$transfer$recipient_name, recipient)
    expect_identical(observed$capability_id,
                     .DSVERT_JOINT_DP_COUNT_FINAL_TYPED_CAPABILITY)
    expect_identical(observed$recipient_pk, base64_to_base64url(peer_pk))
    expect_false(value$payload_delivery_available)
  }
})

test_that("Count split is durable, opaque and has unlimited exact replay", {
  secret <- as.raw(seq_len(32L))
  capsule_id <- strrep("2", 64L)
  query_id <- capsule_id
  source <- .dsvert_joint_dp_convolution_source_contract(
    producer = .DSVERT_JOINT_DP_COUNT_SOURCE_PRODUCER,
    purpose = .DSVERT_JOINT_DP_COUNT_SOURCE_PURPOSE,
    source_context_hash = strrep("3", 64L),
    capsule_release_id = capsule_id,
    ring_bits = 128L, frac_bits = 0L,
    statistic_lower_bounds = "0", statistic_upper_bounds = "1000",
    release_lower_bounds = "0", release_upper_bounds = "1000",
    producer_attestation_hash = strrep("4", 64L))
  state <- list(
    context = list(
      peer_name = "peer_a",
      common = list(designated_noise_peers = c("peer_a", "peer_b"))),
    record = list(query_id = query_id, allocation_index = "7"),
    source = source,
    source_hash = .dsvert_joint_dp_hash(source),
    mask_hash = .dsvert_joint_dp_hash(source$mask),
    secret = secret)
  database <- tempfile(fileext = ".sqlite")
  producer_calls <- 0L
  splitter_calls <- 0L
  splitter <- function(input) {
    splitter_calls <<- splitter_calls + 1L
    list(
      version = input$version,
      capability_available = FALSE,
      unavailable_reason = .DSVERT_JOINT_DP_CONVOLUTION_UNAVAILABLE,
      query_id = input$query_id,
      capsule_release_id = input$capsule_release_id,
      allocation_index = input$allocation_index,
      source_contract_hash = input$source_contract_hash,
      mask_contract_hash = input$mask_contract_hash,
      coordinate_index = input$coordinate_index,
      ring_bits = 128L,
      left_share = "340282366920938463463374607431768211451",
      right_share = "78",
      mask_protocol = .DSVERT_JOINT_DP_CONVOLUTION_MASK_PROTOCOL,
      mask_conditional_min_entropy_bits = 128L,
      generator = "os_csprng_uniform_16_bytes",
      requires_durable_replay = TRUE)
  }
  open_ledger <- function(...) list(
    connection = DBI::dbConnect(RSQLite::SQLite(), database))
  close_ledger <- function(handle) {
    DBI::dbDisconnect(handle$connection)
    invisible(NULL)
  }

  testthat::local_mocked_bindings(
    .dsvert_joint_dp_count_open_state = function(...) state,
    .dsvert_joint_dp_count_bound_snapshot = function(...) {
      producer_calls <<- producer_calls + 1L
      list(admission = list(present = rep(TRUE, 73L)))
    },
    .dsvert_joint_dp_open_ledger = open_ledger,
    .dsvert_joint_dp_close_ledger = close_ledger,
    .dsvert_joint_dp_initialize_validate = function(...) invisible(TRUE),
    .package = "dsVert")

  invoke <- function(hook = NULL) .dsvert_joint_dp_count_commit_split(
    policy = list(), own_opening_token = list(),
    peer_opening_token = list(), data_name = "ignored",
    envir = emptyenv(), .secret = secret,
    .splitter = splitter, .phase_hook = hook)

  expect_error(invoke(function(phase) {
    if (identical(phase, "after_count_split_commit"))
      stop("simulated lost acknowledgement", call. = FALSE)
  }), "lost acknowledgement")
  expect_identical(splitter_calls, 1L)
  expect_identical(producer_calls, 1L)

  replay <- invoke()
  expect_identical(splitter_calls, 1L)
  expect_identical(producer_calls, 1L)
  expect_false(any(grepl("share|count", names(replay), ignore.case = TRUE)))
  expect_false(replay$capability_available)
  expect_identical(replay$capsule_release_id, capsule_id)
  for (index in seq_len(128L)) expect_identical(invoke(), replay)
  expect_identical(splitter_calls, 1L)
  expect_identical(producer_calls, 1L)

  connection <- DBI::dbConnect(RSQLite::SQLite(), database)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  persisted <- .dsvert_joint_dp_count_source_load(
    connection, query_id, secret)
  expect_identical(persisted$local_share,
                   "340282366920938463463374607431768211451")
  expect_identical(persisted$peer_share, "78")
})

test_that("a durable post-clamp Count stage resumes without volatile GC state", {
  session_id <- "12345678-1234-4234-9234-123456789abc"
  staged_operation_id <- paste0("op_", strrep("1", 32L))
  operation_id <- paste0("op_", strrep("9", 32L))
  query_id <- strrep("2", 64L)
  capsule_id <- strrep("3", 64L)
  result_hash <- strrep("4", 64L)
  openings <- list(peer_a = list(token = "a"), peer_b = list(token = "b"))
  state <- list(
    record = list(query_id = query_id, allocation_index = "7"),
    source = list(capsule_release_id = capsule_id),
    source_hash = strrep("5", 64L), secret = as.raw(seq_len(32L)),
    tokens = openings, context = list())
  binding <- list(
    result_contract_hash = result_hash, purpose = "joint.dp.count.test")
  payload <- charToRaw("already-staged-post-clamp-share")
  staged <- list(
    version = .DSVERT_JOINT_DP_COUNT_STAGE_ROW_VERSION,
    query_id = query_id, capsule_release_id = capsule_id,
    allocation_index = "7",
    opening_set_hash = .dsvert_joint_dp_hash(openings),
    result_contract_hash = result_hash,
    operation_id = staged_operation_id,
    output_key = paste0("exact_gc_out_", strrep("6", 32L)),
    payload_b64 = gsub("[\r\n]", "", jsonlite::base64_enc(payload)),
    payload = payload)
  ss <- new.env(parent = emptyenv())
  captured <- new.env(parent = emptyenv())

  result <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_count_prepare_result(
      ss, session_id, operation_id, list(), list(), list()),
    .S = function(...) ss,
    .dsvert_joint_dp_count_open_state = function(...) state,
    .dsvert_joint_dp_count_transfer_binding = function(...) binding,
    .dsvert_joint_dp_count_existing_result = function(...) NULL,
    .dsvert_joint_dp_count_load_final_stage = function(...) staged,
    .exact_gc_consume_output = function(...) {
      stop("volatile GC output was consumed again", call. = FALSE)
    },
    .dsvert_joint_dp_result_prepare = function(
        policy, own, peer, value, contract_hash, ...) {
      captured$payload <- value
      captured$hash <- contract_hash
      list(state = "result_prepared", capability_available = FALSE)
    },
    .package = "dsVert")
  expect_identical(result$state, "result_prepared")
  expect_identical(captured$payload, payload)
  expect_identical(captured$hash, result_hash)
  expect_false(is.environment(ss$.joint_dp_count_gc))
})

test_that("durable Count replay is O(1) in protocol state and non-informative when absent", {
  policy <- .joint_count_test_policy("peer_a")
  policy$datasets <- list(D = list(
    id = "aligned-count-cohort", version = "v1",
    snapshot_sha256 = strrep("9", 64L),
    alignment_manifest_hash = strrep("a", 64L),
    alignment_manifest_version = 1L))
  context <- .dsvert_joint_dp_policy_context(policy)
  contracts <- .dsvert_joint_dp_count_contracts(
    policy, .dsvert_joint_dp_count_dataset_public(policy, "D"))
  query_id <- contracts$capsule_identity$capsule_id
  release <- .joint_count_test_release_row(query_id)
  release$consortium_id <- context$consortium_id
  release$peer_identity_pk <- unname(context$pins[["peer_a"]])
  source <- list(source_contract_hash = release$source_contract_hash)
  record <- list(
    allocation_index = release$allocation_index,
    epsilon = release$epsilon, delta = release$delta)
  output <- list(
    state = "delivery_authorized",
    result_contract_hash = release$result_contract_hash,
    result_set_hash = release$result_set_hash,
    delivery_token = list(
      result_contract_hash = release$result_contract_hash,
      result_set_hash = release$result_set_hash,
      delivery_commit_set_hash = release$delivery_commit_set_hash))
  materialized <- FALSE
  release_reads <- 0L

  result <- testthat::with_mocked_bindings({
    absent <- .dsvert_joint_dp_count_replay(
      policy, "D", .secret = as.raw(seq_len(32L)),
      .verifier = function(...) TRUE)
    expect_identical(absent$state, "not_materialized")
    expect_identical(absent$query_id, query_id)
    expect_identical(absent$release_json, "")
    expect_false(absent$intermediate_values_exposed)

    materialized <- TRUE
    present <- .dsvert_joint_dp_count_replay(
      policy, "D", .secret = as.raw(seq_len(32L)),
      .verifier = function(...) TRUE)
    expect_identical(present$state, "released")
    expect_identical(
      present$release_json, .dsvert_dp_canonical_json(release))
    for (index in seq_len(128L)) {
      expect_identical(.dsvert_joint_dp_count_replay(
        policy, "D", .secret = as.raw(seq_len(32L)),
        .verifier = function(...) TRUE), present)
    }
    present
  },
  .dsvert_joint_dp_open_ledger = function(...) list(connection = list()),
  .dsvert_joint_dp_close_ledger = function(...) invisible(TRUE),
  .dsvert_joint_dp_initialize_validate = function(...) invisible(TRUE),
  .dsvert_joint_dp_count_install_tables = function(...) invisible(TRUE),
  .dsvert_joint_dp_count_release_load = function(...) {
    release_reads <<- release_reads + 1L
    if (materialized) release else NULL
  },
  .dsvert_joint_dp_load = function(...) record,
  .dsvert_joint_dp_output_load = function(...) output,
  .dsvert_joint_dp_count_source_load = function(...) source,
  .dsvert_joint_dp_validate_output_record = function(...) invisible(TRUE),
  .dsvert_dp_resolve_snapshot = function(...) {
    stop("replay inspected protected rows", call. = FALSE)
  },
  .dsvert_dp_admit_units = function(...) {
    stop("replay recomputed a statistic", call. = FALSE)
  },
  .package = "dsVert")
  expect_identical(result$state, "released")
  expect_identical(release_reads, 130L)
})

test_that("the superseded scalar Count phases remain internal only", {
  expected <- c(
    "dsvertJointDPCountReplayDS", "dsvertJointDPCountProposalDS",
    "dsvertJointDPCountSourceDS", "dsvertJointDPCountBackendPrepareDS",
    "dsvertJointDPCountBackendTokenDS", "dsvertJointDPCountStartDS",
    "dsvertJointDPCountResultDS", "dsvertJointDPCountFinalShareDS",
    "dsvertJointDPCountReleaseDS")
  namespace <- asNamespace("dsVert")
  expect_true(all(vapply(expected, exists, logical(1L),
                         envir = namespace, inherits = FALSE)))
  expect_false(any(expected %in% getNamespaceExports("dsVert")))
  expect_false(any(expected %in% .dsvert_test_disclosure_safe_methods))
  expect_false(any(c(
    "dsvertJointDPCountShareDS", "dsvertJointDPCountNoiseDS",
    "dsvertJointDPCountRawDS") %in% getNamespaceExports("dsVert")))
})
