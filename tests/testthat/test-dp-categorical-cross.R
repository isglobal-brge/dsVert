.cross_cat_b64url <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.cross_cat_signature <- function(message, pin) {
  pin_raw <- .dsvert_relay_b64url_decode(pin, "test pin")
  .cross_cat_b64url(openssl::sha512(c(message, pin_raw)))
}

.cross_cat_signer <- function(message, peer_name, pin) {
  .cross_cat_signature(message, pin)
}

.cross_cat_verifier <- function(message, pin, signature) {
  identical(signature, .cross_cat_signature(message, pin))
}

.cross_cat_selector <- function(
    coordinate_count, laplace_epsilons, laplace_sensitivities,
    gaussian_epsilon, gaussian_delta, gaussian_l2_sensitivity,
    objective) {
  list(
    selector = .DSVERT_DP_NOISE_SELECTOR, objective = objective,
    coordinate_count = as.integer(coordinate_count), winner = "laplace",
    laplace = list(available = TRUE, simultaneous_95_abs = 10),
    gaussian = list(available = TRUE, simultaneous_95_abs = 20))
}

.cross_cat_fixture <- function(
    peer = "peer_a", adjacency = "add_remove_patient", padded_v3 = FALSE) {
  stopifnot(peer %in% c("peer_a", "peer_b"))
  pins <- c(
    peer_a = .cross_cat_b64url(as.raw(seq_len(32L))),
    peer_b = .cross_cat_b64url(as.raw(32L + seq_len(32L))))
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  local_a <- identical(peer, "peer_a")
  data_name <- if (local_a) "leftdata" else "rightdata"
  dataset_id <- if (isTRUE(padded_v3)) {
    "vertical-cohort"
  } else if (local_a) {
    "cohort-a"
  } else {
    "cohort-b"
  }
  variable <- if (local_a) "left_cat" else "right_cat"
  levels <- if (local_a) c("A", "B") else c("X", "Y", "Z")
  data <- if (local_a) {
    data.frame(
      patient_id = c("u1", "u2", "u3"),
      left_cat = c("A", "B", NA_character_),
      stringsAsFactors = FALSE)
  } else {
    data.frame(
      patient_id = c("u1", "u2", "u3"),
      right_cat = c("X", "Y", "X"), stringsAsFactors = FALSE)
  }
  policy <- list(
    domain = "cross-categorical-study", cohort_id = "cohort-v1",
    peer_name = peer, peer_pinset = pins,
    peer_pinset_sha256 = pin_hash, peer_count = 2L,
    designated_noise_peers = names(pins),
    global_total_epsilon = 1, global_total_delta = 1e-6,
    lifetime_max_distinct_capsules = 8,
    adjacency = adjacency, patient_column = "patient_id",
    unit_capacity = 4L,
    fixed_cohort_size = if (identical(
      adjacency, "replace_one_fixed_cohort")) 4L else NULL,
    max_records_per_unit = 1L, overflow_policy = "reject_snapshot",
    contingency_unit_aggregation_policy =
      "consistent_cell_else_exclude_v1",
    numeric_grid_bits = 8L, numeric_bounds = list(),
    categorical_levels = stats::setNames(list(levels), variable),
    datasets = stats::setNames(list(list(
      id = dataset_id, version = "v1", snapshot_sha256 = NULL,
      alignment_manifest_hash = NULL,
      alignment_manifest_version = 1L)), data_name),
    noise_root = list(epoch = 1, key_id = "cross-categorical-test-root"),
    ledger_path = tempfile("cross-categorical-ledger-"),
    ledger_private = FALSE, lock_timeout_ms = 30000)
  store_path <- .dsvert_dp_capsule_source_store_path(policy)
  resource_owner <- .dsvert_dp_capsule_source_resource_owner(policy)
  withr::defer({
    .dsvert_resource_external_unregister(resource_owner)
    unlink(c(
      store_path, paste0(store_path, ".lock"),
      paste0(store_path, "-wal"), paste0(store_path, "-shm")),
      force = TRUE)
  }, envir = parent.frame())
  logical_snapshot <- list(
    logical_snapshot_id = "cross-categorical-aligned-cohort",
    version = "v1", alignment_protocol_version = 1L)
  schema <- list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = pin_hash,
    datasets = list(
      leftdata = list(
        dataset_id = if (isTRUE(padded_v3)) {
          "vertical-cohort"
        } else "cohort-a", dataset_version = "v1",
        schema_version = "schema-v1", alignment_group = "aligned-main",
        patient_keys = list(peer_a = "patient_id"),
        columns = list(left_cat = list(
          kind = "categorical", owner_peer = "peer_a",
          levels = c("A", "B")))),
      rightdata = list(
        dataset_id = if (isTRUE(padded_v3)) {
          "vertical-cohort"
        } else "cohort-b", dataset_version = "v1",
        schema_version = "schema-v1", alignment_group = "aligned-main",
        patient_keys = list(peer_b = "patient_id"),
        columns = list(right_cat = list(
          kind = "categorical", owner_peer = "peer_b",
          levels = c("X", "Y", "Z"))))),
    signatures = list(peer_a = strrep("A", 86L),
                      peer_b = strrep("B", 86L)))
  cross <- list(cross_table = list(
    version = "v2", left_dataset = "leftdata",
    right_dataset = "rightdata", left = "left_cat",
    right = "right_cat", family = "categorical_pair"))
  manifest <- .dsvert_dp_capsule_workload_manifest(
    policy, logical_snapshot, schema,
    describe_specs = list(), survival_specs = list(),
    gaussian_specs = list(), vertical_cross_specs = cross,
    .signature_verifier = function(...) TRUE,
    .noise_selector = .cross_cat_selector)
  if (isTRUE(padded_v3)) {
    padded <- .dsvert_test_padded_dp_binding(
      data, "patient_id", dataset_id, "v1", pins)
    aligned <- padded$data
    policy$datasets[[data_name]] <- padded$descriptor
    alignment <- .dsvert_dp_validate_descriptor_alignment(
      aligned, padded$descriptor, "patient_id", expected_pinset = pins)
  } else {
    token <- base64_to_base64url(jsonlite::base64_enc(as.raw(0:31)))
    aligned <- .psi_attach_alignment_manifest(data, "patient_id", token)
    alignment <- .psi_validate_alignment_manifest(aligned)
    policy$datasets[[data_name]]$alignment_manifest_hash <- alignment$hash
    policy$datasets[[data_name]]$alignment_manifest_version <- alignment$version
  }
  resolved <- stats::setNames(list(list(
    data = aligned, dataset = list(public = list(
      data_name = data_name, id = dataset_id, version = "v1",
      alignment_manifest_hash = alignment$hash,
      alignment_manifest_version = alignment$version),
      fingerprint = if (local_a) strrep("a", 64L) else strrep("b", 64L)))),
    data_name)
  list(
    policy = policy, secret = as.raw(seq_len(32L)), manifest = manifest,
    manifest_json = .dsvert_dp_canonical_json(manifest),
    resolved = resolved, alignment = alignment)
}

test_that("one capsule recipient never decrypts a complete alignment hash", {
  left <- .cross_cat_fixture("peer_a")
  right <- .cross_cat_fixture("peer_b")
  expect_identical(
    left$manifest$capsule_identity$capsule_id,
    right$manifest$capsule_identity$capsule_id)

  manifest_json <- left$manifest_json
  fixtures <- list(peer_a = left, peer_b = right)
  key_index <- 0L
  tickets <- lapply(fixtures, function(fixture) {
    key_index <<- key_index + 1L
    .dsvert_dp_capsule_source_ticket_impl(
      manifest_json, .policy = fixture$policy, .secret = fixture$secret,
      .keygen = function() list(
        public_key = gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(
          (seq_len(32L) + 10L * key_index) %% 256L))),
        secret_key = gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(
          (seq_len(32L) + 20L * key_index) %% 256L)))),
      .signer = .cross_cat_signer,
      .allocation_require = function(...) invisible(list(authorized = TRUE)))
  })
  test_encryptor <- function(plaintext, recipient_pk) {
    gsub("[\r\n]", "", jsonlite::base64_enc(c(raw(60L), plaintext)))
  }
  test_decryptor <- function(ciphertext, recipient_sk) {
    ciphertext[-seq_len(60L)]
  }
  summary_json <- .dsvert_dp_capsule_source_prepare_impl(
    manifest_json, tickets[[1L]], tickets[[2L]],
    '{"peer":"peer_a","phase":"test_opening"}',
    '{"peer":"peer_b","phase":"test_opening"}',
    .policy = right$policy, .secret = right$secret,
    .resolved_snapshots = right$resolved,
    .encryptor = test_encryptor,
    .signer = .cross_cat_signer, .verifier = .cross_cat_verifier,
    .allocation_observer = function(...) invisible(list(authorized = TRUE)))
  summary <- .dsvert_dp_capsule_source_decode_json(
    summary_json, "test categorical source summary", 64L * 1024L)
  bundle_json <- .dsvert_dp_capsule_source_chunk_impl(
    summary$source_transfer_id, 0L,
    .policy = right$policy, .secret = right$secret,
    .resolved_snapshots = right$resolved,
    .encryptor = test_encryptor,
    .signer = .cross_cat_signer, .verifier = .cross_cat_verifier)
  bundle <- .dsvert_dp_capsule_source_decode_json(
    bundle_json, "test categorical source bundle",
    .DSVERT_DP_CAPSULE_SOURCE_MAX_BUNDLE_BYTES)

  decrypted_header <- function(recipient) {
    envelope <- bundle$envelopes[[which(vapply(
      bundle$envelopes, function(value) {
        identical(value$recipient_name, recipient)
      }, logical(1L)))]]
    fixture <- fixtures[[recipient]]
    contract <- .dsvert_dp_capsule_source_contract_json(
      fixture$policy, manifest_json)$contract
    key_record <- .dsvert_dp_capsule_source_with_store(
      fixture$policy, fixture$secret, function(connection) {
        .dsvert_dp_capsule_source_key_load(
          connection, contract$capsule_id, fixture$secret)
      })
    ciphertext <- .dsvert_dp_capsule_source_b64_raw(
      envelope$ciphertext, "test recipient ciphertext",
      .DSVERT_DP_CAPSULE_SOURCE_MAX_ENVELOPE_BYTES)
    plaintext <- .dsvert_dp_capsule_source_decrypt(
      ciphertext, key_record$transport_sk, test_decryptor)
    .dsvert_dp_capsule_source_unpack(
      plaintext, as.numeric(envelope$coordinates_in_chunk) * 16L)$header
  }

  headers <- lapply(names(fixtures), decrypted_header)
  names(headers) <- names(fixtures)
  alignment_hash <- right$alignment$hash
  alignment_raw <- as.raw(strtoi(
    substring(alignment_hash, seq.int(1L, 63L, by = 2L),
              seq.int(2L, 64L, by = 2L)), base = 16L))
  shares <- lapply(headers, function(header) {
    expect_false("private_alignment_consensus_hash" %in% names(header))
    expect_identical(
      header$private_alignment_sharing,
      "recipient_specific_xor_share_exact_gc_gate_v1")
    share <- .dsvert_relay_b64url_decode(
      header$private_alignment_consensus_share,
      "recipient-local private alignment share")
    expect_length(share, 32L)
    expect_false(identical(share, alignment_raw))
    expect_false(grepl(
      alignment_hash, .dsvert_dp_canonical_json(header), fixed = TRUE))
    share
  })
  expect_identical(
    as.raw(bitwXor(as.integer(shares[[1L]]), as.integer(shares[[2L]]))),
    alignment_raw)
  expect_false(identical(shares[[1L]], shares[[2L]]))
})

test_that("padded v3 bindings drive one cross categorical alignment consensus", {
  left <- .cross_cat_fixture("peer_a", padded_v3 = TRUE)
  right <- .cross_cat_fixture("peer_b", padded_v3 = TRUE)

  context_left <- .dsvert_dp_gaussian_cross_source_context(
    left$policy, left$manifest, left$resolved, include_release = FALSE)
  context_right <- .dsvert_dp_gaussian_cross_source_context(
    right$policy, right$manifest, right$resolved, include_release = FALSE)
  expect_identical(
    context_left$private_alignment_consensus_hash,
    context_right$private_alignment_consensus_hash)
  expect_identical(
    context_left$private_alignment_consensus_hash,
    left$policy$datasets$leftdata$alignment_manifest_hash)
  expect_identical(
    left$policy$datasets$leftdata$alignment_manifest_version, 3L)
})

.cross_cat_records <- function(values) {
  stopifnot(is.numeric(values), !anyNA(values), all(values >= 0),
            all(values == floor(values)), all(values <= 2^53 - 1))
  result <- raw(length(values) * 16L)
  for (index in seq_along(values)) {
    first <- (index - 1L) * 16L + 1L
    for (byte in 0:6) {
      result[[first + byte]] <- as.raw(
        floor(values[[index]] / 256^byte) %% 256)
    }
  }
  result
}

.cross_cat_decode <- function(value) {
  stopifnot(is.raw(value), length(value) %% 16L == 0L)
  records <- matrix(as.integer(value), nrow = 16L)
  stopifnot(all(records[8:16, , drop = FALSE] == 0L))
  unname(colSums(records[1:7, , drop = FALSE] * 256^(0:6)))
}

.cross_cat_reducer <- function(input) {
  values <- .cross_cat_decode(jsonlite::base64_dec(input$records))
  lengths <- as.integer(input$segment_lengths)
  cursor <- 1L
  sums <- vapply(lengths, function(length) {
    result <- sum(values[seq.int(cursor, length.out = length)])
    cursor <<- cursor + length
    result
  }, numeric(1L))
  list(
    version = .DSVERT_DP_GAUSSIAN_CROSS_REDUCER_VERSION,
    segment_count = length(lengths),
    sums = gsub("[\r\n]", "", jsonlite::base64_enc(
      .cross_cat_records(sums))))
}

test_that("cross categorical descriptor fixes domains, order and sensitivity", {
  add_remove <- .cross_cat_fixture("peer_a")
  artifact <- .dsvert_dp_categorical_cross_artifacts(
    add_remove$manifest)$cross_table
  expect_equal(as.numeric(artifact$coordinate_count), 6)
  expect_identical(artifact$left$levels, c("A", "B"))
  expect_identical(artifact$right$levels, c("X", "Y", "Z"))
  expect_identical(artifact$selected_l1_sensitivity, 1)
  expect_equal(as.numeric(artifact$selected_l2_sensitivity), 1)
  expect_equal(as.numeric(
    artifact$transcript$exact_multiplication_rounds), 1)
  expect_equal(as.numeric(artifact$transcript$data_dependent_branches), 0)
  expect_true(artifact$numeric_certificate$modular_wrap_proved_absent)
  expect_identical(
    artifact$numeric_certificate$overflow_behavior,
    "typed_abort_before_commit")

  replace <- .cross_cat_fixture(
    "peer_a", adjacency = "replace_one_fixed_cohort")
  replaced <- .dsvert_dp_categorical_cross_artifacts(
    replace$manifest)$cross_table
  expect_identical(replaced$selected_l1_sensitivity, 2)
  expect_gt(replaced$selected_l2_sensitivity, sqrt(2))
})

test_that("cross categorical source is capacity padded and never fills release cells", {
  left <- .cross_cat_fixture("peer_a")
  right <- .cross_cat_fixture("peer_b")
  layout_left <- .dsvert_dp_gaussian_cross_layout(left$manifest)
  layout_right <- .dsvert_dp_gaussian_cross_layout(right$manifest)
  expect_identical(layout_left, layout_right)
  expect_identical(
    layout_left$payload_rule,
    paste0("manifest_order_capacity_padded_ring128_value_one_hot_and_",
           "validity_no_exact_release_v1"))
  material_left <- .dsvert_dp_gaussian_cross_materialize_source(
    left$policy, left$manifest, left$resolved)
  material_right <- .dsvert_dp_gaussian_cross_materialize_source(
    right$policy, right$manifest, right$resolved)
  expect_identical(
    material_left$private_alignment_consensus_hash,
    material_right$private_alignment_consensus_hash)
  blocks <- layout_left$blocks
  scale <- 256
  left_onehot <- blocks[["categorical::cross_table::left::one_hot"]]
  right_onehot <- blocks[["categorical::cross_table::right::one_hot"]]
  expect_identical(
    material_left$values[left_onehot$start:left_onehot$end],
    c(scale, 0, 0, 0, 0, scale, 0, 0))
  expect_identical(
    material_right$values[right_onehot$start:right_onehot$end],
    c(scale, 0, scale, 0, 0, scale, 0, 0, 0, 0, 0, 0))
  release <- .dsvert_dp_capsule_coordinate_layout(left$manifest)
  block <- release$blocks[["categorical_pairs::cross::cross_table"]]
  expect_true(all(material_left$values[block$start:block$end] == 0))
  expect_true(all(material_right$values[block$start:block$end] == 0))
})

test_that("cross categorical private input binding requires signed allocation first", {
  fixture <- .cross_cat_fixture("peer_a")
  session <- new.env(parent = emptyenv())
  session$.exact_gc_peer_binding_digest <- strrep("d", 64L)
  calls <- 0L
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_categorical_cross_bind_impl(
      fixture$manifest_json, "cross_table",
      "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
      '{"peer":"peer_a"}', '{"peer":"peer_b"}',
      .policy = fixture$policy, .secret = fixture$secret,
      .verifier = .cross_cat_verifier,
      .allocation_observer = function(
          policy, manifest_json, first_opening_json, second_opening_json,
          secret, verifier) {
        calls <<- calls + 1L
        expect_identical(first_opening_json, '{"peer":"peer_a"}')
        expect_identical(second_opening_json, '{"peer":"peer_b"}')
        stop("categorical allocation observer sentinel")
      }),
    .S = function(...) session,
    .exact_gc_vecmul_party_context = function(...) list(
      self_name = "peer_a", peer_name = "peer_b"),
    .package = "dsVert"), "categorical allocation observer sentinel")
  expect_identical(calls, 1L)
})

test_that("categorical exact producer accepts only the active fixed stage", {
  ss <- new.env(parent = emptyenv())
  purpose <- "dp.categorical-cross.0123456789abcdefabcd.cell-products"
  ss$.dp_categorical_cross_stage <- list(
    status = "preparing", producer = .DSVERT_DP_CATEGORICAL_CROSS_PRODUCER,
    purpose = purpose, x_key = "categorical_x", y_key = "categorical_y",
    output_key = "categorical_z", ring_bits = 128L, frac_bits = 8L,
    operand_bound = "256")
  expect_identical(
    .exact_gc_vecmul_manifest_policy(
      .DSVERT_DP_CATEGORICAL_CROSS_PRODUCER, purpose, ss),
    list(
      x_key = "categorical_x", y_key = "categorical_y",
      output_key = "categorical_z", bound_x = "256", bound_y = "256",
      ring_bits = 128L, frac_bits = 8L))
  ss$.dp_categorical_cross_stage$status <- "prepared"
  expect_error(.exact_gc_vecmul_manifest_policy(
    .DSVERT_DP_CATEGORICAL_CROSS_PRODUCER, purpose, ss), "provenance")
})

test_that("categorical finalizer persists, authenticates and replays only shares", {
  fixture <- .cross_cat_fixture("peer_a")
  artifact <- .dsvert_dp_categorical_cross_artifacts(
    fixture$manifest)$cross_table
  parsed <- .dsvert_dp_capsule_source_contract_json(
    fixture$policy, fixture$manifest_json)
  contract <- parsed$contract
  release_layout <- .dsvert_dp_capsule_coordinate_layout(fixture$manifest)
  private_layout <- .dsvert_dp_gaussian_cross_layout(fixture$manifest)
  block <- release_layout$blocks[[
    "categorical_pairs::cross::cross_table"]]
  session_id <- "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  ss <- new.env(parent = emptyenv())
  ss$.exact_gc_peer_binding_digest <- strrep("d", 64L)
  handle <- strrep("A", 43L)
  batch <- "categorical-batch"
  purpose <- paste0(
    "dp.categorical-cross.",
    .dsvert_dp_categorical_cross_tag(contract$capsule_id, "cross_table"),
    ".cell-products")
  # Six public cell segments, each of fixed length four. Only A/X and B/Y
  # contain one lattice unit.
  products <- c(
    256, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 256, 0, 0, 0,
    rep(0, 8))
  output_key <- "categorical_products"
  encoded <- gsub("[\r\n]", "", jsonlite::base64_enc(
    .cross_cat_records(products)))
  ss[[output_key]] <- encoded
  ss$.exact_gc_vecmul_manifests <- stats::setNames(list(list(
    state = "consumed", producer = .DSVERT_DP_CATEGORICAL_CROSS_PRODUCER,
    purpose = purpose, output_key = output_key, claimed_batch = batch,
    context_hash = strrep("1", 64L), total_n = 24L,
    plan = list(plan_id = strrep("2", 64L), ring_bits = 128L,
                frac_bits = 8L, backend = "direct-wide"))), handle)
  ss$.exact_gc_vecmul_input_stages <- stats::setNames(list(list(
    state = "complete", manifest_handle = handle, output_key = output_key,
    output_digest = .exact_gc_vecmul_value_digest(encoded),
    context_hash = strrep("3", 64L))), batch)
  binding <- list(
    version = .DSVERT_DP_CATEGORICAL_CROSS_BIND_VERSION,
    capsule_id = contract$capsule_id, analysis_id = "cross_table",
    artifact = artifact, artifact_sha256 = .dsvert_joint_dp_hash(artifact),
    tag = .dsvert_dp_categorical_cross_tag(
      contract$capsule_id, "cross_table"),
    source_contract_hash = parsed$contract_hash,
    private_layout_sha256 =
      private_layout$transport_coordinate_order_sha256,
    transcript_sha256 = .dsvert_joint_dp_hash(artifact$transcript),
    numeric_certificate_sha256 =
      .dsvert_joint_dp_hash(artifact$numeric_certificate),
    peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    capacity = 4L, row_levels = 2L, column_levels = 3L, grid_bits = 8L,
    left_key = "private_left", right_key = "private_right",
    left_validity_key = "valid_left", right_validity_key = "valid_right",
    state = "installed", stage = list(
      status = "prepared", producer = .DSVERT_DP_CATEGORICAL_CROSS_PRODUCER,
      purpose = purpose, output_key = output_key, manifest_handle = handle,
      installed = character()))
  ss$.dp_categorical_cross_bindings <- list(cross_table = binding)

  finalize <- function(reducer = .cross_cat_reducer) {
    testthat::with_mocked_bindings(
      .dsvert_dp_categorical_cross_finalize_impl(
        fixture$manifest_json, "cross_table", session_id,
        .policy = fixture$policy, .secret = fixture$secret,
        .signer = .cross_cat_signer, .verifier = .cross_cat_verifier,
        .reducer = reducer),
      .S = function(id) {
        expect_identical(id, session_id)
        ss
      },
      .exact_gc_vecmul_validate_manifest_mac = function(...) invisible(TRUE),
      .package = "dsVert")
  }
  receipt_json <- finalize()
  receipt <- .dsvert_dp_capsule_source_decode_json(
    receipt_json, "test categorical receipt", 128L * 1024L)
  expect_identical(receipt$state, "complete")
  expect_false(receipt$result_share_exposed)
  expect_false(receipt$exact_intermediates_exposed)
  expect_false(receipt$alignment_hash_exposed)
  expect_false(receipt$alignment_hash_exposed_to_relay)
  expect_false(receipt$alignment_hash_exposed_to_computation_peers)
  expect_false(any(c("share", "values", "counts", "table") %in%
                     names(receipt)))
  expect_identical(finalize(function(...) stop("must replay")), receipt_json)

  stored <- .dsvert_dp_capsule_source_with_store(
    fixture$policy, fixture$secret, function(connection) {
      .dsvert_dp_categorical_cross_result_load(
        connection, contract$capsule_id, "cross_table", fixture$secret)
    })
  expect_identical(
    .cross_cat_decode(.dsvert_relay_b64url_decode(
      stored$result_share_b64, "stored categorical share")),
    c(256, 0, 0, 256, 0, 0))
  tampered <- stored
  tampered$result_share_sha256 <- strrep("0", 64L)
  expect_error(.dsvert_dp_categorical_cross_result_validate(
    tampered, fixture$policy, contract, artifact, block,
    .cross_cat_verifier), "payload is invalid")

  injected <- .dsvert_dp_capsule_source_with_store(
    fixture$policy, fixture$secret, function(connection) {
      .dsvert_dp_categorical_cross_inject_release_share_internal(
        connection, fixture$secret, fixture$manifest, contract,
        list(offset = 0L, count = release_layout$coordinate_count),
        raw(release_layout$coordinate_count * 16L),
        policy = fixture$policy, verifier = .cross_cat_verifier)
    })
  bytes <- unlist(lapply(seq.int(block$start, block$end), function(index) {
    seq.int((index - 1L) * 16L + 1L, length.out = 16L)
  }), use.names = FALSE)
  expect_identical(.cross_cat_decode(injected[bytes]),
                   c(256, 0, 0, 256, 0, 0))
})
