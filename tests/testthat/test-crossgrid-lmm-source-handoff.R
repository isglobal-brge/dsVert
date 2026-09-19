.lmm_transport_fixture <- function(f) {
  artifact <- .dsvert_dp_grouped_cross_workload_artifact(f$contract)
  families <- setNames(rep(list(list(artifacts = list())), 10L), c(
    "admitted_count", "numeric_moments", "numeric_pair_moments", "gaussian_models",
    "fixed_numeric_histograms", "categorical_marginals", "categorical_pairs",
    "correlation_artifacts", "describe_artifacts", "survival_artifacts"))
  families$admitted_count <- list(owner_peer = "peer_a", dataset = "cohort")
  families$survival_artifacts <- list()
  families$gaussian_models$artifacts <- list(grouped = artifact)
  manifest <- list(logical_snapshot = f$contract$spec$logical_snapshot,
    capsule_identity = list(capsule_id = strrep("6", 64)),
    workload = list(coordinate_count = artifact$coordinate_count + 1L,
      families = families, capsule_mechanism = list(source_context_hash = strrep("a", 64))))
  layout <- .dsvert_dp_lmm_cross_transport_layout(manifest, artifact)
  transport <- list(version = .DSVERT_DP_GLM_GRID_CROSS_SOURCE_VERSION,
    purpose = .DSVERT_DP_GLM_GRID_CROSS_SOURCE_PURPOSE,
    capsule_id = manifest$capsule_identity$capsule_id,
    logical_snapshot_sha256 = .dsvert_joint_dp_hash(manifest$logical_snapshot),
    workload_sha256 = .dsvert_joint_dp_hash(manifest$workload),
    source_context_hash = manifest$workload$capsule_mechanism$source_context_hash,
    peer_pinset_sha256 = f$policy$peer_pinset_sha256,
    source_peers = artifact$participating_peers,
    designated_noise_peers = artifact$computation_peers,
    coordinate_count = layout$transport_coordinate_count,
    coordinate_order_sha256 = layout$transport_coordinate_order_sha256,
    ring_bits = 128, record_bytes = 16,
    record_encoding = "little_endian_unsigned_fixed_16_bytes",
    chunk_coordinates = 8192, chunk_count = ceiling(layout$transport_coordinate_count / 8192),
    chunk_shape = "fixed_release_prefix_and_capacity_padded_private_slices",
    history_gate = FALSE, ready_for_sampling = FALSE,
    release_coordinate_count = layout$release_coordinate_count,
    release_coordinate_order_sha256 = layout$release_coordinate_order_sha256,
    private_layout_sha256 = layout$transport_coordinate_order_sha256,
    cross_input_peers = artifact$participating_peers,
    private_alignment_consensus = .DSVERT_DP_CAPSULE_SOURCE_ALIGNMENT_SHARING)
  list(artifact = artifact, manifest = manifest, transport = transport, layout = layout)
}

.lmm_handoff_fixture <- function(owners = 2L) {
  f <- .grouped_contract_fixture("lmm", owners = owners)
  f$policy$peer_name <- "peer_a"
  f$secret <- as.raw(seq_len(32L))
  f$ss <- new.env(parent = emptyenv())
  f$ss$.exact_gc_peer_binding_digest <- strrep("8", 64)
  f$ss$.exact_gc_transport_initialized <- TRUE
  f$ss$.exact_gc_self_name <- "peer_a"
  f$ss$peer_transport_pks <- list(peer_b = "private-test-transport")
  f$ss$.exact_gc_peer_identity_pks <- list(peer_b = "pinned-test-peer")
  batches <- .dsvert_dp_alignment_mask_batches(f$ss)
  batch <- new.env(parent = emptyenv())
  batch$status <- "complete"
  batch$peer_binding_digest <- f$ss$.exact_gc_peer_binding_digest
  batch$terminal_peer_blob_digest <- strrep("9", 64)
  batch$first_validity_share <- jsonlite::base64_enc(as.raw(1))
  batches$fixture <- batch
  f$contract <- .dsvert_dp_grouped_cross_contract_validate(
    f$contract, f$policy, f$schema)
  context <- .lmm_transport_fixture(f)
  f[names(context)] <- context
  f$source_hash <- .dsvert_joint_dp_hash(f$transport)
  batch$capsule_id <- f$transport$capsule_id
  batch$contract_hash <- f$source_hash
  layout <- f$layout
  route <- layout$blocks[["grouped::peer_a$cluster::value"]]
  presence <- layout$blocks[["grouped::peer_a$cluster::validity"]]
  payload <- numeric(layout$transport_coordinate_count)
  payload[route$start + 0:7] <- c(1, 0, 1, 0, 0, 0, 0, 0)
  payload[presence$start + 0:7] <- c(1, 1, 1, 0, 1, 0, 0, 0)
  f$producer <- structure(list(
    version = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION,
    purpose = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE,
    capsule_id = f$transport$capsule_id, peer_name = "peer_a",
    logical_snapshot = f$contract$spec$logical_snapshot,
    source_context_hash = strrep("a", 64), coordinate_count = length(payload),
    coordinate_order_sha256 = layout$transport_coordinate_order_sha256, snapshot_binding_sha256 = strrep("c", 64),
    producer_version = .DSVERT_DP_GAUSSIAN_CROSS_SOURCE_PRODUCER_VERSION,
    state = "internal_incremental_secret_share_input_never_release",
    value_commitment_sha256 = strrep("d", 64), authenticatable_sha256 = strrep("e", 64),
    private_alignment_consensus_hash = strrep("f", 64),
    read_range = function(start, count) payload[seq.int(start, length.out = count)],
    generation_chunks = function(...) list(), reset = function() invisible(NULL)),
    class = c("dsvert_capsule_source_producer", "list"))
  f
}

test_that("LMM handoff transposes opaque shares into typed rows after private alignment", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .lmm_handoff_fixture(owners)
    spec <- f$contract$spec
    numeric <- c(unlist(spec$predictor_order), spec$outcome$reference)
    variables <- c(numeric, spec$grouping$reference)
    values <- setNames(lapply(seq_along(variables), function(i)
      as.raw(rep(i * 16 + seq_len(8L), each = 16L))), variables)
    validities <- lapply(values, function(value) as.raw(255L - as.integer(value)))
    run <- function() .dsvert_dp_lmm_cross_source_handoff(f$contract, f$policy,
      f$schema, f$source_hash, values, validities, f$ss, f$transport$capsule_id)
    handoff <- run()
    expect_identical(handoff$plan$Numeric$Sigma2Q64, "18446744073709551616")
    expect_identical(handoff$plan$Numeric$Tau2Q64, "4611686018427387904")
    expect_identical(handoff$plan$Beta, spec$beta_encoded)
    for (row in seq_len(8L)) {
      source <- seq.int((row - 1L) * 16L + 1L, length.out = 16L)
      width <- length(numeric) * 16L
      target <- seq.int((row - 1L) * width + 1L, length.out = width)
      expect_identical(jsonlite::base64_dec(handoff$numeric$Share)[target],
        unname(do.call(c, lapply(values[numeric], `[`, source))))
      columns <- c(validities[numeric], values[spec$grouping$reference],
                   validities[spec$grouping$reference])
      width <- length(columns) * 16L
      target <- seq.int((row - 1L) * width + 1L, length.out = width)
      expect_identical(jsonlite::base64_dec(handoff$metadata$Share)[target],
        unname(do.call(c, lapply(columns, `[`, source))))
    }
    expect_true(all(jsonlite::base64_dec(handoff$numeric$Validity) == as.raw(1)))
    f$policy$peer_name <- "peer_b"
    f$ss$.exact_gc_self_name <- "peer_b"
    f$ss$peer_transport_pks <- list(peer_a = "private-test-transport")
    f$ss$.exact_gc_peer_identity_pks <- list(peer_a = "pinned-test-peer")
    f$ss$.dp_alignment_mask_batches$fixture$first_validity_share <- jsonlite::base64_enc(as.raw(0))
    expect_true(all(jsonlite::base64_dec(run()$numeric$Validity) == as.raw(0)))
    f$ss$.dp_alignment_mask_batches$fixture$first_validity_share <- jsonlite::base64_enc(as.raw(1))
    expect_true(all(jsonlite::base64_dec(run()$numeric$Validity) == as.raw(1)))
    f$ss$.dp_alignment_mask_batches$fixture$status <- "alignment_contract_invalid"
    expect_error(run(), "alignment gate is not complete")
    f$ss$.dp_alignment_mask_batches$fixture$status <- "running"
    expect_error(run(), "alignment gate is not complete")
    f$ss$.dp_alignment_mask_batches$fixture$status <- "complete"
    f$ss$.dp_alignment_mask_batches$fixture$peer_binding_digest <- strrep("0", 64)
    expect_error(run(), class = "dsvert_dp_public_failure")
  }
})

test_that("owner-local route sidecar binds materialized order snapshot and signed scale", {
  f <- .lmm_handoff_fixture()
  sidecar <- .dsvert_dp_lmm_cross_route_sidecar(f$policy, f$secret, f$manifest,
    f$transport, f$schema, "grouped", f$producer)
  read <- function(value = sidecar, producer = f$producer, current_transport = f$transport,
                   policy = f$policy, secret = f$secret) {
    .dsvert_dp_lmm_cross_route_handoff(value, policy, secret, f$manifest,
      current_transport, f$schema, "grouped", producer)
  }
  expect_identical(read(), list(labels = as.list(c(1L, 0L, 1L, 0L, 0L, 0L, 0L, 0L)),
    present = as.list(c(TRUE, TRUE, TRUE, FALSE, TRUE, FALSE, FALSE, FALSE))))
  # Capacity overflow stays private for the router; R must not compact slots or
  # reject based on a private per-cluster live count.
  overflow <- f$producer
  overflow$read_range <- function(start, count) {
    route <- f$layout$blocks[["grouped::peer_a$cluster::value"]]
    if (identical(start, route$start)) rep(0, count) else rep(1, count)
  }
  expect_no_error(.dsvert_dp_lmm_cross_route_sidecar(f$policy, f$secret, f$manifest,
    f$transport, f$schema, "grouped", overflow))
  for (field in c("snapshot_binding_sha256", "value_commitment_sha256",
                 "private_alignment_consensus_hash", "coordinate_order_sha256")) {
    other <- f$producer
    other[[field]] <- strrep("0", 64)
    expect_error(read(producer = other), class = "dsvert_dp_public_failure")
  }
  tampered <- sidecar
  tampered$labels[[1L]] <- 0L
  expect_error(read(tampered), class = "dsvert_dp_public_failure")
  changed_transport <- f$transport
  changed_transport$workload_sha256 <- strrep("1", 64)
  expect_error(read(current_transport = changed_transport), class = "dsvert_dp_public_failure")
  expect_error(read(secret = as.raw(rep(0, 32))), class = "dsvert_dp_public_failure")
  policy <- f$policy
  policy$peer_name <- "peer_b"
  expect_error(read(policy = policy), class = "dsvert_dp_public_failure")
  expect_false(any(grepl("labels|present|controls|count", names(sidecar$binding))))
})

test_that("signed dyadic variances reach Go without decimal precision loss", {
  f <- .grouped_contract_fixture("lmm")
  f$raw$parameters$residual_variance <- 1 + 2^-16
  spec <- .dsvert_dp_grouped_cross_spec(f$raw, f$policy, f$authenticated)
  plan <- .dsvert_dp_lmm_cross_source_plan(list(spec = spec), strrep("7", 64))
  expect_identical(plan$Numeric$Sigma2Q64, "18447025548686262272")
})

test_that("LMM typed loader authenticates stored numeric and routing blocks before handoff", {
  f <- .lmm_handoff_fixture(5L)
  artifact <- f$artifact
  manifest <- f$manifest
  transport <- f$transport
  layout <- f$layout
  expect_identical(.dsvert_dp_capsule_source_contract_validate(transport), transport)
  source_hash <- .dsvert_joint_dp_hash(transport)
  batch <- f$ss$.dp_alignment_mask_batches$fixture
  batch$capsule_id <- transport$capsule_id
  batch$contract_hash <- source_hash
  batch$projection_version <- "private-suffix-v2"
  batch$source_offset <- layout$private_start - 1
  batch$total <- layout$transport_coordinate_count - layout$private_start + 1
  batch$alignment_contract <- .DSVERT_DP_ALIGNMENT_MASK_PRIVATE_CONTRACT
  con <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
  on.exit(DBI::dbDisconnect(con), add = TRUE)
  DBI::dbExecute(con, paste("CREATE TABLE source_incoming_state (",
    "capsule_id TEXT PRIMARY KEY, record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"))
  DBI::dbExecute(con, paste("CREATE TABLE source_aggregate_chunks (",
    "capsule_id TEXT, chunk_index INTEGER, record_json TEXT NOT NULL, row_mac TEXT NOT NULL,",
    "PRIMARY KEY(capsule_id,chunk_index))"))
  state <- list(version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
    capsule_id = transport$capsule_id, contract_hash = source_hash,
    recipient_name = "peer_a", next_source_index = 6, next_chunk_index = 0,
    complete = TRUE, private_alignment_consensus_shares = setNames(
      rep(list(.dsvert_relay_b64url_encode(raw(32))), 5L), unlist(artifact$participating_peers)))
  .dsvert_dp_capsule_source_record_insert(con, "source_incoming_state", "capsule_id",
    list(transport$capsule_id), state, f$secret)
  all_bytes <- raw(16 * layout$transport_coordinate_count)
  variables <- c(unlist(f$contract$spec$predictor_order), f$contract$spec$outcome$reference,
    f$contract$spec$grouping$reference)
  values <- validities <- setNames(vector("list", length(variables)), variables)
  for (i in seq_along(layout$blocks)) {
    block <- layout$blocks[[i]]
    bytes <- as.raw(rep(i * 16 + seq_len(block$length), each = 16))
    all_bytes[seq.int((block$start - 1) * 16 + 1, length.out = length(bytes))] <- bytes
    variable <- sub("::(value|validity)$", "", sub("^grouped::", "", names(layout$blocks)[i]))
    if (block$kind == "value") values[[variable]] <- bytes else validities[[variable]] <- bytes
  }
  records <- lapply(seq_len(transport$chunk_count) - 1, function(index) {
    geometry <- .dsvert_dp_capsule_source_chunk_geometry(transport, index)
    bytes <- all_bytes[seq.int(geometry$offset * 16 + 1, length.out = geometry$count * 16)]
    record <- list(version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
      capsule_id = transport$capsule_id, contract_hash = source_hash,
      recipient_name = "peer_a", chunk_index = index, coordinates_in_chunk = geometry$count,
      source_count = 5, aggregate_b64 = .dsvert_dp_capsule_source_raw_b64(bytes))
    .dsvert_dp_capsule_source_record_insert(con, "source_aggregate_chunks",
      c("capsule_id", "chunk_index"), list(transport$capsule_id, index), record, f$secret)
    record
  })
  # Only connection acquisition is replaced. Real private row MACs, source
  # contract identities, source counts, chunk geometry and bytes are verified.
  local_mocked_bindings(.dsvert_dp_capsule_source_with_store = function(policy, secret, code) code(con))
  load <- function(current_manifest = manifest, current_transport = transport) {
    .dsvert_dp_lmm_cross_load_handoff(f$policy, f$secret, current_manifest,
      current_transport, f$schema, f$ss, "grouped")
  }
  expected <- .dsvert_dp_lmm_cross_source_handoff(f$contract, f$policy, f$schema,
    source_hash, values, validities, f$ss, transport$capsule_id)
  expect_identical(load(), expected)
  update <- function(record) .dsvert_dp_capsule_source_record_update(con,
    "source_aggregate_chunks", record, f$secret,
    "capsule_id = ? AND chunk_index = ?", list(transport$capsule_id, 1L))
  for (field in c("capsule_id", "contract_hash", "recipient_name", "chunk_index")) {
    changed <- records[[2L]]
    changed[[field]] <- if (field == "chunk_index") 0 else "different-source"
    update(changed)
    expect_error(load(), class = "dsvert_dp_public_failure")
  }
  changed <- records[[2L]]
  changed$source_count <- 4
  update(changed)
  expect_error(load(), "completeness validation")
  update(records[[2L]])
  DBI::dbExecute(con, "UPDATE source_aggregate_chunks SET row_mac=? WHERE chunk_index=1",
                 params = list(strrep("0", 64)))
  expect_error(load(), "private-store authentication")
  update(records[[2L]])
  batch$source_offset <- batch$source_offset + 1
  expect_error(load(), class = "dsvert_dp_public_failure")
  batch$source_offset <- batch$source_offset - 1
  changed_manifest <- manifest
  changed_manifest$workload$families$gaussian_models$artifacts$grouped$grouping$reference <- "peer_b$other"
  expect_error(load(current_manifest = changed_manifest), class = "dsvert_dp_public_failure")
  changed_transport <- transport
  changed_transport$workload_sha256 <- strrep("0", 64)
  expect_error(load(current_transport = changed_transport), class = "dsvert_dp_public_failure")
  expect_identical(load(), expected)
})

test_that("private worker preparation uses pinned identity roles and keeps native JSON opaque", {
  f <- .lmm_handoff_fixture()
  manifest <- f$manifest
  transport <- f$transport
  sidecar <- .dsvert_dp_lmm_cross_route_sidecar(f$policy, f$secret, manifest,
    transport, f$schema, "grouped", f$producer)
  pins <- f$policy$peer_pinset
  ids <- setNames(paste0("dsv1_", c(strrep("1", 64), strrep("2", 64))), names(pins))
  f$ss$.exact_gc_peer_identity_pks <- list(peer_b = unname(pins[["peer_b"]]))
  root <- tempfile("private-lmm-prepare-")
  dir.create(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE), add = TRUE)
  received <- list()
  verified <- list(private_verified_store_handoff = TRUE)
  opaque <- jsonlite::base64_enc(charToRaw("synthetic opaque native worker payload"))
  real_mpc <- .callMpcTool
  # The source-store reader and Go parser have separate tests. This perimeter
  # test captures their private invocation and checks role/sidecar separation.
  local_mocked_bindings(
    .dsvert_relay_peer_id = function(pk) unname(ids[match(pk, unname(pins))]),
    .key_get = function(key, ss) unname(pins[[ss$.exact_gc_self_name]]),
    .dsvert_dp_capsule_source_store_path = function(policy) file.path(root, "source.sqlite"),
    .dsvert_dp_glm_grid_cross_key = function(...) strrep("5", 64),
    .dsvert_dp_lmm_cross_load_handoff = function(...) verified,
    .callMpcTool = function(command, input_data, simplify_output = TRUE) {
      if (!identical(command, "grouped-lmm-staged-prepare-v1")) {
        return(real_mpc(command, input_data, simplify_output = simplify_output))
      }
      expect_identical(command, "grouped-lmm-staged-prepare-v1")
      expect_false(simplify_output)
      received[[length(received) + 1L]] <<- input_data
      list(worker_input = opaque, purpose = paste0("grouped-lmm-staged-v1/", strrep("a", 64)),
           vector_len = 3)
    })
  run <- function(route = sidecar, producer = f$producer) {
    .dsvert_dp_lmm_cross_prepare_worker(f$policy, f$secret, manifest, transport,
      f$schema, f$ss, "grouped", route, producer)
  }
  result <- run()
  expect_identical(result$grouped_lmm, opaque)
  expect_identical(received[[1L]]$handoff, verified)
  expect_identical(received[[1L]]$role, "garbler")
  expect_identical(received[[1L]]$authorities, as.list(unname(ids)))
  expect_identical(received[[1L]]$routing, sidecar[c("labels", "present")])
  expect_length(jsonlite::base64_dec(received[[1L]]$store_key), 32L)
  expect_identical(run(), result)
  expect_identical(received[[1L]], received[[2L]])
  # A group owner whose identity sorts after its peer is rejected; role order
  # is never silently changed to alphabetical owner order.
  ids[["peer_a"]] <- paste0("dsv1_", strrep("3", 64))
  expect_error(run(), class = "dsvert_dp_public_failure")
  expect_length(received, 2L)
  ids[["peer_a"]] <- paste0("dsv1_", strrep("1", 64))
  f$policy$peer_name <- "peer_b"
  f$ss$.exact_gc_self_name <- "peer_b"
  f$ss$peer_transport_pks <- list(peer_a = "private-test-transport")
  f$ss$.exact_gc_peer_identity_pks <- list(peer_a = unname(pins[["peer_a"]]))
  expect_error(run(), class = "dsvert_dp_public_failure")
  expect_identical(run(NULL, NULL), result)
  expect_identical(received[[3L]]$role, "evaluator")
  expect_null(received[[3L]]$routing)
})

test_that("real staged preparation CLI preserves typed source bytes and exact native integers", {
  f <- .lmm_handoff_fixture()
  spec <- f$contract$spec
  variables <- c(unlist(spec$predictor_order), spec$outcome$reference, spec$grouping$reference)
  word_bytes <- function(values) {
    result <- raw(16L * length(values))
    result[seq.int(1L, length(result), by = 16L)] <- as.raw(values)
    result
  }
  values <- setNames(rep(list(raw(16L * 8L)), length(variables)), variables)
  validities <- setNames(rep(list(word_bytes(rep(1L, 8L))), length(variables)), variables)
  sidecar <- .dsvert_dp_lmm_cross_route_sidecar(f$policy, f$secret, f$manifest,
    f$transport, f$schema, "grouped", f$producer)
  routing <- .dsvert_dp_lmm_cross_route_handoff(sidecar, f$policy, f$secret,
    f$manifest, f$transport, f$schema, "grouped", f$producer)
  values[[spec$grouping$reference]] <- word_bytes(unlist(routing$labels))
  validities[[spec$grouping$reference]] <- word_bytes(as.integer(unlist(routing$present)))
  handoff <- .dsvert_dp_lmm_cross_source_handoff(f$contract, f$policy, f$schema,
    f$source_hash, values, validities, f$ss, f$transport$capsule_id)
  directory <- tempfile("lmm-real-wire-")
  dir.create(directory, mode = "0700")
  on.exit(unlink(directory, recursive = TRUE), add = TRUE)
  authorities <- sort(vapply(unname(f$policy$peer_pinset), .dsvert_relay_peer_id, character(1L)))
  request <- list(handoff = handoff, role = "garbler", session = "synthetic-lmm-r-wire",
    authorities = as.list(unname(authorities)), semantic_key = strrep("5", 64),
    store_directory = normalizePath(directory), store_key = jsonlite::base64_enc(f$secret),
    routing = routing)
  result <- .callMpcTool("grouped-lmm-staged-prepare-v1", request, simplify_output = FALSE)
  expect_setequal(names(result), c("worker_input", "purpose", "vector_len"))
  expect_equal(result$vector_len, length(spec$beta_grid))
  expect_match(result$purpose, "^grouped-lmm-staged-v1/[0-9a-f]{64}$")
  native <- rawToChar(jsonlite::base64_dec(result$worker_input))
  expect_match(native, paste0('"Sigma2Q64":', handoff$plan$Numeric$Sigma2Q64, ','), fixed = TRUE)
  expect_match(native, paste0('"Tau2Q64":', handoff$plan$Numeric$Tau2Q64, ','), fixed = TRUE)
  expect_match(native, paste0('"Share":"', handoff$numeric$Share, '"'), fixed = TRUE)
  expect_match(native, paste0('"Share":"', handoff$metadata$Share, '"'), fixed = TRUE)
  expect_identical(.callMpcTool("grouped-lmm-staged-prepare-v1", request,
    simplify_output = FALSE), result)
})
