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
    peer_ids <- vapply(unname(f$policy$peer_pinset[unlist(spec$computation_peers)]),
      .dsvert_relay_peer_id, character(1L))
    first_admission <- as.raw(as.integer(peer_ids[[1L]] == sort(peer_ids, method = "radix")[[1L]]))
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
    expect_true(all(jsonlite::base64_dec(handoff$numeric$Validity) == first_admission))
    f$policy$peer_name <- "peer_b"
    f$ss$.exact_gc_self_name <- "peer_b"
    f$ss$peer_transport_pks <- list(peer_a = "private-test-transport")
    f$ss$.exact_gc_peer_identity_pks <- list(peer_a = "pinned-test-peer")
    f$ss$.dp_alignment_mask_batches$fixture$first_validity_share <- jsonlite::base64_enc(as.raw(0))
    second_admission <- as.raw(1L - as.integer(first_admission))
    expect_true(all(jsonlite::base64_dec(run()$numeric$Validity) == second_admission))
    f$ss$.dp_alignment_mask_batches$fixture$first_validity_share <- jsonlite::base64_enc(as.raw(1))
    expect_true(all(jsonlite::base64_dec(run()$numeric$Validity) == second_admission))
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
           vector_len = 3, stage_plan_digest = strrep("c", 64))
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
  for (family in c("lmm", "binomial_glmm")) {
  kind <- .dsvert_dp_staged_grouped_kind(family)
  f <- .lmm_handoff_fixture(family = family)
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
  result <- .callMpcTool(paste0("grouped-", kind, "-staged-prepare-v1"), request, simplify_output = FALSE)
  expect_setequal(names(result), c("worker_input", "purpose", "vector_len", "stage_plan_digest"))
  expect_equal(result$vector_len, f$artifact$coordinate_count)
  expect_match(result$purpose, paste0("^grouped-", kind, "-staged-v1/[0-9a-f]{64}$"))
  native <- rawToChar(jsonlite::base64_dec(result$worker_input))
  if (family == "lmm") {
  expect_match(native, paste0('"Sigma2Q64":', handoff$plan$Numeric$Sigma2Q64, ','), fixed = TRUE)
  expect_match(native, paste0('"Tau2Q64":', handoff$plan$Numeric$Tau2Q64, ','), fixed = TRUE)
  } else {
    expect_match(native, '"VarianceGrid":[0,16384]', fixed = TRUE)
    expect_match(native, paste0('"Share":"', handoff$outcome$Share, '"'), fixed = TRUE)
  }
  expect_match(native, paste0('"Share":"', handoff$numeric$Share, '"'), fixed = TRUE)
  expect_match(native, paste0('"Share":"', handoff$metadata$Share, '"'), fixed = TRUE)
  expect_identical(.callMpcTool(paste0("grouped-", kind, "-staged-prepare-v1"), request,
    simplify_output = FALSE), result)
  }
})

test_that("fresh and unilateral alignment attempts retain the same native source bytes", {
  for (family in c("lmm", "binomial_glmm")) {
  field <- paste0("grouped_", .dsvert_dp_staged_grouped_kind(family))
  f <- .lmm_handoff_fixture(family = family)
  pins <- f$policy$peer_pinset
  ids <- setNames(paste0("dsv1_", c(strrep("1", 64), strrep("2", 64))), names(pins))
  sidecar <- .dsvert_dp_lmm_cross_route_sidecar(f$policy, f$secret, f$manifest,
    f$transport, f$schema, "grouped", f$producer)
  root <- tempfile("lmm-cold-source-")
  dir.create(root, mode = "0700")
  on.exit(unlink(root, recursive = TRUE), add = TRUE)
  variables <- c(unlist(f$contract$spec$predictor_order), f$contract$spec$outcome$reference,
    f$contract$spec$grouping$reference)
  values <- validities <- setNames(rep(list(raw(16L * 8L)), length(variables)), variables)
  source_reads <- 0L
  reject_source <- FALSE
  local_mocked_bindings(
    .dsvert_relay_peer_id = function(pk) unname(ids[match(pk, unname(pins))]),
    .key_get = function(key, ss) unname(pins[[ss$.exact_gc_self_name]]),
    .dsvert_dp_capsule_source_store_path = function(policy) file.path(root, policy$peer_name, "source.sqlite"),
    .dsvert_dp_lmm_cross_load_handoff = function(policy, secret, manifest,
        source_contract, schema_manifest, ss, analysis_id) {
      source_reads <<- source_reads + 1L
      if (reject_source) .dsvert_dp_grouped_cross_fail()
      # The real source-store MAC and immutable aggregate checks have separate
      # coverage. Keep their returned additive bytes fixed across sessions.
      .dsvert_dp_lmm_cross_source_handoff(f$contract, policy, schema_manifest,
        f$source_hash, values, validities, ss, source_contract$capsule_id)
    }, .package = "dsVert")
  fresh <- function(peer, mask, attempt) {
    ss <- list2env(as.list.environment(f$ss, all.names = TRUE), parent = emptyenv())
    ss$session_id <- sprintf("00000000-0000-4000-8000-%012d", attempt)
    ss$.exact_gc_self_name <- peer
    other <- setdiff(names(pins), peer)
    ss$peer_transport_pks <- setNames(list("test-transport"), other)
    ss$.exact_gc_peer_identity_pks <- as.list(pins[other])
    ss$.exact_gc_peer_binding_digest <- .dsvert_joint_dp_hash(list(attempt = attempt))
    ss$.dp_alignment_mask_batches <- new.env(parent = emptyenv())
    batch <- list2env(as.list.environment(f$ss$.dp_alignment_mask_batches$fixture, all.names = TRUE), parent = emptyenv())
    batch$first_validity_share <- jsonlite::base64_enc(as.raw(mask))
    batch$peer_binding_digest <- ss$.exact_gc_peer_binding_digest
    batch$terminal_peer_blob_digest <- .dsvert_joint_dp_hash(list(terminal = attempt))
    ss$.dp_alignment_mask_batches$fixture <- batch
    ss
  }
  prepare <- function(peer, ss, producer = f$producer) {
    policy <- f$policy; policy$peer_name <- peer
    .dsvert_dp_lmm_cross_prepare_worker(policy, f$secret, f$manifest, f$transport,
      f$schema, ss, "grouped", if (peer == "peer_a") sidecar else NULL,
      if (peer == "peer_a") producer else NULL)
  }
  # A prepares on attempt1; B first prepares only after a reconnect/attempt2.
  # These two random local output masks need not belong to one XOR sharing.
  a <- prepare("peer_a", fresh("peer_a", 0L, 1L))
  b <- prepare("peer_b", fresh("peer_b", 0L, 2L))
  expect_identical(prepare("peer_a", fresh("peer_a", 1L, 2L)), a)
  expect_identical(prepare("peer_b", fresh("peer_b", 1L, 3L)), b)
  expect_identical(a$stage_plan_digest, b$stage_plan_digest)
  expect_identical(source_reads, 4L)
  for (status in c("running", "alignment_contract_invalid")) {
    ss <- fresh("peer_a", 1L, 4L)
    ss$.dp_alignment_mask_batches$fixture$status <- status
    expect_error(prepare("peer_a", ss), "alignment gate is not complete")
  }
  changed <- f$producer; changed$snapshot_binding_sha256 <- strrep("9", 64)
  expect_error(prepare("peer_a", fresh("peer_a", 1L, 5L), changed), class = "dsvert_dp_public_failure")
  reject_source <- TRUE
  expect_error(prepare("peer_b", fresh("peer_b", 1L, 6L)), class = "dsvert_dp_public_failure")
  reject_source <- FALSE
  # Changing additive source bytes still changes the sealed native input.
  # The native durable-source replacement test rejects that changed input.
  values[[1L]][[1L]] <- as.raw(1)
  expect_false(identical(prepare("peer_b", fresh("peer_b", 1L, 7L))[[field]], b[[field]]))
  }
})
