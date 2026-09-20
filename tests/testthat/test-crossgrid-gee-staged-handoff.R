test_that("fixed-rho GEE handoffs preserve signed native units and private source blocks", {
  for (family in c("binomial_gee", "poisson_gee")) {
    f <- .lmm_handoff_fixture(family = family, staged_gee = TRUE)
    spec <- f$contract$spec
    variables <- c(unlist(spec$predictor_order), spec$outcome$reference, spec$grouping$reference)
    values <- setNames(lapply(seq_along(variables), function(i)
      as.raw(rep(i * 16 + seq_len(8L), each = 16L))), variables)
    validities <- lapply(values, function(value) as.raw(255L - as.integer(value)))
    handoff <- .dsvert_dp_lmm_cross_source_handoff(f$contract, f$policy, f$schema,
      f$source_hash, values, validities, f$ss, f$transport$capsule_id)
    expect_named(handoff, c("plan", "numeric", "outcome", "metadata"))
    expect_identical(handoff$plan$version, "dsvert-gee-fixed-rho-staged-source-handoff-v1")
    expect_identical(handoff$plan$correlation_contract, "signed-analyst-fixed-rho-v1")
    expect_identical(handoff$plan$Numeric$ScoreClipQ16, "65536")
    expect_identical(handoff$plan$Numeric$RhoQ16, "0")
    expect_identical(handoff$plan$Numeric$RowLossCap, "1")
    expect_identical(handoff$plan$Caps, spec$staged_numeric$Caps)
    expect_null(handoff$plan$Numeric$Caps)
    expect_equal(f$artifact$coordinate_count, length(spec$beta_grid) *
      (1 + (length(spec$predictor_order) + 1) * (length(spec$predictor_order) + 2)))
    expect_identical(jsonlite::base64_dec(handoff$outcome$Share), values[[spec$outcome$reference]])
    expect_length(jsonlite::base64_dec(handoff$metadata$Share), 8L * 16L * (length(spec$predictor_order) + 3L))
    expect_identical(.dsvert_dp_staged_grouped_input_key(family), "grouped_gee")
    expect_identical(.exact_gc_output_kind("grouped-gee-fixed-rho-staged-v1"),
      "grouped-gee-fixed-rho-staged-ring128-share-v1")
    old <- .lmm_handoff_fixture(family = family)
    expect_error(.dsvert_dp_lmm_cross_source_contract(old$contract, old$policy,
      old$schema, old$source_hash))
  }
})

test_that("Fixed-rho GEE durable terminal records retain private validity and reject LMM swaps", {
  f <- .lmm_handoff_fixture(family = "poisson_gee", staged_gee = TRUE)
  count <- as.integer(f$artifact$coordinate_count)
  stage <- list(operation_id = paste0("op_", strrep("a", 32)),
    source_key = paste0("exact_gc_in_", strrep("a", 32)),
    output_key = paste0("exact_gc_out_", strrep("a", 32)),
    operation = "grouped-gee-fixed-rho-staged-v1", purpose = paste0("grouped-gee-fixed-rho-staged-v1/", strrep("b", 64)),
    vector_len = count, stage_plan_digest = strrep("e", 64))
  state <- c(stage, list(source_producer = "dp.gee-fixed-rho-grid-cross.staged-v1",
    ring_bits = 128L, frac_bits = 0L, context_hash = strrep("c", 64)))
  result <- list(version = "dsvert-exact-gc-result-v1", kind = "grouped-gee-fixed-rho-staged-ring128-share-v1",
    ring_bits = 128L, vector_len = count, share = gsub("[\r\n]", "", jsonlite::base64_enc(raw(16L * count))),
    validity_share = jsonlite::base64_enc(as.raw(c(5, rep(0, ceiling(count / 8) - 1)))), context_hash = state$context_hash,
    stage_receipt = strrep("d", 64), stage_plan_digest = stage$stage_plan_digest)
  value <- .exact_gc_validate_result(state, result)
  expect_identical(value$validity_share, result$validity_share)
  swapped <- result
  swapped$kind <- "grouped-lmm-staged-ring128-share-v1"
  expect_error(.exact_gc_validate_result(state, swapped), "kind")
  binding <- list(analysis_id = "grouped", artifact = f$artifact, contract = f$transport,
    contract_hash = f$source_hash, semantic_key = .dsvert_dp_glm_grid_cross_key(f$manifest, f$artifact, f$transport),
    peer_binding_digest = f$ss$.exact_gc_peer_binding_digest, stage = stage, worker_input = "opaque-native-input")
  f$ss$.dp_lmm_grid_cross <- list(grouped = binding)
  con <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
  on.exit(DBI::dbDisconnect(con), add = TRUE)
  DBI::dbExecute(con, paste("CREATE TABLE source_cross_grid_records (capsule_id TEXT, analysis_id TEXT,",
    "batch_index INTEGER, record_json TEXT NOT NULL, row_mac TEXT NOT NULL, PRIMARY KEY(capsule_id,analysis_id,batch_index))"))
  local_mocked_bindings(
    .dsvert_dp_capsule_source_with_store = function(policy, secret, code) code(con),
    .dsvert_dp_lmm_cross_public = function(binding, policy, phase, extra = list()) c(list(phase = phase), extra),
    .exact_gc_consume_output = function(...) value)
  expect_false(.dsvert_dp_lmm_cross_prepare(f$policy, f$secret, f$ss, "grouped")$persisted)
  input <- f$ss$.exact_gc_inputs[[stage$source_key]]
  expect_identical(input$grouped_gee, binding$worker_input)
  expect_null(input$grouped_lmm)
  expect_identical(input$allowed_spec$output_kind, "grouped-gee-fixed-rho-staged-ring128-share-v1")
  .dsvert_dp_lmm_cross_store(f$policy, f$secret, f$ss, "grouped")
  expect_true(.dsvert_dp_lmm_cross_prepare(f$policy, f$secret, f$ss, "grouped")$persisted)
  first <- .dsvert_dp_lmm_cross_finalize(f$policy, f$secret, f$ss, "grouped")
  expect_identical(.dsvert_dp_lmm_cross_finalize(f$policy, f$secret, f$ss, "grouped"), first)
  record <- .dsvert_dp_lmm_cross_record(con, f$secret, f$manifest, f$artifact, f$transport)
  expect_identical(record$version, "gee-fixed-rho-staged-complete-result-v1")
  expect_identical(record$validity_share, result$validity_share)
  public <- .dsvert_dp_lmm_cross_public_record(f$policy, f$secret, f$manifest, f$transport)
  expect_identical(public$version, "gee-fixed-rho-staged-terminal-binding-v1")
  expect_false(any(c("share", "validity_share") %in% names(public)))
  changed <- public
  changed$version <- "lmm-staged-terminal-binding-v1"
  expect_error(.dsvert_dp_lmm_cross_public_record_validate(changed, f$manifest, f$artifact, f$transport))
  chunk <- list(offset = 0, count = f$artifact$coordinate_count + 1L)
  injected <- .dsvert_dp_lmm_cross_inject(con, f$secret, f$manifest, f$transport,
    chunk, raw(chunk$count * 16L), f$policy)
  expect_identical(attr(injected, "dsvert_staged_source")$stage_plan_digest, stage$stage_plan_digest)
  expect_identical(attr(injected, "dsvert_staged_source")$stage_receipt, result$stage_receipt)
})

test_that("fixed-rho GEE worker preparation uses pinned identity roles and keeps native JSON opaque", {
  f <- .lmm_handoff_fixture(family = "binomial_gee", staged_gee = TRUE)
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
      if (!identical(command, "grouped-gee-fixed-rho-staged-prepare-v1")) {
        return(real_mpc(command, input_data, simplify_output = simplify_output))
      }
      expect_identical(command, "grouped-gee-fixed-rho-staged-prepare-v1")
      expect_false(simplify_output)
      received[[length(received) + 1L]] <<- input_data
      list(worker_input = opaque, purpose = paste0("grouped-gee-fixed-rho-staged-v1/", strrep("a", 64)),
           vector_len = f$artifact$coordinate_count, stage_plan_digest = strrep("c", 64))
    })
  run <- function(route = sidecar, producer = f$producer) {
    .dsvert_dp_lmm_cross_prepare_worker(f$policy, f$secret, manifest, transport,
      f$schema, f$ss, "grouped", route, producer)
  }
  result <- run()
  expect_identical(result$grouped_gee, opaque)
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


test_that("real GEE preparation CLI retains both families and every terminal coordinate", {
  directories <- character()
  on.exit(unlink(directories, recursive = TRUE), add = TRUE)
  binary <- Sys.getenv("DSVERT_GEE_TEST_BINARY", "")
  if (nzchar(binary)) {
    skip_if_not(file.exists(binary), "candidate GEE runtime is unavailable")
    local_mocked_bindings(.findMpcBinary = function() binary)
  }
  for (family in c("binomial_gee", "poisson_gee")) {
    f <- .lmm_handoff_fixture(family = family, staged_gee = TRUE)
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
    ids <- vapply(f$policy$peer_pinset, .dsvert_relay_peer_id, character(1L))
    peers <- names(sort(ids, method = "radix"))
    results <- list()
    for (role in c("garbler", "evaluator")) {
      self <- peers[[if (role == "garbler") 1L else 2L]]
      other <- setdiff(peers, self)
      f$policy$peer_name <- self
      f$ss$.exact_gc_self_name <- self
      f$ss$peer_transport_pks <- setNames(list("private-test-transport"), other)
      f$ss$.exact_gc_peer_identity_pks <- setNames(as.list(f$policy$peer_pinset[other]), other)
      handoff <- .dsvert_dp_lmm_cross_source_handoff(f$contract, f$policy, f$schema,
        f$source_hash, values, validities, f$ss, f$transport$capsule_id)
      directory <- tempfile("gee-real-wire-")
      dir.create(directory, mode = "0700")
      directories <- c(directories, directory)
      request <- list(handoff = handoff, role = role, session = "synthetic-gee-r-wire",
        authorities = as.list(unname(ids[peers])), semantic_key = strrep("5", 64),
        store_directory = normalizePath(directory), store_key = jsonlite::base64_enc(f$secret),
        routing = if (role == "garbler") routing else NULL)
      result <- .callMpcTool("grouped-gee-fixed-rho-staged-prepare-v1", request,
        simplify_output = FALSE)
      expect_setequal(names(result), c("worker_input", "purpose", "vector_len", "stage_plan_digest"))
      expect_equal(result$vector_len, f$artifact$coordinate_count)
      expect_equal(result$vector_len, length(spec$beta_grid) *
        (1 + (length(spec$predictor_order) + 1) * (length(spec$predictor_order) + 2)))
      expect_match(result$purpose, "^grouped-gee-fixed-rho-staged-v1/[0-9a-f]{64}$")
      native <- rawToChar(jsonlite::base64_dec(result$worker_input))
      expect_match(native, paste0('"Family":"', sub("_gee$", "", family), '"'), fixed = TRUE)
      expect_match(native, '"CorrelationContract":"signed-analyst-fixed-rho-v1"', fixed = TRUE)
      for (block in c("numeric", "outcome", "metadata")) {
        expect_match(native, paste0('"Share":"', handoff[[block]]$Share, '"'), fixed = TRUE)
      }
      expect_identical(.callMpcTool("grouped-gee-fixed-rho-staged-prepare-v1", request,
        simplify_output = FALSE), result)
      changed <- request
      changed$handoff$plan$correlation_contract <- "moment-estimated-alpha"
      expect_error(.callMpcTool("grouped-gee-fixed-rho-staged-prepare-v1", changed))
      results[[role]] <- result
    }
    expect_identical(results$garbler$purpose, results$evaluator$purpose)
    expect_identical(results$garbler$stage_plan_digest, results$evaluator$stage_plan_digest)
  }
})
