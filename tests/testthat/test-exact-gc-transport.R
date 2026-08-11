.exact_gc_test_cache <- new.env(parent = emptyenv())

.exact_gc_test_binary <- function() {
  cached <- .exact_gc_test_cache$binary
  if (!is.null(cached) && file.exists(cached)) return(cached)
  source_candidates <- file.path(
    .dsvert_test_source_roots(), "inst", "dsvert-mpc")
  source_candidates <- source_candidates[
    file.exists(file.path(source_candidates, "main.go"))]
  if (!length(source_candidates)) {
    .exact_gc_test_cache$binary <- .findMpcBinary()
    .exact_gc_test_cache$temporary <- FALSE
    return(.exact_gc_test_cache$binary)
  }
  go <- Sys.which("go")
  skip_if(!nzchar(go), "Go toolchain is required for exact-gc integration test")
  source <- source_candidates[[1L]]
  binary <- tempfile("dsvert-mpc-exact-test-")
  status <- withr::with_dir(source, system2(
    go, c("build", "-o", binary, "."), stdout = TRUE, stderr = TRUE))
  skip_if(!identical(attr(status, "status"), NULL) &&
            !identical(attr(status, "status"), 0L),
          paste(status, collapse = "\n"))
  Sys.chmod(binary, mode = "0700")
  .exact_gc_test_cache$binary <- binary
  .exact_gc_test_cache$temporary <- TRUE
  binary
}

.exact_gc_test_binary_cleanup <- function(binary) {
  if (isTRUE(.exact_gc_test_cache$temporary) &&
      identical(.exact_gc_test_cache$binary, binary)) {
    unlink(binary)
    .exact_gc_test_cache$binary <- NULL
    .exact_gc_test_cache$temporary <- NULL
  }
  invisible(NULL)
}

.exact_gc_test_b64_records <- function(values, bytes) {
  records <- lapply(values, function(value) {
    stopifnot(value >= 0, value <= 255)
    c(as.raw(value), raw(bytes - 1L))
  })
  gsub("[\r\n]", "", jsonlite::base64_enc(do.call(c, records)))
}

.exact_gc_test_add_le <- function(left, right, ring_bits) {
  stopifnot(length(left) == length(right))
  output <- raw(length(left))
  record_bytes <- .exact_gc_record_bytes(ring_bits)
  used_bytes <- as.integer(ceiling(ring_bits / 8))
  stopifnot(length(left) %% record_bytes == 0L)
  for (first in seq.int(1L, length(left), by = record_bytes)) {
    carry <- 0L
    last <- first + record_bytes - 1L
    for (i in seq.int(first, last)) {
      total <- as.integer(left[[i]]) + as.integer(right[[i]]) + carry
      output[[i]] <- as.raw(total %% 256L)
      carry <- total %/% 256L
    }
    if (ring_bits %% 8L) {
      last_used <- first + used_bytes - 1L
      output[[last_used]] <- as.raw(bitwAnd(
        as.integer(output[[last_used]]),
        bitwShiftL(1L, ring_bits %% 8L) - 1L))
    }
    if (used_bytes < record_bytes) {
      output[seq.int(first + used_bytes, last)] <- raw(record_bytes - used_bytes)
    }
  }
  output
}

.exact_gc_test_payload_histogram <- function(values) {
  levels <- c("0", "1-4KiB", "4-64KiB", "64-256KiB",
              "256KiB-1MiB", ">=1MiB")
  bucket <- ifelse(
    values == 0, levels[[1L]],
    ifelse(values <= 4096, levels[[2L]],
      ifelse(values <= 65536, levels[[3L]],
        ifelse(values <= 262144, levels[[4L]],
          ifelse(values < 1048576, levels[[5L]], levels[[6L]])))))
  as.list(stats::setNames(
    as.integer(table(factor(bucket, levels = levels))), levels))
}

.exact_gc_test_trace_summary <- function(trace) {
  if (!length(trace)) return(NULL)
  rows <- do.call(rbind, trace)
  directions <- unique(rows$direction)
  per_direction <- lapply(directions, function(direction) {
    selected <- rows[rows$direction == direction, , drop = FALSE]
    list(
      cycles = nrow(selected),
      active_payload_cycles = sum(selected$payload_bytes > 0),
      worker_write_cycles = sum(selected$worker_write_bytes > 0),
      payload_bytes = sum(selected$payload_bytes),
      worker_write_bytes = sum(selected$worker_write_bytes),
      delivered_bytes = sum(selected$delivered_bytes),
      payload_histogram = .exact_gc_test_payload_histogram(
        selected$payload_bytes),
      worker_write_histogram = .exact_gc_test_payload_histogram(
        selected$worker_write_bytes))
  })
  names(per_direction) <- directions

  by_cycle <- split(rows, rows$cycle)
  flow <- vapply(by_cycle, function(cycle) {
    active <- cycle$direction[cycle$worker_write_bytes > 0 |
                                cycle$payload_bytes > 0 |
                                cycle$delivered_bytes > 0]
    if (!length(active)) "idle" else paste(sort(active), collapse = "+")
  }, character(1L))
  runs <- rle(flow)
  list(
    per_direction = per_direction,
    empty_poll_cycles = sum(flow == "idle"),
    network_active_cycles = sum(flow != "idle"),
    public_flow_runs = data.frame(
      flow = runs$values, cycles = runs$lengths,
      stringsAsFactors = FALSE))
}

.exact_gc_test_delivery_fields <- function(envelope = NULL) {
  if (is.null(envelope)) {
    return(list(
      delivery_offset = 0,
      delivery_chunk_bytes = 0,
      delivery_payload_hash = "",
      delivery_payload = "",
      delivery_signature = ""))
  }
  list(
    delivery_offset = envelope$offset,
    delivery_chunk_bytes = envelope$chunk_bytes,
    delivery_payload_hash = envelope$payload_hash,
    delivery_payload = envelope$payload,
    delivery_signature = envelope$signature)
}

.exact_gc_test_pump <- function(ss_a, ss_b, session_id, operation_id,
                                seed_a, seed_b, concurrent = FALSE) {
  old_identity_seed <- getOption("dsvert.identity_seed")
  on.exit(options(dsvert.identity_seed = old_identity_seed), add = TRUE)
  states <- list(
    .exact_gc_operation_state(ss_a, operation_id),
    .exact_gc_operation_state(ss_b, operation_id))
  ids <- vapply(states, function(state) state$self_peer_id, character(1L))
  names(states) <- ids
  offsets <- stats::setNames(c(0, 0), ids)
  pending <- stats::setNames(vector("list", 2L), ids)
  complete <- stats::setNames(c(FALSE, FALSE), ids)
  seeds <- stats::setNames(c(seed_a, seed_b), ids)
  sessions <- stats::setNames(list(ss_a, ss_b), ids)
  started_at <- proc.time()[["elapsed"]]
  payload_bytes <- 0
  encoded_request_bytes <- 0
  trace_enabled <- nzchar(Sys.getenv("DSVERT_RUN_EXACT_GC_BENCHMARK")) ||
    identical(Sys.getenv("DSVERT_TRACE_EXACT_GC_BENCHMARK"), "true")
  cycle_trace <- list()
  trace_index <- 0L
  outbound_sizes <- stats::setNames(vapply(states, function(state) {
    .exact_gc_offset_read(
      file.path(state$spool, "outbound.head"), "exact-gc outbound head")
  }, numeric(1L)), ids)
  preferred_peer <- NULL

  for (iteration in seq_len(10000L)) {
    requests <- list()
    cycle_delivery <- stats::setNames(c(0, 0), ids)
    had_pending <- any(!vapply(pending, is.null, logical(1L)))
    preferred_before <- preferred_peer
    for (target in ids) {
      source <- setdiff(ids, target)
      if (!is.null(pending[[source]])) {
        cycle_delivery[[source]] <- as.numeric(pending[[source]]$chunk_bytes)
      }
      requests[[target]] <- c(
        list(peer_id = target, read_offset = offsets[[target]]),
        .exact_gc_test_delivery_fields(pending[[source]]),
        list(long_poll = !had_pending &&
          (is.null(preferred_before) || identical(target, preferred_before))))
    }
    encoded_request_bytes <- encoded_request_bytes +
      sum(vapply(requests, function(request) {
        sum(nchar(unlist(request[c(
          "delivery_payload_hash", "delivery_payload",
          "delivery_signature")], use.names = FALSE), type = "bytes")) +
          nchar(request$peer_id, type = "bytes") + 32L
      }, integer(1L)))
    responses <- list()
    if (isTRUE(concurrent)) {
      if (.Platform$OS.type == "windows") {
        stop("Concurrent exact-gc benchmark requires fork support.",
             call. = FALSE)
      }
      jobs <- lapply(ids, function(peer) parallel::mcparallel({
        options(dsvert.identity_seed = seeds[[peer]])
        ss <- sessions[[peer]]
        # processx handles cannot be polled reliably after fork. The real
        # parent-owned worker remains authoritative; done/error marker files
        # are still shared and checked by .exact_gc_refresh in this child.
        child_state <- .exact_gc_operation_state(ss, operation_id)
        child_state$process <- list(is_alive = function() TRUE)
        response <- do.call(.exact_gc_exchange_impl, c(list(
          ss = ss, session_id = session_id,
          operation_id = operation_id), requests[[peer]]))
        state <- .exact_gc_operation_state(ss, operation_id)
        list(
          response = response, status = state$status,
          out_cache = state$out_cache,
          output_key = state$output_key,
          source_key = state$source_key,
          output = if (identical(state$status, "complete")) {
            ss$.exact_gc_outputs[[state$output_key]]
          } else NULL)
      }, silent = TRUE))
      collected <- parallel::mccollect(jobs, wait = TRUE)
      if (length(collected) != length(ids) ||
          any(vapply(collected, inherits, logical(1L), "try-error"))) {
        details <- vapply(collected, function(value) {
          if (inherits(value, "try-error")) as.character(value) else ""
        }, character(1L))
        stop("Concurrent exact-gc benchmark fan-out failed: ",
             paste(details[nzchar(details)], collapse = " | "),
             call. = FALSE)
      }
      for (index in seq_along(ids)) {
        peer <- ids[[index]]
        child <- collected[[index]]
        state <- states[[peer]]
        state$status <- child$status
        state$out_cache <- child$out_cache
        if (identical(child$status, "complete")) {
          sessions[[peer]]$.exact_gc_outputs[[child$output_key]] <- child$output
          sessions[[peer]]$.exact_gc_inputs[[child$source_key]] <- NULL
        }
        responses[[peer]] <- child$response
      }
    } else {
      for (peer in ids) {
        old_seed <- getOption("dsvert.identity_seed")
        options(dsvert.identity_seed = seeds[[peer]])
        responses[[peer]] <- tryCatch(do.call(
          .exact_gc_exchange_impl, c(list(
            ss = sessions[[peer]], session_id = session_id,
            operation_id = operation_id), requests[[peer]])),
          error = function(e) {
            log_path <- file.path(states[[peer]]$spool, "worker-private.log")
            details <- if (file.exists(log_path)) {
              paste(readLines(log_path, warn = FALSE), collapse = " | ")
            } else "worker log absent"
            stop(conditionMessage(e), ": ", details, call. = FALSE)
          })
        options(dsvert.identity_seed = old_seed)
      }
    }
    current_outbound_sizes <- stats::setNames(vapply(states, function(state) {
      .exact_gc_offset_read(
        file.path(state$spool, "outbound.head"), "exact-gc outbound head")
    }, numeric(1L)), ids)
    worker_write_bytes <- current_outbound_sizes - outbound_sizes
    outbound_sizes <- current_outbound_sizes
    cycle_payload <- stats::setNames(c(0, 0), ids)
    new_sources <- character()
    for (target in ids) {
      source <- setdiff(ids, target)
      delivery <- pending[[source]]
      if (!is.null(delivery)) {
        expected <- delivery$offset + delivery$chunk_bytes
        expect_equal(responses[[target]]$inbound_size, expected)
        offsets[[source]] <- expected
        pending[[source]] <- NULL
      }
    }
    for (source in ids) {
      envelope <- responses[[source]]$outbound
      if (is.null(envelope) || envelope$offset < offsets[[source]]) next
      expect_equal(envelope$offset, offsets[[source]])
      if (is.null(pending[[source]])) {
        pending[[source]] <- envelope
        new_sources <- c(new_sources, source)
        payload_bytes <- payload_bytes + as.numeric(envelope$chunk_bytes)
        cycle_payload[[source]] <- as.numeric(envelope$chunk_bytes)
      } else expect_identical(pending[[source]], envelope)
    }
    if (length(new_sources) == 1L) {
      preferred_peer <- new_sources[[1L]]
    } else if (length(new_sources) > 1L) {
      preferred_peer <- NULL
    } else if (!had_pending && !is.null(preferred_before)) {
      preferred_peer <- NULL
    }
    for (peer in ids) {
      complete[[peer]] <- identical(responses[[peer]]$state, "complete")
    }
    if (trace_enabled) {
      for (source in ids) {
        state <- states[[source]]
        direction <- if (identical(state$role, "garbler")) {
          "garbler_to_evaluator"
        } else "evaluator_to_garbler"
        trace_index <- trace_index + 1L
        cycle_trace[[trace_index]] <- data.frame(
          cycle = iteration, direction = direction,
          payload_bytes = cycle_payload[[source]],
          worker_write_bytes = worker_write_bytes[[source]],
          delivered_bytes = cycle_delivery[[source]],
          worker_state = responses[[source]]$state,
          stringsAsFactors = FALSE)
      }
    }
    if (all(complete) && all(vapply(pending, is.null, logical(1L)))) {
      spool_sizes <- vapply(states, function(state) {
        sum(vapply(
          file.path(state$spool, c("inbound.segments", "outbound.segments")),
          .exact_gc_segment_retained_bytes, numeric(1L)))
      }, numeric(1L))
      return(invisible(list(
        rounds = iteration, payload_bytes = payload_bytes,
        encoded_request_bytes = encoded_request_bytes,
        spool_bytes = sum(spool_sizes),
        elapsed_seconds = proc.time()[["elapsed"]] - started_at,
        transport_trace = .exact_gc_test_trace_summary(cycle_trace))))
    }
    Sys.sleep(0.002)
  }
  stop("Exact-gc integration pump did not converge", call. = FALSE)
}

.exact_gc_test_server_call <- function(ss, identity_seed, fun, ...) {
  old <- options(
    dsvert.identity_seed = getOption("dsvert.identity_seed"),
    dsvert.peer_name = getOption("dsvert.peer_name"))
  on.exit(options(old), add = TRUE)
  options(dsvert.identity_seed = identity_seed)
  if (is.character(ss$.exact_gc_self_name) &&
      length(ss$.exact_gc_self_name) == 1L &&
      !is.na(ss$.exact_gc_self_name) && nzchar(ss$.exact_gc_self_name)) {
    options(dsvert.peer_name = ss$.exact_gc_self_name)
  }
  testthat::with_mocked_bindings(
    do.call(fun, list(...)), .S = function(session_id) ss,
    .package = "dsVert")
}

.exact_gc_analysis_test_identity_pk <- function(index) {
  .dsvert_relay_b64url_encode(as.raw(rep(as.integer(index), 32L)))
}

.exact_gc_analysis_test_signature <- function(message, identity_pk) {
  .dsvert_relay_b64url_encode(digest::hmac(
    key = charToRaw(identity_pk), object = message,
    algo = "sha512", serialize = FALSE, raw = TRUE))
}

.exact_gc_analysis_test_verifier <- function(
    message, identity_pk, signature, peer_name) {
  identical(signature,
            .exact_gc_analysis_test_signature(message, identity_pk))
}

.exact_gc_analysis_test_fixture <- function(k = 3L, pins = NULL) {
  if (is.null(pins)) {
    owners <- paste0("site_", seq_len(k))
    pins <- setNames(vapply(
      seq_along(owners), .exact_gc_analysis_test_identity_pk, character(1L)),
      owners)
  } else {
    owners <- names(pins)
    k <- length(pins)
  }
  config <- list(
    version = "dsvert-dp-count-config-v1",
    domain = "study-domain",
    cohort_id = "cohort-v1",
    dataset_id = "cohort_table",
    dataset_version = "v1",
    privacy_unit_column = "patient_id",
    alignment_purpose = "patient-record-alignment-v1",
    count_upper_bound = 1000,
    max_records_per_unit = 1,
    overflow_policy = "reject_operation",
    privacy = list(
      epsilon = 1, delta = 1e-6),
    calibration = list(implementation_delta = 1e-9),
    peer_pins = pins,
    backend_build_sha256 = strrep("a", 64L),
    transport_chunk_coordinates = 4096)
  config <- .dsvert_dp_count_config_validate_v1(config)
  plan <- .dsvert_joint_dp_laplace_plan_v2(
    .dsvert_dp_count_decimal_text(config$privacy$epsilon),
    .dsvert_dp_count_decimal_text(
      config$calibration$implementation_delta),
    "1", 1L, 8L, 4096L)
  certificate <- .dsvert_dp_count_plan_certificate_v1(plan, config)
  receipts <- stats::setNames(lapply(seq_along(owners), function(index) {
    peer <- owners[[index]]
    draft <- list(
      version = .DSVERT_DP_COUNT_RECEIPT_VERSION,
      peer_name = peer,
      peer_identity_pk = unname(config$peer_pins[[peer]]),
      config_sha256 = .dsvert_dp_count_config_hash_v1(config),
      psi_run_sha256 = strrep("b", 64L),
      snapshot_commitment = digest::digest(
        paste0("snapshot|", peer), algo = "sha256", serialize = FALSE),
      sampler_plan = certificate)
    .dsvert_dp_count_sign_receipt_v1(
      draft, .signer = function(message, peer_name, identity_pk) {
        .exact_gc_analysis_test_signature(message, identity_pk)
      })
  }), owners)
  contract <- .dsvert_dp_count_compile_v1(
    receipts, config, .verifier = .exact_gc_analysis_test_verifier)
  list(config = config, receipts = receipts, contract = contract,
       plan = plan)
}

.exact_gc_analysis_test_contract <- function(k = 3L, pins = NULL) {
  .exact_gc_analysis_test_fixture(k, pins)$contract
}

.exact_gc_frequency_test_fixture <- function(
    k = 3L, local_role = "source_owner") {
  peers <- paste0("site_", seq_len(k))
  pins <- stats::setNames(vapply(
    seq_len(k), .exact_gc_analysis_test_identity_pk, character(1L)), peers)
  role_peers <- c(source_owner = peers[[2L]],
                  secondary_noise_authority = peers[[1L]])
  roles <- stats::setNames(
    as.list(unname(pins[role_peers])), names(role_peers))
  hashes <- list(
    artifact_key = strrep("1", 64L), config_sha256 = strrep("2", 64L),
    source_claim_sha256 = strrep("3", 64L),
    receipt_set_sha256 = strrep("4", 64L),
    psi_run_sha256 = strrep("5", 64L),
    contract_sha256 = strrep("6", 64L),
    analysis_binding_sha256 = strrep("7", 64L),
    worker_static_sha256 = strrep("8", 64L))
  local <- list(
    peer_name = unname(role_peers[[local_role]]),
    identity_pk = unname(roles[[local_role]]), role = local_role)
  authorization <- c(list(
    session_id = "00000000-0000-4000-8000-000000000001",
    config = list(
      peer_pins = pins,
      source_owner = list(peer_name = unname(role_peers[["source_owner"]]),
                          identity_pk = unname(roles$source_owner))),
    analysis_binding = list(authority_roles = roles),
    worker_static = list(
      ring_bits = 128L, frac_bits = 0L, authority_roles = roles,
      release_contract_hash = strrep("9", 64L),
      source_share_policy = list(
        source_owner = "private_frequency_vector_ring128_v1",
        secondary_noise_authority = "zero_vector_ring128_v1")),
    local_authority = local), hashes)
  public <- c(hashes, list(local_authority = local))
  list(
    authorization = authorization, public = public, pins = pins,
    peers = peers, roles = roles, role_peers = role_peers)
}

test_that("Ring128 decimal residues use exact canonical little-endian records", {
  values <- c(
    "0", "1", "9223372036854775807", "9223372036854775808",
    "170141183460469231731687303715884105728",
    "340282366920938463463374607431768211455")
  encoded <- .exact_gc_decimal_residues_b64(values, 128L)
  raw <- jsonlite::base64_dec(encoded)
  expect_length(raw, 16L * length(values))
  records <- lapply(seq_along(values), function(index) {
    first <- (index - 1L) * 16L + 1L
    raw[first:(first + 15L)]
  })
  expect_true(all(as.integer(records[[1L]]) == 0L))
  expect_identical(as.integer(records[[2L]][[1L]]), 1L)
  expect_identical(as.integer(records[[3L]][1:8]),
                   c(rep(255L, 7L), 127L))
  expect_identical(as.integer(records[[4L]][1:8]),
                   c(rep(0L, 7L), 128L))
  expect_identical(as.integer(records[[5L]][[16L]]), 128L)
  expect_true(all(as.integer(records[[5L]][1:15]) == 0L))
  expect_true(all(as.integer(records[[6L]]) == 255L))
  expect_error(.exact_gc_decimal_residues_b64(
    "340282366920938463463374607431768211456", 128L),
    "outside the requested ring")
  expect_error(.exact_gc_decimal_residues_b64("01", 128L),
               "Invalid exact-gc decimal residue")

  oversized <- tryCatch(.exact_gc_decimal_residues_b64(
    rep("0", 4097L), 128L), error = identity)
  expect_s3_class(oversized, "dsvert_resource_oversize")
  expect_identical(oversized$code, "resource_oversize")
  expect_false(oversized$retryable)

  wire <- .exact_gc_b64url_encode(raw(9L))
  oversized <- tryCatch(.exact_gc_b64url_decode(
    wire, "test payload", max_bytes = 8L), error = identity)
  expect_s3_class(oversized, "dsvert_resource_oversize")
  expect_false(oversized$retryable)

  standard <- gsub("[\r\n]", "", jsonlite::base64_enc(raw(10L)))
  oversized <- tryCatch(.exact_gc_standard_b64_raw(
    standard, 8L, "test residue"), error = identity)
  expect_s3_class(oversized, "dsvert_resource_oversize")
  expect_false(oversized$retryable)
})

test_that("Ring4096 residues use canonical dynamic containers", {
  high <- as.character(openssl::bignum(2) ^ 4095L)
  outside <- as.character(openssl::bignum(2) ^ 4096L)
  encoded <- .exact_gc_decimal_residues_b64(c("0", "1", high), 4096L)
  decoded <- jsonlite::base64_dec(encoded)
  expect_length(decoded, 512L * 3L)
  expect_identical(as.integer(decoded[[513L]]), 1L)
  expect_identical(as.integer(decoded[[1536L]]), 128L)
  expect_error(.exact_gc_decimal_residues_b64(outside, 4096L),
               "outside the requested ring")
})

test_that("exact multiplication planner covers its full dynamic domain", {
  skip_on_cran()
  old <- options(dsvert.mpc_binary = .exact_gc_test_binary())
  on.exit(options(old), add = TRUE)

  ring63 <- .exact_gc_mul_plan("1048576", "1048576", 20L)
  expect_identical(ring63$ring_bits, 63L)
  expect_identical(ring63$backend, "direct-wide")
  expect_identical(ring63$truncated_bound, "1048576")
  expect_true(ring63$raw_product_headroom)
  expect_true(ring63$output_headroom)

  ring127 <- .exact_gc_mul_plan(
    "42535295865117307932921825928971026432", "1", 50L)
  expect_identical(ring127$ring_bits, 127L)
  expect_identical(ring127$backend, "ring127-ot")

  wide <- .exact_gc_mul_plan(
    "170141183460469231731687303715884105728", "1", 50L)
  expect_gt(wide$ring_bits, 127L)
  expect_lte(wide$ring_bits, .DSVERT_EXACT_GC_MAX_RING_BITS)
  expect_identical(wide$backend, "direct-wide")

  above_512 <- paste0(
    "670390396497129854978701249910292306373968291029619668886178072186",
    "088201503677348840093714908345171384501592909324302542687694140597",
    "3284973216824503042048")
  dynamic <- .exact_gc_mul_plan(above_512, above_512, 0L)
  expect_gt(dynamic$ring_bits, 512L)
  expect_identical(dynamic$container_bits, 1024L)
  expect_identical(dynamic$max_chunk, 16L)

  published_max <- strrep("9", .DSVERT_EXACT_GC_MAX_DECIMAL_BOUND_DIGITS)
  maximum <- .exact_gc_mul_plan(published_max, "1", 0L)
  expect_gt(maximum$ring_bits, 2048L)
  expect_lte(maximum$ring_bits, .DSVERT_EXACT_GC_MAX_RING_BITS)
  expect_identical(maximum$container_bits, 4096L)
  expect_identical(maximum$max_chunk, 1L)

  error <- tryCatch(.exact_gc_mul_plan(
    published_max, published_max, 0L), error = identity)
  expect_s3_class(error, "dsvert_numeric_backend_unrepresentable")
  expect_identical(error$code, "numeric_backend_unrepresentable")
  expect_identical(error$max_ring_bits, .DSVERT_EXACT_GC_MAX_RING_BITS)
})

test_that("the dynamic capability rejects an old Ring512 helper", {
  legacy <- list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    supported_ring_bits = 63L:512L,
    wire_container_bits = c(64L, 128L, 256L, 512L),
    min_ring_bits = 63L, max_ring_bits = 512L, max_frac_bits = 511L)
  observed <- testthat::with_mocked_bindings(
    .exact_gc_capability_probe(),
    .dsvert_mpc_require_capabilities = function(...) list(exact_gc = TRUE),
    .callMpcTool = function(...) legacy,
    .package = "dsVert")
  expect_null(observed)
})

test_that("dynamic exact truncation and count guard complete over opaque spools", {
  skip_on_cran()
  binary <- .exact_gc_test_binary()
  old <- options(
    dsvert.mpc_binary = binary,
    dsvert.identity_seed = getOption("dsvert.identity_seed"),
    dsvert.peer_name = getOption("dsvert.peer_name"),
    dsvert.trusted_peers = getOption("dsvert.trusted_peers"),
    nfilter.tab = 3,
    dsvert.exact_gc.count_threshold = 1,
    dsvert.exact_gc.ttl_seconds = 300,
    dsvert.exact_gc.chunk_bytes = 65536,
    dsvert.exact_gc.spool_max_bytes = 8 * 1024^2)
  on.exit(options(old), add = TRUE)
  capability <- .exact_gc_capability_probe()
  expect_false(is.null(capability))
  expect_identical(as.integer(capability$max_ring_bits),
                   .DSVERT_EXACT_GC_MAX_RING_BITS)
  expect_identical(as.integer(capability$wire_container_bits),
                   .DSVERT_EXACT_GC_WIRE_CONTAINER_BITS)
  expect_identical(as.integer(capability$max_decimal_bound_digits),
                   .DSVERT_EXACT_GC_MAX_DECIMAL_BOUND_DIGITS)
  expect_true(capability$canonical_input_encoding)
  expect_true(capability$shape_bounds_enforced)
  expect_false(capability$raw_product_overflow_guard)
  expect_false(capability$checked_mul_truncate)
  expect_true(capability$dynamic_ring_fallback)
  ring127_wide <- .exact_gc_mul_plan(
    "112589990684262400", "2361183241434822606848", 50L,
    fixed_ring_bits = 127L)
  expect_identical(ring127_wide$ring_bits, 127L)
  expect_identical(ring127_wide$backend, "direct-wide")
  expect_false(ring127_wide$raw_product_headroom)
  expect_true(ring127_wide$output_headroom)
  expect_error(.exact_gc_mul_plan(
    "85070591730234615865843651857942052863",
    "85070591730234615865843651857942052863", 0L,
    fixed_ring_bits = 127L))

  seed_a <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(31L, 32L))))
  seed_b <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(47L, 32L))))
  identity_a <- .callMpcTool("derive-identity", list(seed = seed_a))
  identity_b <- .callMpcTool("derive-identity", list(seed = seed_b))
  transport_a <- .callMpcTool("transport-keygen", list())
  transport_b <- .callMpcTool("transport-keygen", list())

  session_id <- "12345678-1234-4234-9234-123456789abc"
  ss_a <- new.env(parent = emptyenv())
  ss_b <- new.env(parent = emptyenv())
  ss_a$.session_id <- paste0(session_id, "_exact_a_", Sys.getpid())
  ss_b$.session_id <- paste0(session_id, "_exact_b_", Sys.getpid())
  for (entry in list(
    list(ss_a, transport_a, identity_a, "site_b", transport_b, identity_b,
         "site_a"),
    list(ss_b, transport_b, identity_b, "site_a", transport_a, identity_a,
         "site_b"))) {
    ss <- entry[[1L]]
    .key_put("transport_sk", entry[[2L]]$secret_key, ss)
    .key_put("transport_pk", entry[[2L]]$public_key, ss)
    .key_put("identity_pk", entry[[3L]]$identity_pk, ss)
    ss$.exact_gc_transport_initialized <- TRUE
  }
  pinset <- c(site_a = identity_a$identity_pk,
              site_b = identity_b$identity_pk)
  normalized_pinset <- vapply(
    pinset, .dsvert_relay_normalize_identity_pk, character(1L))
  pinset_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(normalized_pinset)),
    algo = "sha256", serialize = FALSE)
  policy_for <- function(peer_name) list(
    domain = "exact-gc-operation-integration",
    cohort_id = "exact-gc-operation-cohort",
    peer_name = peer_name,
    peer_pinset = pinset,
    peer_pinset_sha256 = pinset_hash,
    peer_count = 2L,
    designated_noise_peers = c("site_a", "site_b"),
    global_total_epsilon = 1,
    global_total_delta = 0,
    lifetime_max_distinct_capsules = 8,
    adjacency = "add_remove_patient", patient_column = "patient_id",
    unit_capacity = 1000L, max_records_per_unit = 100L,
    overflow_policy = "reject_snapshot",
    noise_root = list(epoch = 1, key_id = "test-noise-root"),
    ledger_path = tempfile("exact-gc-operation-ledger-"))
  testthat::local_mocked_bindings(
    .dsvert_dp_policy = function() policy_for(
      getOption("dsvert.peer_name")),
    .package = "dsVert")
  signed_transport <- list(
    site_a = base64_to_base64url(transport_a$public_key),
    site_b = base64_to_base64url(transport_b$public_key))
  signed_identity <- list(
    site_a = list(
      identity_pk = base64_to_base64url(identity_a$identity_pk),
      signature = base64_to_base64url(.sign_transport_pk(
        transport_a$public_key, identity_a$identity_sk))),
    site_b = list(
      identity_pk = base64_to_base64url(identity_b$identity_pk),
      signature = base64_to_base64url(.sign_transport_pk(
        transport_b$public_key, identity_b$identity_sk))))
  encode_handshake <- function(value) .exact_gc_b64url_encode(charToRaw(
    as.character(jsonlite::toJSON(
      value, auto_unbox = TRUE, null = "null"))))
  options(dsvert.peer_name = "site_a",
          dsvert.trusted_peers = c(site_b = identity_b$identity_pk))
  expect_true(.exact_gc_test_server_call(
    ss_a, seed_a, exactGCBindPeersDS,
    transport_keys_b64 = encode_handshake(signed_transport),
    identity_info_b64 = encode_handshake(signed_identity),
    session_id = session_id)$bound)
  options(dsvert.peer_name = "site_b",
          dsvert.trusted_peers = c(site_a = identity_a$identity_pk))
  expect_true(.exact_gc_test_server_call(
    ss_b, seed_b, exactGCBindPeersDS,
    transport_keys_b64 = encode_handshake(signed_transport),
    identity_info_b64 = encode_handshake(signed_identity),
    session_id = session_id)$bound)
  on.exit({
    .exact_gc_abort_all(ss_a)
    .exact_gc_abort_all(ss_b)
    .session_dir_cleanup(ss_a)
    .session_dir_cleanup(ss_b)
    .exact_gc_test_binary_cleanup(binary)
  }, add = TRUE)

  init_pair <- function(operation_id, source_key, output_key, operation,
                        ring, frac_bits, vector_len, purpose,
                        threshold = NULL,
                        deterministic_output_seeds = list(NULL, NULL),
                        joint_dp = NULL,
                        private_seeds = list(NULL, NULL)) {
    options(dsvert.identity_seed = seed_a, dsvert.peer_name = "site_a",
            dsvert.trusted_peers = c(site_b = identity_b$identity_pk))
    left <- .exact_gc_init_impl(
      ss_a, session_id, operation_id, .DSVERT_EXACT_GC_CAPABILITY,
      source_key, output_key, operation, ring, frac_bits, vector_len,
      purpose, threshold = threshold,
      deterministic_output_seed = deterministic_output_seeds[[1L]],
      joint_dp = joint_dp, private_seed = private_seeds[[1L]],
      binary = binary)
    options(dsvert.identity_seed = seed_b, dsvert.peer_name = "site_b",
            dsvert.trusted_peers = c(site_a = identity_a$identity_pk))
    right <- .exact_gc_init_impl(
      ss_b, session_id, operation_id, .DSVERT_EXACT_GC_CAPABILITY,
      source_key, output_key, operation, ring, frac_bits, vector_len,
      purpose, threshold = threshold,
      deterministic_output_seed = deterministic_output_seeds[[2L]],
      joint_dp = joint_dp, private_seed = private_seeds[[2L]],
      binary = binary)
    expect_identical(left$context_hash, right$context_hash)
    expect_setequal(c(left$role, right$role), c("garbler", "evaluator"))
    list(left = left, right = right)
  }

  trunc_op <- "op_11111111111111111111111111111111"
  trunc_in <- "exact_gc_in_11111111111111111111111111111111"
  trunc_out <- "exact_gc_out_11111111111111111111111111111111"
  .exact_gc_stage_share(
    ss_a, trunc_in, .exact_gc_test_b64_records(c(7, 10), 16L),
    127L, 2L, "test.vecmul", "truncate-floor", "test.truncate", 2L,
    "ring-share")
  .exact_gc_stage_share(
    ss_b, trunc_in, .exact_gc_test_b64_records(c(13, 25), 16L),
    127L, 2L, "test.vecmul", "truncate-floor", "test.truncate", 2L,
    "ring-share")
  options(dsvert.identity_seed = seed_a, dsvert.peer_name = "site_a",
          dsvert.trusted_peers = c(site_b = identity_b$identity_pk))
  expect_error(.exact_gc_init_impl(
    ss_a, session_id, "op_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    .DSVERT_EXACT_GC_CAPABILITY, trunc_in,
    "exact_gc_out_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "truncate-floor",
    127L, 2L, 2L, "test.changed-purpose", binary = binary),
    "not allowlisted")
  expect_error(.exact_gc_init_impl(
    ss_a, session_id, "op_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    .DSVERT_EXACT_GC_CAPABILITY, trunc_in,
    "exact_gc_out_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", "count-guard",
    127L, 0L, 2L, "test.truncate", binary = binary),
    "not allowlisted")
  expect_error(.exact_gc_stage_share(
    ss_a, "exact_gc_in_cccccccccccccccccccccccccccccccc",
    .exact_gc_test_b64_records(1, 16L), 127L, 1L, "test.vecmul",
    "truncate-floor", "test.truncate", 2L, "xor-bit-share"),
    "staged-source contract")
  init_pair(trunc_op, trunc_in, trunc_out, "truncate-floor", 127L, 2L,
            2L, "test.truncate")
  .exact_gc_test_pump(ss_a, ss_b, session_id, trunc_op, seed_a, seed_b)
  liveness <- .exact_gc_status_impl(ss_a, session_id, trunc_op)
  expect_identical(sort(names(liveness)), sort(c(
    "capability_id", "context_hash", "state", "stored")))
  expect_false(any(grepl("size|offset|vector|threshold|share",
                         names(liveness), ignore.case = TRUE)))
  expect_error(.exact_gc_consume_output(
    ss_a, trunc_out, trunc_op, "ring-share", "truncate-floor",
    "test.wrong-purpose", 127L, 2L, 2L, "test.vecmul"),
    "wrong context")
  trunc_a <- .exact_gc_consume_output(
    ss_a, trunc_out, trunc_op, "ring-share", "truncate-floor",
    "test.truncate", 127L, 2L, 2L, "test.vecmul")
  trunc_b <- .exact_gc_consume_output(
    ss_b, trunc_out, trunc_op, "ring-share", "truncate-floor",
    "test.truncate", 127L, 2L, 2L, "test.vecmul")
  raw_a <- jsonlite::base64_dec(trunc_a$share)
  raw_b <- jsonlite::base64_dec(trunc_b$share)
  reconstructed <- .exact_gc_test_add_le(raw_a, raw_b, 127L)
  expect_identical(as.integer(reconstructed[[1L]]), 5L)
  expect_identical(as.integer(reconstructed[[17L]]), 8L)
  expect_true(all(as.integer(reconstructed[-c(1L, 17L)]) == 0L))

  # Private-alignment masking crosses the complete real worker/spool path for
  # K=2,3,5.  Every custodian contributes only one recipient-specific XOR
  # digest share; the digest and predicate are reconstructed solely in GC.
  alignment_digest <- openssl::sha256(
    charToRaw("one canonical private alignment"))
  alignment_inputs <- function(k, mismatch = -1L) {
    left <- jsonlite::base64_dec(
      .exact_gc_test_b64_records(c(7, 10), 16L))
    right <- jsonlite::base64_dec(
      .exact_gc_test_b64_records(c(13, 25), 16L))
    for (source in seq_len(k)) {
      mask <- as.raw((seq_len(32L) + 29L * source + 7L * k) %% 256L)
      digest <- if (source == mismatch) {
        openssl::sha256(charToRaw("different private alignment"))
      } else {
        alignment_digest
      }
      left <- c(left, mask)
      right <- c(right, as.raw(bitwXor(
        as.integer(mask), as.integer(digest))))
    }
    list(
      left = gsub("[\r\n]", "", jsonlite::base64_enc(left)),
      right = gsub("[\r\n]", "", jsonlite::base64_enc(right)))
  }
  run_alignment <- function(k, token, mismatch = -1L) {
    suffix <- strrep(token, 16L)
    operation_id <- paste0("op_", suffix)
    source_key <- paste0("exact_gc_in_", suffix)
    output_key <- paste0("exact_gc_out_", suffix)
    purpose <- paste0("test.private-alignment.k", k, ".m", mismatch)
    input <- alignment_inputs(k, mismatch)
    .exact_gc_stage_share(
      ss_a, source_key, input$left, 128L, 2L,
      "test.private-alignment", "alignment-mask-ring128", purpose, 0L,
      "alignment-masked-ring128-share-v1",
      alignment_source_count = k)
    .exact_gc_stage_share(
      ss_b, source_key, input$right, 128L, 2L,
      "test.private-alignment", "alignment-mask-ring128", purpose, 0L,
      "alignment-masked-ring128-share-v1",
      alignment_source_count = k)
    init_pair(
      operation_id, source_key, output_key, "alignment-mask-ring128",
      128L, 0L, 2L, purpose, threshold = as.character(k))
    .exact_gc_test_pump(
      ss_a, ss_b, session_id, operation_id, seed_a, seed_b)
    left <- .exact_gc_consume_output(
      ss_a, output_key, operation_id,
      "alignment-masked-ring128-share-v1", "alignment-mask-ring128",
      purpose, 128L, 0L, 2L, "test.private-alignment")
    right <- .exact_gc_consume_output(
      ss_b, output_key, operation_id,
      "alignment-masked-ring128-share-v1", "alignment-mask-ring128",
      purpose, 128L, 0L, 2L, "test.private-alignment")
    value <- .exact_gc_test_add_le(
      jsonlite::base64_dec(left$share),
      jsonlite::base64_dec(right$share), 128L)
    validity <- bitwXor(
      as.integer(jsonlite::base64_dec(left$validity_share)[[1L]]),
      as.integer(jsonlite::base64_dec(right$validity_share)[[1L]]))
    list(value = value, validity = validity,
         left = left$share, right = right$share,
         left_output = left, right_output = right,
         operation_id = operation_id)
  }
  aligned_runs <- list()
  for (entry in list(list(2L, "a2"), list(3L, "a3"),
                     list(5L, "a5"))) {
    aligned <- run_alignment(entry[[1L]], entry[[2L]])
    aligned_runs[[as.character(entry[[1L]])]] <- aligned
    expect_identical(as.integer(aligned$value[[1L]]), 20L)
    expect_identical(as.integer(aligned$value[[17L]]), 35L)
    expect_identical(aligned$validity, 1L)
    expect_false(identical(aligned$left, aligned$right))
  }
  mismatched <- run_alignment(5L, "a6", mismatch = 3L)
  expect_true(all(as.integer(mismatched$value) == 0L))
  expect_identical(mismatched$validity, 0L)

  # Exercise the real signed/encrypted terminal exchange as well as the
  # worker. JSON numeric types are deliberately round-tripped here: terminal
  # context comparison must be canonical, not dependent on integer/double
  # representation. Only the aggregate outcome may leave either server.
  alignment_terminal_call <- function(
      ss, seed, peer_name, trusted, parsed, fun, ...) {
    previous <- options(
      dsvert.identity_seed = getOption("dsvert.identity_seed"),
      dsvert.peer_name = getOption("dsvert.peer_name"),
      dsvert.trusted_peers = getOption("dsvert.trusted_peers"))
    on.exit(options(previous), add = TRUE)
    options(dsvert.identity_seed = seed, dsvert.peer_name = peer_name,
            dsvert.trusted_peers = trusted)
    testthat::with_mocked_bindings(
      do.call(fun, c(list(...), list(.policy = policy_for(peer_name)))),
      .S = function(session_id) ss,
      .dsvert_dp_alignment_mask_contract = function(policy, manifest_json) {
        parsed
      },
      .package = "dsVert")
  }
  run_alignment_terminal <- function(run, k, token, expected_state) {
    suffix <- strrep(token, 16L)
    batch_operation_id <- paste0("op_", suffix)
    capsule_id <- paste0("dpc_", suffix)
    contract_hash <- digest::digest(
      paste0("alignment-terminal-", token),
      algo = "sha256", serialize = FALSE)
    parsed <- list(
      sources = paste0("source_", seq_len(k)),
      contract_hash = contract_hash,
      contract = list(capsule_id = capsule_id, coordinate_count = 2))
    paths <- c(tempfile("alignment-terminal-a-"),
               tempfile("alignment-terminal-b-"))
    on.exit(unlink(paths), add = TRUE)
    raw_outputs <- list(
      jsonlite::base64_dec(run$left_output$share),
      jsonlite::base64_dec(run$right_output$share))
    for (index in seq_along(paths)) {
      connection <- file(paths[[index]], open = "wb")
      writeBin(raw_outputs[[index]], connection)
      close(connection)
      Sys.chmod(paths[[index]], mode = "0600")
    }
    make_batch <- function(ss, path, output) {
      if (!is.environment(ss$.dp_alignment_mask_batches)) {
        ss$.dp_alignment_mask_batches <- new.env(parent = emptyenv())
      }
      batch <- new.env(parent = emptyenv())
      batch$version <- .DSVERT_DP_ALIGNMENT_MASK_VERSION
      batch$session_id <- session_id
      batch$batch_operation_id <- batch_operation_id
      batch$capsule_id <- capsule_id
      batch$contract_hash <- contract_hash
      batch$source_count <- k
      batch$total <- as.numeric(2)
      batch$chunk_count <- 1L
      batch$chunk_size <- .dsvert_dp_alignment_mask_chunk_size(k)
      batch$peer_binding_digest <- ss$.exact_gc_peer_binding_digest
      batch$path <- path
      batch$status <- "running"
      batch$chunk_digests <- digest::digest(
        jsonlite::base64_dec(output$share),
        algo = "sha256", serialize = FALSE)
      batch$context_hashes <- output$context_hash
      batch$operation_ids <- run$operation_id
      batch$first_validity_share <- output$validity_share
      batch$terminal_peer_blob_digest <- NULL
      batch$terminal_outbound <- NULL
      batch$resource_reservation_bytes <- 32
      ss$.dp_alignment_mask_batches[[batch_operation_id]] <- batch
      batch
    }
    batch_a <- make_batch(ss_a, paths[[1L]], run$left_output)
    batch_b <- make_batch(ss_b, paths[[2L]], run$right_output)
    common <- list(
      manifest_json = "{}", batch_operation_id = batch_operation_id,
      session_id = session_id)
    sealed_a <- do.call(alignment_terminal_call, c(list(
      ss = ss_a, seed = seed_a, peer_name = "site_a",
      trusted = c(site_b = identity_b$identity_pk), parsed = parsed,
      fun = .dsvert_dp_alignment_mask_seal_impl), common))
    sealed_b <- do.call(alignment_terminal_call, c(list(
      ss = ss_b, seed = seed_b, peer_name = "site_b",
      trusted = c(site_a = identity_a$identity_pk), parsed = parsed,
      fun = .dsvert_dp_alignment_mask_seal_impl), common))
    public_a <- do.call(alignment_terminal_call, c(list(
      ss = ss_a, seed = seed_a, peer_name = "site_a",
      trusted = c(site_b = identity_b$identity_pk), parsed = parsed,
      fun = .dsvert_dp_alignment_mask_receive_impl,
      peer_blob = sealed_b$peer_blob), common))
    public_b <- do.call(alignment_terminal_call, c(list(
      ss = ss_b, seed = seed_b, peer_name = "site_b",
      trusted = c(site_a = identity_a$identity_pk), parsed = parsed,
      fun = .dsvert_dp_alignment_mask_receive_impl,
      peer_blob = sealed_a$peer_blob), common))
    expect_identical(public_a, public_b)
    expect_identical(public_a$state, expected_state)
    expect_identical(public_a$terminal_outcome, expected_state)
    expect_false(public_a$alignment_digest_exposed)
    expect_false(public_a$mismatch_source_exposed)
    expect_false(public_a$gate_share_exposed)
    expect_false(any(c(
      "share", "validity_share", "alignment_hash",
      "private_alignment_consensus_hash", "mismatch_source", "value") %in%
        names(public_a)))
    expect_identical(file.exists(paths),
                     rep(identical(expected_state, "complete"), 2L))
    # Same authenticated blob is a byte-exact retry; the opposite peer's blob
    # is not an interchangeable replay even after the terminal decision.
    retry_a <- do.call(alignment_terminal_call, c(list(
      ss = ss_a, seed = seed_a, peer_name = "site_a",
      trusted = c(site_b = identity_b$identity_pk), parsed = parsed,
      fun = .dsvert_dp_alignment_mask_receive_impl,
      peer_blob = sealed_b$peer_blob), common))
    expect_identical(retry_a, public_a)
    expect_error(do.call(alignment_terminal_call, c(list(
      ss = ss_a, seed = seed_a, peer_name = "site_a",
      trusted = c(site_b = identity_b$identity_pk), parsed = parsed,
      fun = .dsvert_dp_alignment_mask_receive_impl,
      peer_blob = sealed_a$peer_blob), common)), "terminal replay")
    invisible(list(left = batch_a, right = batch_b))
  }
  for (entry in list(list(2L, "b2"), list(3L, "b3"),
                     list(5L, "b5"))) {
    run_alignment_terminal(
      aligned_runs[[as.character(entry[[1L]])]], entry[[1L]], entry[[2L]],
      "complete")
  }
  run_alignment_terminal(
    mismatched, 5L, "b6", "alignment_contract_invalid")

  # Count's promoted joint sampler is one specialised data-free contract over
  # the same two real worker processes and authenticated DSI spool.  Seeds and
  # source shares enter only the unlink-before-ready worker configs.
  joint_op <- "op_18181818181818181818181818181818"
  joint_in <- "exact_gc_in_18181818181818181818181818181818"
  joint_out <- "exact_gc_out_18181818181818181818181818181818"
  transcript <- strrep("1", 64L)
  peer_names <- c("site_a", "site_b")
  identities <- c(site_a = identity_a$identity_pk, site_b = identity_b$identity_pk)
  seeds <- c(site_a = seed_a, site_b = seed_b)
  role_order <- peer_names[order(vapply(identities, .dsvert_relay_peer_id,
                                        character(1L)), method = "radix")]
  contexts <- stats::setNames(c(
    .dsvert_joint_dp_backend_commitment_context_v2(
      transcript, "garbler", role_order[[1L]]),
    .dsvert_joint_dp_backend_commitment_context_v2(
      transcript, "evaluator", role_order[[2L]])), role_order)
  commitments <- vapply(role_order, function(peer) {
    .dsvert_joint_dp_backend_hash_raw_v2(c(
      .dsvert_joint_dp_backend_hex_raw_v2(contexts[[peer]], "context"),
      jsonlite::base64_dec(seeds[[peer]])))
  }, character(1L))
  compiled <- .callMpcTool("joint-dp-laplace-worker-contract-v2", list(
    version = .DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT_INPUT,
    ring_bits = 127L, frac_bits = 0L, coordinate_count = 1L,
    epsilon = "1e+00", allocated_delta = "7.888609052210118e-31",
    sensitivity_steps = "1", encoded_lower = "0", encoded_upper = "1000",
    bernoulli_bits = 8L, max_steps = 4096L,
    transcript_hash = transcript,
    garbler_commitment_context = contexts[[role_order[[1L]]]],
    evaluator_commitment_context = contexts[[role_order[[2L]]]],
    garbler_seed_commitment = commitments[[role_order[[1L]]]],
    evaluator_seed_commitment = commitments[[role_order[[2L]]]]))
  expect_true(compiled$capability_available)
  expect_false(compiled$protected_inputs_accepted)
  expect_false(compiled$private_seed_accepted)
  .exact_gc_stage_share(
    ss_a, joint_in, .exact_gc_test_b64_records(13, 16L),
    127L, 1L, "test.joint.dp.count", "joint-dp-laplace-v2",
    compiled$purpose, 0L, "joint-dp-ring-share-v2")
  .exact_gc_stage_share(
    ss_b, joint_in, .exact_gc_test_b64_records(27, 16L),
    127L, 1L, "test.joint.dp.count", "joint-dp-laplace-v2",
    compiled$purpose, 0L, "joint-dp-ring-share-v2")
  # The bounded joint sampler circuit is materially larger than the tiny spool
  # used above to exercise backpressure.  Keep the real DSI/spool path bounded,
  # but give this purpose-specific E2E enough headroom and fewer round trips.
  old_joint_transport <- options(
    dsvert.exact_gc.chunk_bytes = 1024^2,
    dsvert.exact_gc.spool_max_bytes = 1024^3)
  on.exit(options(old_joint_transport), add = TRUE)
  init_pair(
    joint_op, joint_in, joint_out, "joint-dp-laplace-v2",
    127L, 0L, 1L, compiled$purpose,
    joint_dp = compiled$worker_policy,
    private_seeds = list(seed_a, seed_b))
  states <- list(
    .exact_gc_operation_state(ss_a, joint_op),
    .exact_gc_operation_state(ss_b, joint_op))
  expect_false(any(vapply(states, function(state) {
    file.exists(file.path(state$spool, "worker-config.json"))
  }, logical(1L))))
  .exact_gc_test_pump(ss_a, ss_b, session_id, joint_op, seed_a, seed_b)
  joint_a <- .exact_gc_consume_output(
    ss_a, joint_out, joint_op, "joint-dp-ring-share-v2",
    "joint-dp-laplace-v2", compiled$purpose, 127L, 0L, 1L,
    "test.joint.dp.count")
  joint_b <- .exact_gc_consume_output(
    ss_b, joint_out, joint_op, "joint-dp-ring-share-v2",
    "joint-dp-laplace-v2", compiled$purpose, 127L, 0L, 1L,
    "test.joint.dp.count")
  joint_value <- .exact_gc_test_add_le(
    jsonlite::base64_dec(joint_a$share),
    jsonlite::base64_dec(joint_b$share), 127L)
  expect_true(openssl::bignum(rev(joint_value)) <= openssl::bignum("1000"))
  expect_identical(bitwXor(
    as.integer(jsonlite::base64_dec(joint_a$validity_share)[[1L]]),
    as.integer(jsonlite::base64_dec(joint_b$validity_share)[[1L]])), 1L)
  options(old_joint_transport)

  # The same signed-floor protocol crosses the former Ring512 ceiling without
  # changing its canonical records or exposing either input/output share.
  wide_op <- "op_14141414141414141414141414141414"
  wide_in <- "exact_gc_in_14141414141414141414141414141414"
  wide_out <- "exact_gc_out_14141414141414141414141414141414"
  .exact_gc_stage_share(
    ss_a, wide_in, .exact_gc_test_b64_records(7, 128L),
    513L, 1L, "test.vecmul", "truncate-floor", "test.wide-truncate", 2L,
    "ring-share")
  .exact_gc_stage_share(
    ss_b, wide_in, .exact_gc_test_b64_records(13, 128L),
    513L, 1L, "test.vecmul", "truncate-floor", "test.wide-truncate", 2L,
    "ring-share")
  init_pair(wide_op, wide_in, wide_out, "truncate-floor", 513L, 2L,
            1L, "test.wide-truncate")
  .exact_gc_test_pump(ss_a, ss_b, session_id, wide_op, seed_a, seed_b)
  wide_a <- .exact_gc_consume_output(
    ss_a, wide_out, wide_op, "ring-share", "truncate-floor",
    "test.wide-truncate", 513L, 2L, 1L, "test.vecmul")
  wide_b <- .exact_gc_consume_output(
    ss_b, wide_out, wide_op, "ring-share", "truncate-floor",
    "test.wide-truncate", 513L, 2L, 1L, "test.vecmul")
  wide_reconstructed <- .exact_gc_test_add_le(
    jsonlite::base64_dec(wide_a$share),
    jsonlite::base64_dec(wide_b$share), 513L)
  expect_identical(as.integer(wide_reconstructed[[1L]]), 5L)
  expect_true(all(as.integer(wide_reconstructed[-1L]) == 0L))

  # The Count finalizer reconstructs the raw-noised Ring128 value only inside
  # GC, signed-decodes it, and applies exactly one [0, U] saturation before
  # either peer obtains an output share.
  clamp_op <- "op_12121212121212121212121212121212"
  clamp_in <- "exact_gc_in_12121212121212121212121212121212"
  clamp_out <- "exact_gc_out_12121212121212121212121212121212"
  clamp_purpose <- "test.joint.dp.count.clamp"
  clamp_producer <- "test.joint.dp.count.noised-share"
  clamp_values <- c(
    # signed minimum, -1, zero, U, U+1, signed maximum
    "170141183460469231731687303715884105728",
    "340282366920938463463374607431768211455",
    "0", "1000", "1001",
    "170141183460469231731687303715884105727")
  .exact_gc_stage_share(
    ss_a, clamp_in, .exact_gc_decimal_residues_b64(clamp_values, 128L),
    128L, length(clamp_values), clamp_producer,
    "clamp-count", clamp_purpose, 0L, "ring-share")
  .exact_gc_stage_share(
    ss_b, clamp_in,
    .exact_gc_decimal_residues_b64(rep("0", length(clamp_values)), 128L),
    128L, length(clamp_values), clamp_producer,
    "clamp-count", clamp_purpose, 0L, "ring-share")
  wrong_query_purpose <- "test.joint.dp.count.clamp.wrong-query"
  count_output_seeds <- list(
    gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(81L, 32L)))),
    gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(82L, 32L)))))
  options(dsvert.identity_seed = seed_a, dsvert.peer_name = "site_a",
          dsvert.trusted_peers = c(site_b = identity_b$identity_pk))
  expect_error(.exact_gc_init_impl(
    ss_a, session_id, "op_13131313131313131313131313131313",
    .DSVERT_EXACT_GC_CAPABILITY, clamp_in,
    "exact_gc_out_13131313131313131313131313131313", "clamp-count",
    128L, 0L, length(clamp_values), wrong_query_purpose,
    threshold = "1000", binary = binary), "not allowlisted")
  init_pair(
    clamp_op, clamp_in, clamp_out, "clamp-count", 128L, 0L,
    length(clamp_values), clamp_purpose, threshold = "1000",
    deterministic_output_seeds = count_output_seeds)
  for (state in list(
      .exact_gc_operation_state(ss_a, clamp_op),
      .exact_gc_operation_state(ss_b, clamp_op))) {
    expect_false(file.exists(file.path(state$spool, "worker-config.json")))
    expect_false("deterministic_output_seed" %in% names(state$requested_spec))
    expect_match(
      state$requested_spec$deterministic_output_seed_commitment,
      "^[0-9a-f]{64}$")
  }
  .exact_gc_test_pump(ss_a, ss_b, session_id, clamp_op, seed_a, seed_b)
  expect_error(.exact_gc_consume_output(
    ss_a, clamp_out, clamp_op, "ring-share", "clamp-count",
    wrong_query_purpose, 128L, 0L, length(clamp_values),
    clamp_producer), "wrong context")
  expect_error(.exact_gc_consume_output(
    ss_a, clamp_out, clamp_op, "ring-share", "clamp-count",
    clamp_purpose, 128L, 0L, length(clamp_values),
    "joint.dp.count.wrong-source-v1"), "wrong context")
  clamp_a <- .exact_gc_consume_output(
    ss_a, clamp_out, clamp_op, "ring-share", "clamp-count",
    clamp_purpose, 128L, 0L, length(clamp_values),
    clamp_producer)
  clamp_b <- .exact_gc_consume_output(
    ss_b, clamp_out, clamp_op, "ring-share", "clamp-count",
    clamp_purpose, 128L, 0L, length(clamp_values),
    clamp_producer)
  clamped <- .exact_gc_test_add_le(
    jsonlite::base64_dec(clamp_a$share),
    jsonlite::base64_dec(clamp_b$share), 128L)
  expected_clamped <- jsonlite::base64_dec(
    .exact_gc_decimal_residues_b64(
      c("0", "0", "0", "1000", "1000", "1000"), 128L))
  expect_identical(clamped, expected_clamped)
  expect_false(any(c("pre_clamp", "noised_share", "raw_value") %in%
                     names(clamp_a)))

  # A new authenticated transport operation (the state available after an R
  # service restart) must produce the same query-bound post-clamp shares.  The
  # worker session/master key and garbling randomness change; only the private
  # capsule-derived output mask is stable.
  replay_op <- "op_15151515151515151515151515151515"
  replay_in <- "exact_gc_in_15151515151515151515151515151515"
  replay_out <- "exact_gc_out_15151515151515151515151515151515"
  .exact_gc_stage_share(
    ss_a, replay_in, .exact_gc_decimal_residues_b64(clamp_values, 128L),
    128L, length(clamp_values), clamp_producer,
    "clamp-count", clamp_purpose, 0L, "ring-share")
  .exact_gc_stage_share(
    ss_b, replay_in,
    .exact_gc_decimal_residues_b64(rep("0", length(clamp_values)), 128L),
    128L, length(clamp_values), clamp_producer,
    "clamp-count", clamp_purpose, 0L, "ring-share")
  init_pair(
    replay_op, replay_in, replay_out, "clamp-count", 128L, 0L,
    length(clamp_values), clamp_purpose, threshold = "1000",
    deterministic_output_seeds = count_output_seeds)
  .exact_gc_test_pump(
    ss_a, ss_b, session_id, replay_op, seed_a, seed_b)
  replay_a <- .exact_gc_consume_output(
    ss_a, replay_out, replay_op, "ring-share", "clamp-count",
    clamp_purpose, 128L, 0L, length(clamp_values),
    clamp_producer)
  replay_b <- .exact_gc_consume_output(
    ss_b, replay_out, replay_op, "ring-share", "clamp-count",
    clamp_purpose, 128L, 0L, length(clamp_values),
    clamp_producer)
  expect_identical(replay_a$share, clamp_a$share)
  expect_identical(replay_b$share, clamp_b$share)

  wide_op <- "op_dddddddddddddddddddddddddddddddd"
  wide_in <- "exact_gc_in_dddddddddddddddddddddddddddddddd"
  wide_out <- "exact_gc_out_dddddddddddddddddddddddddddddddd"
  .exact_gc_stage_share(
    ss_a, wide_in, .exact_gc_test_b64_records(c(5, 250), 32L),
    256L, 2L, "test.vecmul-wide", "truncate-floor", "test.wide", 3L,
    "ring-share")
  .exact_gc_stage_share(
    ss_b, wide_in, .exact_gc_test_b64_records(c(15, 14), 32L),
    256L, 2L, "test.vecmul-wide", "truncate-floor", "test.wide", 3L,
    "ring-share")
  init_pair(wide_op, wide_in, wide_out, "truncate-floor", 256L, 3L,
            2L, "test.wide")
  .exact_gc_test_pump(ss_a, ss_b, session_id, wide_op, seed_a, seed_b)
  wide_a <- .exact_gc_consume_output(
    ss_a, wide_out, wide_op, "ring-share", "truncate-floor", "test.wide",
    256L, 3L, 2L, "test.vecmul-wide")
  wide_b <- .exact_gc_consume_output(
    ss_b, wide_out, wide_op, "ring-share", "truncate-floor", "test.wide",
    256L, 3L, 2L, "test.vecmul-wide")
  reconstructed_wide <- .exact_gc_test_add_le(
    jsonlite::base64_dec(wide_a$share),
    jsonlite::base64_dec(wide_b$share), 256L)
  expect_identical(as.integer(reconstructed_wide[[1L]]), 2L)
  expect_identical(as.integer(reconstructed_wide[[33L]]), 33L)
  expect_true(all(as.integer(reconstructed_wide[-c(1L, 33L)]) == 0L))

  # Purpose-specific direct multiply -> exact floor -> peer-only validity ->
  # bilateral commit. No Beaver product or preprocessing transcript exists.
  total_n <- 2L
  x_fp <- .callMpcTool("k2-float-to-fp", list(
    values = array(c(3, 1.5), dim = total_n), frac_bits = 50L,
    ring = "ring127"))$fp_data
  y_fp <- .callMpcTool("k2-float-to-fp", list(
    values = array(c(2, 2), dim = total_n), frac_bits = 50L,
    ring = "ring127"))$fp_data
  zero_fp <- gsub("[\r\n]", "", jsonlite::base64_enc(raw(16L * total_n)))
  ss_a$direct_x <- x_fp
  ss_a$direct_y <- y_fp
  ss_b$direct_x <- zero_fp
  ss_b$direct_y <- zero_fp
  call_a <- function(fun, ...) {
    options(dsvert.trusted_peers = c(site_b = identity_b$identity_pk))
    .exact_gc_test_server_call(ss_a, seed_a, fun, ...)
  }
  call_b <- function(fun, ...) {
    options(dsvert.trusted_peers = c(site_a = identity_a$identity_pk))
    .exact_gc_test_server_call(ss_b, seed_b, fun, ...)
  }
  policy_id <- .dsvert_numeric_policy()$policy_id

  # Producer-minted manifests use exactly the same dynamic ring domain and
  # resource-derived chunks as the planner/worker boundary.
  for (case in list(
    list(ring = 512L, chunk = 64L),
    list(ring = 513L, chunk = 16L),
    list(ring = 4096L, chunk = 1L))) {
    suffix <- paste0("ring", case$ring)
    x_key <- paste0("dynamic_x_", suffix)
    y_key <- paste0("dynamic_y_", suffix)
    output_key <- paste0("dynamic_output_", suffix)
    ss_a[[x_key]] <- .exact_gc_decimal_residues_b64("0", case$ring)
    ss_a[[y_key]] <- .exact_gc_decimal_residues_b64("0", case$ring)
    minted <- testthat::with_mocked_bindings(
      .exact_gc_vecmul_mint_manifest(
        ss = ss_a, session_id = session_id,
        producer = "test.vecmul.v1", purpose = "test.vecmul",
        total_n = 1L, x_key = x_key, y_key = y_key,
        output_key = output_key, ring_bits = case$ring, frac_bits = 0L,
        bound_x = "1", bound_y = "1", allow_test = TRUE),
      .S = function(session_id) ss_a, .package = "dsVert")
    expect_identical(minted$ring_bits, case$ring)
    expect_identical(minted$max_chunk, case$chunk)
    stored <- ss_a$.exact_gc_vecmul_manifests[[minted$manifest_handle]]
    expect_identical(stored$plan$version, "dsvert-exact-gc-mul-plan-v3")
    expect_identical(stored$plan$container_bits,
                     .exact_gc_record_bytes(case$ring) * 8L)
  }
  expect_error(testthat::with_mocked_bindings(
    .exact_gc_vecmul_mint_manifest(
      ss = ss_a, session_id = session_id,
      producer = "test.vecmul.v1", purpose = "test.vecmul",
      total_n = 1L, x_key = "dynamic_x_ring4096",
      y_key = "dynamic_y_ring4096", output_key = "dynamic_output_ring4097",
      ring_bits = 4097L, frac_bits = 0L,
      bound_x = "1", bound_y = "1", allow_test = TRUE),
    .S = function(session_id) ss_a, .package = "dsVert"),
    "Invalid exact-gc vecmul ring")

  batch_op <- "op_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
  mint_args <- list(
    session_id = session_id, producer = "test.vecmul.v1",
    purpose = "test.vecmul",
    x_key = "direct_x", y_key = "direct_y", output_key = "direct_product",
    total_n = total_n, ring_bits = 127L, frac_bits = 50L,
    bound_x = "4503599627370496", bound_y = "2251799813685248",
    allow_test = TRUE)
  manifest_a <- testthat::with_mocked_bindings(
    do.call(.exact_gc_vecmul_mint_manifest,
            c(list(ss = ss_a), mint_args)),
    .S = function(session_id) ss_a, .package = "dsVert")
  manifest_b <- testthat::with_mocked_bindings(
    do.call(.exact_gc_vecmul_mint_manifest,
            c(list(ss = ss_b), mint_args)),
    .S = function(session_id) ss_b, .package = "dsVert")
  expect_false(any(c("x_key", "y_key", "output_key") %in%
                     names(manifest_a)))
  expect_match(manifest_a$manifest_handle, "^[A-Za-z0-9_-]{43}$")
  claim_a <- call_a(
    exactGCVecmulClaimInputsDS,
    manifest_handle = manifest_a$manifest_handle,
    batch_operation_id = batch_op, session_id = session_id)
  claim_b <- call_b(
    exactGCVecmulClaimInputsDS,
    manifest_handle = manifest_b$manifest_handle,
    batch_operation_id = batch_op, session_id = session_id)
  bound_a <- claim_a
  bound_b <- claim_b
  expect_identical(bound_a$state, "claimed")
  expect_identical(bound_a$context_hash, bound_b$context_hash)
  expect_identical(bound_a$policy_id, policy_id)
  expect_identical(bound_a$plan_id, bound_b$plan_id)
  plan_id <- bound_a$plan_id
  operation_id <- .exact_gc_checked_mul_chunk_operation(
    batch_op, 1L, 1L, policy_id, plan_id)
  common <- list(
    n = total_n, total_n = total_n, chunk_index = 1L, chunk_count = 1L,
    batch_operation_id = batch_op, session_id = session_id,
    operation_id = operation_id, policy_id = policy_id, plan_id = plan_id)
  started_a <- do.call(call_a, c(list(exactGCVecmulStartDS), common))
  started_b <- do.call(call_b, c(list(exactGCVecmulStartDS), common))
  expect_identical(started_a$context_hash, started_b$context_hash)
  .exact_gc_test_pump(ss_a, ss_b, session_id, operation_id, seed_a, seed_b)
  batch_keys <- .exact_gc_checked_mul_keys(batch_op)
  expect_false(is.null(ss_a[[batch_keys$x]]))
  expect_false(is.null(ss_a[[batch_keys$y]]))
  expect_false(is.null(ss_b[[batch_keys$x]]))
  expect_false(is.null(ss_b[[batch_keys$y]]))
  # A result cannot reach its destination before both validity shares arrive.
  expect_error(do.call(call_a, c(list(exactGCVecmulCommitDS), common)),
               "Exact MPC multiplication failed")
  expect_null(ss_a$direct_product)
  validity_a <- do.call(call_a, c(list(exactGCVecmulValidityDS), common))
  validity_b <- do.call(call_b, c(list(exactGCVecmulValidityDS), common))
  last <- substr(validity_b$peer_blob, nchar(validity_b$peer_blob),
                 nchar(validity_b$peer_blob))
  tampered <- paste0(substr(validity_b$peer_blob, 1L,
                            nchar(validity_b$peer_blob) - 1L),
                     if (identical(last, "A")) "B" else "A")
  expect_error(do.call(call_a, c(
    list(exactGCVecmulValidityReceiveDS), list(peer_blob = tampered), common)),
    "Exact MPC multiplication failed")
  checked_a <- do.call(call_a, c(
    list(exactGCVecmulValidityReceiveDS),
    list(peer_blob = validity_b$peer_blob), common))
  checked_b <- do.call(call_b, c(
    list(exactGCVecmulValidityReceiveDS),
    list(peer_blob = validity_a$peer_blob), common))
  expect_identical(checked_a$state, "checked")
  expect_identical(checked_b$state, "checked")
  # A destination mutation after bind is detected before the one-shot GC
  # output is consumed, so no stale or partially committed value is exposed.
  ss_a$direct_product <- "tampered"
  expect_error(do.call(call_a, c(list(exactGCVecmulCommitDS), common)),
               "Exact MPC multiplication failed")
  expect_false(is.null(ss_a$.exact_gc_outputs[[
    .exact_gc_checked_mul_keys(operation_id)$output]]))
  expect_null(ss_a$.exact_gc_checked_mul_commits[[operation_id]])
  ss_a$direct_product <- NULL
  committed_a <- do.call(call_a, c(list(exactGCVecmulCommitDS), common))
  committed_b <- do.call(call_b, c(list(exactGCVecmulCommitDS), common))
  expect_identical(committed_a$state, "committed")
  expect_identical(committed_b$state, "committed")
  product <- .callMpcTool("k2-ring63-aggregate", list(
    share_a = ss_a$direct_product, share_b = ss_b$direct_product,
    frac_bits = 50L, ring = "ring127"))$values
  expect_equal(as.numeric(product), c(6, 3), tolerance = 1e-12)
  expect_null(ss_a[[batch_keys$x]])
  expect_null(ss_a[[batch_keys$y]])
  expect_null(ss_b[[batch_keys$x]])
  expect_null(ss_b[[batch_keys$y]])
  expect_identical(do.call(call_a, c(
    list(exactGCVecmulCommitDS), common))$state, "committed")
  expect_identical(
    ss_a$.exact_gc_vecmul_manifests[[manifest_a$manifest_handle]]$state,
    "consumed")
  expect_error(call_a(
    exactGCVecmulClaimInputsDS,
    manifest_handle = manifest_a$manifest_handle,
    batch_operation_id = "op_abababababababababababababababab",
    session_id = session_id), "Exact MPC multiplication failed")

  # A producer snapshot cannot be rebound after either source changes. The
  # failed claim has no derived batch side effect while the immutable ticket
  # remains tied to its original digest.
  ss_a$snapshot_x <- x_fp
  ss_a$snapshot_y <- y_fp
  snapshot_manifest <- testthat::with_mocked_bindings(
    .exact_gc_vecmul_mint_manifest(
      ss = ss_a, session_id = session_id,
      producer = "test.vecmul.v1", purpose = "test.vecmul",
      total_n = total_n, x_key = "snapshot_x", y_key = "snapshot_y",
      output_key = "snapshot_product", ring_bits = 127L, frac_bits = 50L,
      bound_x = "4503599627370496", bound_y = "2251799813685248",
      allow_test = TRUE),
    .S = function(session_id) ss_a, .package = "dsVert")
  ss_a$snapshot_x <- zero_fp
  snapshot_batch <- "op_cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd"
  expect_error(call_a(
    exactGCVecmulClaimInputsDS,
    manifest_handle = snapshot_manifest$manifest_handle,
    batch_operation_id = snapshot_batch, session_id = session_id),
    "Exact MPC multiplication failed")
  snapshot_keys <- .exact_gc_checked_mul_keys(snapshot_batch)
  expect_null(ss_a[[snapshot_keys$x]])
  expect_null(ss_a[[snapshot_keys$y]])
  expect_identical(ss_a$.exact_gc_vecmul_manifests[[
    snapshot_manifest$manifest_handle]]$state, "fresh")
  tampered_manifest <- ss_a$.exact_gc_vecmul_manifests[[
    snapshot_manifest$manifest_handle]]
  tampered_manifest$state <- "claimed"
  ss_a$.exact_gc_vecmul_manifests[[snapshot_manifest$manifest_handle]] <-
    tampered_manifest
  expect_error(call_a(
    exactGCVecmulClaimInputsDS,
    manifest_handle = snapshot_manifest$manifest_handle,
    batch_operation_id = snapshot_batch, session_id = session_id),
    "Exact MPC multiplication failed")

  # The runtime-owned bound is checked inside the circuit. Its XOR validity
  # remains peer-only; an invalid product can never reach the destination.
  over_bound <- raw(16L)
  over_bound[[8L]] <- as.raw(128L) # 2^63, one above the fixed bound.
  one <- raw(16L)
  one[[1L]] <- as.raw(1L)
  encode_raw <- function(value) gsub(
    "[\r\n]", "", jsonlite::base64_enc(value))
  ss_a$over_x <- encode_raw(over_bound)
  ss_a$over_y <- encode_raw(one)
  ss_b$over_x <- encode_raw(raw(16L))
  ss_b$over_y <- encode_raw(raw(16L))
  invalid_batch <- "op_ffffffffffffffffffffffffffffffff"
  invalid_mint <- list(
    session_id = session_id, producer = "test.vecmul.v1",
    purpose = "test.vecmul",
    x_key = "over_x", y_key = "over_y", output_key = "must_not_commit",
    total_n = 1L, ring_bits = 127L, frac_bits = 50L,
    bound_x = "9223372036854775807", bound_y = "1",
    allow_test = TRUE)
  invalid_manifest_a <- testthat::with_mocked_bindings(
    do.call(.exact_gc_vecmul_mint_manifest,
            c(list(ss = ss_a), invalid_mint)),
    .S = function(session_id) ss_a, .package = "dsVert")
  invalid_manifest_b <- testthat::with_mocked_bindings(
    do.call(.exact_gc_vecmul_mint_manifest,
            c(list(ss = ss_b), invalid_mint)),
    .S = function(session_id) ss_b, .package = "dsVert")
  invalid_bound_a <- call_a(
    exactGCVecmulClaimInputsDS,
    manifest_handle = invalid_manifest_a$manifest_handle,
    batch_operation_id = invalid_batch, session_id = session_id)
  invalid_bound_b <- call_b(
    exactGCVecmulClaimInputsDS,
    manifest_handle = invalid_manifest_b$manifest_handle,
    batch_operation_id = invalid_batch, session_id = session_id)
  expect_identical(invalid_bound_a$plan_id, invalid_bound_b$plan_id)
  invalid_plan_id <- invalid_bound_a$plan_id
  invalid_op <- .exact_gc_checked_mul_chunk_operation(
    invalid_batch, 1L, 1L, policy_id, invalid_plan_id)
  invalid_common <- list(
    n = 1L, total_n = 1L, chunk_index = 1L, chunk_count = 1L,
    batch_operation_id = invalid_batch, session_id = session_id,
    operation_id = invalid_op, policy_id = policy_id,
    plan_id = invalid_plan_id)
  do.call(call_a, c(list(exactGCVecmulStartDS), invalid_common))
  do.call(call_b, c(list(exactGCVecmulStartDS), invalid_common))
  .exact_gc_test_pump(ss_a, ss_b, session_id, invalid_op, seed_a, seed_b)
  invalid_validity_a <- do.call(call_a, c(
    list(exactGCVecmulValidityDS), invalid_common))
  invalid_validity_b <- do.call(call_b, c(
    list(exactGCVecmulValidityDS), invalid_common))
  expect_error(do.call(call_a, c(
    list(exactGCVecmulValidityReceiveDS),
    list(peer_blob = validity_b$peer_blob), invalid_common)),
    "Exact MPC multiplication failed")
  expect_identical(do.call(call_a, c(
    list(exactGCVecmulValidityReceiveDS),
    list(peer_blob = invalid_validity_b$peer_blob), invalid_common))$state,
    "checked")
  expect_identical(do.call(call_b, c(
    list(exactGCVecmulValidityReceiveDS),
    list(peer_blob = invalid_validity_a$peer_blob), invalid_common))$state,
    "checked")
  expect_error(do.call(call_a, c(
    list(exactGCVecmulCommitDS), invalid_common)),
    "Exact MPC multiplication failed")
  expect_error(do.call(call_b, c(
    list(exactGCVecmulCommitDS), invalid_common)),
    "Exact MPC multiplication failed")
  expect_null(ss_a$must_not_commit)
  expect_null(ss_b$must_not_commit)
  invalid_keys <- .exact_gc_checked_mul_keys(invalid_batch)
  expect_false(is.null(ss_a[[invalid_keys$x]]))
  expect_false(is.null(ss_b[[invalid_keys$x]]))
  expect_true(call_a(
    exactGCAbortDS, session_id = session_id, operation_id = invalid_op))
  expect_true(call_b(
    exactGCAbortDS, session_id = session_id, operation_id = invalid_op))
  expect_null(ss_a[[invalid_keys$x]])
  expect_null(ss_a[[invalid_keys$y]])
  expect_null(ss_b[[invalid_keys$x]])
  expect_null(ss_b[[invalid_keys$y]])
  expect_identical(
    ss_a$.exact_gc_vecmul_input_stages[[invalid_batch]]$state, "aborted")
  expect_identical(
    ss_b$.exact_gc_vecmul_input_stages[[invalid_batch]]$state, "aborted")
  expect_identical(ss_a$.exact_gc_vecmul_manifests[[
    invalid_manifest_a$manifest_handle]]$state, "aborted")
  expect_identical(ss_b$.exact_gc_vecmul_manifests[[
    invalid_manifest_b$manifest_handle]]$state, "aborted")

  # One complete production Chisq workload: provenance-bound one-hot columns,
  # four checked direct-wide products, exact truncation, bilateral validity and
  # fixed-order sealed count accumulation. Reconstruction below exists only in
  # this in-process oracle; no DS endpoint returns either share.
  row_value <- c(1L, 1L, 1L, 1L, 2L, 2L, 2L, 2L)
  col_value <- c(1L, 1L, 2L, 2L, 1L, 2L, 2L, 2L)
  chisq_n <- length(row_value)
  chisq_k <- 2L
  chisq_l <- 2L
  row_matrix <- cbind(row_value == 1L, row_value == 2L)
  col_matrix <- cbind(col_value == 1L, col_value == 2L)
  encode_onehot <- function(value) .callMpcTool("k2-float-to-fp", list(
    values = array(as.numeric(t(value)), dim = length(value)),
    frac_bits = 20L, ring = "ring63"))$fp_data
  row_fp <- encode_onehot(row_matrix)
  col_fp <- encode_onehot(col_matrix)
  zero_matrix <- function(n, levels) gsub(
    "[\r\n]", "", jsonlite::base64_enc(raw(8L * n * levels)))
  record_onehot <- function(ss, key, variable, value, levels,
                            source, peer_name = NULL) {
    ss[[key]] <- value
    if (is.null(ss$.dsvert_shared_onehot_provenance)) {
      ss$.dsvert_shared_onehot_provenance <- list()
    }
    ss$.dsvert_shared_onehot_provenance[[key]] <- list(
      version = .DSVERT_SHARED_ONEHOT_PROVENANCE_VERSION,
      key = key, variable = variable, n = as.integer(chisq_n),
      levels = as.integer(levels), ring_bits = 63L, frac_bits = 20L,
      source = source, peer_name = peer_name,
      value_digest = .dsvert_shared_onehot_digest(value))
  }
  record_onehot(
    ss_a, "k2_onehot_row_fp", "row", row_fp, chisq_k, "local")
  record_onehot(
    ss_b, "k2_onehot_peer_row_fp", "row",
    zero_matrix(chisq_n, chisq_k), chisq_k, "peer", "site_a")
  record_onehot(
    ss_a, "k2_onehot_peer_col_fp", "col", col_fp, chisq_l,
    "peer", "site_b")
  record_onehot(
    ss_b, "k2_onehot_col_fp", "col",
    zero_matrix(chisq_n, chisq_l), chisq_l, "local")

  last_accumulated_a <- NULL
  last_accumulated_b <- NULL
  for (row_index in seq_len(chisq_k)) {
    for (column_index in seq_len(chisq_l)) {
      cell_index <- as.integer(
        (row_index - 1L) * chisq_l + column_index)
      prepare_args <- list(
        row_variable = "row", column_variable = "col",
        row_server = "site_a", column_server = "site_b",
        row_index = as.integer(row_index),
        column_index = as.integer(column_index), n = as.integer(chisq_n),
        row_levels = chisq_k, column_levels = chisq_l,
        session_id = session_id)
      manifest_a <- do.call(call_a, c(
        list(exactGCChisqProductPrepareDS), prepare_args))
      manifest_b <- do.call(call_b, c(
        list(exactGCChisqProductPrepareDS), prepare_args))
      expect_identical(manifest_a$context_hash, manifest_b$context_hash)
      expect_identical(manifest_a$plan_id, manifest_b$plan_id)
      expect_identical(manifest_a$ring_bits, 63L)
      expect_identical(manifest_a$frac_bits, 20L)
      expect_identical(manifest_a$backend, "direct-wide")
      expect_identical(manifest_a$bound_x, "1048576")
      expect_identical(manifest_a$bound_y, "1048576")
      expect_identical(manifest_a$truncated_bound, "1048576")
      expect_true(manifest_a$raw_product_headroom)
      expect_true(manifest_a$output_headroom)
      if (cell_index == 1L) {
        expect_identical(do.call(call_a, c(
          list(exactGCChisqProductPrepareDS), prepare_args)), manifest_a)
      }

      batch <- paste0("op_", sprintf("%032x", 100L + cell_index))
      claim_a <- call_a(
        exactGCVecmulClaimInputsDS,
        manifest_handle = manifest_a$manifest_handle,
        batch_operation_id = batch, session_id = session_id)
      claim_b <- call_b(
        exactGCVecmulClaimInputsDS,
        manifest_handle = manifest_b$manifest_handle,
        batch_operation_id = batch, session_id = session_id)
      expect_identical(claim_a$plan_id, claim_b$plan_id)
      operation_id <- .exact_gc_checked_mul_chunk_operation(
        batch, 1L, 1L, claim_a$policy_id, claim_a$plan_id)
      common <- list(
        n = as.integer(chisq_n), total_n = as.integer(chisq_n),
        chunk_index = 1L, chunk_count = 1L,
        batch_operation_id = batch, session_id = session_id,
        operation_id = operation_id, policy_id = claim_a$policy_id,
        plan_id = claim_a$plan_id)
      do.call(call_a, c(list(exactGCVecmulStartDS), common))
      do.call(call_b, c(list(exactGCVecmulStartDS), common))
      .exact_gc_test_pump(
        ss_a, ss_b, session_id, operation_id, seed_a, seed_b)
      valid_a <- do.call(call_a, c(
        list(exactGCVecmulValidityDS), common))
      valid_b <- do.call(call_b, c(
        list(exactGCVecmulValidityDS), common))
      do.call(call_a, c(
        list(exactGCVecmulValidityReceiveDS),
        list(peer_blob = valid_b$peer_blob), common))
      do.call(call_b, c(
        list(exactGCVecmulValidityReceiveDS),
        list(peer_blob = valid_a$peer_blob), common))
      expect_identical(do.call(call_a, c(
        list(exactGCVecmulCommitDS), common))$state, "committed")
      expect_identical(do.call(call_b, c(
        list(exactGCVecmulCommitDS), common))$state, "committed")
      last_accumulated_a <- call_a(
        k2ChisqCrossAccumulateCountDS,
        cell_index = cell_index, total_cells = chisq_k * chisq_l,
        session_id = session_id)
      last_accumulated_b <- call_b(
        k2ChisqCrossAccumulateCountDS,
        cell_index = cell_index, total_cells = chisq_k * chisq_l,
        session_id = session_id)
      expect_null(ss_a[[.DSVERT_CHISQ_COUNT_SOURCE]])
      expect_null(ss_b[[.DSVERT_CHISQ_COUNT_SOURCE]])
    }
  }
  expect_identical(call_a(
    k2ChisqCrossAccumulateCountDS,
    cell_index = 4L, total_cells = 4L,
    session_id = session_id), last_accumulated_a)
  expect_identical(call_b(
    k2ChisqCrossAccumulateCountDS,
    cell_index = 4L, total_cells = 4L,
    session_id = session_id), last_accumulated_b)
  reconstructed_counts <- .callMpcTool("k2-ring63-aggregate", list(
    share_a = ss_a[[.DSVERT_CHISQ_COUNT_KEY]],
    share_b = ss_b[[.DSVERT_CHISQ_COUNT_KEY]],
    frac_bits = 20L, ring = "ring63"))$values
  central_counts <- as.numeric(t(table(row_value, col_value)))
  expect_identical(as.numeric(reconstructed_counts), central_counts)
  expect_equal(as.numeric(sum(reconstructed_counts)), as.numeric(chisq_n))

  guard_op <- "op_22222222222222222222222222222222"
  guard_in <- "exact_gc_in_22222222222222222222222222222222"
  guard_out <- "exact_gc_out_22222222222222222222222222222222"
  .exact_gc_stage_share(
    ss_a, guard_in, .exact_gc_test_b64_records(c(0, 1, 3), 8L),
    63L, 3L, "test.counts", "count-guard", "test.guard", 0L,
    "xor-bit-share")
  .exact_gc_stage_share(
    ss_b, guard_in, .exact_gc_test_b64_records(c(0, 1, 5), 8L),
    63L, 3L, "test.counts", "count-guard", "test.guard", 0L,
    "xor-bit-share")
  initialized <- init_pair(
    guard_op, guard_in, guard_out, "count-guard", 63L, 0L, 3L,
    "test.guard")
  # The analyst option attempted to lower the threshold to one; the custodian
  # nfilter.tab=3 floor remains authoritative on both peers.
  expect_identical(initialized$left$threshold, "3")
  expect_identical(initialized$right$threshold, "3")
  .exact_gc_test_pump(ss_a, ss_b, session_id, guard_op, seed_a, seed_b)
  guard_a <- .exact_gc_consume_output(
    ss_a, guard_out, guard_op, "xor-bit-share", "count-guard",
    "test.guard", 63L, 0L, 3L, "test.counts")
  guard_b <- .exact_gc_consume_output(
    ss_b, guard_out, guard_op, "xor-bit-share", "count-guard",
    "test.guard", 63L, 0L, 3L, "test.counts")
  bit_a <- bitwAnd(as.integer(jsonlite::base64_dec(guard_a$share)[[1L]]), 1L)
  bit_b <- bitwAnd(as.integer(jsonlite::base64_dec(guard_b$share)[[1L]]), 1L)
  expect_identical(bitwXor(bit_a, bit_b), 0L)
  expect_identical(guard_a$vector_len, 3L)
  expect_false(any(grepl("result|share", c(
    names(initialized$left), names(initialized$right)), ignore.case = TRUE)))

  # The production Chisq path binds one immutable count vector to one aggregate
  # predicate.  It never returns either count shares or exact counts, even when
  # the predicate passes; the only next state is the unavailable joint-DP
  # capability receipt.
  stage_chisq_counts <- function(values) {
    share_a <- .callMpcTool("k2-float-to-fp", list(
      values = array(values, dim = length(values)), frac_bits = 20L,
      ring = "ring63"))$fp_data
    share_b <- .callMpcTool("k2-float-to-fp", list(
      values = array(rep(0, length(values)), dim = length(values)),
      frac_bits = 20L, ring = "ring63"))$fp_data
    context <- .exact_gc_chisq_count_context(session_id, length(values))
    for (entry in list(list(ss_a, share_a), list(ss_b, share_b))) {
      ss <- entry[[1L]]
      share <- entry[[2L]]
      ss[[.DSVERT_CHISQ_COUNT_KEY]] <- share
      ss$.exact_gc_chisq_counts <- list(
        version = context$version, status = "complete",
        total_cells = as.integer(length(values)),
        next_index = as.integer(length(values) + 1L),
        last_index = as.integer(length(values)),
        last_source_digest = strrep("b", 64L),
        count_digest = .exact_gc_chisq_digest(share),
        public_context = context,
        public_context_hash = .exact_gc_chisq_public_hash(context))
      ss$.exact_gc_chisq_guard_manifests <- list()
      ss$.exact_gc_chisq_guard_stages <- list()
      ss$.exact_gc_chisq_guard_authorization <- NULL
      ss$.exact_gc_chisq_joint_release <- NULL
    }
  }
  run_chisq_guard <- function(values, operation_id, inject_seal_failure = FALSE) {
    stage_chisq_counts(values)
    prepared_a <- call_a(
      exactGCChisqGuardPrepareDS, session_id = session_id)
    prepared_b <- call_b(
      exactGCChisqGuardPrepareDS, session_id = session_id)
    expect_identical(prepared_a$context_hash, prepared_b$context_hash)
    expect_identical(prepared_a$threshold, as.character(3L * 2^20))
    expect_false(any(c("share", "source_digest") %in% names(prepared_a)))
    start_a <- call_a(
      exactGCChisqGuardStartDS,
      manifest_handle = prepared_a$manifest_handle,
      operation_id = operation_id, session_id = session_id)
    start_b <- call_b(
      exactGCChisqGuardStartDS,
      manifest_handle = prepared_b$manifest_handle,
      operation_id = operation_id, session_id = session_id)
    expect_identical(start_a$context_hash, start_b$context_hash)
    .exact_gc_test_pump(
      ss_a, ss_b, session_id, operation_id, seed_a, seed_b)
    finalize_args_a <- list(
      manifest_handle = prepared_a$manifest_handle,
      operation_id = operation_id, session_id = session_id)
    finalize_args_b <- list(
      manifest_handle = prepared_b$manifest_handle,
      operation_id = operation_id, session_id = session_id)
    if (isTRUE(inject_seal_failure)) {
      options(dsvert.identity_seed = seed_a,
              dsvert.trusted_peers = c(site_b = identity_b$identity_pk))
      expect_error(testthat::with_mocked_bindings(
        do.call(.exact_gc_chisq_finalize_impl, finalize_args_a),
        .S = function(session_id) ss_a,
        .exact_gc_checked_mul_seal = function(...) stop("injected seal failure"),
        .package = "dsVert"), "injected seal failure")
      expect_identical(
        ss_a$.exact_gc_chisq_guard_stages[[operation_id]]$state,
        "output-consumed")
    }
    sealed_a <- do.call(call_a, c(
      list(exactGCChisqGuardFinalizeDS), finalize_args_a))
    sealed_b <- do.call(call_b, c(
      list(exactGCChisqGuardFinalizeDS), finalize_args_b))
    authorized_a <- call_a(
      exactGCChisqGuardAuthorizeDS,
      manifest_handle = prepared_a$manifest_handle,
      operation_id = operation_id, peer_blob = sealed_b$peer_blob,
      session_id = session_id)
    authorized_b <- call_b(
      exactGCChisqGuardAuthorizeDS,
      manifest_handle = prepared_b$manifest_handle,
      operation_id = operation_id, peer_blob = sealed_a$peer_blob,
      session_id = session_id)
    # Authorization retries remain byte/context exact after the private local
    # bit share has been erased.
    expect_identical(call_a(
      exactGCChisqGuardAuthorizeDS,
      manifest_handle = prepared_a$manifest_handle,
      operation_id = operation_id, peer_blob = sealed_b$peer_blob,
      session_id = session_id), authorized_a)
    list(left = authorized_a, right = authorized_b)
  }

  admitted <- run_chisq_guard(
    c(0, 3, 5), "op_67676767676767676767676767676767",
    inject_seal_failure = TRUE)
  expect_true(admitted$left$authorized)
  expect_true(admitted$right$authorized)
  pending_a <- call_a(exactGCChisqJointReleaseDS, session_id = session_id)
  pending_b <- call_b(exactGCChisqJointReleaseDS, session_id = session_id)
  expect_identical(pending_a, pending_b)
  expect_false(pending_a$released)
  expect_identical(pending_a$state, "joint_mpc_single_opening_required")
  expect_false(any(c("share", "values", "table", "statistic") %in%
                     names(pending_a)))

  rejected <- run_chisq_guard(
    c(0, 2, 3), "op_78787878787878787878787878787878")
  expect_false(rejected$left$authorized)
  expect_false(rejected$right$authorized)
  expect_identical(rejected$left$failure_code, "non_identifiable")
  expect_identical(rejected$right$failure_code, "non_identifiable")
  expect_null(ss_a$.exact_gc_chisq_joint_release)
  expect_null(ss_b$.exact_gc_chisq_joint_release)
  expect_error(call_a(
    exactGCChisqJointReleaseDS, session_id = session_id),
    "purpose-bound cross-contingency release is unavailable")

  # A transport/protocol abort removes every operation-scoped guard artifact,
  # including a locally completed output, without deleting or exposing the
  # immutable protected count vector. The cleanup itself is idempotent.
  stage_chisq_counts(c(0, 3, 5))
  aborted_op <- "op_89898989898989898989898989898989"
  aborted_a <- call_a(exactGCChisqGuardPrepareDS, session_id = session_id)
  aborted_b <- call_b(exactGCChisqGuardPrepareDS, session_id = session_id)
  call_a(
    exactGCChisqGuardStartDS, manifest_handle = aborted_a$manifest_handle,
    operation_id = aborted_op, session_id = session_id)
  call_b(
    exactGCChisqGuardStartDS, manifest_handle = aborted_b$manifest_handle,
    operation_id = aborted_op, session_id = session_id)
  keys <- .exact_gc_chisq_operation_keys(aborted_op)
  spool_a <- .exact_gc_operation_state(ss_a, aborted_op)$spool
  spool_b <- .exact_gc_operation_state(ss_b, aborted_op)$spool
  expect_true(call_a(
    exactGCAbortDS, session_id = session_id, operation_id = aborted_op))
  expect_true(call_b(
    exactGCAbortDS, session_id = session_id, operation_id = aborted_op))
  expect_true(call_a(
    exactGCAbortDS, session_id = session_id, operation_id = aborted_op))
  for (entry in list(
      list(ss_a, aborted_a, spool_a), list(ss_b, aborted_b, spool_b))) {
    ss <- entry[[1L]]
    prepared <- entry[[2L]]
    spool <- entry[[3L]]
    expect_identical(
      ss$.exact_gc_chisq_guard_stages[[aborted_op]]$state, "aborted")
    expect_null(ss$.exact_gc_chisq_guard_stages[[aborted_op]]$local_share)
    expect_null(ss$.exact_gc_chisq_guard_stages[[aborted_op]]$peer_blob)
    expect_identical(
      ss$.exact_gc_chisq_guard_manifests[[prepared$manifest_handle]]$state,
      "aborted")
    expect_identical(
      .exact_gc_operation_state(ss, aborted_op)$status, "aborted")
    expect_null(ss$.exact_gc_inputs[[keys$source]])
    expect_null(ss$.exact_gc_outputs[[keys$output]])
    expect_false(dir.exists(spool))
    expect_false(is.null(ss[[.DSVERT_CHISQ_COUNT_KEY]]))
  }

  # Real worker/spool E2E timings for the hybrid candidate's two GC pieces.
  # These are observations, never pass/fail throughput promises.
  benchmark_mode <- Sys.getenv("DSVERT_RUN_EXACT_GC_BENCHMARK")
  if (benchmark_mode %in% c("true", "truncate", "hybrid", "count")) {
  options(dsvert.exact_gc.chunk_bytes = 1024^2,
          dsvert.exact_gc.spool_max_bytes = 1024^3)
  benchmark_n <- 180L
  benchmark_results <- list()
  if (benchmark_mode %in% c("true", "truncate")) {
  trunc_bench_op <- "op_34343434343434343434343434343434"
  trunc_bench_in <- "exact_gc_in_34343434343434343434343434343434"
  trunc_bench_out <- "exact_gc_out_34343434343434343434343434343434"
  .exact_gc_stage_share(
    ss_a, trunc_bench_in,
    .exact_gc_test_b64_records(rep(20L, benchmark_n), 16L),
    127L, benchmark_n, "benchmark.raw-product", "truncate-floor",
    "benchmark.truncate", 2L, "ring-share")
  .exact_gc_stage_share(
    ss_b, trunc_bench_in,
    .exact_gc_test_b64_records(rep(0L, benchmark_n), 16L),
    127L, benchmark_n, "benchmark.raw-product", "truncate-floor",
    "benchmark.truncate", 2L, "ring-share")
  init_pair(
    trunc_bench_op, trunc_bench_in, trunc_bench_out, "truncate-floor",
    127L, 2L, benchmark_n, "benchmark.truncate")
  trunc_metrics <- .exact_gc_test_pump(
    ss_a, ss_b, session_id, trunc_bench_op, seed_a, seed_b)
  trunc_bench_a <- .exact_gc_consume_output(
    ss_a, trunc_bench_out, trunc_bench_op, "ring-share", "truncate-floor",
    "benchmark.truncate", 127L, 2L, benchmark_n,
    "benchmark.raw-product")
  trunc_bench_b <- .exact_gc_consume_output(
    ss_b, trunc_bench_out, trunc_bench_op, "ring-share", "truncate-floor",
    "benchmark.truncate", 127L, 2L, benchmark_n,
    "benchmark.raw-product")
  trunc_reconstructed <- .exact_gc_test_add_le(
    jsonlite::base64_dec(trunc_bench_a$share),
    jsonlite::base64_dec(trunc_bench_b$share), 127L)
  first_bytes <- seq.int(1L, length(trunc_reconstructed), by = 16L)
  expect_true(all(as.integer(trunc_reconstructed[first_bytes]) == 5L))
  expect_true(all(as.integer(trunc_reconstructed[-first_bytes]) == 0L))
  benchmark_results$ring127_truncate_floor_n180 <- trunc_metrics
  }

  if (benchmark_mode %in% c("true", "hybrid")) {
  hybrid_bench_op <- "op_45454545454545454545454545454545"
  hybrid_bench_in <- "exact_gc_in_45454545454545454545454545454545"
  hybrid_bench_out <- "exact_gc_out_45454545454545454545454545454545"
  # x=y=1 is deliberately simple, but still traverses both crossed OTs,
  # the private bound proof, exact floor truncation and masked output path.
  .exact_gc_stage_share(
    ss_a, hybrid_bench_in,
    .exact_gc_test_b64_records(rep(1L, 2L * benchmark_n), 16L),
    127L, benchmark_n, "benchmark.checked-product",
    "mul-truncate-checked", "benchmark.hybrid", 50L,
    "checked-ring-share")
  .exact_gc_stage_share(
    ss_b, hybrid_bench_in,
    .exact_gc_test_b64_records(rep(0L, 2L * benchmark_n), 16L),
    127L, benchmark_n, "benchmark.checked-product",
    "mul-truncate-checked", "benchmark.hybrid", 50L,
    "checked-ring-share")
  init_pair(
    hybrid_bench_op, hybrid_bench_in, hybrid_bench_out,
    "mul-truncate-checked", 127L, 50L, benchmark_n, "benchmark.hybrid")
  hybrid_metrics <- .exact_gc_test_pump(
    ss_a, ss_b, session_id, hybrid_bench_op, seed_a, seed_b,
    concurrent = TRUE)
  hybrid_bench_a <- .exact_gc_consume_output(
    ss_a, hybrid_bench_out, hybrid_bench_op, "checked-ring-share",
    "mul-truncate-checked", "benchmark.hybrid", 127L, 50L, benchmark_n,
    "benchmark.checked-product")
  hybrid_bench_b <- .exact_gc_consume_output(
    ss_b, hybrid_bench_out, hybrid_bench_op, "checked-ring-share",
    "mul-truncate-checked", "benchmark.hybrid", 127L, 50L, benchmark_n,
    "benchmark.checked-product")
  hybrid_reconstructed <- .exact_gc_test_add_le(
    jsonlite::base64_dec(hybrid_bench_a$share),
    jsonlite::base64_dec(hybrid_bench_b$share), 127L)
  expect_true(all(as.integer(hybrid_reconstructed) == 0L))
  hybrid_valid_a <- bitwAnd(as.integer(
    jsonlite::base64_dec(hybrid_bench_a$validity_share)[[1L]]), 1L)
  hybrid_valid_b <- bitwAnd(as.integer(
    jsonlite::base64_dec(hybrid_bench_b$validity_share)[[1L]]), 1L)
  expect_identical(bitwXor(hybrid_valid_a, hybrid_valid_b), 1L)
  benchmark_results$ring127_hybrid_checked_mul_n180 <- hybrid_metrics
  }

  if (benchmark_mode %in% c("true", "count")) {
  count_bench_op <- "op_56565656565656565656565656565656"
  count_bench_in <- "exact_gc_in_56565656565656565656565656565656"
  count_bench_out <- "exact_gc_out_56565656565656565656565656565656"
  .exact_gc_stage_share(
    ss_a, count_bench_in,
    .exact_gc_test_b64_records(rep(5L, benchmark_n), 16L),
    127L, benchmark_n, "benchmark.counts", "count-guard",
    "benchmark.guard", 0L, "xor-bit-share")
  .exact_gc_stage_share(
    ss_b, count_bench_in,
    .exact_gc_test_b64_records(rep(0L, benchmark_n), 16L),
    127L, benchmark_n, "benchmark.counts", "count-guard",
    "benchmark.guard", 0L, "xor-bit-share")
  init_pair(
    count_bench_op, count_bench_in, count_bench_out, "count-guard",
    127L, 0L, benchmark_n, "benchmark.guard")
  count_metrics <- .exact_gc_test_pump(
    ss_a, ss_b, session_id, count_bench_op, seed_a, seed_b)
  count_bench_a <- .exact_gc_consume_output(
    ss_a, count_bench_out, count_bench_op, "xor-bit-share", "count-guard",
    "benchmark.guard", 127L, 0L, benchmark_n, "benchmark.counts")
  count_bench_b <- .exact_gc_consume_output(
    ss_b, count_bench_out, count_bench_op, "xor-bit-share", "count-guard",
    "benchmark.guard", 127L, 0L, benchmark_n, "benchmark.counts")
  count_bit_a <- bitwAnd(
    as.integer(jsonlite::base64_dec(count_bench_a$share)[[1L]]), 1L)
  count_bit_b <- bitwAnd(
    as.integer(jsonlite::base64_dec(count_bench_b$share)[[1L]]), 1L)
  expect_identical(bitwXor(count_bit_a, count_bit_b), 1L)
  benchmark_results$ring127_count_guard_n180 <- count_metrics
  }
  .exact_gc_test_cache$benchmarks <- benchmark_results
  options(dsvert.exact_gc.benchmark_results =
            .exact_gc_test_cache$benchmarks)
  }
})

test_that("exact spool retries are byte-exact and conflicting overlap is fatal", {
  path <- tempfile("exact-gc-append-")
  .exact_gc_private_file(path, as.raw(1:4))
  on.exit(unlink(path), add = TRUE)
  expect_equal(.exact_gc_append_at(path, 2, as.raw(3:6), 100), 6)
  expect_equal(.exact_gc_append_at(path, 2, as.raw(3:6), 100), 6)
  expect_error(.exact_gc_append_at(path, 2, as.raw(c(3, 99)), 100),
               "Conflicting")
})

test_that("segmented exact spool reclaims bytes without changing absolute offsets", {
  spool <- tempfile("exact-gc-segmented-")
  dir.create(spool, mode = "0700")
  on.exit(unlink(spool, recursive = TRUE), add = TRUE)
  for (name in c(
      "inbound.bin", "outbound.bin", "exchange.hb", "worker.hb")) {
    .exact_gc_private_file(
      file.path(spool, name),
      if (name %in% c("exchange.hb", "worker.hb")) charToRaw(".") else raw(0))
  }
  for (name in c("inbound.segments", "outbound.segments")) {
    dir.create(file.path(spool, name), mode = "0700")
  }
  .exact_gc_private_file(
    file.path(spool, "inbound.state"), charToRaw(paste(
      .DSVERT_EXACT_GC_INBOUND_STATE_VERSION, "0", "-", "-", "-",
      sep = "|")))
  for (name in c("inbound.ack", "outbound.head", "outbound.ack")) {
    .exact_gc_private_file(file.path(spool, name), charToRaw("0"))
  }
  state <- new.env(parent = emptyenv())
  state$spool <- spool
  state$spool_max_bytes <- 6
  state$chunk_bytes <- 8
  state$status <- "complete"
  state$ttl_seconds <- 10
  state$process <- list(is_alive = function() TRUE)

  first <- as.raw(1:4)
  # Crash window: the immutable rename completed but inbound.state did not.
  .exact_gc_segment_publish(
    file.path(spool, "inbound.segments"), 0, first, 6)
  expect_identical(.exact_gc_inbound_state_read(state)$head, 0)
  expect_identical(.exact_gc_inbound_append(state, 0, first), 4)
  inbound_files <- .exact_gc_segment_list(
    file.path(spool, "inbound.segments"))$path
  expect_length(inbound_files, 1L)

  # Simulate the worker's durable consume-base commit and reclamation. A lost
  # response can still retry the exact last frame; a changed frame cannot.
  .exact_gc_offset_write(file.path(spool, "inbound.ack"), 4)
  expect_identical(unlink(inbound_files), 0L)
  expect_identical(.exact_gc_inbound_append(state, 0, first), 4)
  expect_error(.exact_gc_inbound_append(state, 0, as.raw(c(1:3, 9))),
               "Conflicting")
  expect_identical(.exact_gc_inbound_append(state, 4, as.raw(5:8)), 8)
  pauses <- 0L
  expect_identical(testthat::with_mocked_bindings(
    .exact_gc_inbound_append(state, 8, as.raw(9:12)),
    .exact_gc_backpressure_pause = function() {
      pauses <<- pauses + 1L
      .exact_gc_offset_write(file.path(spool, "inbound.ack"), 8)
      paths <- .exact_gc_segment_list(
        file.path(spool, "inbound.segments"))$path
      if (length(paths)) unlink(paths)
    }, .package = "dsVert"), 12)
  expect_identical(pauses, 1L)
  expect_error(.exact_gc_inbound_append(state, 0, first), "Conflicting")
  expect_error(.exact_gc_inbound_append(state, 13, as.raw(13)), "offset gap")
  expect_lte(.exact_gc_segment_retained_bytes(
    file.path(spool, "inbound.segments")), state$spool_max_bytes)

  out_dir <- file.path(spool, "outbound.segments")
  .exact_gc_segment_publish(out_dir, 0, as.raw(11:14), 16)
  .exact_gc_segment_publish(out_dir, 4, as.raw(15:18), 16)
  .exact_gc_offset_write(file.path(spool, "outbound.head"), 8)
  expect_identical(.exact_gc_segment_read(state, 2, 6), as.raw(13:18))
  offer <- list(
    offset = 0, chunk_bytes = 4,
    payload_hash = digest::digest(
      as.raw(11:14), algo = "sha256", serialize = FALSE))
  .exact_gc_outbound_offer_write(state, offer)
  # Opposite crash window: the durable absolute ACK base committed but segment
  # reclamation did not. Re-entry completes deletion idempotently.
  .exact_gc_offset_write(file.path(spool, "outbound.ack"), 4)
  expect_identical(.exact_gc_outbound_compact(state, 4), 4)
  expect_identical(.exact_gc_offset_read(
    file.path(spool, "outbound.ack")), 4)
  expect_identical(.exact_gc_segment_retained_bytes(out_dir), 4)
  expect_identical(.exact_gc_segment_read(state, 4, 4), as.raw(15:18))
  expect_identical(.exact_gc_outbound_compact(state, 4), 4)
  expect_error(.exact_gc_outbound_compact(state, 3), "compaction offset")
})

test_that("segmented exact spool fails closed on capacity and content damage", {
  spool <- tempfile("exact-gc-segment-failure-")
  dir.create(spool, mode = "0700")
  on.exit(unlink(spool, recursive = TRUE), add = TRUE)
  out_dir <- file.path(spool, "outbound.segments")
  dir.create(out_dir, mode = "0700")
  state <- new.env(parent = emptyenv())
  state$spool <- spool
  state$chunk_bytes <- 8
  .exact_gc_private_file(file.path(spool, "outbound.head"), charToRaw("4"))
  .exact_gc_private_file(file.path(spool, "outbound.ack"), charToRaw("0"))

  # Once rename commits an inbound segment, the worker owns it and can consume
  # it before the publishing call returns. That successful hand-off must not be
  # mistaken for storage loss by a pathname re-open after publication.
  handoff_dir <- file.path(spool, "handoff.segments")
  dir.create(handoff_dir, mode = "0700")
  private_replace <- .exact_gc_private_replace
  expect_identical(testthat::with_mocked_bindings(
    .exact_gc_segment_publish(handoff_dir, 0, as.raw(1:4), 6),
    .exact_gc_private_replace = function(path, bytes) {
      private_replace(path, bytes)
      unlink(path)
      invisible(path)
    }, .package = "dsVert"), 4)
  expect_length(list.files(handoff_dir), 0L)

  .exact_gc_segment_publish(out_dir, 0, as.raw(1:4), 6)
  before <- list.files(out_dir)
  condition <- tryCatch({
    .exact_gc_segment_publish(out_dir, 4, as.raw(5:7), 6)
    NULL
  }, error = identity)
  expect_s3_class(condition, "dsvert_resource_backpressure")
  expect_identical(condition$code, "resource_backpressure")
  expect_true(condition$retryable)
  expect_identical(list.files(out_dir), before)

  oversize <- tryCatch({
    .exact_gc_segment_publish(out_dir, 4, as.raw(5:11), 6)
    NULL
  }, error = identity)
  expect_s3_class(oversize, "dsvert_resource_oversize")
  expect_identical(oversize$code, "resource_oversize")
  expect_false(oversize$retryable)
  expect_false(inherits(oversize, "dsvert_resource_backpressure"))
  expect_match(conditionMessage(oversize), "dsvert_resource_oversize", fixed = TRUE)

  # Persisting an absolute ACK releases the first immutable segment. The
  # previously backpressured suffix can then be retried unchanged.
  expect_identical(.exact_gc_outbound_compact(state, 4), 4)
  expect_silent(.exact_gc_segment_publish(out_dir, 4, as.raw(5:7), 6))
  .exact_gc_offset_write(file.path(spool, "outbound.head"), 7)
  segment <- .exact_gc_segment_list(out_dir)
  .exact_gc_private_file(segment$path[[1L]], as.raw(c(5, 6, 9)))
  expect_error(.exact_gc_segment_read(state, 4, 3), "hash mismatch")
  expect_identical(.exact_gc_offset_read(
    file.path(spool, "outbound.ack")), 4)
})

test_that("exact transport TTL is a progress lease, not an absolute lifetime", {
  spool <- tempfile("exact-gc-progress-lease-")
  dir.create(spool, mode = "0700")
  on.exit(unlink(spool, recursive = TRUE), add = TRUE)
  for (name in c("inbound.bin", "outbound.bin", "exchange.hb")) {
    .exact_gc_private_file(file.path(spool, name), raw(0))
  }
  for (name in c("inbound.segments", "outbound.segments")) {
    dir.create(file.path(spool, name), mode = "0700")
  }
  .exact_gc_private_file(
    file.path(spool, "inbound.state"), charToRaw(paste(
      .DSVERT_EXACT_GC_INBOUND_STATE_VERSION, "0", "-", "-", "-",
      sep = "|")))
  for (name in c("inbound.ack", "outbound.ack")) {
    .exact_gc_private_file(file.path(spool, name), charToRaw("0"))
  }
  .exact_gc_private_file(file.path(spool, "outbound.head"), charToRaw("1"))
  .exact_gc_segment_publish(
    file.path(spool, "outbound.segments"), 0, as.raw(0x42), 1024^2)
  session_id <- "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  operation_id <- "op_12121212121212121212121212121212"
  peer_id <- paste0("dsv1_", strrep("a", 64L))
  state <- new.env(parent = emptyenv())
  state$status <- "running"
  state$session_id <- session_id
  state$operation_id <- operation_id
  state$self_peer_id <- peer_id
  state$request_max_bytes <- 1024^2
  state$spool_max_bytes <- 1024^2
  state$chunk_bytes <- 64L
  state$spool <- spool
  state$process <- list(is_alive = function() TRUE)
  state$out_cache <- list(
    offset = 0,
    envelope = list(
      offset = 0, chunk_bytes = 1, marker = "cached",
      payload_hash = digest::digest(
        as.raw(0x42), algo = "sha256", serialize = FALSE)))
  state$outbound_ack_offset <- 0
  state$ttl_seconds <- 10
  state$last_activity <- 100
  state$started_at <- 100
  state$max_runtime_seconds <- 100
  state$relay_heartbeat_at <- 100
  state$worker_pid <- 123
  state$worker_heartbeat_session <- strrep("f", 64L)
  state$worker_heartbeat_key <- as.raw(seq_len(32L))
  state$worker_heartbeat_seen_at <- 100
  state$worker_heartbeat_counter <- 1
  state$source_key <- "exact_gc_in_12121212121212121212121212121212"
  state$output_key <- "exact_gc_out_12121212121212121212121212121212"
  ss <- new.env(parent = emptyenv())
  ss$.exact_gc_inputs <- list()
  ss$.exact_gc_inputs[[state$source_key]] <- list(
    claimed_by = operation_id, share = "private")
  ss$.exact_gc_outputs <- list()
  ss$.exact_gc_ops <- new.env(parent = emptyenv())
  ss$.exact_gc_ops[[operation_id]] <- state
  heartbeat_material <- paste(
    "dsvert-exact-gc-worker-heartbeat-v1",
    state$worker_heartbeat_session, "123", "1", sep = "|")
  heartbeat <- list(
    version = "dsvert-exact-gc-worker-heartbeat-v1",
    session_id = state$worker_heartbeat_session,
    pid = 123, counter = 1,
    mac = digest::hmac(
      state$worker_heartbeat_key, charToRaw(heartbeat_material),
      algo = "sha256", serialize = FALSE))
  .exact_gc_private_replace(file.path(spool, "worker.hb"), charToRaw(
    as.character(jsonlite::toJSON(heartbeat, auto_unbox = TRUE))))
  .exact_gc_outbound_offer_write(state, state$out_cache$envelope)
  clock <- 105

  testthat::with_mocked_bindings({
    duplicate <- .exact_gc_exchange_impl(
      ss, session_id, operation_id, peer_id, 0, long_poll = FALSE)
    expect_identical(duplicate$outbound$marker, "cached")
    expect_identical(state$last_activity, 100)
    expect_null(ss$.last_activity)

    clock <- 109
    acknowledged <- .exact_gc_exchange_impl(
      ss, session_id, operation_id, peer_id, 1, long_poll = FALSE)
    expect_null(acknowledged$outbound)
    expect_identical(state$outbound_ack_offset, 1)
    expect_identical(state$last_activity, 109)
    expect_identical(ss$.last_activity, 109)

    # Total elapsed time now exceeds the lease, but verified ACK progress at
    # t=109 keeps the operation live. The empty poll itself renews nothing.
    clock <- 118
    expect_silent(.exact_gc_exchange_impl(
      ss, session_id, operation_id, peer_id, 1, long_poll = FALSE))
    expect_identical(state$last_activity, 109)
    expect_identical(ss$.last_activity, 109)

    clock <- 120
    expect_error(.exact_gc_exchange_impl(
      ss, session_id, operation_id, peer_id, 1, long_poll = FALSE),
      "worker/progress lease")
  }, .exact_gc_now = function() clock, .package = "dsVert")
  expect_identical(state$status, "aborted")
  expect_false(dir.exists(spool))
  expect_null(ss$.exact_gc_inputs[[state$source_key]]$claimed_by)
})

test_that("worker heartbeats are bound to nonce, protocol session and PID", {
  spool <- tempfile("exact-gc-worker-heartbeat-")
  dir.create(spool, mode = "0700")
  on.exit(unlink(spool, recursive = TRUE), add = TRUE)
  state <- new.env(parent = emptyenv())
  state$spool <- spool
  state$worker_pid <- 321
  state$worker_heartbeat_session <- strrep("a", 64L)
  state$worker_heartbeat_key <- as.raw(seq_len(32L))
  state$worker_heartbeat_counter <- 1
  state$worker_heartbeat_seen_at <- 100
  ss <- new.env(parent = emptyenv())
  write_heartbeat <- function(counter, pid = 321,
                              session = state$worker_heartbeat_session,
                              key = state$worker_heartbeat_key) {
    version <- "dsvert-exact-gc-worker-heartbeat-v1"
    material <- paste(version, session, pid, counter, sep = "|")
    record <- list(
      version = version, session_id = session, pid = pid, counter = counter,
      mac = digest::hmac(
        key, charToRaw(material), algo = "sha256", serialize = FALSE))
    .exact_gc_private_replace(
      file.path(spool, "worker.hb"), charToRaw(as.character(
        jsonlite::toJSON(record, auto_unbox = TRUE))))
  }

  write_heartbeat(1)
  expect_false(.exact_gc_observe_worker_heartbeat(ss, state, 101))
  write_heartbeat(2)
  expect_true(.exact_gc_observe_worker_heartbeat(ss, state, 102))
  expect_identical(state$worker_heartbeat_counter, 2)
  expect_identical(ss$.last_activity, 102)

  write_heartbeat(3, pid = 322)
  expect_error(.exact_gc_observe_worker_heartbeat(ss, state, 103),
               "PID mismatch")
  write_heartbeat(3, session = strrep("b", 64L))
  expect_error(.exact_gc_observe_worker_heartbeat(ss, state, 103),
               "Unauthenticated")
  write_heartbeat(3, key = as.raw(rep(9L, 32L)))
  expect_error(.exact_gc_observe_worker_heartbeat(ss, state, 103),
               "Unauthenticated")
  write_heartbeat(1)
  expect_error(.exact_gc_observe_worker_heartbeat(ss, state, 103),
               "rolled back")
})

test_that("exact exchange accepts only one peer-bound scalar v3 route", {
  state <- new.env(parent = emptyenv())
  state$self_peer_id <- paste0("dsv1_", strrep("a", 64L))
  state$peer_id <- paste0("dsv1_", strrep("b", 64L))
  state$session_id <- "12345678-1234-4234-9234-123456789abc"
  state$operation_id <- "op_33333333333333333333333333333333"
  state$context_hash <- strrep("c", 64L)
  state$chunk_bytes <- 1024L
  state$request_max_bytes <- 1024^2
  expect_identical(.exact_gc_decode_route(
    state, state$self_peer_id, 7, 0, 0, "", "", "", TRUE),
                   list(read_offset = 7, delivery = NULL, long_poll = TRUE))
  expect_error(.exact_gc_decode_route(
    state, state$peer_id, 7, 0, 0, "", "", "", TRUE),
               "Invalid exact-gc route")
  expect_error(.exact_gc_decode_route(
    state, state$self_peer_id, 7, 0, 0, "", "", "", 1),
               "Invalid exact-gc route")
  expect_error(.exact_gc_decode_route(
    state, state$self_peer_id, 7, 0, 0, strrep("d", 64L), "", "", TRUE),
               "Invalid exact-gc route")
  expect_error(.exact_gc_decode_route(
    state, state$self_peer_id, 7, "0", 0, "", "", "", TRUE),
               "Invalid exact-gc route")
  expect_error(.exact_gc_decode_route(
    state, state$self_peer_id, 7, 0.5, 1, strrep("d", 64L), "AQ", "AA",
    TRUE), "Invalid exact-gc envelope offset")
  expect_error(.exact_gc_decode_route(
    state, state$self_peer_id, 7, 0, 1, "not-a-hash", "AQ", "AA", TRUE),
    "Invalid exact-gc route")

  expected <- list(
    version = .DSVERT_EXACT_GC_ENVELOPE_VERSION,
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    session_id = state$session_id,
    operation_id = state$operation_id,
    context_hash = state$context_hash,
    sender_peer_id = state$peer_id,
    recipient_peer_id = state$self_peer_id,
    offset = 11,
    chunk_bytes = 1,
    payload_hash = strrep("d", 64L),
    payload = "AQ",
    signature = "AA")
  route <- .exact_gc_decode_route(
    state, state$self_peer_id, 7, expected$offset, expected$chunk_bytes,
    expected$payload_hash, expected$payload, expected$signature, FALSE)
  expect_identical(route, list(
    read_offset = 7, delivery = expected, long_poll = FALSE))
})

test_that("scalar exact route removes the redundant outer base64 layer", {
  payload <- paste(rep("A", 4 * ceiling(1024^2 / 3)), collapse = "")
  envelope <- list(
    version = "dsvert-exact-gc-envelope-v1",
    capability_id = "exact_gc_v1",
    session_id = "12345678-1234-4234-9234-123456789abc",
    operation_id = "op_33333333333333333333333333333333",
    context_hash = strrep("c", 64L),
    sender_peer_id = paste0("dsv1_", strrep("a", 64L)),
    recipient_peer_id = paste0("dsv1_", strrep("b", 64L)),
    offset = 0, chunk_bytes = 1024^2,
    payload_hash = strrep("d", 64L), payload = payload,
    signature = strrep("A", 86L))
  delivery_json <- as.character(jsonlite::toJSON(
    envelope, auto_unbox = TRUE, null = "null", digits = NA))
  legacy_route <- list(
    version = "dsvert-exact-gc-route-v2", peer_id = paste0(
      "dsv1_", strrep("a", 64L)), read_offset = 0, delivery = envelope)
  legacy_double_encoded <- .exact_gc_b64url_encode(charToRaw(as.character(
    jsonlite::toJSON(legacy_route, auto_unbox = TRUE, null = "null",
                     digits = NA))))
  direct <- .exact_gc_test_delivery_fields(envelope)
  expect_equal(
    jsonlite::fromJSON(delivery_json, simplifyVector = FALSE), envelope)
  expect_identical(direct$delivery_payload, payload)
  direct_bytes <- sum(nchar(unlist(direct[c(
    "delivery_payload_hash", "delivery_payload", "delivery_signature")],
    use.names = FALSE), type = "bytes")) + 32L
  expect_lt(direct_bytes, nchar(delivery_json, type = "bytes"))
  expect_lt(direct_bytes, 0.8 * nchar(
    legacy_double_encoded, type = "bytes"))
})

test_that("the default exact chunk fits the portable DSLite scalar limit", {
  previous <- options(
    dsvert.exact_gc.chunk_bytes = NULL,
    default.dsvert.exact_gc.chunk_bytes = NULL)
  on.exit(options(previous), add = TRUE)
  chunk_bytes <- .exact_gc_chunk_bytes()
  expect_identical(chunk_bytes, 480L * 1024L)
  # One raw chunk is base64url encoded once as its direct scalar argument.
  # DSLite 1.8 accepts 786,432-character strings but not 1,048,576; leave
  # margin for the authenticated envelope and JSON metadata.
  encoded_payload <- 4 * ceiling(chunk_bytes / 3)
  expect_lt(encoded_payload + 16384, 768L * 1024L)
  envelope <- list(
    version = "dsvert-exact-gc-envelope-v1",
    capability_id = "exact_gc_v1",
    session_id = paste0(rep("a", 64L), collapse = ""),
    operation_id = paste0("op_", paste0(rep("b", 32L), collapse = "")),
    context_hash = paste0(rep("c", 64L), collapse = ""),
    sender_peer_id = paste0("dsv1_", paste0(rep("d", 64L), collapse = "")),
    recipient_peer_id = paste0("dsv1_", paste0(rep("e", 64L), collapse = "")),
    offset = 2^53 - 1, chunk_bytes = chunk_bytes,
    payload_hash = paste0(rep("f", 64L), collapse = ""),
    payload = paste0(rep("A", encoded_payload), collapse = ""),
    signature = paste0(rep("A", 86L), collapse = ""))
  fields <- .exact_gc_test_delivery_fields(envelope)
  expression <- as.call(c(list(
    as.name("exactGCExchangeDS"), session_id = envelope$session_id,
    operation_id = envelope$operation_id,
    peer_id = envelope$recipient_peer_id, read_offset = 2^53 - 1),
    fields, list(long_poll = TRUE)))
  rendered <- paste(deparse(expression, width.cutoff = 500L), collapse = "\n")
  expect_false(grepl("\\\\\"", rendered))
  expect_lt(nchar(rendered, type = "bytes"), 768L * 1024L)
})

test_that("fixed exact coalescing preserves fragments, hashes and terminal progress", {
  path <- tempfile("exact-gc-coalesce-")
  .exact_gc_private_file(path, as.raw(1:2))
  on.exit(unlink(path), add = TRUE)
  state <- new.env(parent = emptyenv())
  state$status <- "complete"
  state$chunk_bytes <- 4
  expect_identical(.exact_gc_read_coalesced(state, path, 0), as.raw(1:2))
  .exact_gc_append_at(path, 2, as.raw(3:5), 100)
  first <- .exact_gc_read_coalesced(state, path, 0)
  last <- .exact_gc_read_coalesced(state, path, 4)
  expect_identical(first, as.raw(1:4))
  expect_identical(last, as.raw(5))
  expect_identical(
    digest::digest(c(first, last), algo = "sha256", serialize = FALSE),
    digest::digest(as.raw(1:5), algo = "sha256", serialize = FALSE))

  empty <- tempfile("exact-gc-coalesce-empty-")
  .exact_gc_private_file(empty, raw(0))
  on.exit(unlink(empty), add = TRUE)
  state$status <- "running"
  immediate_started <- proc.time()[["elapsed"]]
  expect_length(.exact_gc_read_coalesced(
    state, empty, 0, long_poll = FALSE), 0L)
  expect_lt(proc.time()[["elapsed"]] - immediate_started, 0.1)
  started <- proc.time()[["elapsed"]]
  expect_length(.exact_gc_read_coalesced(state, empty, 0), 0L)
  expect_gte(proc.time()[["elapsed"]] - started,
             .DSVERT_EXACT_GC_COALESCE_SECONDS * 0.8)
  expect_lt(proc.time()[["elapsed"]] - started, 0.5)
  state$status <- "complete"
  expect_length(.exact_gc_read_coalesced(state, empty, 0), 0L)

  # The wait topology is machine-checkably public: only worker status, public
  # file size/chunk geometry, the route hint and fixed package constants occur.
  coalesce_code <- paste(deparse(body(.exact_gc_read_coalesced)), collapse = " ")
  expect_false(grepl("share|secret|source_key|input", coalesce_code,
                     ignore.case = TRUE))
  expect_match(coalesce_code,
               "deadline <- started \\+ \\.DSVERT_EXACT_GC_COALESCE_SECONDS")
})

test_that("typed worker failure is fail-closed and retry keeps the logical id", {
  spool <- tempfile("exact-gc-typed-failure-")
  dir.create(spool, mode = "0700")
  on.exit(unlink(spool, recursive = TRUE), add = TRUE)
  Sys.chmod(spool, mode = "0700")
  operation_id <- "op_45454545454545454545454545454545"
  source_key <- "exact_gc_in_45454545454545454545454545454545"
  output_key <- "exact_gc_out_45454545454545454545454545454545"
  context_hash <- strrep("a", 64L)
  state <- new.env(parent = emptyenv())
  state$status <- "running"
  state$session_id <- "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  state$operation_id <- operation_id
  state$attempt <- 1L
  state$spool <- spool
  state$operation <- "truncate-floor"
  state$ring_bits <- 127L
  state$context_hash <- context_hash
  state$source_key <- source_key
  state$output_key <- output_key
  state$out_cache <- list(stale = TRUE)
  state$process <- list(is_alive = function() TRUE)
  failure <- list(
    version = .DSVERT_EXACT_GC_FAILURE_VERSION,
    code = "numeric_backend_unavailable", retryable = TRUE,
    retry_contract = .DSVERT_EXACT_GC_RETRY_CONTRACT,
    operation = state$operation, ring_bits = state$ring_bits,
    context_hash = context_hash)
  .exact_gc_private_file(file.path(spool, "failure.json"), charToRaw(
    as.character(jsonlite::toJSON(failure, auto_unbox = TRUE))))
  .exact_gc_private_file(file.path(spool, "error"), charToRaw("1"))
  .exact_gc_private_file(file.path(spool, "result.json"), charToRaw("stale"))
  .exact_gc_private_file(file.path(spool, "done"), charToRaw("1"))
  ss <- new.env(parent = emptyenv())
  ss$.exact_gc_inputs <- list()
  ss$.exact_gc_inputs[[source_key]] <- list(
    share = "private", claimed_by = operation_id)
  ss$.exact_gc_outputs <- list()
  ss$.exact_gc_outputs[[output_key]] <- list(share = "stale")
  ss$.exact_gc_ops <- new.env(parent = emptyenv())
  ss$.exact_gc_ops[[operation_id]] <- state

  expect_identical(.exact_gc_refresh(ss, state), "failed")
  expect_identical(state$failure_code, "numeric_backend_unavailable")
  expect_true(state$retryable)
  expect_null(state$out_cache)
  expect_null(ss$.exact_gc_outputs[[output_key]])
  expect_null(ss$.exact_gc_inputs[[source_key]]$claimed_by)
  expect_false(file.exists(file.path(spool, "result.json")))
  expect_false(file.exists(file.path(spool, "done")))
  public <- .exact_gc_public_liveness(state)
  expect_identical(public$failure_code, "numeric_backend_unavailable")
  expect_true(public$retryable)
  expect_identical(public$retry_contract,
                   .DSVERT_EXACT_GC_RETRY_CONTRACT)
  expect_false(any(c("share", "message", "detail") %in% names(public)))

  binding <- strrep("a", 64L)
  first <- .exact_gc_protocol_session(
    state$session_id, operation_id, 1L,
    peer_binding_digest = binding)
  retry <- .exact_gc_protocol_session(
    state$session_id, operation_id, 2L,
    peer_binding_digest = binding)
  expect_false(identical(first, retry))
  expect_identical(retry, .exact_gc_protocol_session(
    state$session_id, operation_id, 2L,
    peer_binding_digest = binding))
  expect_false(identical(first, .exact_gc_protocol_session(
    state$session_id, operation_id, 1L,
    peer_binding_digest = strrep("b", 64L))))
  expect_error(.exact_gc_protocol_session(
    state$session_id, operation_id, 1L,
    peer_binding_digest = "relay-selected"),
    "authenticated peer binding")
  .exact_gc_reset_retryable_state(ss, state)
  expect_false(dir.exists(spool))
  expect_null(ss$.exact_gc_ops[[operation_id]])
  expect_null(ss$.exact_gc_inputs[[source_key]]$claimed_by)
})

test_that("exact-specific transport binds exactly two signed pinned peers", {
  binary <- .exact_gc_test_binary()
  old <- options(
    dsvert.mpc_binary = binary,
    dsvert.identity_seed = getOption("dsvert.identity_seed"),
    dsvert.peer_name = getOption("dsvert.peer_name"),
    dsvert.trusted_peers = getOption("dsvert.trusted_peers"))
  on.exit(options(old), add = TRUE)
  on.exit(.exact_gc_test_binary_cleanup(binary), add = TRUE)
  session_id <- "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
  ss_a <- new.env(parent = emptyenv())
  ss_b <- new.env(parent = emptyenv())
  ss_a$.session_id <- paste0(session_id, "_handshake_a_", Sys.getpid())
  ss_b$.session_id <- paste0(session_id, "_handshake_b_", Sys.getpid())
  seed_a <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(61L, 32L))))
  seed_b <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(73L, 32L))))
  init_a <- .exact_gc_test_server_call(
    ss_a, seed_a, exactGCTransportInitDS, session_id = session_id)
  init_b <- .exact_gc_test_server_call(
    ss_b, seed_b, exactGCTransportInitDS, session_id = session_id)
  expect_false(any(grepl("secret|private", c(names(init_a), names(init_b)),
                         ignore.case = TRUE)))
  transport <- list(site_a = init_a$transport_pk, site_b = init_b$transport_pk)
  identities <- list(
    site_a = list(identity_pk = init_a$identity_pk,
                  signature = init_a$signature),
    site_b = list(identity_pk = init_b$identity_pk,
                  signature = init_b$signature))
  encode <- function(value) .exact_gc_b64url_encode(charToRaw(as.character(
    jsonlite::toJSON(value, auto_unbox = TRUE, null = "null"))))
  transport_b64 <- encode(transport)
  identities_b64 <- encode(identities)
  pinset <- c(
    site_a = .base64url_to_base64(init_a$identity_pk),
    site_b = .base64url_to_base64(init_b$identity_pk))
  normalized_pinset <- vapply(
    pinset, .dsvert_relay_normalize_identity_pk, character(1L))
  pinset_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(normalized_pinset)),
    algo = "sha256", serialize = FALSE)
  policy_for <- function(peer_name) list(
    domain = "exact-gc-k2-binding-test",
    cohort_id = "exact-gc-k2-cohort",
    peer_name = peer_name,
    peer_pinset = pinset,
    peer_pinset_sha256 = pinset_hash,
    peer_count = 2L,
    designated_noise_peers = c("site_a", "site_b"),
    global_total_epsilon = 1,
    global_total_delta = 0,
    lifetime_max_distinct_capsules = 8,
    adjacency = "add_remove_patient",
    patient_column = "patient_id",
    unit_capacity = 1000L,
    max_records_per_unit = 100L,
    overflow_policy = "reject_snapshot",
    noise_root = list(epoch = 1, key_id = "test-noise-root"),
    ledger_path = tempfile("exact-gc-k2-binding-ledger-"))
  testthat::local_mocked_bindings(
    .dsvert_dp_policy = function() policy_for(
      getOption("dsvert.peer_name")),
    .package = "dsVert")
  options(dsvert.peer_name = "site_a", dsvert.trusted_peers = c(
    site_b = .base64url_to_base64(init_b$identity_pk)))
  bound_a <- .exact_gc_test_server_call(
    ss_a, seed_a, exactGCBindPeersDS,
    transport_keys_b64 = transport_b64,
    identity_info_b64 = identities_b64, session_id = session_id)
  options(dsvert.peer_name = "site_b", dsvert.trusted_peers = c(
    site_a = .base64url_to_base64(init_a$identity_pk)))
  bound_b <- .exact_gc_test_server_call(
    ss_b, seed_b, exactGCBindPeersDS,
    transport_keys_b64 = transport_b64,
    identity_info_b64 = identities_b64, session_id = session_id)
  expect_true(bound_a$bound)
  expect_true(bound_b$bound)
  expect_identical(names(ss_a$peer_transport_pks), "site_b")
  expect_identical(names(ss_b$peer_transport_pks), "site_a")
  options(dsvert.peer_name = "site_a", dsvert.trusted_peers = c(
    site_b = .base64url_to_base64(init_b$identity_pk)))
  expect_true(.exact_gc_test_server_call(
    ss_a, seed_a, exactGCBindPeersDS,
    transport_keys_b64 = transport_b64,
    identity_info_b64 = identities_b64, session_id = session_id)$bound)
  reversed_transport <- encode(transport[c("site_b", "site_a")])
  reversed_identities <- encode(identities[c("site_b", "site_a")])
  expect_true(.exact_gc_test_server_call(
    ss_a, seed_a, exactGCBindPeersDS,
    transport_keys_b64 = reversed_transport,
    identity_info_b64 = reversed_identities,
    session_id = session_id)$bound)

  analysis_session <- "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
  analysis_a <- new.env(parent = emptyenv())
  analysis_b <- new.env(parent = emptyenv())
  analysis_a$.session_id <- paste0(
    analysis_session, "_handshake_a_", Sys.getpid())
  analysis_b$.session_id <- paste0(
    analysis_session, "_handshake_b_", Sys.getpid())
  analysis_init_a <- .exact_gc_test_server_call(
    analysis_a, seed_a, exactGCTransportInitDS,
    session_id = analysis_session)
  analysis_init_b <- .exact_gc_test_server_call(
    analysis_b, seed_b, exactGCTransportInitDS,
    session_id = analysis_session)
  analysis_transport <- list(
    site_a = analysis_init_a$transport_pk,
    site_b = analysis_init_b$transport_pk)
  analysis_identities <- list(
    site_a = list(
      identity_pk = analysis_init_a$identity_pk,
      signature = analysis_init_a$signature),
    site_b = list(
      identity_pk = analysis_init_b$identity_pk,
      signature = analysis_init_b$signature))
  analysis_pins <- c(
    site_a = analysis_init_a$identity_pk,
    site_b = analysis_init_b$identity_pk)
  analysis_fixture <- .exact_gc_analysis_test_fixture(
    pins = analysis_pins)
  analysis_contract <- analysis_fixture$contract
  analysis_binding <- .exact_gc_analysis_contract_binding(analysis_contract)
  expect_error(.exact_gc_test_server_call(
    analysis_a, seed_a, exactGCBindPeersDS,
    transport_keys_b64 = encode(analysis_transport),
    identity_info_b64 = encode(analysis_identities),
    session_id = analysis_session,
    artifact_key = analysis_contract$artifact_key), "authorization")
  authorize_analysis <- function(ss, seed) testthat::with_mocked_bindings(
    withr::with_options(
      list(dsvert.identity_seed = seed),
      .dsvert_dp_count_authorize_session_v1(
        ss, analysis_session, analysis_fixture$config,
        analysis_fixture$receipts,
        .verifier = .exact_gc_analysis_test_verifier,
        .planner = .dsvert_joint_dp_laplace_plan_v2)),
    .dsvert_dp_policy = function(...) stop("policy must not be called"),
    .package = "dsVert")
  authorization_a <- authorize_analysis(analysis_a, seed_a)
  authorization_b <- authorize_analysis(analysis_b, seed_b)
  expect_false("analysis_contract_b64" %in%
                 names(formals(exactGCBindPeersDS)))
  expect_error(testthat::with_mocked_bindings(
    .exact_gc_test_server_call(
      analysis_a, seed_a, exactGCBindPeersDS,
      transport_keys_b64 = encode(analysis_transport),
      identity_info_b64 = encode(analysis_identities),
      session_id = analysis_session),
    .dsvert_dp_policy = function(...) stop("policy must not be called"),
    .package = "dsVert"), "requires its analysis artifact key")
  expect_error(.exact_gc_test_server_call(
    analysis_a, seed_a, exactGCBindPeersDS,
    transport_keys_b64 = encode(analysis_transport),
    identity_info_b64 = encode(analysis_identities),
    session_id = analysis_session, artifact_key = strrep("0", 64L)),
    "authorization")
  expect_error(do.call(exactGCBindPeersDS, list(
    transport_keys_b64 = encode(analysis_transport),
    identity_info_b64 = encode(analysis_identities),
    session_id = analysis_session,
    analysis_contract_b64 = "raw-contract")), "unused argument")
  bind_analysis <- function(ss, seed, peer_name) withr::with_options(
    list(dsvert.peer_name = peer_name), testthat::with_mocked_bindings(
      .exact_gc_test_server_call(
        ss, seed, exactGCBindPeersDS,
        transport_keys_b64 = encode(analysis_transport),
        identity_info_b64 = encode(analysis_identities),
        session_id = analysis_session,
        artifact_key = analysis_contract$artifact_key),
      .dsvert_dp_policy = function(...) stop("policy must not be called"),
      .package = "dsVert"))
  analysis_bound_a <- bind_analysis(analysis_a, seed_a, "site_a")
  analysis_bound_b <- bind_analysis(analysis_b, seed_b, "site_b")
  expect_identical(
    analysis_bound_a$analysis_binding, analysis_binding$binding)
  expect_identical(
    analysis_bound_b$analysis_binding_sha256, analysis_binding$sha256)
  expect_identical(
    analysis_a$.exact_gc_peer_binding_digest,
    analysis_b$.exact_gc_peer_binding_digest)
  expect_identical(length(
    analysis_a$.exact_gc_analysis_contract$execution$peer_pins), 2L)
  expect_true(bind_analysis(analysis_a, seed_a, "site_a")$bound)
  static <- authorization_a$worker_static
  seed_commitment <- function(context, seed) {
    .dsvert_joint_dp_backend_hash_raw_v2(c(
      .dsvert_joint_dp_backend_hex_raw_v2(context, "test context"),
      jsonlite::base64_dec(seed)))
  }
  garbler_seed <- if (identical(
    authorization_a$local_authority$role, "garbler")) seed_a else seed_b
  evaluator_seed <- if (identical(
    authorization_a$local_authority$role, "evaluator")) seed_a else seed_b
  worker <- .callMpcTool(
    "joint-dp-laplace-worker-contract-v2", list(
      version = .DSVERT_JOINT_DP_COUNT_WORKER_CONTRACT_INPUT,
      ring_bits = static$ring_bits, frac_bits = static$frac_bits,
      coordinate_count = static$coordinate_count,
      epsilon = static$epsilon, allocated_delta = static$allocated_delta,
      sensitivity_steps = static$sensitivity_steps,
      encoded_lower = static$encoded_lower,
      encoded_upper = static$encoded_upper,
      bernoulli_bits = static$bernoulli_bits, max_steps = 4096L,
      transcript_hash = static$transcript_hash,
      garbler_commitment_context = static$garbler_commitment_context,
      evaluator_commitment_context = static$evaluator_commitment_context,
      garbler_seed_commitment = seed_commitment(
        static$garbler_commitment_context, garbler_seed),
      evaluator_seed_commitment = seed_commitment(
        static$evaluator_commitment_context, evaluator_seed)))
  validate_worker <- function(policy = worker$worker_policy,
                              ring = 127L, frac_bits = 0L,
                              vector_len = 1L,
                              purpose = worker$purpose) {
    withr::with_options(
      list(dsvert.identity_seed = seed_a),
      .exact_gc_analysis_count_worker_validate_v1(
        analysis_a, analysis_session, policy, ring, frac_bits,
        vector_len, purpose))
  }
  expect_identical(validate_worker()$artifact_key,
                   analysis_contract$artifact_key)
  mutations <- list(
    version = "other-template", sampler = "other-sampler",
    bernoulli_bits = 16L, epsilon = "2", allocated_delta = "1e-6",
    sensitivity_steps = "2", encoded_lower = "-1",
    encoded_upper = "1001", stop_numerator = "1",
    max_geometric_steps = 1L,
    implementation_delta_numerator = "2",
    implementation_delta_denominator = "3",
    transcript_hash = strrep("1", 64L),
    garbler_commitment_context = strrep("2", 64L),
    evaluator_commitment_context = strrep("3", 64L),
    garbler_seed_commitment = strrep("4", 64L))
  for (field in names(mutations)) {
    changed <- worker$worker_policy
    changed[[field]] <- mutations[[field]]
    expect_error(validate_worker(changed), "analysis-bound.*Count")
  }
  changed_circuit <- worker$worker_policy
  changed_circuit$circuit_digest <- strrep("f", 64L)
  expect_error(validate_worker(
    changed_circuit,
    purpose = paste0("joint-dp-laplace-v2/", strrep("f", 64L))),
    "analysis-bound.*Count")
  expect_error(validate_worker(ring = 128L), "analysis-bound.*Count")

  analysis_operation <- "op_99999999999999999999999999999999"
  analysis_source <- "exact_gc_in_99999999999999999999999999999999"
  analysis_output <- "exact_gc_out_99999999999999999999999999999999"
  .exact_gc_stage_share(
    analysis_a, analysis_source,
    .exact_gc_test_b64_records(7, 16L), 127L, 1L,
    "count.scalar.v1", "joint-dp-laplace-v2", worker$purpose,
    0L, "joint-dp-ring-share-v2")
  initialized <- testthat::with_mocked_bindings(
    withr::with_options(
      list(dsvert.identity_seed = seed_a), .exact_gc_init_impl(
        analysis_a, analysis_session, analysis_operation,
        .DSVERT_EXACT_GC_CAPABILITY, analysis_source, analysis_output,
        "joint-dp-laplace-v2", 127L, 0L, 1L, worker$purpose,
        joint_dp = worker$worker_policy, private_seed = seed_a,
        binary = binary)),
    .dsvert_dp_policy = function(...) stop("policy must not be called"),
    .package = "dsVert")
  expect_identical(initialized$operation, "joint-dp-laplace-v2")
  expect_identical(initialized$analysis_binding_sha256,
                   authorization_a$analysis_binding_sha256)
  .exact_gc_abort_all(analysis_a)

  .session_dir_cleanup(ss_a)
  .session_dir_cleanup(ss_b)
  .session_dir_cleanup(analysis_a)
  .session_dir_cleanup(analysis_b)
})

test_that("analysis-bound Count binding is K-generic and execution-free", {
  bindings <- lapply(c(2L, 3L, 5L), function(k) {
    .exact_gc_analysis_contract_binding(
      .exact_gc_analysis_test_contract(k))
  })
  expect_true(all(vapply(bindings, function(value) {
    identical(value$binding$artifact_key, value$contract$artifact_key) &&
      identical(length(value$contract$execution$peer_pins),
                length(value$contract$semantic$owner_snapshots)) &&
      identical(sort(unname(unlist(value$binding$authority_roles)),
                       method = "radix"),
                sort(unlist(
                  value$contract$semantic$noise_authorities),
                  method = "radix"))
  }, logical(1L))))

  binding <- bindings[[2L]]
  expect_identical(
    binding$sha256,
    "7290f74d0d3160c5f64183ec3a6f7474471267dcf7a9c47449b68d6ffed64083")
  binding_json <- .dsvert_dp_canonical_json(binding$binding)
  expect_false(any(vapply(c(
    "session", "operation", "transport", "build_sha256", "ring",
    "chunk_coordinates"), grepl, logical(1L), x = binding_json,
    fixed = TRUE)))

  changed_execution <- binding$contract
  changed_execution$execution$backend$build_sha256 <- strrep("b", 64L)
  changed_execution$execution$transport$chunk_coordinates <- 8192
  expect_identical(
    .exact_gc_analysis_contract_binding(changed_execution)$binding,
    binding$binding)

  pins <- unlist(binding$contract$execution$peer_pins, use.names = TRUE)
  authorities <- unlist(
    binding$contract$semantic$noise_authorities, use.names = FALSE)
  authority_names <- names(pins)[match(authorities, unname(pins))]
  identity_info <- stats::setNames(lapply(authority_names, function(name) {
    list(identity_pk = unname(pins[[name]]), signature = "opaque")
  }), authority_names)
  context <- testthat::with_mocked_bindings(
    .exact_gc_analysis_policy_context(
      binding, identity_info, pins[[authority_names[[1L]]]]),
    .dsvert_dp_policy = function(...) stop("policy must not be called"),
    .package = "dsVert")
  expect_identical(context$designated, sort(authority_names, method = "radix"))
  expect_identical(length(context$full_pins), 3L)

  verified <- list(
    identity_pks = context$pins[context$designated],
    transport_pks = stats::setNames(
      as.list(vapply(seq_along(context$designated), function(index) {
        .exact_gc_analysis_test_identity_pk(index + 10L)
      }, character(1L))), context$designated))
  first <- .exact_gc_analysis_peer_binding_digest(
    "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    binding, context, verified)
  second <- .exact_gc_analysis_peer_binding_digest(
    "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
    binding, context, verified)
  expect_false(identical(first$sha256, second$sha256))
  expect_identical(first$contract$analysis_binding, binding$binding)
  expect_identical(
    first$contract$analysis_binding_sha256, binding$sha256)

  substituted <- identity_info
  substituted[[1L]]$identity_pk <- unname(
    pins[[setdiff(names(pins), authority_names)[[1L]]]])
  expect_error(.exact_gc_analysis_policy_context(
    binding, substituted, pins[[authority_names[[1L]]]]),
    "noise authorities")
  relabelled <- identity_info
  names(relabelled)[[1L]] <- setdiff(names(pins), authority_names)[[1L]]
  expect_error(.exact_gc_analysis_policy_context(
    binding, relabelled, pins[[authority_names[[1L]]]]),
    "peer name|pin")
})

test_that("Frequency binding is K-generic and rejects role or pin substitution", {
  for (k in c(2L, 3L, 5L)) {
    fixture <- .exact_gc_frequency_test_fixture(k)
    binding <- .exact_gc_frequency_contract_binding(
      fixture$authorization, fixture$public)
    expect_identical(length(binding$full_pins), k)
    expect_identical(binding$authority_names,
                     unname(fixture$role_peers[names(fixture$roles)]))
    expect_identical(binding$binding$authority_roles,
                     .dsvert_dp_analysis_canonical_value_v1(fixture$roles))
    expect_identical(binding$binding$release_contract_hash, strrep("9", 64L))
    wire <- .dsvert_dp_canonical_json(binding$binding)
    expect_false(any(vapply(c(
      "garbler", "evaluator", "ring127", "capsule", "final-share",
      "operation", "histogram", "noised_share", "preclamp"), grepl,
      logical(1L), x = wire, fixed = TRUE)))

    swapped <- fixture$authorization
    swapped$analysis_binding$authority_roles <-
      rev(swapped$analysis_binding$authority_roles)
    swapped$worker_static$authority_roles <-
      swapped$analysis_binding$authority_roles
    expect_error(.exact_gc_frequency_contract_binding(swapped, fixture$public),
                 "Frequency")

    relabelled <- fixture$authorization
    relabelled$config$peer_pins <- relabelled$config$peer_pins[c(
      seq.int(2L, length(fixture$pins)), 1L)]
    names(relabelled$config$peer_pins) <- names(fixture$pins)
    expect_error(.exact_gc_frequency_contract_binding(
      relabelled, fixture$public), "Frequency")

    wrong_public <- fixture$public
    wrong_public$local_authority$peer_name <- fixture$peers[[
      if (identical(fixture$authorization$local_authority$peer_name,
                    fixture$peers[[1L]])) 2L else 1L]]
    expect_error(.exact_gc_frequency_contract_binding(
      fixture$authorization, wrong_public), "Frequency")
  }
})

test_that("Frequency init, bind and cleanup use only resident authorization", {
  session_id <- "00000000-0000-4000-8000-000000000001"
  source_fixture <- .exact_gc_frequency_test_fixture(
    3L, "source_owner")
  secondary_fixture <- .exact_gc_frequency_test_fixture(
    3L, "secondary_noise_authority")
  designated <- unname(source_fixture$role_peers)
  transports <- stats::setNames(lapply(c(20L, 21L), function(byte) {
    .dsvert_relay_b64url_encode(as.raw(rep(byte, 32L)))
  }), designated)
  identities <- stats::setNames(lapply(designated, function(peer) list(
    identity_pk = unname(source_fixture$pins[[peer]]),
    signature = .dsvert_relay_b64url_encode(raw(64L)))), designated)
  encode <- function(value) .exact_gc_b64url_encode(charToRaw(as.character(
    jsonlite::toJSON(value, auto_unbox = TRUE, null = "null"))))
  transport_map <- encode(as.list(transports))
  identity_map <- encode(identities)
  signature <- .base64url_to_base64(
    .dsvert_relay_b64url_encode(raw(64L)))

  make_state <- function(fixture) {
    ss <- new.env(parent = emptyenv())
    local <- fixture$authorization$local_authority$peer_name
    ss$.dp_frequency_authorization <- fixture$authorization
    ss$.dp_frequency_public_authorization <- fixture$public
    ss$keys <- list(
      transport_sk = .base64url_to_base64(transports[[local]]),
      transport_pk = .base64url_to_base64(transports[[local]]),
      identity_pk = .base64url_to_base64(fixture$pins[[local]]))
    ss
  }
  source <- make_state(source_fixture)
  secondary <- make_state(secondary_fixture)

  call_as <- function(ss, expression) {
    peer <- ss$.dp_frequency_authorization$local_authority$peer_name
    withr::with_options(list(dsvert.peer_name = peer),
      testthat::with_mocked_bindings(
        expression(),
        .S = function(id) ss,
        .dsvert_dp_frequency_session_authorization_validate_v1 =
          function(state, id, artifact_key = NULL) {
            expect_identical(state, ss)
            expect_identical(id, session_id)
            state$.dp_frequency_authorization
          },
        .dsvert_dp_frequency_public_authorization_validate_v1 =
          function(value, state, ...) value,
        .get_identity_keypair = function() list(
          identity_pk = .key_get("identity_pk", ss), identity_sk = "test"),
        .sign_transport_pk = function(...) signature,
        .verify_peer_identity = function(...) TRUE,
        .dsvert_relay_sign_message = function(...) {
          .dsvert_relay_b64url_encode(raw(64L))
        },
        .dsvert_relay_verify_message = function(...) TRUE,
        .dsvert_dp_policy = function(...) stop("policy must not be called"),
        .package = "dsVert"))
  }
  bind <- function(ss) call_as(ss, function() exactGCBindPeersDS(
    transport_keys_b64 = transport_map,
    identity_info_b64 = identity_map, session_id = session_id))

  expect_identical(call_as(source, function() exactGCTransportInitDS(
    session_id))$capability_id, .DSVERT_EXACT_GC_CAPABILITY)
  expect_identical(call_as(secondary, function() exactGCTransportInitDS(
    session_id))$capability_id, .DSVERT_EXACT_GC_CAPABILITY)
  bound_source <- bind(source)
  bound_secondary <- bind(secondary)
  expect_true(bound_source$bound)
  expect_identical(bound_source$frequency_binding,
                   bound_secondary$frequency_binding)
  expect_identical(source$.exact_gc_peer_binding_digest,
                   secondary$.exact_gc_peer_binding_digest)
  expect_identical(bound_source$cleanup_purpose,
                   .DSVERT_EXACT_GC_FREQUENCY_CLEANUP_PURPOSE)
  expect_match(bound_source$cleanup_capability_json, "cleanup_purpose")
  expect_null(source$.exact_gc_analysis_binding)
  expect_true(bind(source)$bound)
  expect_error(call_as(source, function() exactGCBindPeersDS(
    transport_keys_b64 = transport_map,
    identity_info_b64 = identity_map, session_id = session_id,
    artifact_key = source_fixture$authorization$artifact_key)),
    "Frequency.*artifact")

  inputs_exist <- exists(".exact_gc_inputs", envir = source, inherits = FALSE)
  inputs <- if (inputs_exist) source$.exact_gc_inputs else NULL
  if (inputs_exist) rm(".exact_gc_inputs", envir = source)
  makeActiveBinding(".exact_gc_inputs", function(value) {
    stop("source lookup reached", call. = FALSE)
  }, source)
  expect_error(call_as(source, function() .exact_gc_init_impl(
    source, session_id, "op_ffffffffffffffffffffffffffffffff",
    .DSVERT_EXACT_GC_CAPABILITY,
    "exact_gc_in_ffffffffffffffffffffffffffffffff",
    "exact_gc_out_ffffffffffffffffffffffffffffffff",
    "compare-signed", 127L, 0L, 1L, "frequency.transport-only",
    threshold = "0")), "Frequency.*exact-gc worker")
  rm(".exact_gc_inputs", envir = source)
  if (inputs_exist) source$.exact_gc_inputs <- inputs

  storage <- new.env(parent = emptyenv())
  storage[[session_id]] <- source
  cleaned <- call_as(source, function() testthat::with_mocked_bindings(
    exactGCCleanupDS(session_id, .dsvert_dsi_text_encode(
      bound_source$cleanup_capability_json)),
    .session_storage = function() storage,
    .cleanup_session = function(id) storage[[id]] <- NULL,
    .package = "dsVert"))
  expect_identical(cleaned$state, "cleaned")
  expect_identical(cleaned$cleanup_purpose,
                   .DSVERT_EXACT_GC_FREQUENCY_CLEANUP_PURPOSE)
  expect_null(storage[[session_id]])
})

test_that("dynamic residue records reject non-zero unused high bits", {
  noncanonical <- raw(16L)
  noncanonical[[9L]] <- as.raw(2L)
  encoded <- gsub("[\r\n]", "", jsonlite::base64_enc(noncanonical))
  expect_error(.exact_gc_validate_residue_records(
    encoded, 65L, 1L, "test source"), "Non-canonical")
  noncanonical[[9L]] <- as.raw(1L)
  canonical <- gsub("[\r\n]", "", jsonlite::base64_enc(noncanonical))
  expect_identical(.exact_gc_validate_residue_records(
    canonical, 65L, 1L, "test source"), noncanonical)
})

test_that("GLM manifests resolve only fixed producer-owned slots and bounds", {
  ss <- new.env(parent = emptyenv())
  ss$k2_weights_numeric_family <- "gaussian"
  weighted <- .exact_gc_vecmul_manifest_policy(
    "glm.weighted-residual.v1", "glm.weighted-residual", ss)
  expect_identical(weighted$x_key, "k2_weights_share_fp")
  expect_identical(weighted$y_key, "k2_weight_residual_share_fp")
  expect_identical(weighted$output_key,
                   "k2_weighted_residual_share_fp")
  expect_identical(weighted$ring_bits, 127L)
  expect_identical(weighted$frac_bits, 50L)

  sqrt_weighted <- .exact_gc_vecmul_manifest_policy(
    "glm.weighted-residual.v1", "glm.sqrt-weighted-residual", ss)
  expect_identical(sqrt_weighted$x_key, "k2_sqrt_weights_share_fp")
  expect_identical(sqrt_weighted$output_key,
                   "k2_sqrt_weighted_residual_share_fp")

  ss$k2_weights_numeric_family <- "poisson"
  poisson <- .exact_gc_vecmul_manifest_policy(
    "glm.weighted-residual.v1", "glm.weighted-residual", ss)
  expect_identical(poisson$bound_y, "2361183241434822606848")
  expect_error(.exact_gc_vecmul_manifest_policy(
    "glm.weighted-residual.v1", "glm.unapproved", ss), "not allowlisted")
  ss$k2_weights_numeric_family <- "unsupported"
  expect_error(.exact_gc_vecmul_manifest_policy(
    "glm.weighted-residual.v1", "glm.weighted-residual", ss),
    "provenance is unavailable")

  ss$k2_numeric_family <- "binomial"
  ss$k2_ring <- 127L
  invocation_id <- strrep("a", 32L)
  softplus_purpose <- function(stage) sprintf(
    "glm.binomial-softplus.%s.step-%02d", invocation_id, stage)
  scale <- .exact_gc_vecmul_manifest_policy(
    "glm.binomial-softplus.v1",
    softplus_purpose(0L), ss)
  expect_identical(scale$x_key, "k2_eta_share_fp")
  expect_identical(scale$y_key,
                   paste0("__r127_spconst_", invocation_id))
  expect_identical(scale$output_key,
                   paste0("__r127_spy_", invocation_id))
  step_one <- .exact_gc_vecmul_manifest_policy(
    "glm.binomial-softplus.v1",
    softplus_purpose(1L), ss)
  step_two <- .exact_gc_vecmul_manifest_policy(
    "glm.binomial-softplus.v1",
    softplus_purpose(2L), ss)
  final <- .exact_gc_vecmul_manifest_policy(
    "glm.binomial-softplus.v1",
    softplus_purpose(36L), ss)
  expect_identical(step_one$y_key, paste0("__r127_spbB_", invocation_id))
  expect_identical(step_two$y_key, paste0("__r127_spbA_", invocation_id))
  expect_identical(final$x_key, paste0("__r127_spy_", invocation_id))
  expect_identical(final$y_key, paste0("__r127_spbA_", invocation_id))
  expect_identical(final$output_key,
                   paste0("__r127_spmul36_", invocation_id))
  expect_error(.exact_gc_vecmul_manifest_policy(
    "glm.binomial-softplus.v1",
    softplus_purpose(37L), ss), "stage")
  ss$k2_numeric_family <- "poisson"
  expect_error(.exact_gc_vecmul_manifest_policy(
    "glm.binomial-softplus.v1",
    softplus_purpose(1L), ss), "provenance")

  chisq_purpose <- paste0(
    "chisq.cross.cell-product.", strrep("c", 24L), ".0001")
  ss$.exact_gc_chisq_product <- list(
    status = "preparing", purpose = chisq_purpose,
    x_key = "k2_beaver_x", y_key = "k2_beaver_y",
    output_key = "k2_beaver_z")
  chisq <- .exact_gc_vecmul_manifest_policy(
    "chisq.cross.cell-product.v1", chisq_purpose, ss)
  expect_identical(chisq, list(
    x_key = "k2_beaver_x", y_key = "k2_beaver_y",
    output_key = "k2_beaver_z", bound_x = "1048576",
    bound_y = "1048576", ring_bits = 63L, frac_bits = 20L))
  ss$.exact_gc_chisq_product$status <- "prepared"
  expect_error(.exact_gc_vecmul_manifest_policy(
    "chisq.cross.cell-product.v1", chisq_purpose, ss), "provenance")
})

test_that("Chisq exact product preparation is provenance-bound and replay exact", {
  session_id <- "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  ss <- new.env(parent = emptyenv())
  ss$.exact_gc_peer_binding_digest <- strrep("d", 64L)
  n <- 5L
  K <- 2L
  L <- 2L
  encode <- function(bytes) gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(bytes)))
  row_key <- "k2_onehot_row_fp"
  col_key <- "k2_onehot_peer_col_fp"
  ss[[row_key]] <- encode(rep(0L, 8L * n * K))
  ss[[col_key]] <- encode(rep(0L, 8L * n * L))
  ss$.dsvert_shared_onehot_provenance <- list()
  ss$.dsvert_shared_onehot_provenance[[row_key]] <- list(
    version = .DSVERT_SHARED_ONEHOT_PROVENANCE_VERSION,
    key = row_key, variable = "row", n = n, levels = K,
    ring_bits = 63L, frac_bits = 20L, source = "local",
    peer_name = NULL,
    value_digest = .dsvert_shared_onehot_digest(ss[[row_key]]))
  ss$.dsvert_shared_onehot_provenance[[col_key]] <- list(
    version = .DSVERT_SHARED_ONEHOT_PROVENANCE_VERSION,
    key = col_key, variable = "col", n = n, levels = L,
    ring_bits = 63L, frac_bits = 20L, source = "peer",
    peer_name = "site_b",
    value_digest = .dsvert_shared_onehot_digest(ss[[col_key]]))
  ss$.exact_gc_vecmul_manifests <- list()
  mint_calls <- 0L
  extract_calls <- 0L
  fake_handle <- strrep("A", 43L)
  fake_plan <- list(
    truncated_bound = "1048576", rounding_mode = "floor",
    raw_product_headroom = TRUE, output_headroom = TRUE)

  run <- function(...) testthat::with_mocked_bindings(
    .exact_gc_chisq_product_prepare_impl(...),
    .S = function(id) ss,
    .exact_gc_vecmul_party_context = function(state) {
      list(self_name = "site_a", peer_name = "site_b")
    },
    .dsvert_guard_min_agg_count = function(...) invisible(TRUE),
    .callMpcTool = function(command, args) {
      expect_identical(command, "k2-fp-extract-column")
      extract_calls <<- extract_calls + 1L
      list(result = encode(rep(extract_calls, 8L * n)))
    },
    .exact_gc_vecmul_mint_manifest = function(
        ss, session_id, producer, purpose, total_n, ...) {
      mint_calls <<- mint_calls + 1L
      ss$.exact_gc_vecmul_manifests[[fake_handle]] <- list(
        state = "fresh", plan = fake_plan)
      list(
        capability_id = .DSVERT_EXACT_GC_CAPABILITY,
        manifest_handle = fake_handle, context_hash = strrep("1", 64L),
        plan_id = strrep("2", 64L), ring_bits = 63L, frac_bits = 20L,
        backend = "direct-wide", bound_x = "1048576",
        bound_y = "1048576", max_chunk = 64L, total_n = total_n,
        numeric_policy_id = strrep("3", 64L))
    },
    .exact_gc_vecmul_validate_manifest_mac = function(...) invisible(TRUE),
    .package = "dsVert")

  args <- list(
    row_variable = "row", column_variable = "col",
    row_server = "site_a", column_server = "site_b",
    row_index = 1L, column_index = 1L, n = n,
    row_levels = K, column_levels = L, session_id = session_id)
  first <- do.call(run, args)
  expect_identical(first$producer, "chisq.cross.cell-product.v1")
  expect_identical(first$cell_index, 1L)
  expect_identical(first$bound_x, "1048576")
  expect_identical(first$truncated_bound, "1048576")
  expect_identical(mint_calls, 1L)
  expect_identical(extract_calls, 2L)
  expect_identical(do.call(run, args), first)
  expect_identical(mint_calls, 1L)
  expect_identical(extract_calls, 2L)
  expect_false(any(c(
    "x_key", "y_key", "output_key", "bound_x", "bound_y",
    "ring_bits", "frac_bits") %in%
    names(formals(exactGCChisqProductPrepareDS))))

  bad <- args
  bad$row_index <- 2L
  expect_error(do.call(run, bad), "fixed order")
  bad <- args
  bad$n <- Inf
  expect_error(do.call(run, bad), "row count")
  bad$n <- NaN
  expect_error(do.call(run, bad), "row count")
  bad <- args
  bad$row_levels <- 4097L
  expect_error(do.call(run, bad), "row levels")
  bad <- args
  bad$row_server <- "site_c"
  expect_error(do.call(run, bad), "pinned peer pair")

  ss$.exact_gc_chisq_product <- NULL
  ss[["k2_beaver_x"]] <- NULL
  ss[["k2_beaver_y"]] <- NULL
  ss$.dsvert_shared_onehot_provenance[[row_key]]$value_digest <- strrep("0", 64L)
  expect_error(do.call(run, args), "provenance")
})

test_that("GLM softplus producer accepts only a fixed stage and session", {
  session_id <- "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  ss <- new.env(parent = emptyenv())
  ss$k2_numeric_family <- "binomial"
  ss$k2_ring <- 127L
  ss$k2_x_n <- 19L
  invocation_id <- strrep("b", 32L)
  minted <- NULL
  result <- testthat::with_mocked_bindings(
    exactGCGLMSoftplusPrepareDS(7L, invocation_id, session_id),
    .S = function(id) {
      expect_identical(id, session_id)
      ss
    },
    .exact_gc_vecmul_mint_manifest = function(...) {
      minted <<- list(...)
      list(manifest_handle = strrep("A", 43L), total_n = 19L)
    },
    .package = "dsVert")
  expect_identical(result$manifest_handle, strrep("A", 43L))
  expect_identical(minted$producer, "glm.binomial-softplus.v1")
  expect_identical(minted$purpose,
                   paste0("glm.binomial-softplus.", invocation_id,
                          ".step-07"))
  expect_identical(minted$total_n, 19L)
  expect_false(any(c("x_key", "y_key", "output_key", "bound_x",
                     "bound_y") %in%
                   names(formals(exactGCGLMSoftplusPrepareDS))))
  expect_error(
    exactGCGLMSoftplusPrepareDS(37L, invocation_id, session_id), "stage")
  expect_error(
    exactGCGLMSoftplusPrepareDS(7L, "predictable", session_id), "invocation")
})

test_that("Chisq count accumulation is fixed-order, one-shot and retry exact", {
  session_id <- "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  ss <- new.env(parent = emptyenv())
  encode <- function(bytes) gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(bytes)))
  source_one <- encode(rep(1L, 8L * 5L))
  source_two <- encode(rep(2L, 8L * 5L))
  source_conflict <- encode(rep(3L, 8L * 5L))
  scalar_one <- encode(c(7L, rep(0L, 7L)))
  scalar_two <- encode(c(11L, rep(0L, 7L)))
  mpc_calls <- 0L
  arm_product <- function(source, cell_index) {
    handle <- paste0(strrep(as.character(cell_index), 42L), "A")
    batch <- paste0("op_", strrep(as.character(cell_index), 32L))
    purpose <- paste0(
      "chisq.cross.cell-product.", strrep("a", 24L), ".",
      sprintf("%04d", cell_index))
    ss[[.DSVERT_CHISQ_COUNT_SOURCE]] <- source
    ss$.exact_gc_chisq_product <- list(
      status = "prepared", cell_index = cell_index, total_cells = 2L,
      n = 5L, purpose = purpose, manifest_handle = handle,
      x_key = "k2_beaver_x", y_key = "k2_beaver_y",
      output_key = .DSVERT_CHISQ_COUNT_SOURCE)
    if (is.null(ss$.exact_gc_vecmul_manifests)) {
      ss$.exact_gc_vecmul_manifests <- list()
    }
    ss$.exact_gc_vecmul_manifests[[handle]] <- list(
      state = "consumed", producer = .DSVERT_CHISQ_PRODUCT_PRODUCER,
      purpose = purpose, claimed_batch = batch)
    if (is.null(ss$.exact_gc_vecmul_input_stages)) {
      ss$.exact_gc_vecmul_input_stages <- list()
    }
    ss$.exact_gc_vecmul_input_stages[[batch]] <- list(
      state = "complete", manifest_handle = handle,
      output_key = .DSVERT_CHISQ_COUNT_SOURCE,
      output_digest = .exact_gc_chisq_digest(source))
  }
  arm_product(source_one, 1L)

  testthat::with_mocked_bindings({
    first <- .exact_gc_chisq_accumulate_count_impl(
      1L, 2L, session_id)
    expect_identical(first$state, "collecting")
    expect_identical(mpc_calls, 1L)

    # The identical DSI retry is a pure receipt replay: it neither appends a
    # second scalar nor invokes the local reduction again.
    expect_identical(
      .exact_gc_chisq_accumulate_count_impl(1L, 2L, session_id), first)
    expect_identical(mpc_calls, 1L)

    arm_product(source_two, 2L)
    second <- .exact_gc_chisq_accumulate_count_impl(
      2L, 2L, session_id)
    expect_identical(second$state, "complete")
    expect_identical(mpc_calls, 2L)
    expect_identical(
      jsonlite::base64_dec(ss[[.DSVERT_CHISQ_COUNT_KEY]]),
      c(jsonlite::base64_dec(scalar_one), jsonlite::base64_dec(scalar_two)))
    expect_identical(
      .exact_gc_chisq_accumulate_count_impl(2L, 2L, session_id), second)
    expect_identical(mpc_calls, 2L)

    ss[[.DSVERT_CHISQ_COUNT_SOURCE]] <- source_conflict
    expect_error(
      .exact_gc_chisq_accumulate_count_impl(2L, 2L, session_id),
      "Conflicting retry")
    expect_identical(mpc_calls, 2L)
  }, .S = function(id) {
    expect_identical(id, session_id)
    ss
  }, .dsvert_guard_min_agg_count = function(...) invisible(TRUE),
  .exact_gc_vecmul_validate_manifest_mac = function(...) invisible(TRUE),
  .callMpcTool = function(command, args) {
    expect_identical(command, "k2-fp-sum")
    expect_identical(args$ring, "ring63")
    mpc_calls <<- mpc_calls + 1L
    list(sum_fp = if (mpc_calls == 1L) scalar_one else scalar_two)
  }, .package = "dsVert")

  fresh <- new.env(parent = emptyenv())
  fresh_arm <- function() {
    handle <- paste0(strrep("2", 42L), "A")
    batch <- paste0("op_", strrep("2", 32L))
    purpose <- paste0(
      "chisq.cross.cell-product.", strrep("a", 24L), ".0002")
    fresh[[.DSVERT_CHISQ_COUNT_SOURCE]] <- source_one
    fresh$.exact_gc_chisq_product <- list(
      status = "prepared", cell_index = 2L, total_cells = 2L, n = 5L,
      purpose = purpose, manifest_handle = handle,
      x_key = "k2_beaver_x", y_key = "k2_beaver_y",
      output_key = .DSVERT_CHISQ_COUNT_SOURCE)
    fresh$.exact_gc_vecmul_manifests <- list()
    fresh$.exact_gc_vecmul_manifests[[handle]] <- list(
      state = "consumed", producer = .DSVERT_CHISQ_PRODUCT_PRODUCER,
      purpose = purpose, claimed_batch = batch)
    fresh$.exact_gc_vecmul_input_stages <- list()
    fresh$.exact_gc_vecmul_input_stages[[batch]] <- list(
      state = "complete", manifest_handle = handle,
      output_key = .DSVERT_CHISQ_COUNT_SOURCE,
      output_digest = .exact_gc_chisq_digest(source_one))
  }
  fresh_arm()
  testthat::with_mocked_bindings(
    expect_error(
      .exact_gc_chisq_accumulate_count_impl(2L, 2L, session_id),
      "must start at cell one"),
    .S = function(id) fresh,
    .dsvert_guard_min_agg_count = function(...) invisible(TRUE),
    .exact_gc_vecmul_validate_manifest_mac = function(...) invisible(TRUE),
    .package = "dsVert")
})

test_that("checked vecmul contracts cover 4096/4097 and recompose 17 chunks", {
  session_id <- "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
  batch <- "op_99999999999999999999999999999999"
  policy_id <- strrep("a", 64L)
  plan_id <- strrep("d", 64L)
  plan <- list(
    version = "dsvert-exact-gc-mul-plan-v3", plan_id = plan_id,
    ring_bits = 127L, container_bits = 128L, frac_bits = 50L,
    bound_x = "9223372036854775807",
    bound_y = "9223372036854775807",
    truncated_bound = "75557863725914323402797",
    rounding_mode = "floor",
    backend = "ring127-ot", max_chunk = 256L,
    raw_product_headroom = "1", output_headroom = "1")
  contract_ss <- new.env(parent = emptyenv())
  contract_ss$.exact_gc_vecmul_input_stages <- list()
  make_contracts <- function(total_n) {
    contract_ss$.exact_gc_vecmul_input_stages[[batch]] <- list(
      state = "staged", total_n = total_n, policy_id = policy_id,
      context_hash = strrep("b", 64L), plan = plan)
    count <- as.integer(ceiling(
      total_n / plan$max_chunk))
    lapply(seq_len(count), function(index) {
      n <- as.integer(min(
        plan$max_chunk,
        total_n - (index - 1L) * plan$max_chunk))
      operation_id <- .exact_gc_checked_mul_chunk_operation(
        batch, index, count, policy_id, plan_id)
      .exact_gc_checked_mul_contract(
        contract_ss, batch, operation_id, n, total_n, index, count,
        policy_id, plan_id)
    })
  }
  contracts_4096 <- make_contracts(4096L)
  contracts_4097 <- make_contracts(4097L)
  expect_length(contracts_4096, 16L)
  expect_true(all(vapply(contracts_4096, `[[`, integer(1L), "n") == 256L))
  expect_length(contracts_4097, 17L)
  expect_true(all(vapply(contracts_4097[1:16], `[[`, integer(1L), "n") ==
                    256L))
  expect_identical(contracts_4097[[17L]]$n, 1L)
  expect_identical(contracts_4097[[17L]]$offset, 4096L)
  expect_identical(anyDuplicated(vapply(
    contracts_4097, `[[`, character(1L), "operation_id")), 0L)
  contract_ss$.exact_gc_vecmul_input_stages[[batch]]$total_n <- 4097L
  expect_error(.exact_gc_checked_mul_contract(
    contract_ss, batch, contracts_4097[[1L]]$operation_id, 255L, 4097L,
    1L, 17L, policy_id, plan_id), "chunk contract")
  expect_error(.exact_gc_checked_mul_contract(
    contract_ss, batch, contracts_4097[[1L]]$operation_id, 1L, 4097L,
    17L, 17L, policy_id, plan_id), "chunk contract")

  # Recomposition is tested without pretending to execute 17 expensive
  # circuits here. Ring127 n=256 protocol/resource bounds live in
  # the Go suite; the two-peer real-worker test above covers the full protocol.
  ss <- new.env(parent = emptyenv())
  ss$.exact_gc_outputs <- list()
  ss$.exact_gc_ops <- new.env(parent = emptyenv())
  ss$.exact_gc_checked_mul_stages <- list()
  ss$.exact_gc_checked_mul_validity <- list()
  ss$.exact_gc_checked_mul_commits <- list()
  ss$.exact_gc_checked_mul_chunks <- list()
  ss$.exact_gc_vecmul_input_stages <- list()
  destination <- "checked_product_4097"
  ss$.exact_gc_vecmul_input_stages[[batch]] <- list(
    state = "staged", session_id = session_id,
    batch_operation_id = batch,
    purpose = .DSVERT_EXACT_GC_CHECKED_MUL_PURPOSE,
    policy_id = policy_id, output_key = destination, total_n = 4097L,
    producer = "legacy.remote-slot-bind.v2", plan = plan,
    context_hash = strrep("b", 64L), output_previous_digest = "absent",
    output_digest = NULL)
  batch_keys <- .exact_gc_checked_mul_keys(batch)
  ss[[batch_keys$x]] <- "retained-x"
  ss[[batch_keys$y]] <- "retained-y"

  expected <- vector("list", length(contracts_4097))
  commit_contract <- function(contract) {
    keys <- .exact_gc_checked_mul_keys(contract$operation_id)
    share_raw <- raw(16L * contract$n)
    share_raw[seq.int(1L, length(share_raw), by = 16L)] <-
      as.raw(contract$chunk_index %% 128L)
    expected[[contract$chunk_index]] <<- share_raw
    share <- gsub("[\r\n]", "", jsonlite::base64_enc(share_raw))
    context_hash <- digest::digest(
      contract$operation_id, algo = "sha256", serialize = FALSE)
    ss$.exact_gc_checked_mul_stages[[contract$operation_id]] <- list(
      contract = contract, input_context_hash = strrep("b", 64L),
      source_digest = strrep("c", 64L))
    ss$.exact_gc_checked_mul_validity[[contract$operation_id]] <- list(
      valid = TRUE)
    state <- new.env(parent = emptyenv())
    state$status <- "complete"
    state$session_id <- session_id
    state$operation_id <- contract$operation_id
    state$output_key <- keys$output
    state$context_hash <- context_hash
    state$operation <- "mul-truncate-checked"
    state$purpose <- contract$purpose
    state$ring_bits <- 127L
    state$frac_bits <- 50L
    state$vector_len <- contract$n
    state$output_kind <- "checked-ring-share"
    state$source_producer <- .DSVERT_EXACT_GC_CHECKED_MUL_PRODUCER
    state$spool <- NULL
    ss$.exact_gc_ops[[contract$operation_id]] <- state
    ss$.exact_gc_outputs[[keys$output]] <- list(
      operation_id = contract$operation_id,
      operation = "mul-truncate-checked", purpose = contract$purpose,
      source_producer = .DSVERT_EXACT_GC_CHECKED_MUL_PRODUCER,
      kind = "checked-ring-share", share = share, ring_bits = 127L,
      frac_bits = 50L, vector_len = contract$n,
      context_hash = context_hash)
    testthat::with_mocked_bindings(
      .exact_gc_checked_mul_commit_impl(
        contract$n, contract$total_n, contract$chunk_index,
        contract$chunk_count, batch, session_id, contract$operation_id,
        policy_id, plan_id),
      .S = function(session_id) ss, .package = "dsVert")
  }
  states <- vapply(contracts_4097, function(contract) {
    commit_contract(contract)$state
  }, character(1L))
  expect_true(all(states[1:16] == "partial"))
  expect_identical(states[[17L]], "committed")
  expect_identical(jsonlite::base64_dec(ss[[destination]]), do.call(c, expected))
  expect_null(ss[[batch_keys$x]])
  expect_null(ss[[batch_keys$y]])
  expect_identical(
    ss$.exact_gc_vecmul_input_stages[[batch]]$state, "complete")
  # A cross-peer fan-out can fail after only one peer completed locally. Its
  # best-effort abort must roll that lone destination share back as well.
  .exact_gc_checked_mul_abort_batch(ss, batch)
  expect_null(ss[[destination]])
  expect_identical(
    ss$.exact_gc_vecmul_input_stages[[batch]]$state, "aborted")
})

test_that("Gaussian one-draw stays internal and authority-bound", {
  operation <- "joint-dp-vector-gaussian-one-draw-v1"
  circuit <- strrep("a", 64L)
  purpose <- paste0(operation, "/", circuit)
  peer_a <- paste0("dsv1_", strrep("1", 64L))
  peer_b <- paste0("dsv1_", strrep("2", 64L))
  policy <- list(
    version = paste0(
      "dsvert-joint-dp-vector-discrete-gaussian-one-draw-",
      "gc-template-v1"),
    mechanism = "joint_discrete_gaussian_one_global_draw",
    allocation = "one_stacked_capsule_vector",
    ring_bits = 128L, frac_bits = 0L,
    total_coordinate_count = 1L, chunk_start = 0L,
    coordinate_count = 1L, output_lattice_bits = 20L,
    epsilon = "1", allocated_delta = "1/1000000",
    l2_sensitivity_steps = "1",
    l2_sensitivity_certificate_kind =
      "machine_proven_integer_lattice_l2_v1",
    l2_sensitivity_certificate_sha256 = strrep("3", 64L),
    release_binding_domain =
      "dsVert/formal-cox/runtime-release-binding/v1",
    release_binding_canonical_json = "{}",
    scale_shifts = 0L, raw_upper_bounds = "1",
    release_binding_sha256 = strrep("4", 64L),
    cross_signed_policy_sha256 = strrep("4", 64L),
    transcript_hash = strrep("5", 64L),
    pinset_sha256 = strrep("6", 64L), custodian_count = 2L,
    designated_compute_peer_count = 2L,
    garbler_peer_id = peer_a, evaluator_peer_id = peer_b,
    garbler_commitment_context = strrep("7", 64L),
    evaluator_commitment_context = strrep("8", 64L),
    garbler_seed_commitment = strrep("9", 64L),
    evaluator_seed_commitment = strrep("a", 64L),
    cdf_cumulative = "340282366920938463463374607431768211456",
    circuit_digest = circuit,
    plan = list(
      version =
        "dsvert-joint-dp-vector-discrete-gaussian-one-draw-plan-v1",
      mechanism = "joint_discrete_gaussian_one_global_draw",
      allocation = "one_stacked_capsule_vector",
      sampler = paste0(
        "fixed-work-outward-rational-dyadic-cdf-hkdf-",
        "sha256-chacha20-xor-exact-gc-v1"),
      ring_bits = 128L, frac_bits = 0L, noise_draw_count = 1L,
      total_coordinate_count = 1L, maximum_chunk_coordinates = 1L,
      cdf_cumulative =
        "340282366920938463463374607431768211456",
      finite_support_transfer_charged = TRUE,
      fixed_work_sampler = TRUE, no_wrap_certified = TRUE,
      designated_compute_peer_count = 2L,
      capability_available = TRUE))
  seed <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(42L, 32L))))
  expect_identical(
    .exact_gc_gaussian_one_draw_policy(
      policy, 128L, 0L, 1L, purpose, seed),
    .dsvert_dp_canonical_query_value(policy))
  sentinel <- "PRIVATE-SHARE-SENTINEL"
  error <- tryCatch({
    changed <- policy
    changed$circuit_digest <- sentinel
    .exact_gc_gaussian_one_draw_policy(
      changed, 128L, 0L, 1L, purpose, seed)
    NULL
  }, error = identity)
  expect_s3_class(error, "error")
  expect_false(grepl(sentinel, conditionMessage(error), fixed = TRUE))

  expect_identical(
    .exact_gc_output_kind(operation),
    "joint-dp-vector-gaussian-one-draw-ring128-share-v1")
  ss <- new.env(parent = emptyenv())
  share <- .exact_gc_test_b64_records(0, 16L)
  expect_error(.exact_gc_stage_share(
    ss, "exact_gc_in_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", share,
    128L, 1L, "formal.cox.authorized-source.v1", operation,
    purpose, 0L, .exact_gc_output_kind(operation)),
    "exact recipient authority")
  expect_silent(.exact_gc_stage_share(
    ss, "exact_gc_in_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", share,
    128L, 1L, "formal.cox.authorized-source.v1", operation,
    purpose, 0L, .exact_gc_output_kind(operation),
    gaussian_one_draw_authority_sha256 = strrep("b", 64L)))

  public_formals <- lapply(c(
    "exactGCTransportInitDS", "exactGCBindPeersDS", "exactGCExchangeDS",
    "exactGCAbortDS", "exactGCCleanupDS"), function(name) {
      names(formals(get(name, envir = asNamespace("dsVert"))))
    })
  expect_false(any(vapply(public_formals, function(fields) any(fields %in% c(
    "operation", "backend", "output_kind", "joint_dp_gaussian_one_draw",
    "private_seed", "source_share")), logical(1L))))
  public_metadata <- paste(unlist(lapply(
    c(.dsvert_test_package_file("DESCRIPTION"),
      .dsvert_test_package_file("NAMESPACE")),
    readLines, warn = FALSE), use.names = FALSE), collapse = "\n")
  expect_false(grepl(operation, public_metadata, fixed = TRUE))
})
