.formal_cox_keys <- function(k) {
  keys <- stats::setNames(
    replicate(k, openssl::ed25519_keygen(), simplify = FALSE),
    paste0("site", seq_len(k)))
  pins <- lapply(keys, function(key) {
    raw <- as.list(as.list(key)$pubkey)$data
    base64_to_base64url(jsonlite::base64_enc(raw))
  })
  list(keys = keys, pins = pins)
}

.formal_cox_sign <- function(unsigned, keys) {
  message <- .dsvert_formal_cox_schema_message(unsigned)
  lapply(keys, function(key) base64_to_base64url(gsub(
    "[\r\n[:space:]]", "",
    jsonlite::base64_enc(openssl::ed25519_sign(message, key)))))
}

.formal_cox_schema <- function(
    k = 3L, logical_snapshot_id = "cohort_v1",
    adjacency = "add_remove_patient", entry_mode = "none",
    risk_floor = 1L, ridge_numerator = 0L, beta_l2_bound = 4,
    fixture = NULL) {
  identity <- .formal_cox_keys(k)
  owner2 <- if (k >= 3L) "site3" else "site2"
  unsigned <- .dsvert_formal_cox_schema_compile(
    artifact_sha256 = paste(rep("1", 64L), collapse = ""),
    logical_snapshot_id = logical_snapshot_id,
    peer_pinset = identity$pins,
    outcome_owner = "site1",
    covariate_owners = c(x1 = "site2", x2 = owner2),
    capacity = if (is.null(fixture)) 64L else nrow(fixture),
    time_grid_ticks = 0:24,
    x_lower = c(x1 = -2, x2 = -2),
    x_upper = c(x1 = 2, x2 = 2),
    covariate_l2_bound = 2.8, beta_l2_bound = beta_l2_bound,
    minimum_at_risk_per_event = risk_floor,
    iterations = 8L, step_numerator = 1L, step_denominator = 8L,
    ridge_numerator = ridge_numerator, ridge_denominator = 100L,
    epsilon_numerator = 2L, epsilon_denominator = 1L,
    delta_numerator = 1L, delta_denominator = 1000000L,
    adjacency = adjacency, entry_mode = entry_mode, frac_bits = 30L)
  schema <- .dsvert_formal_cox_schema_seal(
    unsigned, .formal_cox_sign(unsigned, identity$keys))
  list(schema = schema, keys = identity$keys, pins = identity$pins)
}

.formal_cox_fixture <- function(n = 60L, capacity = 64L,
                                delayed_entry = FALSE) {
  set.seed(20260802)
  x1 <- pmax(-1.7, pmin(1.7, stats::rnorm(n, sd = 0.7)))
  x2 <- stats::runif(n, -1.1, 1.1)
  event <- stats::rexp(n, rate = exp(0.45 * x1 - 0.3 * x2) / 7)
  censor <- stats::rexp(n, rate = 1 / 12)
  stop <- pmax(1L, pmin(24L, as.integer(ceiling(pmin(event, censor)))))
  status <- as.numeric(event <= censor & event <= 24)
  entry <- rep(0L, n)
  if (delayed_entry) {
    entry <- pmin(stop - 1L, sample.int(4L, n, replace = TRUE) - 1L)
  }
  result <- data.frame(
    valid = c(rep(TRUE, n), rep(FALSE, capacity - n)),
    entry_tick = c(entry, rep(0L, capacity - n)),
    stop_tick = c(stop, rep(1L, capacity - n)),
    status = c(status, rep(0, capacity - n)),
    x1 = c(x1, rep(0, capacity - n)),
    x2 = c(x2, rep(0, capacity - n)), check.names = FALSE)
  result
}

.formal_cox_reference_rows <- function(fixture, schema) {
  grid <- as.numeric(unlist(schema$unsigned$time_grid_ticks,
                            use.names = FALSE))
  data.frame(
    valid = fixture$valid,
    entry_index = if (schema$unsigned$entry_mode == "none") {
      rep(0L, nrow(fixture))
    } else match(fixture$entry_tick, grid),
    stop_index = match(fixture$stop_tick, grid),
    status = fixture$status, x1 = fixture$x1, x2 = fixture$x2,
    check.names = FALSE)
}

.formal_cox_source_frame <- function(fixture, schema, peer) {
  owners <- unlist(schema$unsigned$covariate_owners, use.names = TRUE)
  columns <- "valid"
  if (peer == schema$unsigned$outcome_owner) {
    columns <- c(columns,
      if (schema$unsigned$entry_mode == "single_interval") "entry_tick",
      "stop_tick", "status")
  }
  columns <- c(columns, names(owners)[owners == peer])
  fixture[, columns, drop = FALSE]
}

.formal_cox_server_source_fixture <- function(
    sealed, fixture, peer, block_capacity = 7L) {
  rows <- .formal_cox_source_frame(fixture, sealed$schema, peer)
  rows$patient_id <- sprintf("patient-%03d", seq_len(nrow(rows)))
  binding <- .dsvert_test_padded_dp_binding(
    rows, "patient_id", "cox-cohort", "v1",
    sealed$schema$unsigned$peer_pinset)
  source <- new.env(parent = emptyenv())
  assign("cox_local", binding$data, envir = source)
  lockBinding("cox_local", source)
  list(
    source = source,
    rows = rows,
    spec = list(
      source_name = peer,
      schema_sha256 = sealed$schema$schema_sha256,
      logical_snapshot_id = sealed$schema$unsigned$logical_snapshot_id,
      dataset = binding$descriptor,
      data_name = "cox_local",
      patient_column = "patient_id",
      block_capacity = block_capacity,
      columns = as.list(stats::setNames(
        names(rows)[names(rows) != "patient_id"],
        names(rows)[names(rows) != "patient_id"])))
  )
}

test_that("formal Cox schema requires unanimous pinned signatures and a positive risk floor", {
  identity <- .formal_cox_keys(3L)
  args <- list(
    artifact_sha256 = paste(rep("1", 64L), collapse = ""),
    logical_snapshot_id = "cohort_v1",
    peer_pinset = identity$pins, outcome_owner = "site1",
    covariate_owners = c(x1 = "site2"), capacity = 32L,
    time_grid_ticks = 0:8, x_lower = c(x1 = -1),
    x_upper = c(x1 = 1), covariate_l2_bound = 1,
    beta_l2_bound = 2, minimum_at_risk_per_event = 0L)
  expect_error(
    do.call(.dsvert_formal_cox_schema_compile, args),
    class = "dsvert_formal_cox_error")
  args$minimum_at_risk_per_event <- 1L
  unsigned <- do.call(.dsvert_formal_cox_schema_compile, args)
  signatures <- .formal_cox_sign(unsigned, identity$keys)
  expect_error(
    .dsvert_formal_cox_schema_seal(unsigned, signatures[-1L]),
    class = "dsvert_formal_cox_error")
  forged <- signatures
  forged[[1L]] <- signatures[[2L]]
  expect_error(
    .dsvert_formal_cox_schema_seal(unsigned, forged),
    class = "dsvert_formal_cox_error")
  schema <- .dsvert_formal_cox_schema_seal(unsigned, signatures)
  expect_silent(.dsvert_formal_cox_schema_validate(schema))
  expect_identical(schema$unsigned$entry_mode, "none")
  expect_equal(.dsvert_formal_cox_schema_numeric(schema)$ridge, 0)

  malformed_artifact <- unsigned
  malformed_artifact$artifact_sha256 <- "not-a-sha256"
  malformed_schema <- .dsvert_formal_cox_schema_seal(
    malformed_artifact,
    .formal_cox_sign(malformed_artifact, identity$keys))
  expect_error(
    .dsvert_formal_cox_schema_validate(malformed_schema),
    class = "dsvert_formal_cox_error")

  unsafe_peer_names <- identity$pins
  names(unsafe_peer_names)[[2L]] <- "../site2"
  unsafe_peer_args <- args
  unsafe_peer_args$peer_pinset <- unsafe_peer_names
  expect_error(
    do.call(.dsvert_formal_cox_schema_compile, unsafe_peer_args),
    class = "dsvert_formal_cox_error")
  unsafe_covariate_args <- args
  unsafe_covariate_args$covariate_owners <- c("x/path" = "site2")
  expect_error(
    do.call(.dsvert_formal_cox_schema_compile, unsafe_covariate_args),
    class = "dsvert_formal_cox_error")

  missing_floor <- unsigned
  missing_floor$minimum_at_risk_per_event <- NULL
  expect_error(
    .dsvert_formal_cox_schema_seal(
      missing_floor, .formal_cox_sign(missing_floor, identity$keys)),
    class = "dsvert_formal_cox_error")
})

test_that("sensitivity is recomputed for fixed-capacity patient adjacency", {
  add <- .formal_cox_schema(2L, adjacency = "add_remove_patient")$schema
  replace <- .formal_cox_schema(2L, adjacency = "replace_one_patient")$schema
  add_plan <- .dsvert_formal_cox_sensitivity_plan(add)
  replace_plan <- .dsvert_formal_cox_sensitivity_plan(replace)
  numeric <- .dsvert_formal_cox_schema_numeric(add)
  expected <- 4 * numeric$covariate_l2_bound / numeric$capacity +
    exp(2 * numeric$covariate_l2_bound * numeric$beta_l2_bound) *
    (2 * numeric$covariate_l2_bound + numeric$covariate_l2_bound^2) *
    log(numeric$capacity + 1) / numeric$capacity
  expect_equal(add_plan$normalized_score_l2_sensitivity,
               expected, tolerance = 1e-14)
  # A public-capacity add/remove is a replacement of the canonical zero slot;
  # both contracts therefore use Lemma 9's one-triple replacement bound.
  expect_equal(replace_plan$normalized_score_l2_sensitivity,
               add_plan$normalized_score_l2_sensitivity,
               tolerance = 1e-14)
  expect_false(add_plan$sensitivity_client_override_accepted)
  expect_identical(add_plan$input_materialization_backend, "exact_ring128")
  expect_true(add_plan$input_ring128_no_wrap_certificate)
  expect_false(add_plan$deterministic_iteration_no_wrap_certificate)
  expect_false(add_plan$final_numeric_error_certificate)
  expect_identical(add_plan$noise_numeric_backend,
                   "exact_dynamic_multiprecision_lift_required_v1")
  expect_false(add_plan$fixed_ring_full_no_wrap_certificate)
  expect_false(add_plan$production_ready)

  wide_beta <- .formal_cox_schema(2L, beta_l2_bound = 20)$schema
  wide_plan <- .dsvert_formal_cox_sensitivity_plan(wide_beta)
  expect_match(wide_plan$deterministic_numeric_backend,
               "^exact_gc_dynamic_ring_[0-9]+$")
  expect_identical(wide_plan$input_materialization_backend, "exact_ring128")
  expect_false(wide_plan$deterministic_iteration_no_wrap_certificate)

  tampered <- add
  tampered$unsigned$capacity <- "65"
  expect_error(.dsvert_formal_cox_sensitivity_plan(tampered),
               class = "dsvert_formal_cox_error")

  delayed <- .formal_cox_schema(
    2L, entry_mode = "single_interval", risk_floor = 8L)$schema
  delayed_numeric <- .dsvert_formal_cox_schema_numeric(delayed)
  delayed_plan <- .dsvert_formal_cox_sensitivity_plan(delayed)
  delayed_expected <- 4 * delayed_numeric$covariate_l2_bound /
    delayed_numeric$capacity +
    exp(2 * delayed_numeric$covariate_l2_bound *
          delayed_numeric$beta_l2_bound) *
    (2 * delayed_numeric$covariate_l2_bound +
       delayed_numeric$covariate_l2_bound^2)
  expect_equal(delayed_plan$normalized_score_l2_sensitivity,
               delayed_expected, tolerance = 1e-14)
  expect_identical(delayed_plan$left_truncation_sensitivity,
                   "conservative_sum_d_over_r_at_most_N_extension_v1")
})

test_that("finite-state patient neighbours obey the signed score bound", {
  identity <- .formal_cox_keys(2L)
  unsigned <- .dsvert_formal_cox_schema_compile(
    artifact_sha256 = paste(rep("2", 64L), collapse = ""),
    logical_snapshot_id = "finite_state_audit",
    peer_pinset = identity$pins, outcome_owner = "site1",
    covariate_owners = c(x = "site2"), capacity = 2L,
    time_grid_ticks = 0:3, x_lower = c(x = -1), x_upper = c(x = 1),
    covariate_l2_bound = 1, beta_l2_bound = 0.5,
    minimum_at_risk_per_event = 1L, iterations = 2L,
    adjacency = "add_remove_patient", entry_mode = "none")
  schema <- .dsvert_formal_cox_schema_seal(
    unsigned, .formal_cox_sign(unsigned, identity$keys))
  states <- rbind(
    data.frame(valid = FALSE, entry_index = 0, stop_index = 1,
               status = 0, x = 0),
    expand.grid(valid = TRUE, entry_index = 0, stop_index = 1:4,
                status = 0:1, x = c(-1, 0, 1),
                KEEP.OUT.ATTRS = FALSE, stringsAsFactors = FALSE))
  plan <- .dsvert_formal_cox_sensitivity_plan(schema)
  direct_score <- function(changed, fixed, beta) {
    rows <- rbind(states[changed, , drop = FALSE],
                  states[fixed, , drop = FALSE])
    score <- 0
    for (tick in 1:4) {
      risk <- rows$valid & rows$entry_index < tick &
        rows$stop_index >= tick
      event <- rows$valid & rows$status == 1 &
        rows$stop_index == tick
      count <- sum(event)
      if (count) {
        weight <- exp(beta * rows$x[risk])
        score <- score + sum(rows$x[event]) - count *
          sum(rows$x[risk] * weight) / sum(weight)
      }
    }
    score / 2
  }
  observed_max <- 0
  for (beta in c(-0.5, 0, 0.5)) {
    score <- matrix(0, nrow(states), nrow(states))
    for (changed in seq_len(nrow(states))) {
      for (fixed in seq_len(nrow(states))) {
        score[changed, fixed] <- direct_score(changed, fixed, beta)
      }
    }
    for (changed in c(1L, 2L, 13L, 25L)) {
      for (fixed in c(1L, 7L, 19L, 25L)) {
        rows <- rbind(states[changed, , drop = FALSE],
                      states[fixed, , drop = FALSE])
        expect_equal(
          .dsvert_formal_cox_oracle_at(schema, rows, beta)$score / 2,
          direct_score(changed, fixed, beta), tolerance = 1e-14)
      }
    }
    observed_max <- max(observed_max, apply(score, 2L, function(value) {
      max(value) - min(value)
    }))
  }
  expect_gt(observed_max, 0)
  expect_lte(observed_max,
             plan$normalized_score_l2_sensitivity + 1e-12)
})

test_that("central grid-Breslow oracle matches survival::coxph with ties", {
  skip_if_not_installed("survival")
  fixture <- .formal_cox_fixture()
  sealed <- .formal_cox_schema(3L, fixture = fixture)
  rows <- .formal_cox_reference_rows(fixture, sealed$schema)
  fit <- .dsvert_formal_cox_oracle_fit(sealed$schema, rows)
  observed <- fixture[fixture$valid, , drop = FALSE]
  reference <- survival::coxph(
    survival::Surv(stop_tick, status) ~ x1 + x2,
    data = observed, ties = "breslow")
  expect_equal(unname(fit$coefficients), unname(stats::coef(reference)),
               tolerance = 2e-6)
  expect_equal(fit$oracle$log_partial_likelihood,
               unname(reference$loglik[[2L]]), tolerance = 2e-6)
  expect_true(any(fit$oracle$event_count > 1L))
  expect_false(fit$opened)
  expect_false(fit$production_ready)
})

test_that("single-interval delayed entry matches counting-process coxph", {
  skip_if_not_installed("survival")
  fixture <- .formal_cox_fixture(delayed_entry = TRUE)
  sealed <- .formal_cox_schema(
    3L, entry_mode = "single_interval", fixture = fixture)
  rows <- .formal_cox_reference_rows(fixture, sealed$schema)
  fit <- .dsvert_formal_cox_oracle_fit(sealed$schema, rows)
  observed <- fixture[fixture$valid, , drop = FALSE]
  reference <- survival::coxph(
    survival::Surv(entry_tick, stop_tick, status) ~ x1 + x2,
    data = observed, ties = "breslow")
  expect_equal(unname(fit$coefficients), unname(stats::coef(reference)),
               tolerance = 3e-6)
})

test_that("signed at-risk floor is checked internally and never opened as a count", {
  fixture <- .formal_cox_fixture(n = 12L, capacity = 64L)
  # Force one late event with a one-patient risk set.
  fixture$stop_tick[fixture$valid] <- seq_len(12L)
  fixture$status[fixture$valid] <- 0
  fixture$status[[12L]] <- 1
  sealed <- .formal_cox_schema(2L, risk_floor = 2L, fixture = fixture)
  rows <- .formal_cox_reference_rows(fixture, sealed$schema)
  error <- tryCatch(
    .dsvert_formal_cox_oracle_at(sealed$schema, rows, c(0, 0)),
    error = identity)
  expect_s3_class(error, "dsvert_formal_cox_error")
  expect_identical(error$code, "non_identifiable_formal_cox")
  expect_identical(error$openings_performed, 0L)
})

test_that("central oracle refuses a non-identifiable unpenalized target", {
  fixture <- .formal_cox_fixture()
  fixture$status[] <- 0
  sealed <- .formal_cox_schema(2L, ridge_numerator = 0L, fixture = fixture)
  rows <- .formal_cox_reference_rows(fixture, sealed$schema)
  error <- tryCatch(
    .dsvert_formal_cox_oracle_fit(sealed$schema, rows), error = identity)
  expect_s3_class(error, "dsvert_formal_cox_error")
  expect_identical(error$code, "non_identifiable_formal_cox")
  expect_identical(error$openings_performed, 0L)
})

test_that("K=2/3/5 fixed Ring128 shares reconstruct only inside the fixture", {
  fixture <- .formal_cox_fixture()
  for (k in c(2L, 3L, 5L)) {
    sealed <- .formal_cox_schema(k, fixture = fixture)
    peers <- names(sealed$schema$unsigned$peer_pinset)
    roots <- stats::setNames(lapply(seq_along(peers), function(index) {
      as.raw(rep(index, 32L))
    }), peers)
    bindings <- stats::setNames(lapply(seq_along(peers), function(index) {
      as.raw(rep(100L + index, 32L))
    }), peers)
    bundles <- stats::setNames(lapply(peers, function(peer) {
      .dsvert_formal_cox_materialize_source(
        sealed$schema, peer,
        .formal_cox_source_frame(fixture, sealed$schema, peer),
        roots[[peer]], bindings[[peer]])
    }), peers)
    reconstructed <- .dsvert_formal_cox_reconstruct_fixture(
      sealed$schema, bundles, roots, bindings)
    expected <- .dsvert_formal_cox_rows_validate(
      sealed$schema,
      .formal_cox_reference_rows(fixture, sealed$schema))
    expect_equal(reconstructed, expected, tolerance = 2^-29)
    expect_equal(.dsvert_formal_cox_reconstruct_fixture(
      sealed$schema, rev(bundles), rev(roots), rev(bindings)),
      expected, tolerance = 2^-29)
    sizes <- vapply(bundles, function(bundle) {
      length(bundle$recipient_shares[[1L]])
    }, integer(1L))
    expect_true(length(unique(sizes)) == 1L)
    expect_true(all(vapply(bundles, `[[`, logical(1L),
                           "production_ready") == FALSE))
    expect_true(all(vapply(bundles, `[[`, logical(1L),
                           "recipient_shares_sealed") == FALSE))
    expect_true(all(vapply(bundles, `[[`, character(1L),
                           "fixture_transport") ==
                      "test_fixture_plaintext_not_transportable_v1"))
  }
})

test_that("formal Cox local source blocks preserve the canonical lattice layout", {
  fixture <- .formal_cox_fixture()
  for (k in c(2L, 3L, 5L)) {
    sealed <- .formal_cox_schema(k, fixture = fixture)
    capacity <- as.integer(sealed$schema$unsigned$capacity)
    for (peer in names(sealed$schema$unsigned$peer_pinset)) {
      rows <- .formal_cox_source_frame(fixture, sealed$schema, peer)
      expected <- .dsvert_formal_cox_source_rows(
        sealed$schema, peer, rows)
      expected_lines <- unname(sprintf("%.0f", as.vector(t(expected))))
      for (block_capacity in c(1L, 7L, capacity)) {
        blocks <- ceiling(capacity / block_capacity)
        observed <- unlist(lapply(seq.int(0L, blocks - 1L), function(index) {
          .dsvert_formal_cox_source_block_decimal_lines(
            sealed$schema, peer, rows, index, block_capacity)
        }), use.names = FALSE)
        expect_identical(observed, expected_lines)
        expect_false(any(observed == "-0"))
        expect_lte(length(.dsvert_formal_cox_source_block_decimal_lines(
          sealed$schema, peer, rows, 0L, block_capacity)),
          block_capacity * ncol(expected))
        expect_error(.dsvert_formal_cox_source_block_decimal_lines(
          sealed$schema, peer, rows, blocks, block_capacity),
          class = "dsvert_formal_cox_error")
      }
    }
    expect_error(.dsvert_formal_cox_source_block_decimal_lines(
      sealed$schema, "not-a-peer",
      .formal_cox_source_frame(fixture, sealed$schema, "site1"), 0L, 7L),
      class = "dsvert_formal_cox_error")
  }
})

test_that("formal Cox server source admits only the configured PSI snapshot", {
  fixture <- .formal_cox_fixture()
  for (k in c(2L, 3L, 5L)) {
    sealed <- .formal_cox_schema(k, fixture = fixture)
    for (peer in names(sealed$schema$unsigned$peer_pinset)) {
      configured <- .formal_cox_server_source_fixture(sealed, fixture, peer)
      withr::local_options(list(
        dsvert.peer_name = peer,
        dsvert.formal_cox.source_specs = stats::setNames(
          list(configured$spec), peer)))
      context <- .dsvert_formal_cox_server_source_open(
        sealed$schema, configured$source)
      expected <- .dsvert_formal_cox_source_rows(
        sealed$schema, peer, configured$rows[, names(configured$spec$columns),
                                              drop = FALSE])
      blocks <- ceiling(nrow(configured$rows) / configured$spec$block_capacity)
      observed <- unlist(lapply(seq.int(0L, blocks - 1L), function(index) {
        .dsvert_formal_cox_server_source_block(context, index)
      }), use.names = FALSE)
      expect_identical(observed, unname(sprintf("%.0f", as.vector(t(expected)))))
      expect_true(is.environment(context))
      expect_false(is.list(context))
      expect_false(any(grepl("share|mask|opening|result", ls(context),
                             ignore.case = TRUE)))
      expect_error(.dsvert_formal_cox_server_source_block(context, blocks),
                   class = "dsvert_formal_cox_error")

      wrong_schema <- configured$spec
      wrong_schema$schema_sha256 <- paste(rep("0", 64L), collapse = "")
      withr::local_options(list(
        dsvert.formal_cox.source_specs = stats::setNames(
          list(wrong_schema), peer)))
      expect_error(.dsvert_formal_cox_server_source_open(
        sealed$schema, configured$source), class = "dsvert_formal_cox_error")

      wrong_map <- configured$spec
      wrong_map$columns[[1L]] <- "patient_id"
      withr::local_options(list(
        dsvert.formal_cox.source_specs = stats::setNames(
          list(wrong_map), peer)))
      expect_error(.dsvert_formal_cox_server_source_open(
        sealed$schema, configured$source), class = "dsvert_formal_cox_error")

      reordered <- new.env(parent = emptyenv())
      reordered_data <- get("cox_local", envir = configured$source)
      reordered_data <- reordered_data[rev(seq_len(nrow(reordered_data))), ,
                                       drop = FALSE]
      assign("cox_local", reordered_data, envir = reordered)
      lockBinding("cox_local", reordered)
      withr::local_options(list(
        dsvert.formal_cox.source_specs = stats::setNames(
          list(configured$spec), peer)))
      expect_error(.dsvert_formal_cox_server_source_open(
        sealed$schema, reordered), class = "dsvert_formal_cox_error")
    }
  }
})

test_that("formal Cox source bridge sends only one configured local block to Go", {
  fixture <- .formal_cox_fixture(n = 12L, capacity = 16L)
  sealed <- .formal_cox_schema(2L, fixture = fixture)
  peer <- "site1"
  configured <- .formal_cox_server_source_fixture(sealed, fixture, peer,
                                                   block_capacity = 4L)
  key <- sealed$keys[[peer]]
  identity <- list(
    identity_pk = jsonlite::base64_enc(as.list(as.list(key)$pubkey)$data),
    identity_sk = jsonlite::base64_enc(as.list(key)$data))
  captured <- new.env(parent = emptyenv())
  captured$calls <- 0L
  testthat::local_mocked_bindings(
    .get_identity_keypair = function() identity,
    .callMpcTool = function(command, input_data, simplify_output = TRUE) {
      captured$calls <- captured$calls + 1L
      captured$command <- command
      captured$input <- input_data
      list(receipt = list(version = "receipt"),
           receipt_sha256 = paste(rep("a", 64L), collapse = ""),
           replayed = FALSE)
    },
    .package = "dsVert")
  withr::local_options(list(
    dsvert.peer_name = peer,
    dsvert.formal_cox.source_specs = stats::setNames(
      list(configured$spec), peer)))
  context <- .dsvert_formal_cox_server_source_open(
    sealed$schema, configured$source)
  tickets <- list(list(ticket = "garbler"), list(ticket = "evaluator"))
  run_id <- paste(rep("f", 64L), collapse = "")
  result <- .dsvert_formal_cox_server_source_produce_block(
    context, run_id, tickets, 1L)
  expect_identical(captured$calls, 1L)
  expect_identical(captured$command, "formal-cox-source-produce")
  expect_identical(names(captured$input), c(
    "version", "schema", "block_capacity", "run_id", "pins",
    "recipient_tickets", "source_peer_name", "source_signing_key",
    "block_index", "canonical_input_base64"))
  expect_identical(captured$input$schema, sealed$schema)
  expect_identical(captured$input$block_capacity, 4)
  expect_identical(captured$input$run_id, run_id)
  expect_identical(captured$input$recipient_tickets, tickets)
  expect_identical(captured$input$source_peer_name, peer)
  expect_identical(captured$input$source_signing_key, identity$identity_sk)
  expect_identical(captured$input$block_index, 1)
  expected <- .dsvert_formal_cox_server_source_block(context, 1L)
  expect_identical(
    rawToChar(jsonlite::base64_dec(captured$input$canonical_input_base64)),
    paste0(paste(expected, collapse = "\n"), "\n"))
  expect_identical(names(result), c("receipt", "receipt_sha256", "replayed"))
  expect_false(any(grepl("key|input|path|row|share", names(result),
                         ignore.case = TRUE)))

  expect_error(.dsvert_formal_cox_server_source_produce_block(
    context, "not-a-run-id", tickets, 1L), class = "dsvert_formal_cox_error")
  expect_error(.dsvert_formal_cox_server_source_produce_block(
    context, run_id, tickets[-1L], 1L), class = "dsvert_formal_cox_error")
  expect_identical(captured$calls, 1L)
})

test_that("formal Cox plaintext fixture has no package or DSI surface", {
  exports <- getNamespaceExports("dsVert")
  expect_false(any(grepl("formal.*cox|cox.*formal", exports,
                         ignore.case = TRUE)))
  description <- read.dcf(.dsvert_test_package_file("DESCRIPTION"))
  aggregate <- trimws(strsplit(
    description[1L, "AggregateMethods"], ",", fixed = TRUE)[[1L]])
  expect_false(any(grepl("formal.*cox|cox.*formal", aggregate,
                         ignore.case = TRUE)))
  namespace <- readLines(
    .dsvert_test_package_file("NAMESPACE"), warn = FALSE)
  expect_false(any(grepl(
    "formalCoxRing128Materializer|formalCoxCapsuleInternal", namespace)))
})

test_that("formal Cox has only closed source and opaque control Go commands", {
  main <- readLines(.dsvert_test_package_file(
    "inst", "dsvert-mpc", "main.go", source_only = TRUE), warn = FALSE)
  commands <- sub(
    '^[[:space:]]*case "([^"]+)":.*$', "\\1",
    grep('^[[:space:]]*case "formal-cox-', main, value = TRUE))
  expect_setequal(commands, c(
    "formal-cox-control-source",
    "formal-cox-control-import",
    "formal-cox-control-delivery",
    "formal-cox-source-produce"))
})

test_that("Ring128 source bundles reject tamper, replay and wrong roots", {
  fixture <- .formal_cox_fixture()
  sealed <- .formal_cox_schema(3L, fixture = fixture)
  peer <- "site1"
  root <- as.raw(rep(7L, 32L))
  binding <- as.raw(rep(9L, 32L))
  bundle <- .dsvert_formal_cox_materialize_source(
    sealed$schema, peer,
    .formal_cox_source_frame(fixture, sealed$schema, peer), root, binding)
  expect_silent(.dsvert_formal_cox_materialization_validate(
    bundle, sealed$schema, root, binding))
  expect_identical(bundle, .dsvert_formal_cox_materialize_source(
    sealed$schema, peer,
    .formal_cox_source_frame(fixture, sealed$schema, peer), root, binding))

  covariate_peer <- "site2"
  covariate_root <- as.raw(rep(11L, 32L))
  covariate_rows <- .formal_cox_source_frame(
    fixture, sealed$schema, covariate_peer)
  original_covariate_bundle <- .dsvert_formal_cox_materialize_source(
    sealed$schema, covariate_peer, covariate_rows,
    covariate_root, binding)
  covariate_rows$x1[[1L]] <- covariate_rows$x1[[1L]] + 0.125
  changed_covariate_bundle <- .dsvert_formal_cox_materialize_source(
    sealed$schema, covariate_peer, covariate_rows,
    covariate_root, binding)
  expect_true(all(vapply(names(original_covariate_bundle$recipient_shares),
    function(recipient_name) {
      !identical(
        original_covariate_bundle$recipient_shares[[recipient_name]],
        changed_covariate_bundle$recipient_shares[[recipient_name]])
    }, logical(1L))))

  tampered <- bundle
  recipient <- names(tampered$recipient_shares)[[1L]]
  tampered$recipient_shares[[recipient]][[1L]] <-
    paste0("00", substring(tampered$recipient_shares[[recipient]][[1L]], 3L))
  expect_error(.dsvert_formal_cox_materialization_validate(
    tampered, sealed$schema, root, binding),
    class = "dsvert_formal_cox_error")
  for (field in c("capacity", "coordinate_count", "transcript_shape",
                  "alignment_gate", "fixture_transport", "opening",
                  "blocker")) {
    metadata_tamper <- bundle
    metadata_tamper[[field]] <- paste0(metadata_tamper[[field]], "-changed")
    expect_error(.dsvert_formal_cox_materialization_validate(
      metadata_tamper, sealed$schema, root, binding),
      class = "dsvert_formal_cox_error")
  }
  sealed_tamper <- bundle
  sealed_tamper$recipient_shares_sealed <- TRUE
  expect_error(.dsvert_formal_cox_materialization_validate(
    sealed_tamper, sealed$schema, root, binding),
    class = "dsvert_formal_cox_error")
  expect_error(.dsvert_formal_cox_materialization_validate(
    bundle, sealed$schema, as.raw(rep(8L, 32L)), binding),
    class = "dsvert_formal_cox_error")
  snapshot_replay <- tryCatch(
    .dsvert_formal_cox_materialization_validate(
      bundle, sealed$schema, root, as.raw(rep(10L, 32L))),
    error = identity)
  expect_s3_class(snapshot_replay, "dsvert_formal_cox_error")
  expect_identical(snapshot_replay$code,
                   "replayed_formal_cox_private_snapshot")

  other_unsigned <- sealed$schema$unsigned
  other_unsigned$logical_snapshot_id <- "cohort_v2"
  other <- .dsvert_formal_cox_schema_seal(
    other_unsigned, .formal_cox_sign(other_unsigned, sealed$keys))
  expect_error(.dsvert_formal_cox_materialization_validate(
    bundle, other, root, binding), class = "dsvert_formal_cox_error")

  rotated <- .formal_cox_schema(
    3L, logical_snapshot_id = sealed$schema$unsigned$logical_snapshot_id,
    fixture = fixture)
  expect_error(.dsvert_formal_cox_materialization_validate(
    bundle, rotated$schema, root, binding),
    class = "dsvert_formal_cox_error")
})

test_that("private reference has fixed work, no exact artifact and no opening", {
  fixture <- .formal_cox_fixture()
  sealed <- .formal_cox_schema(2L, fixture = fixture)
  rows <- .formal_cox_reference_rows(fixture, sealed$schema)
  numeric <- .dsvert_formal_cox_schema_numeric(sealed$schema)
  result <- .dsvert_formal_cox_private_reference(
    sealed$schema, rows,
    matrix(0, nrow = numeric$iterations, ncol = 2L))
  expect_identical(result$planned_final_openings, 1L)
  expect_identical(result$performed_openings, 0L)
  expect_false(result$exact_intermediates_returned)
  expect_false(result$production_ready)
  expect_false(any(c("score", "hessian", "risk_sets", "event_counts",
                     "loglik") %in% names(result)))
  overflow <- tryCatch(.dsvert_formal_cox_private_reference(
    sealed$schema, rows,
    matrix(.Machine$double.xmax,
           nrow = numeric$iterations, ncol = 2L)), error = identity)
  expect_s3_class(overflow, "dsvert_formal_cox_error")
  expect_identical(overflow$code, "formal_cox_reference_numeric_overflow")
  expect_identical(overflow$openings_performed, 0L)
})
