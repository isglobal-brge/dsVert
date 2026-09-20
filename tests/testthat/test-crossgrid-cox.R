.cox_cross_server_fixture <- function(capacity = 16, beta_grid = NULL, owners = 2L,
                                      time_owner_garbler = TRUE) {
  peers <- paste0("site_", letters[seq_len(owners)])
  keys <- stats::setNames(lapply(peers, function(peer) openssl::ed25519_keygen()), peers)
  b64 <- function(value) sub("=+$", "", chartr("+/", "-_",
    gsub("[\r\n]", "", jsonlite::base64_enc(value))))
  # Provision the routing owner before pinning identities or signing anything.
  ids <- vapply(keys[1:2], function(key)
    .dsvert_relay_peer_id(b64(tail(as.raw(as.list(key)$pubkey), 32L))), character(1L))
  selected <- order(ids, method = "radix")
  if (!time_owner_garbler) selected <- rev(selected)
  keys[1:2] <- unname(keys[selected])
  pins <- vapply(keys, function(key) b64(tail(as.raw(as.list(key)$pubkey), 32L)),
                 character(1L))
  policy <- list(peer_pinset = pins,
    peer_pinset_sha256 = .dsvert_joint_dp_hash(as.list(pins)),
    designated_noise_peers = peers[1:2], unit_capacity = capacity,
    numeric_grid_bits = 8, adjacency = "add_remove_patient")
  snapshot <- list(logical_snapshot_id = "cohort", version = "v1",
                   alignment_protocol_version = 1)
  schema_unsigned <- list(version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = snapshot, peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = list(aligned = list(dataset_id = "aligned", dataset_version = "v1",
      schema_version = "v1", alignment_group = "group",
      patient_keys = setNames(rep(list("patient"), owners), peers),
      columns = list(
        event = list(kind = "numeric", owner_peer = "site_a", lower = 0, upper = 1),
        time = list(kind = "numeric", owner_peer = "site_a", lower = 0, upper = 20),
        x = list(kind = "numeric", owner_peer = "site_a", lower = 0, upper = 1),
        z = list(kind = "numeric", owner_peer = "site_b", lower = 0, upper = 1)))))
  extra_predictors <- character()
  if (owners > 2L) for (peer in peers[-c(1L, 2L)]) {
    column <- paste0("x_", peer)
    schema_unsigned$datasets$aligned$columns[[column]] <- list(
      kind = "numeric", owner_peer = peer, lower = 0, upper = 1)
    extra_predictors <- c(extra_predictors, paste0(peer, "$", column))
  }
  sign_schema <- function(value) {
    value$signatures <- NULL
    message <- .dsvert_dp_capsule_schema_message(value)
    c(value, list(signatures = lapply(keys, function(key) {
      b64(openssl::ed25519_sign(message, key))
    })))
  }
  schema_manifest <- sign_schema(schema_unsigned)
  schema <- .dsvert_dp_capsule_schema(policy, snapshot,
    schema_manifest, .dsvert_relay_verify_message)
  if (is.null(beta_grid)) beta_grid <- lapply(list(c(0, 0), c(1, -0.5), c(1, 0)),
    function(beta) c(beta, rep(0, length(extra_predictors))))
  beta_grid <- beta_grid[order(vapply(beta_grid, function(beta) {
    .dsvert_dp_canonical_json(as.list(beta))
  }, character(1L)), method = "radix")]
  raw <- list(version = "cox_grid_cross_v1", analysis_id = "cox_grid",
    dataset = "aligned", time = "site_a$time", event = "site_a$event",
    predictor_order = c("site_a$x", "site_b$z", extra_predictors), beta_grid = beta_grid,
    alignment = list(version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1", alignment_group = "group",
      public_alignment_contract_sha256 = .dsvert_joint_dp_hash(list(
        logical_snapshot = schema$unsigned$logical_snapshot,
        alignment_group = "group", method = "pinned_psi_ordered_manifest_v1")),
      public_patient_dependent_hash = FALSE))
  spec <- .dsvert_dp_cox_grid_cross_spec(raw, policy, schema)
  artifact <- .dsvert_dp_cox_grid_cross_artifact(spec)
  sign <- function(value) {
    value$signatures <- NULL
    message <- .dsvert_dp_cox_grid_cross_message(value)
    c(value, list(signatures = lapply(keys, function(key) {
      b64(openssl::ed25519_sign(message, key))
    })))
  }
  contract <- sign(list(version = .DSVERT_DP_COX_GRID_CROSS_CONTRACT_VERSION,
    spec = spec, artifact = artifact,
    source_contract = .dsvert_dp_cox_grid_cross_source_contract(spec, artifact)))
  list(contract = contract, policy = policy, schema_manifest = schema_manifest,
       schema = schema, raw = raw, keys = keys, b64 = b64,
       sign = sign, sign_schema = sign_schema)
}


test_that("Cox server authenticates both signatures and rejects cap/profile tampering", {
  f <- .cox_cross_server_fixture()
  validate <- function(x) .dsvert_dp_cox_grid_cross_contract_validate(x, f$policy, f$schema_manifest)
  expect_identical(validate(f$contract), .dsvert_dp_canonical_query_value(f$contract))
  for (peer in names(f$keys)) {
    x <- f$contract; x$signatures[[peer]] <- NULL
    expect_error(validate(x), class = "dsvert_dp_public_failure")
  }
  for (field in c("ties", "numeric_contract", "sensitivity", "alignment")) {
    x <- f$contract; x$spec[[field]] <- NULL
    expect_error(validate(f$sign(x)), class = "dsvert_dp_public_failure")
  }
  x <- f$contract; x$artifact$runtime_enabled <- TRUE
  expect_error(validate(f$sign(x)), class = "dsvert_dp_public_failure")
  expect_false(.dsvert_dp_cox_grid_cross_register()$runtime_enabled)
  expect_error(.dsvert_dp_cox_grid_cross_register()$produce(), class = "dsvert_dp_public_failure")
})

test_that("pure R Cox integer profiles match all shared Go boundary fixtures", {
  f <- .cox_integer_profile()
  for (case in f$exp_cases) expect_equal(.cox_integer_exp(case$eta_q16), case$exp_q20)
  for (case in f$log_cases) expect_equal(.cox_integer_log(case$risk_q20), case$log_q20)
  for (n in c(2:50, 127, 1024, 10000)) {
    expect_gte(.dsvert_dp_cox_grid_cross_log_upper_q24(n) / 2^24, log(n))
  }
})

test_that("Cox whole-coordinate sensitivities cover changed risk sets", {
  set.seed(298)
  beta <- list(c(0, 0), c(1, -2), c(4, 4))
  for (adj in c("add_remove_patient", "replace_one_fixed_cohort")) {
    s <- .dsvert_dp_cox_grid_cross_sensitivity(beta, 18, 8, adj)
    caps <- unlist(s$maximum_coordinates)
    expect_equal(s$raw_l1_sensitivity, s$adjacency_multiplier * sum(caps))
    expect_gte(s$raw_l2_sensitivity, s$adjacency_multiplier * sqrt(sum(caps^2)))
    for (trial in 1:40) {
      x <- matrix(sample(0:65536, 16, replace=TRUE) / 65536, 8, 2)
      tm <- sample(0:3, 8, replace=TRUE); event <- sample(0:1, 8, replace=TRUE)
      live <- rep(TRUE, 8)
      evaluate <- function(x, tm, ev, live) vapply(seq_along(beta), function(j) {
        eta <- round(drop(x %*% beta[[j]]) * 65536)
        .cox_integer_loss(eta, tm, ev, live, caps[[j]], 18)
      }, numeric(1L))
      a <- evaluate(x, tm, event, live)
      if (adj == "add_remove_patient") live[[1]] <- FALSE else {
        x[1, ] <- 1 - x[1, ]; tm[[1]] <- 20 - tm[[1]]; event[[1]] <- 1 - event[[1]]
      }
      b <- evaluate(x, tm, event, live); d <- abs(a-b)
      expect_true(all(d <= s$adjacency_multiplier * caps))
      expect_lte(sum(d), s$raw_l1_sensitivity)
      expect_lte(sqrt(sum(d^2)), s$raw_l2_sensitivity)
    }
  }
})

test_that("Cox range cap encloses approximation and keeps error below DP noise", {
  for (n in c(2, 35, 10000)) for (bits in c(8, 16, 18)) {
    s <- .dsvert_dp_cox_grid_cross_sensitivity(list(c(4, 4)), bits, n, "add_remove_patient")
    expect_gte(s$maximum_coordinates[[1]] / 2^bits, n * (log(n) + 16 + 1/64))
  }
  s <- .dsvert_dp_cox_grid_cross_sensitivity(rep(list(c(4,4)),50), 18, 10000, "add_remove_patient")
  for (epsilon in c(1,4,8)) expect_lt(10000/64, s$natural_l1_sensitivity/epsilon/1000)
  for (beta in list(c(4,4,1), c(4+2^-40), c(NA_real_), numeric())) {
    expect_error(.dsvert_dp_cox_grid_cross_sensitivity(list(beta), 18, 2, "add_remove_patient"),
                 class="dsvert_dp_public_failure")
  }
})


test_that("Cox measured admission is enforced even with both valid signatures", {
  admission <- .dsvert_dp_cox_grid_cross_admission(2, 1)
  n <- admission$maximum_rows; j <- admission$maximum_candidates
  grid <- lapply(seq_len(j), function(i) c(i / 100, 0))
  f <- .cox_cross_server_fixture(capacity = n, beta_grid = grid)
  validate <- function(value) .dsvert_dp_cox_grid_cross_contract_validate(
    value, f$policy, f$schema_manifest)
  expect_silent(validate(f$contract))
  expect_identical(f$contract$spec$resource_admission, admission)
  expect_error(.cox_cross_server_fixture(capacity = n + 1), class = "dsvert_dp_public_failure")
  expect_error(.cox_cross_server_fixture(beta_grid = c(grid, list(c(1, 0)))),
    class = "dsvert_dp_public_failure")
  for (field in names(admission)) {
    changed <- f$contract
    changed$spec$resource_admission[[field]] <- NULL
    expect_error(validate(f$sign(changed)), class = "dsvert_dp_public_failure")
  }
  changed <- f$contract
  changed$spec$resource_admission$maximum_rows <- n + 1
  expect_error(validate(f$sign(changed)), class = "dsvert_dp_public_failure")
})


test_that("Cox signed layout pins the terminal share conversion for fusion", {
  f <- .cox_cross_server_fixture()
  layout <- f$contract$source_contract$private_layout
  expect_equal(layout$kernel_output_ring_bits, 64)
  expect_equal(layout$joint_dp_source_ring_bits, 128)
  expect_identical(layout$output_conversion,
    "mod64_reconstruct_cast_remask_in_authenticated_fusion_v1")
  changed <- f$contract
  changed$source_contract$private_layout$kernel_output_ring_bits <- 128
  expect_error(.dsvert_dp_cox_grid_cross_contract_validate(
    f$sign(changed), f$policy, f$schema_manifest), class = "dsvert_dp_public_failure")
})

test_that("Cox K-owner source contracts retain exactly two computation authorities", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .cox_cross_server_fixture(owners = owners)
    validate <- function(value) .dsvert_dp_cox_grid_cross_contract_validate(
      value, f$policy, f$schema_manifest)
    spec <- validate(f$contract)$spec
    expect_length(spec$participating_peers, owners)
    expect_identical(unlist(spec$computation_peers, use.names = FALSE), c("site_a", "site_b"))
    source <- f$contract$source_contract
    expect_identical(source$source_peers, spec$participating_peers)
    expect_identical(source$recipients, spec$computation_peers)
    layout <- .dsvert_dp_cox_grid_cross_layout(spec)
    expect_identical(layout$version, if (owners == 2L)
      "dsvert-cox-cross-private-source-layout-v1" else "dsvert-cox-cross-private-source-layout-v2")
    expect_identical(layout$partial_predictors, if (owners == 2L)
      "two_owners_exact_f100_additive_ring128_v1" else "all_source_owners_exact_f100_additive_ring128_v1")
    expect_identical(layout$release_prefix_source_rule,
      "all_zero_until_authenticated_result_injection_v1")
    expect_identical(spec$numeric_contract$eta_rounding, "one_rne_after_owner_sum_v1")
    for (peer in names(f$keys)) {
      changed <- f$contract; changed$signatures[[peer]] <- NULL
      expect_error(validate(changed), class = "dsvert_dp_public_failure")
    }
    for (mutate in list(
      function(x) { x$spec$participating_peers <- x$spec$participating_peers[-1]; x },
      function(x) { x$spec$computation_peers <- rev(x$spec$computation_peers); x },
      function(x) { x$source_contract$source_peers <- x$source_contract$source_peers[-1]; x },
      function(x) { x$source_contract$recipients <- x$source_contract$recipients[1]; x })) {
      expect_error(validate(f$sign(mutate(f$contract))), class = "dsvert_dp_public_failure")
    }
    for (compute in list("site_a", c("site_a", "site_a"), c("site_a", "absent"),
                         c("site_a", "site_b", "site_c"))) {
      policy <- f$policy; policy$designated_noise_peers <- compute
      expect_error(.dsvert_dp_cox_grid_cross_spec(f$raw, policy, f$schema),
        class = "dsvert_dp_public_failure")
    }
    if (owners > 2L) {
      changed <- f$contract
      changed$source_contract$private_layout$partial_predictors <-
        "two_owners_exact_f100_additive_ring128_v1"
      expect_error(validate(f$sign(changed)), class = "dsvert_dp_public_failure")
      raw <- f$raw; raw$predictor_order <- raw$predictor_order[-length(raw$predictor_order)]
      raw$beta_grid <- lapply(raw$beta_grid, function(beta) beta[-length(beta)])
      expect_error(.dsvert_dp_cox_grid_cross_spec(raw, f$policy, f$schema),
        class = "dsvert_dp_public_failure")
    }
  }
})

test_that("Cox staged source combines every signed owner in exact Ring128", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .cox_cross_server_fixture(capacity = 4, owners = owners)
    spec <- f$contract$spec
    count <- spec$padded_capacity * length(spec$beta_grid)
    inputs <- setNames(rep(list(raw(16 * count)), owners),
      unlist(spec$participating_peers, use.names = FALSE))
    # Wrap modulo 2^128 at coordinate zero, retaining a separate coordinate.
    inputs[[1L]][1:16] <- as.raw(255)
    inputs[[2L]][c(1L, 17L)] <- as.raw(c(1, 123))
    run <- function(values = inputs, validity = raw(count))
      .dsvert_dp_cox_cross_source_handoff(f$contract, f$policy, f$schema_manifest,
        strrep("1", 64), values, validity, raw(32 * spec$padded_capacity),
        raw(2 * spec$padded_capacity))
    result <- run()
    expected <- raw(16 * count); expected[[17L]] <- as.raw(123)
    expect_identical(jsonlite::base64_dec(result$predictors$Share), expected)
    expect_identical(result$plan$caps, as.list(sprintf("%.0f",
      unlist(spec$sensitivity$maximum_coordinates, use.names = FALSE))))
    expect_error(run(inputs[-1L]), class = "dsvert_dp_public_failure")
    expect_error(run(rev(inputs)), class = "dsvert_dp_public_failure")
    expect_error(run(validity = as.raw(rep(2, count))), class = "dsvert_dp_public_failure")
  }
})

test_that("Cox private routing retains ties censor slots and invalid padding", {
  route <- .dsvert_dp_cox_cross_private_routing(c(2, 5, 5, NA, -0),
    c(TRUE, TRUE, TRUE, FALSE, TRUE), 8)
  expect_identical(unlist(route$permutation), c(1L, 2L, 0L, 4L, 3L, 5L, 6L, 7L))
  expect_identical(unlist(route$ends), c(FALSE, TRUE, TRUE, TRUE, FALSE, FALSE, FALSE, TRUE))
  expect_error(.dsvert_dp_cox_cross_private_routing(c(1, Inf), c(TRUE, TRUE), 2),
    class = "dsvert_dp_public_failure")
  expect_error(.dsvert_dp_cox_cross_private_routing(c(1, 2), c(TRUE, TRUE), 3),
    class = "dsvert_dp_public_failure")
})

test_that("Cox public f50 multiplication preserves additive sharing and f100 precision", {
  word <- function(bytes) { value <- raw(16); value[seq_along(bytes)] <- as.raw(bytes); value }
  # -1 times a full-width random-looking share uses modular signed arithmetic.
  value <- as.raw(0:15)
  negated <- .dsvert_dp_cox_cross_multiply_public(value, -1)
  expect_identical(.dsvert_dp_capsule_source_add_ring128(value, negated), raw(16))
  expect_identical(.dsvert_dp_cox_cross_multiply_public(word(255), 257), word(c(255, 255)))
  expect_identical(.dsvert_dp_cox_cross_multiply_public(word(c(0, 1)), 2^50),
    c(raw(7), as.raw(4), raw(8)))
  left <- as.raw(255:240); right <- as.raw(239:224)
  for (coefficient in c(-2^52, -2^50, 0, 1, 2^50, 2^52)) {
    expect_identical(.dsvert_dp_cox_cross_multiply_public(
      .dsvert_dp_capsule_source_add_ring128(left, right), coefficient),
      .dsvert_dp_capsule_source_add_ring128(
        .dsvert_dp_cox_cross_multiply_public(left, coefficient),
        .dsvert_dp_cox_cross_multiply_public(right, coefficient)))
  }
  expect_error(.dsvert_dp_cox_cross_multiply_public(value, 0.5), class = "dsvert_dp_public_failure")
})

test_that("Cox owner materialization retains K2 K3 K5 candidate and owner order", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .cox_cross_server_fixture(capacity = 4, owners = owners)
    spec <- f$contract$spec
    predictors <- unlist(spec$predictor_order, use.names = FALSE)
    shares <- setNames(lapply(seq_along(predictors), function(index) {
      value <- raw(64); value[c(1, 17, 33, 49)] <- as.raw(index); value
    }), predictors)
    peers <- unlist(spec$participating_peers, use.names = FALSE)
    contributions <- setNames(lapply(peers, function(peer) {
      owned <- predictors[vapply(spec$predictors[predictors], function(x)
        identical(x$owner_peer, peer), logical(1))]
      .dsvert_dp_cox_cross_owner_predictors(f$contract, f$policy, f$schema_manifest,
        peer, shares[owned])
    }), peers)
    result <- .dsvert_dp_cox_cross_source_handoff(f$contract, f$policy,
      f$schema_manifest, strrep("2", 64), contributions,
      raw(4 * length(spec$beta_grid)), raw(128), raw(8))
    candidate_words <- lapply(spec$beta_encoded, function(beta) {
      out <- raw(16)
      for (column in seq_along(beta)) out <- .dsvert_dp_capsule_source_add_ring128(out,
        .dsvert_dp_cox_cross_multiply_public(shares[[column]][1:16], as.numeric(beta[[column]])))
      out
    })
    expect_identical(jsonlite::base64_dec(result$predictors$Share), rep(do.call(c, candidate_words), 4))
    expect_error(.dsvert_dp_cox_cross_owner_predictors(f$contract, f$policy,
      f$schema_manifest, peers[[1]], shares), class = "dsvert_dp_public_failure")
  }
})

test_that("Cox source block layout covers every owner without transporting observed times", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .cox_cross_server_fixture(capacity = 5, owners = owners)
    artifact <- c(f$contract$artifact, list(signed_contract =
      .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(f$contract))))
    projection <- .dsvert_dp_cox_cross_source_blocks(artifact, 7)
    blocks <- projection$blocks
    expect_equal(length(blocks), 2 * length(f$contract$spec$predictors) + 3)
    expect_equal(projection$cursor, 7 + 8 * length(blocks))
    expect_setequal(vapply(blocks, `[[`, character(1), "owner_peer"),
      unlist(f$contract$spec$participating_peers, use.names = FALSE))
    time <- blocks[vapply(blocks, `[[`, logical(1), "private_time_validity")]
    expect_length(time, 1)
    expect_identical(time[[1]]$kind, "validity")
    expect_identical(time[[1]]$fraction_bits, 0L)
    expect_true(all(vapply(blocks, function(block) block$length == 8L, logical(1))))
  }
})

# Explicit runtime overlay enables the actual CLI bridge in release proofs.
if (nzchar(Sys.getenv("DSVERT_COX_STAGED_TEST_BINARY"))) {
  test_that("signed Cox K2 K3 K5 handoffs cross the actual native CLI boundary", {
    binary <- Sys.getenv("DSVERT_COX_STAGED_TEST_BINARY")
    expect_true(file.exists(binary))
    withr::local_options(dsvert.mpc_binary = normalizePath(binary))
    directory <- tempfile("cox-native-owner-"); dir.create(directory, mode = "0700")
    other_directory <- tempfile("cox-native-evaluator-"); dir.create(other_directory, mode = "0700")
    on.exit(unlink(c(directory, other_directory), recursive = TRUE), add = TRUE)
    for (owners in c(2L, 3L, 5L)) {
      f <- .cox_cross_server_fixture(capacity = 4, owners = owners)
      spec <- f$contract$spec
      peers <- unlist(spec$participating_peers, use.names = FALSE)
      count <- 4 * length(spec$beta_grid)
      contributions <- setNames(rep(list(raw(16 * count)), owners), peers)
      handoff <- .dsvert_dp_cox_cross_source_handoff(f$contract, f$policy,
        f$schema_manifest, strrep("2", 64), contributions, raw(count), raw(128), raw(8))
      route <- .dsvert_dp_cox_cross_private_routing(c(2, 5, 5, 1), rep(TRUE, 4), 4)
      prepare <- function(role, routing, digest = "", value = handoff) {
        .dsvert_dp_cox_cross_prepare_native(value, role, paste0("cox-r-native-k", owners),
          c("a", "b"), strrep("3", 64),
          if (role == "garbler") directory else other_directory,
          as.raw(rep(if (role == "garbler") 7 else 8, 32)), routing, digest)
      }
      owner <- prepare("garbler", route)
      evaluator <- prepare("evaluator", NULL, owner$routing_digest)
      expect_identical(owner$stage_plan_digest, evaluator$stage_plan_digest)
      expect_identical(owner$purpose, evaluator$purpose)
      expect_equal(owner$vector_len, length(spec$beta_grid))
      expect_identical(owner$operation, "cox-loss-staged-v1")
      expect_type(owner$cox_loss, "character")
      expect_false(identical(owner$cox_loss, evaluator$cox_loss))
      native <- jsonlite::fromJSON(rawToChar(jsonlite::base64_dec(owner$cox_loss)),
        simplifyVector = FALSE)
      expect_equal(unlist(native$spec$Cox$Plan$spec$caps),
        as.numeric(unlist(handoff$plan$caps)))
      expect_error(prepare("evaluator", route, owner$routing_digest))
      expect_error(prepare("garbler", route, strrep("9", 64)))
      tampered <- handoff; tampered$plan$caps[[1]] <- "1e5"
      expect_error(prepare("garbler", route, value = tampered))
    }
  })
}

.cox_transport_fixture <- function(f) {
  artifact <- .dsvert_dp_cox_cross_workload_artifact(f$contract)
  families <- setNames(rep(list(list(artifacts = list())), 10L), c(
    "admitted_count", "numeric_moments", "numeric_pair_moments", "gaussian_models",
    "fixed_numeric_histograms", "categorical_marginals", "categorical_pairs",
    "correlation_artifacts", "describe_artifacts", "survival_artifacts"))
  families$admitted_count <- list(owner_peer = "site_a", dataset = "aligned")
  families$survival_artifacts <- list()
  families$gaussian_models$artifacts <- list(cox_grid = artifact)
  manifest <- list(logical_snapshot = f$contract$spec$logical_snapshot,
    capsule_identity = list(capsule_id = strrep("6", 64)),
    workload = list(coordinate_count = artifact$coordinate_count + 1L,
      families = families, capsule_mechanism = list(source_context_hash = strrep("a", 64))))
  layout <- .dsvert_dp_cox_cross_transport_layout(manifest, artifact)
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

test_that("Cox workload and source context authenticate K-owner transport without time values", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .cox_cross_server_fixture(capacity = 17, owners = owners)
    t <- .cox_transport_fixture(f)
    context <- function(manifest = t$manifest, transport = t$transport) {
      .dsvert_dp_cox_cross_source_context(f$policy, manifest, transport,
        f$schema_manifest, "cox_grid")
    }
    validated <- context()
    expect_identical(validated$spec, .dsvert_dp_canonical_query_value(f$contract$spec))
    expect_false(t$artifact$intercept)
    expect_false(t$artifact$runtime_enabled)
    expect_null(t$artifact$outcome)
    expect_null(t$artifact$grouping)
    expect_identical(t$artifact$numeric_certificate, f$contract$spec$numeric_contract)
    expect_identical(t$artifact$statistic_maximum, f$contract$spec$sensitivity$maximum_coordinates)
    expect_equal(t$layout$private_start, 8193)
    expect_identical(unlist(t$layout$source_peers), paste0("site_", letters[seq_len(owners)]))
    expect_length(t$layout$computation_peers, 2L)
    blocks <- t$layout$blocks
    time <- blocks[vapply(blocks, function(b) b$private_time_validity, logical(1))]
    expect_length(time, 1L)
    expect_identical(time[[1L]]$kind, "validity")
    expect_true(all(vapply(blocks, function(b) b$length == 32L, logical(1))))
    for (field in c("workload_sha256", "logical_snapshot_sha256", "peer_pinset_sha256",
        "coordinate_order_sha256", "private_layout_sha256", "source_context_hash")) {
      changed <- t$transport; changed[[field]] <- strrep("b", 64)
      expect_error(context(transport = changed))
    }
    changed <- t$manifest
    changed$workload$families$gaussian_models$artifacts$cox_grid$intercept <- TRUE
    expect_error(context(manifest = changed), class = "dsvert_dp_public_failure")
    changed <- t$manifest
    changed$logical_snapshot$version <- "other"
    expect_error(context(manifest = changed), class = "dsvert_dp_public_failure")
    changed <- t$transport; changed$source_peers <- changed$source_peers[-owners]
    expect_error(context(transport = changed))
  }
})

test_that("Cox source alignment requires the signed time owner at the actual garbler", {
  for (time_owner_garbler in c(TRUE, FALSE)) {
    f <- .cox_cross_server_fixture(time_owner_garbler = time_owner_garbler)
    for (peer in c("site_a", "site_b")) {
      other <- setdiff(c("site_a", "site_b"), peer)
      f$policy$peer_name <- peer
      ss <- new.env(parent = emptyenv())
      ss$.exact_gc_transport_initialized <- TRUE
      ss$.exact_gc_self_name <- peer
      ss$.exact_gc_peer_binding_digest <- strrep("8", 64)
      ss$peer_transport_pks <- setNames(list("private-test-transport"), other)
      ss$.exact_gc_peer_identity_pks <- as.list(f$policy$peer_pinset[other])
      .key_put("identity_pk", unname(f$policy$peer_pinset[[peer]]), ss)
      batches <- .dsvert_dp_alignment_mask_batches(ss)
      batch <- new.env(parent = emptyenv())
      batch$status <- "complete"
      batch$capsule_id <- "cox-route-fixture"
      batch$contract_hash <- strrep("2", 64)
      batch$peer_binding_digest <- ss$.exact_gc_peer_binding_digest
      batch$terminal_peer_blob_digest <- strrep("9", 64)
      batch$first_validity_share <- jsonlite::base64_enc(as.raw(1))
      batches$fixture <- batch
      # Both cases have authentic signed contracts and matching live keys.
      # Only the pre-signing identity-to-owner assignment differs.
      expect_no_error(.dsvert_dp_cox_grid_cross_contract_validate(
        f$contract, f$policy, f$schema_manifest))
      align <- function() .dsvert_dp_cox_cross_source_alignment(
        f$contract$spec, f$policy, ss, batch$capsule_id, batch$contract_hash)
      if (time_owner_garbler) expect_identical(align(), batch) else
        expect_error(align(), class = "dsvert_dp_public_failure")
    }
  }
})

test_that("Cox owner time sidecar binds exact times and committed source order", {
  for (owners in c(2L, 3L, 5L)) {
    f <- .cox_cross_server_fixture(capacity = 5, owners = owners)
    t <- .cox_transport_fixture(f)
    f$policy$peer_name <- "site_a"
    secret <- as.raw(seq_len(32L))
    times <- c(2, 5, 5, NA_real_, -0)
    valid <- c(TRUE, TRUE, TRUE, FALSE, TRUE)
    block <- t$layout$blocks[["cox_grid::site_a$time::validity"]]
    payload <- numeric(t$layout$transport_coordinate_count)
    payload[seq.int(block$start, length.out = block$length)] <- c(as.numeric(valid), 0, 0, 0)
    producer <- structure(list(
      version = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_VERSION,
      purpose = .DSVERT_DP_CAPSULE_LOCAL_MATERIAL_PURPOSE,
      capsule_id = t$transport$capsule_id, peer_name = "site_a",
      logical_snapshot = f$contract$spec$logical_snapshot,
      source_context_hash = t$transport$source_context_hash,
      coordinate_count = t$layout$transport_coordinate_count,
      coordinate_order_sha256 = t$layout$transport_coordinate_order_sha256,
      snapshot_binding_sha256 = strrep("c", 64),
      producer_version = .DSVERT_DP_GAUSSIAN_CROSS_SOURCE_PRODUCER_VERSION,
      state = "internal_incremental_secret_share_input_never_release",
      value_commitment_sha256 = strrep("d", 64), authenticatable_sha256 = strrep("e", 64),
      private_alignment_consensus_hash = strrep("f", 64),
      read_range = function(start, count) payload[seq.int(start, length.out = count)],
      generation_chunks = function(...) list(), reset = function() invisible(NULL)),
      class = c("dsvert_capsule_source_producer", "list"))
    make <- function(current_times = times, current_valid = valid, current_producer = producer,
                     policy = f$policy) {
      .dsvert_dp_cox_cross_route_sidecar(policy, secret, t$manifest, t$transport,
        f$schema_manifest, "cox_grid", current_producer, current_times, current_valid)
    }
    sidecar <- make()
    read <- function(value = sidecar, current_times = times, current_producer = producer,
                     current_secret = secret) {
      .dsvert_dp_cox_cross_route_handoff(value, f$policy, current_secret, t$manifest,
        t$transport, f$schema_manifest, "cox_grid", current_producer, current_times, valid)
    }
    expect_identical(read(), list(permutation = as.list(c(1L, 2L, 0L, 4L, 3L, 5L, 6L, 7L)),
      ends = as.list(c(FALSE, TRUE, TRUE, TRUE, FALSE, FALSE, FALSE, TRUE))))
    cold <- jsonlite::fromJSON(.dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(sidecar)), simplifyVector = FALSE)
    expect_equal(read(cold), read())
    # Invalid placeholders and the sign of zero cannot change private routing.
    expect_identical(make(c(2, 5, 5, Inf, 0)), sidecar)
    expect_false(any(c("times", "time_valid", "labels") %in% names(sidecar)))
    # Distinct binary64 observations with the SAME ordering are still different
    # sources; decimal JSON rounding must not erase this difference.
    changed_times <- times; changed_times[1L] <- 2 + 2^-51
    expect_identical(make(changed_times)$routing, sidecar$routing)
    expect_false(identical(make(changed_times)$binding$private_time_mac,
      sidecar$binding$private_time_mac))
    expect_error(read(current_times = changed_times), class = "dsvert_dp_public_failure")
    for (field in c("snapshot_binding_sha256", "value_commitment_sha256",
                    "authenticatable_sha256", "private_alignment_consensus_hash",
                    "coordinate_order_sha256")) {
      changed <- producer; changed[[field]] <- strrep("0", 64)
      expect_error(read(current_producer = changed), class = "dsvert_dp_public_failure")
    }
    changed <- producer; changed$private_alignment_consensus_hash <- "not_applicable"
    expect_error(make(current_producer = changed), class = "dsvert_dp_public_failure")
    changed <- sidecar; changed$routing$ends[[1L]] <- TRUE
    expect_error(read(changed), class = "dsvert_dp_public_failure")
    changed <- sidecar; changed$routing$permutation <- rev(changed$routing$permutation)
    expect_error(read(changed), class = "dsvert_dp_public_failure")
    expect_error(read(current_secret = raw(32)), class = "dsvert_dp_public_failure")
    expect_error(make(c(2, 21, 5, NA, 0)), class = "dsvert_dp_public_failure")
    expect_error(make(c(2, Inf, 5, NA, 0)), class = "dsvert_dp_public_failure")
    expect_error(make(times[-1L]), class = "dsvert_dp_public_failure")
    expect_error(make(current_valid = rep(TRUE, 5)), class = "dsvert_dp_public_failure")
    policy <- f$policy; policy$peer_name <- "site_b"
    expect_error(make(policy = policy), class = "dsvert_dp_public_failure")
    payload[block$start] <- 0
    expect_error(read(), class = "dsvert_dp_public_failure")
  }
})

test_that("Cox input loader verifies actual store MACs and all-owner completion", {
  f <- .cox_cross_server_fixture(capacity = 16, owners = 5L)
  transport_fixture <- .cox_transport_fixture(f)
  f[names(transport_fixture)] <- transport_fixture
  f$policy$peer_name <- "site_a"
  f$secret <- as.raw(seq_len(32L))
  f$ss <- new.env(parent = emptyenv())
  f$ss$.exact_gc_peer_binding_digest <- strrep("8", 64)
  f$ss$.exact_gc_transport_initialized <- TRUE
  f$ss$.exact_gc_self_name <- "site_a"
  f$ss$peer_transport_pks <- list(site_b = "private-test-transport")
  f$ss$.exact_gc_peer_identity_pks <- as.list(f$policy$peer_pinset["site_b"])
  .key_put("identity_pk", unname(f$policy$peer_pinset[["site_a"]]), f$ss)
  batches <- .dsvert_dp_alignment_mask_batches(f$ss)
  batch <- new.env(parent = emptyenv())
  batch$status <- "complete"
  batch$peer_binding_digest <- f$ss$.exact_gc_peer_binding_digest
  batch$terminal_peer_blob_digest <- strrep("9", 64)
  batch$first_validity_share <- jsonlite::base64_enc(as.raw(1))
  batches$fixture <- batch
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
    recipient_name = "site_a", next_source_index = 6, next_chunk_index = 0,
    complete = TRUE, private_alignment_consensus_shares = setNames(
      rep(list(.dsvert_relay_b64url_encode(raw(32))), 5L), unlist(artifact$participating_peers)))
  .dsvert_dp_capsule_source_record_insert(con, "source_incoming_state", "capsule_id",
    list(transport$capsule_id), state, f$secret)
  all_bytes <- raw(16 * layout$transport_coordinate_count)
  variables <- c(unlist(f$contract$spec$predictor_order), f$contract$spec$event$reference,
    f$contract$spec$time$reference)
  validities <- setNames(vector("list", length(variables)), variables)
  values <- validities[setdiff(variables, f$contract$spec$time$reference)]
  for (i in seq_along(layout$blocks)) {
    block <- layout$blocks[[i]]
    bytes <- as.raw(rep(i * 16 + seq_len(block$length), each = 16))
    all_bytes[seq.int((block$start - 1) * 16 + 1, length.out = length(bytes))] <- bytes
    variable <- block$reference
    if (block$kind == "value") values[[variable]] <- bytes else validities[[variable]] <- bytes
  }
  records <- lapply(seq_len(transport$chunk_count) - 1, function(index) {
    geometry <- .dsvert_dp_capsule_source_chunk_geometry(transport, index)
    bytes <- all_bytes[seq.int(geometry$offset * 16 + 1, length.out = geometry$count * 16)]
    record <- list(version = .DSVERT_DP_CAPSULE_SOURCE_STORE_VERSION,
      capsule_id = transport$capsule_id, contract_hash = source_hash,
      recipient_name = "site_a", chunk_index = index, coordinates_in_chunk = geometry$count,
      source_count = 5, aggregate_b64 = .dsvert_dp_capsule_source_raw_b64(bytes))
    .dsvert_dp_capsule_source_record_insert(con, "source_aggregate_chunks",
      c("capsule_id", "chunk_index"), list(transport$capsule_id, index), record, f$secret)
    record
  })
  # Only connection acquisition is replaced. Real private row MACs, source
  # contract identities, source counts, chunk geometry and bytes are verified.
  local_mocked_bindings(.dsvert_dp_capsule_source_with_store = function(policy, secret, code) code(con))
  load <- function(current_manifest = manifest, current_transport = transport) {
    .dsvert_dp_cox_cross_load_inputs(f$policy, f$secret, current_manifest,
      current_transport, f$schema_manifest, f$ss, "cox_grid")
  }
  expected <- list(context = .dsvert_dp_cox_cross_source_context(f$policy,
    manifest, transport, f$schema_manifest, "cox_grid"), values = values, validities = validities)
  expect_identical(load(), expected)
  # Keep the authenticated peer names and alignment digest unchanged while
  # substituting another owner's real key. Both transport roles must reject.
  f$ss$.exact_gc_peer_identity_pks$site_b <- unname(f$policy$peer_pinset[["site_c"]])
  expect_error(load(), class = "dsvert_dp_public_failure")
  f$ss$.exact_gc_peer_identity_pks$site_b <- unname(f$policy$peer_pinset[["site_b"]])
  .key_put("identity_pk", unname(f$policy$peer_pinset[["site_c"]]), f$ss)
  expect_error(load(), class = "dsvert_dp_public_failure")
  .key_put("identity_pk", unname(f$policy$peer_pinset[["site_a"]]), f$ss)
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
  changed_manifest$workload$families$gaussian_models$artifacts$cox_grid$time$owner_peer <- "site_b$other"
  expect_error(load(current_manifest = changed_manifest), class = "dsvert_dp_public_failure")
  changed_transport <- transport
  changed_transport$workload_sha256 <- strrep("0", 64)
  expect_error(load(current_transport = changed_transport))
  expect_identical(load(), expected)
})
