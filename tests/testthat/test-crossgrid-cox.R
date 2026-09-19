.cox_cross_server_fixture <- function(capacity = 16, beta_grid = NULL) {
  peers <- c("site_a", "site_b")
  keys <- stats::setNames(lapply(peers, function(peer) openssl::ed25519_keygen()), peers)
  b64 <- function(value) sub("=+$", "", chartr("+/", "-_",
    gsub("[\r\n]", "", jsonlite::base64_enc(value))))
  pins <- vapply(keys, function(key) b64(tail(as.raw(as.list(key)$pubkey), 32L)),
                 character(1L))
  policy <- list(peer_pinset = pins,
    peer_pinset_sha256 = .dsvert_joint_dp_hash(as.list(pins)),
    designated_noise_peers = peers, unit_capacity = capacity,
    numeric_grid_bits = 8, adjacency = "add_remove_patient")
  snapshot <- list(logical_snapshot_id = "cohort", version = "v1",
                   alignment_protocol_version = 1)
  schema_unsigned <- list(version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = snapshot, peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = list(aligned = list(dataset_id = "aligned", dataset_version = "v1",
      schema_version = "v1", alignment_group = "group",
      patient_keys = list(site_a = "patient", site_b = "patient"),
      columns = list(
        event = list(kind = "numeric", owner_peer = "site_a", lower = 0, upper = 1),
        time = list(kind = "numeric", owner_peer = "site_a", lower = 0, upper = 20),
        x = list(kind = "numeric", owner_peer = "site_a", lower = 0, upper = 1),
        z = list(kind = "numeric", owner_peer = "site_b", lower = 0, upper = 1)))))
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
  if (is.null(beta_grid)) beta_grid <- list(c(0, 0), c(1, -0.5), c(1, 0))
  beta_grid <- beta_grid[order(vapply(beta_grid, function(beta) {
    .dsvert_dp_canonical_json(as.list(beta))
  }, character(1L)), method = "radix")]
  raw <- list(version = "cox_grid_cross_v1", analysis_id = "cox_grid",
    dataset = "aligned", time = "site_a$time", event = "site_a$event",
    predictor_order = c("site_a$x", "site_b$z"), beta_grid = beta_grid,
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
