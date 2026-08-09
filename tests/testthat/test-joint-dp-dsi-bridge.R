.dsi_joint_b64url <- function(value) {
  encoded <- gsub("[\r\n]", "", jsonlite::base64_enc(value))
  sub("=+$", "", chartr("+/", "-_", encoded), perl = TRUE)
}

.dsi_joint_fixture <- function(k = 3L) {
  stopifnot(k %in% 3:5)
  root <- tempfile("joint-dp-dsi-")
  dir.create(root)
  peers <- paste0("peer_", letters[seq_len(k)])
  pins <- stats::setNames(vapply(seq_along(peers), function(index) {
    .dsi_joint_b64url(as.raw(seq_len(32L) + 32L * (index - 1L)))
  }, character(1L)), peers)
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  make_policy <- function(peer, offset) {
    key <- as.raw((seq_len(32L) + offset) %% 256L)
    list(
      domain = "joint-dsi-study", cohort_id = "joint-dsi-cohort",
      peer_name = peer, peer_pinset = pins,
      peer_pinset_sha256 = pin_hash, peer_count = as.integer(k),
      designated_noise_peers = c("peer_a", "peer_c"),
      global_total_epsilon = 1, global_total_delta = 1e-6, decay = 0.5,
      lifetime_max_distinct_capsules = 8,
      adjacency = "add_remove_patient", patient_column = "patient_id",
      unit_capacity = 100L, max_records_per_unit = 2L,
      overflow_policy = "reject_snapshot",
      noise_root = list(
        protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
        provider_id = "joint_dp_dsi_test_provider",
        epoch = 1, key_id = paste0("joint-dsi-key-", peer),
        hmac = function(message) digest::hmac(
          key, message, algo = "sha256", serialize = FALSE)),
      ledger_path = file.path(root, paste0(peer, ".sqlite")),
      ledger_private = FALSE, lock_timeout_ms = 30000L,
      anchor_provider = NULL)
  }
  signing_keys <- list(
    peer_a = charToRaw("joint-dsi-signing-a"),
    peer_c = charToRaw("joint-dsi-signing-c"))
  signer <- function(message, peer_name, identity_pk) {
    digest::hmac(
      signing_keys[[peer_name]], message, algo = "sha256",
      serialize = FALSE)
  }
  verifier <- function(message, identity_pk, signature, peer_name) {
    identical(signature, digest::hmac(
      signing_keys[[peer_name]], message, algo = "sha256",
      serialize = FALSE))
  }
  list(
    root = root, pins = pins,
    policies = list(
      peer_a = make_policy("peer_a", 96L),
      peer_c = make_policy("peer_c", 160L)),
    secrets = list(
      peer_a = as.raw(128L + seq_len(32L)),
      peer_c = as.raw(192L + seq_len(32L))),
    signer = signer, verifier = verifier)
}

.dsi_joint_mechanism <- function() {
  list(
    release_scope = .DSVERT_JOINT_DP_SCOPE,
    capability_id = .DSVERT_JOINT_DP_CAPABILITY,
    producer = "chisq.cross.count-vector.v1",
    purpose = "k2_chisq_cross_count_shares",
    source_context_hash = strrep("a", 64L),
    mechanism = "discrete-laplace",
    mechanism_version = "joint-sampler-v1",
    sampler = .DSVERT_JOINT_DP_SAMPLER,
    sensitivity_norm = "l1", sensitivity = 2,
    coordinate_count = 4L, uses_delta = FALSE,
    clipping_hash = strrep("b", 64L), ring_bits = 63L, frac_bits = 20L)
}

.dsi_joint_proposals <- function(fixture) {
  snapshot <- list(
    logical_snapshot_id = "aligned-cohort-v1", version = "v1",
    alignment_protocol_version = 1L)
  mechanism <- .dsi_joint_mechanism()
  values <- lapply(names(fixture$policies), function(peer) {
    policy <- fixture$policies[[peer]]
    capsule_identity <- .dsvert_joint_dp_capsule_identity(
      policy, snapshot,
      capsule_schema = "dsi-test-capsule-v1",
      admission = list(
        adjacency = policy$adjacency,
        unit_capacity = policy$unit_capacity,
        max_records_per_unit = policy$max_records_per_unit,
        overflow_policy = policy$overflow_policy),
      bounds = list(clipping_hash = mechanism$clipping_hash),
      workload = list(
        capsule_mechanism = mechanism,
        schema_hash = strrep("7", 64L),
        workload_version = "dsi-test-workload-v1"))
    .dsvert_joint_dp_proposal(
      policy, snapshot, "chisq_cross",
      list(alpha = 1L, tag = "dsi"),
      digest::digest(
        paste0("private-snapshot-", peer), algo = "sha256",
        serialize = FALSE),
      mechanism, capsule_identity = capsule_identity,
      .secret = fixture$secrets[[peer]])
  })
  stats::setNames(values, names(fixture$policies))
}

.dsi_joint_call <- function(fixture, peer, fun, ...) {
  do.call(fun, c(list(...), list(
    .policy = fixture$policies[[peer]],
    .secret = fixture$secrets[[peer]],
    .signer = fixture$signer,
    .verifier = fixture$verifier)))
}

.dsi_joint_allocate <- function(fixture) {
  peers <- sort(names(fixture$policies), method = "radix")
  leader <- peers[[1L]]
  follower <- peers[[2L]]
  proposals <- .dsi_joint_proposals(fixture)
  tokens <- stats::setNames(lapply(peers, function(peer) {
    .dsvert_joint_dp_dsi_mint_proposal(
      fixture$policies[[peer]], proposals[[peer]],
      .secret = fixture$secrets[[peer]])
  }), peers)
  prepares <- list()
  prepares[[leader]] <- .dsvert_joint_dp_dsi_prepare_impl(
    tokens[[leader]], leader_prepare_json = "",
    .policy = fixture$policies[[leader]],
    .secret = fixture$secrets[[leader]], .signer = fixture$signer,
    .verifier = fixture$verifier)
  prepares[[follower]] <- .dsvert_joint_dp_dsi_prepare_impl(
    tokens[[follower]], leader_prepare_json = prepares[[leader]],
    .policy = fixture$policies[[follower]],
    .secret = fixture$secrets[[follower]], .signer = fixture$signer,
    .verifier = fixture$verifier)
  prepares <- prepares[peers]
  commits <- stats::setNames(lapply(peers, function(peer) {
    .dsi_joint_call(
      fixture, peer, .dsvert_joint_dp_dsi_commit_impl,
      first_prepare_json = prepares[[peers[[1L]]]],
      second_prepare_json = prepares[[peers[[2L]]]])
  }), peers)
  authorizations <- stats::setNames(lapply(peers, function(peer) {
    .dsi_joint_call(
      fixture, peer, .dsvert_joint_dp_dsi_authorize_impl,
      first_commit_json = commits[[peers[[1L]]]],
      second_commit_json = commits[[peers[[2L]]]])
  }), peers)
  openings <- stats::setNames(lapply(peers, function(peer) {
    .dsi_joint_call(
      fixture, peer, .dsvert_joint_dp_dsi_open_impl,
      first_authorization_json = authorizations[[peers[[1L]]]],
      second_authorization_json = authorizations[[peers[[2L]]]])
  }), peers)
  list(
    proposals = proposals, tokens = tokens, prepares = prepares,
    commits = commits, authorizations = authorizations, openings = openings)
}

test_that("DSI bridge binds full K pinset and replays every allocation phase", {
  roots <- character()
  on.exit(unlink(roots, recursive = TRUE), add = TRUE)
  for (k in 3:5) {
    fixture <- .dsi_joint_fixture(k)
    roots <- c(roots, fixture$root)
    flow <- .dsi_joint_allocate(fixture)
    designated <- names(fixture$policies)

    expect_length(unique(vapply(
      flow$proposals, `[[`, character(1L), "query_id")), 1L)
    for (peer in designated) {
      prepare <- .dsvert_joint_dp_dsi_receipt(
        flow$prepares[[peer]], "test prepare")
      opening <- .dsvert_joint_dp_dsi_receipt(
        flow$openings[[peer]], "test opening")
      expect_identical(prepare$peer_name, peer)
      expect_identical(opening$capability_available, FALSE)
      expect_identical(
        .dsvert_joint_dp_dsi_prepare_impl(
          flow$tokens[[peer]],
          leader_prepare_json = if (identical(peer, designated[[1L]])) {
            ""
          } else {
            flow$prepares[[designated[[1L]]]]
          },
          .policy = fixture$policies[[peer]],
          .secret = fixture$secrets[[peer]], .signer = fixture$signer,
          .verifier = fixture$verifier),
        flow$prepares[[peer]])
      expect_identical(.dsi_joint_call(
        fixture, peer, .dsvert_joint_dp_dsi_open_impl,
        first_authorization_json = flow$authorizations[[designated[[1L]]]],
        second_authorization_json = flow$authorizations[[designated[[2L]]]]),
        flow$openings[[peer]])
    }
    context <- .dsvert_joint_dp_policy_context(fixture$policies$peer_a)
    expect_identical(context$common$peer_count, as.numeric(k))
    expect_identical(context$common$designated_noise_peers,
                     c("peer_a", "peer_c"))
    expect_identical(
      names(context$common$ordered_peer_pinset), names(fixture$pins))
  }
})

test_that("proposal authentication and receipt conflicts fail closed", {
  fixture <- .dsi_joint_fixture()
  on.exit(unlink(fixture$root, recursive = TRUE), add = TRUE)
  proposals <- .dsi_joint_proposals(fixture)
  token <- .dsvert_joint_dp_dsi_mint_proposal(
    fixture$policies$peer_a, proposals$peer_a,
    .secret = fixture$secrets$peer_a)
  decoded <- .dsvert_joint_dp_dsi_decode(
    token, "test token", .DSVERT_JOINT_DP_DSI_MAX_PROPOSAL_BYTES)
  decoded$proposal$common_query$capsule_identity$workload$coordinate_count <- 5
  tampered <- .dsvert_joint_dp_dsi_encode(
    decoded, "test token", .DSVERT_JOINT_DP_DSI_MAX_PROPOSAL_BYTES)
  expect_error(.dsvert_joint_dp_dsi_prepare_impl(
    tampered, .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer),
    "proposal token is invalid")
  expect_error(.dsvert_joint_dp_dsi_prepare_impl(
    paste0(" ", token), .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer),
    "non-canonical")

  follower_token <- .dsvert_joint_dp_dsi_mint_proposal(
    fixture$policies$peer_c, proposals$peer_c,
    .secret = fixture$secrets$peer_c)
  expect_error(.dsvert_joint_dp_dsi_prepare_impl(
    follower_token, .policy = fixture$policies$peer_c,
    .secret = fixture$secrets$peer_c, .signer = fixture$signer,
    .verifier = fixture$verifier),
    "requires the signed leader assignment")

  leader_json <- .dsvert_joint_dp_dsi_prepare_impl(
    token, .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)
  rebound <- .dsvert_joint_dp_dsi_receipt(
    leader_json, "test leader prepare")
  rebound$capsule_id <- strrep("9", 64L)
  rebound$query_id <- strrep("9", 64L)
  rebound$signature <- NULL
  rebound <- .dsvert_joint_dp_sign(
    rebound, fixture$policies$peer_a, fixture$signer)
  expect_error(.dsvert_joint_dp_dsi_prepare_impl(
    follower_token,
    leader_prepare_json = .dsvert_joint_dp_dsi_receipt_json(
      rebound, "test rebound leader prepare"),
    .policy = fixture$policies$peer_c,
    .secret = fixture$secrets$peer_c, .signer = fixture$signer,
    .verifier = fixture$verifier),
    "does not match the local proposal")

  flow <- .dsi_joint_allocate(fixture)
  bad <- .dsvert_joint_dp_dsi_receipt(
    flow$prepares$peer_c, "test prepare")
  bad$capsule_id <- strrep("f", 64L)
  bad$query_id <- strrep("f", 64L)
  bad <- .dsvert_joint_dp_dsi_receipt_json(bad, "test prepare")
  expect_error(.dsi_joint_call(
    fixture, "peer_a", .dsvert_joint_dp_dsi_commit_impl,
    first_prepare_json = flow$prepares$peer_a,
    second_prepare_json = bad), "signature|allocation")
  expect_error(dsvertJointDPPrepareDS("{}"),
               "Joint-DP DSI prepare failed closed", fixed = TRUE)
})

test_that("result receipts commit durably without exposing payload bytes", {
  fixture <- .dsi_joint_fixture()
  on.exit(unlink(fixture$root, recursive = TRUE), add = TRUE)
  flow <- .dsi_joint_allocate(fixture)
  peers <- names(fixture$policies)
  openings <- lapply(flow$openings, .dsvert_joint_dp_dsi_receipt,
                     what = "test opening")
  contract_hash <- digest::digest(
    "joint-dsi-result-contract", algo = "sha256", serialize = FALSE)
  payloads <- list(
    peer_a = as.raw(7L),
    peer_c = as.raw(9L))
  results <- stats::setNames(lapply(peers, function(peer) {
    receipt <- .dsvert_joint_dp_result_prepare(
      fixture$policies[[peer]], openings[[peer]],
      openings[[setdiff(peers, peer)]], payloads[[peer]], contract_hash,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier)
    .dsvert_joint_dp_dsi_receipt_json(receipt, "test result receipt")
  }), peers)
  for (peer in peers) {
    receipt <- .dsvert_joint_dp_dsi_receipt(
      results[[peer]], "test result receipt")
    expect_identical(
      receipt$version, "dsvert-joint-dp-result-prepare-receipt-v2")
    expect_true(grepl("^[0-9a-f]{64}$", receipt$payload_commitment))
    expect_false(any(c("payload", "payload_b64", "payload_hash") %in%
                     names(receipt)))
    old_dictionary <- vapply(0:255, function(candidate) {
      digest::digest(c(
        charToRaw(paste0(
          "dsVert/joint-dp/result-payload/v1|", receipt$query_id, "|",
          receipt$opening_set_hash, "|", receipt$result_contract_hash, "|")),
        as.raw(candidate)), algo = "sha256", serialize = FALSE)
    }, character(1L))
    expect_false(receipt$payload_commitment %in% old_dictionary)
  }
  tampered_result <- .dsvert_joint_dp_dsi_receipt(
    results[[peers[[2L]]]], "test result receipt")
  tampered_result$payload_commitment <- strrep("f", 64L)
  expect_error(.dsi_joint_call(
    fixture, peers[[1L]], .dsvert_joint_dp_dsi_result_receipt_impl,
    first_result_json = results[[peers[[1L]]]],
    second_result_json = .dsvert_joint_dp_dsi_receipt_json(
      tampered_result, "test result receipt")), "signature")
  result_commits <- stats::setNames(lapply(peers, function(peer) {
    .dsi_joint_call(
      fixture, peer, .dsvert_joint_dp_dsi_result_receipt_impl,
      first_result_json = results[[peers[[1L]]]],
      second_result_json = results[[peers[[2L]]]])
  }), peers)
  deliveries <- stats::setNames(lapply(peers, function(peer) {
    .dsi_joint_call(
      fixture, peer, .dsvert_joint_dp_dsi_delivery_impl,
      first_result_commit_json = result_commits[[peers[[1L]]]],
      second_result_commit_json = result_commits[[peers[[2L]]]])
  }), peers)
  contracts <- stats::setNames(lapply(peers, function(peer) {
    .dsvert_joint_dp_dsi_delivery_contract_impl(
      deliveries[[peers[[1L]]]], deliveries[[peers[[2L]]]],
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]], .verifier = fixture$verifier)
  }), peers)

  for (peer in peers) {
    delivery <- .dsvert_joint_dp_dsi_receipt(
      deliveries[[peer]], "test delivery")
    contract <- .dsvert_joint_dp_dsi_receipt(
      contracts[[peer]], "test delivery contract")
    expect_identical(delivery$capability_available, FALSE)
    expect_identical(delivery$payload_delivery_available, FALSE)
    expect_identical(contract$capability_available, FALSE)
    expect_identical(contract$payload_delivery_available, FALSE)
    expect_identical(contract$payload_persisted, TRUE)
    expect_identical(contract$payload_exposed, FALSE)
    expect_false("local_payload_hash" %in% names(contract))
    expect_false(any(c(
      "payload", "payload_hash", "payload_commitment", "seed", "noise",
      "statistic_share") %in% names(contract)))
    expect_identical(.dsvert_joint_dp_dsi_delivery_contract_impl(
      deliveries[[peers[[1L]]]], deliveries[[peers[[2L]]]],
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]], .verifier = fixture$verifier),
      contracts[[peer]])
  }
  expect_false("payload" %in% names(formals(dsvertJointDPResultReceiptDS)))
  expect_false("payload" %in% names(formals(dsvertJointDPDeliveryDS)))
  expect_false("payload" %in%
                 names(formals(dsvertJointDPDeliveryContractDS)))
  expect_false("payload_commitment" %in%
                 names(formals(dsvertJointDPResultReceiptDS)))
  registered <- .dsvert_registered_remote_methods(
    .dsvert_test_package_file("DESCRIPTION"))
  expect_false(any(c(
    "dsvertJointDPResultPrepareDS", "dsvertJointDPPayloadVerifyDS",
    "dsvertJointDPCommitmentVerifyDS") %in% registered))
})

test_that("a non-designated full-pinset peer cannot run the allocator", {
  fixture <- .dsi_joint_fixture()
  on.exit(unlink(fixture$root, recursive = TRUE), add = TRUE)
  policy <- fixture$policies$peer_a
  policy$peer_name <- "peer_b"
  policy$ledger_path <- file.path(fixture$root, "peer_b.sqlite")
  policy$noise_root$key_id <- "joint-dsi-key-peer_b"
  expect_error(.dsvert_joint_dp_policy_context(policy),
               "Only a custodian-designated noise peer")
})
