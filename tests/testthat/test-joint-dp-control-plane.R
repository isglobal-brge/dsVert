.joint_test_b64url <- function(value) {
  base64_to_base64url(gsub("[\r\n]", "", jsonlite::base64_enc(value)))
}

.joint_test_fixture <- function(external_anchor = FALSE) {
  root <- tempfile("joint-dp-control-")
  dir.create(root)
  pins <- c(
    peer_a = .joint_test_b64url(as.raw(seq_len(32L))),
    peer_b = .joint_test_b64url(as.raw(32L + seq_len(32L))))
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  anchor_states <- new.env(parent = emptyenv())
  anchor <- function(action, anchor_id, expected = NULL,
                     replacement = NULL) {
    if (identical(action, "capabilities")) {
      return(list(
        schema_version = 2L, provider_id = "joint-test-anchor",
        external = TRUE, durable = TRUE, linearizable_cas = TRUE))
    }
    current <- if (exists(anchor_id, envir = anchor_states,
                          inherits = FALSE)) {
      get(anchor_id, envir = anchor_states, inherits = FALSE)
    } else {
      NULL
    }
    if (identical(action, "read")) return(current)
    if (!identical(action, "compare_and_swap")) {
      stop("unsupported test anchor action", call. = FALSE)
    }
    same <- if (is.null(expected)) is.null(current) else
      identical(current, expected)
    if (isTRUE(same)) {
      assign(anchor_id, replacement, envir = anchor_states)
      current <- replacement
    }
    list(swapped = isTRUE(same), state = current)
  }
  make_policy <- function(peer, offset) {
    key <- as.raw((seq_len(32L) + offset) %% 256L)
    list(
      domain = "joint-test-study", cohort_id = "joint-test-cohort",
      peer_name = peer, peer_pinset = pins,
      peer_pinset_sha256 = pin_hash,
      peer_count = 2L,
      designated_noise_peers = c("peer_a", "peer_b"),
      global_total_epsilon = 1, global_total_delta = 1e-6,
      lifetime_max_distinct_capsules = 8,
      adjacency = "add_remove_patient", patient_column = "patient_id",
      unit_capacity = 100L, max_records_per_unit = 2L,
      overflow_policy = "reject_snapshot",
      noise_root = list(
        protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
        provider_id = "joint_dp_control_test_provider",
        epoch = 1,
        key_id = paste0("joint-test-key-", peer),
        hmac = function(message) digest::hmac(
          key, message, algo = "sha256", serialize = FALSE)),
      ledger_path = file.path(root, paste0(peer, "-local.sqlite")),
      ledger_private = FALSE, lock_timeout_ms = 30000L,
      anchor_provider = if (isTRUE(external_anchor)) anchor else NULL)
  }
  signing_keys <- list(
    peer_a = charToRaw("joint-test-signing-a"),
    peer_b = charToRaw("joint-test-signing-b"))
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
    root = root,
    policies = list(
      peer_a = make_policy("peer_a", 64L),
      peer_b = make_policy("peer_b", 128L)),
    secrets = list(
      peer_a = as.raw(128L + seq_len(32L)),
      peer_b = as.raw(160L + seq_len(32L))),
    signer = signer, verifier = verifier, anchor_states = anchor_states)
}

.joint_test_mechanism <- function(uses_delta = FALSE) {
  list(
    release_scope = .DSVERT_JOINT_DP_SCOPE,
    capability_id = .DSVERT_JOINT_DP_CAPABILITY,
    producer = "chisq.cross.count-vector.v1",
    purpose = "k2_chisq_cross_count_shares",
    source_context_hash = strrep("a", 64L),
    mechanism = if (uses_delta) "discrete-gaussian" else "discrete-laplace",
    mechanism_version = "joint-sampler-v1",
    sampler = .DSVERT_JOINT_DP_SAMPLER,
    sensitivity_norm = if (uses_delta) "l2" else "l1",
    sensitivity = 2,
    coordinate_count = 4L,
    uses_delta = uses_delta,
    clipping_hash = strrep("b", 64L),
    ring_bits = 63L, frac_bits = 20L)
}

.joint_test_capsule_identity <- function(policy, snapshot, mechanism) {
  .dsvert_joint_dp_capsule_identity(
    policy, snapshot,
    capsule_schema = "biomedical-test-capsule-v1",
    admission = list(
      adjacency = policy$adjacency,
      unit_capacity = policy$unit_capacity,
      max_records_per_unit = policy$max_records_per_unit,
      overflow_policy = policy$overflow_policy),
    bounds = list(clipping_hash = mechanism$clipping_hash),
    workload = list(
      capsule_mechanism = mechanism,
      schema_hash = strrep("7", 64L),
      workload_version = "biomedical-test-workload-v1"))
}

.joint_test_proposals <- function(fixture, tag = "q1", uses_delta = FALSE,
                                  arguments_a = NULL,
                                  arguments_b = NULL,
                                  method_a = "chisq_cross",
                                  method_b = method_a) {
  if (is.null(arguments_a)) arguments_a <- list(tag = tag, alpha = 1L)
  if (is.null(arguments_b)) arguments_b <- list(alpha = 1, tag = tag)
  snapshot <- list(
    logical_snapshot_id = "aligned-cohort-v1",
    version = paste0("v1-", tag),
    alignment_protocol_version = 1L)
  mechanism <- .joint_test_mechanism(uses_delta)
  list(
    peer_a = .dsvert_joint_dp_proposal(
      fixture$policies$peer_a, snapshot, method_a, arguments_a,
      digest::digest(paste0("snapshot-a-", tag), algo = "sha256",
                     serialize = FALSE),
      mechanism,
      capsule_identity = .joint_test_capsule_identity(
        fixture$policies$peer_a, snapshot, mechanism),
      .secret = fixture$secrets$peer_a),
    peer_b = .dsvert_joint_dp_proposal(
      fixture$policies$peer_b, snapshot, method_b, arguments_b,
      digest::digest(paste0("snapshot-b-", tag), algo = "sha256",
                     serialize = FALSE),
      mechanism,
      capsule_identity = .joint_test_capsule_identity(
        fixture$policies$peer_b, snapshot, mechanism),
      .secret = fixture$secrets$peer_b))
}

.joint_test_prepare_pair <- function(fixture, proposals) {
  peers <- sort(names(fixture$policies), method = "radix")
  leader <- peers[[1L]]
  follower <- peers[[2L]]
  values <- list()
  values[[leader]] <- .dsvert_joint_dp_prepare(
    fixture$policies[[leader]], proposals[[leader]],
    .secret = fixture$secrets[[leader]], .signer = fixture$signer,
    .verifier = fixture$verifier)
  values[[follower]] <- .dsvert_joint_dp_prepare(
    fixture$policies[[follower]], proposals[[follower]],
    leader_prepare = values[[leader]],
    .secret = fixture$secrets[[follower]], .signer = fixture$signer,
    .verifier = fixture$verifier)
  values[peers]
}

.joint_test_commit_pair <- function(fixture, prepares) {
  values <- lapply(names(fixture$policies), function(peer) {
    .dsvert_joint_dp_commit(
      fixture$policies[[peer]], prepares$peer_a, prepares$peer_b,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier)
  })
  stats::setNames(values, names(fixture$policies))
}

.joint_test_authorize_pair <- function(fixture, commits) {
  values <- lapply(names(fixture$policies), function(peer) {
    .dsvert_joint_dp_authorize(
      fixture$policies[[peer]], commits$peer_a, commits$peer_b,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier)
  })
  stats::setNames(values, names(fixture$policies))
}

.joint_test_finalize_pair <- function(fixture, authorizations) {
  values <- lapply(names(fixture$policies), function(peer) {
    .dsvert_joint_dp_finalize_authorization(
      fixture$policies[[peer]], authorizations$peer_a,
      authorizations$peer_b, .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .verifier = fixture$verifier)
  })
  stats::setNames(values, names(fixture$policies))
}

.joint_test_bind_legacy_policy_hash <- function(fixture) {
  for (peer in names(fixture$policies)) {
    policy <- fixture$policies[[peer]]
    context <- .dsvert_joint_dp_policy_context(policy)
    legacy_hash <- .dsvert_joint_dp_legacy_local_policy_hash(
      context, policy$noise_root$epoch, policy$noise_root$key_id)
    connection <- DBI::dbConnect(
      RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(policy))
    .dsvert_joint_dp_transaction(connection, {
      state <- .dsvert_joint_dp_allocator_state_read(
        connection, fixture$secrets[[peer]])
      .dsvert_joint_dp_meta_set(connection, "policy_hash", legacy_hash)
      .dsvert_joint_dp_allocator_state_write(
        connection, fixture$secrets[[peer]], state)
    })
    DBI::dbDisconnect(connection)
    if (is.function(policy$anchor_provider)) {
      anchor_id <- .dsvert_joint_dp_external_anchor_id(context)
      anchor <- get(
        anchor_id, envir = fixture$anchor_states, inherits = FALSE)
      anchor$policy_hash <- legacy_hash
      assign(anchor_id, anchor, envir = fixture$anchor_states)
    }
  }
  fixture
}

.joint_test_rotate_noise_roots <- function(fixture) {
  for (index in seq_along(fixture$policies)) {
    peer <- names(fixture$policies)[[index]]
    key <- as.raw((seq_len(32L) + 192L + index) %% 256L)
    fixture$policies[[peer]]$noise_root$epoch <- 2
    fixture$policies[[peer]]$noise_root$key_id <-
      paste0("joint-test-key-v2-", peer)
    fixture$policies[[peer]]$noise_root$hmac <- local({
      private_key <- key
      function(message) digest::hmac(
        private_key, message, algo = "sha256", serialize = FALSE)
    })
  }
  fixture
}

.joint_test_identity_options <- function(seed_path, state_dir) {
  list(
    dsvert.state_dir = state_dir,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = seed_path,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.ledger_path = NULL,
    default.dsvert.dp.ledger_path = "")
}

test_that("the joint ledger rechecks sidecars after acquiring its lock", {
  skip_on_os("windows")
  fixture <- .joint_test_fixture()
  policy <- fixture$policies$peer_a
  policy$ledger_private <- TRUE
  path <- .dsvert_joint_dp_ledger_path(policy)
  wal_path <- paste0(path, "-wal")
  target <- tempfile("joint-ledger-race-target-", tmpdir = dirname(path))
  on.exit(unlink(c(wal_path, target), force = TRUE), add = TRUE)
  expect_true(file.create(target))
  Sys.chmod(target, mode = "0644")
  real_lock <- filelock::lock
  substituted <- FALSE
  racing_lock <- function(path, timeout = Inf) {
    substituted <<- file.symlink(target, wal_path)
    real_lock(path, timeout = timeout)
  }
  condition <- testthat::with_mocked_bindings(
    tryCatch(.dsvert_joint_dp_open_ledger(policy), error = identity),
    lock = racing_lock, .package = "filelock")
  expect_true(substituted)
  expect_s3_class(condition, "error")
  expect_match(condition$message, "symbolic link")
  expect_identical(as.integer(file.info(target)$mode),
                   strtoi("644", base = 8L))
})

.joint_test_prepare_pair_with_identity <- function(
    fixture, proposals, identity_paths, identity_state_dirs) {
  peers <- sort(names(fixture$policies), method = "radix")
  leader <- peers[[1L]]
  follower <- peers[[2L]]
  values <- list()
  values[[leader]] <- withr::with_options(
    .joint_test_identity_options(
      identity_paths[[leader]], identity_state_dirs[[leader]]),
    .dsvert_joint_dp_prepare(
      fixture$policies[[leader]], proposals[[leader]],
      .secret = fixture$secrets[[leader]], .signer = fixture$signer,
      .verifier = fixture$verifier))
  values[[follower]] <- withr::with_options(
    .joint_test_identity_options(
      identity_paths[[follower]], identity_state_dirs[[follower]]),
    .dsvert_joint_dp_prepare(
      fixture$policies[[follower]], proposals[[follower]],
      leader_prepare = values[[leader]],
      .secret = fixture$secrets[[follower]], .signer = fixture$signer,
      .verifier = fixture$verifier))
  values[peers]
}

.joint_test_resign <- function(receipt, fixture) {
  receipt$signature <- NULL
  .dsvert_joint_dp_sign(
    receipt, fixture$policies[[receipt$peer_name]], fixture$signer)
}

.joint_test_capture_db_get_queries <- function(code) {
  tracker_name <- ".dsvert_joint_dp_query_tracker"
  had_tracker <- exists(
    tracker_name, envir = .GlobalEnv, inherits = FALSE)
  old_tracker <- if (had_tracker) {
    get(tracker_name, envir = .GlobalEnv, inherits = FALSE)
  } else {
    NULL
  }
  tracker <- new.env(parent = emptyenv())
  tracker$statements <- character()
  assign(tracker_name, tracker, envir = .GlobalEnv)
  on.exit({
    if (had_tracker) {
      assign(tracker_name, old_tracker, envir = .GlobalEnv)
    } else if (exists(tracker_name, envir = .GlobalEnv, inherits = FALSE)) {
      rm(list = tracker_name, envir = .GlobalEnv)
    }
  }, add = TRUE)
  suppressMessages(trace(
    "dbGetQuery", signature = c("DBIConnection", "character"),
    where = asNamespace("DBI"), print = FALSE,
    tracer = quote({
      tracker <- get(
        ".dsvert_joint_dp_query_tracker", envir = .GlobalEnv,
        inherits = FALSE)
      tracker$statements <- c(
        tracker$statements, as.character(statement))
    })))
  on.exit(suppressMessages(untrace(
    "dbGetQuery", signature = c("DBIConnection", "character"),
    where = asNamespace("DBI"))), add = TRUE)
  value <- force(code)
  list(value = value, statements = tracker$statements)
}

test_that("joint allocator uses one global allocation and exact replay", {
  fixture <- .joint_test_fixture()
  registered <- .dsvert_registered_remote_methods(
    .dsvert_test_package_file("DESCRIPTION"))
  dsi_control <- c(
    "dsvertJointDPPrepareDS", "dsvertJointDPCommitDS",
    "dsvertJointDPAuthorizeDS", "dsvertJointDPOpenDS",
    "dsvertJointDPResultReceiptDS", "dsvertJointDPDeliveryDS",
    "dsvertJointDPDeliveryContractDS")
  expect_length(intersect(dsi_control, registered), 0L)
  expect_length(intersect(
    dsi_control, .dsvert_test_disclosure_safe_methods), 0L)
  proposals <- .joint_test_proposals(fixture)
  expect_identical(proposals$peer_a$query_id, proposals$peer_b$query_id)

  prepares <- .joint_test_prepare_pair(fixture, proposals)
  expect_identical(prepares$peer_a$capsule_id, proposals$peer_a$capsule_id)
  expect_identical(prepares$peer_a$query_id, prepares$peer_a$capsule_id)
  expect_identical(prepares$peer_a$epsilon, "1e+00")
  expect_identical(prepares$peer_b$epsilon, "1e+00")
  expect_equal(as.numeric(prepares$peer_a$epsilon), 1)
  expect_false(any(c("seed", "protected_fingerprint") %in%
                   names(prepares$peer_a)))
  expect_false(identical(prepares$peer_a$seed_commitment,
                         prepares$peer_b$seed_commitment))

  commits <- .joint_test_commit_pair(fixture, prepares)
  expect_identical(commits$peer_a$new_chain, commits$peer_b$new_chain)
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  tokens <- .joint_test_finalize_pair(fixture, authorizations)
  expect_true(all(vapply(tokens, function(value) {
    identical(value$phase, "open_authorized") &&
      identical(value$capability_available, FALSE)
  }, logical(1L))))
  sampler_contract <- .dsvert_joint_dp_sampler_contract(
    fixture$policies$peer_a, tokens$peer_a,
    .secret = fixture$secrets$peer_a, .verifier = fixture$verifier)
  expect_identical(sampler_contract$capability_available, FALSE)
  expect_identical(
    sampler_contract$unavailable_reason,
    "exact_gc_two_seed_prf_sampler_not_e2e_verified")
  expect_identical(
    sampler_contract$own_seed_commitment,
    prepares$peer_a$seed_commitment)
  expect_identical(
    sampler_contract$prepare_set_hash, commits$peer_a$prepare_set_hash)
  expect_identical(
    sampler_contract$commit_set_hash,
    authorizations$peer_a$commit_set_hash)
  expect_identical(sampler_contract$capsule_id, proposals$peer_a$capsule_id)
  expect_identical(sampler_contract$query_id, sampler_contract$capsule_id)
  expect_identical(sampler_contract$epsilon, "1e+00")
  expect_true(sampler_contract$result_commit_required_before_delivery)
  expect_false(any(c("seed", "noise", "statistic_share") %in%
                   names(sampler_contract)))

  expect_identical(
    .dsvert_joint_dp_prepare(
      fixture$policies$peer_a, proposals$peer_a,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer),
    prepares$peer_a)
  expect_identical(
    .dsvert_joint_dp_commit(
      fixture$policies$peer_a, prepares$peer_b, prepares$peer_a,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer,
      .verifier = fixture$verifier),
    commits$peer_a)
  expect_identical(
    .dsvert_joint_dp_authorize(
      fixture$policies$peer_a, commits$peer_b, commits$peer_a,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer,
      .verifier = fixture$verifier),
    authorizations$peer_a)
  expect_identical(
    .dsvert_joint_dp_finalize_authorization(
      fixture$policies$peer_a, authorizations$peer_b,
      authorizations$peer_a, .secret = fixture$secrets$peer_a,
      .signer = fixture$signer, .verifier = fixture$verifier),
    tokens$peer_a)
  expect_error(
    .dsvert_joint_dp_local_seed(
      fixture$policies$peer_a, tokens$peer_a,
      .secret = fixture$secrets$peer_a,
      .verifier = fixture$verifier),
    "sampler adapter is not promoted")
  expect_false(file.exists(fixture$policies$peer_a$ledger_path))
})

test_that("methods and arguments reuse one immutable capsule without charge", {
  fixture <- .joint_test_fixture()
  initial <- .joint_test_proposals(
    fixture, "shared-capsule",
    arguments_a = list(statistic = "count", threshold = 1L),
    arguments_b = list(threshold = 1, statistic = "count"),
    method_a = "count", method_b = "count")
  prepares <- .joint_test_prepare_pair(fixture, initial)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  .joint_test_finalize_pair(fixture, authorizations)

  ledger_meta <- function(policy) {
    connection <- DBI::dbConnect(
      RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(policy))
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    rows <- DBI::dbGetQuery(
      connection,
      "SELECT key, value FROM joint_meta ORDER BY key")
    stats::setNames(rows$value, rows$key)
  }
  before <- lapply(fixture$policies, ledger_meta)

  for (index in seq_len(25L)) {
    replay <- .joint_test_proposals(
      fixture, "shared-capsule",
      arguments_a = list(model = "glm", iteration = index),
      arguments_b = list(iteration = as.numeric(index), model = "glm"),
      method_a = "glm", method_b = "survival")
    expect_identical(replay$peer_a$capsule_id, initial$peer_a$capsule_id)
    expect_identical(replay$peer_b$capsule_id, initial$peer_b$capsule_id)
    expect_false(any(c("method", "arguments") %in%
                     names(replay$peer_a$common_query)))
    expect_identical(.joint_test_prepare_pair(fixture, replay), prepares)
  }

  after <- lapply(fixture$policies, ledger_meta)
  expect_identical(after, before)
  expect_true(all(vapply(after, function(meta) {
    identical(meta[["next_index"]], "1") &&
      identical(as.numeric(meta[["cumulative_epsilon"]]), 1)
  }, logical(1L))))
})

test_that("noise-root rotation preserves and migrates a non-empty joint ledger", {
  for (external_anchor in c(FALSE, TRUE)) {
    fixture <- .joint_test_fixture(external_anchor = external_anchor)
    original_proposals <- .joint_test_proposals(
      fixture, paste0("before-rotation-", external_anchor))
    original_prepares <- .joint_test_prepare_pair(
      fixture, original_proposals)
    original_commits <- .joint_test_commit_pair(fixture, original_prepares)
    original_authorizations <- .joint_test_authorize_pair(
      fixture, original_commits)
    .joint_test_finalize_pair(fixture, original_authorizations)

    fixture <- .joint_test_bind_legacy_policy_hash(fixture)
    fixture <- .joint_test_rotate_noise_roots(fixture)

    replay_proposals <- .joint_test_proposals(
      fixture, paste0("before-rotation-", external_anchor))
    expect_identical(replay_proposals, original_proposals)
    expect_identical(
      .joint_test_prepare_pair(fixture, replay_proposals),
      original_prepares)

    rotated_proposals <- .joint_test_proposals(
      fixture, paste0("after-rotation-", external_anchor))
    rotated_prepares <- .joint_test_prepare_pair(fixture, rotated_proposals)
    expect_true(all(vapply(names(rotated_prepares), function(peer) {
      identical(rotated_prepares[[peer]]$privacy_epoch, "2") &&
        identical(
          rotated_prepares[[peer]]$noise_key_id,
          fixture$policies[[peer]]$noise_root$key_id) &&
        identical(rotated_prepares[[peer]]$allocation_index, "1")
    }, logical(1L))))
    .joint_test_commit_pair(fixture, rotated_prepares)

    for (peer in names(fixture$policies)) {
      policy <- fixture$policies[[peer]]
      context <- .dsvert_joint_dp_policy_context(policy)
      connection <- DBI::dbConnect(
        RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(policy))
      metadata <- .dsvert_joint_dp_meta_snapshot(
        connection, .DSVERT_JOINT_DP_FAST_META_KEYS)
      state <- .dsvert_joint_dp_allocator_state_read(
        connection, fixture$secrets[[peer]])
      rows <- DBI::dbGetQuery(
        connection, "SELECT * FROM joint_records ORDER BY sequence")
      records <- lapply(seq_len(nrow(rows)), function(index) {
        .dsvert_joint_dp_record_decode(
          rows[index, , drop = FALSE], fixture$secrets[[peer]])
      })
      expect_identical(metadata[["policy_hash"]], context$local_policy_hash)
      expect_identical(metadata[["next_index"]], "2")
      expect_equal(as.numeric(metadata[["cumulative_epsilon"]]), 2)
      expect_identical(state$committed_count, 2)
      expect_identical(
        vapply(records, function(record) {
          record$own_prepare$privacy_epoch
        }, character(1L)), c("1", "2"))
      expect_identical(records[[1L]]$query_id,
                       original_proposals[[peer]]$query_id)
      expect_identical(records[[1L]]$own_prepare,
                       original_prepares[[peer]])
      expect_invisible(.dsvert_joint_dp_allocator_forensic_audit(
        connection, policy, fixture$secrets[[peer]], fixture$verifier))
      DBI::dbDisconnect(connection)

      if (isTRUE(external_anchor)) {
        anchor <- get(
          .dsvert_joint_dp_external_anchor_id(context),
          envir = fixture$anchor_states, inherits = FALSE)
        expect_identical(anchor$policy_hash, context$local_policy_hash)
        expect_identical(anchor$next_index, 2)
        expect_identical(anchor$chain_head, state$chain_head)
      }
    }
  }
})

test_that("one peer may rotate its noise root without synchronizing epochs", {
  fixture <- .joint_test_fixture()
  rotated_key <- as.raw((seq_len(32L) + 233L) %% 256L)
  fixture$policies$peer_b$noise_root$epoch <- 2
  fixture$policies$peer_b$noise_root$key_id <-
    "joint-test-key-v2-peer-b-only"
  fixture$policies$peer_b$noise_root$hmac <- local({
    private_key <- rotated_key
    function(message) digest::hmac(
      private_key, message, algo = "sha256", serialize = FALSE)
  })

  proposals <- .joint_test_proposals(fixture, "asymmetric-root-epochs")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  expect_identical(prepares$peer_a$privacy_epoch, "1")
  expect_identical(prepares$peer_b$privacy_epoch, "2")
  expect_identical(prepares$peer_b$noise_key_id,
                   "joint-test-key-v2-peer-b-only")
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  openings <- .joint_test_finalize_pair(fixture, authorizations)
  expect_identical(names(openings), c("peer_a", "peer_b"))
  expect_identical(.joint_test_prepare_pair(fixture, proposals), prepares)
  for (peer in names(fixture$policies)) {
    status <- .dsvert_joint_dp_capsule_status(
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .verifier = fixture$verifier)
    expect_identical(
      status$composition_telemetry$capsules_created, 1)
    expect_identical(status$privacy_contract$operation_limit, TRUE)
  }
})

test_that("irrecoverable file-root loss rotates without blocking a used joint ledger", {
  skip_on_os("windows")
  for (external_anchor in c(FALSE, TRUE)) {
    fixture <- .joint_test_fixture(external_anchor = external_anchor)
    identity_paths <- identity_state_dirs <- noise_paths <- list()

    for (index in seq_along(fixture$policies)) {
      peer <- names(fixture$policies)[[index]]
      state_dir <- file.path(fixture$root, paste0("state-", peer))
      dir.create(state_dir, mode = "0700")
      Sys.chmod(state_dir, mode = "0700")
      seed_path <- file.path(state_dir, "identity.seed")
      noise_path <- file.path(state_dir, "privacy", "noise_root")
      bootstrap <- list(
        ledger_path = fixture$policies[[peer]]$ledger_path,
        anchor_provider = NULL, anchor_id = NULL)
      root <- withr::with_options(
        .joint_test_identity_options(seed_path, state_dir), {
          .dsvert_init_identity_seed(
            seed_path,
            random_bytes = function(n) as.raw(rep(80L + index, n)),
            .allow_test_path = TRUE)
          .dsvert_dp_ensure_noise_key_file(
            noise_path,
            random_bytes = function(n) as.raw(rep(120L + index, n)),
            .allow_test_path = TRUE, .bootstrap_state = bootstrap)
          .dsvert_dp_noise_key_file(
            noise_path, .allow_test_path = TRUE,
            .bootstrap_state = bootstrap)
        })
      identity_paths[[peer]] <- seed_path
      identity_state_dirs[[peer]] <- state_dir
      noise_paths[[peer]] <- noise_path
      fixture$policies[[peer]]$noise_root <- root
    }

    original_proposals <- .joint_test_proposals(
      fixture, paste0("file-root-before-loss-", external_anchor))
    original_prepares <- .joint_test_prepare_pair_with_identity(
      fixture, original_proposals, identity_paths, identity_state_dirs)
    original_commits <- .joint_test_commit_pair(fixture, original_prepares)
    original_authorizations <- .joint_test_authorize_pair(
      fixture, original_commits)
    .joint_test_finalize_pair(fixture, original_authorizations)
    original_key_ids <- vapply(
      fixture$policies, function(policy) policy$noise_root$key_id,
      character(1L))

    for (index in seq_along(fixture$policies)) {
      peer <- names(fixture$policies)[[index]]
      old_policy <- fixture$policies[[peer]]
      noise_path <- noise_paths[[peer]]
      unlink(c(
        noise_path, .dsvert_dp_noise_recovery_path(noise_path)),
        force = TRUE)
      bootstrap_options <- .joint_test_identity_options(
        identity_paths[[peer]], identity_state_dirs[[peer]])
      bootstrap_options$dsvert.dp.ledger_path <- old_policy$ledger_path
      bootstrap_options$default.dsvert.dp.ledger_path <- NULL
      rotated_root <- withr::with_options(
        bootstrap_options,
        testthat::with_mocked_bindings({
          bootstrap <- .dsvert_noise_bootstrap_state_from_options()
          expect_true(is.function(bootstrap$history_provider))
          .dsvert_dp_ensure_noise_key_file(
            noise_path,
            random_bytes = function(n) as.raw(rep(160L + index, n)),
            .allow_test_path = TRUE, .bootstrap_state = bootstrap)
          .dsvert_dp_noise_key_file(
            noise_path, .allow_test_path = TRUE,
            .bootstrap_state = bootstrap)
        },
        .dsvert_dp_secret = function() fixture$secrets[[peer]],
        .package = "dsVert"))
      expect_identical(rotated_root$epoch, 2)
      expect_identical(
        rotated_root$previous_key_id, original_key_ids[[peer]])
      expect_false(identical(rotated_root$key_id,
                             original_key_ids[[peer]]))
      expect_true(rotated_root$automatic_rotation)
      fixture$policies[[peer]]$noise_root <- rotated_root
    }

    replay_proposals <- .joint_test_proposals(
      fixture, paste0("file-root-before-loss-", external_anchor))
    expect_identical(replay_proposals, original_proposals)
    expect_identical(
      .joint_test_prepare_pair_with_identity(
        fixture, replay_proposals, identity_paths, identity_state_dirs),
      original_prepares)

    new_proposals <- .joint_test_proposals(
      fixture, paste0("file-root-after-loss-", external_anchor))
    new_prepares <- .joint_test_prepare_pair_with_identity(
      fixture, new_proposals, identity_paths, identity_state_dirs)
    expect_true(all(vapply(names(new_prepares), function(peer) {
      identical(new_prepares[[peer]]$privacy_epoch, "2") &&
        identical(new_prepares[[peer]]$noise_key_id,
                  fixture$policies[[peer]]$noise_root$key_id) &&
        identical(new_prepares[[peer]]$allocation_index, "1")
    }, logical(1L))))
    .joint_test_commit_pair(fixture, new_prepares)

    for (peer in names(fixture$policies)) {
      policy <- fixture$policies[[peer]]
      context <- .dsvert_joint_dp_policy_context(policy)
      connection <- DBI::dbConnect(
        RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(policy))
      metadata <- .dsvert_joint_dp_meta_snapshot(
        connection, .DSVERT_JOINT_DP_FAST_META_KEYS)
      state <- .dsvert_joint_dp_allocator_state_read(
        connection, fixture$secrets[[peer]])
      expect_identical(metadata[["policy_hash"]], context$local_policy_hash)
      expect_identical(metadata[["next_index"]], "2")
      expect_equal(as.numeric(metadata[["cumulative_epsilon"]]), 2)
      expect_identical(state$committed_count, 2)
      expect_invisible(.dsvert_joint_dp_allocator_forensic_audit(
        connection, policy, fixture$secrets[[peer]], fixture$verifier))
      DBI::dbDisconnect(connection)
      if (isTRUE(external_anchor)) {
        anchor <- get(
          .dsvert_joint_dp_external_anchor_id(context),
          envir = fixture$anchor_states, inherits = FALSE)
        expect_identical(anchor$next_index, 2)
        expect_identical(anchor$chain_head, state$chain_head)
      }
    }
  }
})

test_that("rotation migration rejects cryptographic and policy-binding tamper", {
  corrupted <- .joint_test_fixture()
  proposals <- .joint_test_proposals(corrupted, "rotation-mac-tamper")
  prepares <- .joint_test_prepare_pair(corrupted, proposals)
  .joint_test_commit_pair(corrupted, prepares)
  corrupted <- .joint_test_bind_legacy_policy_hash(corrupted)
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(
      corrupted$policies$peer_a))
  DBI::dbExecute(connection, paste(
    "UPDATE joint_records SET row_mac = ? WHERE sequence = 0"),
    params = list(strrep("0", 64L)))
  DBI::dbDisconnect(connection)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_dp_inactive_noise_history(
      corrupted$policies$peer_a$ledger_path),
    .dsvert_dp_secret = function() corrupted$secrets$peer_a,
    .package = "dsVert"),
    "failed its integrity check")
  corrupted <- .joint_test_rotate_noise_roots(corrupted)
  expect_error(.dsvert_joint_dp_prepare(
    corrupted$policies$peer_a,
    .joint_test_proposals(corrupted, "after-rotation-mac-tamper")$peer_a,
    .secret = corrupted$secrets$peer_a, .signer = corrupted$signer,
    .verifier = corrupted$verifier),
    "ledger failed its integrity check")

  rebound <- .joint_test_fixture()
  proposals <- .joint_test_proposals(rebound, "rotation-binding-tamper")
  prepares <- .joint_test_prepare_pair(rebound, proposals)
  .joint_test_commit_pair(rebound, prepares)
  policy <- rebound$policies$peer_a
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(policy))
  .dsvert_joint_dp_transaction(connection, {
    state <- .dsvert_joint_dp_allocator_state_read(
      connection, rebound$secrets$peer_a)
    .dsvert_joint_dp_meta_set(connection, "policy_hash", strrep("f", 64L))
    .dsvert_joint_dp_allocator_state_write(
      connection, rebound$secrets$peer_a, state)
  })
  DBI::dbDisconnect(connection)
  rebound <- .joint_test_rotate_noise_roots(rebound)
  expect_error(.dsvert_joint_dp_prepare(
    rebound$policies$peer_a,
    .joint_test_proposals(rebound, "after-binding-tamper")$peer_a,
    .secret = rebound$secrets$peer_a, .signer = rebound$signer,
    .verifier = rebound$verifier),
    "does not match the immutable local policy")
})

test_that("capsule identity binds policy snapshot schema admission and bounds", {
  fixture <- .joint_test_fixture()
  policy <- fixture$policies$peer_a
  snapshot <- list(
    logical_snapshot_id = "capsule-binding", version = "v1",
    alignment_protocol_version = 2L)
  admission <- list(
    adjacency = "add_remove_patient", unit_capacity = 100L,
    max_records_per_unit = 2L, overflow_policy = "reject_snapshot")
  bounds <- list(lower = 0L, upper = 100L)
  workload <- list(
    schema_hash = strrep("1", 64L), coordinate_count = 8L,
    ring_bits = 128L, frac_bits = 0L)
  identity <- .dsvert_joint_dp_capsule_identity(
    policy, snapshot, "biomedical-capsule-v1",
    admission, bounds, workload)
  expect_identical(identity$capsule_id,
                   .dsvert_joint_dp_hash(identity$contract))
  mechanism <- .joint_test_mechanism()
  expect_error(.dsvert_joint_dp_proposal(
    policy, snapshot, "count", list(), strrep("9", 64L), mechanism,
    .secret = fixture$secrets$peer_a),
    "explicit server-minted full-capsule identity")

  semantic_variants <- list(
    .dsvert_joint_dp_capsule_identity(
      policy, utils::modifyList(snapshot, list(version = "v2")),
      "biomedical-capsule-v1", admission, bounds, workload),
    .dsvert_joint_dp_capsule_identity(
      policy, snapshot, "biomedical-capsule-v2",
      admission, bounds, workload),
    .dsvert_joint_dp_capsule_identity(
      policy, snapshot, "biomedical-capsule-v1",
      utils::modifyList(admission, list(unit_capacity = 101L)),
      bounds, workload),
    .dsvert_joint_dp_capsule_identity(
      policy, snapshot, "biomedical-capsule-v1", admission,
      utils::modifyList(bounds, list(upper = 101L)), workload),
    .dsvert_joint_dp_capsule_identity(
      utils::modifyList(policy, list(
        global_total_epsilon = 2,
        lifetime_max_distinct_capsules = 4)),
      snapshot, "biomedical-capsule-v1", admission, bounds, workload))
  expect_true(all(vapply(semantic_variants, function(value) {
    !identical(value$capsule_id, identity$capsule_id)
  }, logical(1L))))
  rotated_identity <- .dsvert_joint_dp_capsule_identity(
    utils::modifyList(policy, list(noise_root = list(
      epoch = 2, key_id = "rotated-key"))),
    snapshot, "biomedical-capsule-v1", admission, bounds, workload)
  expect_identical(rotated_identity, identity)
  expect_error(.dsvert_joint_dp_capsule_identity(
    policy, snapshot, "biomedical-capsule-v1", admission, bounds,
    utils::modifyList(workload, list(method = "glm"))),
    "operation-independent")
})

test_that("lifetime composition bounds use exact canonical decimals", {
  fixture <- .joint_test_fixture()
  context <- .dsvert_joint_dp_policy_context(fixture$policies$peer_a)
  expect_identical(
    context$lifetime$maximum_distinct_capsules, 8)
  expect_identical(context$lifetime$lifetime_epsilon, "8")
  expect_identical(
    context$lifetime$lifetime_delta, "7.9999999999999996e-6")
  expect_identical(
    context$common$privacy_accounting,
    "bounded_distinct_capsules_one_public_instance_each_v1")
  expect_identical(
    context$consortium_id,
    paste0("jdpc1_",
           "0a4af0da437caf103562897a7fd2aad2deab92f3adc8b72b3cdf8fcf7969576f"))

  epsilon_over <- fixture$policies$peer_a
  epsilon_over$lifetime_max_distinct_capsules <- 9
  expect_error(
    .dsvert_joint_dp_policy_context(epsilon_over),
    "lifetime composition bound")

  decimal_over <- fixture$policies$peer_a
  decimal_over$lifetime_max_distinct_capsules <- 10
  decimal_over$global_total_epsilon <- 0.8
  expect_error(
    .dsvert_joint_dp_policy_context(decimal_over),
    "lifetime composition bound")

  delta_vacuous <- fixture$policies$peer_a
  delta_vacuous$lifetime_max_distinct_capsules <- 4
  delta_vacuous$global_total_delta <- 0.25
  expect_error(
    .dsvert_joint_dp_policy_context(delta_vacuous),
    "lifetime composition bound")

  malformed <- fixture$policies$peer_a
  malformed$lifetime_max_distinct_capsules <- 1.5
  expect_error(
    .dsvert_joint_dp_policy_context(malformed),
    "lifetime maximum distinct capsules")
})

test_that("distinct capsules stop at the authenticated lifetime boundary", {
  fixture <- .joint_test_fixture()
  first_proposal <- NULL
  first_prepare <- NULL
  capsule_count <- 8L
  fast_query_counts <- integer()

  for (index in seq_len(capsule_count)) {
    proposals <- .joint_test_proposals(
      fixture, sprintf("capsule-%03d", index))
    leader <- .dsvert_joint_dp_prepare(
      fixture$policies$peer_a, proposals$peer_a,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer,
      .verifier = fixture$verifier)
    follower <- leader
    follower$peer_name <- "peer_b"
    follower$peer_identity_pk <-
      fixture$policies$peer_b$peer_pinset[["peer_b"]]
    follower$noise_key_id <- fixture$policies$peer_b$noise_root$key_id
    follower$snapshot_binding <- proposals$peer_b$snapshot_binding
    follower$seed_commitment <- digest::digest(
      paste0("synthetic-follower-seed-", index),
      algo = "sha256", serialize = FALSE)
    follower$signature <- NULL
    follower <- .dsvert_joint_dp_sign(
      follower, fixture$policies$peer_b, fixture$signer)
    .dsvert_joint_dp_commit(
      fixture$policies$peer_a, leader, follower,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer,
      .verifier = fixture$verifier)
    expect_identical(leader$allocation_index, as.character(index - 1L))
    expect_identical(leader$epsilon, "1e+00")
    if (index == 1L) {
      first_proposal <- proposals$peer_a
      first_prepare <- leader
    }
    if (index %in% c(1L, capsule_count)) {
      checkpoint <- DBI::dbConnect(
        RSQLite::SQLite(),
        .dsvert_joint_dp_ledger_path(fixture$policies$peer_a))
      captured <- .joint_test_capture_db_get_queries(
        testthat::with_mocked_bindings(
          .dsvert_joint_dp_initialize_validate(
            checkpoint, fixture$policies$peer_a,
            fixture$secrets$peer_a, fixture$verifier),
          .dsvert_joint_dp_allocator_full_audit = function(...) {
            stop("full allocator audit entered", call. = FALSE)
          },
          .package = "dsVert"))
      DBI::dbDisconnect(checkpoint)
      fast_query_counts <- c(
        fast_query_counts, length(captured$statements))
    }
  }

  denied_proposal <- .joint_test_proposals(
    fixture, "capsule-over-lifetime-boundary")$peer_a
  denied <- tryCatch(.dsvert_joint_dp_prepare(
    fixture$policies$peer_a, denied_proposal,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), error = identity)
  expect_s3_class(denied, "dsvert_dp_lifetime_budget_exhausted")
  expect_identical(
    conditionMessage(denied),
    "[dsvert_dp_lifetime_budget_exhausted:v1]")

  replay <- .dsvert_joint_dp_prepare(
    fixture$policies$peer_a, first_proposal,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_identical(replay, first_prepare)
  connection <- DBI::dbConnect(
    RSQLite::SQLite(),
    .dsvert_joint_dp_ledger_path(fixture$policies$peer_a))
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  meta <- DBI::dbGetQuery(
    connection, "SELECT key, value FROM joint_meta ORDER BY key")
  meta <- stats::setNames(meta$value, meta$key)
  expect_identical(meta[["next_index"]], as.character(capsule_count))
  expect_equal(as.numeric(meta[["cumulative_epsilon"]]), capsule_count)
  expect_equal(as.numeric(meta[["cumulative_delta"]]), 0)
  state <- .dsvert_joint_dp_allocator_state_read(
    connection, fixture$secrets$peer_a)
  expect_identical(state$committed_count, as.numeric(capsule_count))
  expect_identical(
    state$operation_accounting,
    "one_per_distinct_capsule_allocator_commit")
  expect_true(state$operation_limit)
  expect_true(state$history_can_deny_operation)
  expect_length(fast_query_counts, 2L)
  expect_identical(fast_query_counts[[1L]], fast_query_counts[[2L]])
  expect_lte(fast_query_counts[[2L]], 12L)

  target_plan <- DBI::dbGetQuery(connection, paste(
    "EXPLAIN QUERY PLAN SELECT * FROM joint_records",
    "WHERE query_id = ?"), params = list(first_proposal$query_id))
  sequence_plan <- DBI::dbGetQuery(connection, paste(
    "EXPLAIN QUERY PLAN SELECT * FROM joint_records",
    "WHERE sequence = ?"), params = list(capsule_count - 1L))
  state_plan <- DBI::dbGetQuery(connection, paste(
    "EXPLAIN QUERY PLAN SELECT * FROM joint_allocator_state",
    "WHERE singleton = 1"))
  output_plan <- DBI::dbGetQuery(connection, paste(
    "EXPLAIN QUERY PLAN SELECT * FROM joint_outputs",
    "WHERE query_id = ?"), params = list(first_proposal$query_id))
  expect_true(any(grepl("USING INDEX", target_plan$detail, fixed = TRUE)))
  expect_true(any(grepl("USING INDEX", sequence_plan$detail, fixed = TRUE)))
  expect_true(any(grepl(
    "INTEGER PRIMARY KEY", state_plan$detail, fixed = TRUE)))
  expect_true(any(grepl("USING INDEX", output_plan$detail, fixed = TRUE)))
  fast_source <- paste(deparse(
    body(.dsvert_joint_dp_allocator_fast_validate)), collapse = "\n")
  expect_false(grepl(
    "SELECT \\* FROM joint_records ORDER BY sequence", fast_source))
  state_columns <- DBI::dbGetQuery(
    connection, "PRAGMA table_info(joint_allocator_state)")$name
  expect_false(any(grepl(
    "max|remaining|quota|limit|exhaust", state_columns,
    ignore.case = TRUE)))
})

test_that("allocator fast state fails closed on head and bootstrap tampering", {
  state_fixture <- .joint_test_fixture()
  state_proposals <- .joint_test_proposals(state_fixture, "state-tamper")
  state_prepares <- .joint_test_prepare_pair(state_fixture, state_proposals)
  .joint_test_commit_pair(state_fixture, state_prepares)
  state_path <- .dsvert_joint_dp_ledger_path(
    state_fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), state_path)
  DBI::dbExecute(connection, paste(
    "UPDATE joint_allocator_state SET state_mac = ? WHERE singleton = 1"),
    params = list(strrep("0", 64L)))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_prepare(
    state_fixture$policies$peer_a,
    .joint_test_proposals(state_fixture, "after-state-tamper")$peer_a,
    .secret = state_fixture$secrets$peer_a,
    .signer = state_fixture$signer, .verifier = state_fixture$verifier),
    "allocator state failed its integrity check")

  missing_fixture <- .joint_test_fixture()
  missing_proposal <- .joint_test_proposals(
    missing_fixture, "missing-state")$peer_a
  .dsvert_joint_dp_prepare(
    missing_fixture$policies$peer_a, missing_proposal,
    .secret = missing_fixture$secrets$peer_a,
    .signer = missing_fixture$signer, .verifier = missing_fixture$verifier)
  missing_path <- .dsvert_joint_dp_ledger_path(
    missing_fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), missing_path)
  DBI::dbExecute(connection, "DELETE FROM joint_allocator_state")
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_prepare(
    missing_fixture$policies$peer_a, missing_proposal,
    .secret = missing_fixture$secrets$peer_a,
    .signer = missing_fixture$signer, .verifier = missing_fixture$verifier),
    "allocator state is missing")

  schema_fixture <- .joint_test_fixture()
  schema_proposal <- .joint_test_proposals(
    schema_fixture, "missing-schema")$peer_a
  .dsvert_joint_dp_prepare(
    schema_fixture$policies$peer_a, schema_proposal,
    .secret = schema_fixture$secrets$peer_a,
    .signer = schema_fixture$signer, .verifier = schema_fixture$verifier)
  schema_path <- .dsvert_joint_dp_ledger_path(
    schema_fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), schema_path)
  DBI::dbExecute(connection,
    "DELETE FROM joint_meta WHERE key = 'schema_version'")
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_prepare(
    schema_fixture$policies$peer_a, schema_proposal,
    .secret = schema_fixture$secrets$peer_a,
    .signer = schema_fixture$signer, .verifier = schema_fixture$verifier),
    "lacks its schema binding")
})

test_that("allocator fast state authenticates prepared and committed tails", {
  prepared_fixture <- .joint_test_fixture()
  prepared_proposal <- .joint_test_proposals(
    prepared_fixture, "prepared-row-tamper")$peer_a
  .dsvert_joint_dp_prepare(
    prepared_fixture$policies$peer_a, prepared_proposal,
    .secret = prepared_fixture$secrets$peer_a,
    .signer = prepared_fixture$signer,
    .verifier = prepared_fixture$verifier)
  prepared_path <- .dsvert_joint_dp_ledger_path(
    prepared_fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), prepared_path)
  DBI::dbExecute(connection, paste(
    "UPDATE joint_records SET row_mac = ? WHERE query_id = ?"),
    params = list(strrep("0", 64L), prepared_proposal$query_id))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_prepare(
    prepared_fixture$policies$peer_a, prepared_proposal,
    .secret = prepared_fixture$secrets$peer_a,
    .signer = prepared_fixture$signer,
    .verifier = prepared_fixture$verifier),
    "ledger failed its integrity check")

  tail_fixture <- .joint_test_fixture()
  tail_proposals <- .joint_test_proposals(
    tail_fixture, "committed-row-tamper")
  tail_prepares <- .joint_test_prepare_pair(tail_fixture, tail_proposals)
  .joint_test_commit_pair(tail_fixture, tail_prepares)
  tail_path <- .dsvert_joint_dp_ledger_path(
    tail_fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), tail_path)
  DBI::dbExecute(connection, paste(
    "UPDATE joint_records SET row_mac = ? WHERE query_id = ?"),
    params = list(strrep("0", 64L), tail_proposals$peer_a$query_id))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_prepare(
    tail_fixture$policies$peer_a,
    .joint_test_proposals(tail_fixture, "after-tail-tamper")$peer_a,
    .secret = tail_fixture$secrets$peer_a,
    .signer = tail_fixture$signer,
    .verifier = tail_fixture$verifier),
    "ledger failed its integrity check")
})

test_that("allocator fast state rejects authentic rollback and writes atomically", {
  rollback_fixture <- .joint_test_fixture()
  first <- .joint_test_proposals(rollback_fixture, "state-rollback-1")
  first_prepares <- .joint_test_prepare_pair(rollback_fixture, first)
  .joint_test_commit_pair(rollback_fixture, first_prepares)
  path <- .dsvert_joint_dp_ledger_path(
    rollback_fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  retained_state <- DBI::dbGetQuery(connection, paste(
    "SELECT state_json, state_mac FROM joint_allocator_state",
    "WHERE singleton = 1"))
  DBI::dbDisconnect(connection)

  second <- .joint_test_proposals(rollback_fixture, "state-rollback-2")
  second_prepares <- .joint_test_prepare_pair(rollback_fixture, second)
  .joint_test_commit_pair(rollback_fixture, second_prepares)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, paste(
    "UPDATE joint_allocator_state SET state_json = ?, state_mac = ?",
    "WHERE singleton = 1"), params = list(
      retained_state$state_json[[1L]], retained_state$state_mac[[1L]]))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_prepare(
    rollback_fixture$policies$peer_a,
    .joint_test_proposals(rollback_fixture, "after-authentic-rollback")$peer_a,
    .secret = rollback_fixture$secrets$peer_a,
    .signer = rollback_fixture$signer,
    .verifier = rollback_fixture$verifier),
    "metadata is inconsistent|tail does not match")

  atomic_fixture <- .joint_test_fixture()
  proposal <- .joint_test_proposals(atomic_fixture, "atomic-state-write")
  prepares <- .joint_test_prepare_pair(atomic_fixture, proposal)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_joint_dp_commit(
      atomic_fixture$policies$peer_a, prepares$peer_a, prepares$peer_b,
      .secret = atomic_fixture$secrets$peer_a,
      .signer = atomic_fixture$signer,
      .verifier = atomic_fixture$verifier),
    .dsvert_joint_dp_allocator_state_write = function(...) {
      stop("injected allocator-state write failure", call. = FALSE)
    },
    .package = "dsVert"), "injected allocator-state write failure")
  atomic_path <- .dsvert_joint_dp_ledger_path(
    atomic_fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), atomic_path)
  row <- DBI::dbGetQuery(connection,
    "SELECT state FROM joint_records WHERE query_id = ?",
    params = list(proposal$peer_a$query_id))
  metadata <- DBI::dbGetQuery(connection, paste(
    "SELECT key, value FROM joint_meta",
    "WHERE key IN ('next_index', 'chain_head')"))
  metadata <- stats::setNames(metadata$value, metadata$key)
  state <- .dsvert_joint_dp_allocator_state_read(
    connection, atomic_fixture$secrets$peer_a)
  DBI::dbDisconnect(connection)
  expect_identical(row$state[[1L]], "prepared")
  expect_identical(metadata[["next_index"]], "0")
  expect_identical(metadata[["chain_head"]], "GENESIS")
  expect_identical(state$committed_count, 0)
  expect_identical(state$prepared_query_id, proposal$peer_a$query_id)

  committed <- .dsvert_joint_dp_commit(
    atomic_fixture$policies$peer_a, prepares$peer_a, prepares$peer_b,
    .secret = atomic_fixture$secrets$peer_a,
    .signer = atomic_fixture$signer,
    .verifier = atomic_fixture$verifier)
  expect_identical(committed$phase, "committed")
})

test_that("allocator output tail detects tamper rollback and partial writes", {
  prepare_outputs <- function(label) {
    fixture <- .joint_test_fixture()
    proposals <- .joint_test_proposals(fixture, label)
    prepares <- .joint_test_prepare_pair(fixture, proposals)
    commits <- .joint_test_commit_pair(fixture, prepares)
    authorizations <- .joint_test_authorize_pair(fixture, commits)
    openings <- .joint_test_finalize_pair(fixture, authorizations)
    contract_hash <- digest::digest(
      paste0(label, "-result-contract"), algo = "sha256", serialize = FALSE)
    receipts <- lapply(names(fixture$policies), function(peer) {
      other <- setdiff(names(fixture$policies), peer)
      .dsvert_joint_dp_result_prepare(
        fixture$policies[[peer]], openings[[peer]], openings[[other]],
        charToRaw(paste0("masked-", peer)), contract_hash,
        .secret = fixture$secrets[[peer]], .signer = fixture$signer,
        .verifier = fixture$verifier)
    })
    list(
      fixture = fixture, proposals = proposals, openings = openings,
      contract_hash = contract_hash,
      receipts = stats::setNames(receipts, names(fixture$policies)))
  }

  rolled <- prepare_outputs("output-tail-rollback")
  policy <- rolled$fixture$policies$peer_a
  secret <- rolled$fixture$secrets$peer_a
  path <- .dsvert_joint_dp_ledger_path(policy)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  old_output <- DBI::dbGetQuery(connection,
    "SELECT * FROM joint_outputs WHERE query_id = ?",
    params = list(rolled$proposals$peer_a$query_id))
  state <- .dsvert_joint_dp_allocator_state_read(connection, secret)
  expect_identical(state$output_count, 1)
  expect_identical(
    state$output_tail_query_id, rolled$proposals$peer_a$query_id)
  expect_identical(state$output_tail_row_mac, old_output$row_mac[[1L]])
  DBI::dbDisconnect(connection)

  .dsvert_joint_dp_result_commit(
    policy, rolled$receipts$peer_a, rolled$receipts$peer_b,
    .secret = secret, .signer = rolled$fixture$signer,
    .verifier = rolled$fixture$verifier)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  current_output <- DBI::dbGetQuery(connection,
    "SELECT * FROM joint_outputs WHERE query_id = ?",
    params = list(rolled$proposals$peer_a$query_id))
  expect_false(identical(current_output$row_mac[[1L]], old_output$row_mac[[1L]]))
  DBI::dbExecute(connection, paste(
    "UPDATE joint_outputs SET state = ?, output_json = ?, row_mac = ?",
    "WHERE query_id = ?"), params = list(
      old_output$state[[1L]], old_output$output_json[[1L]],
      old_output$row_mac[[1L]], old_output$query_id[[1L]]))
  DBI::dbDisconnect(connection)
  expect_error({
    handle <- .dsvert_joint_dp_open_ledger(policy)
    on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, secret, rolled$fixture$verifier)
  }, "output tail is unavailable")

  deleted <- prepare_outputs("output-tail-delete")
  delete_policy <- deleted$fixture$policies$peer_a
  delete_secret <- deleted$fixture$secrets$peer_a
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(delete_policy))
  DBI::dbExecute(connection, "DELETE FROM joint_outputs WHERE query_id = ?",
    params = list(deleted$proposals$peer_a$query_id))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_result_prepare(
    delete_policy, deleted$openings$peer_a, deleted$openings$peer_b,
    charToRaw("masked-peer_a"), deleted$contract_hash,
    .secret = delete_secret, .signer = deleted$fixture$signer,
    .verifier = deleted$fixture$verifier),
    "output tail is unavailable")

  atomic <- .joint_test_fixture()
  atomic_proposals <- .joint_test_proposals(atomic, "output-tail-atomic")
  atomic_prepares <- .joint_test_prepare_pair(atomic, atomic_proposals)
  atomic_commits <- .joint_test_commit_pair(atomic, atomic_prepares)
  atomic_authorizations <- .joint_test_authorize_pair(atomic, atomic_commits)
  atomic_openings <- .joint_test_finalize_pair(atomic, atomic_authorizations)
  atomic_contract <- digest::digest(
    "output-tail-atomic-contract", algo = "sha256", serialize = FALSE)
  expect_error(testthat::with_mocked_bindings(
    .dsvert_joint_dp_result_prepare(
      atomic$policies$peer_a, atomic_openings$peer_a,
      atomic_openings$peer_b, charToRaw("masked-atomic"), atomic_contract,
      .secret = atomic$secrets$peer_a, .signer = atomic$signer,
      .verifier = atomic$verifier),
    .dsvert_joint_dp_allocator_state_write = function(...) {
      stop("injected output-state write failure", call. = FALSE)
    },
    .package = "dsVert"), "injected output-state write failure")
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(atomic$policies$peer_a))
  expect_identical(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM joint_outputs")$n[[1L]], 0L)
  state <- .dsvert_joint_dp_allocator_state_read(
    connection, atomic$secrets$peer_a)
  DBI::dbDisconnect(connection)
  expect_identical(state$output_count, 0)
  expect_null(state$output_tail_query_id)
  expect_null(state$output_tail_row_mac)
})

test_that("legacy allocator migration audits once and historical reuse stays safe", {
  fixture <- .joint_test_fixture()
  proposals <- vector("list", 2L)
  for (index in seq_len(2L)) {
    proposals[[index]] <- .joint_test_proposals(
      fixture, sprintf("fast-history-%02d", index))
    prepares <- .joint_test_prepare_pair(fixture, proposals[[index]])
    .joint_test_commit_pair(fixture, prepares)
  }
  path <- .dsvert_joint_dp_ledger_path(fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, "DELETE FROM joint_allocator_state")
  DBI::dbExecute(connection, paste(
    "DELETE FROM joint_meta WHERE key =",
    "'allocator_state_version'"))
  .dsvert_joint_dp_transaction(connection, {
    .dsvert_joint_dp_initialize_validate(
      connection, fixture$policies$peer_a,
      fixture$secrets$peer_a, fixture$verifier)
  })
  expect_invisible(testthat::with_mocked_bindings(
    .dsvert_joint_dp_initialize_validate(
      connection, fixture$policies$peer_a,
      fixture$secrets$peer_a, fixture$verifier),
    .dsvert_joint_dp_allocator_full_audit = function(...) {
      stop("full allocator audit entered", call. = FALSE)
    },
    .package = "dsVert"))

  first_id <- proposals[[1L]]$peer_a$query_id
  DBI::dbExecute(connection, paste(
    "UPDATE joint_records SET row_mac = ? WHERE query_id = ?"),
    params = list(strrep("0", 64L), first_id))
  expect_invisible(.dsvert_joint_dp_initialize_validate(
    connection, fixture$policies$peer_a,
    fixture$secrets$peer_a, fixture$verifier))
  expect_error(.dsvert_joint_dp_load(
    connection, first_id, fixture$secrets$peer_a),
    "ledger failed its integrity check")
  expect_error(.dsvert_joint_dp_allocator_forensic_audit(
    connection, fixture$policies$peer_a,
    fixture$secrets$peer_a, fixture$verifier),
    "ledger failed its integrity check")
  DBI::dbDisconnect(connection)
})

test_that("vacuous lifetime delta is rejected before allocator state", {
  fixture <- .joint_test_fixture()
  for (peer in names(fixture$policies)) {
    fixture$policies[[peer]]$global_total_delta <- 0.25
  }
  expect_false(file.exists(fixture$policies$peer_a$ledger_path))
  expect_error(
    .joint_test_proposals(fixture, "vacuous-delta", uses_delta = TRUE),
    "lifetime composition bound")
  expect_false(file.exists(fixture$policies$peer_a$ledger_path))
})

test_that("two designated peers allocate globally inside a larger pinset", {
  fixture <- .joint_test_fixture()
  full_pins <- c(
    fixture$policies$peer_a$peer_pinset,
    peer_c = .joint_test_b64url(as.raw(64L + seq_len(32L))))
  full_pins <- full_pins[order(names(full_pins), method = "radix")]
  full_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(full_pins)), algo = "sha256",
    serialize = FALSE)
  for (peer in names(fixture$policies)) {
    fixture$policies[[peer]]$peer_pinset <- full_pins
    fixture$policies[[peer]]$peer_pinset_sha256 <- full_hash
    fixture$policies[[peer]]$peer_count <- 3L
    fixture$policies[[peer]]$designated_noise_peers <-
      c("peer_b", "peer_a")
  }
  proposals <- .joint_test_proposals(fixture, "k3-designated")
  prepared <- .joint_test_prepare_pair(fixture, proposals)
  expect_equal(as.numeric(prepared$peer_a$epsilon), 1)
  expect_equal(as.numeric(prepared$peer_b$epsilon), 1)
  expect_equal(
    .dsvert_joint_dp_policy_context(fixture$policies$peer_a)$common$peer_count,
    3L)
  expect_identical(
    .dsvert_joint_dp_policy_context(
      fixture$policies$peer_a)$common$designated_noise_peers,
    c("peer_a", "peer_b"))

  non_designated <- fixture$policies$peer_a
  non_designated$peer_name <- "peer_c"
  expect_error(
    .dsvert_joint_dp_policy_context(non_designated),
    "Only a custodian-designated noise peer")
})

test_that("canonical query normalization and every receipt binding fail closed", {
  fixture <- .joint_test_fixture()
  canonical <- .joint_test_proposals(
    fixture, arguments_a = list(beta = c(2L, 3L), alpha = -0),
    arguments_b = list(alpha = 0, beta = c(2, 3)))
  expect_identical(canonical$peer_a$query_id, canonical$peer_b$query_id)

  # Recomputing the public mechanism hash is insufficient: the mechanism must
  # also be the one sealed into the operation-independent capsule identity.
  substituted <- canonical$peer_a
  substituted$common_query$mechanism$purpose <- "substituted-purpose"
  substituted$mechanism_hash <- .dsvert_joint_dp_hash(
    substituted$common_query$mechanism)
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_a, substituted,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer),
    "Invalid server-minted joint-DP proposal")

  prepares <- .joint_test_prepare_pair(fixture, canonical)
  rebound <- canonical$peer_a
  rebound$snapshot_binding <- strrep("9", 64L)
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_a, rebound,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer),
    "snapshot or mechanism changed")

  wrong_query <- prepares$peer_b
  wrong_query$capsule_id <- strrep("1", 64L)
  wrong_query$query_id <- strrep("1", 64L)
  wrong_query <- .joint_test_resign(wrong_query, fixture)
  expect_error(.dsvert_joint_dp_commit(
    fixture$policies$peer_a, prepares$peer_a, wrong_query,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "do not describe one allocation")

  mismatched_alias <- prepares$peer_b
  mismatched_alias$query_id <- strrep("8", 64L)
  mismatched_alias <- .joint_test_resign(mismatched_alias, fixture)
  expect_error(.dsvert_joint_dp_commit(
    fixture$policies$peer_a, prepares$peer_a, mismatched_alias,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier),
    "Invalid signed joint-DP receipt fields")

  wrong_epoch <- prepares$peer_b
  wrong_epoch$privacy_epoch <- "0"
  wrong_epoch <- .joint_test_resign(wrong_epoch, fixture)
  expect_error(.dsvert_joint_dp_commit(
    fixture$policies$peer_a, prepares$peer_a, wrong_epoch,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "Invalid signed joint-DP receipt fields")

  wrong_mechanism <- prepares$peer_b
  wrong_mechanism$mechanism_hash <- strrep("2", 64L)
  wrong_mechanism <- .joint_test_resign(wrong_mechanism, fixture)
  expect_error(.dsvert_joint_dp_commit(
    fixture$policies$peer_a, prepares$peer_a, wrong_mechanism,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "do not describe one allocation")

  wrong_snapshot <- prepares$peer_b
  wrong_snapshot$snapshot_binding <- strrep("3", 64L)
  wrong_snapshot <- .joint_test_resign(wrong_snapshot, fixture)
  expect_error(.dsvert_joint_dp_commit(
    fixture$policies$peer_b, prepares$peer_a, wrong_snapshot,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier), "conflicts with the local")

  wrong_peer <- prepares$peer_b
  wrong_peer$peer_name <- "peer_a"
  wrong_peer$peer_identity_pk <-
    fixture$policies$peer_a$peer_pinset[["peer_a"]]
  wrong_peer <- .joint_test_resign(wrong_peer, fixture)
  expect_error(.dsvert_joint_dp_commit(
    fixture$policies$peer_a, prepares$peer_a, wrong_peer,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "one receipt from each")

  unsigned_tamper <- prepares$peer_b
  unsigned_tamper$snapshot_binding <- strrep("4", 64L)
  expect_error(.dsvert_joint_dp_commit(
    fixture$policies$peer_a, prepares$peer_a, unsigned_tamper,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "signature verification failed")
})

test_that("leader assignment prevents adversarial A/B head forks", {
  fixture <- .joint_test_fixture()
  proposals_a <- .joint_test_proposals(fixture, "fork-a")
  proposals_b <- .joint_test_proposals(fixture, "fork-b")

  # Seeing B first cannot make the follower reserve an independent head.
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_b, proposals_b$peer_b,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier),
    "requires the signed leader assignment")

  prepare_a <- .dsvert_joint_dp_prepare(
    fixture$policies$peer_a, proposals_a$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)

  # A valid leader receipt cannot be rebound to B, and the leader cannot
  # allocate B while A is the durable prepared head.
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_b, proposals_b$peer_b,
    leader_prepare = prepare_a,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier),
    "does not match the local proposal")
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_a, proposals_b$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier),
    "already occupies the consensus head")

  prepare_b <- .dsvert_joint_dp_prepare(
    fixture$policies$peer_b, proposals_a$peer_b,
    leader_prepare = prepare_a,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_true(.dsvert_joint_dp_same_prepare_assignment(
    prepare_a, prepare_b))

  for (peer in names(fixture$policies)) {
    connection <- DBI::dbConnect(
      RSQLite::SQLite(),
      .dsvert_joint_dp_ledger_path(fixture$policies[[peer]]))
    rows <- DBI::dbGetQuery(
      connection,
      "SELECT query_id, sequence, state FROM joint_records ORDER BY sequence")
    DBI::dbDisconnect(connection)
    expect_equal(nrow(rows), 1L)
    expect_identical(rows$query_id[[1L]], proposals_a[[peer]]$query_id)
    expect_identical(as.numeric(rows$sequence[[1L]]), 0)
    expect_identical(rows$state[[1L]], "prepared")
  }

  commits <- .joint_test_commit_pair(
    fixture, list(peer_a = prepare_a, peer_b = prepare_b))
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  .joint_test_finalize_pair(fixture, authorizations)
  next_prepares <- .joint_test_prepare_pair(fixture, proposals_b)
  expect_identical(next_prepares$peer_a$allocation_index, "1")
  expect_identical(next_prepares$peer_b$allocation_index, "1")
})

test_that("every durable crash phase is replayable without a reroll", {
  fixture <- .joint_test_fixture(external_anchor = TRUE)
  proposals <- .joint_test_proposals(fixture, "crash")
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_a, proposals$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .phase_hook = function(phase) stop(phase, call. = FALSE)),
    "after_prepare_commit")
  prepare_a <- .dsvert_joint_dp_prepare(
    fixture$policies$peer_a, proposals$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_b, proposals$peer_b,
    leader_prepare = prepare_a,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) stop(phase, call. = FALSE)),
    "after_prepare_commit")
  prepare_b <- .dsvert_joint_dp_prepare(
    fixture$policies$peer_b, proposals$peer_b,
    leader_prepare = prepare_a,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier)

  expect_error(.dsvert_joint_dp_commit(
    fixture$policies$peer_a, prepare_a, prepare_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) {
      if (identical(phase, "after_local_commit")) stop(phase, call. = FALSE)
    }), "after_local_commit")
  commit_a <- .dsvert_joint_dp_commit(
    fixture$policies$peer_a, prepare_a, prepare_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_error(.dsvert_joint_dp_commit(
    fixture$policies$peer_b, prepare_a, prepare_b,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) {
      if (identical(phase, "after_external_anchor")) stop(phase, call. = FALSE)
    }), "after_external_anchor")
  commit_b <- .dsvert_joint_dp_commit(
    fixture$policies$peer_b, prepare_a, prepare_b,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier)

  expect_error(.dsvert_joint_dp_authorize(
    fixture$policies$peer_a, commit_a, commit_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) stop(phase, call. = FALSE)),
    "after_authorization_commit")
  authorization_a <- .dsvert_joint_dp_authorize(
    fixture$policies$peer_a, commit_a, commit_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)
  authorization_b <- .dsvert_joint_dp_authorize(
    fixture$policies$peer_b, commit_a, commit_b,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_error(.dsvert_joint_dp_finalize_authorization(
    fixture$policies$peer_a, authorization_a, authorization_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) stop(phase, call. = FALSE)),
    "after_open_authorization_commit")
  token <- .dsvert_joint_dp_finalize_authorization(
    fixture$policies$peer_a, authorization_a, authorization_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_identical(token$capability_available, FALSE)
})

test_that("result bytes are durably mapped and cross-signed before delivery", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "result-map")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  openings <- .joint_test_finalize_pair(fixture, authorizations)
  contract_hash <- digest::digest(
    "fixed-shape-noised-result-v1", algo = "sha256", serialize = FALSE)
  payloads <- list(
    peer_a = charToRaw('{"share":"alpha","value":17}'),
    peer_b = charToRaw('{"share":"beta","value":29}'))

  expect_error(.dsvert_joint_dp_result_prepare(
    fixture$policies$peer_a, openings$peer_a, openings$peer_b,
    payloads$peer_a, contract_hash,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) stop(phase, call. = FALSE)),
    "after_result_persist")
  result_prepares <- lapply(names(fixture$policies), function(peer) {
    other <- setdiff(names(fixture$policies), peer)
    .dsvert_joint_dp_result_prepare(
      fixture$policies[[peer]], openings[[peer]], openings[[other]],
      payloads[[peer]], contract_hash,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier)
  })
  result_prepares <- stats::setNames(
    result_prepares, names(fixture$policies))
  expect_identical(.dsvert_joint_dp_result_prepare(
    fixture$policies$peer_a, openings$peer_a, openings$peer_b,
    payloads$peer_a, contract_hash,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), result_prepares$peer_a)
  expect_false(any(grepl("alpha|beta", jsonlite::toJSON(
    result_prepares, auto_unbox = TRUE, null = "null"))))
  tampered <- result_prepares$peer_b
  tampered$result_contract_hash <- strrep("0", 64L)
  expect_error(.dsvert_joint_dp_result_commit(
    fixture$policies$peer_a, result_prepares$peer_a, tampered,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "signature verification failed")
  expect_error(.dsvert_joint_dp_result_prepare(
    fixture$policies$peer_a, openings$peer_a, openings$peer_b,
    charToRaw("different-result"), contract_hash,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "Conflicting replay")

  expect_error(.dsvert_joint_dp_result_commit(
    fixture$policies$peer_a,
    result_prepares$peer_a, result_prepares$peer_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) stop(phase, call. = FALSE)),
    "after_result_commit")
  result_commits <- lapply(names(fixture$policies), function(peer) {
    .dsvert_joint_dp_result_commit(
      fixture$policies[[peer]],
      result_prepares$peer_a, result_prepares$peer_b,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier)
  })
  result_commits <- stats::setNames(result_commits, names(fixture$policies))
  expect_identical(result_commits$peer_a$result_set_hash,
                   result_commits$peer_b$result_set_hash)
  expect_identical(.dsvert_joint_dp_result_commit(
    fixture$policies$peer_a,
    result_prepares$peer_b, result_prepares$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), result_commits$peer_a)

  mismatched_commit <- result_commits$peer_b
  mismatched_commit$payload_commitment <- strrep("f", 64L)
  mismatched_commit <- .joint_test_resign(mismatched_commit, fixture)
  expect_error(.dsvert_joint_dp_finalize_delivery(
    fixture$policies$peer_a, result_commits$peer_a, mismatched_commit,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "does not match its peer's prepared payload")

  expect_error(.dsvert_joint_dp_finalize_delivery(
    fixture$policies$peer_a, result_commits$peer_a, result_commits$peer_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) stop(phase, call. = FALSE)),
    "after_delivery_authorization")
  delivery_tokens <- lapply(names(fixture$policies), function(peer) {
    .dsvert_joint_dp_finalize_delivery(
      fixture$policies[[peer]], result_commits$peer_a,
      result_commits$peer_b, .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .verifier = fixture$verifier)
  })
  delivery_tokens <- stats::setNames(
    delivery_tokens, names(fixture$policies))
  expect_identical(.dsvert_joint_dp_finalize_delivery(
    fixture$policies$peer_a, result_commits$peer_b,
    result_commits$peer_a, .secret = fixture$secrets$peer_a,
    .signer = fixture$signer, .verifier = fixture$verifier),
    delivery_tokens$peer_a)
  contract <- .dsvert_joint_dp_delivery_contract(
    fixture$policies$peer_a, delivery_tokens$peer_a,
    delivery_tokens$peer_b, .secret = fixture$secrets$peer_a,
    .verifier = fixture$verifier)
  expect_identical(contract$capability_available, FALSE)
  expect_identical(contract$payload_delivery_available, FALSE)
  expect_true(contract$payload_persisted)
  expect_false(contract$payload_exposed)
  expect_false(any(c("payload", "payload_b64") %in% names(contract)))

  ledger <- .dsvert_joint_dp_ledger_path(fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  expect_equal(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM joint_outputs")$n[[1L]], 1)
  expect_identical(DBI::dbGetQuery(
    connection,
    "SELECT value FROM joint_meta WHERE key = 'next_index'")$value[[1L]],
    "1")
  DBI::dbExecute(
    connection, "UPDATE joint_outputs SET row_mac = ?",
    params = list(strrep("0", 64L)))
  expect_error(.dsvert_joint_dp_delivery_contract(
    fixture$policies$peer_a, delivery_tokens$peer_a,
    delivery_tokens$peer_b, .secret = fixture$secrets$peer_a,
    .verifier = fixture$verifier), "output tail is unavailable")
})

test_that("relay-visible result commitments resist a low-entropy dictionary", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "result-dictionary")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  openings <- .joint_test_finalize_pair(fixture, authorizations)
  contract_hash <- digest::digest(
    "one-byte-result-contract", algo = "sha256", serialize = FALSE)
  payload <- as.raw(7L)
  receipt <- .dsvert_joint_dp_result_prepare(
    fixture$policies$peer_a, openings$peer_a, openings$peer_b,
    payload, contract_hash, .secret = fixture$secrets$peer_a,
    .signer = fixture$signer, .verifier = fixture$verifier)

  expect_identical(
    receipt$version, "dsvert-joint-dp-result-prepare-receipt-v2")
  expect_true(grepl("^[0-9a-f]{64}$", receipt$payload_commitment))
  expect_false(any(c("payload", "payload_b64", "payload_hash") %in%
                   names(receipt)))

  # This is the complete 256-value dictionary that recovered a one-byte
  # payload from the former public SHA256(context || payload) commitment.
  old_public_dictionary <- vapply(0:255, function(candidate) {
    digest::digest(c(
      charToRaw(paste0(
        "dsVert/joint-dp/result-payload/v1|", receipt$query_id, "|",
        receipt$opening_set_hash, "|", receipt$result_contract_hash, "|")),
      as.raw(candidate)), algo = "sha256", serialize = FALSE)
  }, character(1L))
  expect_false(receipt$payload_commitment %in% old_public_dictionary)
  expect_identical(receipt$payload_commitment,
    .dsvert_joint_dp_payload_commitment(
      fixture$secrets$peer_a, receipt$query_id,
      receipt$opening_set_hash, receipt$result_contract_hash, payload))
  expect_false(identical(receipt$payload_commitment,
    .dsvert_joint_dp_payload_commitment(
      fixture$secrets$peer_b, receipt$query_id,
      receipt$opening_set_hash, receipt$result_contract_hash, payload)))
  expect_false(identical(receipt$payload_commitment,
    .dsvert_joint_dp_payload_commitment(
      fixture$secrets$peer_a, receipt$query_id,
      receipt$opening_set_hash, receipt$result_contract_hash, as.raw(8L))))

  # Every call closes the SQLite handle. Re-entering with the same persistent
  # key models a fresh service process and must return the byte-identical
  # receipt; substituting another valid 256-bit key must fail before mutation.
  restart_replay <- .dsvert_joint_dp_result_prepare(
    fixture$policies$peer_a, openings$peer_a, openings$peer_b,
    payload, contract_hash, .secret = fixture$secrets$peer_a,
    .signer = fixture$signer, .verifier = fixture$verifier)
  expect_identical(restart_replay, receipt)
  expect_error(.dsvert_joint_dp_result_prepare(
    fixture$policies$peer_a, openings$peer_a, openings$peer_b,
    payload, contract_hash, .secret = fixture$secrets$peer_b,
    .signer = fixture$signer, .verifier = fixture$verifier),
    "ledger does not match|integrity check")
  expect_identical(.dsvert_joint_dp_result_prepare(
    fixture$policies$peer_a, openings$peer_a, openings$peer_b,
    payload, contract_hash, .secret = fixture$secrets$peer_a,
    .signer = fixture$signer, .verifier = fixture$verifier), receipt)

  legacy <- receipt
  legacy$version <- "dsvert-joint-dp-result-prepare-receipt-v1"
  legacy$payload_hash <- legacy$payload_commitment
  legacy$payload_commitment <- NULL
  legacy <- .joint_test_resign(legacy, fixture)
  expect_error(.dsvert_joint_dp_result_commit(
    fixture$policies$peer_a, receipt, legacy,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "Invalid signed joint-DP receipt")
})

test_that("concurrent identical result persistence has one durable mapping", {
  skip_on_os("windows")
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "result-race")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  openings <- .joint_test_finalize_pair(fixture, authorizations)
  contract_hash <- digest::digest(
    "race-result-contract", algo = "sha256", serialize = FALSE)
  values <- parallel::mclapply(seq_len(4L), function(index) {
    tryCatch(.dsvert_joint_dp_result_prepare(
      fixture$policies$peer_a, openings$peer_a, openings$peer_b,
      charToRaw("same-sticky-result"), contract_hash,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer,
      .verifier = fixture$verifier), error = identity)
  }, mc.cores = 2L)
  expect_false(any(vapply(values, inherits, logical(1L), "error")))
  expect_true(all(vapply(values[-1L], identical, logical(1L), values[[1L]])))
  ledger <- .dsvert_joint_dp_ledger_path(fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  expect_equal(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM joint_outputs")$n[[1L]], 1)
})

test_that("the output tail stops one-peer payload rollback locally", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "result-rollback")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  openings <- .joint_test_finalize_pair(fixture, authorizations)
  contract_hash <- digest::digest(
    "rollback-result-contract", algo = "sha256", serialize = FALSE)
  payloads <- list(peer_a = charToRaw("sticky-a"),
                   peer_b = charToRaw("sticky-b"))
  result_prepares <- lapply(names(fixture$policies), function(peer) {
    other <- setdiff(names(fixture$policies), peer)
    .dsvert_joint_dp_result_prepare(
      fixture$policies[[peer]], openings[[peer]], openings[[other]],
      payloads[[peer]], contract_hash, .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .verifier = fixture$verifier)
  })
  result_prepares <- stats::setNames(
    result_prepares, names(fixture$policies))
  result_commits <- lapply(names(fixture$policies), function(peer) {
    .dsvert_joint_dp_result_commit(
      fixture$policies[[peer]], result_prepares$peer_a,
      result_prepares$peer_b, .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .verifier = fixture$verifier)
  })
  result_commits <- stats::setNames(result_commits, names(fixture$policies))
  .dsvert_joint_dp_finalize_delivery(
    fixture$policies$peer_b, result_commits$peer_a, result_commits$peer_b,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier)

  ledger_a <- .dsvert_joint_dp_ledger_path(fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger_a)
  DBI::dbExecute(connection, "DELETE FROM joint_outputs")
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_result_prepare(
    fixture$policies$peer_a, openings$peer_a, openings$peer_b,
    charToRaw("rerolled-a"), contract_hash,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "output tail is unavailable")
})

test_that("one-peer rollback is stopped by the retained cross-signed head", {
  fixture <- .joint_test_fixture()
  first <- .joint_test_proposals(fixture, "rollback-1")
  first_prepares <- .joint_test_prepare_pair(fixture, first)
  first_commits <- .joint_test_commit_pair(fixture, first_prepares)
  first_authorizations <- .joint_test_authorize_pair(fixture, first_commits)
  .joint_test_finalize_pair(fixture, first_authorizations)

  ledger_a <- .dsvert_joint_dp_ledger_path(fixture$policies$peer_a)
  backup <- paste0(ledger_a, ".rollback-copy")
  expect_true(file.copy(ledger_a, backup, overwrite = TRUE))

  second <- .joint_test_proposals(fixture, "rollback-2")
  second_prepares <- .joint_test_prepare_pair(fixture, second)
  second_commits <- .joint_test_commit_pair(fixture, second_prepares)
  second_authorizations <- .joint_test_authorize_pair(fixture, second_commits)
  .joint_test_finalize_pair(fixture, second_authorizations)

  unlink(c(ledger_a, paste0(ledger_a, "-wal"), paste0(ledger_a, "-shm")),
         force = TRUE)
  expect_true(file.copy(backup, ledger_a, overwrite = TRUE))
  third <- .joint_test_proposals(fixture, "rollback-3")
  prepare_a <- .dsvert_joint_dp_prepare(
    fixture$policies$peer_a, third$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_identical(prepare_a$allocation_index, "1")
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_b, third$peer_b,
    leader_prepare = prepare_a,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier),
    "leader assignment conflicts with the follower consensus head")
})

test_that("optional external CAS detects local rollback before prepare", {
  fixture <- .joint_test_fixture(external_anchor = TRUE)
  first <- .joint_test_proposals(fixture, "anchor-1")
  prepares <- .joint_test_prepare_pair(fixture, first)
  ledger_a <- .dsvert_joint_dp_ledger_path(fixture$policies$peer_a)
  backup <- paste0(ledger_a, ".before-commit")
  expect_true(file.copy(ledger_a, backup, overwrite = TRUE))
  .joint_test_commit_pair(fixture, prepares)
  # Restore an authentic local image from before the externally anchored
  # allocation. The anchor must be observed ahead before a new prepare.
  unlink(c(ledger_a, paste0(ledger_a, "-wal"), paste0(ledger_a, "-shm")),
         force = TRUE)
  expect_true(file.copy(backup, ledger_a, overwrite = TRUE))
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_a,
    .joint_test_proposals(fixture, "anchor-2")$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer),
    "anchor is ahead")
})

test_that("concurrent identical prepare calls reserve one sticky head", {
  skip_on_os("windows")
  fixture <- .joint_test_fixture()
  proposal <- .joint_test_proposals(fixture, "concurrent")$peer_a
  values <- parallel::mclapply(seq_len(4L), function(index) {
    tryCatch(.dsvert_joint_dp_prepare(
      fixture$policies$peer_a, proposal,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer),
      error = identity)
  }, mc.cores = 2L)
  expect_false(any(vapply(values, inherits, logical(1L), "error")))
  expect_true(all(vapply(values[-1L], identical, logical(1L), values[[1L]])))
  ledger <- .dsvert_joint_dp_ledger_path(fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  expect_equal(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM joint_records")$n[[1L]], 1)
})

test_that("v2 bounded-source integers exactly respect every supported signed ring", {
  limits <- c(
    `63` = "4611686018427387904",
    `127` = "85070591730234615865843651857942052864",
    `128` = "170141183460469231731687303715884105728",
    `256` = paste0(
      "578960446186580977117854925043439539266349923328202820197287920039",
      "56564819968"),
    `512` = paste0(
      "670390396497129854978701249910292306373968291029619668886178072186",
      "088201503677348840093714908345171384501592909324302542687694140597",
      "3284973216824503042048"))
  decimal_minus_one <- function(x) {
    digits <- rev(utf8ToInt(x) - utf8ToInt("0"))
    index <- 1L
    while (digits[[index]] == 0L) {
      digits[[index]] <- 9L
      index <- index + 1L
    }
    digits[[index]] <- digits[[index]] - 1L
    paste0(rev(digits), collapse = "")
  }
  decimal_plus_one <- function(x) {
    digits <- rev(utf8ToInt(x) - utf8ToInt("0"))
    index <- 1L
    carry <- 1L
    while (carry && index <= length(digits)) {
      value <- digits[[index]] + carry
      digits[[index]] <- value %% 10L
      carry <- value %/% 10L
      index <- index + 1L
    }
    if (carry) digits <- c(digits, carry)
    paste0(rev(digits), collapse = "")
  }
  for (ring_name in names(limits)) {
    ring_bits <- as.integer(ring_name)
    limit <- limits[[ring_name]]
    source <- list(
      version = .DSVERT_JOINT_DP_BACKEND_SOURCE_V2,
      producer = "bounded.count.vector.v2",
      purpose = "joint_dp_ring_boundary_test",
      source_context_hash = strrep("c", 64L),
      ring_bits = ring_bits, frac_bits = 1L, coordinate_count = 1L,
      encoded_lower = paste0("-", limit),
      encoded_upper = decimal_minus_one(limit), sensitivity_steps = "1")
    mechanism <- list(
      producer = source$producer, purpose = source$purpose,
      source_context_hash = source$source_context_hash,
      ring_bits = ring_bits, frac_bits = 1L, coordinate_count = 1L,
      sensitivity = 1)
    mechanism$clipping_hash <- .dsvert_joint_dp_hash(source)
    expect_silent(.dsvert_joint_dp_backend_source_v2(source, mechanism))

    invalid <- source
    invalid$encoded_upper <- limit
    mechanism$clipping_hash <- .dsvert_joint_dp_hash(invalid)
    expect_error(.dsvert_joint_dp_backend_source_v2(invalid, mechanism),
                 "Invalid server-minted")
    invalid <- source
    invalid$encoded_lower <- paste0("-", decimal_plus_one(limit))
    mechanism$clipping_hash <- .dsvert_joint_dp_hash(invalid)
    expect_error(.dsvert_joint_dp_backend_source_v2(invalid, mechanism),
                 "Invalid server-minted")
    invalid <- source
    invalid$encoded_upper <- paste0(limit, "0")
    mechanism$clipping_hash <- .dsvert_joint_dp_hash(invalid)
    expect_error(.dsvert_joint_dp_backend_source_v2(invalid, mechanism),
                 "Invalid server-minted")
  }
})

test_that("v2 backend preflight uses raw-seed commitments and stays unavailable", {
  fixture <- .joint_test_fixture()
  source <- list(
    version = .DSVERT_JOINT_DP_BACKEND_SOURCE_V2,
    producer = "bounded.count.vector.v2",
    purpose = "joint_dp_test_count_vector",
    source_context_hash = strrep("c", 64L),
    ring_bits = 63L, frac_bits = 20L, coordinate_count = 4L,
    encoded_lower = "0", encoded_upper = as.character(1000L * 2^20),
    sensitivity_steps = "2")
  mechanism <- list(
    release_scope = .DSVERT_JOINT_DP_SCOPE,
    capability_id = .DSVERT_JOINT_DP_CAPABILITY,
    producer = source$producer, purpose = source$purpose,
    source_context_hash = source$source_context_hash,
    mechanism = "discrete-laplace-geometric-tv-v2",
    mechanism_version = "joint-sampler-v2",
    sampler = .DSVERT_JOINT_DP_SAMPLER,
    sensitivity_norm = "l1", sensitivity = 2,
    coordinate_count = 4L, uses_delta = TRUE,
    clipping_hash = .dsvert_joint_dp_hash(source),
    ring_bits = 63L, frac_bits = 20L)
  snapshot <- list(
    logical_snapshot_id = "aligned-cohort-v2", version = "v2",
    alignment_protocol_version = 2L)
  proposals <- lapply(names(fixture$policies), function(peer) {
    capsule_identity <- .dsvert_joint_dp_capsule_identity(
      fixture$policies[[peer]], snapshot,
      capsule_schema = "backend-v2-test-capsule-v1",
      admission = list(
        adjacency = fixture$policies[[peer]]$adjacency,
        unit_capacity = fixture$policies[[peer]]$unit_capacity,
        max_records_per_unit =
          fixture$policies[[peer]]$max_records_per_unit,
        overflow_policy = fixture$policies[[peer]]$overflow_policy),
      bounds = list(source_contract_hash = .dsvert_joint_dp_hash(source)),
      workload = list(
        capsule_mechanism = mechanism,
        workload_version = "backend-v2-test-workload-v1"))
    .dsvert_joint_dp_proposal(
      fixture$policies[[peer]], snapshot, "joint_dp_backend_test",
      list(statistic = "count-vector"),
      digest::digest(paste0("backend-v2-", peer), algo = "sha256",
                     serialize = FALSE),
      mechanism, capsule_identity = capsule_identity,
      .secret = fixture$secrets[[peer]])
  })
  proposals <- stats::setNames(proposals, names(fixture$policies))
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  openings <- .joint_test_finalize_pair(fixture, authorizations)
  planner <- function(epsilon, delta, sensitivity_steps, coordinate_count,
                      bernoulli_bits, max_steps) {
    list(
      version = "dsvert-joint-dp-laplace-plan-v2",
      sampler = .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2,
      bernoulli_bits = 8L, stop_numerator = "51",
      max_geometric_steps = 76L, sensitivity_steps = "2",
      coordinate_count = 4L,
      epsilon_effective_upper_numerator = "102",
      epsilon_effective_upper_denominator = "205",
      implementation_delta_numerator = "1",
      implementation_delta_denominator = "3000000",
      implementation_delta_bound = "1/3000000",
      accounting = "test exact-rational certificate",
      bernoulli_trials = 608L, aes_blocks = 38L,
      capability_available = FALSE,
      unavailable_reason =
        "linear_fixed_trial_sampler_not_promoted_for_general_biomedical_workloads")
  }
  backend_prepares <- lapply(names(fixture$policies), function(peer) {
    other <- setdiff(names(fixture$policies), peer)
    .dsvert_joint_dp_backend_prepare_v2(
      fixture$policies[[peer]], openings[[peer]], openings[[other]], source,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier, .planner = planner)
  })
  backend_prepares <- stats::setNames(
    backend_prepares, names(fixture$policies))
  expect_identical(
    vapply(backend_prepares, `[[`, character(1L), "role"),
    c(peer_a = "garbler", peer_b = "evaluator"))
  expect_false(any(vapply(names(backend_prepares), function(peer) {
    identical(backend_prepares[[peer]]$seed_commitment_v2,
              openings[[peer]]$seed_commitment)
  }, logical(1L))))
  expect_identical(backend_prepares$peer_a$transcript_hash,
                   backend_prepares$peer_b$transcript_hash)
  tokens <- lapply(names(fixture$policies), function(peer) {
    .dsvert_joint_dp_backend_token_v2(
      fixture$policies[[peer]], backend_prepares$peer_a,
      backend_prepares$peer_b, .signer = fixture$signer,
      .verifier = fixture$verifier)
  })
  tokens <- stats::setNames(tokens, names(fixture$policies))
  expect_true(all(vapply(tokens, function(value) {
    identical(value$capability_available, FALSE) &&
      identical(value$worker_attestation_available, FALSE)
  }, logical(1L))))
  expect_identical(tokens$peer_a$semantic_circuit_contract_hash,
                   tokens$peer_b$semantic_circuit_contract_hash)
  expect_false(any(grepl("private_seed|seed_hex", jsonlite::toJSON(
    tokens, auto_unbox = TRUE, null = "null"), fixed = FALSE)))

  tampered <- backend_prepares$peer_b
  tampered$commitment_context <- strrep("0", 64L)
  tampered$signature <- NULL
  tampered <- .dsvert_joint_dp_backend_sign_v2(
    tampered, fixture$policies$peer_b, fixture$signer)
  expect_error(.dsvert_joint_dp_backend_token_v2(
    fixture$policies$peer_a, backend_prepares$peer_a, tampered,
    .signer = fixture$signer, .verifier = fixture$verifier),
    "conflict")
  expect_error(.dsvert_joint_dp_local_seed(
    fixture$policies$peer_a, openings$peer_a,
    .secret = fixture$secrets$peer_a, .verifier = fixture$verifier),
    "not promoted")
})

test_that("each local allocator commit atomically reserves its registry sequence", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "registry-binding")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- list()

  for (peer in names(fixture$policies)) {
    expect_error(.dsvert_joint_dp_commit(
      fixture$policies[[peer]], prepares$peer_a, prepares$peer_b,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier,
      .phase_hook = function(phase) {
        if (identical(phase, "after_commit_activation")) {
          stop(phase, call. = FALSE)
        }
      }), "after_commit_activation")
    config <- .dsvert_capsule_registry_config_from_policy(
      fixture$policies[[peer]])
    expect_false(file.exists(config$registry_path))
    connection <- DBI::dbConnect(
      RSQLite::SQLite(),
      .dsvert_joint_dp_ledger_path(fixture$policies[[peer]]))
    journal <- DBI::dbGetQuery(connection, paste(
      "SELECT state, allocator_sequence, registry_sequence, journal_json",
      "FROM joint_capsule_registry"))
    record <- .dsvert_joint_dp_load(
      connection, proposals[[peer]]$query_id, fixture$secrets[[peer]])
    allocator <- .dsvert_joint_dp_allocator_state_read(
      connection, fixture$secrets[[peer]])
    reservation_state <- .dsvert_joint_dp_registry_state_read(
      connection, config, fixture$secrets[[peer]])
    DBI::dbDisconnect(connection)
    expect_equal(nrow(journal), 1L)
    expect_identical(journal$state[[1L]], "pending")
    expect_identical(as.numeric(journal$allocator_sequence[[1L]]), 0)
    expect_identical(as.numeric(journal$registry_sequence[[1L]]), 0)
    reservation <- jsonlite::fromJSON(
      journal$journal_json[[1L]], simplifyVector = FALSE)
    expect_identical(
      reservation$prepare_set_hash, record$own_commit$prepare_set_hash)
    expect_identical(
      reservation$own_commit_hash,
      .dsvert_joint_dp_hash(record$own_commit))
    expect_identical(
      reservation$reservation_evidence,
      "two_signed_prepares_plus_own_signed_commit")
    expect_identical(allocator$committed_count, 1)
    expect_identical(allocator$registry_eligible_count, 1)
    expect_identical(reservation_state$journal_count, 1)
    expect_identical(reservation_state$registered_count, 0)

    commits[[peer]] <- .dsvert_joint_dp_commit(
      fixture$policies[[peer]], prepares$peer_a, prepares$peer_b,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier)
    expect_identical(commits[[peer]], record$own_commit)
    expect_identical(
      .dsvert_capsule_registry_status(
        config, fixture$secrets[[peer]])$capsule_count,
      1)
  }

  commits <- commits[names(fixture$policies)]
  authorizations <- .joint_test_authorize_pair(fixture, commits)
  for (peer in names(fixture$policies)) {
    config <- .dsvert_capsule_registry_config_from_policy(
      fixture$policies[[peer]])
    snapshot <- .dsvert_capsule_registry_snapshot(
      config, fixture$secrets[[peer]])
    expect_identical(snapshot$summary$capsule_count, 1)
    expect_true(snapshot$summary$operation_limit)
    expect_true(snapshot$summary$history_can_deny_operation)
    expect_identical(
      snapshot$summary$operation_accounting,
      "one_per_distinct_capsule_allocator_commit")

    connection <- DBI::dbConnect(
      RSQLite::SQLite(),
      .dsvert_joint_dp_ledger_path(fixture$policies[[peer]]))
    journal <- DBI::dbGetQuery(connection, paste(
      "SELECT state, allocator_sequence, registry_sequence, journal_json",
      "FROM joint_capsule_registry"))
    DBI::dbDisconnect(connection)
    expect_identical(journal$state[[1L]], "registered")
    expect_identical(as.numeric(journal$allocator_sequence[[1L]]), 0)
    expect_identical(as.numeric(journal$registry_sequence[[1L]]), 0)
    binding <- jsonlite::fromJSON(
      journal$journal_json[[1L]], simplifyVector = FALSE)
    expect_identical(binding$capsule_id, proposals[[peer]]$capsule_id)
    expect_identical(binding$query_id, binding$capsule_id)
    expect_identical(binding$joint_record_hash,
                     commits[[peer]]$joint_record_hash)
    expect_identical(binding$prepare_set_hash,
                     commits[[peer]]$prepare_set_hash)
    expect_identical(binding$own_commit_hash,
                     .dsvert_joint_dp_hash(commits[[peer]]))
    expect_true(binding$operation_limit)
    expect_true(binding$history_can_deny_operation)
    expect_false(binding$capability_available)

    replay <- .dsvert_joint_dp_authorize(
      fixture$policies[[peer]], commits$peer_b, commits$peer_a,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier)
    expect_identical(replay, authorizations[[peer]])
    expect_identical(.dsvert_capsule_registry_status(
      config, fixture$secrets[[peer]])$capsule_count, 1)
    connection <- DBI::dbConnect(
      RSQLite::SQLite(),
      .dsvert_joint_dp_ledger_path(fixture$policies[[peer]]))
    allocator <- .dsvert_joint_dp_allocator_state_read(
      connection, fixture$secrets[[peer]])
    reservation_state <- .dsvert_joint_dp_registry_state_read(
      connection, config, fixture$secrets[[peer]])
    DBI::dbDisconnect(connection)
    expect_identical(allocator$committed_count, 1)
    expect_identical(allocator$registry_eligible_count, 1)
    expect_identical(reservation_state$journal_count, 1)
    expect_identical(reservation_state$registered_count, 1)
  }
})

test_that("allocator-registry crash phases reconcile without duplicate charge", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "registry-crash")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  config <- .dsvert_capsule_registry_config_from_policy(policy)

  expect_error(.dsvert_joint_dp_commit(
    policy, prepares$peer_a, prepares$peer_b,
    .secret = secret, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) {
      if (identical(phase, "after_commit_activation")) {
        stop(phase, call. = FALSE)
      }
    }), "after_commit_activation")
  expect_false(file.exists(config$registry_path))

  read_journal <- function() {
    connection <- DBI::dbConnect(
      RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(policy))
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    DBI::dbGetQuery(connection, paste(
      "SELECT state, allocator_sequence, registry_sequence",
      "FROM joint_capsule_registry"))
  }
  expect_identical(read_journal()$state[[1L]], "pending")

  expect_error(.dsvert_joint_dp_commit(
    policy, prepares$peer_a, prepares$peer_b,
    .secret = secret, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) {
      if (identical(phase, "after_capsule_registry_register")) {
        stop(phase, call. = FALSE)
      }
    }), "after_capsule_registry_register")
  expect_identical(read_journal()$state[[1L]], "pending")
  expect_identical(
    .dsvert_capsule_registry_status(config, secret)$capsule_count, 1)

  expect_error(.dsvert_joint_dp_commit(
    policy, prepares$peer_a, prepares$peer_b,
    .secret = secret, .signer = fixture$signer,
    .verifier = fixture$verifier,
    .phase_hook = function(phase) {
      if (identical(phase, "after_capsule_registry_binding_commit")) {
        stop(phase, call. = FALSE)
      }
    }), "after_capsule_registry_binding_commit")
  journal <- read_journal()
  expect_identical(journal$state[[1L]], "registered")
  expect_identical(as.numeric(journal$allocator_sequence[[1L]]), 0)
  expect_identical(as.numeric(journal$registry_sequence[[1L]]), 0)

  commit_a <- .dsvert_joint_dp_commit(
    policy, prepares$peer_a, prepares$peer_b,
    .secret = secret, .signer = fixture$signer,
    .verifier = fixture$verifier)
  commit_b <- .dsvert_joint_dp_commit(
    fixture$policies$peer_b, prepares$peer_a, prepares$peer_b,
    .secret = fixture$secrets$peer_b, .signer = fixture$signer,
    .verifier = fixture$verifier)
  authorization <- .dsvert_joint_dp_authorize(
    policy, commit_a, commit_b,
    .secret = secret, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_identical(authorization$capsule_id, proposals$peer_a$capsule_id)
  expect_identical(
    .dsvert_capsule_registry_status(config, secret)$capsule_count, 1)
})

test_that("a failed journal append rolls back the allocator charge atomically", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "registry-atomic-rollback")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a

  expect_error(testthat::with_mocked_bindings(
    .dsvert_joint_dp_commit(
      policy, prepares$peer_a, prepares$peer_b,
      .secret = secret, .signer = fixture$signer,
      .verifier = fixture$verifier),
    .dsvert_joint_dp_registry_journal_ensure = function(...) {
      stop("injected reservation journal failure", call. = FALSE)
    },
    .package = "dsVert"), "injected reservation journal failure")

  connection <- DBI::dbConnect(
    RSQLite::SQLite(), .dsvert_joint_dp_ledger_path(policy))
  record <- .dsvert_joint_dp_load(
    connection, proposals$peer_a$query_id, secret)
  allocator <- .dsvert_joint_dp_allocator_state_read(connection, secret)
  journal_count <- DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM joint_capsule_registry")$n[[1L]]
  next_index <- .dsvert_joint_dp_meta_get(connection, "next_index")
  DBI::dbDisconnect(connection)
  expect_identical(record$state, "prepared")
  expect_identical(allocator$committed_count, 0)
  expect_identical(allocator$registry_eligible_count, 0)
  expect_identical(journal_count, 0L)
  expect_identical(next_index, "0")

  replay <- .dsvert_joint_dp_commit(
    policy, prepares$peer_a, prepares$peer_b,
    .secret = secret, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_identical(replay$allocation_index, "0")
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  expect_identical(
    .dsvert_capsule_registry_status(config, secret)$capsule_count, 1)
})

test_that("an abandoned reservation keeps sequence zero dense for sequence one", {
  fixture <- .joint_test_fixture()
  for (peer in names(fixture$policies)) {
    fixture$policies[[peer]]$lifetime_max_distinct_capsules <- 2
    fixture$policies[[peer]]$noise_root$key_id <- paste0(
      "file_", digest::digest(peer, algo = "sha256", serialize = FALSE))
  }
  first <- .joint_test_proposals(fixture, "abandoned-sequence-zero")
  first_prepares <- .joint_test_prepare_pair(fixture, first)
  for (peer in names(fixture$policies)) {
    expect_error(.dsvert_joint_dp_commit(
      fixture$policies[[peer]], first_prepares$peer_a,
      first_prepares$peer_b, .secret = fixture$secrets[[peer]],
      .signer = fixture$signer, .verifier = fixture$verifier,
      .phase_hook = function(phase) {
        if (identical(phase, "after_local_commit")) {
          stop(phase, call. = FALSE)
        }
      }), "after_local_commit")
  }

  for (peer in names(fixture$policies)) {
    history <- .dsvert_dp_inactive_joint_history(
      .dsvert_joint_dp_ledger_path(fixture$policies[[peer]]),
      fixture$secrets[[peer]])
    expect_identical(history$status, "used")
    expect_equal(history$count, 1)
  }

  second <- .joint_test_proposals(fixture, "completed-sequence-one")
  second_prepares <- .joint_test_prepare_pair(fixture, second)
  expect_true(all(vapply(
    second_prepares, function(value) identical(value$allocation_index, "1"),
    logical(1L))))
  second_commits <- .joint_test_commit_pair(fixture, second_prepares)

  for (peer in names(fixture$policies)) {
    config <- .dsvert_capsule_registry_config_from_policy(
      fixture$policies[[peer]])
    snapshot <- .dsvert_capsule_registry_snapshot(
      config, fixture$secrets[[peer]])
    expect_identical(snapshot$summary$capsule_count, 2)
    expect_identical(snapshot$summary$remaining_distinct_capsules, 0)
    expect_identical(
      vapply(snapshot$records, `[[`, numeric(1L), "sequence"), c(0, 1))
    connection <- DBI::dbConnect(
      RSQLite::SQLite(),
      .dsvert_joint_dp_ledger_path(fixture$policies[[peer]]))
    journal <- DBI::dbGetQuery(connection, paste(
      "SELECT state, allocator_sequence, registry_sequence",
      "FROM joint_capsule_registry ORDER BY allocator_sequence"))
    records <- DBI::dbGetQuery(connection, paste(
      "SELECT sequence, state FROM joint_records ORDER BY sequence"))
    state <- .dsvert_joint_dp_registry_state_read(
      connection, config, fixture$secrets[[peer]])
    DBI::dbDisconnect(connection)
    expect_identical(journal$state, c("registered", "registered"))
    expect_identical(as.numeric(journal$allocator_sequence), c(0, 1))
    expect_identical(as.numeric(journal$registry_sequence), c(0, 1))
    expect_identical(records$state,
                     c("locally_committed", "committed"))
    expect_identical(state$journal_count, 2)
    expect_identical(state$registered_count, 2)
  }

  before <- lapply(names(fixture$policies), function(peer) {
    connection <- DBI::dbConnect(
      RSQLite::SQLite(),
      .dsvert_joint_dp_ledger_path(fixture$policies[[peer]]))
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    .dsvert_joint_dp_allocator_state_read(
      connection, fixture$secrets[[peer]])$committed_count
  })
  authorizations <- .joint_test_authorize_pair(fixture, second_commits)
  expect_true(all(vapply(
    authorizations, function(value) identical(value$allocation_index, "1"),
    logical(1L))))
  after <- lapply(names(fixture$policies), function(peer) {
    connection <- DBI::dbConnect(
      RSQLite::SQLite(),
      .dsvert_joint_dp_ledger_path(fixture$policies[[peer]]))
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    .dsvert_joint_dp_allocator_state_read(
      connection, fixture$secrets[[peer]])$committed_count
  })
  expect_identical(after, before)
})

test_that("allocator cumulative decimals are locale independent", {
  fixture <- .joint_test_fixture()
  withr::local_options(OutDec = ",")
  proposals <- .joint_test_proposals(fixture, "decimal-comma-locale")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  .joint_test_commit_pair(fixture, prepares)

  for (peer in names(fixture$policies)) {
    connection <- DBI::dbConnect(
      RSQLite::SQLite(),
      .dsvert_joint_dp_ledger_path(fixture$policies[[peer]]))
    epsilon <- .dsvert_joint_dp_meta_get(
      connection, "cumulative_epsilon")
    delta <- .dsvert_joint_dp_meta_get(connection, "cumulative_delta")
    expect_false(grepl(",", epsilon, fixed = TRUE))
    expect_false(grepl(",", delta, fixed = TRUE))
    expect_silent(.dsvert_joint_dp_allocator_full_audit(
      connection, fixture$policies[[peer]], fixture$secrets[[peer]],
      fixture$verifier))
    DBI::dbDisconnect(connection)
  }
})

test_that("an abandoned commit exhausts N one but exact replay remains free", {
  fixture <- .joint_test_fixture()
  for (peer in names(fixture$policies)) {
    fixture$policies[[peer]]$lifetime_max_distinct_capsules <- 1
  }
  first <- .joint_test_proposals(fixture, "single-abandoned-reservation")
  prepares <- .joint_test_prepare_pair(fixture, first)
  for (peer in names(fixture$policies)) {
    expect_error(.dsvert_joint_dp_commit(
      fixture$policies[[peer]], prepares$peer_a, prepares$peer_b,
      .secret = fixture$secrets[[peer]], .signer = fixture$signer,
      .verifier = fixture$verifier,
      .phase_hook = function(phase) {
        if (identical(phase, "after_local_commit")) {
          stop(phase, call. = FALSE)
        }
      }), "after_local_commit")
  }

  denied <- .joint_test_proposals(fixture, "single-over-boundary")
  error <- tryCatch(.dsvert_joint_dp_prepare(
    fixture$policies$peer_a, denied$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), error = identity)
  expect_s3_class(error, "dsvert_dp_lifetime_budget_exhausted")

  commits <- .joint_test_commit_pair(fixture, prepares)
  replay <- .joint_test_commit_pair(fixture, prepares)
  expect_identical(replay, commits)
  for (peer in names(fixture$policies)) {
    config <- .dsvert_capsule_registry_config_from_policy(
      fixture$policies[[peer]])
    expect_identical(
      .dsvert_capsule_registry_status(
        config, fixture$secrets[[peer]])$capsule_count,
      1)
  }
})

test_that("tampered or missing commit reservations fail closed on replay", {
  make_pending <- function(tag) {
    fixture <- .joint_test_fixture()
    proposals <- .joint_test_proposals(fixture, tag)
    prepares <- .joint_test_prepare_pair(fixture, proposals)
    expect_error(.dsvert_joint_dp_commit(
      fixture$policies$peer_a, prepares$peer_a, prepares$peer_b,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer,
      .verifier = fixture$verifier,
      .phase_hook = function(phase) {
        if (identical(phase, "after_commit_activation")) {
          stop(phase, call. = FALSE)
        }
      }), "after_commit_activation")
    list(fixture = fixture, prepares = prepares)
  }

  tampered <- make_pending("tampered-commit-reservation")
  path <- .dsvert_joint_dp_ledger_path(tampered$fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT query_id, journal_json FROM joint_capsule_registry"))
  altered <- sub(
    '"prepare_set_hash":"[0-9a-f]{64}"',
    paste0('"prepare_set_hash":"', strrep("0", 64L), '"'),
    row$journal_json[[1L]])
  DBI::dbExecute(connection, paste(
    "UPDATE joint_capsule_registry SET journal_json = ?",
    "WHERE query_id = ?"), params = list(altered, row$query_id[[1L]]))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_commit(
    tampered$fixture$policies$peer_a,
    tampered$prepares$peer_a, tampered$prepares$peer_b,
    .secret = tampered$fixture$secrets$peer_a,
    .signer = tampered$fixture$signer,
    .verifier = tampered$fixture$verifier),
    "journal failed authentication")

  missing <- make_pending("missing-commit-reservation")
  path <- .dsvert_joint_dp_ledger_path(missing$fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, "DELETE FROM joint_capsule_registry")
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_commit(
    missing$fixture$policies$peer_a,
    missing$prepares$peer_a, missing$prepares$peer_b,
    .secret = missing$fixture$secrets$peer_a,
    .signer = missing$fixture$signer,
    .verifier = missing$fixture$verifier),
    "reservation journal is out of order")
})

test_that("historical journal loss blocks new burns but not exact replay", {
  fixture <- .joint_test_fixture()
  for (peer in names(fixture$policies)) {
    fixture$policies[[peer]]$lifetime_max_distinct_capsules <- 3
  }
  retained <- NULL
  for (index in seq_len(2L)) {
    proposals <- .joint_test_proposals(
      fixture, sprintf("historical-journal-%02d", index))
    prepares <- .joint_test_prepare_pair(fixture, proposals)
    commits <- .joint_test_commit_pair(fixture, prepares)
    retained <- list(prepares = prepares, commits = commits)
  }

  path <- .dsvert_joint_dp_ledger_path(fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, paste(
    "DELETE FROM joint_capsule_registry WHERE allocator_sequence = 0"))
  DBI::dbDisconnect(connection)

  audit <- function() {
    connection <- DBI::dbConnect(RSQLite::SQLite(), path)
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    .dsvert_joint_dp_allocator_forensic_audit(
      connection, fixture$policies$peer_a, fixture$secrets$peer_a,
      fixture$verifier)
  }
  expect_error(audit(), "journal are incomplete")
  expect_identical(.dsvert_joint_dp_commit(
    fixture$policies$peer_a,
    retained$prepares$peer_a, retained$prepares$peer_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), retained$commits$peer_a)

  next_proposals <- .joint_test_proposals(fixture, "historical-journal-new")
  expect_error(.dsvert_joint_dp_prepare(
    fixture$policies$peer_a, next_proposals$peer_a,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "journal are incomplete")
})

test_that("authenticated registry suffix rollback is restored, not recharged", {
  fixture <- .joint_test_fixture()
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  empty <- .dsvert_capsule_registry_integrity_state(config, secret)
  expect_identical(empty$summary$capsule_count, 0)
  backup <- tempfile("empty-capsule-registry-")
  expect_true(file.copy(config$registry_path, backup))

  proposals <- .joint_test_proposals(fixture, "registry-rollback")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorization <- .dsvert_joint_dp_authorize(
    policy, commits$peer_a, commits$peer_b,
    .secret = secret, .signer = fixture$signer,
    .verifier = fixture$verifier)
  before <- .dsvert_capsule_registry_snapshot(config, secret)
  expect_identical(before$summary$capsule_count, 1)

  expect_true(file.copy(backup, config$registry_path, overwrite = TRUE))
  expect_identical(
    .dsvert_capsule_registry_status(config, secret)$capsule_count, 0)
  replay <- .dsvert_joint_dp_authorize(
    policy, commits$peer_a, commits$peer_b,
    .secret = secret, .signer = fixture$signer,
    .verifier = fixture$verifier)
  expect_identical(replay, authorization)
  after <- .dsvert_capsule_registry_snapshot(config, secret)
  expect_identical(after, before)
  expect_true(after$summary$operation_limit)
  expect_true(after$summary$history_can_deny_operation)
})

test_that("concurrent authorization memoizes one authenticated registry row", {
  skip_on_os("windows")
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "registry-concurrent")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a

  results <- parallel::mclapply(seq_len(8L), function(unused) {
    tryCatch(.dsvert_joint_dp_authorize(
      policy, commits$peer_a, commits$peer_b,
      .secret = secret, .signer = fixture$signer,
      .verifier = fixture$verifier), error = identity)
  }, mc.cores = 4L)
  expect_false(any(vapply(results, inherits, logical(1L), "error")))
  expect_true(all(vapply(results[-1L], identical, logical(1L), results[[1L]])))
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  snapshot <- .dsvert_capsule_registry_snapshot(config, secret)
  expect_identical(snapshot$summary$capsule_count, 1)
  expect_true(snapshot$summary$operation_limit)
  expect_true(snapshot$summary$history_can_deny_operation)
})

test_that("an unbound pre-authorization registry row fails closed", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "registry-unbound")
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  config <- .dsvert_capsule_registry_config_from_policy(policy)
  identity <- list(
    capsule_id = proposals$peer_a$capsule_id,
    contract = proposals$peer_a$common_query$capsule_identity)
  unbound <- .dsvert_capsule_registry_register(config, identity, secret)
  expect_true(unbound$created)

  prepares <- .joint_test_prepare_pair(fixture, proposals)
  expect_error(.dsvert_joint_dp_commit(
    policy, prepares$peer_a, prepares$peer_b,
    .secret = secret, .signer = fixture$signer,
    .verifier = fixture$verifier), "unbound allocator entry")
})

test_that("invalid lifetime composition never reaches the capsule registry", {
  fixture <- .joint_test_fixture()
  config <- .dsvert_capsule_registry_config_from_policy(
    fixture$policies$peer_a)
  for (peer in names(fixture$policies)) {
    fixture$policies[[peer]]$global_total_delta <- 0.5
  }
  expect_false(file.exists(config$registry_path))
  expect_error(
    .joint_test_proposals(fixture, "registry-vacuous", uses_delta = TRUE),
    "lifetime composition bound")
  expect_false(file.exists(config$registry_path))
})

test_that("a tampered historical allocator binding is detected on reuse", {
  fixture <- .joint_test_fixture()
  retained <- NULL
  for (index in seq_len(2L)) {
    proposals <- .joint_test_proposals(
      fixture, sprintf("registry-binding-tamper-%02d", index))
    prepares <- .joint_test_prepare_pair(fixture, proposals)
    commits <- .joint_test_commit_pair(fixture, prepares)
    authorization <- .dsvert_joint_dp_authorize(
      fixture$policies$peer_a, commits$peer_a, commits$peer_b,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer,
      .verifier = fixture$verifier)
    if (index == 1L) retained <- list(commits = commits,
                                      authorization = authorization)
  }
  config <- .dsvert_capsule_registry_config_from_policy(
    fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), config$registry_path)
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT capsule_id, binding_json FROM capsule_registry_allocator_bindings",
    "WHERE capsule_id = ?"),
    params = list(retained$authorization$capsule_id))
  altered <- sub(
    '"own_commit_hash":"[0-9a-f]{64}"',
    paste0('"own_commit_hash":"', strrep("0", 64L), '"'),
    row$binding_json[[1L]])
  DBI::dbExecute(connection, paste(
    "UPDATE capsule_registry_allocator_bindings SET binding_json = ?",
    "WHERE capsule_id = ?"), params = list(altered, row$capsule_id[[1L]]))
  DBI::dbDisconnect(connection)

  expect_error(.dsvert_joint_dp_authorize(
    fixture$policies$peer_a,
    retained$commits$peer_a, retained$commits$peer_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier),
    "binding failed authentication|invalid allocator binding")
})

test_that("steady-state allocator-registry reconciliation uses authenticated heads", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "registry-fast-head")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorization <- .dsvert_joint_dp_authorize(
    fixture$policies$peer_a, commits$peer_a, commits$peer_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)
  handle <- .dsvert_joint_dp_open_ledger(fixture$policies$peer_a)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  context <- .dsvert_joint_dp_policy_context(fixture$policies$peer_a)

  reconciled <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_capsule_registry_reconcile(
      handle$connection, fixture$policies$peer_a, context,
      fixture$secrets$peer_a, query_id = authorization$query_id,
      verifier = fixture$verifier),
    .dsvert_joint_dp_registry_journal_audit = function(...) {
      stop("full allocator audit entered", call. = FALSE)
    },
    .dsvert_capsule_registry_audit = function(...) {
      stop("full registry audit entered", call. = FALSE)
    },
    .package = "dsVert")
  expect_identical(reconciled$binding$state, "registered")
  expect_identical(reconciled$summary$capsule_count, 1)
  expect_true(reconciled$operation_limit)
  expect_true(reconciled$history_can_deny_operation)
})

test_that("legacy allocator-registry state migrates once then loss fails closed", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "registry-state-migration")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorization <- .dsvert_joint_dp_authorize(
    fixture$policies$peer_a, commits$peer_a, commits$peer_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)
  path <- .dsvert_joint_dp_ledger_path(fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection,
    "DELETE FROM joint_capsule_registry_state")
  DBI::dbExecute(connection, paste(
    "DELETE FROM joint_meta WHERE key =",
    "'capsule_registry_state_version'"))
  DBI::dbDisconnect(connection)

  audits <- 0L
  original_audit <- .dsvert_joint_dp_registry_journal_audit
  replay <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_authorize(
      fixture$policies$peer_a, commits$peer_a, commits$peer_b,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer,
      .verifier = fixture$verifier),
    .dsvert_joint_dp_registry_journal_audit = function(...) {
      audits <<- audits + 1L
      original_audit(...)
    },
    .package = "dsVert")
  expect_identical(replay, authorization)
  expect_identical(audits, 1L)
  expect_silent(testthat::with_mocked_bindings(
    .dsvert_joint_dp_authorize(
      fixture$policies$peer_a, commits$peer_a, commits$peer_b,
      .secret = fixture$secrets$peer_a, .signer = fixture$signer,
      .verifier = fixture$verifier),
    .dsvert_joint_dp_registry_journal_audit = function(...) {
      stop("unexpected repeated journal audit", call. = FALSE)
    },
    .package = "dsVert"))

  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  marker <- DBI::dbGetQuery(connection, paste(
    "SELECT value FROM joint_meta WHERE key =",
    "'capsule_registry_state_version'"))$value[[1L]]
  expect_identical(marker, .DSVERT_JOINT_DP_REGISTRY_STATE_VERSION)
  DBI::dbExecute(connection,
    "DELETE FROM joint_capsule_registry_state")
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_joint_dp_authorize(
    fixture$policies$peer_a, commits$peer_a, commits$peer_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier),
    "authenticated joint-DP capsule-registry state is missing")
})

test_that("authenticated allocator-registry heads detect state tampering", {
  fixture <- .joint_test_fixture()
  proposals <- .joint_test_proposals(fixture, "registry-head-tamper")
  prepares <- .joint_test_prepare_pair(fixture, proposals)
  commits <- .joint_test_commit_pair(fixture, prepares)
  authorization <- .dsvert_joint_dp_authorize(
    fixture$policies$peer_a, commits$peer_a, commits$peer_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier)

  allocator <- DBI::dbConnect(
    RSQLite::SQLite(),
    .dsvert_joint_dp_ledger_path(fixture$policies$peer_a))
  DBI::dbExecute(allocator, paste(
    "UPDATE joint_capsule_registry_state",
    "SET registered_count = registered_count + 1 WHERE singleton = 1"))
  DBI::dbDisconnect(allocator)
  expect_error(.dsvert_joint_dp_authorize(
    fixture$policies$peer_a, commits$peer_a, commits$peer_b,
    .secret = fixture$secrets$peer_a, .signer = fixture$signer,
    .verifier = fixture$verifier), "state failed its integrity check")

  second <- .joint_test_fixture()
  second_proposals <- .joint_test_proposals(second, "registry-head-tamper-2")
  second_prepares <- .joint_test_prepare_pair(second, second_proposals)
  second_commits <- .joint_test_commit_pair(second, second_prepares)
  .dsvert_joint_dp_authorize(
    second$policies$peer_a, second_commits$peer_a, second_commits$peer_b,
    .secret = second$secrets$peer_a, .signer = second$signer,
    .verifier = second$verifier)
  config <- .dsvert_capsule_registry_config_from_policy(
    second$policies$peer_a)
  registry <- DBI::dbConnect(RSQLite::SQLite(), config$registry_path)
  DBI::dbExecute(registry, paste(
    "UPDATE capsule_registry_allocator_state",
    "SET binding_count = binding_count + 1 WHERE singleton = 1"))
  DBI::dbDisconnect(registry)
  expect_error(.dsvert_joint_dp_authorize(
    second$policies$peer_a, second_commits$peer_a, second_commits$peer_b,
    .secret = second$secrets$peer_a, .signer = second$signer,
    .verifier = second$verifier), "allocator-state authentication")
  expect_identical(authorization$phase, "authorized")
})

test_that("capsule status separates the lifetime gate from request quotas", {
  fixture <- .joint_test_fixture()
  first <- .dsvert_joint_dp_capsule_status(
    fixture$policies$peer_a, fixture$secrets$peer_a,
    fixture$verifier)

  expect_identical(first$version,
                   "dsvert-joint-dp-capsule-status-v5")
  expect_true(first$enabled)
  expect_true(first$role$designated_noise_peer)
  expect_identical(first$role$allocator, "authenticated_ready")
  expect_identical(
    first$privacy_contract$operation_accounting,
    "one_per_distinct_capsule_allocator_commit")
  expect_true(first$privacy_contract$privacy_budget_gate)
  expect_true(first$privacy_contract$operation_limit)
  expect_false(first$privacy_contract$request_limit)
  expect_true(first$privacy_contract$history_can_deny_operation)
  expect_identical(
    first$privacy_contract$
      simultaneous_designated_history_rollback_protection,
    "not_claimed_without_external_linearizable_cas")
  expect_match(
    first$privacy_contract$assumptions,
    "retains_and_uses_complete_authenticated_monotonic_history",
    fixed = TRUE)
  expect_identical(
    first$privacy_contract$release_instance_accounting,
    "one_public_release_instance_per_capsule_id")
  expect_false(first$privacy_contract$accuracy_depends_on_request_history)
  expect_identical(first$privacy_contract$reuse,
                   "unlimited_sticky_postprocessing")
  expect_identical(first$privacy_contract$new_capsules,
                   "allowed_until_authenticated_lifetime_bound")
  expect_identical(
    first$privacy_contract$lifetime_max_distinct_capsules, 8)
  expect_identical(first$composition_telemetry$capsules_created, 0)
  expect_identical(
    first$composition_telemetry$remaining_distinct_capsules, 8)
  expect_identical(
    first$release_instance_telemetry$releases_published, 0)
  expect_identical(
    first$release_instance_telemetry$remaining_distinct_capsules, 8)
  expect_true(first$release_instance_telemetry$operation_limit)
  expect_false(first$release_instance_telemetry$request_limit)
  expect_match(first$release_domain$domain_id, "^rd_[0-9a-f]{64}$")
  expect_identical(first$release_domain$generation, 1)
  expect_identical(first$release_domain$snapshot_derived, FALSE)
  expect_identical(first$release_domain$key_material_exposed, FALSE)

  # Every call reopens and validates persistent state, which also exercises
  # restart semantics. Status reads neither consume privacy nor change output.
  repeated <- replicate(128L, .dsvert_joint_dp_capsule_status(
    fixture$policies$peer_a, fixture$secrets$peer_a,
    fixture$verifier), simplify = FALSE)
  expect_true(all(vapply(repeated, identical, logical(1L), first)))

  encoded <- .dsvert_dp_canonical_json(first)
  forbidden <- c(
    "decay", "slot", "queries_remaining", "request_quota",
    "snapshot_sha256", "alignment_manifest_hash", "\"query_id\":",
    "\"capsule_id\":", "seed_commitment", "record_mac")
  expect_false(any(vapply(
    forbidden, grepl, logical(1L), x = encoded, fixed = TRUE)))
})

test_that("capsule telemetry validates its authenticated lifetime boundary", {
  capsule_count <- 8
  summary <- list(
    capsule_count = capsule_count,
    lifetime_max_distinct_capsules = 8,
    remaining_distinct_capsules = 0,
    capsule_epsilon = 1,
    capsule_delta = 1e-6,
    cumulative_epsilon = capsule_count,
    cumulative_delta = capsule_count * 1e-6,
    cumulative_delta_vacuous = FALSE,
    composition_role =
      "basic_composition_authenticated_lifetime_bound",
    registration_policy = paste0(
      "allocator_admitted_distinct_capsules_up_to_lifetime_limit"),
    operation_accounting = "one_per_distinct_capsule_allocator_commit",
    operation_limit = TRUE,
    history_can_deny_operation = TRUE)

  telemetry <- .dsvert_joint_dp_capsule_status_telemetry(summary)

  expect_identical(telemetry$capsules_created, capsule_count)
  expect_identical(telemetry$remaining_distinct_capsules, 0)
  expect_false(telemetry$cumulative_delta_vacuous)
  expect_identical(
    telemetry$admission_role,
    "allocator_reservation_before_protected_access")
  invalid <- summary
  invalid$capsule_count <- 9
  invalid$remaining_distinct_capsules <- -1
  expect_error(.dsvert_joint_dp_capsule_status_telemetry(invalid),
               "composition telemetry is invalid")
})

test_that("a non-designated K3 peer attests policy without allocator state", {
  fixture <- .joint_test_fixture()
  peer_c_pin <- .joint_test_b64url(as.raw(64L + seq_len(32L)))
  pins <- c(fixture$policies$peer_a$peer_pinset, peer_c = peer_c_pin)
  pins <- pins[order(names(pins), method = "radix")]
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  policy <- fixture$policies$peer_a
  policy$peer_name <- "peer_c"
  policy$peer_pinset <- pins
  policy$peer_pinset_sha256 <- pin_hash
  policy$peer_count <- 3L
  policy$designated_noise_peers <- c("peer_a", "peer_b")
  policy$ledger_path <- file.path(fixture$root, "peer-c-local.sqlite")
  policy$noise_root$key_id <- "joint-test-key-peer-c"

  status <- testthat::with_mocked_bindings(
    .dsvert_joint_dp_capsule_status(policy),
    .dsvert_joint_dp_open_ledger = function(...) {
      stop("non-designated peer opened allocator", call. = FALSE)
    },
    .dsvert_dp_secret = function(...) {
      stop("non-designated peer requested ledger secret", call. = FALSE)
    },
    .package = "dsVert")
  expect_false(status$role$designated_noise_peer)
  expect_identical(status$role$allocator,
                   "not_applicable_policy_attestor")
  expect_null(status$composition_telemetry)
  expect_null(status$release_domain)
  expect_identical(status$policy$peer_count, 3L)
  expect_identical(status$policy$peer_name, "peer_c")
  expect_identical(status$policy$own_identity_pk, peer_c_pin)
  expect_identical(status$policy$designated_noise_peers,
                   c("peer_a", "peer_b"))
  expect_true(status$privacy_contract$history_can_deny_operation)
  expect_identical(
    status$privacy_contract$lifetime_max_distinct_capsules, 8)
})
