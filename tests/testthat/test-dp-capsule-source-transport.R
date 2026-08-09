.capsule_source_test_b64url <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.capsule_source_test_signature <- function(message, pin) {
  pin_raw <- .dsvert_relay_b64url_decode(pin, "test pin")
  .capsule_source_test_b64url(openssl::sha512(c(message, pin_raw)))
}

.capsule_source_test_signer <- function(message, peer_name, pin) {
  .capsule_source_test_signature(message, pin)
}

.capsule_source_test_verifier <- function(message, pin, signature) {
  identical(signature, .capsule_source_test_signature(message, pin))
}

.capsule_source_test_allocation_require <- function(...) {
  invisible(list(authorized = TRUE))
}

.capsule_source_test_allocation_observer <- function(...) {
  invisible(list(authorized = TRUE, relay_is_authority = FALSE))
}

.capsule_source_test_selector <- function(
    coordinate_count, laplace_epsilons, laplace_sensitivities,
    gaussian_epsilon, gaussian_delta, gaussian_l2_sensitivity,
    objective) {
  list(
    selector = .DSVERT_DP_NOISE_SELECTOR,
    objective = objective, coordinate_count = as.integer(coordinate_count),
    winner = "gaussian",
    laplace = list(available = TRUE, simultaneous_95_abs = 100),
    gaussian = list(available = TRUE, simultaneous_95_abs = 50))
}

.capsule_source_test_fixture <- function(
    k = 2L, noise_selector = .capsule_source_test_selector,
    gaussian_planner = function(...) {
      stop("test exact-Gaussian backend unavailable", call. = FALSE)
    }, count_only = FALSE) {
  stopifnot(k %in% 2:5)
  peers <- paste0("peer_", letters[seq_len(k)])
  pins <- vapply(seq_along(peers), function(index) {
    .capsule_source_test_b64url(as.raw(
      ((seq_len(32L) + 37L * index) %% 256L)))
  }, character(1L))
  names(pins) <- peers
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(pins)), algo = "sha256",
    serialize = FALSE)
  logical_snapshot <- list(
    logical_snapshot_id = "capsule-source-aligned-cohort",
    version = "v1", alignment_protocol_version = 1L)
  datasets <- vector("list", k)
  names(datasets) <- paste0("data_", peers)
  for (index in seq_along(peers)) {
    peer <- peers[[index]]
    variable <- paste0("x_", peer)
    datasets[[index]] <- list(
      dataset_id = paste0("cohort-", peer), dataset_version = "v1",
      schema_version = "schema-v1", alignment_group = "aligned-main",
      patient_keys = stats::setNames(list("patient_id"), peer),
      columns = stats::setNames(list(list(
        kind = "numeric", owner_peer = peer, lower = 0, upper = 10)),
        variable))
  }
  schema <- list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = pin_hash,
    datasets = datasets,
    signatures = stats::setNames(
      lapply(seq_along(peers), function(index) {
        strrep(LETTERS[[index]], 86L)
      }), peers))
  policies <- resolved <- vector("list", k)
  names(policies) <- names(resolved) <- peers
  secrets <- vector("list", k)
  names(secrets) <- peers
  manifests <- vector("list", k)
  names(manifests) <- peers
  for (index in seq_along(peers)) {
    peer <- peers[[index]]
    data_name <- paste0("data_", peer)
    variable <- paste0("x_", peer)
    ledger <- tempfile(paste0("capsule-source-", peer, "-"))
    policies[[peer]] <- list(
      domain = "capsule-source-study", cohort_id = "cohort-v1",
      peer_name = peer, peer_pinset = pins,
      peer_pinset_sha256 = pin_hash, peer_count = as.integer(k),
      designated_noise_peers = peers[1:2],
      global_total_epsilon = 1, global_total_delta = 1e-6,
      lifetime_max_distinct_capsules = 8,
      adjacency = "add_remove_patient", patient_column = "patient_id",
      unit_capacity = 2L, fixed_cohort_size = NULL,
      max_records_per_unit = 1L, overflow_policy = "reject_snapshot",
      contingency_unit_aggregation_policy =
        "consistent_cell_else_exclude_v1",
      numeric_grid_bits = 8L,
      numeric_bounds = stats::setNames(list(c(0, 10)), variable),
      categorical_levels = list(),
      datasets = stats::setNames(list(list(
        id = paste0("cohort-", peer), version = "v1",
        snapshot_sha256 = NULL, alignment_manifest_hash = NULL,
        alignment_manifest_version = 1L)), data_name),
      noise_root = list(epoch = 1, key_id = "capsule-source-test-root"),
      ledger_path = ledger, ledger_private = FALSE,
      lock_timeout_ms = 30000)
    if (isTRUE(count_only)) {
      policies[[peer]]$capsule_workload_scope <- list(
        mode = "catalog_v1", numeric_moments = character(),
        categorical_marginals = character(), categorical_pairs = list(),
        correlations = list())
    }
    data <- data.frame(patient_id = c("u1", "u2"), stringsAsFactors = FALSE)
    data[[variable]] <- c(0, 10)
    resolved[[peer]] <- stats::setNames(list(list(
      data = data,
      dataset = list(
        public = list(
          data_name = data_name, id = paste0("cohort-", peer),
          version = "v1", alignment_manifest_hash = NULL,
          alignment_manifest_version = 1L),
        fingerprint = strrep(as.character(index), 64L)))), data_name)
    secrets[[peer]] <- as.raw(rep(20L + index, 32L))
    manifests[[peer]] <- .dsvert_dp_capsule_workload_manifest(
      policies[[peer]], logical_snapshot, schema,
      describe_specs = list(), survival_specs = list(),
      .signature_verifier = function(...) TRUE,
      .noise_selector = noise_selector,
      .gaussian_planner = gaussian_planner)
  }
  ids <- vapply(manifests, function(value) {
    value$capsule_identity$capsule_id
  }, character(1L))
  stopifnot(length(unique(ids)) == 1L)
  manifest_json <- .dsvert_dp_canonical_json(manifests[[1L]])
  store_paths <- vapply(policies, function(policy) {
    paste0(policy$ledger_path, ".capsule-source-v3.sqlite")
  }, character(1L))
  owners <- vapply(
    policies, .dsvert_dp_capsule_source_resource_owner, character(1L))
  withr::defer({
    for (owner in owners) {
      .dsvert_resource_external_unregister(owner)
    }
    unlink(c(
      store_paths, paste0(store_paths, ".lock"),
      paste0(store_paths, "-wal"), paste0(store_paths, "-shm")),
      force = TRUE)
  }, envir = parent.frame())
  list(
    peers = peers, policies = policies, resolved = resolved,
    secrets = secrets, manifests = manifests,
    manifest_json = manifest_json,
    openings = stats::setNames(lapply(peers[1:2], function(peer) {
      .dsvert_dp_canonical_json(list(peer = peer, phase = "test_opening"))
    }), peers[1:2]),
    expected = if (isTRUE(count_only)) 2 else
      c(2, rep(c(2, 256, 256), k)))
}

.capsule_source_test_decode_small <- function(value) {
  stopifnot(is.raw(value), length(value) %% 16L == 0L)
  bytes <- matrix(as.numeric(value), nrow = 16L)
  if (any(bytes[8:16, , drop = FALSE] != 0)) {
    stop("test reconstruction escaped the exact-integer range")
  }
  unname(colSums(bytes[1:7, , drop = FALSE] * 256^(0:6)))
}

.capsule_source_test_prepare <- function(fixture, tickets,
                                         random_bytes =
                                           .dsvert_secure_random_bytes,
                                         encryptor = NULL) {
  lapply(fixture$peers, function(peer) {
    .dsvert_dp_capsule_source_prepare_impl(
      fixture$manifest_json, tickets[[1L]], tickets[[2L]],
      fixture$openings[[1L]], fixture$openings[[2L]],
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .resolved_snapshots = fixture$resolved[[peer]],
      .random_bytes = random_bytes, .encryptor = encryptor,
      .signer = .capsule_source_test_signer,
      .verifier = .capsule_source_test_verifier,
      .allocation_observer = .capsule_source_test_allocation_observer)
  })
}

.capsule_source_test_tickets <- function(fixture) {
  lapply(fixture$peers[1:2], function(peer) {
    .dsvert_dp_capsule_source_ticket_impl(
      fixture$manifest_json,
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .signer = .capsule_source_test_signer,
      .allocation_require = .capsule_source_test_allocation_require)
  })
}

.capsule_source_test_envelope <- function(fixture, summaries, source,
                                          recipient, chunk_index) {
  summary <- .dsvert_dp_capsule_source_decode_json(
    summaries[[match(source, fixture$peers)]], "test summary", 64L * 1024L)
  bundle_json <- .dsvert_dp_capsule_source_chunk_impl(
    summary$source_transfer_id, chunk_index,
    .policy = fixture$policies[[source]],
    .secret = fixture$secrets[[source]],
    .resolved_snapshots = fixture$resolved[[source]],
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier)
  bundle <- .dsvert_dp_capsule_source_decode_json(
    bundle_json, "test bundle", .DSVERT_DP_CAPSULE_SOURCE_MAX_BUNDLE_BYTES)
  recipients <- vapply(bundle$envelopes, `[[`, character(1L),
                       "recipient_name")
  .dsvert_dp_capsule_source_encode_json(
    bundle$envelopes[[match(recipient, recipients)]])
}

.capsule_source_test_accept <- function(fixture, recipient, envelope,
                                        decryptor = NULL) {
  .dsvert_dp_capsule_source_accept_impl(
    envelope, .policy = fixture$policies[[recipient]],
    .secret = fixture$secrets[[recipient]], .decryptor = decryptor,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier)
}

.capsule_source_test_names <- function(value) {
  if (!is.list(value)) return(character())
  c(names(value), unlist(lapply(value, .capsule_source_test_names),
                         use.names = FALSE))
}

test_that("the capsule source store rejects linked SQLite files and sidecars", {
  skip_on_os("windows")
  fixture <- .capsule_source_test_fixture(2L)
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  .dsvert_dp_capsule_source_with_store(policy, secret, function(...) TRUE)
  policy$ledger_private <- TRUE
  path <- .dsvert_dp_capsule_source_store_path(policy)
  lock_path <- paste0(path, ".lock")
  Sys.chmod(c(path, lock_path), mode = "0600")

  hardlink <- tempfile("capsule-source-hardlink-", tmpdir = dirname(path))
  on.exit(unlink(hardlink, force = TRUE), add = TRUE)
  expect_true(file.link(path, hardlink))
  expect_error(
    .dsvert_dp_capsule_source_with_store(policy, secret, function(...) TRUE),
    "hard links")
  unlink(hardlink, force = TRUE)

  target <- tempfile("capsule-source-link-target-", tmpdir = dirname(path))
  on.exit(unlink(target, force = TRUE), add = TRUE)
  expect_true(file.create(target))
  linked_policy <- policy
  linked_policy$ledger_path <- tempfile(
    "capsule-source-linked-main-", tmpdir = dirname(path))
  linked_main <- paste0(linked_policy$ledger_path, ".capsule-source-v3.sqlite")
  on.exit(unlink(linked_main, force = TRUE), add = TRUE)
  Sys.chmod(target, mode = "0644")
  expect_true(file.symlink(target, linked_main))
  expect_error(
    .dsvert_dp_capsule_source_with_store(
      linked_policy, secret, function(...) TRUE),
    "symbolic link")
  expect_identical(as.integer(file.info(target)$mode),
                   strtoi("644", base = 8L))
  unlink(linked_main, force = TRUE)

  for (sidecar in c(lock_path, paste0(path, "-wal"), paste0(path, "-shm"))) {
    unlink(sidecar, force = TRUE)
    Sys.chmod(target, mode = "0644")
    expect_true(file.symlink(target, sidecar))
    expect_error(
      .dsvert_dp_capsule_source_with_store(
        policy, secret, function(...) TRUE),
      "symbolic link")
    expect_identical(as.integer(file.info(target)$mode),
                     strtoi("644", base = 8L))
    unlink(sidecar, force = TRUE)
  }
})

test_that("Gaussian one-draw authority requires the exact signed ticket pair", {
  fixture <- .capsule_source_test_fixture(2L)
  tickets <- lapply(seq_len(2L), function(index) {
    peer <- fixture$peers[[index]]
    .dsvert_dp_capsule_source_ticket_impl(
      fixture$manifest_json, .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .keygen = function() list(
        public_key = gsub("[\r\n]", "", jsonlite::base64_enc(
          as.raw(rep(40L + index, 32L)))),
        secret_key = gsub("[\r\n]", "", jsonlite::base64_enc(
          as.raw(rep(80L + index, 32L))))),
      .signer = .capsule_source_test_signer,
      .allocation_require = .capsule_source_test_allocation_require)
  })
  policy <- fixture$policies$peer_a
  contract <- .dsvert_dp_capsule_source_contract_json(
    policy, fixture$manifest_json)$contract
  roles <- fixture$peers[1:2]
  role_ids <- vapply(roles, function(peer) {
    .dsvert_relay_peer_id(unname(policy$peer_pinset[[peer]]))
  }, character(1L))
  transcript <- strrep("f", 64L)
  circuit <- strrep("e", 64L)
  operation <- "joint-dp-vector-gaussian-one-draw-v1"
  purpose <- paste0(operation, "/", circuit)
  binding <- list(
    capsule_id = contract$capsule_id,
    manifest_sha256 = digest::digest(
      fixture$manifest_json, algo = "sha256", serialize = FALSE),
    source_fan_in_transcript_sha256 = transcript,
    pinset_sha256 = contract$peer_pinset_sha256,
    garbler_peer_name = roles[[1L]], garbler_peer_id = role_ids[[1L]],
    evaluator_peer_name = roles[[2L]], evaluator_peer_id = role_ids[[2L]])
  worker <- list(
    release_binding_canonical_json = .dsvert_dp_canonical_json(binding),
    pinset_sha256 = contract$peer_pinset_sha256,
    garbler_peer_id = role_ids[[1L]],
    evaluator_peer_id = role_ids[[2L]], circuit_digest = circuit)
  authority <- list(
    version = "dsvert-joint-dp-gaussian-one-draw-r-authority-v1",
    manifest_json = fixture$manifest_json,
    recipient_ticket_jsons = tickets,
    local_recipient_name = "peer_a",
    source_fan_in_transcript_sha256 = transcript)
  summary <- .exact_gc_gaussian_one_draw_authority(
    authority, worker, purpose, .policy = policy,
    .verifier = .capsule_source_test_verifier)
  expect_match(summary$authority_sha256, "^[0-9a-f]{64}$")
  expect_setequal(names(summary$recipient_ticket_sha256), roles)
  expect_false(any(grepl(
    "json|transport|share|seed", .capsule_source_test_names(summary),
    ignore.case = TRUE)))

  duplicate <- authority
  duplicate$recipient_ticket_jsons[[2L]] <- tickets[[1L]]
  expect_error(.exact_gc_gaussian_one_draw_authority(
    duplicate, worker, purpose, .policy = policy,
    .verifier = .capsule_source_test_verifier),
    "exact recipients")
  changed_fan_in <- authority
  changed_fan_in$source_fan_in_transcript_sha256 <- strrep("d", 64L)
  expect_error(.exact_gc_gaussian_one_draw_authority(
    changed_fan_in, worker, purpose, .policy = policy,
    .verifier = .capsule_source_test_verifier),
    "does not match")
  expect_error(.exact_gc_gaussian_one_draw_authority(
    authority, worker, paste0(operation, "/", strrep("c", 64L)),
    .policy = policy, .verifier = .capsule_source_test_verifier),
    "does not match")
})

test_that("private source header commitments are domain-separated HMACs only", {
  message <- .dsvert_dp_canonical_json(list(
    contract_hash = strrep("a", 64L), peer_name = "source_a",
    commitment_sha256 = strrep("b", 64L)))
  source_a <- as.raw(rep(17L, 32L))
  source_b <- as.raw(rep(93L, 32L))
  snapshot_a <- .dsvert_dp_capsule_source_mac(
    source_a, "private-snapshot-binding", message)
  snapshot_a_retry <- .dsvert_dp_capsule_source_mac(
    source_a, "private-snapshot-binding", message)
  snapshot_b <- .dsvert_dp_capsule_source_mac(
    source_b, "private-snapshot-binding", message)
  value_a <- .dsvert_dp_capsule_source_mac(
    source_a, "private-value-commitment", message)
  public_digest <- digest::digest(
    message, algo = "sha256", serialize = FALSE)

  expect_match(snapshot_a, "^[0-9a-f]{64}$")
  expect_identical(snapshot_a, snapshot_a_retry)
  expect_false(identical(snapshot_a, snapshot_b))
  expect_false(identical(snapshot_a, value_a))
  expect_false(identical(snapshot_a, public_digest))

  gate_source <- paste(readLines(
    .dsvert_test_package_file(
      "R", "exactGCAlignmentMaskDS.R", source_only = TRUE),
    warn = FALSE), collapse = "\n")
  expect_false(grepl(
    "private_snapshot_binding_mac|private_value_commitment_mac",
    gate_source, perl = TRUE))
  expect_true(grepl("private_alignment_consensus_shares", gate_source,
                    fixed = TRUE))
})

test_that("allocation gates precede source keys and raw materialization", {
  fixture <- .capsule_source_test_fixture(2L)
  ticket_gate_calls <- 0L
  expect_error(.dsvert_dp_capsule_source_ticket_impl(
    fixture$manifest_json, .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .keygen = function(...) stop("key generation ran before allocation"),
    .signer = .capsule_source_test_signer,
    .allocation_require = function(policy, manifest_json, secret,
                                   verifier) {
      ticket_gate_calls <<- ticket_gate_calls + 1L
      expect_identical(manifest_json, fixture$manifest_json)
      stop("ticket allocation gate sentinel")
    }), "ticket allocation gate sentinel")
  expect_identical(ticket_gate_calls, 1L)

  tickets <- .capsule_source_test_tickets(fixture)
  observer_calls <- 0L
  expect_error(.dsvert_dp_capsule_source_prepare_impl(
    fixture$manifest_json, tickets[[1L]], tickets[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .materializer = function(...) {
      stop("materializer ran before allocation observer")
    },
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier,
    .allocation_observer = function(
        policy, manifest_json, first_opening_json, second_opening_json,
        secret, verifier) {
      observer_calls <<- observer_calls + 1L
      expect_identical(first_opening_json, fixture$openings[[1L]])
      expect_identical(second_opening_json, fixture$openings[[2L]])
      stop("source allocation observer sentinel")
    }), "source allocation observer sentinel")
  expect_identical(observer_calls, 1L)
})

test_that("Ring128 source splits are exact at boundaries and retain all mask bits", {
  values <- c(0, 1, 65535, 65536, 2^32, 2^53 - 1)
  deterministic <- function(n) {
    as.raw(rep(0:255, length.out = n))
  }
  split <- .dsvert_dp_capsule_source_split_ring128(values, deterministic)
  expect_length(split$left, 16L * length(values))
  expect_length(split$right, 16L * length(values))
  recovered <- .dsvert_dp_capsule_source_add_ring128(
    split$left, split$right)
  expect_identical(.capsule_source_test_decode_small(recovered), values)

  many <- .dsvert_dp_capsule_source_split_ring128(
    numeric(4096L), .dsvert_secure_random_bytes)
  first_bytes <- as.integer(many$left[seq.int(1L, length(many$left), by = 16L)])
  expect_gt(length(unique(first_bytes)), 240L)
  expect_false(identical(many$left, many$right))
})

test_that("K=2 source transport is opaque, ordered, sticky and exactly reconstructs", {
  local_mocked_bindings(
    .DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES = 2L,
    .package = "dsVert")
  fixture <- .capsule_source_test_fixture(2L)
  tickets <- .capsule_source_test_tickets(fixture)
  ticket_replay <- .dsvert_dp_capsule_source_ticket_impl(
    fixture$manifest_json, .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .keygen = function() stop("must not regenerate"),
    .signer = .capsule_source_test_signer,
    .allocation_require = .capsule_source_test_allocation_require)
  expect_identical(ticket_replay, tickets[[1L]])

  summaries <- .capsule_source_test_prepare(fixture, tickets)
  summary_replay <- .dsvert_dp_capsule_source_prepare_impl(
    fixture$manifest_json, tickets[[1L]], tickets[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .materializer = function(...) stop("must not rematerialize"),
    .random_bytes = function(...) stop("must not resplit"),
    .encryptor = function(...) stop("must not re-encrypt"),
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier,
    .allocation_observer = function(...) {
      stop("a complete replay must not reauthorize materialization")
    })
  expect_identical(summary_replay, summaries[[1L]])

  first_summary <- .dsvert_dp_capsule_source_decode_json(
    summaries[[1L]], "test summary", 64L * 1024L)
  first_bundle <- .dsvert_dp_capsule_source_chunk_impl(
    first_summary$source_transfer_id, 0L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier)
  decoded_bundle <- .dsvert_dp_capsule_source_decode_json(
    first_bundle, "test bundle", .DSVERT_DP_CAPSULE_SOURCE_MAX_BUNDLE_BYTES)
  expect_identical(decoded_bundle$version,
                   .DSVERT_DP_CAPSULE_SOURCE_BUNDLE_VERSION)
  expect_identical(
    vapply(decoded_bundle$envelopes, `[[`, character(1L), "recipient_name"),
    fixture$peers[1:2])
  expect_identical(decoded_bundle$recipients, as.list(fixture$peers[1:2]))
  expect_lt(nchar(first_bundle, type = "bytes"),
            .DSVERT_DP_CAPSULE_SOURCE_MAX_BUNDLE_BYTES)

  # Neither a later owner nor a later chunk may create recipient state first.
  wrong_owner <- .capsule_source_test_envelope(
    fixture, summaries, "peer_b", "peer_a", 0L)
  expect_error(
    .capsule_source_test_accept(fixture, "peer_a", wrong_owner),
    "canonical owner")
  wrong_chunk <- .capsule_source_test_envelope(
    fixture, summaries, "peer_a", "peer_b", 1L)
  expect_error(
    .capsule_source_test_accept(fixture, "peer_b", wrong_chunk),
    "canonical owner and chunk order")

  public_objects <- c(tickets, summaries, first_bundle)
  first_ack <- NULL
  first_envelope <- NULL
  for (recipient in fixture$peers[1:2]) {
    for (source in fixture$peers) {
      contract <- .dsvert_dp_capsule_source_contract_json(
        fixture$policies[[source]], fixture$manifest_json)$contract
      for (chunk in seq.int(0, contract$chunk_count - 1L)) {
        envelope <- .capsule_source_test_envelope(
          fixture, summaries, source, recipient, chunk)
        ack <- .capsule_source_test_accept(fixture, recipient, envelope)
        public_objects <- c(public_objects, envelope, ack)
        if (is.null(first_ack)) {
          first_ack <- ack
          first_envelope <- envelope
        }
      }
    }
  }
  lost_ack_retry <- .capsule_source_test_accept(
    fixture, "peer_a", first_envelope,
    decryptor = function(...) stop("a committed retry must not decrypt"))
  expect_identical(lost_ack_retry, first_ack)

  shares <- lapply(fixture$peers[1:2], function(recipient) {
    contract <- .dsvert_dp_capsule_source_contract_json(
      fixture$policies[[recipient]], fixture$manifest_json)$contract
    do.call(c, lapply(seq.int(0, contract$chunk_count - 1L), function(chunk) {
      .dsvert_dp_capsule_source_aggregate_chunk_internal(
        fixture$policies[[recipient]], fixture$manifest_json, chunk,
        fixture$secrets[[recipient]])
    }))
  })
  reconstructed <- .dsvert_dp_capsule_source_add_ring128(
    shares[[1L]], shares[[2L]])
  expect_identical(
    .capsule_source_test_decode_small(reconstructed), fixture$expected)

  forbidden <- c(
    "values", "value", "share", "shares", "mask", "seed",
    "protected_fingerprint", "snapshot_binding_sha256",
    "value_commitment_sha256", "private_snapshot_binding_mac",
    "private_value_commitment_mac", "aggregate_b64")
  decoded_public <- lapply(public_objects, function(value) {
    if (!is.character(value) || length(value) != 1L) return(value)
    tryCatch(jsonlite::fromJSON(value, simplifyVector = FALSE),
             error = function(e) value)
  })
  public_names <- unlist(lapply(decoded_public, .capsule_source_test_names),
                         use.names = FALSE)
  expect_false(any(tolower(public_names) %in% forbidden))

  private_material <- .dsvert_dp_capsule_materialize_local(
    fixture$policies$peer_a, fixture$manifests$peer_a,
    fixture$resolved$peer_a)
  transcript <- paste(unlist(public_objects, use.names = FALSE),
                      collapse = "\n")
  private_tokens <- c(
    '"u1"', '"u2"',
    private_material$snapshot_binding_sha256,
    private_material$value_commitment_sha256,
    private_material$authenticatable_sha256,
    fixture$resolved$peer_a[[1L]]$dataset$fingerprint)
  expect_false(any(vapply(private_tokens, function(token) {
    is.character(token) && length(token) == 1L && nzchar(token) &&
      grepl(token, transcript, fixed = TRUE)
  }, logical(1L))))

  contract <- .dsvert_dp_capsule_source_contract_json(
    fixture$policies$peer_a, fixture$manifest_json)$contract
  key_db <- .dsvert_dp_capsule_source_store_path(
    fixture$policies$peer_a)
  key_connection <- DBI::dbConnect(RSQLite::SQLite(), key_db)
  on.exit(if (DBI::dbIsValid(key_connection)) {
    DBI::dbDisconnect(key_connection)
  }, add = TRUE)
  key_record <- .dsvert_dp_capsule_source_key_load(
    key_connection, contract$capsule_id, fixture$secrets$peer_a)
  expect_false(grepl(key_record$transport_sk, transcript, fixed = TRUE))
  DBI::dbDisconnect(key_connection)

  visible_hash_fields <- unique(public_names[grepl(
    "(^|_)hash$|sha256$|_id$", public_names, ignore.case = TRUE)])
  expect_setequal(visible_hash_fields, c(
    "capsule_id", "contract_hash", "transport_key_id",
    "peer_pinset_sha256", "source_transfer_id", "recipient_ticket_hash",
    "ciphertext_sha256"))
  expect_true(all(vapply(decoded_public, function(value) {
    if (!is.list(value) || is.null(value$ready_for_sampling)) return(TRUE)
    identical(value$ready_for_sampling, FALSE)
  }, logical(1L))))

  tampered <- .dsvert_dp_capsule_source_decode_json(
    first_envelope, "test envelope", 1024L^2)
  replacement <- if (substr(tampered$ciphertext, 1L, 1L) == "A") "B" else "A"
  substr(tampered$ciphertext, 1L, 1L) <- replacement
  expect_error(.capsule_source_test_accept(
    fixture, "peer_a", .dsvert_dp_canonical_json(tampered)),
    "invalid|hash")

  signed <- .dsvert_dp_capsule_source_decode_json(
    first_envelope, "test envelope", 1024L^2)
  unsigned <- signed[setdiff(names(signed), "signature")]
  message <- .dsvert_dp_capsule_source_signature_message(
    "encrypted-chunk", unsigned)
  expect_lt(length(message), 4096L)
  expect_false(grepl(unsigned$ciphertext, rawToChar(message), fixed = TRUE))
  envelope_for_b <- .capsule_source_test_envelope(
    fixture, summaries, "peer_a", "peer_b", 0L)
  expect_error(
    .capsule_source_test_accept(fixture, "peer_a", envelope_for_b),
    "invalid")
})

test_that("K=3 through K=5 include every owner without extra noise shares", {
  for (k in 3:5) {
    fixture <- .capsule_source_test_fixture(k)
    tickets <- .capsule_source_test_tickets(fixture)
    non_designated <- fixture$peers[-(1:2)]
    for (peer in non_designated) {
      expect_error(.dsvert_dp_capsule_source_ticket_impl(
        fixture$manifest_json, .policy = fixture$policies[[peer]],
        .secret = fixture$secrets[[peer]],
        .signer = .capsule_source_test_signer,
        .allocation_require = .capsule_source_test_allocation_require),
        "designated")
    }
    summaries <- .capsule_source_test_prepare(fixture, tickets)
    contract <- .dsvert_dp_capsule_source_contract_json(
      fixture$policies$peer_a, fixture$manifest_json)$contract
    for (peer in non_designated) {
      public <- .dsvert_dp_capsule_source_decode_json(
        summaries[[match(peer, fixture$peers)]], "test summary", 64L * 1024L)
      expect_identical(public$source_name, peer)
      expect_false(public$ready_for_sampling)
    }

    for (recipient in fixture$peers[1:2]) {
      for (source in fixture$peers) {
        envelope <- .capsule_source_test_envelope(
          fixture, summaries, source, recipient, 0L)
        .capsule_source_test_accept(fixture, recipient, envelope)
      }
      durable <- .dsvert_dp_capsule_source_with_store(
        fixture$policies[[recipient]], fixture$secrets[[recipient]],
        function(connection) {
          key_row <- DBI::dbGetQuery(connection, paste(
            "SELECT record_json, row_mac FROM source_recipient_keys",
            "WHERE capsule_id = ?"), params = list(contract$capsule_id))
          key_record <- .dsvert_dp_capsule_source_record_decode(
            key_row, fixture$secrets[[recipient]], "source_recipient_keys",
            "test recipient key")
          list(
            state = .dsvert_dp_capsule_source_store_state(
              connection, fixture$secrets[[recipient]]),
            recipient_reservation =
              .dsvert_dp_capsule_source_recipient_reservation_validate(
                key_record),
            receipts = DBI::dbGetQuery(
              connection,
              "SELECT COUNT(*) AS n FROM source_incoming_receipts")$n[[1L]])
        })
      expect_identical(
        as.numeric(durable$receipts),
        as.numeric(k * contract$chunk_count))
      expect_identical(
        as.numeric(durable$state$reserved_bytes),
        .dsvert_dp_capsule_source_outbound_reservation(contract) +
          .dsvert_dp_capsule_source_inbound_reservation(contract) +
          durable$recipient_reservation)
    }
    shares <- lapply(fixture$peers[1:2], function(recipient) {
      .dsvert_dp_capsule_source_aggregate_chunk_internal(
        fixture$policies[[recipient]], fixture$manifest_json, 0L,
        fixture$secrets[[recipient]])
    })
    expect_identical(
      .capsule_source_test_decode_small(
        .dsvert_dp_capsule_source_add_ring128(shares[[1L]], shares[[2L]])),
      fixture$expected)
    for (peer in non_designated) {
      expect_error(.dsvert_dp_capsule_source_aggregate_chunk_internal(
        fixture$policies[[peer]], fixture$manifest_json, 0L,
        fixture$secrets[[peer]]), "designated")
    }
  }
})

test_that("paired ciphertext commits survive interruption without resplitting them", {
  local_mocked_bindings(
    .DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES = 2L,
    .package = "dsVert")
  fixture <- .capsule_source_test_fixture(2L)
  tickets <- .capsule_source_test_tickets(fixture)
  calls <- 0L
  interrupting_encryptor <- function(plaintext, recipient_pk) {
    calls <<- calls + 1L
    if (calls == 2L) stop("simulated process interruption")
    .callMpcTool("transport-encrypt", list(
      data = gsub("[\r\n]", "", jsonlite::base64_enc(plaintext)),
      recipient_pk = .base64url_to_base64(recipient_pk)))$sealed
  }
  summary <- .dsvert_dp_capsule_source_prepare_impl(
    fixture$manifest_json, tickets[[1L]], tickets[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier,
    .allocation_observer = .capsule_source_test_allocation_observer)
  expect_identical(calls, 0L)
  transfer <- .dsvert_dp_capsule_source_transfer_id(
    .dsvert_dp_capsule_source_contract_json(
      fixture$policies$peer_a, fixture$manifest_json)$contract, "peer_a")
  expect_error(.dsvert_dp_capsule_source_chunk_impl(
    transfer, 0L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .encryptor = interrupting_encryptor,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier), "interruption")
  db <- .dsvert_dp_capsule_source_store_path(
    fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), db)
  on.exit(if (DBI::dbIsValid(connection)) DBI::dbDisconnect(connection),
          add = TRUE)
  before <- DBI::dbGetQuery(connection, paste(
    "SELECT recipient_name, record_json FROM source_outbound_chunks",
    "WHERE transfer_id = ? AND chunk_index = 0 ORDER BY recipient_name"),
    params = list(transfer))
  expect_equal(nrow(before), 0L)
  DBI::dbDisconnect(connection)

  committed <- .dsvert_dp_capsule_source_chunk_impl(
    transfer, 0L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier)
  replay <- .dsvert_dp_capsule_source_chunk_impl(
    transfer, 0L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .random_bytes = function(...) stop("must not resplit"),
    .encryptor = function(...) stop("must not re-encrypt"),
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier)
  expect_identical(replay, committed)
  expect_match(summary, "source_chunk_stream_ready", fixed = TRUE)
  connection <- DBI::dbConnect(RSQLite::SQLite(), db)
  after <- DBI::dbGetQuery(connection, paste(
    "SELECT recipient_name, record_json FROM source_outbound_chunks",
    "WHERE transfer_id = ? AND chunk_index = 0 ORDER BY recipient_name"),
    params = list(transfer))
  DBI::dbDisconnect(connection)
  expect_equal(nrow(after), 2L)
})

test_that("lazy chunks bind one snapshot and complete only after every index", {
  local_mocked_bindings(
    .DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES = 2L,
    .package = "dsVert")
  fixture <- .capsule_source_test_fixture(2L)
  tickets <- .capsule_source_test_tickets(fixture)
  summary_json <- .dsvert_dp_capsule_source_prepare_impl(
    fixture$manifest_json, tickets[[1L]], tickets[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier,
    .allocation_observer = .capsule_source_test_allocation_observer)
  summary <- .dsvert_dp_capsule_source_decode_json(
    summary_json, "test streaming summary", 64L * 1024L)
  expect_identical(summary$phase, "source_chunk_stream_ready")
  expect_true(summary$emitted_chunk_durable_replay)
  expect_true(summary$unmaterialized_requires_same_snapshot)
  expect_false(summary$complete_durable_replay)

  changed <- fixture$resolved$peer_a
  changed[[1L]]$dataset$fingerprint <- strrep("f", 64L)
  expect_error(.dsvert_dp_capsule_source_chunk_impl(
    summary$source_transfer_id, 1L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = changed,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier),
    class = "dsvert_capsule_source_snapshot_changed")
  expect_error(.dsvert_dp_capsule_source_chunk_impl(
    summary$source_transfer_id, 1L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .materializer = function(...) {
      stop("The resolved biomedical capsule snapshot digest changed.",
           call. = FALSE)
    },
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier),
    class = "dsvert_capsule_source_snapshot_changed")

  contract <- .dsvert_dp_capsule_source_contract_json(
    fixture$policies$peer_a, fixture$manifest_json)$contract
  order <- c(contract$chunk_count - 1L,
             setdiff(seq.int(0L, contract$chunk_count - 1L),
                     contract$chunk_count - 1L))
  for (chunk_index in order) {
    .dsvert_dp_capsule_source_chunk_impl(
      summary$source_transfer_id, chunk_index,
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .resolved_snapshots = fixture$resolved$peer_a,
      .signer = .capsule_source_test_signer,
      .verifier = .capsule_source_test_verifier)
  }
  connection <- DBI::dbConnect(
    RSQLite::SQLite(),
    .dsvert_dp_capsule_source_store_path(fixture$policies$peer_a))
  on.exit(if (DBI::dbIsValid(connection)) DBI::dbDisconnect(connection),
          add = TRUE)
  outbound <- DBI::dbGetQuery(connection, paste(
    "SELECT status FROM source_outbound WHERE transfer_id = ?"),
    params = list(summary$source_transfer_id))
  chunks <- DBI::dbGetQuery(connection, paste(
    "SELECT COUNT(*) AS n FROM source_outbound_chunks",
    "WHERE transfer_id = ?"),
    params = list(summary$source_transfer_id))
  expect_identical(outbound$status[[1L]], "complete")
  expect_equal(chunks$n[[1L]], 2 * contract$chunk_count)
})

test_that("the public source boundary redacts typed snapshot failures", {
  expect_error(
    .dsvert_dp_capsule_source_public(
      "ciphertext bundle fetch",
      .dsvert_dp_capsule_source_snapshot_changed()),
    regexp = "^\\[dsvert_dp_public_failure:v1\\] Protected capsule operation failed\\.$",
    class = "dsvert_dp_public_failure")
})

test_that("authenticated source-stream state rejects local tampering", {
  fixture <- .capsule_source_test_fixture(2L)
  tickets <- .capsule_source_test_tickets(fixture)
  summary_json <- .capsule_source_test_prepare(fixture, tickets)[[1L]]
  summary <- .dsvert_dp_capsule_source_decode_json(
    summary_json, "test streaming summary", 64L * 1024L)
  path <- .dsvert_dp_capsule_source_store_path(fixture$policies$peer_a)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  DBI::dbExecute(connection, paste(
    "UPDATE source_outbound SET record_json = record_json || ' '",
    "WHERE transfer_id = ?"), params = list(summary$source_transfer_id))
  DBI::dbDisconnect(connection)
  expect_error(.dsvert_dp_capsule_source_chunk_impl(
    summary$source_transfer_id, 0L,
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier),
    "failed private-store authentication")
})

test_that("concurrent lazy chunk retries commit one byte-identical pair", {
  skip_on_os("windows")
  fixture <- .capsule_source_test_fixture(2L)
  tickets <- .capsule_source_test_tickets(fixture)
  summary_json <- .capsule_source_test_prepare(fixture, tickets)[[1L]]
  summary <- .dsvert_dp_capsule_source_decode_json(
    summary_json, "test streaming summary", 64L * 1024L)
  bundles <- parallel::mclapply(seq_len(4L), function(index) {
    .dsvert_dp_capsule_source_chunk_impl(
      summary$source_transfer_id, 0L,
      .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a,
      .resolved_snapshots = fixture$resolved$peer_a,
      .signer = .capsule_source_test_signer,
      .verifier = .capsule_source_test_verifier)
  }, mc.cores = 2L)
  expect_true(all(vapply(
    bundles, identical, logical(1L), bundles[[1L]])))
})

test_that("inbound reservation covers every durable source chunk receipt", {
  coordinate_count <- 64 * 1024^2
  chunk_count <- coordinate_count /
    .DSVERT_DP_CAPSULE_SOURCE_CHUNK_COORDINATES
  source_counts <- c(2, 3, 5, 4096)
  observed <- vapply(source_counts, function(source_count) {
    .dsvert_dp_capsule_source_inbound_reservation(list(
      coordinate_count = coordinate_count,
      chunk_count = chunk_count,
      source_peers = as.list(sprintf(
        "peer_%04d", seq_len(source_count)))))
  }, numeric(1L))
  per_source <- 16 * 1024 * chunk_count
  expected <- 24 * coordinate_count +
    source_counts * per_source + 32 * 1024
  old_source_independent_bound <-
    24 * coordinate_count + per_source + 32 * 1024

  expect_identical(observed, as.numeric(expected))
  expect_identical(
    observed - old_source_independent_bound,
    as.numeric((source_counts - 1) * per_source))
  expect_true(all(diff(observed) > 0))
})

test_that("recipient tickets reserve their durable key bytes for K=2,3,5", {
  observed <- numeric()
  for (k in c(2L, 3L, 5L)) {
    fixture <- .capsule_source_test_fixture(k)
    tickets <- .capsule_source_test_tickets(fixture)
    peer <- "peer_a"
    policy <- fixture$policies[[peer]]
    secret <- fixture$secrets[[peer]]
    owner <- .dsvert_dp_capsule_source_resource_owner(policy)
    durable <- .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) {
        row <- DBI::dbGetQuery(connection, paste(
          "SELECT record_json, row_mac FROM source_recipient_keys",
          "WHERE capsule_id = ?"), params = list(
            fixture$manifests[[peer]]$capsule_identity$capsule_id))
        list(
          record = .dsvert_dp_capsule_source_record_decode(
            row, secret, "source_recipient_keys", "test recipient key"),
          record_bytes = nchar(row$record_json[[1L]], type = "bytes"),
          state = .dsvert_dp_capsule_source_store_state(connection, secret))
      })
    observed <- c(observed, durable$record$reserved_bytes)
    expect_gt(as.numeric(durable$record$reserved_bytes),
              as.numeric(durable$record_bytes))
    expect_identical(
      as.numeric(durable$state$reserved_bytes),
      as.numeric(durable$record$reserved_bytes))
    expect_identical(
      .dsvert_resource_registry$external[[owner]]$bytes,
      as.numeric(durable$record$reserved_bytes))

    replay <- .dsvert_dp_capsule_source_ticket_impl(
      fixture$manifest_json, .policy = policy, .secret = secret,
      .keygen = function() stop("must not regenerate"),
      .signer = .capsule_source_test_signer,
      .allocation_require = .capsule_source_test_allocation_require)
    expect_identical(replay, tickets[[1L]])
    after_replay <- .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) {
        .dsvert_dp_capsule_source_store_state(connection, secret)
      })
    expect_identical(after_replay, durable$state)

    .dsvert_resource_external_unregister(owner)
    restarted <- .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) {
        .dsvert_dp_capsule_source_store_state(connection, secret)
      })
    expect_identical(restarted, durable$state)
    expect_identical(
      .dsvert_resource_registry$external[[owner]]$bytes,
      as.numeric(durable$record$reserved_bytes))
  }
  expect_true(all(diff(observed) > 0))
})

test_that("recipient-ticket byte admission is exact, retryable and atomic", {
  keygen <- function() list(
    public_key = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(71L, 32L)))),
    secret_key = gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(93L, 32L)))))
  mint <- function(fixture) {
    .dsvert_dp_capsule_source_ticket_impl(
      fixture$manifest_json, .policy = fixture$policies$peer_a,
      .secret = fixture$secrets$peer_a, .keygen = keygen,
      .signer = .capsule_source_test_signer,
      .allocation_require = .capsule_source_test_allocation_require)
  }
  inspect <- function(fixture) {
    .dsvert_dp_capsule_source_with_store(
      fixture$policies$peer_a, fixture$secrets$peer_a,
      function(connection) list(
        state = .dsvert_dp_capsule_source_store_state(
          connection, fixture$secrets$peer_a),
        keys = DBI::dbGetQuery(connection, paste(
          "SELECT COUNT(*) AS n FROM source_recipient_keys"))$n[[1L]]))
  }
  old <- options(dsvert.transport.global_spool_max_bytes = 256 * 1024^3)
  on.exit(options(old), add = TRUE)

  probe <- .capsule_source_test_fixture(3L)
  mint(probe)
  expected <- as.numeric(inspect(probe)$state$reserved_bytes)
  expect_gt(expected, 0)

  below <- .capsule_source_test_fixture(3L)
  terminal <- tryCatch(testthat::with_mocked_bindings(
    mint(below),
    .dsvert_dp_capsule_source_spool_max_bytes = function() expected - 1,
    .package = "dsVert"), error = identity)
  expect_s3_class(terminal, "dsvert_resource_oversize")
  expect_identical(as.numeric(inspect(below)$state$reserved_bytes), 0)
  expect_identical(as.numeric(inspect(below)$keys), 0)

  exact <- .capsule_source_test_fixture(3L)
  exact_ticket <- testthat::with_mocked_bindings(
    mint(exact),
    .dsvert_dp_capsule_source_spool_max_bytes = function() expected,
    .package = "dsVert")
  expect_identical(as.numeric(inspect(exact)$state$reserved_bytes), expected)
  expect_identical(as.numeric(inspect(exact)$keys), 1)

  pressured <- .capsule_source_test_fixture(3L)
  prior <- 2048
  owner <- .dsvert_dp_capsule_source_resource_owner(
    pressured$policies$peer_a)
  .dsvert_dp_capsule_source_with_store(
    pressured$policies$peer_a, pressured$secrets$peer_a,
    function(connection) {
      .dsvert_dp_capsule_source_transaction(connection,
        .dsvert_dp_capsule_source_reserve(
          connection, pressured$secrets$peer_a, prior, owner))
    })
  pressure <- tryCatch(testthat::with_mocked_bindings(
    mint(pressured),
    .dsvert_dp_capsule_source_spool_max_bytes =
      function() prior + expected - 1,
    .package = "dsVert"), error = identity)
  expect_s3_class(pressure, "dsvert_resource_backpressure")
  expect_true(pressure$retryable)
  expect_identical(as.numeric(inspect(pressured)$state$reserved_bytes), prior)
  expect_identical(as.numeric(inspect(pressured)$keys), 0)

  retried <- testthat::with_mocked_bindings(
    mint(pressured),
    .dsvert_dp_capsule_source_spool_max_bytes =
      function() prior + expected,
    .package = "dsVert")
  expect_identical(retried, exact_ticket)
  expect_identical(
    as.numeric(inspect(pressured)$state$reserved_bytes), prior + expected)
  expect_identical(as.numeric(inspect(pressured)$keys), 1)
})

test_that("legacy recipient-key rows migrate once and reconcile on restart", {
  fixture <- .capsule_source_test_fixture(5L)
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  owner <- .dsvert_dp_capsule_source_resource_owner(policy)
  ticket <- .capsule_source_test_tickets(fixture)[[1L]]
  expected <- .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT record_json, row_mac FROM source_recipient_keys",
        "WHERE capsule_id = ?"), params = list(
          fixture$manifests$peer_a$capsule_identity$capsule_id))
      record <- .dsvert_dp_capsule_source_record_decode(
        row, secret, "source_recipient_keys", "test migration key")
      as.numeric(record$reserved_bytes)
    })

  .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT record_json, row_mac FROM source_recipient_keys",
        "WHERE capsule_id = ?"), params = list(
          fixture$manifests$peer_a$capsule_identity$capsule_id))
      legacy <- .dsvert_dp_capsule_source_record_decode(
        row, secret, "source_recipient_keys", "test migration key")
      legacy$reserved_bytes <- NULL
      .dsvert_dp_capsule_source_transaction(connection, {
        .dsvert_dp_capsule_source_record_update(
          connection, "source_recipient_keys", legacy, secret,
          "capsule_id = ?", list(legacy$capsule_id))
        state <- .dsvert_dp_capsule_source_store_state(connection, secret)
        state$reserved_bytes <- as.numeric(state$reserved_bytes) - expected
        .dsvert_dp_capsule_source_record_update(
          connection, "source_store_state", state, secret,
          "singleton = 1", list())
      })
    })
  .dsvert_resource_external_unregister(owner)

  migrated <- .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT record_json, row_mac FROM source_recipient_keys",
        "WHERE capsule_id = ?"), params = list(
          fixture$manifests$peer_a$capsule_identity$capsule_id))
      list(
        record = .dsvert_dp_capsule_source_record_decode(
          row, secret, "source_recipient_keys", "test migrated key"),
        state = .dsvert_dp_capsule_source_store_state(connection, secret))
    })
  expect_identical(as.numeric(migrated$record$reserved_bytes), expected)
  expect_identical(as.numeric(migrated$state$reserved_bytes), expected)
  expect_identical(.dsvert_resource_registry$external[[owner]]$bytes, expected)

  replay <- .dsvert_dp_capsule_source_ticket_impl(
    fixture$manifest_json, .policy = policy, .secret = secret,
    .keygen = function() stop("must not regenerate migrated key"),
    .signer = .capsule_source_test_signer,
    .allocation_require = .capsule_source_test_allocation_require)
  expect_identical(replay, ticket)
  .dsvert_resource_external_unregister(owner)
  restarted <- .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      .dsvert_dp_capsule_source_store_state(connection, secret)
    })
  expect_identical(restarted, migrated$state)
  expect_identical(.dsvert_resource_registry$external[[owner]]$bytes, expected)
})

test_that("authenticated capacity state cannot under-count recipient keys", {
  fixture <- .capsule_source_test_fixture(2L)
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  owner <- .dsvert_dp_capsule_source_resource_owner(policy)
  .capsule_source_test_tickets(fixture)
  .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      state <- .dsvert_dp_capsule_source_store_state(connection, secret)
      state$reserved_bytes <- as.numeric(state$reserved_bytes) - 1
      .dsvert_dp_capsule_source_transaction(connection,
        .dsvert_dp_capsule_source_record_update(
          connection, "source_store_state", state, secret,
          "singleton = 1", list()))
    })
  .dsvert_resource_external_unregister(owner)
  expect_error(
    .dsvert_dp_capsule_source_with_store(
      policy, secret, function(...) stop("must not enter callback")),
    "under-counts recipient-key bytes")
  expect_false(owner %in% names(.dsvert_resource_registry$external))
})

test_that("one source reservation that can never fit is terminal", {
  fixture <- .capsule_source_test_fixture(2L)
  tickets <- .capsule_source_test_tickets(fixture)
  local_mocked_bindings(
    .dsvert_dp_capsule_source_spool_max_bytes = function() 1,
    .package = "dsVert")
  condition <- tryCatch(.dsvert_dp_capsule_source_prepare_impl(
    fixture$manifest_json, tickets[[1L]], tickets[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier,
    .allocation_observer = .capsule_source_test_allocation_observer),
    error = identity)
  expect_s3_class(condition, "dsvert_resource_oversize")
  expect_identical(condition$code, "resource_oversize")
  expect_false(condition$retryable)
  expect_false(inherits(condition, "dsvert_resource_backpressure"))
  expect_match(conditionMessage(condition), "dsvert_resource_oversize", fixed = TRUE)
  expect_false(any(grepl(
    "epsilon|delta|remaining|request|history",
    capture.output(print(.dsvert_dp_capsule_source_outbound_reservation(
      .dsvert_dp_capsule_source_contract_json(
        fixture$policies$peer_a, fixture$manifest_json)$contract))),
    ignore.case = TRUE)))
})

test_that("S-aware inbound bytes enforce exact boundary and restart", {
  fixture <- .capsule_source_test_fixture(5L)
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  contract <- .dsvert_dp_capsule_source_contract_json(
    policy, fixture$manifest_json)$contract
  inbound <- .dsvert_dp_capsule_source_inbound_reservation(contract)
  prior <- 2048
  owner <- .dsvert_dp_capsule_source_resource_owner(policy)
  old <- options(dsvert.transport.global_spool_max_bytes = 256 * 1024^3)
  on.exit(options(old), add = TRUE)
  on.exit(.dsvert_resource_external_unregister(owner), add = TRUE)

  .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      .dsvert_dp_capsule_source_transaction(connection,
        .dsvert_dp_capsule_source_reserve(
          connection, secret, prior, owner))
    })
  pressure <- tryCatch(testthat::with_mocked_bindings(
    .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) {
        .dsvert_dp_capsule_source_transaction(connection,
          .dsvert_dp_capsule_source_reserve(
            connection, secret, inbound, owner))
      }),
    .dsvert_dp_capsule_source_spool_max_bytes =
      function() prior + inbound - 1,
    .package = "dsVert"), error = identity)
  expect_s3_class(pressure, "dsvert_resource_backpressure")
  expect_identical(as.numeric(pressure$retained_bytes), as.numeric(prior))
  expect_identical(as.numeric(pressure$requested_bytes), inbound)
  expect_identical(
    as.numeric(pressure$capacity_bytes), prior + inbound - 1)

  .dsvert_resource_external_unregister(owner)
  restarted <- .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      .dsvert_dp_capsule_source_store_state(connection, secret)
    })
  expect_identical(as.numeric(restarted$reserved_bytes), as.numeric(prior))
  expect_identical(
    .dsvert_resource_registry$external[[owner]]$bytes, as.numeric(prior))

  admitted <- testthat::with_mocked_bindings(
    .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) {
        .dsvert_dp_capsule_source_transaction(connection,
          .dsvert_dp_capsule_source_reserve(
            connection, secret, inbound, owner))
      }),
    .dsvert_dp_capsule_source_spool_max_bytes =
      function() prior + inbound,
    .package = "dsVert")
  expect_identical(
    as.numeric(admitted$reserved_bytes), prior + inbound)
  expect_identical(
    .dsvert_resource_registry$external[[owner]]$bytes, prior + inbound)
})

test_that("durable source bytes reconcile after rollback and process restart", {
  fixture <- .capsule_source_test_fixture(2L)
  policy <- fixture$policies$peer_a
  secret <- fixture$secrets$peer_a
  owner <- .dsvert_dp_capsule_source_resource_owner(policy)
  old <- options(dsvert.transport.global_spool_max_bytes = 256 * 1024^3)
  on.exit(options(old), add = TRUE)
  on.exit(.dsvert_resource_external_unregister(owner), add = TRUE)

  committed <- .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      .dsvert_dp_capsule_source_transaction(connection,
        .dsvert_dp_capsule_source_reserve(
          connection, secret, 128 * 1024, owner))
    })
  .dsvert_dp_capsule_source_resource_reconcile(policy, committed)
  expect_identical(
    .dsvert_resource_registry$external[[owner]]$bytes, 128 * 1024)

  # The transaction updates its authenticated capacity row before later work.
  # A crash/error rolls that row back. The in-process head may conservatively
  # over-reserve until reopen, but must never under-count committed bytes.
  expect_error(.dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      .dsvert_dp_capsule_source_transaction(connection, {
        .dsvert_dp_capsule_source_reserve(
          connection, secret, 64 * 1024, owner)
        stop("simulated transaction crash", call. = FALSE)
      })
    }), "simulated transaction crash")
  expect_identical(
    .dsvert_resource_registry$external[[owner]]$bytes, 192 * 1024)

  # Simulate a fresh R worker: discard only its in-memory provider head. Store
  # opening re-verifies the MAC-protected SQLite row and restores exact bytes.
  .dsvert_resource_external_unregister(owner)
  reopened <- .dsvert_dp_capsule_source_with_store(
    policy, secret, function(connection) {
      .dsvert_dp_capsule_source_store_state(connection, secret)
    })
  expect_identical(as.numeric(reopened$reserved_bytes), 128 * 1024)
  expect_identical(
    .dsvert_resource_registry$external[[owner]]$bytes, 128 * 1024)
  for (index in seq_len(20L)) {
    .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) {
        .dsvert_dp_capsule_source_store_state(connection, secret)
      })
  }
  expect_identical(
    .dsvert_resource_registry$external[[owner]]$bytes, 128 * 1024)

  # Aggregate occupancy is transient backpressure, while the same immutable
  # reservation succeeds once the public byte capacity is available.
  pressure <- tryCatch(testthat::with_mocked_bindings(
    .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) {
        .dsvert_dp_capsule_source_transaction(connection,
          .dsvert_dp_capsule_source_reserve(
            connection, secret, 2048, owner))
      }),
    .dsvert_dp_capsule_source_spool_max_bytes =
      function() 128 * 1024 + 1024,
    .package = "dsVert"), error = identity)
  expect_s3_class(pressure, "dsvert_resource_backpressure")
  expect_identical(pressure$code, "resource_backpressure")
  expect_true(pressure$retryable)

  retried <- testthat::with_mocked_bindings(
    .dsvert_dp_capsule_source_with_store(
      policy, secret, function(connection) {
        .dsvert_dp_capsule_source_transaction(connection,
          .dsvert_dp_capsule_source_reserve(
            connection, secret, 2048, owner))
      }),
    .dsvert_dp_capsule_source_spool_max_bytes =
      function() 128 * 1024 + 4096,
    .package = "dsVert")
  .dsvert_dp_capsule_source_resource_reconcile(policy, retried)
  expect_identical(as.numeric(retried$reserved_bytes), 128 * 1024 + 2048)
})

test_that("global byte manager remains bounded across many durable stores", {
  baseline <- .dsvert_resource_retained_bytes()
  owners <- vapply(seq_len(128L), function(index) {
    .dsvert_resource_external_owner(
      "capsule-source",
      file.path(tempdir(), sprintf("resource-stress-%03d.sqlite", index)))
  }, character(1L))
  on.exit(for (owner in owners) {
    .dsvert_resource_external_unregister(owner)
  }, add = TRUE)
  bytes_each <- 4096
  for (owner in owners) {
    .dsvert_resource_external_reconcile(
      owner, bytes_each, "capsule-source")
  }
  expect_identical(
    .dsvert_resource_retained_bytes(),
    baseline + length(owners) * bytes_each)
  expect_length(intersect(
    owners, names(.dsvert_resource_registry$external)), length(owners))

  capacity <- max(
    1024^2, baseline + length(owners) * bytes_each + 1024)
  old <- options(dsvert.transport.global_spool_max_bytes = capacity)
  on.exit(options(old), add = TRUE)
  headroom <- capacity - .dsvert_resource_retained_bytes()
  extra <- .dsvert_resource_external_owner(
    "capsule-source", file.path(tempdir(), "resource-stress-extra.sqlite"))
  on.exit(.dsvert_resource_external_unregister(extra), add = TRUE)
  pressure <- tryCatch({
    .dsvert_resource_admit_external(
      extra, 0, headroom + 1, "capsule-source")
    NULL
  }, error = identity)
  expect_s3_class(pressure, "dsvert_resource_backpressure")
  expect_identical(pressure$scope, "process-wide durable transport")
  expect_true(pressure$retryable)

  terminal <- tryCatch({
    .dsvert_resource_admit_external(
      extra, 0, capacity + 1, "capsule-source")
    NULL
  }, error = identity)
  expect_s3_class(terminal, "dsvert_resource_oversize")
  expect_identical(terminal$code, "resource_oversize")
  expect_false(terminal$retryable)
})

test_that("128 SQLite source stores reconcile and vacuum only bounded pages", {
  fixture <- .capsule_source_test_fixture(2L)
  policies <- lapply(seq_len(128L), function(index) {
    policy <- fixture$policies$peer_a
    policy$ledger_path <- tempfile(sprintf("capsule-store-%03d-", index))
    policy
  })
  owners <- vapply(policies, .dsvert_dp_capsule_source_resource_owner,
                   character(1L))
  on.exit(for (owner in owners) {
    .dsvert_resource_external_unregister(owner)
  }, add = TRUE)
  modes <- vapply(policies, function(policy) {
    .dsvert_dp_capsule_source_with_store(
      policy, fixture$secrets$peer_a, function(connection) {
        state <- .dsvert_dp_capsule_source_store_state(
          connection, fixture$secrets$peer_a)
        expect_identical(as.numeric(state$reserved_bytes), 0)
        as.numeric(DBI::dbGetQuery(
          connection, "PRAGMA auto_vacuum")[[1L]][[1L]])
      })
  }, numeric(1L))
  expect_true(all(modes == 2))
  expect_length(intersect(
    owners, names(.dsvert_resource_registry$external)), 128L)

  vacuum <- .dsvert_dp_capsule_source_with_store(
    policies[[1L]], fixture$secrets$peer_a, function(connection) {
      DBI::dbExecute(connection,
        "CREATE TABLE vacuum_probe(value BLOB NOT NULL)")
      payload <- strrep("V", 4096L)
      for (index in seq_len(64L)) {
        DBI::dbExecute(connection,
          "INSERT INTO vacuum_probe(value) VALUES(?)", params = list(payload))
      }
      DBI::dbExecute(connection, "DELETE FROM vacuum_probe")
      .dsvert_dp_capsule_source_compact_pages(
        connection, maximum_pages = 8L)
    })
  expect_true(vacuum$incremental)
  expect_lte(vacuum$requested_pages, 8L)
})

test_that("concurrent recipient-ticket retries commit one byte-identical key", {
  skip_on_os("windows")
  fixture <- .capsule_source_test_fixture(2L)
  peer <- "peer_a"
  tickets <- parallel::mclapply(seq_len(4L), function(index) {
    .dsvert_dp_capsule_source_ticket_impl(
      fixture$manifest_json, .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .signer = .capsule_source_test_signer,
      .allocation_require = .capsule_source_test_allocation_require)
  }, mc.cores = 2L)
  failures <- vapply(tickets, inherits, logical(1L), "try-error")
  if (any(failures)) {
    stop("Concurrent recipient-ticket retry failed: ",
         paste(vapply(tickets[failures], as.character, character(1L)),
               collapse = " | "), call. = FALSE)
  }
  expect_true(all(vapply(tickets, identical, logical(1L), tickets[[1L]])))
})

test_that("signed window negotiation wraps byte-identical legacy artifacts", {
  fixture <- .capsule_source_test_fixture(3L)
  tickets <- .capsule_source_test_tickets(fixture)
  negotiated <- lapply(seq_along(tickets), function(index) {
    peer <- fixture$peers[[index]]
    .dsvert_dp_capsule_source_ticket_negotiation_wrap(
      tickets[[index]], fixture$policies[[peer]],
      .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT,
      .capsule_source_test_signer)
  })
  for (index in seq_along(tickets)) {
    wrapper <- .dsvert_dp_capsule_source_decode_json(
      negotiated[[index]], "test negotiation", 64L * 1024L)
    expect_identical(wrapper$ticket_json, tickets[[index]])
  }

  summaries <- lapply(fixture$peers, function(peer) {
    response <- .dsvert_dp_capsule_source_prepare_negotiated_impl(
      fixture$manifest_json, negotiated[[1L]], negotiated[[2L]],
      fixture$openings[[1L]], fixture$openings[[2L]],
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .resolved_snapshots = fixture$resolved[[peer]],
      .signer = .capsule_source_test_signer,
      .verifier = .capsule_source_test_verifier,
      .allocation_observer = .capsule_source_test_allocation_observer)
    wrapper <- .dsvert_dp_capsule_source_decode_json(
      response, "test source negotiation", 64L * 1024L)
    legacy <- .dsvert_dp_capsule_source_prepare_impl(
      fixture$manifest_json, tickets[[1L]], tickets[[2L]],
      fixture$openings[[1L]], fixture$openings[[2L]],
      .policy = fixture$policies[[peer]],
      .secret = fixture$secrets[[peer]],
      .resolved_snapshots = fixture$resolved[[peer]],
      .signer = .capsule_source_test_signer,
      .verifier = .capsule_source_test_verifier,
      .allocation_observer = .capsule_source_test_allocation_observer)
    expect_identical(wrapper$summary_json, legacy)
    wrapper
  })
  expect_true(all(vapply(summaries, function(value) {
    identical(
      .dsvert_dp_capsule_source_encode_json(value$capability),
      .dsvert_dp_capsule_source_encode_json(
        .dsvert_dp_capsule_source_window_capability()))
  }, logical(1L))))

  legacy_negotiated <- lapply(seq_along(tickets), function(index) {
    peer <- fixture$peers[[index]]
    .dsvert_dp_capsule_source_ticket_negotiation_wrap(
      tickets[[index]], fixture$policies[[peer]],
      .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
      .capsule_source_test_signer)
  })
  legacy_capability <-
    .dsvert_dp_capsule_source_legacy_window_capability()
  for (index in seq_along(legacy_negotiated)) {
    wrapper <- .dsvert_dp_capsule_source_decode_json(
      legacy_negotiated[[index]], "legacy test negotiation", 64L * 1024L)
    expect_identical(wrapper$ticket_json, tickets[[index]])
    expect_identical(
      .dsvert_dp_capsule_source_encode_json(wrapper$capability),
      .dsvert_dp_capsule_source_encode_json(legacy_capability))
  }
  legacy_summary <- .dsvert_dp_capsule_source_prepare_negotiated_impl(
    fixture$manifest_json, legacy_negotiated[[1L]], legacy_negotiated[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a,
    .resolved_snapshots = fixture$resolved$peer_a,
    .signer = .capsule_source_test_signer,
    .verifier = .capsule_source_test_verifier,
    .allocation_observer = .capsule_source_test_allocation_observer)
  legacy_summary_wrapper <- .dsvert_dp_capsule_source_decode_json(
    legacy_summary, "legacy test source negotiation", 64L * 1024L)
  expect_identical(
    .dsvert_dp_capsule_source_encode_json(
      legacy_summary_wrapper$capability),
    .dsvert_dp_capsule_source_encode_json(legacy_capability))
  expect_identical(
    legacy_summary_wrapper$summary_json, summaries[[1L]]$summary_json)

  for (peer in fixture$peers) {
    attestation_json <- .dsvert_dp_capsule_source_capability_attestation(
      fixture$manifest_json, fixture$policies[[peer]],
      .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT,
      .capsule_source_test_signer)
    attestation <- .dsvert_dp_capsule_source_decode_json(
      attestation_json, "test source capability", 64L * 1024L)
    expect_identical(
      attestation$version,
      .DSVERT_DP_CAPSULE_SOURCE_CAPABILITY_ATTESTATION_VERSION)
    expect_identical(attestation$source_name, peer)
    expect_true(.dsvert_dp_capsule_source_verify(
      attestation, fixture$policies[[peer]],
      "source-window-capability-advertisement", peer,
      .capsule_source_test_verifier))
  }

  contract <- .dsvert_dp_capsule_source_contract_validate(
    .dsvert_dp_capsule_source_contract_json(
      fixture$policies$peer_a, fixture$manifest_json)$contract)
  tampered <- .dsvert_dp_capsule_source_decode_json(
    negotiated[[1L]], "test negotiation", 64L * 1024L)
  tampered$capability$maximum_window_chunks <- 7
  expect_error(.dsvert_dp_capsule_source_ticket_negotiation_validate(
    .dsvert_dp_capsule_source_encode_json(tampered),
    fixture$policies$peer_a, contract,
    .capsule_source_test_verifier), "Invalid capsule source ticket negotiation")
  expect_error(.dsvert_dp_capsule_source_prepare_negotiated_impl(
    fixture$manifest_json, negotiated[[1L]], tickets[[2L]],
    fixture$openings[[1L]], fixture$openings[[2L]],
    .policy = fixture$policies$peer_a,
    .secret = fixture$secrets$peer_a), "must cover both recipients")
})

test_that("ticket transport contracts are bounded before service bootstrap", {
  touched <- FALSE
  local_mocked_bindings(
    .dsvert_dp_policy = function() {
      touched <<- TRUE
      stop("policy must remain untouched", call. = FALSE)
    },
    .package = "dsVert")

  expect_error(dsvertDPCapsuleSourceTicketDS(
    .dsvert_dsi_text_encode("{}"),
    transport_contract = strrep("A", 129L)))
  expect_false(touched)
  expect_error(dsvertDPCapsuleSourceTicketDS(
    .dsvert_dsi_text_encode("{}"),
    transport_contract = "unsupported-source-transport-v1"))
  expect_false(touched)
  expect_error(dsvertDPCapsuleSourceTicketDS(
    .dsvert_dsi_text_encode("{}"), transport_contract = c(
      .DSVERT_DP_CAPSULE_SOURCE_SCALAR_TRANSPORT,
      .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION)))
  expect_false(touched)
})

test_that("byte-bounded source windows return exact canonical prefixes", {
  transfer_id <- paste0("csrc_", strrep("1", 64L))
  calls <- numeric()
  chunk <- function(source_transfer_id, chunk_index) {
    calls <<- c(calls, chunk_index)
    .dsvert_dp_capsule_source_encode_json(list(
      version = .DSVERT_DP_CAPSULE_SOURCE_BUNDLE_VERSION,
      phase = "encrypted_source_chunk_bundle_committed",
      source_transfer_id = source_transfer_id,
      chunk_index = as.numeric(chunk_index),
      padding = strrep("A", 300000L)))
  }
  response <- .dsvert_dp_capsule_source_chunk_window_impl(
    transfer_id, 0:7, .chunk_impl = chunk,
    .maximum_bytes = .DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_BYTES)
  window <- .dsvert_dp_capsule_source_decode_json(
    response, "test ciphertext window",
    .DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_BYTES)
  expect_identical(window$version,
                   .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION)
  expect_length(window$bundles, 8L)
  expect_identical(calls, as.numeric(0:7))
  for (index in seq_along(window$bundles)) {
    expect_identical(
      .dsvert_dp_capsule_source_encode_json(window$bundles[[index]]),
      chunk(transfer_id, index - 1L))
  }
  legacy_response <- .dsvert_dp_capsule_source_chunk_window_impl(
    transfer_id, 0:7, .chunk_impl = chunk,
    .maximum_bytes = .DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_WINDOW_BYTES)
  legacy_window <- .dsvert_dp_capsule_source_decode_json(
    legacy_response, "legacy test ciphertext window",
    .DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_WINDOW_BYTES)
  expect_length(legacy_window$bundles, 2L)
  expect_lte(
    nchar(legacy_response, type = "bytes"),
    .DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_WINDOW_BYTES)
  expect_error(.dsvert_dp_capsule_source_chunk_window_impl(
    transfer_id, c(0, 0), .chunk_impl = chunk), "Invalid.*window")
  expect_error(.dsvert_dp_capsule_source_chunk_window_impl(
    transfer_id, 0:8, .chunk_impl = chunk), "Invalid.*window")
})

test_that("new servers enforce old-client and adaptive source caps", {
  transfer_id <- paste0("csrc_", strrep("6", 64L))
  touched <- 0L
  local_mocked_bindings(
    .dsvert_dp_capsule_source_chunk_impl = function(
        source_transfer_id, chunk_index, ...) {
      touched <<- touched + 1L
      .dsvert_dp_capsule_source_encode_json(list(
        version = .DSVERT_DP_CAPSULE_SOURCE_BUNDLE_VERSION,
        phase = "encrypted_source_chunk_bundle_committed",
        source_transfer_id = source_transfer_id,
        chunk_index = as.numeric(chunk_index),
        padding = strrep("A", 300000L)))
    },
    .package = "dsVert")

  legacy <- dsvertDPCapsuleSourceChunkDS(transfer_id, 0:7)
  legacy_value <- .dsvert_dp_capsule_source_decode_json(
    legacy, "public legacy ciphertext window",
    .DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_WINDOW_BYTES)
  expect_length(legacy_value$bundles, 2L)
  expect_lte(
    nchar(legacy, type = "bytes"),
    .DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_WINDOW_BYTES)

  adaptive <- dsvertDPCapsuleSourceChunkDS(
    transfer_id, 0:7,
    transport_contract = .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT)
  adaptive_value <- .dsvert_dp_capsule_source_decode_json(
    adaptive, "public adaptive ciphertext window",
    .DSVERT_DP_CAPSULE_SOURCE_MAX_WINDOW_BYTES)
  expect_length(adaptive_value$bundles, 8L)

  before_invalid <- touched
  expect_error(dsvertDPCapsuleSourceChunkDS(
    transfer_id, 0:7, transport_contract = "forged-window-v9"),
    "Unsupported.*window contract")
  expect_identical(touched, before_invalid)
})

test_that("recipient windows are ordered idempotent and byte bounded", {
  make_envelope <- function(index) list(
    version = .DSVERT_DP_CAPSULE_SOURCE_CHUNK_VERSION,
    capsule_id = strrep("1", 64L), contract_hash = strrep("2", 64L),
    source_transfer_id = paste0("csrc_", strrep("3", 64L)),
    source_name = "peer_a", source_identity_pk = strrep("A", 43L),
    recipient_name = "peer_b", recipient_identity_pk = strrep("B", 43L),
    recipient_ticket_hash = strrep("4", 64L),
    chunk_index = as.numeric(index), chunk_count = 4,
    chunk_coordinates = 8192, ring_bits = 128,
    record_encoding = "little_endian_unsigned_fixed_16_bytes",
    ciphertext_sha256 = strrep(as.character(index %% 10L), 64L))
  envelopes <- lapply(0:3, make_envelope)
  request <- function(values) .dsvert_dp_capsule_source_encode_json(list(
    version = .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
    phase = "recipient_encrypted_chunk_window",
    envelopes = values, ready_for_sampling = FALSE))
  accepted <- list()
  accept <- function(value_json) {
    value <- .dsvert_dp_capsule_source_decode_json(
      value_json, "test envelope", 64L * 1024L)
    key <- as.character(value$chunk_index)
    hash <- .dsvert_joint_dp_hash(value)
    if (!is.null(accepted[[key]]) && !identical(accepted[[key]], hash)) {
      stop("conflicting retry", call. = FALSE)
    }
    accepted[[key]] <<- hash
    .dsvert_dp_capsule_source_encode_json(list(
      version = .DSVERT_DP_CAPSULE_SOURCE_ACK_VERSION,
      source_transfer_id = value$source_transfer_id,
      chunk_index = value$chunk_index,
      ciphertext_sha256 = value$ciphertext_sha256))
  }
  first <- .dsvert_dp_capsule_source_accept_window_impl(
    request(envelopes), .accept_impl = accept)
  second <- .dsvert_dp_capsule_source_accept_window_impl(
    request(envelopes), .accept_impl = accept)
  expect_identical(second, first)
  expect_length(accepted, 4L)
  expect_error(.dsvert_dp_capsule_source_accept_window_impl(
    request(rev(envelopes)), .accept_impl = accept), "Invalid.*window")
  expect_error(.dsvert_dp_capsule_source_accept_window_impl(
    request(c(envelopes[1L], envelopes[1L])), .accept_impl = accept),
    "Invalid.*window")
  oversized <- strrep(
    "A", .DSVERT_DP_CAPSULE_SOURCE_MAX_ACCEPT_WINDOW_BYTES + 1L)
  expect_error(.dsvert_dp_capsule_source_accept_window_impl(
    oversized, .accept_impl = accept), "resource_oversize|resource policy")
})

test_that("new recipients enforce old-client and adaptive accept caps", {
  make_envelope <- function(index) list(
    version = .DSVERT_DP_CAPSULE_SOURCE_CHUNK_VERSION,
    capsule_id = strrep("1", 64L), contract_hash = strrep("2", 64L),
    source_transfer_id = paste0("csrc_", strrep("3", 64L)),
    source_name = "peer_a", source_identity_pk = strrep("A", 43L),
    recipient_name = "peer_b", recipient_identity_pk = strrep("B", 43L),
    recipient_ticket_hash = strrep("4", 64L),
    chunk_index = as.numeric(index), chunk_count = 4,
    chunk_coordinates = 8192, ring_bits = 128,
    record_encoding = "little_endian_unsigned_fixed_16_bytes",
    ciphertext_sha256 = strrep(as.character(index %% 10L), 64L),
    padding = strrep("P", 300000L))
  payload <- .dsvert_dp_capsule_source_encode_json(list(
    version = .DSVERT_DP_CAPSULE_SOURCE_WINDOW_VERSION,
    phase = "recipient_encrypted_chunk_window",
    envelopes = lapply(0:3, make_envelope),
    ready_for_sampling = FALSE))
  expect_gt(
    nchar(payload, type = "bytes"),
    .DSVERT_DP_CAPSULE_SOURCE_LEGACY_MAX_ACCEPT_WINDOW_BYTES)
  expect_lt(
    nchar(payload, type = "bytes"),
    .DSVERT_DP_CAPSULE_SOURCE_MAX_ACCEPT_WINDOW_BYTES)

  touched <- 0L
  local_mocked_bindings(
    .dsvert_dp_capsule_source_accept_impl = function(envelope_json) {
      touched <<- touched + 1L
      value <- .dsvert_dp_capsule_source_decode_json(
        envelope_json, "mock adaptive envelope", 512L * 1024L)
      .dsvert_dp_capsule_source_encode_json(list(
        version = .DSVERT_DP_CAPSULE_SOURCE_ACK_VERSION,
        source_transfer_id = value$source_transfer_id,
        chunk_index = value$chunk_index,
        ciphertext_sha256 = value$ciphertext_sha256))
    },
    .package = "dsVert")

  expect_error(
    dsvertDPCapsuleSourceAcceptDS(.dsvert_dsi_text_encode(payload)),
    "resource_oversize|resource policy")
  expect_identical(touched, 0L)
  adaptive <- dsvertDPCapsuleSourceAcceptDS(
    .dsvert_dsi_text_encode(payload),
    transport_contract = .DSVERT_DP_CAPSULE_SOURCE_ADAPTIVE_TRANSPORT)
  expect_identical(touched, 4L)
  expect_lt(nchar(adaptive, type = "bytes"), 64L * 1024L)

  before_invalid <- touched
  expect_error(dsvertDPCapsuleSourceAcceptDS(
    .dsvert_dsi_text_encode(payload),
    transport_contract = "forged-window-v9"),
    "Unsupported.*window contract")
  expect_identical(touched, before_invalid)
})
