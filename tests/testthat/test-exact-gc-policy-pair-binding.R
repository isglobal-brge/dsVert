.exact_gc_policy_pair_identity <- function(index) {
  .callMpcTool("derive-identity", list(
    seed = jsonlite::base64_enc(as.raw(
      (seq_len(32L) + 29L * as.integer(index)) %% 256L))))
}

.exact_gc_policy_pair_fixture <- function(k, designated) {
  stopifnot(k >= 2L, length(designated) == 2L)
  peer_names <- paste0("site_", letters[seq_len(k)])
  identities <- lapply(seq_len(k), .exact_gc_policy_pair_identity)
  transports <- lapply(seq_len(k), function(index) {
    .callMpcTool("transport-keygen", list())
  })
  names(identities) <- names(transports) <- peer_names
  pinset <- stats::setNames(vapply(
    identities, `[[`, character(1L), "identity_pk"), peer_names)
  pinset <- pinset[order(names(pinset), method = "radix")]
  pinset_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(vapply(
      pinset, .dsvert_relay_normalize_identity_pk, character(1L)))),
    algo = "sha256", serialize = FALSE)
  policies <- stats::setNames(lapply(peer_names, function(peer_name) list(
    domain = "exact-gc-policy-pair-test",
    cohort_id = "exact-gc-policy-pair-cohort",
    peer_name = peer_name,
    peer_pinset = pinset,
    peer_pinset_sha256 = pinset_hash,
    peer_count = as.integer(k),
    designated_noise_peers = designated,
    global_total_epsilon = 1,
    global_total_delta = 0,
    lifetime_max_distinct_capsules = 8,
    adjacency = "add_remove_patient",
    patient_column = "patient_id",
    unit_capacity = 1000L,
    max_records_per_unit = 100L,
    overflow_policy = "reject_snapshot",
    noise_root = list(epoch = 1, key_id = "test-noise-root"),
    ledger_path = tempfile("exact-gc-policy-pair-ledger-"))), peer_names)
  signed <- stats::setNames(lapply(peer_names, function(peer_name) list(
    identity_pk = base64_to_base64url(
      identities[[peer_name]]$identity_pk),
    signature = base64_to_base64url(.sign_transport_pk(
      transports[[peer_name]]$public_key,
      identities[[peer_name]]$identity_sk)))), peer_names)
  public_transport <- stats::setNames(lapply(peer_names, function(peer_name) {
    base64_to_base64url(transports[[peer_name]]$public_key)
  }), peer_names)
  list(
    peer_names = peer_names,
    designated = sort(designated, method = "radix"),
    identities = identities,
    transports = transports,
    pinset = pinset,
    policies = policies,
    identity_info = signed,
    transport_keys = public_transport)
}

.exact_gc_policy_pair_session <- function(fixture, peer_name) {
  ss <- new.env(parent = emptyenv())
  ss$.session_id <- paste0("policy-pair-", peer_name, "-", Sys.getpid())
  .key_put("transport_sk",
           fixture$transports[[peer_name]]$secret_key, ss)
  .key_put("transport_pk",
           fixture$transports[[peer_name]]$public_key, ss)
  .key_put("identity_pk",
           fixture$identities[[peer_name]]$identity_pk, ss)
  ss$.exact_gc_transport_initialized <- TRUE
  ss
}

.exact_gc_policy_pair_encode <- function(value) {
  .exact_gc_b64url_encode(charToRaw(as.character(jsonlite::toJSON(
    value, auto_unbox = TRUE, null = "null", digits = NA))))
}

.exact_gc_policy_pair_bind <- function(fixture, peer_name, ss,
                                       identity_info = NULL,
                                       transport_keys = NULL,
                                       policy = NULL) {
  if (is.null(identity_info)) {
    identity_info <- fixture$identity_info[fixture$designated]
  }
  if (is.null(transport_keys)) {
    transport_keys <- fixture$transport_keys[fixture$designated]
  }
  if (is.null(policy)) policy <- fixture$policies[[peer_name]]
  trusted <- policy$peer_pinset[names(policy$peer_pinset) != peer_name]
  withr::with_options(list(
    dsvert.peer_name = peer_name,
    default.dsvert.peer_name = "",
    dsvert.trusted_peers = trusted),
    testthat::with_mocked_bindings(
      exactGCBindPeersDS(
        transport_keys_b64 = .exact_gc_policy_pair_encode(transport_keys),
        identity_info_b64 = .exact_gc_policy_pair_encode(identity_info),
        session_id = "12345678-1234-4234-9234-123456789abc"),
      .S = function(session_id) ss,
      .dsvert_dp_policy = function() policy,
      .package = "dsVert"))
}

test_that("exact-GC binds the server-policy pair inside K=3 and K=5 pinsets", {
  cases <- list(
    list(k = 3L, designated = c("site_a", "site_c")),
    list(k = 5L, designated = c("site_b", "site_e")))
  for (case in cases) {
    fixture <- .exact_gc_policy_pair_fixture(case$k, case$designated)
    bindings <- lapply(fixture$designated, function(peer_name) {
      ss <- .exact_gc_policy_pair_session(fixture, peer_name)
      result <- .exact_gc_policy_pair_bind(fixture, peer_name, ss)
      expect_true(result$bound)
      expect_identical(
        names(ss$peer_transport_pks),
        setdiff(fixture$designated, peer_name))
      list(result = result, session = ss)
    })
    expect_identical(
      bindings[[1L]]$session$.exact_gc_peer_binding_digest,
      bindings[[2L]]$session$.exact_gc_peer_binding_digest)
    expect_identical(
      bindings[[1L]]$session$.exact_gc_full_peer_pinset_sha256,
      fixture$policies[[fixture$designated[[1L]]]]$peer_pinset_sha256)
    expect_identical(
      bindings[[1L]]$session$.exact_gc_designated_peers,
      fixture$designated)
  }
})

test_that("exact-GC policy-pair binding rejects relay-selected membership", {
  fixture <- .exact_gc_policy_pair_fixture(
    5L, designated = c("site_b", "site_e"))

  non_designated <- .exact_gc_policy_pair_session(fixture, "site_c")
  expect_error(
    .exact_gc_policy_pair_bind(fixture, "site_c", non_designated),
    "custodian-designated noise peer")

  local <- fixture$designated[[1L]]
  expect_error(.exact_gc_policy_pair_bind(
    fixture, local, .exact_gc_policy_pair_session(fixture, local),
    identity_info = fixture$identity_info[
      c(fixture$designated, "site_c")],
    transport_keys = fixture$transport_keys[
      c(fixture$designated, "site_c")]),
    "exactly the custodian-designated pair")

  expect_error(.exact_gc_policy_pair_bind(
    fixture, local, .exact_gc_policy_pair_session(fixture, local),
    identity_info = fixture$identity_info[fixture$designated[[1L]]],
    transport_keys = fixture$transport_keys[fixture$designated[[1L]]]),
    "exactly the custodian-designated pair")

  relabelled_info <- fixture$identity_info[fixture$designated]
  relabelled_transport <- fixture$transport_keys[fixture$designated]
  names(relabelled_info)[[2L]] <- "site_c"
  names(relabelled_transport)[[2L]] <- "site_c"
  expect_error(.exact_gc_policy_pair_bind(
    fixture, local, .exact_gc_policy_pair_session(fixture, local),
    identity_info = relabelled_info,
    transport_keys = relabelled_transport),
    "exactly the custodian-designated pair")

  swapped_info <- fixture$identity_info[rev(fixture$designated)]
  swapped_transport <- fixture$transport_keys[rev(fixture$designated)]
  names(swapped_info) <- names(swapped_transport) <- fixture$designated
  expect_error(.exact_gc_policy_pair_bind(
    fixture, local, .exact_gc_policy_pair_session(fixture, local),
    identity_info = swapped_info, transport_keys = swapped_transport),
    "relabels or substitutes")

  peer <- setdiff(fixture$designated, local)
  substituted_info <- fixture$identity_info[fixture$designated]
  substituted_transport <- fixture$transport_keys[fixture$designated]
  substituted_info[[peer]] <- fixture$identity_info[["site_d"]]
  substituted_transport[[peer]] <- fixture$transport_keys[["site_d"]]
  unrecognized <- tryCatch(
    .exact_gc_policy_pair_bind(
      fixture, local, .exact_gc_policy_pair_session(fixture, local),
      identity_info = substituted_info,
      transport_keys = substituted_transport),
    dsvert_peer_not_recognized = identity)
  expect_s3_class(unrecognized, "dsvert_peer_not_recognized")
  expect_identical(unrecognized$peer_name, peer)
  expect_match(conditionMessage(unrecognized), "ds.getIdentityPks",
               fixed = TRUE)
  expect_match(conditionMessage(unrecognized), "verify the observed fingerprint out of band")
  expect_match(conditionMessage(unrecognized), "Never approve a replacement key solely from the analyst/relay",
               fixed = TRUE)

  tampered_transport <- fixture$transport_keys[fixture$designated]
  tampered_transport[[2L]] <- fixture$transport_keys[["site_d"]]
  expect_error(.exact_gc_policy_pair_bind(
    fixture, local, .exact_gc_policy_pair_session(fixture, local),
    transport_keys = tampered_transport),
    "invalid signature")
})

test_that("exact-GC binding digest is canonical and binds the full pinset", {
  fixture <- .exact_gc_policy_pair_fixture(
    3L, designated = c("site_a", "site_b"))
  local <- fixture$designated[[1L]]
  first <- .exact_gc_policy_pair_session(fixture, local)
  expect_true(.exact_gc_policy_pair_bind(fixture, local, first)$bound)
  digest_first <- first$.exact_gc_peer_binding_digest
  typed_digest_first <- first$.typed_blob_peer_binding_digest
  expect_identical(first$.typed_blob_parent_binding_digest, digest_first)

  expect_true(.exact_gc_policy_pair_bind(
    fixture, local, first,
    identity_info = rev(fixture$identity_info[fixture$designated]),
    transport_keys = rev(fixture$transport_keys[fixture$designated]))$bound)
  expect_identical(first$.exact_gc_peer_binding_digest, digest_first)

  replacement <- .exact_gc_policy_pair_identity(19L)$identity_pk
  alternate_policy <- fixture$policies[[local]]
  alternate_policy$peer_pinset[["site_c"]] <- replacement
  normalized <- vapply(
    alternate_policy$peer_pinset,
    .dsvert_relay_normalize_identity_pk, character(1L))
  normalized <- normalized[order(names(normalized), method = "radix")]
  alternate_policy$peer_pinset_sha256 <- digest::digest(
    .dsvert_dp_canonical_json(as.list(normalized)),
    algo = "sha256", serialize = FALSE)
  alternate <- .exact_gc_policy_pair_session(fixture, local)
  expect_true(.exact_gc_policy_pair_bind(
    fixture, local, alternate, policy = alternate_policy)$bound)
  expect_false(identical(
    alternate$.exact_gc_peer_binding_digest, digest_first))
  expect_identical(
    alternate$.typed_blob_parent_binding_digest,
    alternate$.exact_gc_peer_binding_digest)
  expect_false(identical(
    alternate$.typed_blob_peer_binding_digest, typed_digest_first))
})

test_that("an operation rejects policy substitution after exact-GC bind", {
  fixture <- .exact_gc_policy_pair_fixture(
    3L, designated = c("site_a", "site_b"))
  local <- "site_a"
  session_id <- "12345678-1234-4234-9234-123456789abc"
  ss <- .exact_gc_policy_pair_session(fixture, local)
  expect_true(.exact_gc_policy_pair_bind(fixture, local, ss)$bound)

  changed <- fixture$policies[[local]]
  changed$peer_pinset[["site_c"]] <-
    .exact_gc_policy_pair_identity(23L)$identity_pk
  normalized <- vapply(
    changed$peer_pinset,
    .dsvert_relay_normalize_identity_pk, character(1L))
  normalized <- normalized[order(names(normalized), method = "radix")]
  changed$peer_pinset_sha256 <- digest::digest(
    .dsvert_dp_canonical_json(as.list(normalized)),
    algo = "sha256", serialize = FALSE)
  withr::local_options(list(
    dsvert.peer_name = local,
    dsvert.trusted_peers = changed$peer_pinset[
      names(changed$peer_pinset) != local]))
  expect_error(testthat::with_mocked_bindings(
    .exact_gc_init_impl(
      ss, session_id,
      "op_77777777777777777777777777777777",
      .DSVERT_EXACT_GC_CAPABILITY,
      "exact_gc_in_77777777777777777777777777777777",
      "exact_gc_out_77777777777777777777777777777777",
      "compare-signed", 63L, 0L, 1L,
      "test.policy-substitution", threshold = "0"),
    .dsvert_dp_policy = function() changed,
    .package = "dsVert"),
    "current server policy conflicts")
  expect_null(ss$.exact_gc_ops)
})

test_that("worker readiness polling cannot change the cryptographic retry attempt", {
  skip_on_os("windows")
  # This test deliberately keeps all K=2/3/5 fixture sessions alive until its
  # final cleanup. Give that synthetic aggregate fixture enough process-wide
  # byte headroom; capacity enforcement itself has dedicated tests.
  withr::local_options(list(
    dsvert.transport.global_spool_max_bytes = 64 * 1024^3))
  delayed_worker <- function(delay) {
    path <- tempfile("exact-gc-delayed-ready-")
    writeLines(c(
      "#!/bin/sh",
      paste("sleep", delay),
      "touch \"$(dirname \"$2\")/ready\"",
      "sleep 10"), path, useBytes = TRUE)
    Sys.chmod(path, mode = "0700")
    path
  }
  cleanup <- list()
  on.exit(lapply(cleanup, function(record) {
    lapply(record$sessions, .exact_gc_abort_all)
    lapply(record$sessions, .session_dir_cleanup)
    unlink(record$binaries)
  }), add = TRUE)
  for (k in c(2L, 3L, 5L)) {
    designated <- if (k == 5L) c("site_b", "site_e") else
      c("site_a", "site_b")
    fixture <- .exact_gc_policy_pair_fixture(k, designated)
    session_id <- "12345678-1234-4234-9234-123456789abc"
    suffix <- strrep(as.character(k), 32L)
    operation_id <- paste0("op_", suffix)
    source_key <- paste0("exact_gc_in_", suffix)
    output_key <- paste0("exact_gc_out_", suffix)
    purpose <- paste0("test.readiness-attempt-k", k)
    sessions <- stats::setNames(lapply(fixture$designated, function(peer) {
      ss <- .exact_gc_policy_pair_session(fixture, peer)
      expect_true(.exact_gc_policy_pair_bind(fixture, peer, ss)$bound)
      .exact_gc_stage_share(
        ss, source_key, .exact_gc_decimal_residues_b64("1", 63L),
        63L, 1L, "test.readiness", "compare-signed", purpose, 0L,
        "ring-share")
      ss
    }), fixture$designated)
    binaries <- c(delayed_worker("0.05"), delayed_worker("0.25"))
    cleanup[[length(cleanup) + 1L]] <- list(
      sessions = sessions, binaries = binaries)
    testthat::local_mocked_bindings(
      .dsvert_dp_policy = function() fixture$policies[[
        getOption("dsvert.peer_name")]],
      .exact_gc_worker_heartbeat_record = function(state) list(
        pid = as.numeric(state$worker_pid), counter = 1),
      .package = "dsVert")

    initialize <- function() {
      contexts <- character()
      for (index in seq_along(fixture$designated)) {
        peer <- fixture$designated[[index]]
        policy <- fixture$policies[[peer]]
        result <- withr::with_options(list(
          dsvert.peer_name = peer,
          dsvert.trusted_peers = policy$peer_pinset[
            names(policy$peer_pinset) != peer]),
          .exact_gc_init_impl(
            sessions[[peer]], session_id, operation_id,
            .DSVERT_EXACT_GC_CAPABILITY, source_key, output_key,
            "compare-signed", 63L, 0L, 1L, purpose,
            threshold = "0", binary = binaries[[index]]))
        contexts <- c(contexts, result$context_hash)
      }
      contexts
    }
    expect_length(unique(initialize()), 1L)
    expect_identical(unname(vapply(sessions, function(ss) {
      .exact_gc_operation_state(ss, operation_id)$attempt
    }, integer(1L))), c(1L, 1L), info = paste("K=", k))

    lapply(sessions, function(ss) {
      .exact_gc_mark_failed(
        ss, .exact_gc_operation_state(ss, operation_id),
        "infrastructure_unavailable")
    })
    expect_length(unique(initialize()), 1L)
    expect_identical(unname(vapply(sessions, function(ss) {
      .exact_gc_operation_state(ss, operation_id)$attempt
    }, integer(1L))), c(2L, 2L), info = paste("retry K=", k))
  }
})

test_that("exact-GC rejects substitution of its nested typed binding", {
  fixture <- .exact_gc_policy_pair_fixture(
    3L, designated = c("site_a", "site_b"))
  local <- "site_a"
  session_id <- "12345678-1234-4234-9234-123456789abc"
  ss <- .exact_gc_policy_pair_session(fixture, local)
  expect_true(.exact_gc_policy_pair_bind(fixture, local, ss)$bound)
  original <- ss$.typed_blob_peer_binding_digest
  ss$.typed_blob_peer_binding_digest <- if (identical(
      original, strrep("f", 64L))) strrep("e", 64L) else strrep("f", 64L)

  expect_error(
    .exact_gc_policy_pair_bind(fixture, local, ss),
    "typed transport disagrees")

  policy <- fixture$policies[[local]]
  withr::local_options(list(
    dsvert.peer_name = local,
    dsvert.trusted_peers = policy$peer_pinset[
      names(policy$peer_pinset) != local]))
  expect_error(testthat::with_mocked_bindings(
    .exact_gc_init_impl(
      ss, session_id,
      "op_88888888888888888888888888888888",
      .DSVERT_EXACT_GC_CAPABILITY,
      "exact_gc_in_88888888888888888888888888888888",
      "exact_gc_out_88888888888888888888888888888888",
      "compare-signed", 63L, 0L, 1L,
      "test.typed-binding-substitution", threshold = "0"),
    .dsvert_dp_policy = function() policy,
    .package = "dsVert"),
    "typed transport disagrees")
  expect_null(ss$.exact_gc_ops)
})

test_that("exact-GC bind never learns its local role name from the relay", {
  fixture <- .exact_gc_policy_pair_fixture(
    3L, designated = c("site_a", "site_c"))
  local <- "site_a"
  ss <- .exact_gc_policy_pair_session(fixture, local)
  policy <- fixture$policies[[local]]
  withr::local_options(list(
    dsvert.peer_name = NULL,
    default.dsvert.peer_name = "",
    dsvert.trusted_peers = policy$peer_pinset[
      names(policy$peer_pinset) != local]))
  expect_error(testthat::with_mocked_bindings(
    exactGCBindPeersDS(
      transport_keys_b64 = .exact_gc_policy_pair_encode(
        fixture$transport_keys[fixture$designated]),
      identity_info_b64 = .exact_gc_policy_pair_encode(
        fixture$identity_info[fixture$designated]),
      session_id = "12345678-1234-4234-9234-123456789abc"),
    .S = function(session_id) ss,
    .dsvert_dp_policy = function() policy,
    .package = "dsVert"),
    "server-authoritative logical site name")
  expect_null(ss$.exact_gc_peer_binding_digest)
})
