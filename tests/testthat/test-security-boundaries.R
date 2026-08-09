test_that("legacy column mutation validates names without evaluating expressions", {
  D <- data.frame(id = 1:4, x = c(1, NA, 3, 4))

  expect_error(dsvertColNamesDS("identity(D)"), "Invalid data_name")
  expect_error(dsvertNaOmitDS("identity(D)"), "Invalid data_name")

  result <- dsvertNaOmitDS("D", vars = "x")
  expect_identical(result$n_dropped, 1L)
  expect_identical(nrow(D), 3L)
})

test_that("outcome discovery returns schema only and never observed counts", {
  D <- data.frame(y = factor(c("case", "control", "case"),
                             levels = c("control", "case", "unknown")),
                  z = c("a", "b", "a"))
  result <- dsvertOutcomeLevelsDS("D", "y")
  expect_identical(result, list(
    levels = c("control", "case", "unknown"), source = "factor_schema"))
  expect_false(any(c("counts", "n") %in% names(result)))

  expect_error(dsvertOutcomeLevelsDS("D", "z"), "not declared")
  old <- options(dsvert.categorical_levels = list(z = c("a", "b", "c")))
  on.exit(options(old), add = TRUE)
  configured <- dsvertOutcomeLevelsDS("D", "z")
  expect_identical(configured, list(
    levels = c("a", "b", "c"), source = "custodian_schema"))
  expect_false(any(c("counts", "n") %in% names(configured)))
})

test_that("session identifiers and disk-store keys reject path traversal", {
  expect_error(.S("../escape"), "Invalid session_id")
  expect_error(.S(".."), "Invalid session_id")
  expect_error(.S("session/child"), "Invalid session_id")
  expect_error(.S(c("session-a", "session-b")), "single character")

  sid <- "security-storage-keys"
  ss <- .S(sid)
  on.exit(.cleanup_session(sid), add = TRUE)
  large_value <- strrep("x", .DISK_THRESHOLD + 1L)

  expect_error(.blob_put("../escape", large_value, ss), "Invalid blob key")
  expect_error(.blob_consume("../escape", ss), "Invalid blob key")
  expect_error(.key_put("../escape", large_value, ss), "Invalid key name")
  expect_error(.key_get("../escape", ss), "Invalid key name")
  expect_error(.key_exists("../escape", ss), "Invalid key name")
  expect_error(
    mpcStoreBlobDS("../escape", "chunk", chunk_index = 1L,
                   n_chunks = 2L, session_id = sid),
    "Invalid blob key"
  )

  .blob_put("safe_blob", large_value, ss)
  session_dir <- .expected_session_dir(ss)
  blob_path <- file.path(session_dir, "blobs", "safe_blob")
  expect_true(file.exists(blob_path))
  if (.Platform$OS.type == "unix") {
    group_other_mask <- strtoi("077", base = 8L)
    expect_identical(
      bitwAnd(as.integer(file.info(session_dir)$mode), group_other_mask), 0L)
    expect_identical(
      bitwAnd(as.integer(file.info(blob_path)$mode), group_other_mask), 0L)
  }
  expect_identical(.blob_consume("safe_blob", ss), large_value)
  .key_put("safe_key", large_value, ss)
  expect_false(file.exists(file.path(session_dir, "keys", "safe_key")))
  expect_identical(.key_get("safe_key", ss), large_value)

  outside <- tempfile("dsvert-security-outside-")
  dir.create(outside)
  sentinel <- file.path(outside, "sentinel")
  file.create(sentinel)
  ss$.session_dir <- outside
  expect_error(.session_dir_cleanup(ss), "Invalid session storage path")
  expect_true(file.exists(sentinel))
  ss$.session_dir <- NULL
  unlink(outside, recursive = TRUE)
})

test_that("DSLite host metadata is hashed before entering disk paths", {
  bridge <- function() {
    ss <- .S("security-dslite-marker")
    path <- .ensure_session_dir(ss)
    result <- c(session_id = ss$.session_id, path = path)
    .session_dir_cleanup(ss)
    result
  }
  fake_dslite_host <- function() {
    frame <- sys.frame(sys.nframe())
    attr(frame, "name") <- "DSLiteEnv_../../outside"
    bridge()
  }

  result <- fake_dslite_host()
  expect_match(result[["session_id"]],
               "^security-dslite-marker__dslite_[0-9a-f]{16}$")
  expect_false(grepl("outside", result[["path"]], fixed = TRUE))
})

test_that("trusted peer pins bind logical names to exact identities", {
  to_url <- function(x) {
    gsub("\\+", "-", gsub("/", "_", sub("=+$", "", x)))
  }
  make_identity <- function(seed) {
    .callMpcTool("derive-identity", list(
      seed = jsonlite::base64_enc(charToRaw(seed))))
  }
  make_transport <- function(identity) {
    transport <- .callMpcTool("transport-keygen", list())
    list(
      transport = transport,
      signature = .sign_transport_pk(
        transport$public_key, identity$identity_sk))
  }

  own_id <- make_identity("name-pin-own")
  a_id <- make_identity("name-pin-a")
  b_id <- make_identity("name-pin-b")
  own <- make_transport(own_id)
  a <- make_transport(a_id)
  b <- make_transport(b_id)
  transport_keys <- list(
    own = to_url(own$transport$public_key),
    site_a = to_url(a$transport$public_key),
    site_b = to_url(b$transport$public_key))
  identity_info <- list(
    own = list(identity_pk = to_url(own_id$identity_pk),
               signature = to_url(own$signature)),
    site_a = list(identity_pk = to_url(a_id$identity_pk),
                  signature = to_url(a$signature)),
    site_b = list(identity_pk = to_url(b_id$identity_pk),
                  signature = to_url(b$signature)))

  old <- options(
    dsvert.peer_name = "own",
    dsvert.trusted_peers = c(
      site_a = to_url(a_id$identity_pk),
      site_b = to_url(b_id$identity_pk)))
  on.exit(options(old), add = TRUE)

  verified <- .verify_all_peer_identities(
    identity_info, transport_keys, own_id$identity_pk)
  expect_named(verified, c("site_a", "site_b"))

  relabelled_info <- identity_info
  relabelled_keys <- transport_keys
  names(relabelled_info)[names(relabelled_info) == "own"] <- "relay_self"
  names(relabelled_keys)[names(relabelled_keys) == "own"] <- "relay_self"
  expect_error(
    .verify_all_peer_identities(
      relabelled_info, relabelled_keys, own_id$identity_pk),
    "configured dsvert.peer_name 'own'", fixed = TRUE)

  typed_sid <- "security-name-pin-typed-relabel"
  typed_ss <- .S(typed_sid)
  on.exit(.cleanup_session(typed_sid), add = TRUE)
  .key_put("identity_pk", own_id$identity_pk, typed_ss)
  expect_error(
    .dsvert_typed_blob_install_peer_manifest(
      typed_ss, relabelled_info, relabelled_keys),
    "configured dsvert.peer_name 'own'", fixed = TRUE)

  swapped_info <- identity_info
  swapped_keys <- transport_keys
  swapped_info[c("site_a", "site_b")] <-
    swapped_info[c("site_b", "site_a")]
  swapped_keys[c("site_a", "site_b")] <-
    swapped_keys[c("site_b", "site_a")]
  unrecognized <- tryCatch(
    .verify_all_peer_identities(
      swapped_info, swapped_keys, own_id$identity_pk),
    dsvert_peer_not_recognized = identity)
  expect_s3_class(unrecognized, "dsvert_peer_not_recognized")
  expect_identical(unrecognized$code, "peer_not_recognized")
  expect_identical(unrecognized$peer_name, "site_a")
  expect_match(unrecognized$expected_fingerprint_sha256, "^[0-9a-f]{64}$")
  expect_match(unrecognized$observed_fingerprint_sha256, "^[0-9a-f]{64}$")
  expect_false(identical(
    unrecognized$expected_fingerprint_sha256,
    unrecognized$observed_fingerprint_sha256))
  expect_match(conditionMessage(unrecognized), "ds.getIdentityPks", fixed = TRUE)
  expect_match(conditionMessage(unrecognized), "verify the observed fingerprint out of band")
  expect_match(conditionMessage(unrecognized), "dsvert.trusted_peers", fixed = TRUE)
  expect_match(conditionMessage(unrecognized), "each other participating server")
  expect_match(conditionMessage(unrecognized), "must not pin its own identity")
  expect_false(grepl(
    "identity_sk|private key|identity.seed|noise_root",
    conditionMessage(unrecognized), ignore.case = TRUE))

  sid <- "security-name-pin-endpoint"
  ss <- .S(sid)
  on.exit(.cleanup_session(sid), add = TRUE)
  .key_put("transport_sk", own$transport$secret_key, ss)
  .key_put("transport_pk", own$transport$public_key, ss)
  .key_put("identity_pk", own_id$identity_pk, ss)
  endpoint_error <- tryCatch(
    mpcStoreTransportKeysDS(
      transport_keys = swapped_keys,
      identity_info = swapped_info,
      session_id = sid),
    dsvert_peer_not_recognized = identity)
  expect_s3_class(endpoint_error, "dsvert_peer_not_recognized")
  expect_identical(endpoint_error$peer_name, "site_a")

  # Removed public selectors cannot turn the signed, name-bound handshake into
  # a key-only route.
  options(dsvert.require_trusted_peers = FALSE,
          dsvert.allow_legacy_unbound_peers = TRUE)
  expect_error(
    mpcStoreTransportKeysDS(
      transport_keys = transport_keys,
      identity_info = NULL,
      session_id = sid),
    "require signed identity_info")

  # The failure has no rotation quota. Once an administrator independently
  # verifies the replacement identities and updates every name-bound pin, the
  # same handshake succeeds immediately.
  options(dsvert.trusted_peers = c(
    site_a = to_url(b_id$identity_pk),
    site_b = to_url(a_id$identity_pk)))
  expect_named(.verify_all_peer_identities(
    swapped_info, swapped_keys, own_id$identity_pk), c("site_a", "site_b"))
  options(dsvert.trusted_peers = c(
    site_a = to_url(a_id$identity_pk),
    site_b = to_url(b_id$identity_pk)))

  expect_error(
    .verify_all_peer_identities(
      identity_info[c("own", "site_a")],
      transport_keys[c("own", "site_a")], own_id$identity_pk),
    "Pinned peer set mismatch")

  options(dsvert.trusted_peers = paste(
    to_url(a_id$identity_pk), to_url(b_id$identity_pk), sep = ","))
  expect_error(.get_trusted_peers(), "name-bound")
})

test_that("trusted peer configuration is canonical and fail closed", {
  valid_pk <- .callMpcTool("derive-identity", list(
    seed = jsonlite::base64_enc(charToRaw("canonical-pin"))))$identity_pk
  old <- options(
    dsvert.require_trusted_peers = "not-a-boolean",
    dsvert.trusted_peers = c(site_a = valid_pk),
    dsvert.allow_legacy_unbound_peers = TRUE)
  on.exit(options(old), add = TRUE)
  withr::local_envvar(c(
    DSVERT_REQUIRE_TRUSTED_PEERS = "false",
    DSVERT_ALLOW_LEGACY_UNBOUND_PEERS = "true"))

  # Obsolete options and environment variables are not consulted. A valid
  # exact name-bound map remains mandatory even when they request a bypass.
  expect_named(.get_trusted_peers(), "site_a")

  options(dsvert.trusted_peers = c("../site" = valid_pk))
  expect_error(.get_trusted_peers(), "Invalid logical peer name")

  options(dsvert.trusted_peers = structure(
    c(valid_pk, valid_pk), names = c("site_a", "site_a")))
  expect_error(.get_trusted_peers(), "names must be unique")

  options(dsvert.trusted_peers = c(site_a = "AAAA"))
  expect_error(.get_trusted_peers(), "identity public key length")

  options(dsvert.trusted_peers = c(site_a = valid_pk, site_b = valid_pk))
  expect_error(.get_trusted_peers(), "distinct pinned identity")

  options(dsvert.trusted_peers = unname(valid_pk))
  expect_error(.get_trusted_peers(), "name-bound")

  options(dsvert.trusted_peers = NULL)
  expect_error(.get_trusted_peers(), "peer_not_recognized")
})

test_that("an empty default peer name is unset, not a relabel bypass", {
  old <- options(
    dsvert.peer_name = NULL,
    default.dsvert.peer_name = "")
  on.exit(options(old), add = TRUE)
  expect_null(.dsvert_configured_local_peer_name())
  expect_error(
    .dsvert_require_configured_local_peer_name(),
    "Server administrator.*dsvert.peer_name")

  # Public identity discovery and the ephemeral transport bootstrap are kept
  # available so an administrator can provision the server-side name/pin map.
  identity <- .callMpcTool("derive-identity", list(
    seed = jsonlite::base64_enc(as.raw(seq_len(32L)))))
  testthat::local_mocked_bindings(
    .get_identity_keypair = function() identity,
    .package = "dsVert")
  expect_identical(
    dsvertIdentityPkDS()$identity_pk,
    base64_to_base64url(identity$identity_pk))
  bootstrap <- new.env(parent = emptyenv())
  bootstrap$.session_id <- "peer-name-bootstrap-test"
  transport <- testthat::with_mocked_bindings(
    glmRing63TransportInitDS("peer-name-bootstrap-test"),
    .S = function(session_id) bootstrap,
    .package = "dsVert")
  expect_identical(transport$identity_pk,
                   base64_to_base64url(identity$identity_pk))

  peer_identity <- .callMpcTool("derive-identity", list(
    seed = jsonlite::base64_enc(as.raw(33:64))))
  peer_transport <- .callMpcTool("transport-keygen", list())
  peer_signature <- .sign_transport_pk(
    peer_transport$public_key, peer_identity$identity_sk)
  transport_keys <- list(
    relay_self = transport$transport_pk,
    peer = base64_to_base64url(peer_transport$public_key))
  identity_info <- list(
    relay_self = list(
      identity_pk = transport$identity_pk,
      signature = transport$signature),
    peer = list(
      identity_pk = base64_to_base64url(peer_identity$identity_pk),
      signature = base64_to_base64url(peer_signature)))
  options(dsvert.trusted_peers = c(peer = peer_identity$identity_pk))
  expect_error(testthat::with_mocked_bindings(
    mpcStoreTransportKeysDS(
      transport_keys = transport_keys,
      identity_info = identity_info,
      session_id = "peer-name-bootstrap-test"),
    .S = function(session_id) bootstrap,
    .package = "dsVert"),
    "server-authoritative logical site name")
  expect_error(
    .dsvert_typed_blob_install_peer_manifest(
      bootstrap, identity_info, transport_keys),
    "server-authoritative logical site name")
  expect_null(bootstrap$peer_transport_pks)

  options(dsvert.peer_name = " relay-name ")
  expect_error(.dsvert_configured_local_peer_name(),
               "Invalid logical peer name")
})

test_that("a cloned local identity cannot masquerade as a distinct peer", {
  cloned <- .callMpcTool("derive-identity", list(
    seed = jsonlite::base64_enc(charToRaw("cloned-image-identity"))))
  withr::local_options(list(dsvert.peer_name = "site_a"))
  testthat::local_mocked_bindings(
    .get_identity_keypair = function() cloned,
    .get_trusted_peers = function(...) c(site_b = cloned$identity_pk),
    .package = "dsVert")

  expect_error(
    .dsvert_dp_peer_pinset(),
    "one distinct pinned Ed25519 key")
})

test_that("ephemeral transport creation cannot bypass identity bootstrap", {
  transport_calls <- 0L
  psi_data <- data.frame(patient_id = "id-1")
  withr::local_options(.psi_padded_test_source_options(
    psi_data, id_col = "patient_id"))
  testthat::local_mocked_bindings(
    .get_identity_keypair = function(...) {
      stop("persistent identity barrier unavailable", call. = FALSE)
    },
    .callMpcTool = function(...) {
      transport_calls <<- transport_calls + 1L
      stop("transport must not run", call. = FALSE)
    },
    .S = function(...) new.env(parent = emptyenv()),
    .psi_policy = function(...) list(),
    .psi_padded_state_restore = function(...) invisible(FALSE),
    .psi_padded_state_commit = function(...) invisible(TRUE),
    .package = "dsVert")

  expect_error(glmRing63TransportInitDS(), "identity barrier unavailable")
  expect_error(.psi_padded_init_impl(
    new.env(parent = emptyenv()), psi_data,
    "D", "patient_id", "00000000-0000-4000-8000-000000000001",
    "op_00000000000000000000000000000001"),
    "identity barrier unavailable")
  expect_error(
    exactGCTransportInitDS("00000000-0000-4000-8000-000000000001"),
    "identity barrier unavailable")
  expect_identical(transport_calls, 0L)
})

test_that("the shared MPC bridge gates every transport key generation", {
  binary_calls <- 0L
  testthat::local_mocked_bindings(
    .dsvert_identity_test_mode = function() FALSE,
    .get_identity_seed = function(...) {
      stop("persistent identity barrier unavailable", call. = FALSE)
    },
    .findMpcBinary = function(...) {
      binary_calls <<- binary_calls + 1L
      stop("binary lookup must not run", call. = FALSE)
    },
    .package = "dsVert")

  expect_error(
    .callMpcTool("transport-keygen", list()),
    "persistent identity barrier unavailable")
  expect_identical(binary_calls, 0L)
})

test_that("identity derivation rejects an inconsistent Ed25519 keypair", {
  public <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(11L, 32L))))
  private <- gsub("[\r\n]", "", jsonlite::base64_enc(as.raw(rep(13L, 64L))))
  testthat::local_mocked_bindings(
    .get_identity_seed = function(...) {
      jsonlite::base64_enc(as.raw(rep(17L, 32L)))
    },
    .callMpcTool = function(...) list(
      identity_pk = public, identity_sk = private),
    .package = "dsVert")

  expect_error(.get_identity_keypair(), "keypair is inconsistent")
})

test_that("identity handshake rejects malformed self and peer maps", {
  make_identity <- function(seed) {
    .callMpcTool("derive-identity", list(
      seed = jsonlite::base64_enc(charToRaw(seed))))
  }
  make_transport <- function(identity) {
    transport <- .callMpcTool("transport-keygen", list())
    list(
      transport = transport,
      signature = .sign_transport_pk(
        transport$public_key, identity$identity_sk))
  }
  own_id <- make_identity("strict-handshake-own")
  peer_id <- make_identity("strict-handshake-peer")
  own <- make_transport(own_id)
  peer <- make_transport(peer_id)
  transport_keys <- list(
    own = own$transport$public_key,
    peer = peer$transport$public_key)
  identity_info <- list(
    own = list(identity_pk = own_id$identity_pk,
               signature = own$signature),
    peer = list(identity_pk = peer_id$identity_pk,
                signature = peer$signature))
  old <- options(
    dsvert.peer_name = "own",
    dsvert.trusted_peers = c(peer = peer_id$identity_pk))
  on.exit(options(old), add = TRUE)

  expect_named(.verify_all_peer_identities(
    identity_info, transport_keys, own_id$identity_pk), "peer")

  bad_self <- identity_info
  bad_self$own$signature <- peer$signature
  expect_error(.verify_all_peer_identities(
    bad_self, transport_keys, own_id$identity_pk), "invalid signature")

  expect_error(.verify_all_peer_identities(
    identity_info, transport_keys["peer"], own_id$identity_pk),
    "name exactly the same peers")

  duplicate_names <- identity_info
  names(duplicate_names) <- c("own", "own")
  expect_error(.verify_all_peer_identities(
    duplicate_names, transport_keys, own_id$identity_pk),
    "uniquely name-bound")

  missing_self <- identity_info["peer"]
  expect_error(.verify_all_peer_identities(
    missing_self, transport_keys["peer"], own_id$identity_pk),
    "bind this server exactly once")
})

test_that("IKNP KOS validation cannot be downgraded by an R option", {
  implementation <- paste(deparse(body(k2IknpSenderEncryptDS)),
                          collapse = "\n")
  expect_match(implementation, "if \\(!have_kos\\)")
  expect_match(implementation, "DSVERT_KOS_REQUIRED")
  expect_false(grepl("iknp_require_kos_check", implementation, fixed = TRUE))
  expect_false(grepl("unchecked OT", implementation, fixed = TRUE) &&
                 grepl("permit", implementation, fixed = TRUE))
})
