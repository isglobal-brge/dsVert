.identity_test_isolation <- function() {
  withr::local_options(list(
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.state_dir = NULL,
    default.dsvert.state_dir = NULL,
    dsvert.dp.ledger_path = NULL,
    default.dsvert.dp.ledger_path = "",
    dsvert.dp.noise_key_path = NULL,
    default.dsvert.dp.noise_key_path = NULL),
  .local_envir = parent.frame())
}

.identity_test_noise_root <- function(
    key = as.raw(rep(197L, 32L)), key_id = "hsm-noise-root-v1") {
  force(key)
  list(
    protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
    provider_id = "test-hsm", key_id = key_id,
    external = TRUE, storage = "hsm_kms_provider", epoch = 1,
    # The recovery implementation receives only this non-extractable HMAC
    # interface, matching the production HSM/KMS contract.
    hmac = function(message) digest::hmac(
      key = key, object = message, algo = "sha256", serialize = FALSE))
}

test_that("identity seeds are generated from exactly 256 CSPRNG bits", {
  .identity_test_isolation()
  seed_dir <- tempfile("dsvert-identity-")
  seed_path <- file.path(seed_dir, "identity.seed")
  requested <- integer(0)
  deterministic_rng <- function(n) {
    requested <<- c(requested, n)
    as.raw(seq_len(n) - 1L)
  }

  expect_invisible(.dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = deterministic_rng,
    .allow_test_path = TRUE
  ))
  expect_identical(requested, 32L)
  expect_true(file.exists(seed_path))
  expect_identical(
    jsonlite::base64_dec(readLines(seed_path, n = 1L, warn = FALSE)),
    as.raw(0:31)
  )
  receipt_path <- .dsvert_identity_receipt_path(seed_path)
  expect_true(file.exists(receipt_path))
  expect_true(.dsvert_validate_identity_receipt(
    receipt_path, .dsvert_validate_identity_seed_file(seed_path)))

  if (.Platform$OS.type == "unix") {
    expect_identical(as.integer(file.info(seed_dir)$mode), 448L) # 0700
    expect_identical(as.integer(file.info(seed_path)$mode), 384L) # 0600
    expect_identical(as.integer(file.info(receipt_path)$mode), 384L) # 0600
  }
})

test_that("first cryptographic use creates distinct persistent node identities", {
  .identity_test_isolation()
  skip_on_os("windows")
  first_state <- withr::local_tempdir(pattern = "dsvert-node-a-")
  second_state <- withr::local_tempdir(pattern = "dsvert-node-b-")
  draws <- 0L
  testthat::local_mocked_bindings(
    .dsvert_secure_random_bytes = function(n) {
      draws <<- draws + 1L
      as.raw(rep(draws, n))
    },
    .dsvert_dp_noise_root_for_identity_recovery = function(...) NULL,
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")

  options(dsvert.state_dir = first_state)
  first_seed <- .get_identity_seed()
  first_pk <- .get_identity_keypair()$identity_pk
  expect_identical(.get_identity_seed(), first_seed)
  expect_true(file.exists(file.path(first_state, "identity.seed")))
  expect_false(file.exists(file.path(
    first_state, "privacy", "noise_root")))

  options(dsvert.state_dir = second_state)
  second_seed <- .get_identity_seed()
  second_pk <- .get_identity_keypair()$identity_pk
  expect_true(file.exists(file.path(second_state, "identity.seed")))
  expect_false(file.exists(file.path(
    second_state, "privacy", "noise_root")))
  expect_identical(draws, 2L)
  expect_false(identical(first_seed, second_seed))
  expect_false(identical(first_pk, second_pk))
})

test_that("identity seed creation preserves an existing identity", {
  .identity_test_isolation()
  seed_dir <- tempfile("dsvert-identity-")
  dir.create(seed_dir, mode = "0700")
  seed_path <- file.path(seed_dir, "identity.seed")
  existing <- jsonlite::base64_enc(as.raw(rep(7L, 32L)))
  writeLines(existing, seed_path)
  Sys.chmod(seed_path, mode = "0600")
  called <- FALSE

  expect_invisible(.dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = function(n) {
      called <<- TRUE
      raw(n)
    },
    .allow_test_path = TRUE
  ))
  expect_false(called)
  expect_identical(readLines(seed_path, warn = FALSE), existing)
  expect_true(file.exists(.dsvert_identity_receipt_path(seed_path)))
})

test_that("pre-receipt identity upgrades authenticate the existing DP ledger", {
  .identity_test_isolation()
  seed_dir <- withr::local_tempdir(pattern = "dsvert-identity-ledger-")
  seed_path <- file.path(seed_dir, "identity.seed")
  ledger_path <- file.path(seed_dir, "ledger.sqlite")
  original <- jsonlite::base64_enc(as.raw(rep(37L, 32L)))
  writeLines(original, seed_path)
  Sys.chmod(seed_path, mode = "0600")
  secret <- digest::hmac(
    key = jsonlite::base64_dec(original),
    object = charToRaw("dsVert/dp-ledger/key/v1"),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  secret_id <- .dsvert_dp_hmac(secret, "secret-id-v1")
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger_path)
  DBI::dbExecute(connection,
    "CREATE TABLE dp_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
  DBI::dbExecute(connection,
    "INSERT INTO dp_meta(key, value) VALUES('schema_version', '3')")
  DBI::dbExecute(connection,
    "INSERT INTO dp_meta(key, value) VALUES('secret_id', ?)",
    params = list(secret_id))
  DBI::dbDisconnect(connection)
  Sys.chmod(ledger_path, mode = "0600")
  withr::local_options(list(
    dsvert.dp.ledger_path = ledger_path,
    default.dsvert.dp.ledger_path = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = ""))

  expect_invisible(.dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = function(n) stop("must not sample"),
    .allow_test_path = TRUE))
  receipt <- .dsvert_identity_receipt_path(seed_path)
  expect_true(.dsvert_validate_identity_receipt(receipt, original))

  unlink(receipt, force = TRUE)
  replacement <- jsonlite::base64_enc(as.raw(rep(41L, 32L)))
  writeLines(replacement, seed_path)
  Sys.chmod(seed_path, mode = "0600")
  expect_error(
    .dsvert_init_identity_seed(
      seed_path = seed_path,
      random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "cannot authenticate the existing DP ledger")
  expect_false(file.exists(receipt))
})

test_that("pre-receipt identity upgrades authenticate a surviving joint ledger", {
  .identity_test_isolation()
  seed_dir <- withr::local_tempdir(pattern = "dsvert-identity-joint-")
  seed_path <- file.path(seed_dir, "identity.seed")
  ledger_path <- file.path(seed_dir, "ledger.sqlite")
  joint_path <- paste0(
    ledger_path, ".joint-mpc-single-opening-v1.sqlite")
  original <- jsonlite::base64_enc(as.raw(rep(43L, 32L)))
  replacement <- jsonlite::base64_enc(as.raw(rep(47L, 32L)))
  secret <- digest::hmac(
    key = jsonlite::base64_dec(original),
    object = charToRaw("dsVert/dp-ledger/key/v1"),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  secret_id <- .dsvert_dp_hmac(secret, list(
    "dsvert-joint-dp-ledger-secret-id-v1", "site-a"))
  connection <- DBI::dbConnect(RSQLite::SQLite(), joint_path)
  DBI::dbExecute(connection,
    "CREATE TABLE joint_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
  for (entry in list(
      c("schema_version", "1"), c("secret_id", secret_id),
      c("peer_name", "site-a"))) {
    DBI::dbExecute(connection,
      "INSERT INTO joint_meta(key, value) VALUES(?, ?)",
      params = as.list(entry))
  }
  DBI::dbDisconnect(connection)
  Sys.chmod(joint_path, mode = "0600")
  writeLines(replacement, seed_path)
  Sys.chmod(seed_path, mode = "0600")
  withr::local_options(list(
    dsvert.dp.ledger_path = ledger_path,
    default.dsvert.dp.ledger_path = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = ""))

  expect_error(
    .dsvert_init_identity_seed(
      seed_path = seed_path,
      random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "cannot authenticate the existing DP ledger")
  expect_false(file.exists(.dsvert_identity_receipt_path(seed_path)))
})

test_that("pre-receipt identity upgrades authenticate current joint ledgers", {
  .identity_test_isolation()
  seed_dir <- withr::local_tempdir(pattern = "dsvert-identity-joint-v2-")
  seed_path <- file.path(seed_dir, "identity.seed")
  ledger_path <- file.path(seed_dir, "ledger.sqlite")
  joint_path <- paste0(
    ledger_path, ".joint-mpc-single-opening-v2.sqlite")
  original <- jsonlite::base64_enc(as.raw(rep(59L, 32L)))
  secret <- digest::hmac(
    key = jsonlite::base64_dec(original),
    object = charToRaw("dsVert/dp-ledger/key/v1"),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  secret_id <- .dsvert_dp_hmac(secret, list(
    "dsvert-joint-dp-ledger-secret-id-v1", "site-a"))
  connection <- DBI::dbConnect(RSQLite::SQLite(), joint_path)
  DBI::dbExecute(connection,
    "CREATE TABLE joint_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
  for (entry in list(
      c("schema_version", "2"), c("secret_id", secret_id),
      c("peer_name", "site-a"))) {
    DBI::dbExecute(connection,
      "INSERT INTO joint_meta(key, value) VALUES(?, ?)",
      params = as.list(entry))
  }
  DBI::dbDisconnect(connection)
  Sys.chmod(joint_path, mode = "0600")
  writeLines(original, seed_path)
  Sys.chmod(seed_path, mode = "0600")
  withr::local_options(list(
    dsvert.dp.ledger_path = ledger_path,
    default.dsvert.dp.ledger_path = NULL))

  expect_invisible(.dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = function(n) stop("must not sample"),
    .allow_test_path = TRUE))
  receipt <- .dsvert_identity_receipt_path(seed_path)
  expect_true(.dsvert_validate_identity_receipt(receipt, original))

  unlink(receipt, force = TRUE)
  connection <- DBI::dbConnect(RSQLite::SQLite(), joint_path)
  DBI::dbExecute(connection,
    "UPDATE joint_meta SET value = '1' WHERE key = 'schema_version'")
  DBI::dbDisconnect(connection)
  expect_error(
    .dsvert_init_identity_seed(
      seed_path = seed_path,
      random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "cannot authenticate the existing DP ledger")
  expect_false(file.exists(receipt))

  connection <- DBI::dbConnect(RSQLite::SQLite(), joint_path)
  DBI::dbExecute(connection,
    "UPDATE joint_meta SET value = '2' WHERE key = 'schema_version'")
  DBI::dbExecute(connection,
    "UPDATE joint_meta SET value = 'wrong-secret' WHERE key = 'secret_id'")
  DBI::dbDisconnect(connection)
  expect_error(
    .dsvert_init_identity_seed(
      seed_path = seed_path,
      random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "cannot authenticate the existing DP ledger")
  expect_false(file.exists(receipt))
})

test_that("pre-receipt identity upgrades reject orphan ledger sidecars", {
  .identity_test_isolation()
  seed_dir <- withr::local_tempdir(pattern = "dsvert-identity-sidecar-")
  seed_path <- file.path(seed_dir, "identity.seed")
  ledger_path <- file.path(seed_dir, "ledger.sqlite")
  seed <- jsonlite::base64_enc(as.raw(rep(73L, 32L)))
  writeLines(seed, seed_path)
  Sys.chmod(seed_path, mode = "0600")
  writeBin(charToRaw("orphan authenticated WAL"), paste0(ledger_path, "-wal"))
  withr::local_options(list(
    dsvert.dp.ledger_path = ledger_path,
    default.dsvert.dp.ledger_path = NULL))

  expect_error(
    .dsvert_init_identity_seed(
      seed_path = seed_path,
      random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "local DP ledger has orphan SQLite sidecars")
  expect_false(file.exists(.dsvert_identity_receipt_path(seed_path)))
})

test_that("identity continuity rejects orphan current joint-ledger sidecars", {
  .identity_test_isolation()
  seed_dir <- withr::local_tempdir(
    pattern = "dsvert-identity-joint-v2-sidecar-")
  seed_path <- file.path(seed_dir, "identity.seed")
  ledger_path <- file.path(seed_dir, "ledger.sqlite")
  joint_wal <- paste0(
    ledger_path, ".joint-mpc-single-opening-v2.sqlite-wal")
  seed <- jsonlite::base64_enc(as.raw(rep(79L, 32L)))
  writeLines(seed, seed_path)
  Sys.chmod(seed_path, mode = "0600")
  writeBin(charToRaw("orphan joint WAL"), joint_wal)
  withr::local_options(list(
    dsvert.identity_seed_path = seed_path,
    dsvert.dp.ledger_path = ledger_path,
    default.dsvert.dp.ledger_path = NULL))

  expect_error(
    .dsvert_init_identity_seed(
      seed_path = seed_path,
      random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "joint DP ledger has orphan SQLite sidecars")
  expect_false(file.exists(.dsvert_identity_receipt_path(seed_path)))

})

test_that("pre-receipt identity history enforces the read-only boundary", {
  .identity_test_isolation()
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-identity-history-ro-")
  Sys.chmod(directory, mode = "0700")
  ledger <- file.path(directory, "ledger.sqlite")
  seed <- jsonlite::base64_enc(as.raw(rep(89L, 32L)))
  secret <- digest::hmac(
    key = jsonlite::base64_dec(seed),
    object = charToRaw("dsVert/dp-ledger/key/v1"),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  DBI::dbExecute(connection,
    "CREATE TABLE dp_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
  DBI::dbExecute(connection,
    "INSERT INTO dp_meta(key, value) VALUES('schema_version', '3')")
  DBI::dbExecute(connection,
    "INSERT INTO dp_meta(key, value) VALUES('secret_id', ?)",
    params = list(.dsvert_dp_hmac(secret, "secret-id-v1")))
  DBI::dbDisconnect(connection)
  Sys.chmod(ledger, mode = "0600")
  withr::local_options(list(
    dsvert.dp.ledger_path = ledger,
    default.dsvert.dp.ledger_path = NULL))
  validate <- function(path = ledger) {
    options(dsvert.dp.ledger_path = path)
    .dsvert_identity_validate_pre_receipt_ledgers(seed)
  }
  expect_invisible(validate())

  public <- file.path(directory, "public.sqlite")
  expect_true(file.copy(ledger, public))
  Sys.chmod(public, mode = "0644")
  alias <- file.path(directory, "ledger-alias.sqlite")
  expect_true(file.symlink(public, alias))
  expect_error(validate(alias), "symbolic link")
  expect_identical(as.integer(file.info(public)$mode), 420L)
  unlink(alias, force = TRUE)

  hardlink <- file.path(directory, "ledger-hardlink.sqlite")
  expect_true(file.link(ledger, hardlink))
  expect_error(validate(), "hard links")
  unlink(hardlink, force = TRUE)

  Sys.chmod(ledger, mode = "0644")
  expect_error(validate(), "mode 0600")
  Sys.chmod(ledger, mode = "0600")

  wal <- paste0(ledger, "-wal")
  sidecar_target <- file.path(directory, "sidecar-target")
  writeBin(charToRaw("target"), sidecar_target)
  Sys.chmod(sidecar_target, mode = "0644")
  expect_true(file.symlink(sidecar_target, wal))
  expect_error(validate(), "sidecar must not be a symbolic link")
  expect_identical(as.integer(file.info(sidecar_target)$mode), 420L)
  unlink(wal, force = TRUE)

  expect_true(file.create(wal))
  Sys.chmod(wal, mode = "0600")
  sidecar_hardlink <- file.path(directory, "sidecar-hardlink")
  expect_true(file.link(wal, sidecar_hardlink))
  expect_error(validate(), "sidecar must not have hard links")
  unlink(c(wal, sidecar_hardlink), force = TRUE)

  expect_true(file.create(wal))
  Sys.chmod(wal, mode = "0644")
  expect_error(validate(), "sidecar must be owned.*mode 0600")
  unlink(wal, force = TRUE)

  real_stamp <- .dsvert_dp_ledger_content_stamp
  calls <- 0L
  condition <- testthat::with_mocked_bindings(
    tryCatch(validate(), error = identity),
    .dsvert_dp_ledger_content_stamp = function(path) {
      calls <<- calls + 1L
      if (calls == 2L) {
        stream <- file(path, open = "ab")
        on.exit(close(stream), add = TRUE)
        writeBin(as.raw(0L), stream)
        flush(stream)
      }
      real_stamp(path)
    },
    .package = "dsVert")
  expect_s3_class(condition, "error")
  expect_match(condition$message, "changed during its recovery audit")
})

test_that("an empty configured default never shadows persistent identity", {
  .identity_test_isolation()
  seed_dir <- withr::local_tempdir(pattern = "dsvert-identity-empty-")
  seed_path <- file.path(seed_dir, "identity.seed")
  expected <- jsonlite::base64_enc(as.raw(rep(17L, 32L)))
  writeLines(expected, seed_path)
  Sys.chmod(seed_path, mode = "0600")
  withr::local_options(list(
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = seed_path,
    default.dsvert.identity_seed_path = NULL))

  expect_identical(.get_identity_seed(), expected)
})

test_that("a configured identity is persisted without drawing new entropy", {
  .identity_test_isolation()
  seed_dir <- withr::local_tempdir(pattern = "dsvert-identity-configured-")
  seed_path <- file.path(seed_dir, "identity.seed")
  configured <- jsonlite::base64_enc(as.raw(rep(23L, 32L)))
  sampled <- FALSE
  withr::local_options(list(
    dsvert.identity_seed = configured,
    default.dsvert.identity_seed = NULL))

  expect_invisible(.dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = function(n) {
      sampled <<- TRUE
      raw(n)
    },
    .allow_test_path = TRUE
  ))
  expect_false(sampled)
  expect_identical(.dsvert_validate_identity_seed_file(seed_path), configured)
  expect_true(.dsvert_validate_identity_receipt(
    .dsvert_identity_receipt_path(seed_path), configured))
})

test_that("a configured identity cannot replace persistent identity", {
  .identity_test_isolation()
  seed_dir <- withr::local_tempdir(pattern = "dsvert-identity-conflict-")
  seed_path <- file.path(seed_dir, "identity.seed")
  persistent <- jsonlite::base64_enc(as.raw(rep(29L, 32L)))
  configured <- jsonlite::base64_enc(as.raw(rep(31L, 32L)))
  writeLines(persistent, seed_path)
  Sys.chmod(seed_path, mode = "0600")
  withr::local_options(list(
    dsvert.identity_seed = configured,
    default.dsvert.identity_seed = NULL))

  expect_error(
    .dsvert_init_identity_seed(
      seed_path = seed_path,
      random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "configured identity seed conflicts"
  )
  expect_identical(.dsvert_validate_identity_seed_file(seed_path), persistent)
})

test_that("identity location policy is rechecked after symlink resolution", {
  .identity_test_isolation()
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-identity-alias-")
  target <- file.path(directory, "resolved")
  alias <- file.path(directory, "configured")
  dir.create(target, mode = "0700")
  expect_true(file.symlink(target, alias))
  calls <- character()
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(path, ...) {
      calls <<- c(calls, path)
      if (length(calls) == 2L) stop("resolved location rejected", call. = FALSE)
      invisible(NULL)
    },
    .package = "dsVert")

  expect_error(
    .dsvert_init_identity_seed(
      seed_path = file.path(alias, "identity", "identity.seed"),
      random_bytes = function(n) stop("must not sample")),
    "resolved location rejected")
  expect_length(calls, 2L)
  expect_match(calls[[1L]], "/configured/identity/identity.seed$",
               fixed = FALSE)
  expect_match(calls[[2L]], "/resolved/identity/identity.seed$",
               fixed = FALSE)
})

test_that("unrecoverable identity loss mints a replacement and preserves evidence", {
  .identity_test_isolation()
  skip_on_os("windows")
  seed_dir <- tempfile("dsvert-identity-continuity-")
  seed_path <- file.path(seed_dir, "identity.seed")
  expect_invisible(.dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = function(n) as.raw(seq_len(n) - 1L),
    .allow_test_path = TRUE
  ))
  receipt_path <- .dsvert_identity_receipt_path(seed_path)
  expect_true(file.exists(receipt_path))
  original <- .dsvert_validate_identity_seed_file(seed_path)

  unlink(seed_path, force = TRUE)
  sampled <- FALSE
  expect_invisible(.dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = function(n) {
      sampled <<- TRUE
      as.raw(rep(7L, n))
    },
    .allow_test_path = TRUE
  ))
  expect_true(sampled)
  replacement <- .dsvert_validate_identity_seed_file(seed_path)
  expect_false(identical(replacement, original))
  expect_true(.dsvert_validate_identity_receipt(receipt_path, replacement))
  retired <- list.files(
    file.path(seed_dir, ".retired-identity-continuity"),
    recursive = TRUE, full.names = TRUE)
  expect_true(any(basename(retired) == "identity.seed.receipt"))

  writeLines(jsonlite::base64_enc(as.raw(rep(8L, 32L))), seed_path)
  Sys.chmod(seed_path, mode = "0600")
  expect_error(
    .dsvert_init_identity_seed(
      seed_path = seed_path,
      random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE
    ),
    "receipt does not match"
  )
})

test_that("noise-root recovery restores exactly the same pinned identity", {
  .identity_test_isolation()
  skip_on_os("windows")
  seed_dir <- withr::local_tempdir(pattern = "dsvert-identity-recovery-")
  seed_path <- file.path(seed_dir, "identity.seed")
  withr::local_options(list(dsvert.identity_seed_path = seed_path))
  root <- .identity_test_noise_root()
  expect_invisible(.dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = function(n) as.raw(seq_len(n) - 1L),
    .allow_test_path = TRUE))
  original <- .dsvert_validate_identity_seed_file(seed_path)
  public_before <- .get_identity_keypair()$identity_pk

  recovery <- .dsvert_ensure_identity_recovery(
    seed_path, original, root,
    random_bytes = function(n) as.raw(seq_len(n) + 47L))
  expect_identical(recovery, .dsvert_identity_recovery_path(seed_path))
  expect_identical(.dsvert_identity_open_recovery(recovery, root), original)
  envelope <- readBin(recovery, "raw", n = file.size(recovery))
  expect_false(grepl(original, rawToChar(envelope), fixed = TRUE))
  expect_identical(as.integer(file.info(recovery)$mode), 384L)
  expect_identical(.dsvert_dp_noise_link_count(recovery), 1)

  unlink(seed_path, force = TRUE)
  sampled <- FALSE
  expect_invisible(.dsvert_init_identity_seed(
    seed_path = seed_path,
    random_bytes = function(n) {
      sampled <<- TRUE
      raw(n)
    },
    .allow_test_path = TRUE,
    noise_root_for_recovery = root))
  expect_false(sampled)
  expect_identical(.dsvert_validate_identity_seed_file(seed_path), original)
  expect_identical(.get_identity_keypair()$identity_pk, public_before)
  expect_true(.dsvert_validate_identity_receipt(
    .dsvert_identity_receipt_path(seed_path), original))
  expect_identical(as.integer(file.info(seed_path)$mode), 384L)
})

test_that("each DP privacy epoch can recover the same pinned identity", {
  .identity_test_isolation()
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-identity-epoch-recovery-")
  seed_path <- file.path(directory, "identity.seed")
  withr::local_options(list(dsvert.identity_seed_path = seed_path))
  .dsvert_init_identity_seed(
    seed_path, random_bytes = function(n) as.raw(seq_len(n) + 19L),
    .allow_test_path = TRUE)
  original <- .dsvert_validate_identity_seed_file(seed_path)
  root_one <- .identity_test_noise_root(
    key = as.raw(rep(83L, 32L)), key_id = "noise-root-epoch-1")
  root_two <- .identity_test_noise_root(
    key = as.raw(rep(89L, 32L)), key_id = "noise-root-epoch-2")

  first_path <- .dsvert_ensure_identity_recovery(
    seed_path, original, root_one,
    random_bytes = function(n) as.raw(seq_len(n) + 31L))
  second_path <- .dsvert_ensure_identity_recovery(
    seed_path, original, root_two,
    random_bytes = function(n) as.raw(seq_len(n) + 63L))
  expect_identical(first_path, .dsvert_identity_recovery_path(seed_path))
  expect_false(identical(first_path, second_path))
  expect_true(file.exists(first_path))
  expect_true(file.exists(second_path))
  expect_identical(.dsvert_identity_open_recovery(first_path, root_one),
                   original)
  expect_identical(.dsvert_identity_open_recovery(second_path, root_two),
                   original)

  unlink(seed_path, force = TRUE)
  expect_invisible(.dsvert_init_identity_seed(
    seed_path, random_bytes = function(n) stop("must restore"),
    .allow_test_path = TRUE, noise_root_for_recovery = root_two))
  expect_identical(.dsvert_validate_identity_seed_file(seed_path), original)

  unlink(seed_path, force = TRUE)
  expect_invisible(.dsvert_init_identity_seed(
    seed_path, random_bytes = function(n) stop("must restore"),
    .allow_test_path = TRUE, noise_root_for_recovery = root_one))
  expect_identical(.dsvert_validate_identity_seed_file(seed_path), original)
})

test_that("tamper and a wrong noise root fail before identity restore", {
  .identity_test_isolation()
  skip_on_os("windows")
  seed_dir <- withr::local_tempdir(pattern = "dsvert-identity-tamper-")
  seed_path <- file.path(seed_dir, "identity.seed")
  root <- .identity_test_noise_root()
  .dsvert_init_identity_seed(
    seed_path, random_bytes = function(n) as.raw(seq_len(n) + 7L),
    .allow_test_path = TRUE)
  seed <- .dsvert_validate_identity_seed_file(seed_path)
  recovery <- .dsvert_ensure_identity_recovery(
    seed_path, seed, root,
    random_bytes = function(n) as.raw(seq_len(n) + 79L))
  original_envelope <- readBin(recovery, "raw", n = file.size(recovery))
  unlink(seed_path, force = TRUE)

  value <- jsonlite::fromJSON(
    rawToChar(original_envelope), simplifyVector = TRUE)
  first <- substr(value$mac_sha256, 1L, 1L)
  substr(value$mac_sha256, 1L, 1L) <-
    if (identical(first, "0")) "1" else "0"
  writeBin(charToRaw(.dsvert_dp_canonical_json(value)), recovery)
  Sys.chmod(recovery, mode = "0600")
  expect_error(.dsvert_init_identity_seed(
    seed_path, random_bytes = function(n) stop("must not reroll"),
    .allow_test_path = TRUE, noise_root_for_recovery = root),
    "cannot be authenticated")
  expect_false(file.exists(seed_path))
  expect_false(any(grepl(
    "^\\.identity\\.seed-restore-", list.files(seed_dir))))

  writeBin(original_envelope, recovery)
  Sys.chmod(recovery, mode = "0600")
  wrong_root <- .identity_test_noise_root(
    key = as.raw(rep(199L, 32L)), key_id = root$key_id)
  expect_error(.dsvert_init_identity_seed(
    seed_path, random_bytes = function(n) stop("must not reroll"),
    .allow_test_path = TRUE, noise_root_for_recovery = wrong_root),
    "cannot be authenticated")
  expect_false(file.exists(seed_path))
  expect_identical(
    readBin(recovery, "raw", n = file.size(recovery)), original_envelope)
})

test_that("identity recovery rejects symbolic and hard links", {
  .identity_test_isolation()
  skip_on_os("windows")
  make_fixture <- function(tag) {
    directory <- tempfile(paste0("dsvert-identity-link-", tag, "-"))
    dir.create(directory, mode = "0700")
    seed_path <- file.path(directory, "identity.seed")
    root <- .identity_test_noise_root()
    .dsvert_init_identity_seed(
      seed_path, random_bytes = function(n) as.raw(seq_len(n) + 15L),
      .allow_test_path = TRUE)
    seed <- .dsvert_validate_identity_seed_file(seed_path)
    recovery <- .dsvert_ensure_identity_recovery(
      seed_path, seed, root,
      random_bytes = function(n) as.raw(seq_len(n) + 95L))
    bytes <- readBin(recovery, "raw", n = file.size(recovery))
    unlink(c(seed_path, recovery), force = TRUE)
    list(directory = directory, seed_path = seed_path, recovery = recovery,
         root = root, bytes = bytes)
  }

  symbolic <- make_fixture("symbolic")
  target <- file.path(symbolic$directory, "recovery-target")
  writeBin(symbolic$bytes, target)
  Sys.chmod(target, mode = "0600")
  expect_true(file.symlink(target, symbolic$recovery))
  expect_error(.dsvert_init_identity_seed(
    symbolic$seed_path, random_bytes = function(n) stop("must not reroll"),
    .allow_test_path = TRUE, noise_root_for_recovery = symbolic$root),
    "without links|symbolic")
  expect_false(file.exists(symbolic$seed_path))

  hard <- make_fixture("hard")
  target <- file.path(hard$directory, "recovery-target")
  writeBin(hard$bytes, target)
  Sys.chmod(target, mode = "0600")
  expect_true(file.link(target, hard$recovery))
  expect_error(.dsvert_init_identity_seed(
    hard$seed_path, random_bytes = function(n) stop("must not reroll"),
    .allow_test_path = TRUE, noise_root_for_recovery = hard$root),
    "without links")
  expect_false(file.exists(hard$seed_path))
})

test_that("concurrent identity recovery converges on the original public key", {
  .identity_test_isolation()
  skip_on_os("windows")
  seed_dir <- withr::local_tempdir(
    pattern = "dsvert-identity-concurrent-restore-")
  seed_path <- file.path(seed_dir, "identity.seed")
  withr::local_options(list(dsvert.identity_seed_path = seed_path))
  root <- .identity_test_noise_root()
  .dsvert_init_identity_seed(
    seed_path, random_bytes = function(n) as.raw(seq_len(n) + 23L),
    .allow_test_path = TRUE)
  original <- .dsvert_validate_identity_seed_file(seed_path)
  public_before <- .get_identity_keypair()$identity_pk
  .dsvert_ensure_identity_recovery(
    seed_path, original, root,
    random_bytes = function(n) as.raw(seq_len(n) + 111L))
  unlink(seed_path, force = TRUE)

  public_keys <- unlist(parallel::mclapply(
    seq_len(6L), function(unused) {
      .dsvert_init_identity_seed(
        seed_path, random_bytes = function(n) stop("must not reroll"),
        .allow_test_path = TRUE, noise_root_for_recovery = root)
      .get_identity_keypair()$identity_pk
    }, mc.cores = 6L, mc.preschedule = FALSE), use.names = FALSE)
  expect_identical(unique(public_keys), public_before)
  expect_identical(.dsvert_validate_identity_seed_file(seed_path), original)
  expect_true(.dsvert_validate_identity_receipt(
    .dsvert_identity_receipt_path(seed_path), original))
  expect_false(any(grepl(
    "^\\.identity\\.seed-restore-", list.files(seed_dir))))
})

test_that("loss of both primary roots creates a new unpinned identity", {
  .identity_test_isolation()
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-both-roots-lost-")
  seed_path <- file.path(directory, "identity.seed")
  noise_path <- file.path(directory, "privacy", "noise_root")
  withr::local_options(list(dsvert.identity_seed_path = seed_path))
  .dsvert_init_identity_seed(
    seed_path, random_bytes = function(n) as.raw(seq_len(n) + 31L),
    .allow_test_path = TRUE)
  root <- .dsvert_dp_noise_key_file(noise_path, .allow_test_path = TRUE)
  seed <- .dsvert_validate_identity_seed_file(seed_path)
  .dsvert_ensure_identity_recovery(
    seed_path, seed, root,
    random_bytes = function(n) as.raw(seq_len(n) + 127L))
  expect_true(file.exists(.dsvert_dp_noise_recovery_path(noise_path)))
  expect_true(file.exists(.dsvert_identity_recovery_path(seed_path)))

  unlink(c(seed_path, noise_path), force = TRUE)
  expect_invisible(.dsvert_init_identity_seed(
    seed_path, random_bytes = function(n) as.raw(rep(211L, n)),
    .allow_test_path = TRUE, noise_root_for_recovery = NULL))
  replacement <- .dsvert_validate_identity_seed_file(seed_path)
  expect_false(identical(replacement, seed))
  expect_true(.dsvert_validate_identity_receipt(
    .dsvert_identity_receipt_path(seed_path), replacement))
  expect_false(file.exists(noise_path))
  retired <- list.files(
    file.path(directory, ".retired-identity-continuity"),
    recursive = TRUE, full.names = TRUE)
  expect_true(any(basename(retired) == "identity.seed.recovery"))
})

test_that("concurrent identity bootstrap converges on one seed and receipt", {
  .identity_test_isolation()
  skip_on_os("windows")
  seed_dir <- tempfile("dsvert-identity-concurrent-")
  seed_path <- file.path(seed_dir, "identity.seed")
  results <- unlist(parallel::mclapply(
    seq_len(6L), function(unused) {
      .dsvert_init_identity_seed(
        seed_path = seed_path, .allow_test_path = TRUE)
      .dsvert_validate_identity_seed_file(seed_path)
    }, mc.cores = 6L, mc.preschedule = FALSE), use.names = FALSE)
  expect_length(unique(results), 1L)
  expect_true(.dsvert_validate_identity_receipt(
    .dsvert_identity_receipt_path(seed_path), results[[1L]]))
})

test_that("concurrent pre-receipt upgrades serialize on the identity lock", {
  .identity_test_isolation()
  skip_on_os("windows")
  seed_dir <- withr::local_tempdir(
    pattern = "dsvert-identity-concurrent-upgrade-")
  seed_path <- file.path(seed_dir, "identity.seed")
  existing <- jsonlite::base64_enc(as.raw(rep(53L, 32L)))
  writeLines(existing, seed_path)
  Sys.chmod(seed_path, mode = "0600")

  results <- unlist(parallel::mclapply(
    seq_len(6L), function(unused) {
      .dsvert_init_identity_seed(
        seed_path = seed_path, .allow_test_path = TRUE)
      .dsvert_validate_identity_receipt(
        .dsvert_identity_receipt_path(seed_path), existing)
    }, mc.cores = 6L, mc.preschedule = FALSE), use.names = FALSE)
  expect_true(all(results))
  expect_true(.dsvert_validate_identity_receipt(
    .dsvert_identity_receipt_path(seed_path), existing))
  expect_false(any(grepl(
    "^\\.identity\\.seed-receipt-", list.files(seed_dir))))
})

test_that("identity bootstrap fails closed without durable synchronization", {
  .identity_test_isolation()
  skip_on_os("windows")
  seed_dir <- tempfile("dsvert-identity-sync-")
  seed_path <- file.path(seed_dir, "identity.seed")
  testthat::local_mocked_bindings(
    .dsvert_dp_noise_sync_file = function(path) FALSE,
    .package = "dsVert")
  expect_error(
    .dsvert_init_identity_seed(
      seed_path = seed_path,
      random_bytes = function(n) as.raw(seq_len(n) - 1L),
      .allow_test_path = TRUE
    ),
    "durably synchronize"
  )
  expect_false(file.exists(seed_path))
  expect_false(file.exists(.dsvert_identity_receipt_path(seed_path)))
})

test_that("persistent state overrides an ephemeral HOME across reloads", {
  .identity_test_isolation()
  state_root <- tempfile("dsvert-persistent-state-")
  ephemeral_home <- tempfile("dsvert-ephemeral-home-")
  dir.create(state_root, mode = "0700")
  dir.create(ephemeral_home, mode = "0700")
  withr::local_options(list(
    dsvert.state_dir = NULL,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = NULL,
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL))
  withr::local_envvar(c(
    DSVERT_STATE_DIR = state_root,
    HOME = ephemeral_home))
  seed_path <- file.path(state_root, "identity.seed")
  expect_identical(.dsvert_identity_seed_path(), seed_path)
  .dsvert_init_identity_seed(
    random_bytes = function(n) as.raw(seq_len(n) - 1L),
    .allow_test_path = TRUE)
  first <- .get_identity_seed()

  different_home <- tempfile("dsvert-other-ephemeral-home-")
  dir.create(different_home, mode = "0700")
  withr::local_envvar(HOME = different_home)
  expect_identical(.dsvert_identity_seed_path(), seed_path)
  expect_identical(.get_identity_seed(), first)
  expect_false(file.exists(file.path(ephemeral_home, ".dsvert",
                                     "identity.seed")))
  expect_false(file.exists(file.path(different_home, ".dsvert",
                                     "identity.seed")))
})

test_that("Rock persistent home precedes the container HOME fallback", {
  .identity_test_isolation()
  withr::local_options(list(
    dsvert.state_dir = NULL,
    default.dsvert.state_dir = NULL))
  withr::local_envvar(c(
    DSVERT_STATE_DIR = NA_character_,
    ROCK_HOME = "/srv",
    HOME = "/root"))

  expect_identical(.dsvert_state_root(), "/srv/.dsvert")
  expect_identical(.dsvert_identity_seed_path(), "/srv/.dsvert/identity.seed")
})

test_that("configured identity seeds require canonical 256-bit entropy", {
  .identity_test_isolation()
  valid <- jsonlite::base64_enc(as.raw(rep(9L, 32L)))
  old <- options(dsvert.identity_seed = valid)
  on.exit(options(old), add = TRUE)
  expect_identical(.get_identity_seed(), valid)

  options(dsvert.identity_seed = jsonlite::base64_enc(charToRaw("weak")))
  expect_error(.get_identity_seed(), "identity_seed length")

  options(dsvert.identity_seed = paste0(valid, "\n"))
  expect_error(.get_identity_seed(), "Invalid dsvert.identity_seed")
})

test_that("identity seed files reject trailing or non-canonical content", {
  .identity_test_isolation()
  seed_dir <- tempfile("dsvert-identity-")
  dir.create(seed_dir, mode = "0700")
  seed_path <- file.path(seed_dir, "identity.seed")
  valid <- jsonlite::base64_enc(as.raw(rep(11L, 32L)))
  writeLines(c(valid, valid), seed_path)
  Sys.chmod(seed_path, mode = "0600")
  expect_error(.dsvert_validate_identity_seed_file(seed_path),
               "exactly 256")

  writeLines(sub("=+$", "", valid), seed_path)
  Sys.chmod(seed_path, mode = "0600")
  expect_error(.dsvert_validate_identity_seed_file(seed_path),
               "exactly 256")
})

test_that("identity seed creation fails closed on invalid entropy", {
  .identity_test_isolation()
  private_marker <- "RAW_IDENTITY_ENTROPY_DETAIL_123"
  for (bad_rng in list(
    function(n) raw(n - 1L),
    function(n) rep(0, n),
    function(n) stop(private_marker)
  )) {
    seed_path <- file.path(tempfile("dsvert-identity-"), "identity.seed")
    error <- tryCatch(
      .dsvert_init_identity_seed(
        seed_path, random_bytes = bad_rng, .allow_test_path = TRUE),
      error = identity)
    expect_s3_class(error, "error")
    expect_match(conditionMessage(error), "secure identity seed|entropy")
    expect_false(grepl(
      private_marker, conditionMessage(error), fixed = TRUE))
    expect_false(grepl(
      private_marker,
      paste(capture.output(print(error)), collapse = "\n"), fixed = TRUE))
    expect_false(file.exists(seed_path))
  }
})

test_that("the production random-byte helper validates its contract", {
  .identity_test_isolation()
  expect_error(.dsvert_secure_random_bytes(0), "positive integer")
  expect_error(.dsvert_secure_random_bytes(1.5), "positive integer")
  bytes <- .dsvert_secure_random_bytes(32L)
  expect_type(bytes, "raw")
  expect_length(bytes, 32L)
})
