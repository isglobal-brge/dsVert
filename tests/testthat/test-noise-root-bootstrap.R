test_that("noise-root bootstrap creates once and survives runtime reloads", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-bootstrap-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  identity_seed <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(211L, 32L))))
  withr::local_options(list(dsvert.identity_seed = identity_seed))
  requested <- integer()
  deterministic_rng <- function(n) {
    requested <<- c(requested, n)
    as.raw(seq_len(n) - 1L)
  }

  first <- .dsvert_dp_ensure_noise_key_file(
    path, random_bytes = deterministic_rng, .allow_test_path = TRUE)
  expect_identical(first, normalizePath(path, winslash = "/"))
  expect_identical(requested, 32L)
  expect_identical(readChar(path, nchars = 64L, useBytes = TRUE),
                   paste(sprintf("%02x", 0:31), collapse = ""))
  expect_identical(as.integer(file.info(dirname(path))$mode), 448L)
  expect_identical(as.integer(file.info(path)$mode), 384L)
  expect_identical(.dsvert_dp_noise_link_count(path), 1)
  receipt <- .dsvert_dp_noise_receipt_path(path)
  expect_true(file.exists(receipt))
  expect_identical(as.integer(file.info(receipt)$mode), 384L)
  expect_true(.dsvert_dp_noise_validate_receipt(
    receipt, .dsvert_dp_noise_validate_file(path)))
  recovery <- .dsvert_dp_noise_recovery_path(path)
  expect_true(file.exists(recovery))
  expect_identical(as.integer(file.info(recovery)$mode), 384L)
  expect_identical(
    .dsvert_dp_noise_open_recovery(recovery, identity_seed),
    .dsvert_dp_noise_validate_file(path))

  second <- .dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must not resample"),
    .allow_test_path = TRUE)
  expect_identical(second, first)
  root_one <- .dsvert_dp_noise_key_file(path, .allow_test_path = TRUE)
  root_two <- .dsvert_dp_noise_key_file(path, .allow_test_path = TRUE)
  expect_identical(root_one$key_id, root_two$key_id)
  expect_identical(root_one$hmac(charToRaw("reload")),
                   root_two$hmac(charToRaw("reload")))

  key_hex <- readChar(path, nchars = 64L, useBytes = TRUE)
  serialized_hex <- paste(
    format(serialize(root_one, NULL, version = 3L)), collapse = "")
  expect_false(grepl(key_hex, serialized_hex, fixed = TRUE))

  unlink(path, force = TRUE)
  expect_identical(
    .dsvert_dp_ensure_noise_key_file(
      path, random_bytes = function(n) stop("must restore, not resample"),
      .allow_test_path = TRUE),
    first)
  expect_identical(readChar(path, nchars = 64L, useBytes = TRUE), key_hex)
  expect_identical(root_one$hmac(charToRaw("reload")),
                   .dsvert_dp_noise_key_file(
                     path, .allow_test_path = TRUE)$hmac(
                       charToRaw("reload")))
})

test_that("automatic recovery is identity-authenticated and never rerolls", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-recovery-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  identity_a <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(149L, 32L))))
  identity_b <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(151L, 32L))))
  withr::local_options(list(dsvert.identity_seed = identity_a))
  expect_identical(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) as.raw(seq_len(n) + 31L),
    .allow_test_path = TRUE), normalizePath(path, winslash = "/"))
  original <- .dsvert_dp_noise_validate_file(path)
  recovery <- .dsvert_dp_noise_recovery_path(path)
  recovery_bytes <- readBin(recovery, "raw", n = file.size(recovery))
  expect_false(grepl(
    paste(format(original), collapse = ""), rawToChar(recovery_bytes),
    fixed = TRUE))

  unlink(path, force = TRUE)
  options(dsvert.identity_seed = identity_b)
  expect_error(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must not reroll"),
    .allow_test_path = TRUE), "cannot be authenticated")
  expect_false(file.exists(path))

  options(dsvert.identity_seed = identity_a)
  value <- jsonlite::fromJSON(
    rawToChar(recovery_bytes), simplifyVector = TRUE)
  first <- substr(value$mac_sha256, 1L, 1L)
  substr(value$mac_sha256, 1L, 1L) <- if (identical(first, "0")) "1" else "0"
  writeBin(charToRaw(.dsvert_dp_canonical_json(value)), recovery)
  Sys.chmod(recovery, mode = "0600")
  expect_error(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must not reroll"),
    .allow_test_path = TRUE), "cannot be authenticated")
  expect_false(file.exists(path))

  writeBin(recovery_bytes, recovery)
  Sys.chmod(recovery, mode = "0600")
  expect_identical(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must restore exactly"),
    .allow_test_path = TRUE), normalizePath(path, winslash = "/"))
  expect_identical(.dsvert_dp_noise_validate_file(path), original)
})

test_that("pre-receipt noise-root upgrades authenticate the local DP ledger", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-ledger-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  dir.create(dirname(path), mode = "0700")
  original <- as.raw(rep(59L, 32L))
  writeChar(paste(format(original), collapse = ""), path,
            eos = NULL, useBytes = TRUE)
  Sys.chmod(path, mode = "0600")
  key_id <- paste0(
    "file_", digest::digest(original, algo = "sha256", serialize = FALSE))
  ledger <- file.path(directory, "ledger.sqlite")
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  DBI::dbExecute(connection,
    "CREATE TABLE dp_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
  DBI::dbExecute(connection,
    "CREATE TABLE dp_releases (query_hash TEXT PRIMARY KEY)")
  for (entry in list(
      c("schema_version", "3"), c("next_index", "0"),
      c("noise_key_id", key_id),
      c("noise_key_provider_id", "owner_only_file_v2"))) {
    DBI::dbExecute(connection,
      "INSERT INTO dp_meta(key, value) VALUES(?, ?)",
      params = as.list(entry))
  }
  DBI::dbDisconnect(connection)
  Sys.chmod(ledger, mode = "0600")
  withr::local_options(list(
    dsvert.dp.ledger_path = ledger,
    default.dsvert.dp.ledger_path = NULL))

  expect_identical(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must not sample"),
    .allow_test_path = TRUE), normalizePath(path, winslash = "/"))
  receipt <- .dsvert_dp_noise_receipt_path(path)
  expect_true(.dsvert_dp_noise_validate_receipt(receipt, original))

  unlink(receipt, force = TRUE)
  replacement <- as.raw(rep(61L, 32L))
  writeChar(paste(format(replacement), collapse = ""), path,
            eos = NULL, useBytes = TRUE)
  Sys.chmod(path, mode = "0600")
  expect_error(
    .dsvert_dp_ensure_noise_key_file(
      path, random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "cannot authenticate the existing local/joint release history")
  expect_false(file.exists(receipt))
})

test_that("pre-receipt noise-root upgrades authenticate joint history", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-joint-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  dir.create(dirname(path), mode = "0700")
  original <- as.raw(rep(67L, 32L))
  replacement <- as.raw(rep(71L, 32L))
  original_id <- paste0(
    "file_", digest::digest(original, algo = "sha256", serialize = FALSE))
  writeChar(paste(format(replacement), collapse = ""), path,
            eos = NULL, useBytes = TRUE)
  Sys.chmod(path, mode = "0600")
  ledger <- file.path(directory, "ledger.sqlite")
  joint <- paste0(ledger, ".joint-mpc-single-opening-v1.sqlite")
  connection <- DBI::dbConnect(RSQLite::SQLite(), joint)
  DBI::dbExecute(connection,
    "CREATE TABLE joint_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
  DBI::dbExecute(connection,
    "CREATE TABLE joint_records (record_json TEXT NOT NULL)")
  DBI::dbExecute(connection,
    "INSERT INTO joint_meta(key, value) VALUES('schema_version', '1')")
  DBI::dbExecute(connection,
    "INSERT INTO joint_records(record_json) VALUES(?)",
    params = list(as.character(jsonlite::toJSON(list(
      own_prepare = list(
        noise_key_id = original_id, privacy_epoch = "1")),
      auto_unbox = TRUE, null = "null"))))
  DBI::dbDisconnect(connection)
  Sys.chmod(joint, mode = "0600")
  withr::local_options(list(
    dsvert.dp.ledger_path = ledger,
    default.dsvert.dp.ledger_path = NULL))

  expect_error(
    .dsvert_dp_ensure_noise_key_file(
      path, random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "cannot authenticate the existing local/joint release history")
  expect_false(file.exists(.dsvert_dp_noise_receipt_path(path)))

  replacement_id <- paste0(
    "file_", digest::digest(
      replacement, algo = "sha256", serialize = FALSE))
  connection <- DBI::dbConnect(RSQLite::SQLite(), joint)
  DBI::dbExecute(connection,
    "INSERT INTO joint_records(record_json) VALUES(?)",
    params = list(as.character(jsonlite::toJSON(list(
      own_prepare = list(
        noise_key_id = replacement_id, privacy_epoch = "2")),
      auto_unbox = TRUE, null = "null"))))
  DBI::dbDisconnect(connection)
  expect_identical(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must not sample"),
    .allow_test_path = TRUE), normalizePath(path, winslash = "/"))
  expect_true(.dsvert_dp_noise_validate_receipt(
    .dsvert_dp_noise_receipt_path(path), replacement))
})

test_that("pre-receipt noise-root upgrades reject orphan ledger sidecars", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-sidecar-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  dir.create(dirname(path), mode = "0700")
  key <- as.raw(rep(79L, 32L))
  writeChar(paste(format(key), collapse = ""), path,
            eos = NULL, useBytes = TRUE)
  Sys.chmod(path, mode = "0600")
  ledger <- file.path(directory, "ledger.sqlite")
  writeBin(charToRaw("orphan authenticated SHM"), paste0(ledger, "-shm"))
  withr::local_options(list(
    dsvert.dp.ledger_path = ledger,
    default.dsvert.dp.ledger_path = NULL))

  expect_error(
    .dsvert_dp_ensure_noise_key_file(
      path, random_bytes = function(n) stop("must not sample"),
      .allow_test_path = TRUE),
    "local DP ledger has orphan SQLite sidecars")
  expect_false(file.exists(.dsvert_dp_noise_receipt_path(path)))
})

test_that("pre-receipt noise-root history enforces the read-only boundary", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-history-ro-")
  Sys.chmod(directory, mode = "0700")
  ledger <- file.path(directory, "ledger.sqlite")
  connection <- DBI::dbConnect(RSQLite::SQLite(), ledger)
  DBI::dbExecute(connection,
    "CREATE TABLE dp_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
  DBI::dbExecute(connection,
    "CREATE TABLE dp_releases (query_hash TEXT PRIMARY KEY)")
  DBI::dbExecute(connection,
    "INSERT INTO dp_meta(key, value) VALUES('schema_version', '3')")
  DBI::dbExecute(connection,
    "INSERT INTO dp_meta(key, value) VALUES('next_index', '0')")
  DBI::dbDisconnect(connection)
  Sys.chmod(ledger, mode = "0600")
  key <- as.raw(rep(83L, 32L))
  withr::local_options(list(
    dsvert.dp.ledger_path = ledger,
    default.dsvert.dp.ledger_path = NULL))
  validate <- function(path = ledger) {
    options(dsvert.dp.ledger_path = path)
    .dsvert_dp_noise_validate_pre_receipt_ledgers(key)
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

test_that("concurrent processes converge on one noise root", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-concurrent-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")

  identifiers <- unlist(parallel::mclapply(
    seq_len(6L), function(unused) {
      .dsvert_dp_noise_key_file(path, .allow_test_path = TRUE)$key_id
    }, mc.cores = 6L, mc.preschedule = FALSE), use.names = FALSE)
  expect_length(unique(identifiers), 1L)
  expect_identical(file.info(path)$size, 64)
  expect_identical(as.integer(file.info(path)$mode), 384L)
  expect_identical(.dsvert_dp_noise_link_count(path), 1)
})

test_that("noise-root bootstrap rejects entropy and filesystem substitution", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-negative-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  error <- tryCatch(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("RAW_ENTROPY_DETAIL_123"),
    .allow_test_path = TRUE),
    error = identity)
  expect_s3_class(error, "error")
  expect_match(conditionMessage(error), "operating-system entropy")
  expect_false(grepl(
    "RAW_ENTROPY_DETAIL_123", conditionMessage(error), fixed = TRUE))
  expect_false(file.exists(path))
  expect_false(any(grepl(
    "^\\.noise_root\\.", list.files(dirname(path)), perl = TRUE)))

  dir.create(dirname(path), recursive = TRUE, showWarnings = FALSE,
             mode = "0700")
  Sys.chmod(dirname(path), mode = "0700")
  writeChar(paste0(paste(rep("0", 64L), collapse = ""), "x"),
            path, eos = NULL, useBytes = TRUE)
  Sys.chmod(path, mode = "0600")
  expect_error(.dsvert_dp_noise_key_file(
    path, .allow_test_path = TRUE),
    "invalid representation|exactly 32 random bytes")
  unlink(path, force = TRUE)

  target <- file.path(dirname(path), "target")
  writeChar(paste(rep("1", 64L), collapse = ""), target,
            eos = NULL, useBytes = TRUE)
  Sys.chmod(target, mode = "0600")
  expect_true(file.symlink(target, path))
  expect_error(.dsvert_dp_noise_key_file(
    path, .allow_test_path = TRUE), "symbolic link")
  unlink(path, force = TRUE)

  unlink(c(target, path), force = TRUE)
  writeChar(paste(rep("2", 64L), collapse = ""), target,
            eos = NULL, useBytes = TRUE)
  Sys.chmod(target, mode = "0600")
  expect_true(file.link(target, path))
  Sys.chmod(c(target, path), mode = "0600")
  expect_error(.dsvert_dp_noise_validate_file(path), "hard links")
})

test_that("noise-root location policy is rechecked after symlink resolution", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-alias-")
  target <- file.path(directory, "resolved")
  alias <- file.path(directory, "configured")
  dir.create(target, mode = "0700")
  expect_true(file.symlink(target, alias))
  calls <- character()
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(path, ...) {
      calls <<- c(calls, path)
      invisible(NULL)
    },
    .package = "dsVert")

  result <- .dsvert_dp_noise_private_directory(
    file.path(alias, "privacy", "noise_root"))
  expect_length(calls, 2L)
  expect_match(calls[[1L]], "/configured/privacy/noise_root$", fixed = FALSE)
  expect_identical(calls[[2L]], result)
  expect_identical(
    dirname(result),
    normalizePath(file.path(target, "privacy"), winslash = "/"))
})

test_that("a missing root never replaces a ledger or external-anchor binding", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-recovery-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  ledger <- file.path(directory, "ledger.sqlite")
  writeBin(charToRaw("prior authenticated ledger"), ledger)
  expect_error(
    .dsvert_dp_ensure_noise_key_file(
      path, .allow_test_path = TRUE,
      random_bytes = function(n) stop("must not mint a replacement"),
      .bootstrap_state = list(
        ledger_path = ledger, anchor_provider = NULL, anchor_id = NULL)),
    "restore the original key")
  expect_false(file.exists(path))

  unlink(ledger, force = TRUE)
  joint_ledger <- paste0(
    ledger, ".joint-mpc-single-opening-v1.sqlite")
  writeBin(charToRaw("prior joint authenticated ledger"), joint_ledger)
  expect_error(
    .dsvert_dp_ensure_noise_key_file(
      path, .allow_test_path = TRUE,
      random_bytes = function(n) stop("must not mint a replacement"),
      .bootstrap_state = list(
        ledger_path = ledger, anchor_provider = NULL, anchor_id = NULL)),
    "restore the original key")
  expect_false(file.exists(path))

  unlink(joint_ledger, force = TRUE)
  prior_anchor <- function(action, anchor_id) {
    expect_identical(action, "read")
    expect_identical(anchor_id, "anchor-v1")
    list(schema_version = 2L, next_index = 1)
  }
  expect_error(
    .dsvert_dp_ensure_noise_key_file(
      path, .allow_test_path = TRUE,
      random_bytes = function(n) stop("must not mint a replacement"),
      .bootstrap_state = list(
        ledger_path = ledger, anchor_provider = prior_anchor,
        anchor_id = "anchor-v1")),
    "external rollback anchor already exists")
  expect_false(file.exists(path))
})

test_that("noise-root bootstrap fails closed when durable sync is unavailable", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-sync-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  testthat::local_mocked_bindings(
    .dsvert_dp_noise_sync_file = function(path) FALSE,
    .package = "dsVert")
  expect_error(
    .dsvert_dp_ensure_noise_key_file(
      path, random_bytes = function(n) as.raw(seq_len(n) - 1L),
      .allow_test_path = TRUE),
    "durably synchronize")
  expect_false(file.exists(path))
})

test_that("default roots are persistent and install loads never create keys", {
  skip_on_os("windows")
  withr::local_options(list(
    dsvert.state_dir = NULL, default.dsvert.state_dir = NULL))
  withr::local_envvar(DSVERT_STATE_DIR = NA_character_)
  path <- .dsvert_dp_noise_default_path()
  temporary <- normalizePath(tempdir(), winslash = "/", mustWork = TRUE)
  expect_false(startsWith(path, paste0(temporary, "/")))
  expect_identical(
    path,
    file.path(path.expand("~"), ".dsvert", "privacy", "noise_root"))
  expect_error(.dsvert_dp_ensure_noise_key_file(
    file.path(tempdir(), "forbidden-noise-root")),
    "outside temporary")
  expect_true(.dsvert_is_install_or_development_load(
    file.path(tempdir(), "00LOCK-dsVert", "00new")))
  withr::local_envvar(setNames("dsVert", "_R_CHECK_PACKAGE_NAME_"))
  expect_true(.dsvert_is_install_or_development_load("/runtime/library"))
  withr::local_envvar(R_INSTALL_PKG = "/build/dsVert")
  expect_true(.dsvert_is_install_or_development_load("/runtime/library"))

  package_root <- normalizePath(
    .dsvert_test_package_file(), winslash = "/", mustWork = TRUE)
  key_names <- c("noise_root", "identity.seed")
  expect_false(any(basename(list.files(
    package_root, recursive = TRUE, full.names = TRUE,
    all.files = TRUE, no.. = TRUE)) %in% key_names))
})

test_that("configure never creates cryptographic material", {
  configure <- paste(readLines(
    .dsvert_test_package_file("configure", source_only = TRUE),
    warn = FALSE), collapse = "\n")
  expect_false(grepl(
    "sample\\.int|runif|rnorm|set\\.seed|/dev/urandom|dd[[:space:]]+if=",
    configure, perl = TRUE))
})

test_that("package load is secret-write-free outside install environments", {
  skip_on_os("windows")
  state <- withr::local_tempdir(pattern = "dsvert-image-build-state-")
  withr::local_options(list(
    dsvert.state_dir = state,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.noise_key_path = NULL,
    default.dsvert.dp.noise_key_path = NULL))
  initialization_called <- FALSE
  testthat::local_mocked_bindings(
    .dsvert_dp_assert_canonical_query_runtime = function(...) invisible(NULL),
    .dsvert_initialize_service_state = function(...) {
      initialization_called <<- TRUE
      stop("package load attempted secret bootstrap", call. = FALSE)
    },
    .dsvert_guard_remote_entrypoints = function(...) invisible(NULL),
    .package = "dsVert")

  package_path <- find.package("dsVert")
  expect_invisible(dsVert:::.onLoad(dirname(package_path), "dsVert"))
  expect_false(initialization_called)
  expect_false(file.exists(file.path(state, "identity.seed")))
  expect_false(file.exists(file.path(state, "privacy", "noise_root")))
})

test_that("service initialization bootstraps roots before dataset policy", {
  withr::local_options(list(
    dsvert.dp.enabled = TRUE,
    dsvert.dp.datasets = NULL))
  identity_calls <- policy_calls <- root_calls <- recovery_root_calls <- 0L
  reciprocal_calls <- 0L
  early_root <- list(key_id = "original-root-for-identity-recovery")
  testthat::local_mocked_bindings(
    .dsvert_identity_seed_path = function(...) "/missing/identity.seed",
    .dsvert_dp_noise_root_for_identity_recovery = function() {
      recovery_root_calls <<- recovery_root_calls + 1L
      early_root
    },
    .dsvert_init_identity_seed = function(
        seed_path, noise_root_for_recovery, ...) {
      identity_calls <<- identity_calls + 1L
      expect_identical(seed_path, "/missing/identity.seed")
      expect_identical(noise_root_for_recovery, early_root)
      invisible(NULL)
    },
    .dsvert_dp_policy_build = function(...) {
      policy_calls <<- policy_calls + 1L
      stop("DP policy validation must be deferred", call. = FALSE)
    },
    .dsvert_dp_noise_root = function(...) {
      root_calls <<- root_calls + 1L
      list(key_id = "bootstrapped-before-policy", hmac = identity)
    },
    .dsvert_validate_identity_seed_file = function(...) "persisted-seed",
    .dsvert_ensure_identity_recovery = function(
        seed_path, identity_seed, noise_root, ...) {
      reciprocal_calls <<- reciprocal_calls + 1L
      expect_identical(seed_path, "/missing/identity.seed")
      expect_identical(identity_seed, "persisted-seed")
      expect_true(noise_root$key_id %in% c(
        "bootstrapped", "bootstrapped-before-policy"))
      invisible("/missing/identity.seed.recovery")
    },
    .package = "dsVert")
  expect_silent(.dsvert_initialize_service_state())
  expect_identical(identity_calls, 1L)
  expect_identical(policy_calls, 0L)
  expect_identical(root_calls, 1L)
  expect_identical(recovery_root_calls, 1L)
  expect_identical(reciprocal_calls, 1L)

  expect_silent(.dsvert_initialize_service_state())
  expect_identical(identity_calls, 2L)
  expect_identical(policy_calls, 0L)
  expect_identical(root_calls, 2L)
  expect_identical(recovery_root_calls, 2L)
  expect_identical(reciprocal_calls, 2L)

  expect_true(.dsvert_is_install_or_development_load(
    file.path(tempdir(), "00LOCK-dsVert", "00new")))
})

test_that("enabled service bootstrap tolerates an absent dataset policy", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-service-before-policy-")
  Sys.chmod(directory, mode = "0700")
  noise_path <- file.path(directory, "privacy", "noise_root")
  withr::local_options(list(
    dsvert.state_dir = directory,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.enabled = TRUE,
    default.dsvert.dp.enabled = NULL,
    dsvert.dp.datasets = NULL,
    default.dsvert.dp.datasets = NULL,
    dsvert.dp.noise_key_provider = NULL,
    default.dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = noise_path,
    default.dsvert.dp.noise_key_path = NULL,
    dsvert.dp.ledger_path = NULL,
    default.dsvert.dp.ledger_path = ""))
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")

  expect_invisible(.dsvert_initialize_service_state())
  expect_true(file.exists(file.path(directory, "identity.seed")))
  expect_true(file.exists(noise_path))
  expect_silent(.dsvert_validate_identity_seed_file(
    file.path(directory, "identity.seed")))
  expect_silent(.dsvert_dp_noise_validate_file(noise_path))
})

test_that("service startup restores identity from its original file noise root", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-service-identity-recovery-")
  Sys.chmod(directory, mode = "0700")
  noise_path <- file.path(directory, "privacy", "noise_root")
  withr::local_options(list(
    dsvert.state_dir = directory,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.enabled = FALSE,
    default.dsvert.dp.enabled = NULL,
    dsvert.dp.noise_key_provider = NULL,
    default.dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = noise_path,
    default.dsvert.dp.noise_key_path = NULL,
    dsvert.dp.ledger_path = NULL,
    default.dsvert.dp.ledger_path = ""))
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")

  expect_invisible(.dsvert_initialize_service_state())
  seed_path <- file.path(directory, "identity.seed")
  seed <- .dsvert_validate_identity_seed_file(seed_path)
  public_before <- .get_identity_keypair()$identity_pk
  noise_before <- .dsvert_dp_noise_validate_file(noise_path)
  expect_true(file.exists(.dsvert_identity_recovery_path(seed_path)))
  expect_true(file.exists(.dsvert_dp_noise_recovery_path(noise_path)))

  unlink(seed_path, force = TRUE)
  expect_invisible(.dsvert_initialize_service_state())
  expect_identical(.dsvert_validate_identity_seed_file(seed_path), seed)
  expect_identical(.get_identity_keypair()$identity_pk, public_before)
  expect_identical(.dsvert_dp_noise_validate_file(noise_path), noise_before)
})

test_that("service startup regenerates both irrecoverably lost roots", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-service-both-roots-lost-")
  Sys.chmod(directory, mode = "0700")
  noise_path <- file.path(directory, "privacy", "noise_root")
  withr::local_options(list(
    dsvert.state_dir = directory,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.enabled = FALSE,
    default.dsvert.dp.enabled = NULL,
    dsvert.dp.noise_key_provider = NULL,
    default.dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = noise_path,
    default.dsvert.dp.noise_key_path = NULL,
    dsvert.dp.ledger_path = NULL,
    default.dsvert.dp.ledger_path = ""))
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")

  expect_invisible(.dsvert_initialize_service_state())
  seed_path <- file.path(directory, "identity.seed")
  identity_before <- .get_identity_keypair()$identity_pk
  noise_before <- .dsvert_dp_noise_validate_file(noise_path)

  unlink(c(seed_path, noise_path), force = TRUE)
  expect_invisible(.dsvert_initialize_service_state())
  expect_false(identical(.get_identity_keypair()$identity_pk,
                         identity_before))
  expect_false(identical(.dsvert_dp_noise_validate_file(noise_path),
                         noise_before))
  expect_true(dir.exists(file.path(
    directory, ".retired-identity-continuity")))
})

test_that("unrecoverable identity loss rotates a surviving noise root", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-service-identity-and-root-rotation-")
  Sys.chmod(directory, mode = "0700")
  noise_path <- file.path(directory, "privacy", "noise_root")
  withr::local_options(list(
    dsvert.state_dir = directory,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.enabled = FALSE,
    default.dsvert.dp.enabled = NULL,
    dsvert.dp.noise_key_provider = NULL,
    default.dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = noise_path,
    default.dsvert.dp.noise_key_path = NULL,
    dsvert.dp.ledger_path = NULL,
    default.dsvert.dp.ledger_path = ""))
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")

  expect_invisible(.dsvert_initialize_service_state())
  seed_path <- file.path(directory, "identity.seed")
  identity_before <- .get_identity_keypair()$identity_pk
  root_before <- .dsvert_dp_noise_key_file(
    noise_path, .allow_test_path = TRUE)$key_id
  unlink(c(seed_path, .dsvert_identity_recovery_paths(seed_path)),
         force = TRUE)

  expect_invisible(.dsvert_initialize_service_state())
  expect_false(identical(.get_identity_keypair()$identity_pk,
                         identity_before))
  root_after <- .dsvert_dp_noise_key_file(
    noise_path, .allow_test_path = TRUE)
  expect_false(identical(root_after$key_id, root_before))
  expect_true(root_after$automatic_rotation)
  expect_true(any(basename(list.files(
    file.path(directory, "privacy", ".retired-noise-continuity"),
    recursive = TRUE, full.names = TRUE)) == "noise_root"))
})

test_that("service bootstrap rejects a configured identity before root creation", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-service-configured-root-restore-")
  Sys.chmod(directory, mode = "0700")
  noise_path <- file.path(directory, "privacy", "noise_root")
  configured <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(223L, 32L))))
  withr::local_options(list(
    dsvert.state_dir = directory,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = configured,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.enabled = FALSE,
    default.dsvert.dp.enabled = NULL,
    dsvert.dp.noise_key_provider = NULL,
    default.dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = noise_path,
    default.dsvert.dp.noise_key_path = NULL,
    dsvert.dp.ledger_path = NULL,
    default.dsvert.dp.ledger_path = ""))
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")

  seed_path <- file.path(directory, "identity.seed")
  expect_error(
    .dsvert_initialize_service_state(),
    "must not be configured in a package image or service profile")
  expect_false(file.exists(seed_path))
  expect_false(file.exists(noise_path))
})

test_that("simultaneous root loss retires old DP state and resumes cleanly", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-service-both-roots-ledger-")
  Sys.chmod(directory, mode = "0700")
  seed_path <- file.path(directory, "identity.seed")
  noise_path <- file.path(directory, "privacy", "noise_root")
  ledger <- file.path(directory, "ledger.sqlite")
  withr::local_options(list(
    dsvert.state_dir = directory,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.enabled = FALSE,
    default.dsvert.dp.enabled = NULL,
    dsvert.dp.noise_key_provider = NULL,
    default.dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = noise_path,
    default.dsvert.dp.noise_key_path = NULL,
    dsvert.dp.ledger_path = ledger,
    default.dsvert.dp.ledger_path = NULL))
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")

  expect_invisible(.dsvert_initialize_service_state())
  identity_before <- .get_identity_keypair()$identity_pk
  root_before <- .dsvert_dp_noise_key_file(
    noise_path, .allow_test_path = TRUE)
  policy <- list(
    schema_version = 7L, datasets = list(), ledger_path = ledger,
    ledger_private = TRUE, lock_timeout_ms = 30000L,
    noise_root = root_before)
  handle <- .dsvert_dp_open_ledger(policy)
  expect_invisible(.dsvert_dp_initialize_or_validate(
    handle$connection, policy, .dsvert_dp_secret()))
  expect_invisible(.dsvert_dp_initialize_or_validate_noise_root(
    handle$connection, policy))
  .dsvert_dp_close_ledger(handle)

  # Exercise every persistent DP store derived from the configured ledger.
  extra_bases <- setdiff(
    .dsvert_identity_dp_state_bases(ledger), ledger)
  for (index in seq_along(extra_bases)) {
    writeBin(charToRaw(paste0("retired-store-", index)),
             extra_bases[[index]])
    Sys.chmod(extra_bases[[index]], mode = "0600")
  }
  active_artifacts <- .dsvert_identity_dp_state_bases(ledger)
  before_hashes <- setNames(vapply(active_artifacts, function(path) {
    digest::digest(file = path, algo = "sha256", serialize = FALSE)
  }, character(1L)), basename(active_artifacts))

  # Both primary roots are gone; reciprocal envelopes and old ledgers remain.
  unlink(c(seed_path, noise_path), force = TRUE)
  results <- parallel::mclapply(seq_len(4L), function(unused) {
    .dsvert_initialize_service_state()
    list(
      identity_pk = .get_identity_keypair()$identity_pk,
      root_id = .dsvert_dp_noise_key_file(
        noise_path, .allow_test_path = TRUE)$key_id)
  }, mc.cores = 4L, mc.preschedule = FALSE)
  expect_length(unique(vapply(
    results, `[[`, character(1L), "identity_pk")), 1L)
  expect_length(unique(vapply(
    results, `[[`, character(1L), "root_id")), 1L)
  expect_false(identical(results[[1L]]$identity_pk, identity_before))
  expect_false(identical(results[[1L]]$root_id, root_before$key_id))
  expect_false(any(file.exists(active_artifacts)))

  retired <- list.files(
    file.path(directory, ".dsvert-retired-dp-state"),
    recursive = TRUE, full.names = TRUE)
  retired_by_name <- setNames(retired, basename(retired))
  expect_true(all(names(before_hashes) %in% names(retired_by_name)))
  after_hashes <- vapply(names(before_hashes), function(name) {
    digest::digest(
      file = retired_by_name[[name]], algo = "sha256", serialize = FALSE)
  }, character(1L))
  expect_identical(unname(after_hashes), unname(before_hashes))
  manifest_path <- retired_by_name[["transition.json"]]
  manifest <- jsonlite::fromJSON(manifest_path, simplifyVector = TRUE)
  expect_identical(
    manifest$protocol, .DSVERT_IDENTITY_RETIRED_DP_STATE_PROTOCOL)
  expect_identical(
    manifest$authentication,
    "not_claimed_after_loss_of_both_reciprocal_roots")

  # The original path is immediately reusable under the replacement identity
  # and root. This is the post-repin server-side continuation boundary.
  root_after <- .dsvert_dp_noise_key_file(
    noise_path, .allow_test_path = TRUE)
  expect_true(root_after$automatic_rotation)
  journal <- .dsvert_dp_noise_read_epoch_journal(
    .dsvert_dp_noise_epoch_path(noise_path),
    .dsvert_validate_identity_seed_file(seed_path))
  expect_identical(
    journal$active$reason,
    "identity_replacement_after_continuity_loss")
  replacement_policy <- policy
  replacement_policy$noise_root <- root_after
  handle <- .dsvert_dp_open_ledger(replacement_policy)
  expect_invisible(.dsvert_dp_initialize_or_validate(
    handle$connection, replacement_policy, .dsvert_dp_secret()))
  expect_invisible(.dsvert_dp_initialize_or_validate_noise_root(
    handle$connection, replacement_policy))
  expect_identical(
    .dsvert_dp_meta_get(handle$connection, "next_index"), "0")
  .dsvert_dp_close_ledger(handle)
  expect_invisible(.dsvert_initialize_service_state())
  expect_identical(.get_identity_keypair()$identity_pk,
                   results[[1L]]$identity_pk)
  expect_identical(.dsvert_dp_noise_key_file(
    noise_path, .allow_test_path = TRUE)$key_id,
    results[[1L]]$root_id)
})

test_that("service startup can restore identity through an original HSM root", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-service-hsm-recovery-")
  Sys.chmod(directory, mode = "0700")
  hsm_key <- as.raw(rep(173L, 32L))
  provider <- function(action, message_base64 = NULL) {
    if (identical(action, "capabilities")) {
      return(list(
        schema_version = 1L, provider_id = "startup-test-hsm",
        key_id = "persistent-hsm-root-v1",
        external = TRUE, hmac_sha256 = TRUE))
    }
    if (!identical(action, "hmac_sha256") ||
        !is.character(message_base64) || length(message_base64) != 1L) {
      stop("unsupported HSM action", call. = FALSE)
    }
    list(
      schema_version = 1L, provider_id = "startup-test-hsm",
      key_id = "persistent-hsm-root-v1",
      digest_sha256 = digest::hmac(
        key = hsm_key, object = jsonlite::base64_dec(message_base64),
        algo = "sha256", serialize = FALSE))
  }
  withr::local_options(list(
    dsvert.state_dir = directory,
    default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = "",
    dsvert.identity_seed_path = NULL,
    default.dsvert.identity_seed_path = NULL,
    dsvert.dp.enabled = FALSE,
    default.dsvert.dp.enabled = NULL,
    dsvert.dp.noise_key_provider = provider,
    default.dsvert.dp.noise_key_provider = NULL,
    dsvert.dp.noise_key_path = NULL,
    default.dsvert.dp.noise_key_path = NULL,
    dsvert.dp.ledger_path = NULL,
    default.dsvert.dp.ledger_path = ""))
  testthat::local_mocked_bindings(
    .dsvert_dp_reject_ephemeral_or_library_path = function(...) invisible(),
    .package = "dsVert")

  expect_invisible(.dsvert_initialize_service_state())
  seed_path <- file.path(directory, "identity.seed")
  seed <- .dsvert_validate_identity_seed_file(seed_path)
  public_before <- .get_identity_keypair()$identity_pk
  recovery <- .dsvert_identity_recovery_path(seed_path)
  expect_true(file.exists(recovery))
  expect_identical(.dsvert_identity_open_recovery(
    recovery, .dsvert_dp_noise_root()), seed)

  unlink(seed_path, force = TRUE)
  expect_invisible(.dsvert_initialize_service_state())
  expect_identical(.dsvert_validate_identity_seed_file(seed_path), seed)
  expect_identical(.get_identity_keypair()$identity_pk, public_before)

  # If the identity and its reciprocal envelope are both lost, the external
  # root remains usable. Mint a new unpinned identity and commit its transition
  # only after the HSM-wrapped replacement envelope is durable.
  unlink(c(seed_path, .dsvert_identity_recovery_paths(seed_path)),
         force = TRUE)
  expect_invisible(.dsvert_initialize_service_state())
  expect_false(identical(.get_identity_keypair()$identity_pk, public_before))
  expect_identical(.dsvert_dp_noise_root()$key_id,
                   "persistent-hsm-root-v1")
  identity_archive <- file.path(
    directory, ".retired-identity-continuity")
  expect_length(Sys.glob(file.path(
    identity_archive, "*", "noise-root-transition.pending")), 0L)
  expect_length(Sys.glob(file.path(
    identity_archive, "*", "noise-root-transition.complete")), 1L)
})

test_that("inactive bootstrap refuses to replace a configured ledger root", {
  ledger <- tempfile("dsvert-existing-ledger-", fileext = ".sqlite")
  writeBin(charToRaw("prior authenticated ledger"), ledger)
  withr::local_options(list(dsvert.dp.ledger_path = ledger))
  state <- .dsvert_noise_bootstrap_state_from_options()
  expect_identical(state$ledger_path, path.expand(ledger))
  expect_null(state$anchor_provider)
  expect_null(state$anchor_id)
  expect_true(is.function(state$history_provider))

  directory <- withr::local_tempdir(
    pattern = "dsvert-inactive-noise-guard-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  expect_error(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must not resample"),
    .allow_test_path = TRUE, .bootstrap_state = state),
    "could not be authenticated")
  expect_false(file.exists(path))

  forged <- state
  forged$history_provider <- function() list(
    protocol = .DSVERT_DP_AUTHENTICATED_EMPTY_HISTORY_PROTOCOL,
    sources = "local", audit_sha256 = strrep("0", 64L))
  forged_path <- file.path(directory, "forged", "noise_root")
  expect_error(.dsvert_dp_ensure_noise_key_file(
    forged_path, random_bytes = function(n) as.raw(rep(7L, n)),
    .allow_test_path = TRUE, .bootstrap_state = forged),
    "invalid noise-root binding")
  expect_false(file.exists(forged_path))
})

test_that("inactive bootstrap rejects orphan sidecars and legacy joint v1", {
  directory <- withr::local_tempdir(
    pattern = "dsvert-inactive-legacy-guard-")
  Sys.chmod(directory, mode = "0700")
  ledger <- file.path(directory, "ledger.sqlite")
  withr::local_options(list(dsvert.dp.ledger_path = ledger))
  state <- .dsvert_noise_bootstrap_state_from_options()

  orphan <- paste0(ledger, "-wal")
  writeBin(charToRaw("orphaned committed state"), orphan)
  Sys.chmod(orphan, mode = "0600")
  orphan_root <- file.path(directory, "orphan", "noise_root")
  expect_error(.dsvert_dp_ensure_noise_key_file(
    orphan_root, random_bytes = function(n) stop("must not resample"),
    .allow_test_path = TRUE, .bootstrap_state = state),
    "could not be authenticated")
  expect_false(file.exists(orphan_root))

  unlink(orphan, force = TRUE)
  legacy <- paste0(
    ledger, ".joint-mpc-single-opening-v1.sqlite")
  writeBin(charToRaw("legacy joint history"), legacy)
  Sys.chmod(legacy, mode = "0600")
  legacy_root <- file.path(directory, "legacy", "noise_root")
  expect_error(.dsvert_dp_ensure_noise_key_file(
    legacy_root, random_bytes = function(n) stop("must not resample"),
    .allow_test_path = TRUE, .bootstrap_state = state),
    "could not be authenticated")
  expect_false(file.exists(legacy_root))
})

test_that("irrecoverable file-root loss rotates automatically without a quota", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-epoch-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  identity_seed <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(181L, 32L))))
  withr::local_options(list(dsvert.identity_seed = identity_seed))
  authenticated_history <- NULL
  bootstrap <- list(
    ledger_path = file.path(directory, "ledger.sqlite"),
    anchor_provider = NULL, anchor_id = NULL,
    history_provider = function() authenticated_history)
  draw <- 0L
  entropy <- function(n) {
    draw <<- draw + 1L
    as.raw(rep(20L + draw, n))
  }

  expect_identical(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = entropy, .allow_test_path = TRUE,
    .bootstrap_state = bootstrap), normalizePath(path, winslash = "/"))
  first <- .dsvert_dp_noise_key_file(
    path, .allow_test_path = TRUE, .bootstrap_state = bootstrap)
  expect_identical(first$epoch, 1)
  expect_identical(first$rotation_count, 0)
  context <- charToRaw("same semantic release")
  first_sticky <- first$hmac(context)
  expect_identical(first_sticky, first$hmac(context))

  for (rotation in seq_len(6L)) {
    current <- .dsvert_dp_noise_read_epoch_journal(
      .dsvert_dp_noise_epoch_path(path), identity_seed)$active
    authenticated_history <- list(
      privacy_epoch = current$privacy_epoch,
      noise_key_id = current$key_id,
      noise_key_provider_id = "owner_only_file_v2",
      composition_audit = list(
        source = "local", release_count = as.character(rotation),
        cumulative_epsilon = as.character(rotation * 1000),
        # Deliberately above one: composition is audit telemetry, never a
        # rotation/admission budget gate.
        cumulative_delta = as.character(rotation * 10),
        chain_head = strrep(sprintf("%x", rotation %% 16L), 64L)))
    unlink(c(path, .dsvert_dp_noise_recovery_path(path)), force = TRUE)
    expect_identical(.dsvert_dp_ensure_noise_key_file(
      path, random_bytes = entropy, .allow_test_path = TRUE,
      .bootstrap_state = bootstrap), normalizePath(path, winslash = "/"))
  }

  final <- .dsvert_dp_noise_key_file(
    path, .allow_test_path = TRUE, .bootstrap_state = bootstrap)
  journal <- .dsvert_dp_noise_read_epoch_journal(
    .dsvert_dp_noise_epoch_path(path), identity_seed)
  expect_identical(final$epoch, 7)
  expect_identical(final$rotation_count, 6)
  expect_true(final$automatic_rotation)
  expect_identical(journal$record_count, 13)
  expect_null(journal$pending)
  expect_identical(journal$active$composition_audit$cumulative_delta, "60")
  expect_false(identical(first$key_id, final$key_id))
  expect_false(identical(first_sticky, final$hmac(context)))
  expect_identical(final$hmac(context), final$hmac(context))
  expect_true(file.exists(paste0(
    .dsvert_dp_noise_receipt_path(path), ".epoch-6.",
    substr(journal$active$previous_key_id, 6L, 21L))))

  authenticated_history$composition_audit$release_count <- "5"
  unlink(c(path, .dsvert_dp_noise_recovery_path(path)), force = TRUE)
  expect_error(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must reject rollback first"),
    .allow_test_path = TRUE, .bootstrap_state = bootstrap),
    "rolled back")
  expect_false(file.exists(path))
})

test_that("an unreleased surviving receipt bootstraps one authenticated rotation", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-noise-receipt-only-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  identity_seed <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(182L, 32L))))
  withr::local_options(list(dsvert.identity_seed = identity_seed))
  bootstrap <- list(
    ledger_path = file.path(directory, "ledger.sqlite"),
    anchor_provider = NULL, anchor_id = NULL,
    history_provider = function() NULL)
  first_entropy <- function(n) as.raw(rep(41L, n))
  .dsvert_dp_ensure_noise_key_file(
    path, random_bytes = first_entropy, .allow_test_path = TRUE,
    .bootstrap_state = bootstrap)
  first_key <- .dsvert_dp_noise_validate_file(path)
  first_key_id <- paste0("file_", digest::digest(
    first_key, algo = "sha256", serialize = FALSE))
  receipt <- .dsvert_dp_noise_receipt_path(path)

  unlink(c(
    path, .dsvert_dp_noise_recovery_path(path),
    .dsvert_dp_noise_epoch_path(path)), force = TRUE)
  draws <- 0L
  expect_identical(.dsvert_dp_ensure_noise_key_file(
    path,
    random_bytes = function(n) {
      draws <<- draws + 1L
      as.raw(rep(42L, n))
    },
    .allow_test_path = TRUE, .bootstrap_state = bootstrap),
    normalizePath(path, winslash = "/"))

  expect_identical(draws, 1L)
  replacement <- .dsvert_dp_noise_validate_file(path)
  expect_false(identical(replacement, first_key))
  journal <- .dsvert_dp_noise_read_epoch_journal(
    .dsvert_dp_noise_epoch_path(path), identity_seed)
  expect_identical(journal$active$privacy_epoch, 2)
  expect_identical(journal$active$previous_key_id, first_key_id)
  expect_identical(journal$record_count, 3)
  expect_null(journal$pending)
  archived <- paste0(
    receipt, ".epoch-1.", substr(first_key_id, 6L, 21L))
  expect_true(file.exists(archived))
  expect_identical(
    .dsvert_dp_noise_read_receipt_key_id(archived), first_key_id)
  expect_true(.dsvert_dp_noise_validate_receipt(receipt, replacement))
})

test_that("receipt-only recovery rejects tamper and surviving release state", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-noise-receipt-guard-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  identity_seed <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(184L, 32L))))
  withr::local_options(list(dsvert.identity_seed = identity_seed))
  clean <- list(
    ledger_path = file.path(directory, "ledger.sqlite"),
    anchor_provider = NULL, anchor_id = NULL,
    history_provider = function() NULL)
  .dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) as.raw(rep(51L, n)),
    .allow_test_path = TRUE, .bootstrap_state = clean)
  receipt <- .dsvert_dp_noise_receipt_path(path)
  unlink(c(
    path, .dsvert_dp_noise_recovery_path(path),
    .dsvert_dp_noise_epoch_path(path)), force = TRUE)

  writeBin(charToRaw("not a receipt"), receipt)
  Sys.chmod(receipt, mode = "0600")
  expect_error(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must not reroll tamper"),
    .allow_test_path = TRUE, .bootstrap_state = clean),
    "receipt is invalid")
  expect_false(file.exists(path))

  writeBin(charToRaw(.dsvert_dp_canonical_json(list(
    protocol = .DSVERT_DP_NOISE_RECEIPT_PROTOCOL,
    key_id = paste0("file_", strrep("3", 64L))))), receipt)
  Sys.chmod(receipt, mode = "0600")
  writeBin(charToRaw("surviving release state"), clean$ledger_path)
  expect_error(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must not reroll history"),
    .allow_test_path = TRUE, .bootstrap_state = clean),
    "persistent ledger state already exists")
  expect_false(file.exists(path))
  expect_false(file.exists(.dsvert_dp_noise_epoch_path(path)))
})

test_that("concurrent loss recovery commits exactly one new privacy epoch", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(
    pattern = "dsvert-noise-epoch-concurrent-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  identity_seed <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(183L, 32L))))
  withr::local_options(list(dsvert.identity_seed = identity_seed))
  history <- NULL
  bootstrap <- list(
    ledger_path = file.path(directory, "ledger.sqlite"),
    anchor_provider = NULL, anchor_id = NULL,
    history_provider = function() history)
  .dsvert_dp_ensure_noise_key_file(
    path, .allow_test_path = TRUE, .bootstrap_state = bootstrap)
  active <- .dsvert_dp_noise_read_epoch_journal(
    .dsvert_dp_noise_epoch_path(path), identity_seed)$active
  history <- list(
    privacy_epoch = active$privacy_epoch, noise_key_id = active$key_id,
    noise_key_provider_id = "owner_only_file_v2",
    composition_audit = .dsvert_dp_noise_epoch_audit())
  unlink(c(path, .dsvert_dp_noise_recovery_path(path)), force = TRUE)

  identifiers <- unlist(parallel::mclapply(seq_len(6L), function(unused) {
    .dsvert_dp_ensure_noise_key_file(
      path, .allow_test_path = TRUE, .bootstrap_state = bootstrap)
    key <- .dsvert_dp_noise_validate_file(path)
    paste0("file_", digest::digest(
      key, algo = "sha256", serialize = FALSE))
  }, mc.cores = 6L, mc.preschedule = FALSE), use.names = FALSE)
  expect_length(unique(identifiers), 1L)
  journal <- .dsvert_dp_noise_read_epoch_journal(
    .dsvert_dp_noise_epoch_path(path), identity_seed)
  expect_identical(journal$active$privacy_epoch, 2)
  expect_identical(journal$record_count, 3)
  expect_null(journal$pending)
})

test_that("pending rotations resume and journal corruption never rerolls", {
  skip_on_os("windows")
  directory <- withr::local_tempdir(pattern = "dsvert-noise-pending-")
  Sys.chmod(directory, mode = "0700")
  path <- file.path(directory, "privacy", "noise_root")
  identity_seed <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(rep(185L, 32L))))
  withr::local_options(list(dsvert.identity_seed = identity_seed))
  history <- NULL
  bootstrap <- list(
    ledger_path = file.path(directory, "ledger.sqlite"),
    anchor_provider = NULL, anchor_id = NULL,
    history_provider = function() history)
  .dsvert_dp_ensure_noise_key_file(
    path, .allow_test_path = TRUE, .bootstrap_state = bootstrap)
  active <- .dsvert_dp_noise_read_epoch_journal(
    .dsvert_dp_noise_epoch_path(path), identity_seed)$active
  history <- list(
    privacy_epoch = active$privacy_epoch, noise_key_id = active$key_id,
    noise_key_provider_id = "owner_only_file_v2",
    composition_audit = .dsvert_dp_noise_epoch_audit())
  unlink(c(path, .dsvert_dp_noise_recovery_path(path)), force = TRUE)
  staged <- .dsvert_dp_noise_stage_new_key(
    path, function(n) as.raw(rep(193L, n)))
  pending <- .dsvert_dp_noise_append_epoch_record(
    path, phase = "pending", epoch = 2, key_id = staged$key_id,
    previous_key_id = active$key_id,
    reason = "irrecoverable_file_root_loss", audit = NULL,
    identity_seed = identity_seed)
  expect_identical(pending$pending$key_id, staged$key_id)

  expect_identical(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must resume staged key"),
    .allow_test_path = TRUE, .bootstrap_state = bootstrap),
    normalizePath(path, winslash = "/"))
  complete <- .dsvert_dp_noise_read_epoch_journal(
    .dsvert_dp_noise_epoch_path(path), identity_seed)
  expect_identical(complete$active$privacy_epoch, 2)
  expect_identical(complete$active$key_id, staged$key_id)
  expect_null(complete$pending)

  journal_path <- .dsvert_dp_noise_epoch_path(path)
  bytes <- readBin(journal_path, "raw", n = file.size(journal_path))
  bytes[[length(bytes) - 2L]] <- as.raw(bitwXor(
    as.integer(bytes[[length(bytes) - 2L]]), 1L))
  writeBin(bytes, journal_path)
  Sys.chmod(journal_path, mode = "0600")
  before <- .dsvert_dp_noise_validate_file(path)
  expect_error(.dsvert_dp_ensure_noise_key_file(
    path, random_bytes = function(n) stop("must not reroll corruption"),
    .allow_test_path = TRUE, .bootstrap_state = bootstrap),
    "journal")
  expect_identical(.dsvert_dp_noise_validate_file(path), before)
})
