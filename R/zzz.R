#' Package Load Hook
#'
#' Package loading validates the executable surface but never creates secret
#' material. Independent Ed25519 identity and sticky-noise roots are generated
#' on the first cryptographic service operation, preventing image-build loads
#' from baking one deployment identity into every clone. A recovered identity
#' is preferred; an unrecoverable replacement remains untrusted by its peers
#' until their administrators verify and update the name-bound pin.
#'
#' @name dsVert-package
#' @encoding UTF-8
#' @keywords internal
#' @importFrom utils file_test head tail packageVersion
"_PACKAGE"

.DSVERT_IDENTITY_RECEIPT_PROTOCOL <- "dsvert-identity-seed-receipt-v1"
.DSVERT_IDENTITY_RECOVERY_PROTOCOL <-
  "dsvert-identity-seed-noise-root-wrapped-recovery-v1"
.DSVERT_IDENTITY_RETIRED_DP_STATE_PROTOCOL <-
  "dsvert-retired-dp-state-after-identity-loss-v1"

.dsvert_state_root <- function(
    configured = getOption(
      "dsvert.state_dir", getOption("default.dsvert.state_dir")),
    environment = Sys.getenv("DSVERT_STATE_DIR", unset = ""),
    rock_home = Sys.getenv("ROCK_HOME", unset = ""),
    home = Sys.getenv("HOME", unset = "")) {
  value <- if (!is.null(configured)) {
    configured
  } else if (nzchar(environment)) {
    environment
  } else if (nzchar(rock_home)) {
    file.path(rock_home, ".dsvert")
  } else {
    file.path(home, ".dsvert")
  }
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value)) {
    stop("The persistent dsVert state directory is unavailable",
         call. = FALSE)
  }
  value <- path.expand(value)
  if (!grepl("^/", value)) {
    stop("The persistent dsVert state directory must be absolute",
         call. = FALSE)
  }
  value
}

.dsvert_identity_seed_path <- function(
    configured = getOption(
      "dsvert.identity_seed_path",
      getOption("default.dsvert.identity_seed_path"))) {
  if (!is.null(configured)) {
    if (!is.character(configured) || length(configured) != 1L ||
        is.na(configured) || !nzchar(configured)) {
      stop("dsvert.identity_seed_path must be one non-empty path",
           call. = FALSE)
    }
    return(path.expand(configured))
  }
  file.path(.dsvert_state_root(), "identity.seed")
}

.dsvert_configured_identity_seed <- function() {
  # Test-only peer emulation. Production bootstrap rejects a literal seed so
  # package images and shared service profiles cannot clone one deployment
  # identity across nodes.
  seed <- getOption("dsvert.identity_seed")
  if (is.null(seed)) seed <- getOption("default.dsvert.identity_seed")
  # DataSHIELD package profiles commonly materialise an empty-string default.
  # It means "not configured"; it must not shadow the persistent seed.
  if (is.null(seed) ||
      (is.character(seed) && length(seed) == 1L && !is.na(seed) &&
       !nzchar(seed))) {
    return(NULL)
  }
  .dsvert_normalize_crypto_b64(seed, 32L, "dsvert.identity_seed")
}

.dsvert_identity_seed_configuration <- function(allow_test = FALSE) {
  configured <- .dsvert_configured_identity_seed()
  if (!isTRUE(allow_test) && !is.null(configured)) {
    stop(
      "A production identity seed must not be configured in a package image or service profile; restore the owner-only identity.seed file instead",
      call. = FALSE)
  }
  configured
}

.dsvert_identity_seed_matches_configuration <- function(seed) {
  configured <- .dsvert_configured_identity_seed()
  if (!is.null(configured) && !identical(seed, configured)) {
    stop(
      "The configured identity seed conflicts with the persistent identity",
      call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_secure_random_bytes <- function(n) {
  if (!is.numeric(n) || length(n) != 1L || is.na(n) || !is.finite(n) ||
      n < 1 || n != as.integer(n)) {
    stop("n must be one positive integer", call. = FALSE)
  }
  bytes <- tryCatch(
    openssl::rand_bytes(as.integer(n)),
    error = function(e) {
      stop("Secure operating-system entropy is unavailable: ",
           conditionMessage(e), call. = FALSE)
    }
  )
  if (!is.raw(bytes) || length(bytes) != as.integer(n)) {
    stop("Secure operating-system entropy returned an invalid result",
         call. = FALSE)
  }
  bytes
}

.dsvert_validate_identity_seed_file <- function(seed_path) {
  if (!file.exists(seed_path) || !file_test("-f", seed_path)) {
    stop("Identity seed is not a regular file", call. = FALSE)
  }
  if (.dsvert_dp_path_is_link(seed_path)) {
    stop("Identity seed must not be a symbolic link", call. = FALSE)
  }
  if (!.dsvert_dp_private_mode(seed_path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(seed_path), 1)) {
    stop("Identity seed must be an owner-only file without hard links",
         call. = FALSE)
  }
  info <- file.info(seed_path)
  if (nrow(info) != 1L || is.na(info$size) ||
      !info$size %in% c(44, 45, 46)) {
    stop("Identity seed file must contain exactly 256 base64-encoded bits",
         call. = FALSE)
  }
  before <- unname(info[c("size", "mtime", "ctime")])
  encoded_raw <- readBin(seed_path, what = "raw", n = info$size + 1L)
  after_info <- file.info(seed_path)
  after <- unname(after_info[c("size", "mtime", "ctime")])
  if (.dsvert_dp_path_is_link(seed_path) ||
      !file.exists(seed_path) || !file_test("-f", seed_path) ||
      !.dsvert_dp_private_mode(seed_path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(seed_path), 1) ||
      !identical(before, after) || length(encoded_raw) != info$size) {
    stop("Identity seed changed while it was being read", call. = FALSE)
  }
  encoded_text <- rawToChar(encoded_raw)
  encoded <- if (info$size == 44) {
    encoded_text
  } else if (info$size == 45 && endsWith(encoded_text, "\n")) {
    substr(encoded_text, 1L, 44L)
  } else if (info$size == 46 && endsWith(encoded_text, "\r\n")) {
    substr(encoded_text, 1L, 44L)
  } else {
    ""
  }
  canonical <- tryCatch(
    .dsvert_normalize_crypto_b64(
      encoded, 32L, "identity seed"),
    error = function(e) NULL)
  if (is.null(canonical) ||
      !identical(encoded, canonical)) {
    stop("Identity seed file must contain exactly 256 base64-encoded bits",
         call. = FALSE)
  }
  canonical
}

.dsvert_identity_receipt_path <- function(seed_path) {
  paste0(seed_path, ".receipt")
}

.dsvert_identity_recovery_path <- function(seed_path) {
  paste0(seed_path, ".recovery")
}

.dsvert_identity_recovery_epoch_path <- function(
    seed_path, noise_root_provider_id, noise_root_key_id) {
  binding <- .dsvert_dp_canonical_json(list(
    provider_id = noise_root_provider_id, key_id = noise_root_key_id))
  paste0(
    .dsvert_identity_recovery_path(seed_path), ".",
    digest::digest(binding, algo = "sha256", serialize = FALSE))
}

.dsvert_identity_recovery_paths <- function(seed_path) {
  canonical <- .dsvert_identity_recovery_path(seed_path)
  unique(c(canonical, Sys.glob(paste0(canonical, ".*"))))
}

.dsvert_identity_dp_state_bases <- function(ledger_path) {
  unique(c(
    paste0(ledger_path, ".joint-mpc-single-opening-v1.sqlite"),
    paste0(ledger_path, ".joint-mpc-single-opening-v2.sqlite"),
    paste0(
      ledger_path,
      ".joint-mpc-single-opening-v2.sqlite.capsule-registry-v1.sqlite"),
    paste0(
      ledger_path,
      ".joint-mpc-single-opening-v2.sqlite.capsule-registry-v2.sqlite"),
    paste0(
      ledger_path,
      ".joint-mpc-single-opening-v2.sqlite.capsule-registry-v3.sqlite"),
    paste0(ledger_path, ".joint-dp-vector-v3.sqlite"),
    paste0(ledger_path, ".joint-dp-vector-v4.sqlite"),
    paste0(ledger_path, ".capsule-source-v1.sqlite"),
    paste0(ledger_path, ".capsule-source-v2.sqlite"),
    paste0(ledger_path, ".capsule-source-v3.sqlite")))
}

# When both reciprocal roots are unavailable, an old identity-derived ledger
# can no longer be authenticated. Preserve it as private forensic evidence and
# remove it from the active path before minting the replacement identity. This
# is a continuity reset, not a claim that the replacement key authenticates the
# retired history. External anchors remain untouched under their old anchor id.
.dsvert_retire_dp_state_after_identity_loss <- function(archive) {
  state <- .dsvert_noise_bootstrap_state_from_options()
  if (is.null(state)) return(invisible(character()))
  ledger_path <- file.path(
    normalizePath(dirname(state$ledger_path), winslash = "/",
                  mustWork = TRUE),
    basename(state$ledger_path))
  bases <- .dsvert_identity_dp_state_bases(ledger_path)
  suffixes <- c("", "-wal", "-shm", "-journal")
  artifacts <- unique(unlist(lapply(
    bases, function(path) paste0(path, suffixes)), use.names = FALSE))
  if (anyDuplicated(basename(artifacts))) {
    stop("DP-state retirement paths are ambiguous", call. = FALSE)
  }
  present_for_base <- vapply(bases, function(path) {
    any(vapply(paste0(path, suffixes), function(candidate) {
      file.exists(candidate) || .dsvert_dp_path_is_link(candidate)
    }, logical(1L)))
  }, logical(1L))
  bases <- bases[present_for_base]
  retired_root <- file.path(
    dirname(ledger_path), ".dsvert-retired-dp-state")
  if (.dsvert_dp_path_is_link(retired_root)) {
    stop("Retired DP-state root must not be a symbolic link", call. = FALSE)
  }
  if (!dir.exists(retired_root) &&
      !dir.create(retired_root, mode = "0700", showWarnings = FALSE)) {
    stop("Could not create the retired DP-state root", call. = FALSE)
  }
  Sys.chmod(retired_root, mode = "0700")
  if (!.dsvert_dp_private_mode(retired_root, directory = TRUE)) {
    stop("Retired DP-state root must be owner-only", call. = FALSE)
  }
  retired <- file.path(retired_root, basename(archive))
  manifest <- file.path(retired, "transition.json")
  already_retired <- if (dir.exists(retired) &&
                         !.dsvert_dp_path_is_link(retired)) {
    setdiff(list.files(retired, all.files = TRUE, no.. = TRUE),
            basename(manifest))
  } else {
    character()
  }
  if (!length(bases) && !length(already_retired)) {
    return(invisible(character()))
  }
  if (.dsvert_dp_path_is_link(retired)) {
    stop("Retired DP-state directory must not be a symbolic link",
         call. = FALSE)
  }
  if (!dir.exists(retired) &&
      !dir.create(retired, mode = "0700", showWarnings = FALSE)) {
    stop("Could not create the retired DP-state directory", call. = FALSE)
  }
  Sys.chmod(retired, mode = "0700")
  if (!.dsvert_dp_private_mode(retired, directory = TRUE)) {
    stop("Retired DP-state directory must be owner-only", call. = FALSE)
  }

  if (file.exists(manifest) || .dsvert_dp_path_is_link(manifest)) {
    if (length(bases)) {
      stop("Active DP state reappeared after its retirement was committed",
           call. = FALSE)
    }
    valid_manifest <- tryCatch({
      if (.dsvert_dp_path_is_link(manifest) || !file_test("-f", manifest) ||
          !.dsvert_dp_private_mode(manifest, directory = FALSE) ||
          !identical(.dsvert_dp_noise_link_count(manifest), 1)) {
        stop("invalid manifest")
      }
      value <- jsonlite::fromJSON(manifest, simplifyVector = TRUE)
      identical(
        value$protocol, .DSVERT_IDENTITY_RETIRED_DP_STATE_PROTOCOL) &&
        identical(
          value$authentication,
          "not_claimed_after_loss_of_both_reciprocal_roots")
    }, error = function(e) FALSE)
    if (!isTRUE(valid_manifest)) {
      stop("The retired DP-state manifest is invalid", call. = FALSE)
    }
    return(invisible(file.path(retired, already_retired)))
  }

  locks <- list()
  on.exit({
    for (lock in rev(locks)) {
      try(filelock::unlock(lock), silent = TRUE)
    }
  }, add = TRUE)
  for (base in sort(bases, method = "radix")) {
    lock_path <- paste0(base, ".lock")
    if (.dsvert_dp_path_is_link(lock_path)) {
      stop("A DP-state retirement lock must not be a symbolic link",
           call. = FALSE)
    }
    lock <- filelock::lock(lock_path, timeout = 30000)
    if (is.null(lock)) {
      stop("A DP state store is busy during identity replacement",
           call. = FALSE)
    }
    Sys.chmod(lock_path, mode = "0600")
    if (.dsvert_dp_path_is_link(lock_path) ||
        !.dsvert_dp_private_mode(lock_path, directory = FALSE) ||
        !identical(.dsvert_dp_noise_link_count(lock_path), 1)) {
      filelock::unlock(lock)
      stop("A DP-state retirement lock is not private", call. = FALSE)
    }
    locks[[length(locks) + 1L]] <- lock
  }

  present <- artifacts[vapply(artifacts, function(path) {
    file.exists(path) || .dsvert_dp_path_is_link(path)
  }, logical(1L))]
  invalid <- vapply(present, function(path) {
    .dsvert_dp_path_is_link(path) || !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)
  }, logical(1L))
  if (any(invalid)) {
    stop("Retired DP state is not a regular owner-only file without links",
         call. = FALSE)
  }
  targets <- file.path(retired, basename(present))
  if (any(vapply(targets, function(path) {
    file.exists(path) || .dsvert_dp_path_is_link(path)
  }, logical(1L)))) {
    stop("Retired DP-state evidence conflicts with an existing archive",
         call. = FALSE)
  }
  for (index in seq_along(present)) {
    if (!file.rename(present[[index]], targets[[index]])) {
      stop("Could not preserve retired DP-state evidence", call. = FALSE)
    }
    Sys.chmod(targets[[index]], mode = "0600")
    .dsvert_identity_require_sync(
      targets[[index]], "retired DP-state evidence")
  }
  retired_names <- setdiff(
    list.files(retired, all.files = TRUE, no.. = TRUE),
    basename(manifest))
  value <- .dsvert_dp_canonical_json(list(
    protocol = .DSVERT_IDENTITY_RETIRED_DP_STATE_PROTOCOL,
    active_ledger_basename = basename(ledger_path),
    retired_artifacts = as.list(sort(retired_names, method = "radix")),
    continuity = "unrecoverable_identity_root_loss",
    authentication = "not_claimed_after_loss_of_both_reciprocal_roots"))
  temporary <- tempfile(
    paste0(".retired-dp-state-", Sys.getpid(), "."), tmpdir = retired)
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(value), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  .dsvert_identity_require_sync(temporary, "staged retired DP-state manifest")
  if (!file.rename(temporary, manifest)) {
    stop("Could not commit the retired DP-state manifest", call. = FALSE)
  }
  Sys.chmod(manifest, mode = "0600")
  .dsvert_identity_require_sync(manifest, "retired DP-state manifest")
  .dsvert_identity_require_sync(retired, "retired DP-state directory")
  .dsvert_identity_require_sync(retired_root, "retired DP-state root")
  invisible(targets)
}

.dsvert_retire_identity_continuity <- function(seed_path) {
  artifacts <- unique(c(
    .dsvert_identity_receipt_path(seed_path),
    .dsvert_identity_recovery_paths(seed_path)))
  present <- artifacts[vapply(artifacts, function(path) {
    file.exists(path) || .dsvert_dp_path_is_link(path)
  }, logical(1L))]
  archive_root <- file.path(
    dirname(seed_path), ".retired-identity-continuity")
  pending <- if (dir.exists(archive_root) &&
                 !.dsvert_dp_path_is_link(archive_root)) {
    Sys.glob(file.path(
      archive_root, "*", "noise-root-transition.pending"))
  } else {
    character()
  }
  if (!length(present) && !length(pending)) return(invisible(NULL))
  if (length(pending) > 1L) {
    stop("Multiple pending identity-replacement transitions exist",
         call. = FALSE)
  }
  invalid <- vapply(present, function(path) {
    .dsvert_dp_path_is_link(path) || !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)
  }, logical(1L))
  if (any(invalid)) {
    stop("Lost-identity continuity evidence is not a regular owner-only file",
         call. = FALSE)
  }

  if (.dsvert_dp_path_is_link(archive_root)) {
    stop("Retired identity directory must not be a symbolic link",
         call. = FALSE)
  }
  if (!dir.exists(archive_root) &&
      !dir.create(archive_root, mode = "0700", showWarnings = FALSE)) {
    stop("Could not create the retired identity directory", call. = FALSE)
  }
  Sys.chmod(archive_root, mode = "0700")
  if (!.dsvert_dp_private_mode(archive_root, directory = TRUE)) {
    stop("Retired identity directory must be owner-only", call. = FALSE)
  }
  archive <- if (length(pending)) {
    dirname(pending[[1L]])
  } else {
    tempfile("identity-", tmpdir = archive_root)
  }
  if (!dir.exists(archive) &&
      !dir.create(archive, mode = "0700", showWarnings = FALSE)) {
    stop("Could not create a retired identity epoch", call. = FALSE)
  }
  Sys.chmod(archive, mode = "0700")
  marker <- file.path(archive, "noise-root-transition.pending")
  if (!file.exists(marker)) {
    connection <- file(marker, open = "wb")
    on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
            add = TRUE)
    writeBin(charToRaw("dsvert-identity-replacement-v1"), connection)
    flush(connection)
    close(connection)
    Sys.chmod(marker, mode = "0600")
    .dsvert_identity_require_sync(marker, "identity replacement marker")
  }

  invisible(.dsvert_retire_dp_state_after_identity_loss(archive))

  for (path in present) {
    target <- file.path(archive, basename(path))
    if (file.exists(target) || .dsvert_dp_path_is_link(target)) {
      stop("Retired identity evidence conflicts with an existing archive",
           call. = FALSE)
    }
    if (!file.rename(path, target)) {
      stop("Could not preserve lost-identity continuity evidence",
           call. = FALSE)
    }
    .dsvert_identity_require_sync(target, "retired identity evidence")
  }
  .dsvert_identity_require_sync(archive, "retired identity epoch")
  .dsvert_identity_require_sync(
    archive_root, "retired identity directory")
  .dsvert_identity_require_sync(
    dirname(seed_path), "identity directory")
  invisible(archive)
}

.dsvert_complete_external_identity_replacement <- function() {
  archive_root <- file.path(
    dirname(.dsvert_identity_seed_path()),
    ".retired-identity-continuity")
  if (!dir.exists(archive_root)) return(invisible(NULL))
  if (.dsvert_dp_path_is_link(archive_root) ||
      !.dsvert_dp_private_mode(archive_root, directory = TRUE)) {
    stop("Retired identity directory must be an owner-only directory",
         call. = FALSE)
  }
  markers <- Sys.glob(file.path(
    archive_root, "*", "noise-root-transition.pending"))
  if (!length(markers)) return(invisible(NULL))
  if (length(markers) != 1L) {
    stop("Multiple pending identity-replacement transitions exist",
         call. = FALSE)
  }
  marker <- markers[[1L]]
  if (.dsvert_dp_path_is_link(marker) || !file_test("-f", marker) ||
      !.dsvert_dp_private_mode(marker, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(marker), 1)) {
    stop("Identity replacement marker is not a regular owner-only file",
         call. = FALSE)
  }
  completed <- sub("[.]pending$", ".complete", marker)
  if (file.exists(completed) || .dsvert_dp_path_is_link(completed) ||
      !file.rename(marker, completed)) {
    stop("Could not commit the external-root identity replacement",
         call. = FALSE)
  }
  Sys.chmod(completed, mode = "0600")
  .dsvert_identity_require_sync(
    dirname(completed), "external-root identity replacement")
  invisible(completed)
}

# The first noise root keeps the compatibility path. A later privacy epoch gets
# a content-addressed envelope instead of overwriting the only recovery copy.
# Selection depends solely on the authenticated root provider/key identifiers;
# the selected file is still fully MAC-verified before use.
.dsvert_identity_recovery_path_for_root <- function(
    seed_path, noise_root) {
  keys <- .dsvert_dp_identity_recovery_keys(noise_root)
  canonical <- .dsvert_identity_recovery_path(seed_path)
  if (file.exists(canonical) || .dsvert_dp_path_is_link(canonical)) {
    value <- .dsvert_identity_read_recovery(canonical)
    if (identical(value$noise_root_provider_id,
                  keys$noise_root_provider_id) &&
        identical(value$noise_root_key_id, keys$noise_root_key_id)) {
      return(canonical)
    }
    return(.dsvert_identity_recovery_epoch_path(
      seed_path, keys$noise_root_provider_id, keys$noise_root_key_id))
  }
  epoch_path <- .dsvert_identity_recovery_epoch_path(
    seed_path, keys$noise_root_provider_id, keys$noise_root_key_id)
  if (file.exists(epoch_path) || .dsvert_dp_path_is_link(epoch_path)) {
    return(epoch_path)
  }
  canonical
}

.dsvert_identity_seed_id <- function(seed) {
  seed <- .dsvert_normalize_crypto_b64(seed, 32L, "identity seed")
  paste0(
    "seed_",
    digest::digest(
      jsonlite::base64_dec(seed), algo = "sha256", serialize = FALSE))
}

.dsvert_identity_recovery_b64_encode <- function(value) {
  if (!is.raw(value)) {
    stop("Invalid identity-recovery bytes", call. = FALSE)
  }
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.dsvert_identity_recovery_b64_decode <- function(value, bytes, what) {
  valid <- is.character(value) && length(value) == 1L && !is.na(value) &&
    grepl("^[A-Za-z0-9_-]+$", value) && nchar(value) %% 4L != 1L
  decoded <- if (isTRUE(valid)) tryCatch(
    jsonlite::base64_dec(.base64url_to_base64(value)),
    error = function(e) NULL) else NULL
  if (is.null(decoded) || !is.raw(decoded) || length(decoded) != bytes ||
      !identical(.dsvert_identity_recovery_b64_encode(decoded), value)) {
    stop("The identity recovery ", what, " is invalid", call. = FALSE)
  }
  decoded
}

.dsvert_identity_recovery_message <- function(value) {
  charToRaw(paste0(
    "dsVert/identity-seed/recovery-envelope/v1|",
    .dsvert_dp_canonical_json(value)))
}

.dsvert_identity_read_recovery <- function(path) {
  if (.dsvert_dp_path_is_link(path) || !file.exists(path) ||
      !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)) {
    stop("The identity recovery must be a regular owner-only file without links",
         call. = FALSE)
  }
  info <- file.info(path)
  if (nrow(info) != 1L || is.na(info$size) || info$size < 1L ||
      info$size > 2048L) {
    stop("The identity recovery has an invalid representation",
         call. = FALSE)
  }
  before <- unname(info[c("size", "mtime", "ctime")])
  encoded <- readBin(path, what = "raw", n = info$size + 1L)
  after_info <- file.info(path)
  after <- unname(after_info[c("size", "mtime", "ctime")])
  if (.dsvert_dp_path_is_link(path) || !file.exists(path) ||
      !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1) ||
      !identical(before, after) || length(encoded) != info$size) {
    stop("The identity recovery changed while it was being read",
         call. = FALSE)
  }
  value <- tryCatch(
    jsonlite::fromJSON(rawToChar(encoded), simplifyVector = TRUE),
    error = function(e) NULL)
  required <- c(
    "protocol", "noise_root_provider_id", "noise_root_key_id",
    "identity_seed_id", "cipher", "iv_base64url",
    "ciphertext_base64url", "mac_sha256")
  scalar_id <- function(x) {
    is.character(x) && length(x) == 1L && !is.na(x) &&
      grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", x)
  }
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), required) &&
    identical(value$protocol, .DSVERT_IDENTITY_RECOVERY_PROTOCOL) &&
    scalar_id(value$noise_root_provider_id) &&
    scalar_id(value$noise_root_key_id) &&
    is.character(value$identity_seed_id) &&
    length(value$identity_seed_id) == 1L &&
    !is.na(value$identity_seed_id) &&
    grepl("^seed_[0-9a-f]{64}$", value$identity_seed_id) &&
    identical(value$cipher, "aes-256-ctr+hmac-sha256") &&
    is.character(value$mac_sha256) && length(value$mac_sha256) == 1L &&
    !is.na(value$mac_sha256) &&
    grepl("^[0-9a-f]{64}$", value$mac_sha256)
  if (!isTRUE(valid)) {
    stop("The identity recovery has an invalid contract", call. = FALSE)
  }
  value
}

.dsvert_identity_open_recovery <- function(path, noise_root) {
  value <- .dsvert_identity_read_recovery(path)
  keys <- .dsvert_dp_identity_recovery_keys(noise_root)
  unsigned <- value[setdiff(names(value), "mac_sha256")]
  expected_mac <- digest::hmac(
    key = keys$authentication,
    object = .dsvert_identity_recovery_message(unsigned),
    algo = "sha256", serialize = FALSE)
  authenticated <-
    identical(value$noise_root_provider_id,
              keys$noise_root_provider_id) &&
    identical(value$noise_root_key_id, keys$noise_root_key_id) &&
    .dsvert_dp_noise_recovery_hex_equal(value$mac_sha256, expected_mac)
  if (!isTRUE(authenticated)) {
    stop("The identity recovery cannot be authenticated by the original DP noise root",
         call. = FALSE)
  }
  iv <- .dsvert_identity_recovery_b64_decode(
    value$iv_base64url, 16L, "initialization vector")
  ciphertext <- .dsvert_identity_recovery_b64_decode(
    value$ciphertext_base64url, 32L, "ciphertext")
  seed_raw <- tryCatch(
    openssl::aes_ctr_decrypt(ciphertext, keys$encryption, iv = iv),
    error = function(e) NULL)
  if (is.raw(seed_raw)) attributes(seed_raw) <- NULL
  seed <- if (is.raw(seed_raw) && length(seed_raw) == 32L) {
    gsub("[\r\n]", "", jsonlite::base64_enc(seed_raw))
  } else NULL
  if (is.null(seed) ||
      !identical(.dsvert_identity_seed_id(seed), value$identity_seed_id)) {
    stop("The identity recovery plaintext is invalid", call. = FALSE)
  }
  seed_raw <- keys <- NULL
  seed
}

# Caller holds identity.seed.lock. Authentication and receipt validation happen
# before the staging file is allocated, so a wrong root or modified envelope
# cannot write a replacement identity.
.dsvert_identity_restore_recovery <- function(seed_path, noise_root) {
  recovery <- .dsvert_identity_recovery_path_for_root(
    seed_path, noise_root)
  seed <- .dsvert_identity_open_recovery(recovery, noise_root)
  receipt <- .dsvert_identity_receipt_path(seed_path)
  if (file.exists(receipt)) {
    invisible(.dsvert_validate_identity_receipt(receipt, seed))
  } else if (.dsvert_dp_path_is_link(receipt)) {
    stop("Identity receipt must not be a symbolic link", call. = FALSE)
  }
  .dsvert_identity_seed_matches_configuration(seed)

  temporary <- tempfile(
    paste0(".identity.seed-restore-", Sys.getpid(), "."),
    tmpdir = dirname(seed_path))
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(seed), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  staged <- .dsvert_validate_identity_seed_file(temporary)
  if (!identical(staged, seed)) {
    stop("The staged recovered identity does not match its envelope",
         call. = FALSE)
  }
  .dsvert_identity_require_sync(temporary, "staged recovered identity seed")
  if (file.exists(seed_path) || .dsvert_dp_path_is_link(seed_path)) {
    existing <- .dsvert_validate_identity_seed_file(seed_path)
    if (!identical(existing, seed)) {
      stop("A conflicting identity appeared during recovery", call. = FALSE)
    }
    return(invisible(seed_path))
  }
  if (!file.rename(temporary, seed_path)) {
    stop("Could not atomically restore the private identity seed",
         call. = FALSE)
  }
  Sys.chmod(seed_path, mode = "0600")
  restored <- .dsvert_validate_identity_seed_file(seed_path)
  if (!identical(restored, seed)) {
    stop("The committed recovered identity is invalid", call. = FALSE)
  }
  .dsvert_identity_require_sync(
    dirname(seed_path), "recovered identity directory")
  invisible(seed_path)
}

.dsvert_ensure_identity_recovery <- function(
    seed_path, identity_seed, noise_root,
    random_bytes = .dsvert_secure_random_bytes) {
  seed_path <- path.expand(seed_path)
  identity_seed <- .dsvert_normalize_crypto_b64(
    identity_seed, 32L, "identity recovery seed")
  if (!is.function(random_bytes)) {
    stop("random_bytes must be a secure random-byte function", call. = FALSE)
  }
  keys <- .dsvert_dp_identity_recovery_keys(noise_root)
  lock_path <- paste0(seed_path, ".lock")
  if (.dsvert_dp_path_is_link(lock_path)) {
    stop("Identity seed lock must not be a symbolic link", call. = FALSE)
  }
  previous_umask <- Sys.umask("0077")
  on.exit(try(Sys.umask(previous_umask), silent = TRUE), add = TRUE)
  lock <- filelock::lock(lock_path, timeout = 30000)
  if (is.null(lock)) {
    stop("Identity recovery lock is unavailable", call. = FALSE)
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  Sys.chmod(lock_path, mode = "0600")
  if (.dsvert_dp_path_is_link(lock_path) ||
      !.dsvert_dp_private_mode(lock_path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(lock_path), 1)) {
    stop("Identity recovery lock is not private", call. = FALSE)
  }
  active <- .dsvert_validate_identity_seed_file(seed_path)
  if (!identical(active, identity_seed)) {
    stop("The identity recovery seed is not the active persistent identity",
         call. = FALSE)
  }
  recovery <- .dsvert_identity_recovery_path_for_root(
    seed_path, noise_root)
  if (file.exists(recovery)) {
    recovered <- .dsvert_identity_open_recovery(recovery, noise_root)
    if (!identical(recovered, active)) {
      stop("The identity recovery does not match the active identity",
           call. = FALSE)
    }
    return(invisible(recovery))
  }
  if (.dsvert_dp_path_is_link(recovery)) {
    stop("The identity recovery must not be a symbolic link",
         call. = FALSE)
  }
  iv <- random_bytes(16L)
  if (!is.raw(iv) || length(iv) != 16L) {
    stop("Secure operating-system entropy returned an invalid identity recovery IV",
         call. = FALSE)
  }
  seed_raw <- jsonlite::base64_dec(active)
  ciphertext <- openssl::aes_ctr_encrypt(
    seed_raw, keys$encryption, iv = iv)
  attributes(ciphertext) <- NULL
  unsigned <- list(
    protocol = .DSVERT_IDENTITY_RECOVERY_PROTOCOL,
    noise_root_provider_id = keys$noise_root_provider_id,
    noise_root_key_id = keys$noise_root_key_id,
    identity_seed_id = .dsvert_identity_seed_id(active),
    cipher = "aes-256-ctr+hmac-sha256",
    iv_base64url = .dsvert_identity_recovery_b64_encode(iv),
    ciphertext_base64url =
      .dsvert_identity_recovery_b64_encode(ciphertext))
  value <- c(unsigned, list(mac_sha256 = digest::hmac(
    key = keys$authentication,
    object = .dsvert_identity_recovery_message(unsigned),
    algo = "sha256", serialize = FALSE)))
  .dsvert_identity_require_sync(seed_path, "identity seed")
  .dsvert_identity_require_sync(dirname(seed_path), "identity directory")
  temporary <- tempfile(
    paste0(".identity.seed-recovery-", Sys.getpid(), "."),
    tmpdir = dirname(seed_path))
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(.dsvert_dp_canonical_json(value)), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  staged <- .dsvert_identity_open_recovery(temporary, noise_root)
  if (!identical(staged, active)) {
    stop("The staged identity recovery failed verification", call. = FALSE)
  }
  .dsvert_identity_require_sync(temporary, "staged identity recovery")
  if (file.exists(recovery) || .dsvert_dp_path_is_link(recovery)) {
    stop("A conflicting identity recovery appeared during commit",
         call. = FALSE)
  }
  if (!file.rename(temporary, recovery)) {
    stop("Could not atomically commit the identity recovery",
         call. = FALSE)
  }
  Sys.chmod(recovery, mode = "0600")
  recovered <- .dsvert_identity_open_recovery(recovery, noise_root)
  if (!identical(recovered, active)) {
    stop("The committed identity recovery failed verification",
         call. = FALSE)
  }
  .dsvert_identity_require_sync(
    dirname(seed_path), "identity recovery directory")
  seed_raw <- keys <- NULL
  invisible(recovery)
}

.dsvert_validate_identity_receipt <- function(receipt_path, seed) {
  if (.dsvert_dp_path_is_link(receipt_path) ||
      !file.exists(receipt_path) || !file_test("-f", receipt_path) ||
      !.dsvert_dp_private_mode(receipt_path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(receipt_path), 1)) {
    stop("Identity receipt must be a regular owner-only file without links",
         call. = FALSE)
  }
  info <- file.info(receipt_path)
  if (nrow(info) != 1L || is.na(info$size) || info$size < 1L ||
      info$size > 512L) {
    stop("Identity receipt has an invalid representation", call. = FALSE)
  }
  before <- unname(info[c("size", "mtime", "ctime")])
  encoded <- readBin(receipt_path, what = "raw", n = info$size + 1L)
  after <- unname(file.info(receipt_path)[c("size", "mtime", "ctime")])
  if (.dsvert_dp_path_is_link(receipt_path) ||
      !identical(before, after) || length(encoded) != info$size) {
    stop("Identity receipt changed while it was being read", call. = FALSE)
  }
  value <- tryCatch(
    jsonlite::fromJSON(rawToChar(encoded), simplifyVector = TRUE),
    error = function(e) NULL)
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), c("protocol", "seed_id")) &&
    identical(value$protocol, .DSVERT_IDENTITY_RECEIPT_PROTOCOL) &&
    identical(value$seed_id, .dsvert_identity_seed_id(seed))
  if (!isTRUE(valid)) {
    stop("Identity receipt does not match the active identity seed",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_identity_require_sync <- function(path, what) {
  if (!isTRUE(.dsvert_dp_noise_sync_file(path))) {
    stop("Could not durably synchronize the ", what,
         "; the peer identity remains unavailable", call. = FALSE)
  }
  invisible(NULL)
}

.dsvert_identity_validate_pre_receipt_ledgers <- function(seed) {
  ledger <- getOption(
    "dsvert.dp.ledger_path", getOption("default.dsvert.dp.ledger_path"))
  if (is.null(ledger) ||
      (is.character(ledger) && length(ledger) == 1L && !is.na(ledger) &&
       !nzchar(trimws(ledger)))) {
    return(invisible(NULL))
  }
  if (!is.character(ledger) || length(ledger) != 1L || is.na(ledger)) {
    stop("The configured DP ledger path is invalid", call. = FALSE)
  }
  ledger <- path.expand(trimws(ledger))
  if (!grepl("^/", ledger)) {
    stop("The configured DP ledger path must be absolute", call. = FALSE)
  }
  candidates <- c(
    joint_v1 = paste0(
      ledger, ".joint-mpc-single-opening-v1.sqlite"),
    joint_v2 = paste0(
      ledger, ".joint-mpc-single-opening-v2.sqlite"))
  descriptions <- c(
    joint_v1 = "legacy joint DP ledger",
    joint_v2 = "joint DP ledger")
  present <- vapply(names(candidates), function(type) {
    .dsvert_dp_history_file_present(
      candidates[[type]], descriptions[[type]])
  }, logical(1L))
  candidates <- candidates[present]
  if (!length(candidates)) return(invisible(NULL))

  seed_raw <- jsonlite::base64_dec(
    .dsvert_normalize_crypto_b64(seed, 32L, "identity seed"))
  ledger_secret <- digest::hmac(
    key = seed_raw, object = charToRaw("dsVert/dp-ledger/key/v1"),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  expected_id <- function(value) {
    digest::hmac(
      key = ledger_secret, object = serialize(value, NULL, version = 3L),
      algo = "sha256", serialize = FALSE, raw = FALSE)
  }
  validate_one <- function(path, type) {
    .dsvert_dp_history_readonly(
      path, descriptions[[type]], function(connection) {
        expected_schema <- switch(
          type, joint_v1 = "1", joint_v2 = "2", NULL)
        if (is.null(expected_schema)) return(FALSE)
        rows <- tryCatch(DBI::dbGetQuery(connection, paste(
          "SELECT key, value FROM joint_meta",
          "WHERE key IN ('schema_version', 'secret_id', 'peer_name')")),
          error = function(e) NULL)
        if (!is.data.frame(rows) || nrow(rows) != 3L ||
            anyDuplicated(rows$key) ||
            !setequal(rows$key,
                      c("schema_version", "secret_id", "peer_name"))) {
          return(FALSE)
        }
        values <- setNames(rows$value, rows$key)
        identical(values[["schema_version"]], expected_schema) &&
          is.character(values[["peer_name"]]) &&
          grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
                values[["peer_name"]]) &&
          identical(values[["secret_id"]], expected_id(list(
            "dsvert-joint-dp-ledger-secret-id-v1", values[["peer_name"]])))
      })
  }
  valid <- vapply(names(candidates), function(type) {
    validate_one(candidates[[type]], type)
  }, logical(1L))
  ledger_secret <- seed_raw <- NULL
  if (!all(valid)) {
    stop(
      "The active identity seed cannot authenticate the existing DP ledger; restore the original identity before creating its continuity receipt",
      call. = FALSE)
  }
  invisible(NULL)
}

.dsvert_ensure_identity_receipt <- function(seed_path, seed) {
  receipt_path <- .dsvert_identity_receipt_path(seed_path)
  if (file.exists(receipt_path)) {
    invisible(.dsvert_validate_identity_receipt(receipt_path, seed))
    return(invisible(receipt_path))
  }
  if (.dsvert_dp_path_is_link(receipt_path)) {
    stop("Identity receipt must not be a symbolic link", call. = FALSE)
  }

  # During an upgrade from a pre-receipt installation, authenticate every
  # existing joint DP store with the candidate identity before sealing it as
  # the deployment identity.
  .dsvert_identity_validate_pre_receipt_ledgers(seed)

  .dsvert_identity_require_sync(seed_path, "identity seed")
  .dsvert_identity_require_sync(dirname(seed_path), "identity directory")
  temporary <- tempfile(
    paste0(".identity.seed-receipt-", Sys.getpid(), "."),
    tmpdir = dirname(seed_path))
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  payload <- jsonlite::toJSON(list(
    protocol = .DSVERT_IDENTITY_RECEIPT_PROTOCOL,
    seed_id = .dsvert_identity_seed_id(seed)),
    auto_unbox = TRUE, null = "null", pretty = FALSE)
  writeBin(charToRaw(as.character(payload)), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  invisible(.dsvert_validate_identity_receipt(temporary, seed))
  .dsvert_identity_require_sync(temporary, "staged identity receipt")
  if (!file.rename(temporary, receipt_path)) {
    stop("Could not atomically commit the identity receipt", call. = FALSE)
  }
  Sys.chmod(receipt_path, mode = "0600")
  invisible(.dsvert_validate_identity_receipt(receipt_path, seed))
  .dsvert_identity_require_sync(
    dirname(seed_path), "identity receipt directory")
  invisible(receipt_path)
}

.dsvert_noise_bootstrap_state_from_options <- function() {
  ledger <- .dsvert_dp_option("ledger_path", NULL)
  if (is.null(ledger)) return(NULL)
  if (!is.character(ledger) || length(ledger) != 1L || is.na(ledger)) {
    stop("dsvert.dp.ledger_path must be one path", call. = FALSE)
  }
  ledger <- trimws(ledger)
  if (!nzchar(ledger)) return(NULL)
  ledger <- path.expand(ledger)
  if (!grepl("^/", ledger)) {
    stop("dsvert.dp.ledger_path must be absolute", call. = FALSE)
  }
  force(ledger)
  list(
    ledger_path = ledger, anchor_provider = NULL, anchor_id = NULL,
    history_provider = function() {
      .dsvert_dp_inactive_noise_history(ledger)
    })
}

.dsvert_init_identity_seed <- function(
    seed_path = .dsvert_identity_seed_path(),
    random_bytes = .dsvert_secure_random_bytes,
    .allow_test_path = FALSE, noise_root_for_recovery = NULL) {
  if (!is.character(seed_path) || length(seed_path) != 1L ||
      is.na(seed_path) || !nzchar(seed_path)) {
    stop("Identity seed path must be one non-empty string", call. = FALSE)
  }
  if (!is.function(random_bytes)) {
    stop("random_bytes must be a secure random-byte function", call. = FALSE)
  }
  configured_seed <- .dsvert_identity_seed_configuration(
    allow_test = .allow_test_path)

  seed_path <- path.expand(seed_path)
  if (!grepl("^/", seed_path)) {
    stop("Identity seed path must be absolute", call. = FALSE)
  }
  if (!isTRUE(.allow_test_path)) {
    .dsvert_dp_reject_ephemeral_or_library_path(
      seed_path, what = "identity seed")
  }
  seed_dir <- dirname(seed_path)
  if (!dir.exists(seed_dir) &&
      !dir.create(seed_dir, showWarnings = FALSE, recursive = TRUE,
                  mode = "0700")) {
    stop("Could not create the private identity directory", call. = FALSE)
  }
  if (.dsvert_dp_path_is_link(seed_dir)) {
    stop("Identity seed directory must not be a symbolic link",
         call. = FALSE)
  }
  Sys.chmod(seed_dir, mode = "0700")
  if (!.dsvert_dp_private_mode(seed_dir, directory = TRUE)) {
    stop("Identity seed directory must be owner-only", call. = FALSE)
  }
  seed_path <- file.path(normalizePath(
    seed_dir, winslash = "/", mustWork = TRUE), basename(seed_path))
  if (!isTRUE(.allow_test_path)) {
    .dsvert_dp_reject_ephemeral_or_library_path(
      seed_path, what = "identity seed")
  }

  if (.dsvert_dp_path_is_link(seed_path)) {
    stop("Identity seed must not be a symbolic link", call. = FALSE)
  }
  if (file.exists(seed_path)) {
    seed <- .dsvert_validate_identity_seed_file(seed_path)
    .dsvert_identity_seed_matches_configuration(seed)
    receipt_path <- .dsvert_identity_receipt_path(seed_path)
    if (file.exists(receipt_path) ||
        .dsvert_dp_path_is_link(receipt_path)) {
      invisible(.dsvert_ensure_identity_receipt(seed_path, seed))
      return(invisible(NULL))
    }
    # A pre-receipt installation is upgraded while holding the same
    # inter-process lock used for first creation.
  }

  lock_path <- paste0(seed_path, ".lock")
  if (.dsvert_dp_path_is_link(lock_path)) {
    stop("Identity seed lock must not be a symbolic link", call. = FALSE)
  }
  previous_umask <- Sys.umask("0077")
  on.exit(try(Sys.umask(previous_umask), silent = TRUE), add = TRUE)
  lock <- filelock::lock(lock_path, timeout = 30000)
  if (is.null(lock)) {
    stop("Identity seed creation lock is unavailable", call. = FALSE)
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  Sys.chmod(lock_path, mode = "0600")
  if (.dsvert_dp_path_is_link(lock_path) ||
      !.dsvert_dp_private_mode(lock_path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(lock_path), 1)) {
    stop("Identity seed creation lock is not private", call. = FALSE)
  }

  # Re-check after acquiring the lock in case another process just committed.
  if (file.exists(seed_path)) {
    seed <- .dsvert_validate_identity_seed_file(seed_path)
    .dsvert_identity_seed_matches_configuration(seed)
    invisible(.dsvert_ensure_identity_receipt(seed_path, seed))
    return(invisible(NULL))
  }
  recovery_paths <- .dsvert_identity_recovery_paths(seed_path)
  has_recovery <- any(vapply(recovery_paths, function(path) {
    file.exists(path) || .dsvert_dp_path_is_link(path)
  }, logical(1L)))
  if (isTRUE(has_recovery)) {
    if (!is.null(noise_root_for_recovery)) {
      invisible(.dsvert_identity_restore_recovery(
        seed_path, noise_root_for_recovery))
      seed <- .dsvert_validate_identity_seed_file(seed_path)
      .dsvert_identity_seed_matches_configuration(seed)
      invisible(.dsvert_ensure_identity_receipt(seed_path, seed))
      return(invisible(NULL))
    }
    if (is.null(configured_seed)) {
      # Neither primary root survived. Preserve the old continuity evidence
      # and mint a fresh identity below. Existing peers will reject the new
      # public key until administrators update the name-bound pin.
      invisible(.dsvert_retire_identity_continuity(seed_path))
    }
  }
  receipt_path <- .dsvert_identity_receipt_path(seed_path)
  if (file.exists(receipt_path) || .dsvert_dp_path_is_link(receipt_path)) {
    if (is.null(configured_seed)) {
      invisible(.dsvert_retire_identity_continuity(seed_path))
    } else {
      invisible(.dsvert_validate_identity_receipt(
        receipt_path, configured_seed))
    }
  }

  seed_raw <- if (!is.null(configured_seed)) {
    jsonlite::base64_dec(configured_seed)
  } else {
    tryCatch(
      random_bytes(32L),
      error = function(e) {
        stop("Secure operating-system entropy is unavailable for identity bootstrap",
             call. = FALSE)
      })
  }
  if (!is.raw(seed_raw) || length(seed_raw) != 32L) {
    stop("A secure identity seed must contain exactly 32 raw bytes",
         call. = FALSE)
  }

  tmp_path <- tempfile(
    paste0(".identity.seed-", Sys.getpid(), "."), tmpdir = seed_dir)
  on.exit(if (file.exists(tmp_path)) unlink(tmp_path, force = TRUE), add = TRUE)
  connection <- file(tmp_path, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(jsonlite::base64_enc(seed_raw)), connection)
  flush(connection)
  close(connection)
  Sys.chmod(tmp_path, mode = "0600")
  .dsvert_validate_identity_seed_file(tmp_path)
  .dsvert_identity_require_sync(tmp_path, "staged identity seed")
  if (file.exists(seed_path)) {
    seed <- .dsvert_validate_identity_seed_file(seed_path)
    .dsvert_identity_seed_matches_configuration(seed)
    invisible(.dsvert_ensure_identity_receipt(seed_path, seed))
    return(invisible(NULL))
  }
  if (!file.rename(tmp_path, seed_path)) {
    stop("Could not atomically commit the private identity seed",
         call. = FALSE)
  }
  Sys.chmod(seed_path, mode = "0600")
  seed <- .dsvert_validate_identity_seed_file(seed_path)
  .dsvert_identity_seed_matches_configuration(seed)
  .dsvert_identity_require_sync(seed_dir, "identity directory")
  invisible(.dsvert_ensure_identity_receipt(seed_path, seed))
  invisible(NULL)
}

.dsvert_is_install_or_development_load <- function(libname) {
  path <- normalizePath(libname, winslash = "/", mustWork = FALSE)
  install_environment <- c(
    Sys.getenv("R_INSTALL_PKG", unset = ""),
    Sys.getenv("R_PACKAGE_DIR", unset = ""))
  check_environment <- Sys.getenv("_R_CHECK_PACKAGE_NAME_", unset = "")
  grepl("(^|/)00LOCK([^/]*)(/|$)", path) ||
    any(nzchar(install_environment)) ||
    nzchar(check_environment) ||
    nzchar(Sys.getenv("DEVTOOLS_LOAD", unset = ""))
}

.dsvert_initialize_service_state <- function() {
  invisible(.dsvert_identity_seed_configuration(allow_test = FALSE))
  seed_path <- .dsvert_identity_seed_path()
  recovery_root <- if (!file.exists(seed_path)) {
    .dsvert_dp_noise_root_for_identity_recovery()
  } else NULL
  .dsvert_init_identity_seed(
    seed_path = seed_path,
    noise_root_for_recovery = recovery_root)
  # Bootstrap the independent sticky-noise root before admitting any DP
  # dataset policy. Identity, peer pinning and service status must remain
  # available when statistical policy options are incomplete; the complete
  # policy is therefore validated only by the first DP operation.
  active_root <- .dsvert_dp_noise_root(
    .bootstrap_state = .dsvert_noise_bootstrap_state_from_options())
  # Both active roots now exist and have passed their normal continuity
  # checks. Keep the reciprocal recovery pair complete on every real service
  # startup. If neither old root can be recovered, the replacement identity is
  # deliberately untrusted until the other server administrators verify and
  # update its name-bound pin; no analyst/relay autoaccept path exists.
  identity_seed <- .dsvert_validate_identity_seed_file(seed_path)
  invisible(.dsvert_ensure_identity_recovery(
    seed_path, identity_seed, active_root))
  if (isTRUE(active_root$external)) {
    # A surviving HSM/KMS root is not managed by the file-root transition
    # helper. Commit the identity transition only after the replacement
    # identity has a durable recovery envelope under that external root.
    invisible(.dsvert_complete_external_identity_replacement())
  }
  invisible(NULL)
}

.onLoad <- function(libname, pkgname) {
  .dsvert_dp_assert_canonical_query_runtime()
  description_path <- system.file("DESCRIPTION", package = pkgname,
                                  lib.loc = libname)
  if (!nzchar(description_path)) {
    stop("Cannot install the dsVert remote-entrypoint security gate",
         call. = FALSE)
  }
  .dsvert_guard_remote_entrypoints(
    asNamespace(pkgname), description_path)
}
