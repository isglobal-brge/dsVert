# Persistent root for deterministic, replay-stable DP randomness. The root is
# bootstrapped from the operating-system CSPRNG on the first legacy DP policy
# invocation, unless a custodian configured an HSM/KMS provider. That complete
# policy performs the full ledger/anchor bootstrap check; identity-only service
# initialization does not create the root. The root is never returned through
# DSI, written into the package/library, or stored in the DP ledger.

.DSVERT_DP_NOISE_ROOT_PROTOCOL <- "dsvert-dp-noise-root-v1"
.DSVERT_DP_STICKY_NOISE_PROTOCOL <- "dsvert-sticky-noise-v1"
.DSVERT_DP_NOISE_RECEIPT_PROTOCOL <- "dsvert-dp-noise-root-receipt-v1"
.DSVERT_DP_NOISE_RECOVERY_PROTOCOL <-
  "dsvert-dp-noise-root-identity-wrapped-recovery-v1"
.DSVERT_DP_NOISE_EPOCH_PROTOCOL <-
  "dsvert-dp-noise-root-identity-authenticated-epoch-journal-v1"
.DSVERT_DP_AUTHENTICATED_EMPTY_HISTORY_PROTOCOL <-
  "dsvert-authenticated-empty-dp-ledger-history-v1"
.DSVERT_IDENTITY_NOISE_RECOVERY_KEY_DOMAIN <-
  "dsVert/identity-seed/noise-root-recovery-key/v1|"
.DSVERT_IDENTITY_NOISE_EPOCH_KEY_DOMAIN <-
  "dsVert/identity-seed/noise-root-epoch-journal-key/v1"

.dsvert_dp_noise_key_id <- function(value, what = "DP noise key id") {
  value <- .dsvert_dp_scalar_string(value, what)
  if (!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)) {
    stop(what, " contains unsupported characters", call. = FALSE)
  }
  value
}

.dsvert_dp_noise_epoch <- function(value) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value < 1 || value > 2^53 - 1 ||
      value != floor(value)) {
    stop("dsvert.dp.noise_key_epoch must be a positive exactly representable integer",
         call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_dp_noise_provider_call <- function(provider, action, ...) {
  tryCatch(
    do.call(provider, c(list(action = action), list(...))),
    error = function(e) {
      stop("The DP noise-root provider failed during '", action,
           "'", call. = FALSE)
    })
}

.dsvert_dp_noise_provider <- function(provider) {
  capabilities <- .dsvert_dp_noise_provider_call(provider, "capabilities")
  expected <- c(
    "schema_version", "provider_id", "key_id", "external", "hmac_sha256")
  valid <- is.list(capabilities) && !is.null(names(capabilities)) &&
    !anyDuplicated(names(capabilities)) &&
    setequal(names(capabilities), expected) &&
    is.numeric(capabilities$schema_version) &&
    length(capabilities$schema_version) == 1L &&
    !is.na(capabilities$schema_version) &&
    is.finite(capabilities$schema_version) &&
    capabilities$schema_version == 1 &&
    is.character(capabilities$provider_id) &&
    length(capabilities$provider_id) == 1L &&
    !is.na(capabilities$provider_id) &&
    grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
          capabilities$provider_id) &&
    is.character(capabilities$key_id) &&
    length(capabilities$key_id) == 1L &&
    !is.na(capabilities$key_id) &&
    grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
          capabilities$key_id) &&
    identical(capabilities$external, TRUE) &&
    identical(capabilities$hmac_sha256, TRUE)
  if (!isTRUE(valid)) {
    stop("The DP noise-root provider does not attest the required external HMAC-SHA256 contract",
         call. = FALSE)
  }
  provider_id <- capabilities$provider_id
  key_id <- capabilities$key_id
  hmac <- function(message) {
    if (!is.raw(message) || !length(message)) {
      stop("The DP noise seed context is invalid", call. = FALSE)
    }
    result <- .dsvert_dp_noise_provider_call(
      provider, "hmac_sha256",
      message_base64 = jsonlite::base64_enc(message))
    expected_result <- c(
      "schema_version", "provider_id", "key_id", "digest_sha256")
    valid_result <- is.list(result) && !is.null(names(result)) &&
      !anyDuplicated(names(result)) &&
      setequal(names(result), expected_result) &&
      is.numeric(result$schema_version) &&
      length(result$schema_version) == 1L &&
      !is.na(result$schema_version) && is.finite(result$schema_version) &&
      result$schema_version == 1 &&
      identical(result$provider_id, provider_id) &&
      identical(result$key_id, key_id) &&
      is.character(result$digest_sha256) &&
      length(result$digest_sha256) == 1L &&
      !is.na(result$digest_sha256) &&
      grepl("^[0-9a-f]{64}$", result$digest_sha256)
    if (!isTRUE(valid_result)) {
      stop("The DP noise-root provider returned an invalid HMAC response",
           call. = FALSE)
    }
    result$digest_sha256
  }
  list(
    protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
    provider_id = provider_id,
    key_id = key_id,
    external = TRUE,
    storage = "hsm_kms_provider",
    hmac = hmac)
}

# Open only an already-present root for the early identity-recovery phase.
# In particular, this helper never generates or restores a file-backed root:
# doing so would create a circular and unauthenticated continuity decision
# while identity.seed is absent. An external provider is usable because its
# HMAC operation keeps the original HSM/KMS root non-extractable.
.dsvert_dp_noise_root_for_identity_recovery <- function() {
  provider <- .dsvert_dp_option("noise_key_provider", NULL)
  path <- .dsvert_dp_option("noise_key_path", NULL)
  if (!is.null(provider) && !is.function(provider)) {
    stop("dsvert.dp.noise_key_provider must be a provider function",
         call. = FALSE)
  }
  if (!is.null(provider) && !is.null(path)) {
    stop("Configure exactly one of dsvert.dp.noise_key_provider or dsvert.dp.noise_key_path",
         call. = FALSE)
  }
  if (is.function(provider)) {
    root <- .dsvert_dp_noise_provider(provider)
    root$epoch <- .dsvert_dp_noise_epoch(
      .dsvert_dp_option("noise_key_epoch", 1))
    return(root)
  }
  if (is.null(path)) path <- .dsvert_dp_noise_default_path()
  path <- .dsvert_dp_scalar_string(path, "dsvert.dp.noise_key_path")
  path <- path.expand(path)
  if (!identical(.Platform$OS.type, "unix")) {
    stop("File-backed DP noise roots require POSIX owner-only permissions",
         call. = FALSE)
  }
  if (!grepl("^/", path)) {
    stop("The DP noise-root key path must be absolute", call. = FALSE)
  }
  .dsvert_dp_reject_ephemeral_or_library_path(path)
  if (.dsvert_dp_path_is_link(path)) {
    stop("The DP noise-root key must not be a symbolic link", call. = FALSE)
  }
  if (!file.exists(path)) return(NULL)
  parent <- dirname(path)
  if (!dir.exists(parent) || .dsvert_dp_path_is_link(parent) ||
      !.dsvert_dp_private_mode(parent, directory = TRUE)) {
    stop("The DP noise-root key directory must be a regular owner-only directory",
         call. = FALSE)
  }
  canonical_path <- file.path(normalizePath(
    parent, winslash = "/", mustWork = TRUE), basename(path))
  .dsvert_dp_reject_ephemeral_or_library_path(canonical_path)
  key <- .dsvert_dp_noise_validate_file(canonical_path)
  key_id <- paste0(
    "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
  key <- NULL
  list(
    protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
    provider_id = "owner_only_file_v2", key_id = key_id,
    external = FALSE, storage = "owner_only_file",
    epoch = .dsvert_dp_noise_epoch(
      .dsvert_dp_option("noise_key_epoch", 1)),
    hmac = function(message) {
      active <- .dsvert_dp_noise_validate_file(canonical_path)
      active_key_id <- paste0(
        "file_", digest::digest(
          active, algo = "sha256", serialize = FALSE))
      if (!identical(active_key_id, key_id)) {
        stop("The DP noise root changed during identity recovery",
             call. = FALSE)
      }
      digest::hmac(
        key = active, object = message, algo = "sha256",
        serialize = FALSE, raw = FALSE)
    })
}

.dsvert_dp_identity_recovery_keys <- function(noise_root) {
  valid <- is.list(noise_root) &&
    identical(noise_root$protocol, .DSVERT_DP_NOISE_ROOT_PROTOCOL) &&
    is.character(noise_root$provider_id) &&
    length(noise_root$provider_id) == 1L &&
    !is.na(noise_root$provider_id) &&
    grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
          noise_root$provider_id) &&
    is.character(noise_root$key_id) && length(noise_root$key_id) == 1L &&
    !is.na(noise_root$key_id) &&
    grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", noise_root$key_id) &&
    is.function(noise_root$hmac)
  if (!isTRUE(valid)) {
    stop("The identity recovery requires an authenticated DP noise root",
         call. = FALSE)
  }
  derive <- function(label) {
    value <- noise_root$hmac(charToRaw(paste0(
      .DSVERT_IDENTITY_NOISE_RECOVERY_KEY_DOMAIN, label)))
    if (!is.character(value) || length(value) != 1L || is.na(value) ||
        !grepl("^[0-9a-f]{64}$", value)) {
      stop("The DP noise root returned an invalid identity-recovery derivation",
           call. = FALSE)
    }
    positions <- seq.int(1L, 63L, by = 2L)
    as.raw(strtoi(substring(value, positions, positions + 1L), base = 16L))
  }
  list(
    noise_root_provider_id = noise_root$provider_id,
    noise_root_key_id = noise_root$key_id,
    encryption = derive("aes-256-ctr"),
    authentication = derive("hmac-sha256"))
}

.dsvert_dp_noise_default_path <- function() {
  state_root <- .dsvert_state_root()
  candidate <- file.path(state_root, "privacy", "noise_root")
  temporary <- normalizePath(tempdir(), winslash = "/", mustWork = TRUE)
  candidate_parent <- normalizePath(
    dirname(dirname(candidate)), winslash = "/", mustWork = FALSE)
  if (identical(candidate_parent, temporary) ||
      startsWith(candidate_parent, paste0(temporary, "/"))) {
    stop("The default DP noise root must use persistent service state, not a temporary directory",
         call. = FALSE)
  }
  candidate
}

.dsvert_dp_path_is_link <- function(path) {
  link <- Sys.readlink(path)
  length(link) != 1L || (!is.na(link) && nzchar(link))
}

.dsvert_dp_path_below <- function(path, root) {
  identical(path, root) || startsWith(path, paste0(root, "/"))
}

.dsvert_dp_reject_ephemeral_or_library_path <- function(
    path, what = "DP noise root") {
  expanded <- path.expand(path)
  parent <- normalizePath(dirname(expanded), winslash = "/",
                          mustWork = FALSE)
  forbidden <- c("/tmp", "/var/tmp", "/dev/shm", tempdir())
  forbidden <- unique(vapply(forbidden, function(candidate) {
    if (file.exists(candidate)) {
      normalizePath(candidate, winslash = "/", mustWork = TRUE)
    } else {
      candidate
    }
  }, character(1L)))
  library_roots <- c(.libPaths(), system.file(package = "dsVert"))
  library_roots <- library_roots[nzchar(library_roots)]
  library_roots <- unique(vapply(library_roots, normalizePath,
    character(1L), winslash = "/", mustWork = FALSE))
  if (any(vapply(c(forbidden, library_roots), function(root) {
    .dsvert_dp_path_below(parent, root)
  }, logical(1L)))) {
    stop("The ", what,
         " must be outside temporary and installed-library trees",
         call. = FALSE)
  }
  invisible(NULL)
}

.dsvert_dp_noise_link_count <- function(path) {
  value <- tryCatch(
    fs::file_info(path, follow = FALSE)$hard_links[[1L]],
    error = function(e) NA_real_)
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value < 1 || value != floor(value)) {
    stop("Cannot verify the DP noise-root hard-link count", call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_dp_noise_private_directory <- function(path,
                                                .allow_test_path = FALSE) {
  if (!identical(.Platform$OS.type, "unix")) {
    stop("File-backed DP noise roots require POSIX owner-only permissions",
         call. = FALSE)
  }
  expanded <- path.expand(path)
  if (!grepl("^/", expanded)) {
    stop("The DP noise-root key path must be absolute", call. = FALSE)
  }
  if (!isTRUE(.allow_test_path)) {
    .dsvert_dp_reject_ephemeral_or_library_path(expanded)
  }
  parent <- dirname(expanded)
  if (!dir.exists(parent) &&
      !dir.create(parent, recursive = TRUE, showWarnings = FALSE,
                  mode = "0700")) {
    stop("Could not create the private DP noise-root directory",
         call. = FALSE)
  }
  if (.dsvert_dp_path_is_link(parent)) {
    stop("The DP noise-root directory must not be a symbolic link",
         call. = FALSE)
  }
  Sys.chmod(parent, mode = "0700")
  if (!.dsvert_dp_private_mode(parent, directory = TRUE)) {
    stop("The DP noise-root key directory must be owned by the service account with mode 0700",
         call. = FALSE)
  }
  canonical_path <- file.path(
    normalizePath(parent, winslash = "/", mustWork = TRUE),
    basename(expanded))
  # Re-apply the location policy after resolving every existing symlink
  # component. Otherwise an apparently persistent path could traverse an
  # ancestor symlink into a temporary or installed-library tree.
  if (!isTRUE(.allow_test_path)) {
    .dsvert_dp_reject_ephemeral_or_library_path(canonical_path)
  }
  canonical_path
}

.dsvert_dp_noise_validate_file <- function(path) {
  if (.dsvert_dp_path_is_link(path)) {
    stop("The DP noise-root key must not be a symbolic link", call. = FALSE)
  }
  if (!file.exists(path) || !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE)) {
    stop("The DP noise-root key must be a regular owner-only file with mode 0600",
         call. = FALSE)
  }
  if (!identical(.dsvert_dp_noise_link_count(path), 1)) {
    stop("The DP noise-root key must not have hard links", call. = FALSE)
  }
  info <- file.info(path)
  if (nrow(info) != 1L || is.na(info$size) ||
      !info$size %in% c(64, 65, 66)) {
    stop("The DP noise-root key file has an invalid representation",
         call. = FALSE)
  }
  before <- unname(info[c("size", "mtime", "ctime")])
  encoded_raw <- readBin(path, what = "raw", n = info$size + 1L)
  after_info <- file.info(path)
  after <- unname(after_info[c("size", "mtime", "ctime")])
  if (.dsvert_dp_path_is_link(path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1) ||
      !identical(before, after) || length(encoded_raw) != info$size) {
    stop("The DP noise-root key changed while it was being read",
         call. = FALSE)
  }
  encoded <- rawToChar(encoded_raw)
  encoded <- if (info$size == 64) {
    encoded
  } else if (info$size == 65 && endsWith(encoded, "\n")) {
    substr(encoded, 1L, 64L)
  } else if (info$size == 66 && endsWith(encoded, "\r\n")) {
    substr(encoded, 1L, 64L)
  } else {
    ""
  }
  if (!grepl("^[0-9a-f]{64}$", encoded)) {
    stop("The DP noise-root key must contain exactly 32 random bytes encoded as lowercase hexadecimal",
         call. = FALSE)
  }
  pairs <- substring(encoded, seq.int(1L, 63L, 2L), seq.int(2L, 64L, 2L))
  as.raw(strtoi(pairs, base = 16L))
}

.dsvert_dp_noise_receipt_path <- function(path) paste0(path, ".receipt")

.dsvert_dp_noise_recovery_path <- function(path) paste0(path, ".recovery")

.dsvert_dp_noise_recovery_identity <- function() {
  tryCatch(.get_identity_seed(), error = function(e) NULL)
}

.dsvert_dp_noise_recovery_keys <- function(identity_seed) {
  identity_seed <- .dsvert_normalize_crypto_b64(
    identity_seed, 32L, "identity recovery seed")
  identity_raw <- jsonlite::base64_dec(identity_seed)
  derive <- function(label) {
    digest::hmac(
      key = identity_raw,
      object = charToRaw(paste0(
        "dsVert/dp-noise-root/recovery-key/v1|", label)),
      algo = "sha256", serialize = FALSE, raw = TRUE)
  }
  list(
    identity_seed_id = .dsvert_identity_seed_id(identity_seed),
    encryption = derive("aes-256-ctr"),
    authentication = derive("hmac-sha256"))
}

.dsvert_dp_noise_recovery_b64_encode <- function(value) {
  if (!is.raw(value)) stop("Invalid DP recovery bytes", call. = FALSE)
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

.dsvert_dp_noise_recovery_b64_decode <- function(value, bytes, what) {
  valid <- is.character(value) && length(value) == 1L && !is.na(value) &&
    grepl("^[A-Za-z0-9_-]+$", value) && nchar(value) %% 4L != 1L
  decoded <- if (isTRUE(valid)) tryCatch(
    jsonlite::base64_dec(.base64url_to_base64(value)),
    error = function(e) NULL) else NULL
  if (is.null(decoded) || !is.raw(decoded) || length(decoded) != bytes ||
      !identical(.dsvert_dp_noise_recovery_b64_encode(decoded), value)) {
    stop("The DP noise-root recovery ", what, " is invalid", call. = FALSE)
  }
  decoded
}

.dsvert_dp_noise_recovery_message <- function(value) {
  charToRaw(paste0(
    "dsVert/dp-noise-root/recovery-envelope/v1|",
    .dsvert_dp_canonical_json(value)))
}

.dsvert_dp_noise_recovery_hex_equal <- function(left, right) {
  valid <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^[0-9a-f]{64}$", value)
  }
  if (!valid(left) || !valid(right)) return(FALSE)
  positions <- seq.int(1L, 63L, by = 2L)
  left_raw <- strtoi(substring(left, positions, positions + 1L), base = 16L)
  right_raw <- strtoi(
    substring(right, positions, positions + 1L), base = 16L)
  identical(sum(bitwXor(left_raw, right_raw)), 0L)
}

.dsvert_dp_noise_epoch_path <- function(path) paste0(path, ".epochs")

.dsvert_dp_noise_next_key_path <- function(path) paste0(path, ".next")

.dsvert_dp_noise_apply_identity_replacement <- function(canonical_path) {
  identity_archive <- file.path(
    dirname(.dsvert_identity_seed_path()),
    ".retired-identity-continuity")
  if (!dir.exists(identity_archive) ||
      .dsvert_dp_path_is_link(identity_archive)) {
    return(list(applied = FALSE, root_missing = !file.exists(canonical_path)))
  }
  markers <- Sys.glob(file.path(
    identity_archive, "*", "noise-root-transition.pending"))
  if (!length(markers)) {
    return(list(applied = FALSE, root_missing = !file.exists(canonical_path)))
  }
  if (length(markers) != 1L) {
    stop("Multiple pending identity-replacement transitions exist",
         call. = FALSE)
  }
  invalid_marker <- vapply(markers, function(path) {
    .dsvert_dp_path_is_link(path) || !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)
  }, logical(1L))
  if (any(invalid_marker)) {
    stop("Identity replacement marker is not a regular owner-only file",
         call. = FALSE)
  }

  root_missing <- !file.exists(canonical_path)
  artifacts <- c(
    canonical_path,
    .dsvert_dp_noise_receipt_path(canonical_path),
    .dsvert_dp_noise_recovery_path(canonical_path),
    .dsvert_dp_noise_epoch_path(canonical_path),
    .dsvert_dp_noise_next_key_path(canonical_path),
    Sys.glob(paste0(
      .dsvert_dp_noise_receipt_path(canonical_path), ".epoch-*")))
  artifacts <- unique(artifacts)
  present <- artifacts[vapply(artifacts, function(path) {
    file.exists(path) || .dsvert_dp_path_is_link(path)
  }, logical(1L))]
  invalid <- vapply(present, function(path) {
    .dsvert_dp_path_is_link(path) || !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)
  }, logical(1L))
  if (any(invalid)) {
    stop("Retired DP continuity evidence is not a regular owner-only file",
         call. = FALSE)
  }

  if (length(present)) {
    archive_root <- file.path(
      dirname(canonical_path), ".retired-noise-continuity")
    if (.dsvert_dp_path_is_link(archive_root)) {
      stop("Retired DP continuity directory must not be a symbolic link",
           call. = FALSE)
    }
    if (!dir.exists(archive_root) &&
        !dir.create(archive_root, mode = "0700", showWarnings = FALSE)) {
      stop("Could not create the retired DP continuity directory",
           call. = FALSE)
    }
    Sys.chmod(archive_root, mode = "0700")
    if (!.dsvert_dp_private_mode(archive_root, directory = TRUE)) {
      stop("Retired DP continuity directory must be owner-only",
           call. = FALSE)
    }
    archive <- file.path(
      archive_root, basename(dirname(markers[[1L]])))
    if (!dir.exists(archive) &&
        !dir.create(archive, mode = "0700", showWarnings = FALSE)) {
      stop("Could not create a retired DP continuity epoch", call. = FALSE)
    }
    Sys.chmod(archive, mode = "0700")
    if (!.dsvert_dp_private_mode(archive, directory = TRUE)) {
      stop("Retired DP continuity epoch must be owner-only",
           call. = FALSE)
    }
    for (path in present) {
      target <- file.path(archive, basename(path))
      if (file.exists(target) || .dsvert_dp_path_is_link(target)) {
        stop("Retired DP continuity evidence conflicts with its archive",
             call. = FALSE)
      }
      if (!file.rename(path, target)) {
        stop("Could not preserve retired DP continuity evidence",
             call. = FALSE)
      }
      .dsvert_dp_noise_require_sync(target, "retired DP continuity evidence")
    }
    .dsvert_dp_noise_require_sync(archive, "retired DP continuity epoch")
    .dsvert_dp_noise_require_sync(
      archive_root, "retired DP continuity directory")
  }

  for (marker in markers) {
    completed <- sub("[.]pending$", ".complete", marker)
    if (!file.rename(marker, completed)) {
      stop("Could not commit the identity replacement transition",
           call. = FALSE)
    }
    Sys.chmod(completed, mode = "0600")
    .dsvert_dp_noise_require_sync(
      dirname(completed), "identity replacement transition")
  }
  .dsvert_dp_noise_require_sync(
    dirname(canonical_path), "DP noise-root directory")
  list(applied = TRUE, root_missing = root_missing)
}

.dsvert_dp_noise_epoch_key <- function(identity_seed) {
  identity_seed <- .dsvert_normalize_crypto_b64(
    identity_seed, 32L, "identity epoch-journal seed")
  digest::hmac(
    key = jsonlite::base64_dec(identity_seed),
    object = charToRaw(.DSVERT_IDENTITY_NOISE_EPOCH_KEY_DOMAIN),
    algo = "sha256", serialize = FALSE, raw = TRUE)
}

.dsvert_dp_noise_epoch_audit <- function(value = NULL) {
  empty <- list(
    source = "none", release_count = "0", cumulative_epsilon = "0",
    cumulative_delta = "0", chain_head = "GENESIS")
  if (is.null(value)) return(empty)
  required <- names(empty)
  valid_decimal <- function(x, nonnegative = TRUE) {
    is.character(x) && length(x) == 1L && !is.na(x) &&
      grepl("^(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?$", x) &&
      is.finite(suppressWarnings(as.numeric(x))) &&
      (!nonnegative || as.numeric(x) >= 0)
  }
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), required) &&
    is.character(value$source) && length(value$source) == 1L &&
    !is.na(value$source) &&
    grepl("^[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}$", value$source) &&
    is.character(value$release_count) &&
    length(value$release_count) == 1L && !is.na(value$release_count) &&
    grepl("^(0|[1-9][0-9]*)$", value$release_count) &&
    is.finite(suppressWarnings(as.numeric(value$release_count))) &&
    as.numeric(value$release_count) <= 2^53 - 1 &&
    valid_decimal(value$cumulative_epsilon) &&
    valid_decimal(value$cumulative_delta) &&
    is.character(value$chain_head) && length(value$chain_head) == 1L &&
    !is.na(value$chain_head) &&
    (identical(value$chain_head, "GENESIS") ||
       grepl("^[0-9a-f]{64}$", value$chain_head))
  if (!isTRUE(valid)) {
    stop("The authenticated DP noise-root composition audit is invalid",
         call. = FALSE)
  }
  value[required]
}

.dsvert_dp_noise_epoch_record_message <- function(value) {
  charToRaw(paste0(
    "dsVert/dp-noise-root/epoch-journal-record/v1|",
    .dsvert_dp_canonical_json(value)))
}

.dsvert_dp_noise_epoch_record <- function(
    sequence, phase, epoch, key_id, previous_key_id, reason, audit,
    previous_record_mac, identity_seed) {
  sequence <- .dsvert_dp_noise_epoch(sequence)
  epoch <- .dsvert_dp_noise_epoch(epoch)
  if (!phase %in% c("pending", "active")) {
    stop("The DP noise-root epoch phase is invalid", call. = FALSE)
  }
  key_id <- .dsvert_dp_noise_key_id(key_id)
  previous_key_id <- if (is.null(previous_key_id)) NULL else
    .dsvert_dp_noise_key_id(previous_key_id, "previous DP noise key id")
  reason <- .dsvert_dp_noise_key_id(reason, "DP noise-root epoch reason")
  if (!is.character(previous_record_mac) ||
      length(previous_record_mac) != 1L || is.na(previous_record_mac) ||
      !(identical(previous_record_mac, "GENESIS") ||
        grepl("^[0-9a-f]{64}$", previous_record_mac))) {
    stop("The DP noise-root epoch journal chain is invalid", call. = FALSE)
  }
  keys <- .dsvert_dp_noise_recovery_keys(identity_seed)
  unsigned <- list(
    protocol = .DSVERT_DP_NOISE_EPOCH_PROTOCOL,
    identity_seed_id = keys$identity_seed_id,
    record_sequence = format(sequence, scientific = FALSE, trim = TRUE),
    phase = phase,
    privacy_epoch = format(epoch, scientific = FALSE, trim = TRUE),
    key_id = key_id,
    previous_key_id = previous_key_id,
    provider_id = "owner_only_file_v2",
    reason = reason,
    composition_audit = .dsvert_dp_noise_epoch_audit(audit),
    previous_record_mac = previous_record_mac)
  c(unsigned, list(record_mac = digest::hmac(
    key = .dsvert_dp_noise_epoch_key(identity_seed),
    object = .dsvert_dp_noise_epoch_record_message(unsigned),
    algo = "sha256", serialize = FALSE)))
}

.dsvert_dp_noise_read_epoch_journal <- function(path, identity_seed) {
  if (.dsvert_dp_path_is_link(path) || !file.exists(path) ||
      !utils::file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)) {
    stop("The DP noise-root epoch journal must be a regular owner-only file without links",
         call. = FALSE)
  }
  info <- file.info(path)
  if (nrow(info) != 1L || is.na(info$size) || info$size < 2L) {
    stop("The DP noise-root epoch journal is empty or invalid",
         call. = FALSE)
  }
  final_byte <- local({
    tail_connection <- file(path, open = "rb")
    on.exit(close(tail_connection), add = TRUE)
    seek(tail_connection, where = info$size - 1L, origin = "start")
    readBin(tail_connection, what = "raw", n = 1L)
  })
  if (!identical(final_byte, charToRaw("\n"))) {
    stop("The DP noise-root epoch journal has an incomplete final record",
         call. = FALSE)
  }
  identity_keys <- .dsvert_dp_noise_recovery_keys(identity_seed)
  journal_key <- .dsvert_dp_noise_epoch_key(identity_seed)
  connection <- file(path, open = "rb")
  on.exit(close(connection), add = TRUE)
  previous_mac <- "GENESIS"
  record_sequence <- 0
  active <- NULL
  pending <- NULL
  active_records <- list()
  repeat {
    line <- readLines(connection, n = 1L, warn = FALSE, encoding = "UTF-8")
    if (!length(line)) break
    if (!nzchar(line) || nchar(line, type = "bytes") > 16384L) {
      stop("The DP noise-root epoch journal contains an invalid record",
           call. = FALSE)
    }
    value <- tryCatch(
      jsonlite::fromJSON(line, simplifyVector = FALSE),
      error = function(e) NULL)
    required <- c(
      "protocol", "identity_seed_id", "record_sequence", "phase",
      "privacy_epoch", "key_id", "previous_key_id", "provider_id",
      "reason", "composition_audit", "previous_record_mac", "record_mac")
    valid <- is.list(value) && !is.null(names(value)) &&
      !anyNA(names(value)) && !anyDuplicated(names(value)) &&
      setequal(names(value), required) &&
      identical(value$protocol, .DSVERT_DP_NOISE_EPOCH_PROTOCOL) &&
      is.character(value$identity_seed_id) &&
      length(value$identity_seed_id) == 1L &&
      grepl("^seed_[0-9a-f]{64}$", value$identity_seed_id) &&
      is.character(value$record_sequence) &&
      length(value$record_sequence) == 1L &&
      grepl("^[1-9][0-9]*$", value$record_sequence) &&
      is.character(value$privacy_epoch) &&
      length(value$privacy_epoch) == 1L &&
      grepl("^[1-9][0-9]*$", value$privacy_epoch) &&
      value$phase %in% c("pending", "active") &&
      identical(value$provider_id, "owner_only_file_v2") &&
      identical(value$previous_record_mac, previous_mac) &&
      is.character(value$record_mac) && length(value$record_mac) == 1L &&
      grepl("^[0-9a-f]{64}$", value$record_mac)
    if (!isTRUE(valid)) {
      stop("The DP noise-root epoch journal contract is invalid",
           call. = FALSE)
    }
    if (!identical(value$identity_seed_id,
                   identity_keys$identity_seed_id)) {
      stop("The DP noise-root epoch journal cannot be authenticated by the persistent identity",
           call. = FALSE)
    }
    sequence_value <- suppressWarnings(as.numeric(value$record_sequence))
    epoch_value <- suppressWarnings(as.numeric(value$privacy_epoch))
    if (!is.finite(sequence_value) || sequence_value > 2^53 - 1 ||
        sequence_value != record_sequence + 1 ||
        !is.finite(epoch_value) || epoch_value > 2^53 - 1) {
      stop("The DP noise-root epoch journal sequence is invalid",
           call. = FALSE)
    }
    value$key_id <- .dsvert_dp_noise_key_id(value$key_id)
    if (!is.null(value$previous_key_id)) {
      value$previous_key_id <- .dsvert_dp_noise_key_id(
        value$previous_key_id, "previous DP noise key id")
    }
    value$reason <- .dsvert_dp_noise_key_id(
      value$reason, "DP noise-root epoch reason")
    value$composition_audit <- .dsvert_dp_noise_epoch_audit(
      value$composition_audit)
    unsigned <- value[setdiff(names(value), "record_mac")]
    expected_mac <- digest::hmac(
      key = journal_key,
      object = .dsvert_dp_noise_epoch_record_message(unsigned),
      algo = "sha256", serialize = FALSE)
    if (!.dsvert_dp_noise_recovery_hex_equal(
          value$record_mac, expected_mac)) {
      stop("The DP noise-root epoch journal cannot be authenticated by the persistent identity",
           call. = FALSE)
    }
    if (identical(value$phase, "pending")) {
      if (is.null(active) || !is.null(pending) ||
          epoch_value != active$privacy_epoch + 1 ||
          !identical(value$previous_key_id, active$key_id) ||
          identical(value$key_id, active$key_id)) {
        stop("The DP noise-root pending epoch transition is invalid",
             call. = FALSE)
      }
      pending <- list(
        privacy_epoch = epoch_value, key_id = value$key_id,
        previous_key_id = value$previous_key_id,
        composition_audit = value$composition_audit,
        reason = value$reason, record_mac = value$record_mac)
    } else if (is.null(active)) {
      if (!is.null(value$previous_key_id) ||
          !is.null(pending)) {
        stop("The first DP noise-root epoch journal record is invalid",
             call. = FALSE)
      }
      active <- list(
        privacy_epoch = epoch_value, key_id = value$key_id,
        previous_key_id = NULL,
        composition_audit = value$composition_audit,
        reason = value$reason, record_mac = value$record_mac)
      active_records[[length(active_records) + 1L]] <- active
    } else {
      if (is.null(pending) || epoch_value != pending$privacy_epoch ||
          !identical(value$key_id, pending$key_id) ||
          !identical(value$previous_key_id, pending$previous_key_id)) {
        stop("The completed DP noise-root epoch transition is invalid",
             call. = FALSE)
      }
      active <- list(
        privacy_epoch = epoch_value, key_id = value$key_id,
        previous_key_id = value$previous_key_id,
        composition_audit = value$composition_audit,
        reason = value$reason, record_mac = value$record_mac)
      active_records[[length(active_records) + 1L]] <- active
      pending <- NULL
    }
    previous_mac <- value$record_mac
    record_sequence <- sequence_value
  }
  if (is.null(active)) {
    stop("The DP noise-root epoch journal has no active epoch",
         call. = FALSE)
  }
  list(
    record_count = record_sequence, chain_head = previous_mac,
    baseline_epoch = active_records[[1L]]$privacy_epoch,
    active = active, pending = pending, active_records = active_records)
}

.dsvert_dp_noise_append_epoch_record <- function(
    path, phase, epoch, key_id, previous_key_id, reason, audit,
    identity_seed) {
  journal_path <- .dsvert_dp_noise_epoch_path(path)
  state <- if (file.exists(journal_path)) {
    .dsvert_dp_noise_read_epoch_journal(journal_path, identity_seed)
  } else {
    list(record_count = 0, chain_head = "GENESIS")
  }
  record <- .dsvert_dp_noise_epoch_record(
    sequence = state$record_count + 1, phase = phase, epoch = epoch,
    key_id = key_id, previous_key_id = previous_key_id,
    reason = reason, audit = audit,
    previous_record_mac = state$chain_head,
    identity_seed = identity_seed)
  temporary <- tempfile(
    pattern = paste0(".noise_root_epochs.", Sys.getpid(), "."),
    tmpdir = dirname(path))
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  if (file.exists(journal_path) &&
      !file.copy(journal_path, temporary, overwrite = FALSE,
                 copy.mode = FALSE, copy.date = FALSE)) {
    stop("Could not stage the DP noise-root epoch journal",
         call. = FALSE)
  }
  connection <- file(temporary, open = if (file.exists(temporary)) "ab" else "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(paste0(.dsvert_dp_canonical_json(record), "\n")),
           connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  staged <- .dsvert_dp_noise_read_epoch_journal(temporary, identity_seed)
  if (!identical(staged$chain_head, record$record_mac)) {
    stop("The staged DP noise-root epoch journal failed verification",
         call. = FALSE)
  }
  .dsvert_dp_noise_require_sync(
    temporary, "staged DP noise-root epoch journal")
  if (!file.rename(temporary, journal_path)) {
    stop("Could not atomically commit the DP noise-root epoch journal",
         call. = FALSE)
  }
  Sys.chmod(journal_path, mode = "0600")
  .dsvert_dp_noise_require_sync(
    dirname(path), "DP noise-root epoch-journal directory")
  .dsvert_dp_noise_read_epoch_journal(journal_path, identity_seed)
}

.dsvert_dp_noise_read_recovery <- function(path) {
  if (.dsvert_dp_path_is_link(path) || !file.exists(path) ||
      !utils::file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)) {
    stop("The DP noise-root recovery must be a regular owner-only file without links",
         call. = FALSE)
  }
  info <- file.info(path)
  if (nrow(info) != 1L || is.na(info$size) || info$size < 1L ||
      info$size > 2048L) {
    stop("The DP noise-root recovery has an invalid representation",
         call. = FALSE)
  }
  before <- unname(info[c("size", "mtime", "ctime")])
  encoded <- readBin(path, what = "raw", n = info$size + 1L)
  after <- unname(file.info(path)[c("size", "mtime", "ctime")])
  if (.dsvert_dp_path_is_link(path) || !identical(before, after) ||
      length(encoded) != info$size) {
    stop("The DP noise-root recovery changed while it was being read",
         call. = FALSE)
  }
  value <- tryCatch(
    jsonlite::fromJSON(rawToChar(encoded), simplifyVector = TRUE),
    error = function(e) NULL)
  required <- c(
    "protocol", "identity_seed_id", "noise_key_id", "cipher",
    "iv_base64url", "ciphertext_base64url", "mac_sha256")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), required) ||
      !identical(value$protocol, .DSVERT_DP_NOISE_RECOVERY_PROTOCOL) ||
      !identical(value$cipher, "aes-256-ctr+hmac-sha256") ||
      !is.character(value$identity_seed_id) ||
      length(value$identity_seed_id) != 1L ||
      !grepl("^seed_[0-9a-f]{64}$", value$identity_seed_id) ||
      !is.character(value$noise_key_id) ||
      length(value$noise_key_id) != 1L ||
      !grepl("^file_[0-9a-f]{64}$", value$noise_key_id) ||
      !is.character(value$mac_sha256) ||
      length(value$mac_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", value$mac_sha256)) {
    stop("The DP noise-root recovery has an invalid contract",
         call. = FALSE)
  }
  value
}

.dsvert_dp_noise_open_recovery <- function(path, identity_seed) {
  value <- .dsvert_dp_noise_read_recovery(path)
  keys <- .dsvert_dp_noise_recovery_keys(identity_seed)
  unsigned <- value[setdiff(names(value), "mac_sha256")]
  expected_mac <- digest::hmac(
    key = keys$authentication,
    object = .dsvert_dp_noise_recovery_message(unsigned),
    algo = "sha256", serialize = FALSE)
  if (!identical(value$identity_seed_id, keys$identity_seed_id) ||
      !.dsvert_dp_noise_recovery_hex_equal(
        value$mac_sha256, expected_mac)) {
    stop("The DP noise-root recovery cannot be authenticated by the persistent identity",
         call. = FALSE)
  }
  iv <- .dsvert_dp_noise_recovery_b64_decode(
    value$iv_base64url, 16L, "initialization vector")
  ciphertext <- .dsvert_dp_noise_recovery_b64_decode(
    value$ciphertext_base64url, 32L, "ciphertext")
  key <- tryCatch(
    openssl::aes_ctr_decrypt(ciphertext, keys$encryption, iv = iv),
    error = function(e) NULL)
  if (is.null(key) || !is.raw(key) || length(key) != 32L ||
      !identical(
        paste0("file_", digest::digest(
          key, algo = "sha256", serialize = FALSE)),
        value$noise_key_id)) {
    stop("The DP noise-root recovery plaintext is invalid", call. = FALSE)
  }
  key
}

.dsvert_dp_noise_ensure_recovery <- function(
    canonical_path, key, identity_seed = NULL,
    random_bytes = .dsvert_secure_random_bytes) {
  if (is.null(identity_seed)) {
    identity_seed <- .dsvert_dp_noise_recovery_identity()
  }
  # Direct unit helpers and installation-time namespace loads may run before a
  # service identity exists. Real service startup creates identity.seed first.
  if (is.null(identity_seed)) return(invisible(NULL))
  recovery <- .dsvert_dp_noise_recovery_path(canonical_path)
  if (file.exists(recovery)) {
    recovered <- .dsvert_dp_noise_open_recovery(recovery, identity_seed)
    if (!identical(recovered, key)) {
      stop("The DP noise-root recovery does not match the active root",
           call. = FALSE)
    }
    return(invisible(recovery))
  }
  if (.dsvert_dp_path_is_link(recovery)) {
    stop("The DP noise-root recovery must not be a symbolic link",
         call. = FALSE)
  }
  if (!is.function(random_bytes)) {
    stop("random_bytes must be a secure random-byte function", call. = FALSE)
  }
  keys <- .dsvert_dp_noise_recovery_keys(identity_seed)
  iv <- random_bytes(16L)
  if (!is.raw(iv) || length(iv) != 16L) {
    stop("Secure operating-system entropy returned an invalid DP recovery IV",
         call. = FALSE)
  }
  ciphertext <- openssl::aes_ctr_encrypt(key, keys$encryption, iv = iv)
  attributes(ciphertext) <- NULL
  unsigned <- list(
    protocol = .DSVERT_DP_NOISE_RECOVERY_PROTOCOL,
    identity_seed_id = keys$identity_seed_id,
    noise_key_id = paste0(
      "file_", digest::digest(key, algo = "sha256", serialize = FALSE)),
    cipher = "aes-256-ctr+hmac-sha256",
    iv_base64url = .dsvert_dp_noise_recovery_b64_encode(iv),
    ciphertext_base64url =
      .dsvert_dp_noise_recovery_b64_encode(ciphertext))
  value <- c(unsigned, list(mac_sha256 = digest::hmac(
    key = keys$authentication,
    object = .dsvert_dp_noise_recovery_message(unsigned),
    algo = "sha256", serialize = FALSE)))
  temporary <- tempfile(
    pattern = paste0(".noise_root_recovery.", Sys.getpid(), "."),
    tmpdir = dirname(canonical_path))
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(.dsvert_dp_canonical_json(value)), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  recovered <- .dsvert_dp_noise_open_recovery(temporary, identity_seed)
  if (!identical(recovered, key)) {
    stop("The staged DP noise-root recovery failed verification",
         call. = FALSE)
  }
  .dsvert_dp_noise_require_sync(
    temporary, "staged DP noise-root recovery")
  if (!file.rename(temporary, recovery)) {
    stop("Could not atomically commit the DP noise-root recovery",
         call. = FALSE)
  }
  Sys.chmod(recovery, mode = "0600")
  .dsvert_dp_noise_require_sync(
    dirname(canonical_path), "DP noise-root recovery directory")
  invisible(recovery)
}

.dsvert_dp_noise_restore_recovery <- function(
    canonical_path, identity_seed = NULL) {
  if (is.null(identity_seed)) {
    identity_seed <- .dsvert_dp_noise_recovery_identity()
  }
  if (is.null(identity_seed)) {
    stop("The DP noise root is missing and its automatic recovery requires the persistent pinned identity",
         call. = FALSE)
  }
  recovery <- .dsvert_dp_noise_recovery_path(canonical_path)
  key <- .dsvert_dp_noise_open_recovery(recovery, identity_seed)
  receipt <- .dsvert_dp_noise_receipt_path(canonical_path)
  if (file.exists(receipt)) {
    invisible(.dsvert_dp_noise_validate_receipt(receipt, key))
  } else if (.dsvert_dp_path_is_link(receipt)) {
    stop("The DP noise-root receipt must not be a symbolic link",
         call. = FALSE)
  }
  temporary <- tempfile(
    pattern = paste0(".noise_root_restore.", Sys.getpid(), "."),
    tmpdir = dirname(canonical_path))
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(paste(format(key), collapse = "")), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  invisible(.dsvert_dp_noise_validate_file(temporary))
  .dsvert_dp_noise_require_sync(
    temporary, "staged recovered DP noise-root key")
  if (!file.rename(temporary, canonical_path)) {
    stop("Could not atomically restore the private DP noise root",
         call. = FALSE)
  }
  Sys.chmod(canonical_path, mode = "0600")
  .dsvert_dp_noise_require_sync(
    dirname(canonical_path), "recovered DP noise-root directory")
  invisible(.dsvert_dp_noise_validate_file(canonical_path))
  canonical_path
}

.dsvert_dp_noise_read_receipt_key_id <- function(path) {
  if (.dsvert_dp_path_is_link(path) || !file.exists(path) ||
      !utils::file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)) {
    stop("The DP noise-root receipt must be a regular owner-only file without links",
         call. = FALSE)
  }
  info <- file.info(path)
  if (nrow(info) != 1L || is.na(info$size) || info$size < 1L ||
      info$size > 512L) {
    stop("The DP noise-root receipt has an invalid representation",
         call. = FALSE)
  }
  before <- unname(info[c("size", "mtime", "ctime")])
  encoded <- readBin(path, what = "raw", n = info$size + 1L)
  after <- unname(file.info(path)[c("size", "mtime", "ctime")])
  if (.dsvert_dp_path_is_link(path) || !identical(before, after) ||
      length(encoded) != info$size) {
    stop("The DP noise-root receipt changed while it was being read",
         call. = FALSE)
  }
  value <- tryCatch(
    jsonlite::fromJSON(rawToChar(encoded), simplifyVector = TRUE),
    error = function(e) NULL)
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), c("protocol", "key_id")) &&
    identical(value$protocol, .DSVERT_DP_NOISE_RECEIPT_PROTOCOL) &&
    is.character(value$key_id) && length(value$key_id) == 1L &&
    !is.na(value$key_id) && grepl("^file_[0-9a-f]{64}$", value$key_id)
  if (!isTRUE(valid)) {
    stop("The DP noise-root receipt is invalid",
         call. = FALSE)
  }
  value$key_id
}

.dsvert_dp_noise_validate_receipt <- function(path, key) {
  expected_key_id <- paste0(
    "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
  if (!identical(.dsvert_dp_noise_read_receipt_key_id(path),
                 expected_key_id)) {
    stop("The DP noise-root receipt does not match the active key",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_noise_sync_file <- function(path) {
  sync <- Sys.which("sync")
  if (!nzchar(sync)) return(invisible(FALSE))
  status <- suppressWarnings(tryCatch(
    system2(sync, c("-f", shQuote(path)), stdout = FALSE, stderr = FALSE),
    error = function(e) 1L))
  invisible(identical(as.integer(status), 0L))
}

.dsvert_dp_noise_require_sync <- function(path, what) {
  if (!isTRUE(.dsvert_dp_noise_sync_file(path))) {
    stop("Could not durably synchronize the ", what,
         "; DP release service remains unavailable", call. = FALSE)
  }
  invisible(NULL)
}

.dsvert_dp_noise_validate_pre_receipt_ledgers <- function(key) {
  state <- .dsvert_noise_bootstrap_state_from_options()
  if (is.null(state)) return(invisible(NULL))
  ledger <- state$ledger_path
  candidates <- c(
    joint_v1 = paste0(ledger, ".joint-mpc-single-opening-v1.sqlite"),
    joint_v2 = paste0(ledger, ".joint-mpc-single-opening-v2.sqlite"))
  descriptions <- c(
    joint_v1 = "legacy joint DP ledger",
    joint_v2 = "joint DP ledger")
  present <- vapply(names(candidates), function(type) {
    .dsvert_dp_history_file_present(
      candidates[[type]], descriptions[[type]])
  }, logical(1L))
  candidates <- candidates[present]
  if (!length(candidates)) return(invisible(NULL))
  key_id <- paste0(
    "file_", digest::digest(key, algo = "sha256", serialize = FALSE))

  validate_joint <- function(path, expected_schema) {
    type <- if (identical(expected_schema, "1")) "joint_v1" else "joint_v2"
    .dsvert_dp_history_readonly(
      path, descriptions[[type]], function(connection) {
        if (!all(c("joint_meta", "joint_records") %in%
                 tryCatch(DBI::dbListTables(connection),
                          error = function(e) character()))) {
          return(FALSE)
        }
        schema <- tryCatch(DBI::dbGetQuery(connection,
          "SELECT value FROM joint_meta WHERE key = 'schema_version'"),
          error = function(e) NULL)
        if (!is.data.frame(schema) || nrow(schema) != 1L ||
            !identical(schema$value[[1L]], expected_schema)) {
          return(FALSE)
        }
        rows <- tryCatch(DBI::dbGetQuery(
          connection, "SELECT record_json FROM joint_records"),
          error = function(e) NULL)
        if (!is.data.frame(rows)) return(FALSE)
        if (!nrow(rows)) return(TRUE)
        bindings <- lapply(rows$record_json, function(json) {
          record <- tryCatch(
            jsonlite::fromJSON(json, simplifyVector = FALSE),
            error = function(e) NULL)
          if (!is.list(record) || !is.list(record$own_prepare) ||
              !is.character(record$own_prepare$noise_key_id) ||
              length(record$own_prepare$noise_key_id) != 1L ||
              !is.character(record$own_prepare$privacy_epoch) ||
              length(record$own_prepare$privacy_epoch) != 1L) {
            return(NULL)
          }
          epoch <- suppressWarnings(as.numeric(
            record$own_prepare$privacy_epoch))
          if (!is.finite(epoch) || epoch < 1 ||
              epoch != floor(epoch)) return(NULL)
          list(epoch = epoch, key_id = record$own_prepare$noise_key_id)
        })
        if (any(vapply(bindings, is.null, logical(1L)))) return(FALSE)
        epochs <- vapply(bindings, `[[`, numeric(1L), "epoch")
        latest_ids <- unique(vapply(
          bindings[epochs == max(epochs)], `[[`, character(1L), "key_id"))
        length(latest_ids) == 1L && identical(latest_ids[[1L]], key_id)
      })
  }
  valid <- vapply(names(candidates), function(type) {
    validate_joint(
      candidates[[type]], if (identical(type, "joint_v1")) "1" else "2")
  }, logical(1L))
  key <- NULL
  if (!all(valid)) {
    stop(
      "The active DP noise root cannot authenticate the existing joint release history; restore the original key before creating its continuity receipt",
      call. = FALSE)
  }
  invisible(NULL)
}

.dsvert_dp_noise_ensure_receipt <- function(
    canonical_path, key, .authenticated_rotation = FALSE) {
  receipt <- .dsvert_dp_noise_receipt_path(canonical_path)
  if (file.exists(receipt)) {
    invisible(.dsvert_dp_noise_validate_receipt(receipt, key))
    return(invisible(receipt))
  }
  if (.dsvert_dp_path_is_link(receipt)) {
    stop("The DP noise-root receipt must not be a symbolic link",
         call. = FALSE)
  }
  if (!isTRUE(.authenticated_rotation)) {
    .dsvert_dp_noise_validate_pre_receipt_ledgers(key)
  }
  # A receipt is written only after the key and containing directory are
  # durably synchronized. Its continued presence prevents a later missing key
  # from being mistaken for a first deployment.
  .dsvert_dp_noise_require_sync(canonical_path, "DP noise-root key")
  .dsvert_dp_noise_require_sync(
    dirname(canonical_path), "DP noise-root directory")
  temporary <- tempfile(
    pattern = paste0(".noise_root_receipt.", Sys.getpid(), "."),
    tmpdir = dirname(canonical_path))
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  key_id <- paste0(
    "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(.dsvert_dp_canonical_json(list(
    protocol = .DSVERT_DP_NOISE_RECEIPT_PROTOCOL,
    key_id = key_id))), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  invisible(.dsvert_dp_noise_validate_receipt(temporary, key))
  .dsvert_dp_noise_require_sync(temporary, "staged DP noise-root receipt")
  if (!file.rename(temporary, receipt)) {
    stop("Could not atomically commit the DP noise-root receipt",
         call. = FALSE)
  }
  Sys.chmod(receipt, mode = "0600")
  invisible(.dsvert_dp_noise_validate_receipt(receipt, key))
  .dsvert_dp_noise_require_sync(
    dirname(canonical_path), "DP noise-root receipt directory")
  invisible(receipt)
}

.dsvert_dp_noise_history_path_sha256 <- function(path) {
  path <- path.expand(.dsvert_dp_scalar_string(
    path, "authenticated DP history path"))
  parent <- dirname(path)
  if (dir.exists(parent)) {
    path <- file.path(normalizePath(
      parent, winslash = "/", mustWork = TRUE), basename(path))
  }
  digest::digest(path, algo = "sha256", serialize = FALSE)
}

.dsvert_dp_noise_history_probe <- function(state) {
  provider <- if (is.list(state)) state$history_provider else NULL
  if (is.null(provider)) {
    return(list(history = NULL, authenticated_empty = FALSE))
  }
  if (!is.function(provider)) {
    stop("The DP noise-root authenticated-history provider is invalid",
         call. = FALSE)
  }
  value <- tryCatch(provider(), error = function(e) {
    stop("The existing DP release history could not be authenticated by the persistent identity",
         call. = FALSE)
  })
  if (is.null(value)) {
    return(list(history = NULL, authenticated_empty = FALSE))
  }
  empty_fields <- c(
    "protocol", "sources", "audit_sha256", "ledger_path_sha256",
    "identity_mac")
  empty_shape <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), empty_fields)
  empty_material <- if (isTRUE(empty_shape)) value[setdiff(
    empty_fields, "identity_mac")] else NULL
  expected_empty_mac <- if (isTRUE(empty_shape)) tryCatch(
    .dsvert_dp_hmac(.dsvert_dp_secret(), list(
      "dsvert-authenticated-empty-dp-ledger-history-mac-v1",
      empty_material)), error = function(error) NULL) else NULL
  authenticated_empty <- isTRUE(empty_shape) &&
    identical(
      value$protocol, .DSVERT_DP_AUTHENTICATED_EMPTY_HISTORY_PROTOCOL) &&
    is.character(value$sources) && length(value$sources) >= 1L &&
    length(value$sources) <= 3L && !anyNA(value$sources) &&
    !anyDuplicated(value$sources) &&
    identical(value$sources, sort(value$sources, method = "radix")) &&
    all(value$sources %in% c("joint", "local", "vector")) &&
    is.character(value$audit_sha256) &&
    length(value$audit_sha256) == 1L && !is.na(value$audit_sha256) &&
    grepl("^[0-9a-f]{64}$", value$audit_sha256) &&
    is.character(value$ledger_path_sha256) &&
    length(value$ledger_path_sha256) == 1L &&
    !is.na(value$ledger_path_sha256) &&
    identical(
      value$ledger_path_sha256,
      .dsvert_dp_noise_history_path_sha256(state$ledger_path)) &&
    is.character(value$identity_mac) &&
    length(value$identity_mac) == 1L && !is.na(value$identity_mac) &&
    grepl("^[0-9a-f]{64}$", value$identity_mac) &&
    identical(value$identity_mac, expected_empty_mac)
  if (isTRUE(authenticated_empty)) {
    return(list(history = NULL, authenticated_empty = TRUE))
  }
  expected <- c(
    "privacy_epoch", "noise_key_id", "noise_key_provider_id",
    "composition_audit")
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), expected) &&
    identical(value$noise_key_provider_id, "owner_only_file_v2")
  if (!isTRUE(valid)) {
    stop("The authenticated DP release history has an invalid noise-root binding",
         call. = FALSE)
  }
  history <- list(
    privacy_epoch = .dsvert_dp_noise_epoch(value$privacy_epoch),
    noise_key_id = .dsvert_dp_noise_key_id(value$noise_key_id),
    noise_key_provider_id = value$noise_key_provider_id,
    composition_audit = .dsvert_dp_noise_epoch_audit(
      value$composition_audit))
  list(history = history, authenticated_empty = FALSE)
}

.dsvert_dp_noise_authenticated_history <- function(state) {
  .dsvert_dp_noise_history_probe(state)$history
}

.dsvert_dp_noise_epoch_state_or_null <- function(path, identity_seed) {
  journal <- .dsvert_dp_noise_epoch_path(path)
  if (!file.exists(journal) && !.dsvert_dp_path_is_link(journal)) {
    return(NULL)
  }
  .dsvert_dp_noise_read_epoch_journal(journal, identity_seed)
}

.dsvert_dp_noise_bootstrap_epoch_journal <- function(
    canonical_path, key_id, identity_seed, bootstrap_state,
    reason = "first_install") {
  existing <- .dsvert_dp_noise_epoch_state_or_null(
    canonical_path, identity_seed)
  if (!is.null(existing)) {
    if (!is.null(existing$pending) ||
        !identical(existing$active$key_id, key_id)) {
      stop("The active DP noise root does not match its authenticated epoch journal",
           call. = FALSE)
    }
    return(existing)
  }
  history <- .dsvert_dp_noise_authenticated_history(bootstrap_state)
  if (!is.null(history) && !identical(history$noise_key_id, key_id)) {
    stop("The active DP noise root does not match the authenticated DP release history",
         call. = FALSE)
  }
  epoch <- if (is.null(history)) 1 else history$privacy_epoch
  audit <- if (is.null(history)) NULL else history$composition_audit
  .dsvert_dp_noise_append_epoch_record(
    canonical_path, phase = "active", epoch = epoch, key_id = key_id,
    previous_key_id = NULL, reason = reason, audit = audit,
    identity_seed = identity_seed)
}

.dsvert_dp_noise_archive_previous_receipt <- function(
    canonical_path, previous_epoch, previous_key_id) {
  receipt <- .dsvert_dp_noise_receipt_path(canonical_path)
  if (!file.exists(receipt) && !.dsvert_dp_path_is_link(receipt)) {
    return(invisible(NULL))
  }
  observed <- .dsvert_dp_noise_read_receipt_key_id(receipt)
  if (!identical(observed, previous_key_id)) {
    return(invisible(NULL))
  }
  archive <- paste0(
    receipt, ".epoch-",
    format(previous_epoch, scientific = FALSE, trim = TRUE), ".",
    substr(previous_key_id, 6L, 21L))
  if (file.exists(archive) || .dsvert_dp_path_is_link(archive)) {
    if (!identical(.dsvert_dp_noise_read_receipt_key_id(archive),
                   previous_key_id)) {
      stop("The archived DP noise-root receipt is inconsistent",
           call. = FALSE)
    }
    unlink(receipt, force = TRUE)
  } else if (!file.rename(receipt, archive)) {
    stop("Could not archive the previous DP noise-root receipt",
         call. = FALSE)
  }
  Sys.chmod(archive, mode = "0600")
  .dsvert_dp_noise_require_sync(
    dirname(canonical_path), "DP noise-root receipt archive directory")
  invisible(archive)
}

.dsvert_dp_noise_stage_new_key <- function(
    canonical_path, random_bytes) {
  staged <- .dsvert_dp_noise_next_key_path(canonical_path)
  if (file.exists(staged) || .dsvert_dp_path_is_link(staged)) {
    key <- .dsvert_dp_noise_validate_file(staged)
    return(list(path = staged, key = key, key_id = paste0(
      "file_", digest::digest(key, algo = "sha256", serialize = FALSE))))
  }
  key <- tryCatch(random_bytes(32L), error = function(e) {
    stop("Secure operating-system entropy is unavailable for DP noise-root rotation",
         call. = FALSE)
  })
  if (!is.raw(key) || length(key) != 32L) {
    stop("Secure operating-system entropy returned an invalid DP rotation result",
         call. = FALSE)
  }
  connection <- file(staged, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(paste(format(key), collapse = "")), connection)
  flush(connection)
  close(connection)
  Sys.chmod(staged, mode = "0600")
  key <- .dsvert_dp_noise_validate_file(staged)
  .dsvert_dp_noise_require_sync(staged, "staged rotated DP noise-root key")
  .dsvert_dp_noise_require_sync(
    dirname(canonical_path), "DP noise-root rotation directory")
  list(path = staged, key = key, key_id = paste0(
    "file_", digest::digest(key, algo = "sha256", serialize = FALSE)))
}

.dsvert_dp_noise_complete_rotation <- function(
    canonical_path, journal, identity_seed, bootstrap_state,
    random_bytes) {
  pending <- journal$pending
  if (is.null(pending)) {
    stop("The DP noise-root rotation has no authenticated pending epoch",
         call. = FALSE)
  }
  staged <- .dsvert_dp_noise_next_key_path(canonical_path)
  key <- NULL
  if (file.exists(canonical_path)) {
    key <- .dsvert_dp_noise_validate_file(canonical_path)
    key_id <- paste0(
      "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
    if (!identical(key_id, pending$key_id)) {
      stop("The pending DP noise-root epoch does not match the active key",
           call. = FALSE)
    }
  } else if (file.exists(staged) || .dsvert_dp_path_is_link(staged)) {
    key <- .dsvert_dp_noise_validate_file(staged)
    key_id <- paste0(
      "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
    if (!identical(key_id, pending$key_id)) {
      stop("The staged DP noise-root rotation key is inconsistent",
           call. = FALSE)
    }
    .dsvert_dp_noise_archive_previous_receipt(
      canonical_path, journal$active$privacy_epoch,
      journal$active$key_id)
    if (!file.rename(staged, canonical_path)) {
      stop("Could not atomically activate the rotated DP noise root",
           call. = FALSE)
    }
    Sys.chmod(canonical_path, mode = "0600")
    .dsvert_dp_noise_require_sync(
      dirname(canonical_path), "rotated DP noise-root directory")
  } else {
    recovery <- .dsvert_dp_noise_recovery_path(canonical_path)
    if (file.exists(recovery) || .dsvert_dp_path_is_link(recovery)) {
      recovered <- .dsvert_dp_noise_open_recovery(recovery, identity_seed)
      recovered_id <- paste0("file_", digest::digest(
        recovered, algo = "sha256", serialize = FALSE))
      if (!identical(recovered_id, pending$key_id)) {
        stop("The pending DP noise-root recovery is inconsistent",
             call. = FALSE)
      }
      .dsvert_dp_noise_restore_recovery(
        canonical_path, identity_seed = identity_seed)
      key <- .dsvert_dp_noise_validate_file(canonical_path)
    } else {
      stop("The authenticated pending DP noise-root rotation lost its staged key",
           call. = FALSE)
    }
  }
  key <- .dsvert_dp_noise_validate_file(canonical_path)
  key_id <- paste0(
    "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
  if (!identical(key_id, pending$key_id)) {
    stop("The activated DP noise-root rotation key is inconsistent",
         call. = FALSE)
  }
  .dsvert_dp_noise_archive_previous_receipt(
    canonical_path, journal$active$privacy_epoch, journal$active$key_id)
  invisible(.dsvert_dp_noise_ensure_receipt(
    canonical_path, key, .authenticated_rotation = TRUE))
  invisible(.dsvert_dp_noise_ensure_recovery(
    canonical_path, key, identity_seed = identity_seed))
  key <- NULL
  .dsvert_dp_noise_append_epoch_record(
    canonical_path, phase = "active",
    epoch = pending$privacy_epoch, key_id = pending$key_id,
    previous_key_id = pending$previous_key_id,
    reason = pending$reason, audit = pending$composition_audit,
    identity_seed = identity_seed)
}

.dsvert_dp_noise_rotate_missing_key <- function(
    canonical_path, journal, identity_seed, bootstrap_state,
    random_bytes) {
  if (!is.null(journal$pending)) {
    return(.dsvert_dp_noise_complete_rotation(
      canonical_path, journal, identity_seed, bootstrap_state,
      random_bytes))
  }
  history <- .dsvert_dp_noise_authenticated_history(bootstrap_state)
  audit <- journal$active$composition_audit
  if (is.null(history)) {
    # The journal alone is sufficient only in the clean window before any
    # ledger/anchor exists. Once release state exists, it must authenticate
    # under the persistent identity before a replacement root is minted.
    .dsvert_dp_noise_bootstrap_guard(bootstrap_state)
  } else {
    matching <- which(vapply(journal$active_records, function(record) {
      identical(record$privacy_epoch, history$privacy_epoch) &&
        identical(record$key_id, history$noise_key_id)
    }, logical(1L)))
    if (length(matching) != 1L) {
      stop("The missing DP noise root cannot be rotated because its authenticated release history diverges from the epoch journal",
           call. = FALSE)
    }
    previous_audit <- journal$active$composition_audit
    monotonic <-
      as.numeric(history$composition_audit$release_count) >=
        as.numeric(previous_audit$release_count) &&
      as.numeric(history$composition_audit$cumulative_epsilon) >=
        as.numeric(previous_audit$cumulative_epsilon) &&
      as.numeric(history$composition_audit$cumulative_delta) >=
        as.numeric(previous_audit$cumulative_delta)
    if (!isTRUE(monotonic)) {
      stop("The authenticated DP composition history was rolled back below the epoch journal",
           call. = FALSE)
    }
    audit <- history$composition_audit
  }
  staged <- .dsvert_dp_noise_stage_new_key(canonical_path, random_bytes)
  journal <- .dsvert_dp_noise_append_epoch_record(
    canonical_path, phase = "pending",
    epoch = journal$active$privacy_epoch + 1,
    key_id = staged$key_id, previous_key_id = journal$active$key_id,
    reason = "irrecoverable_file_root_loss",
    audit = audit, identity_seed = identity_seed)
  staged$key <- NULL
  .dsvert_dp_noise_complete_rotation(
    canonical_path, journal, identity_seed, bootstrap_state, random_bytes)
}

.dsvert_dp_noise_bootstrap_guard <- function(state) {
  if (is.null(state)) return(invisible(NULL))
  expected <- c("ledger_path", "anchor_provider", "anchor_id")
  if (!is.list(state) || is.null(names(state)) || anyNA(names(state)) ||
      anyDuplicated(names(state)) ||
      !setequal(names(state), c(
        expected, intersect("history_provider", names(state))))) {
    stop("The DP noise-root bootstrap state is invalid", call. = FALSE)
  }
  ledger_path <- state$ledger_path
  if (!is.character(ledger_path) || length(ledger_path) != 1L ||
      is.na(ledger_path) || !nzchar(ledger_path)) {
    stop("The DP noise-root bootstrap ledger binding is invalid",
         call. = FALSE)
  }
  joint_ledgers <- paste0(
    ledger_path, c(
      ".joint-mpc-single-opening-v1.sqlite",
      ".joint-mpc-single-opening-v2.sqlite"))
  vector_ledgers <- paste0(
    ledger_path, ".joint-dp-vector-v4.sqlite")
  prior_paths <- c(
    joint_ledgers, paste0(joint_ledgers, "-wal"),
    paste0(joint_ledgers, "-shm"),
    vector_ledgers, paste0(vector_ledgers, "-wal"),
    paste0(vector_ledgers, "-shm"))
  prior_promoted_state <- any(vapply(prior_paths, function(path) {
    if (!file.exists(path)) return(FALSE)
    info <- file.info(path)
    nrow(info) == 1L && !isTRUE(info$isdir) &&
      !is.na(info$size) && info$size > 0
  }, logical(1L)))
  if (isTRUE(prior_promoted_state)) {
    probe <- .dsvert_dp_noise_history_probe(state)
    if (!isTRUE(probe$authenticated_empty)) {
      stop(
        "The DP noise root is missing but persistent ledger state already exists; restore the original key or perform an explicit custodian-controlled epoch recovery",
        call. = FALSE)
    }
  }
  if (!is.null(state$anchor_provider)) {
    if (!is.function(state$anchor_provider) ||
        !is.character(state$anchor_id) || length(state$anchor_id) != 1L ||
        is.na(state$anchor_id) || !nzchar(state$anchor_id)) {
      stop("The DP noise-root bootstrap anchor binding is invalid",
           call. = FALSE)
    }
    observed <- tryCatch(
      state$anchor_provider(action = "read", anchor_id = state$anchor_id),
      error = identity)
    if (inherits(observed, "error")) {
      stop(
        "The DP noise root is missing and prior anchor state could not be ruled out; restore the original key or the anchor service",
        call. = FALSE)
    }
    if (!is.null(observed)) {
      stop(
        "The DP noise root is missing but an external rollback anchor already exists; restore the original key or perform an explicit custodian-controlled epoch recovery",
        call. = FALSE)
    }
  }
  invisible(NULL)
}

.dsvert_dp_ensure_noise_key_file <- function(
    path = .dsvert_dp_noise_default_path(),
    random_bytes = .dsvert_secure_random_bytes,
    .allow_test_path = FALSE, .bootstrap_state = NULL) {
  if (!is.function(random_bytes)) {
    stop("random_bytes must be a secure random-byte function", call. = FALSE)
  }
  previous_umask <- Sys.umask("0077")
  on.exit(try(Sys.umask(previous_umask), silent = TRUE), add = TRUE)
  canonical_path <- .dsvert_dp_noise_private_directory(
    path, .allow_test_path = .allow_test_path)
  lock_path <- paste0(canonical_path, ".lock")
  if (.dsvert_dp_path_is_link(lock_path)) {
    stop("The DP noise-root lock must not be a symbolic link", call. = FALSE)
  }
  lock <- filelock::lock(lock_path, timeout = 30000)
  if (is.null(lock)) {
    stop("The DP noise-root bootstrap lock is unavailable", call. = FALSE)
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  Sys.chmod(lock_path, mode = "0600")
  if (.dsvert_dp_path_is_link(lock_path) ||
      !.dsvert_dp_private_mode(lock_path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(lock_path), 1)) {
    stop("The DP noise-root bootstrap lock is not private", call. = FALSE)
  }

  identity_replacement <-
    .dsvert_dp_noise_apply_identity_replacement(canonical_path)
  if (isTRUE(identity_replacement$applied)) {
    # The prior history is retained as evidence but cannot be authenticated by
    # the replacement identity. Start an independent privacy epoch instead of
    # presenting the old journal as verified continuity.
    .bootstrap_state <- NULL
  }

  receipt_path <- .dsvert_dp_noise_receipt_path(canonical_path)
  recovery_path <- .dsvert_dp_noise_recovery_path(canonical_path)
  identity_seed <- .dsvert_dp_noise_recovery_identity()
  epoch_path <- .dsvert_dp_noise_epoch_path(canonical_path)
  if ((file.exists(epoch_path) || .dsvert_dp_path_is_link(epoch_path)) &&
      is.null(identity_seed)) {
    stop("The DP noise-root epoch journal requires the persistent pinned identity",
         call. = FALSE)
  }
  journal <- if (is.null(identity_seed)) NULL else
    .dsvert_dp_noise_epoch_state_or_null(canonical_path, identity_seed)

  # A durable pending journal record is the transaction marker. Complete it
  # before considering recovery or a new bootstrap, so a crash cannot turn
  # one rotation into two privacy epochs.
  if (!is.null(journal) && !is.null(journal$pending)) {
    .dsvert_dp_noise_complete_rotation(
      canonical_path, journal, identity_seed, .bootstrap_state,
      random_bytes)
    return(canonical_path)
  }

  if (file.exists(canonical_path)) {
    key <- .dsvert_dp_noise_validate_file(canonical_path)
    key_id <- paste0(
      "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
    if (!is.null(journal) &&
        !identical(journal$active$key_id, key_id)) {
      stop("The active DP noise root cannot authenticate the existing joint release history or its epoch journal",
           call. = FALSE)
    }
    invisible(.dsvert_dp_noise_ensure_receipt(canonical_path, key))
    invisible(.dsvert_dp_noise_ensure_recovery(
      canonical_path, key, identity_seed = identity_seed))
    if (!is.null(identity_seed) && is.null(journal)) {
      invisible(.dsvert_dp_noise_bootstrap_epoch_journal(
        canonical_path, key_id, identity_seed, .bootstrap_state,
        reason = "existing_root_migration"))
    }
    key <- NULL
    return(canonical_path)
  }
  if (file.exists(recovery_path) ||
      .dsvert_dp_path_is_link(recovery_path)) {
    .dsvert_dp_noise_restore_recovery(
      canonical_path, identity_seed = identity_seed)
    key <- .dsvert_dp_noise_validate_file(canonical_path)
    key_id <- paste0(
      "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
    if (!is.null(journal) &&
        !identical(journal$active$key_id, key_id)) {
      stop("The recovered DP noise root does not match its authenticated epoch journal",
           call. = FALSE)
    }
    invisible(.dsvert_dp_noise_ensure_receipt(canonical_path, key))
    invisible(.dsvert_dp_noise_ensure_recovery(
      canonical_path, key, identity_seed = identity_seed))
    if (!is.null(identity_seed) && is.null(journal)) {
      invisible(.dsvert_dp_noise_bootstrap_epoch_journal(
        canonical_path, key_id, identity_seed, .bootstrap_state,
        reason = "recovered_root_migration"))
    }
    key <- NULL
    return(canonical_path)
  }

  if (!is.null(journal)) {
    .dsvert_dp_noise_rotate_missing_key(
      canonical_path, journal, identity_seed, .bootstrap_state,
      random_bytes)
    return(canonical_path)
  }

  history <- .dsvert_dp_noise_authenticated_history(.bootstrap_state)
  if (!is.null(history)) {
    if (is.null(identity_seed)) {
      stop("Automatic DP noise-root rotation requires the persistent pinned identity",
           call. = FALSE)
    }
    if (file.exists(receipt_path) || .dsvert_dp_path_is_link(receipt_path)) {
      if (!identical(.dsvert_dp_noise_read_receipt_key_id(receipt_path),
                     history$noise_key_id)) {
        stop("The surviving DP noise-root receipt contradicts the authenticated release history",
             call. = FALSE)
      }
    }
    journal <- .dsvert_dp_noise_append_epoch_record(
      canonical_path, phase = "active",
      epoch = history$privacy_epoch, key_id = history$noise_key_id,
      previous_key_id = NULL, reason = "authenticated_history_migration",
      audit = history$composition_audit, identity_seed = identity_seed)
    .dsvert_dp_noise_rotate_missing_key(
      canonical_path, journal, identity_seed, .bootstrap_state,
      random_bytes)
    return(canonical_path)
  }

  if (file.exists(receipt_path) || .dsvert_dp_path_is_link(receipt_path)) {
    # A receipt is continuity evidence, but it is not release history.  When
    # the key, recovery envelope and epoch journal were all lost before any
    # ledger or rollback anchor existed, retain the receipt as epoch 1 and
    # rotate through the normal authenticated transaction.  This keeps a
    # restart or clean migration available without treating malformed or
    # contradictory state as a first deployment.
    receipt_key_id <- .dsvert_dp_noise_read_receipt_key_id(receipt_path)
    .dsvert_dp_noise_bootstrap_guard(.bootstrap_state)
    if (is.null(identity_seed)) {
      stop("Automatic DP noise-root receipt recovery requires the persistent pinned identity",
           call. = FALSE)
    }
    journal <- .dsvert_dp_noise_append_epoch_record(
      canonical_path, phase = "active", epoch = 1,
      key_id = receipt_key_id, previous_key_id = NULL,
      reason = "unreleased_receipt_recovery", audit = NULL,
      identity_seed = identity_seed)
    .dsvert_dp_noise_rotate_missing_key(
      canonical_path, journal, identity_seed, .bootstrap_state,
      random_bytes)
    return(canonical_path)
  }
  .dsvert_dp_noise_bootstrap_guard(.bootstrap_state)
  key <- tryCatch(
    random_bytes(32L),
    error = function(e) {
      stop("Secure operating-system entropy is unavailable for DP noise-root bootstrap",
           call. = FALSE)
    })
  if (!is.raw(key) || length(key) != 32L) {
    stop("Secure operating-system entropy returned an invalid DP bootstrap result",
         call. = FALSE)
  }
  temporary <- tempfile(
    pattern = paste0(".noise_root.", Sys.getpid(), "."),
    tmpdir = dirname(canonical_path))
  if (file.exists(temporary) || .dsvert_dp_path_is_link(temporary)) {
    stop("Could not allocate a private DP noise-root staging file",
         call. = FALSE)
  }
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(paste(format(key), collapse = "")), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  invisible(.dsvert_dp_noise_validate_file(temporary))
  .dsvert_dp_noise_require_sync(temporary, "staged DP noise-root key")
  if (file.exists(canonical_path)) {
    existing_key <- .dsvert_dp_noise_validate_file(canonical_path)
    invisible(.dsvert_dp_noise_ensure_receipt(
      canonical_path, existing_key))
    invisible(.dsvert_dp_noise_ensure_recovery(
      canonical_path, existing_key))
    existing_key <- NULL
    return(canonical_path)
  }
  if (!file.rename(temporary, canonical_path)) {
    stop("Could not atomically commit the private DP noise root",
         call. = FALSE)
  }
  Sys.chmod(canonical_path, mode = "0600")
  key <- .dsvert_dp_noise_validate_file(canonical_path)
  invisible(.dsvert_dp_noise_ensure_receipt(canonical_path, key))
  invisible(.dsvert_dp_noise_ensure_recovery(
    canonical_path, key, identity_seed = identity_seed))
  if (!is.null(identity_seed)) {
    key_id <- paste0(
      "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
    invisible(.dsvert_dp_noise_bootstrap_epoch_journal(
      canonical_path, key_id, identity_seed, .bootstrap_state,
      reason = if (isTRUE(identity_replacement$applied)) {
        "identity_replacement_after_continuity_loss"
      } else {
        "first_install"
      }))
  } else if (!is.null(.bootstrap_state)) {
    stop("DP noise-root bootstrap requires the persistent pinned identity",
         call. = FALSE)
  }
  key <- NULL
  canonical_path
}

.dsvert_dp_noise_key_file <- function(path, automatic_generation = TRUE,
                                      .allow_test_path = FALSE,
                                      .bootstrap_state = NULL) {
  path <- .dsvert_dp_scalar_string(path, "dsvert.dp.noise_key_path")
  canonical_path <- .dsvert_dp_ensure_noise_key_file(
    path, .allow_test_path = .allow_test_path,
    .bootstrap_state = .bootstrap_state)
  key <- .dsvert_dp_noise_validate_file(canonical_path)
  key_id <- paste0(
    "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
  key <- NULL
  identity_seed <- .dsvert_dp_noise_recovery_identity()
  journal <- if (is.null(identity_seed)) NULL else
    .dsvert_dp_noise_epoch_state_or_null(canonical_path, identity_seed)
  if (!is.null(journal) && (!is.null(journal$pending) ||
      !identical(journal$active$key_id, key_id))) {
    stop("The active DP noise root does not match its authenticated epoch journal",
         call. = FALSE)
  }
  epoch <- if (is.null(journal)) {
    .dsvert_dp_noise_epoch(.dsvert_dp_option("noise_key_epoch", 1))
  } else {
    journal$active$privacy_epoch
  }
  previous_key_id <- if (is.null(journal)) {
    previous <- .dsvert_dp_option("noise_key_previous_id", NULL)
    if (is.null(previous)) NULL else
      .dsvert_dp_noise_key_id(
        previous, "dsvert.dp.noise_key_previous_id")
  } else {
    journal$active$previous_key_id
  }
  transition_chain <- if (is.null(journal)) NULL else function() {
    .dsvert_dp_noise_read_epoch_journal(
      .dsvert_dp_noise_epoch_path(canonical_path),
      .dsvert_dp_noise_recovery_identity())$active_records
  }
  list(
    protocol = .DSVERT_DP_NOISE_ROOT_PROTOCOL,
    provider_id = "owner_only_file_v2",
    key_id = key_id,
    epoch = epoch,
    previous_key_id = previous_key_id,
    external = FALSE,
    storage = "owner_only_file",
    automatic_generation = isTRUE(automatic_generation),
    automatic_recovery = file.exists(
      .dsvert_dp_noise_recovery_path(canonical_path)),
    automatic_rotation = !is.null(journal) &&
      any(vapply(journal$active_records, function(record) {
        record$reason %in% c(
          "irrecoverable_file_root_loss",
          "identity_replacement_after_continuity_loss")
      }, logical(1L))),
    rotation_count = if (is.null(journal)) 0 else
      max(0, length(journal$active_records) - 1L),
    transition_chain = transition_chain,
    hmac = function(message) {
      key <- .dsvert_dp_noise_validate_file(canonical_path)
      active_key_id <- paste0(
        "file_", digest::digest(key, algo = "sha256", serialize = FALSE))
      if (!identical(active_key_id, key_id)) {
        stop("The DP noise root changed after the active policy was built",
             call. = FALSE)
      }
      digest::hmac(
        key = key, object = message, algo = "sha256",
        serialize = FALSE, raw = FALSE)
    })
}

.dsvert_dp_noise_root <- function(.bootstrap_state = NULL) {
  provider <- .dsvert_dp_option("noise_key_provider", NULL)
  path <- .dsvert_dp_option("noise_key_path", NULL)
  if (!is.null(provider) && !is.function(provider)) {
    stop("dsvert.dp.noise_key_provider must be a provider function",
         call. = FALSE)
  }
  if (!is.null(provider) && !is.null(path)) {
    stop("Configure exactly one of dsvert.dp.noise_key_provider or dsvert.dp.noise_key_path",
         call. = FALSE)
  }
  file_backed <- !is.function(provider)
  root <- if (!file_backed) {
    value <- .dsvert_dp_noise_provider(provider)
    value$automatic_generation <- FALSE
    value
  } else {
    if (is.null(path)) path <- .dsvert_dp_noise_default_path()
    .dsvert_dp_noise_key_file(
      path, automatic_generation = TRUE,
      .bootstrap_state = .bootstrap_state)
  }
  if (!file_backed) {
    root$epoch <- .dsvert_dp_noise_epoch(
      .dsvert_dp_option("noise_key_epoch", 1))
    previous <- .dsvert_dp_option("noise_key_previous_id", NULL)
    root$previous_key_id <- if (is.null(previous)) NULL else
      .dsvert_dp_noise_key_id(previous, "dsvert.dp.noise_key_previous_id")
    root$automatic_rotation <- FALSE
    root$rotation_count <- 0
    root$transition_chain <- NULL
  }
  root
}

.dsvert_dp_noise_root_public <- function(root) {
  list(
    protocol = root$protocol,
    provider_id = root$provider_id,
    key_id = root$key_id,
    privacy_epoch = root$epoch,
    external = root$external,
    storage = root$storage,
    automatic_generation = isTRUE(root$automatic_generation),
    automatic_recovery = isTRUE(root$automatic_recovery),
    automatic_rotation = isTRUE(root$automatic_rotation),
    rotation_count = as.numeric(root$rotation_count %||% 0),
    key_material_exposed = FALSE)
}

.dsvert_dp_noise_seed <- function(policy, query_hash, release_index,
                                  mechanism, epsilon, delta, sensitivity) {
  if (!is.character(query_hash) || length(query_hash) != 1L ||
      is.na(query_hash) || !grepl("^[0-9a-f]{64}$", query_hash)) {
    stop("The canonical DP query hash is invalid", call. = FALSE)
  }
  message <- .dsvert_dp_canonical_json(list(
    protocol = .DSVERT_DP_STICKY_NOISE_PROTOCOL,
    peer = policy$peer_name,
    domain = policy$domain,
    cohort = policy$cohort_id,
    canonical_query_hash = query_hash,
    mechanism = mechanism,
    allocation = list(
      release_index = as.numeric(release_index),
      epsilon = as.numeric(epsilon),
      delta = as.numeric(delta),
      sensitivity = as.numeric(sensitivity)),
    privacy_epoch = policy$noise_root$epoch,
    noise_key_id = policy$noise_root$key_id))
  seed <- policy$noise_root$hmac(charToRaw(message))
  if (!is.character(seed) || length(seed) != 1L || is.na(seed) ||
      !grepl("^[0-9a-f]{64}$", seed)) {
    stop("The DP noise root did not produce a valid deterministic seed",
         call. = FALSE)
  }
  # The root has now completed a real authenticated HMAC operation. Complete
  # the reciprocal recovery envelope before any sampler can consume the seed.
  # This is deliberately after ledger initialization in every release path, so
  # package/image loads and a failing provider cannot alter persistent state.
  identity_path <- .dsvert_identity_seed_path()
  identity_seed <- .dsvert_validate_identity_seed_file(identity_path)
  invisible(.dsvert_ensure_identity_recovery(
    identity_path, identity_seed, policy$noise_root))
  if (isTRUE(policy$noise_root$external)) {
    # File roots commit a pending identity replacement while opening the lazy
    # root. An external root has no file transition hook, so complete it only
    # after the replacement identity is durably wrapped by the real HMAC call.
    invisible(.dsvert_complete_external_identity_replacement())
  }
  seed
}
