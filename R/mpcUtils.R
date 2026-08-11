.DSVERT_MPC_RUNTIME_VERSION <- "1.1.0"
.DSVERT_MPC_API_VERSION <- "1.2.0"
.DSVERT_MPC_RUNTIME_PROTOCOL <- "dsvert-mpc-runtime-v1"
.DSVERT_MPC_RUNTIME_SCHEMA <- 1L
.DSVERT_MPC_PACKAGED_PATHS <- c(
  "darwin-amd64/dsvert-mpc",
  "darwin-arm64/dsvert-mpc",
  "linux-amd64/dsvert-mpc",
  "windows-amd64/dsvert-mpc.exe")
.dsvert_mpc_integrity_cache <- new.env(parent = emptyenv())
.dsvert_mpc_compatibility_cache <- new.env(parent = emptyenv())

.dsvert_mpc_runtime_error <- function(detail) {
  stop("Incompatible dsvert-mpc runtime: ", detail, call. = FALSE)
}

.dsvert_mpc_runtime_exact_names <- function(value, expected) {
  is.list(value) && !is.null(names(value)) && !anyNA(names(value)) &&
    !anyDuplicated(names(value)) &&
    identical(sort(names(value), method = "radix"),
              sort(expected, method = "radix"))
}

.dsvert_mpc_validate_feature <- function(value, capability_id,
                                         protocol_version, commands,
                                         operations,
                                         core_operations = NULL) {
  expected <- c("available", "capability_id", "protocol_version",
                "commands", "operations")
  if (!is.null(core_operations)) expected <- c(expected, "core_operations")
  .dsvert_mpc_runtime_exact_names(value, expected) &&
    identical(value$available, TRUE) &&
    identical(value$capability_id, capability_id) &&
    identical(value$protocol_version, protocol_version) &&
    identical(as.character(value$commands), commands) &&
    identical(as.character(value$operations), operations) &&
    (is.null(core_operations) ||
       identical(as.character(value$core_operations), core_operations))
}

#' Validate the deterministic Go runtime compatibility manifest
#' @param value Parsed runtime manifest.
#' @return The validated manifest.
#' @keywords internal
.dsvert_mpc_validate_runtime_manifest <- function(value) {
  expected <- c("schema_version", "protocol_version", "runtime_version",
                "api_version", "capabilities")
  valid_top <- .dsvert_mpc_runtime_exact_names(value, expected)
  valid_schema <- valid_top && is.numeric(value$schema_version) &&
    length(value$schema_version) == 1L && !is.na(value$schema_version) &&
    is.finite(value$schema_version) &&
    value$schema_version == .DSVERT_MPC_RUNTIME_SCHEMA
  if (!valid_top || !valid_schema ||
      !identical(value$protocol_version, .DSVERT_MPC_RUNTIME_PROTOCOL) ||
      !identical(value$runtime_version, .DSVERT_MPC_RUNTIME_VERSION) ||
      !identical(value$api_version, .DSVERT_MPC_API_VERSION)) {
    .dsvert_mpc_runtime_error("unsupported manifest schema or API version")
  }
  capabilities <- value$capabilities
  if (!.dsvert_mpc_runtime_exact_names(
        capabilities, c(
          "dp_noise_int64", "dp_gaussian_int64", "exact_gc",
          "typed_source_stream", "joint_dp_vector_convolution",
          "joint_dp_frequency_backend_selection")) ||
      !.dsvert_mpc_validate_feature(
        capabilities$dp_noise_int64,
        "dp_noise_int64_v2", "dsvert-dp-noise-int64-v2",
        "dp-noise-int64", "deterministic-granular-laplace-int64") ||
      !.dsvert_mpc_validate_feature(
        capabilities$dp_gaussian_int64,
        "dp_gaussian_int64_v3", "dsvert-dp-gaussian-int64-v3",
        c("dp-gaussian-int64", "dp-noise-select-int64"),
        c(paste0(
            "deterministic-approximate-gaussian-int64-l2-",
            "dp-transfer-tv-accounted"),
          "minimum-conservative-95-radius-v3")) ||
      !.dsvert_mpc_validate_feature(
        capabilities$exact_gc,
        "exact_gc_v1", "dsvert-exact-gc-worker-v4",
        c("exact-gc-derive-master", "exact-gc-capability",
          "exact-gc-plan-mul", "joint-dp-laplace-plan-v2",
          "joint-dp-laplace-worker-contract-v2",
          "joint-dp-vector-laplace-plan-v3",
          "joint-dp-vector-worker-contract-v3", "exact-gc-worker"),
        c("truncate-floor", "count-guard", "clamp-count",
          "joint-dp-laplace-v2", "joint-dp-vector-laplace-v3",
          "alignment-mask-ring128"),
        c("compare-signed", "truncate-floor", "mul-truncate-checked",
          "count-guard", "clamp-count", "joint-dp-laplace-v2",
          "joint-dp-vector-laplace-v3", "alignment-mask-ring128")) ||
      !.dsvert_mpc_validate_feature(
        capabilities$typed_source_stream,
        "typed_source_stream_probe_v1", "dsvert-typed-source-stream-v1",
        "typed-source-stream-probe", "data-free-random-source-probe") ||
      !.dsvert_mpc_validate_feature(
        capabilities$joint_dp_vector_convolution,
        "joint_dp_vector_hybrid_v5",
        "dsvert-joint-dp-vector-hybrid-v5",
        c("joint-dp-vector-convolution-plan-v3",
          "joint-dp-vector-convolution-share-v3",
          "joint-dp-vector-convolution-finalize-v3",
          "joint-dp-vector-gaussian-plan-v2",
          "joint-dp-vector-gaussian-share-v2",
          "joint-dp-vector-gaussian-finalize-v2"),
        c("sticky-independent-complete-vector-discrete-laplace-ring128-v3",
          paste0("sticky-independent-complete-vector-dyadic-discrete-",
                 "gaussian-tv-bounded-ring128-v2"),
          "signed-decode-fixed-public-clamp-no-wrap-v3")) ||
      !.dsvert_mpc_validate_feature(
        capabilities$joint_dp_frequency_backend_selection,
        "joint_dp_frequency_backend_selection_v1",
        "dsvert-joint-dp-frequency-backend-selection-v1",
        "joint-dp-frequency-backend-select-v1",
        "public-data-free-certified-frequency-backend-selection-v1")) {
    .dsvert_mpc_runtime_error("required capability contract is absent")
  }
  value
}

#' Probe and validate the deterministic Go runtime compatibility manifest
#' @return The validated manifest.
#' @keywords internal
.dsvert_mpc_binary_identity <- function(bin_path) {
  info <- file.info(bin_path)
  if (nrow(info) != 1L || is.na(info$size) || isTRUE(info$isdir) ||
      is.na(info$mtime) || is.na(info$ctime)) {
    .dsvert_mpc_runtime_error("the selected runtime is not a regular file")
  }
  list(
    cache_key = normalizePath(bin_path, mustWork = TRUE),
    stamp = c(
      as.character(info$size),
      format(info$mtime, "%Y-%m-%dT%H:%M:%OS6", tz = "UTC"),
      format(info$ctime, "%Y-%m-%dT%H:%M:%OS6", tz = "UTC")))
}

.dsvert_mpc_cached_manifest <- function(identity) {
  if (!exists(identity$cache_key, envir = .dsvert_mpc_compatibility_cache,
              inherits = FALSE)) {
    return(NULL)
  }
  cached <- get(identity$cache_key, envir = .dsvert_mpc_compatibility_cache,
                inherits = FALSE)
  if (is.list(cached) && identical(cached$stamp, identity$stamp) &&
      is.list(cached$manifest)) {
    return(cached$manifest)
  }
  rm(list = identity$cache_key, envir = .dsvert_mpc_compatibility_cache)
  NULL
}

.dsvert_mpc_runtime_manifest <- function() {
  identity <- tryCatch(
    .dsvert_mpc_binary_identity(.findMpcBinary()),
    error = function(e) NULL)
  if (is.null(identity)) {
    .dsvert_mpc_runtime_error(
      "the required runtime-capabilities command is unavailable")
  }
  cached <- .dsvert_mpc_cached_manifest(identity)
  if (!is.null(cached)) return(cached)

  value <- tryCatch(
    .callMpcTool("runtime-capabilities", list()),
    error = function(e) NULL)
  if (is.null(value)) {
    .dsvert_mpc_runtime_error(
      "the required runtime-capabilities command is unavailable")
  }
  manifest <- .dsvert_mpc_validate_runtime_manifest(value)
  post_identity <- tryCatch(
    .dsvert_mpc_binary_identity(.findMpcBinary()),
    error = function(e) NULL)
  if (is.null(post_identity) ||
      !identical(post_identity$cache_key, identity$cache_key) ||
      !identical(post_identity$stamp, identity$stamp)) {
    .dsvert_mpc_runtime_error(
      "the selected runtime changed during capability validation")
  }
  assign(identity$cache_key,
         list(stamp = identity$stamp, manifest = manifest),
         envir = .dsvert_mpc_compatibility_cache)
  manifest
}

#' Require named Go runtime capabilities before advertising readiness
#' @param capabilities Character vector of required capability names.
#' @return The validated manifest.
#' @keywords internal
.dsvert_mpc_require_capabilities <- function(capabilities) {
  known <- c(
    "dp_noise_int64", "dp_gaussian_int64", "exact_gc",
    "typed_source_stream", "joint_dp_vector_convolution",
    "joint_dp_frequency_backend_selection")
  if (!is.character(capabilities) || !length(capabilities) ||
      anyNA(capabilities) || anyDuplicated(capabilities) ||
      length(setdiff(capabilities, known))) {
    stop("Invalid dsvert-mpc capability requirement", call. = FALSE)
  }
  manifest <- .dsvert_mpc_runtime_manifest()
  if (any(!vapply(capabilities, function(name) {
    identical(manifest$capabilities[[name]]$available, TRUE)
  }, logical(1L)))) {
    .dsvert_mpc_runtime_error("a required capability is unavailable")
  }
  manifest
}

.dsvert_mpc_require_compatible_binary <- function(bin_path) {
  identity <- .dsvert_mpc_binary_identity(bin_path)
  cached <- .dsvert_mpc_cached_manifest(identity)
  if (!is.null(cached)) {
    return(invisible(cached))
  }
  manifest <- .dsvert_mpc_require_capabilities(c(
    "dp_noise_int64", "dp_gaussian_int64", "exact_gc"))
  cached <- .dsvert_mpc_cached_manifest(identity)
  if (is.null(cached) || !identical(cached, manifest)) {
    .dsvert_mpc_runtime_error(
      "the validated capability manifest belongs to a different runtime")
  }
  invisible(manifest)
}

# ---------------------------------------------------------------------------
# Disclosure Control Settings (following dsBase pattern)
# ---------------------------------------------------------------------------
# dsBase uses listDisclosureSettingsDS() with a two-tier fallback:
#   getOption("nfilter.glm") -> getOption("default.nfilter.glm")
# We follow the same pattern so Opal administrators can override per-profile.
# Defaults are declared in DESCRIPTION (Options section).
# ---------------------------------------------------------------------------

#' @title MPC Utility Functions
#' @description Internal utility functions for calling the dsvert-mpc Go binary
#'   and handling base64/base64url encoding conversions.
#'
#' @details
#' \subsection{Why base64url?}{
#' DataSHIELD passes function arguments through R's parser on the Opal/Rock
#' server. Standard base64 contains \code{+} and \code{/} characters that
#' R's parser can misinterpret in long strings (particularly in function
#' call arguments). Base64url replaces these with \code{-} and \code{_},
#' which are safe. All data is converted to base64url for transit between
#' client and server, then back to standard base64 before passing to the
#' Go binary (which uses Go's standard base64 library).
#' }
#'
#' \subsection{File-based I/O}{
#' The \code{.callMpcTool} function uses temporary files (not stdin/stdout
#' pipes) for JSON I/O because encrypted data can be hundreds of KB.
#' Pipe-based I/O can cause R's C stack to overflow with large outputs.
#' }
#'
#' Read dsVert disclosure control settings
#'
#' Reads nfilter options using the dsBase two-tier fallback pattern:
#' first checks \code{getOption("nfilter.X")}, then falls back to
#' \code{getOption("default.nfilter.X")}. This allows Opal administrators
#' to override settings per DataSHIELD profile.
#'
#' @return Named list with nfilter.tab, nfilter.glm, nfilter.subset,
#'   and datashield.privacyLevel.
#' @keywords internal
.dsvert_disclosure_settings <- function() {
  .read_nfilter <- function(name, fallback_default) {
    val <- getOption(name)
    if (is.null(val)) val <- getOption(paste0("default.", name))
    if (is.null(val)) val <- fallback_default
    as.numeric(val)
  }

  list(
    nfilter.tab     = .read_nfilter("nfilter.tab", 3),
    nfilter.glm     = .read_nfilter("nfilter.glm", 0.33),
    nfilter.subset  = .read_nfilter("nfilter.subset", 3),
    privacyLevel    = as.numeric(getOption("datashield.privacyLevel", 5))
  )
}

#' Check GLM disclosure controls (saturated model + binary variables)
#'
#' Checks two disclosure risks following dsBase glmDS1/glmDS2 pattern:
#' \enumerate{
#'   \item \strong{Model saturation}: Blocks if \code{p > nfilter.glm * n},
#'     preventing models where the number of parameters approaches the number
#'     of observations (risk of individual data reconstruction).
#'   \item \strong{Binary variable small cells}: For any binary variable
#'     (response or predictor), blocks if the smaller category has fewer than
#'     \code{nfilter.tab} observations.
#' }
#'
#' @param X Numeric matrix. Design matrix (n x p).
#' @param y Numeric vector. Response variable (optional, NULL to skip y check).
#' @param p_total Integer. Total number of parameters across ALL servers in the
#'   vertical partition. If NULL, uses ncol(X).
#' @return TRUE if all checks pass, otherwise stops with error.
#' @keywords internal
.check_glm_disclosure <- function(X, y = NULL, p_total = NULL) {
  settings <- .dsvert_disclosure_settings()
  n <- nrow(X)
  p <- if (!is.null(p_total)) p_total else ncol(X)

  # Check 1: Model saturation (dsBase: p > nfilter.glm * N)
  if (p > settings$nfilter.glm * n) {
    stop(
      "Disclosure control: model is oversaturated (too many parameters ",
      "relative to sample size). With ", p, " total parameters and ",
      "nfilter.glm = ", round(settings$nfilter.glm, 4), ", you need at least ",
      ceiling(p / settings$nfilter.glm), " observations (have ", n, ").",
      call. = FALSE
    )
  }

  # Check 2: Binary variable small cells (dsBase: nfilter.tab)
  .check_binary_cells <- function(vec, label) {
    vals <- unique(vec[!is.na(vec)])
    if (length(vals) == 2) {
      tab <- table(vec[!is.na(vec)])
      min_cell <- min(tab)
      if (min_cell < settings$nfilter.tab) {
        stop(
          "Disclosure control: ", label, " is binary with one category ",
          "having only ", min_cell, " observations (minimum: nfilter.tab = ",
          settings$nfilter.tab, ").",
          call. = FALSE
        )
      }
    }
  }

  # Check y if provided
  if (!is.null(y)) {
    .check_binary_cells(y, "response variable")
  }

  # Check each X column. Internal columns owned by ds.vertLMM's
  # cluster-mean GLS transform ("dsvertlmmint") encode only the
  # vector (1 - lambda_i[cluster]) -- a deterministic function of
  # the cluster-size vector n_i that is ALREADY disclosed to the
  # DCF peer via the documented cluster-ID broadcast (see
  # dsvertLMMBroadcastClusterIDsDS disclosure tier). Flagging it as
  # a patient-level binary variable is a false positive; the
  # apparent "two categories" just reflect which cluster size an
  # observation falls in. We skip the binary check on these columns
  # only. Suppression can be opted-out via
  # `options(dsvert.skip_internal_binary_check = FALSE)`.
  allow_internal <- isTRUE(getOption(
    "dsvert.skip_internal_binary_check", TRUE))
  internal_cols <- c("dsvertlmmint", "__dsvert_lmm_int")
  cn <- colnames(X)
  for (j in seq_len(ncol(X))) {
    if (allow_internal && !is.null(cn) && cn[j] %in% internal_cols) next
    .check_binary_cells(X[, j], paste0("predictor '", cn[j], "'"))
  }

  TRUE
}

#' Validate that a data_name is a safe R identifier
#'
#' Prevents expression injection when resolving server-side data by ensuring
#' data_name contains only letters, digits, dots, and underscores.
#'
#' @param data_name Character. Name to validate.
#' @return TRUE if valid, otherwise stops with an error.
#' @keywords internal
.validate_data_name <- function(data_name) {
  .dsvert_enforce_release_mode()
  if (!is.character(data_name) || length(data_name) != 1) {
    stop("data_name must be a single character string", call. = FALSE)
  }
  if (!grepl("^[a-zA-Z._][a-zA-Z0-9._]*$", data_name)) {
    stop("Invalid data_name: must be a valid R identifier (letters, digits, dots, underscores)",
         call. = FALSE)
  }
  TRUE
}

#' Resolve a data frame by name, checking session storage first
#' @param data_name Character. Name of the data frame to find.
#' @param env Environment to search if not found in session storage (typically parent.frame() of caller).
#' @param session_id Character or NULL. Session identifier for session-scoped storage.
#' @return The data frame
#' @keywords internal
.resolveData <- function(data_name, env, session_id = NULL) {
  .validate_data_name(data_name)
  ss <- .S(session_id)
  if (!is.null(ss$std_data_name) &&
      data_name == ss$std_data_name &&
      !is.null(ss$std_data)) {
    return(ss$std_data)
  }
  get(data_name, envir = env)
}

#' Convert base64url to standard base64
#' @description Converts base64url encoding (URL-safe) to standard base64.
#'   This is needed because R's parser on Opal/Rock has issues with "/" and "+"
#'   characters in long strings passed as function parameters.
#' @param x Character string in base64url encoding
#' @return Character string in standard base64 encoding
#' @keywords internal
.base64url_to_base64 <- function(x) {
  # Replace URL-safe characters with standard base64
  x <- gsub("-", "+", x, fixed = TRUE)
  x <- gsub("_", "/", x, fixed = TRUE)

  # Add padding if needed
  padding_needed <- (4 - nchar(x) %% 4) %% 4
  if (padding_needed > 0) {
    x <- paste0(x, paste(rep("=", padding_needed), collapse = ""))
  }

  x
}

#' Convert standard base64 to base64url
#' @description Converts standard base64 to base64url encoding (URL-safe).
#' @param x Character string in standard base64 encoding
#' @return Character string in base64url encoding
#' @keywords internal
base64_to_base64url <- function(x) {
  # Replace standard base64 characters with URL-safe ones
  x <- gsub("+", "-", x, fixed = TRUE)
  x <- gsub("/", "_", x, fixed = TRUE)
  # Remove padding
  x <- gsub("=", "", x, fixed = TRUE)
  x
}

#' Read and validate the packaged dsvert-mpc checksum manifest
#' @param bin_root Root of the packaged `inst/bin` tree.
#' @return Named character vector of expected SHA-256 digests.
#'
#' @keywords internal
.dsvert_mpc_packaged_checksums <- function(bin_root) {
  checksum_path <- file.path(bin_root, "SHA256SUMS")
  if (!file.exists(checksum_path) || isTRUE(file.info(checksum_path)$isdir) ||
      nzchar(Sys.readlink(checksum_path))) {
    stop("dsvert-mpc packaged binary integrity check failed: missing regular ",
         "SHA256SUMS manifest", call. = FALSE)
  }
  lines <- readLines(checksum_path, warn = FALSE, encoding = "bytes")
  valid <- length(lines) == length(.DSVERT_MPC_PACKAGED_PATHS) &&
    all(grepl("^[0-9a-f]{64}  [A-Za-z0-9._/-]+$", lines))
  if (!valid) {
    stop("dsvert-mpc packaged binary integrity check failed: malformed ",
         "SHA256SUMS manifest", call. = FALSE)
  }
  hashes <- substr(lines, 1L, 64L)
  paths <- substring(lines, 67L)
  if (anyDuplicated(paths) ||
      !identical(paths, .DSVERT_MPC_PACKAGED_PATHS)) {
    stop("dsvert-mpc packaged binary integrity check failed: unexpected ",
         "SHA256SUMS entries", call. = FALSE)
  }
  stats::setNames(hashes, paths)
}

#' Verify one packaged runtime artifact against its release checksum
#' @param bin_path Resolved path to the runtime executable.
#' @param bin_root Root of the packaged `inst/bin` tree.
#' @param relative_path Canonical platform-relative artifact path.
#' @return `TRUE` invisibly after successful verification.
#' @keywords internal
.dsvert_mpc_verify_packaged_binary <- function(bin_path, bin_root,
                                                relative_path) {
  if (!is.character(relative_path) || length(relative_path) != 1L ||
      !relative_path %in% .DSVERT_MPC_PACKAGED_PATHS) {
    stop("dsvert-mpc packaged binary integrity check failed: unsupported ",
         "artifact path", call. = FALSE)
  }
  expected_path <- file.path(bin_root, relative_path)
  if (!file.exists(bin_path) || isTRUE(file.info(bin_path)$isdir) ||
      nzchar(Sys.readlink(bin_path)) ||
      !identical(normalizePath(bin_path, mustWork = TRUE),
                 normalizePath(expected_path, mustWork = TRUE))) {
    stop("dsvert-mpc packaged binary integrity check failed: artifact is ",
         "missing, non-regular, or outside its package path", call. = FALSE)
  }
  checksums <- .dsvert_mpc_packaged_checksums(bin_root)
  expected <- unname(checksums[[relative_path]])
  checksum_path <- file.path(bin_root, "SHA256SUMS")
  bin_info <- file.info(bin_path)
  checksum_info <- file.info(checksum_path)
  stamp <- c(
    expected,
    as.character(bin_info$size),
    format(bin_info$mtime, "%Y-%m-%dT%H:%M:%OS6", tz = "UTC"),
    format(bin_info$ctime, "%Y-%m-%dT%H:%M:%OS6", tz = "UTC"),
    as.character(checksum_info$size),
    format(checksum_info$mtime, "%Y-%m-%dT%H:%M:%OS6", tz = "UTC"),
    format(checksum_info$ctime, "%Y-%m-%dT%H:%M:%OS6", tz = "UTC"))
  cache_key <- normalizePath(bin_path, mustWork = TRUE)
  cached <- if (exists(cache_key, envir = .dsvert_mpc_integrity_cache,
                       inherits = FALSE)) {
    get(cache_key, envir = .dsvert_mpc_integrity_cache, inherits = FALSE)
  } else {
    NULL
  }
  if (is.list(cached) && identical(cached$stamp, stamp)) {
    return(invisible(TRUE))
  }
  actual <- tolower(digest::digest(
    file = bin_path, algo = "sha256", serialize = FALSE))
  if (!identical(actual, expected)) {
    if (exists(cache_key, envir = .dsvert_mpc_integrity_cache,
               inherits = FALSE)) {
      rm(list = cache_key, envir = .dsvert_mpc_integrity_cache)
    }
    stop("dsvert-mpc packaged binary integrity check failed: SHA-256 ",
         "mismatch", call. = FALSE)
  }
  assign(cache_key, list(stamp = stamp),
         envir = .dsvert_mpc_integrity_cache)
  invisible(TRUE)
}

#' Find the dsvert-mpc binary
#'
#' Explicit administrator/development overrides are not release artifacts and
#' therefore are not listed in package SHA256SUMS; operational calls still
#' require their compatible runtime manifest. Binaries discovered under an
#' installed or source package must pass both checksum and runtime-manifest
#' validation.
#'
#' @return Path to the dsvert-mpc binary
#' @keywords internal
.findMpcBinary <- function() {
  # Determine platform-specific binary name
  os <- .Platform$OS.type
  if (os == "windows") {
    binary_name <- "dsvert-mpc.exe"
  } else {
    binary_name <- "dsvert-mpc"
  }

  # Check architecture for macOS (arm64 vs amd64)
  arch <- Sys.info()["machine"]
  if (Sys.info()["sysname"] == "Darwin") {
    if (arch == "arm64") {
      subdir <- "darwin-arm64"
    } else {
      subdir <- "darwin-amd64"
    }
  } else if (os == "windows") {
    subdir <- "windows-amd64"
  } else {
    subdir <- "linux-amd64"
  }

  bin_path <- ""
  packaged_root <- NULL
  relative_path <- file.path(subdir, binary_name)

  # Development and validation runs may need to exercise a repo-local binary
  # even when an installed dsVert package is also present.
  opt_path <- getOption("dsvert.mpc_binary")
  if (is.null(opt_path)) opt_path <- getOption("default.dsvert.mpc_binary")
  if (!is.null(opt_path) &&
      (!is.character(opt_path) || length(opt_path) != 1L || is.na(opt_path))) {
    stop("dsvert.mpc_binary must be one non-missing path", call. = FALSE)
  }
  if (!is.null(opt_path) && nzchar(opt_path)) {
    if (!file.exists(opt_path) || isTRUE(file.info(opt_path)$isdir)) {
      stop("Configured dsvert.mpc_binary is not a regular file",
           call. = FALSE)
    }
    bin_path <- opt_path
  }

  # Look for binary in package installation (platform-specific)
  if (bin_path == "" || !file.exists(bin_path)) {
    tryCatch({
      root <- system.file("bin", package = "dsVert")
      candidate <- if (nzchar(root)) file.path(root, relative_path) else ""
      if (nzchar(candidate) && file.exists(candidate)) {
        bin_path <- candidate
        packaged_root <- root
      }
    }, error = function(e) {})
  }

  # Fallback: look in development locations
  if (bin_path == "" || !file.exists(bin_path)) {
    # Try relative to this file (for development)
    dev_roots <- c(
      file.path(getwd(), "inst", "bin"),
      file.path(dirname(getwd()), "dsVert", "inst", "bin")
    )

    for (root in dev_roots) {
      candidate <- file.path(root, relative_path)
      if (file.exists(candidate)) {
        bin_path <- candidate
        packaged_root <- root
        break
      }
    }
  }

  if (bin_path == "" || !file.exists(bin_path)) {
    stop(
      "dsvert-mpc binary not found. ",
      "The MPC functionality requires the compiled Go binary.\n",
      "Expected location: inst/bin/", subdir, "/", binary_name, "\n",
      "Or set the dsvert.mpc_binary R option in the DataSHIELD profile.",
      call. = FALSE
    )
  }

  # Installation permissions are part of the release artifact. Never mutate
  # them at runtime: a non-executable helper is an invalid deployment.
  if (os != "windows" && file.access(bin_path, mode = 1L) != 0L) {
    stop("dsvert-mpc binary is not executable", call. = FALSE)
  }

  if (!is.null(packaged_root)) {
    .dsvert_mpc_verify_packaged_binary(
      bin_path, packaged_root, gsub("\\\\", "/", relative_path))
  }

  return(bin_path)
}

#' Call dsvert-mpc with JSON input
#'
#' @param input_data List that will be converted to JSON input
#' @return Parsed JSON output from dsvert-mpc
#' @keywords internal
.dsvert_mpc_encode_json <- function(input_data) {
  if (!is.list(input_data)) {
    stop("dsvert-mpc input_data must be a list", call. = FALSE)
  }
  as.character(jsonlite::toJSON(
    input_data, auto_unbox = TRUE, null = "null", digits = 17))
}

#' @keywords internal
.callMpcTool <- function(command, input_data, simplify_output = TRUE) {
  if (!is.character(command) || length(command) != 1L || is.na(command) ||
      !grepl("^[a-z0-9][a-z0-9-]{0,63}$", command)) {
    stop("Invalid dsvert-mpc command name", call. = FALSE)
  }
  if (!is.list(input_data)) {
    stop("dsvert-mpc input_data must be a list", call. = FALSE)
  }
  if (!is.logical(simplify_output) || length(simplify_output) != 1L ||
      is.na(simplify_output)) {
    stop("Invalid dsvert-mpc simplify_output", call. = FALSE)
  }
  # A transport key is meaningful only as an ephemeral child of the node's
  # persistent pinned identity.  Keep this check at the shared process
  # boundary as a backstop: a future caller cannot accidentally mint
  # transport state before the locked, atomic identity bootstrap has run.
  # `derive-identity` itself is excluded to avoid recursion; its only package
  # caller obtains the seed through .get_identity_seed() first.
  if (identical(command, "transport-keygen") &&
      !isTRUE(.dsvert_identity_test_mode())) {
    invisible(.get_identity_seed())
  }
  bin_path <- .findMpcBinary()
  # The manifest command is the bootstrap root and is validated by its caller.
  # Every operational command is otherwise version/capability-gated. The
  # successful probe is cached against the executable's filesystem identity.
  if (!identical(command, "runtime-capabilities")) {
    .dsvert_mpc_require_compatible_binary(bin_path)
  }

  # Requests and responses can contain private shares and ephemeral key
  # material.  Put every invocation in its own private directory and create
  # the files before use so their mode is fixed before any secret is written.
  temp_dir <- tempfile("dsvert-mpc-")
  if (!dir.create(temp_dir, mode = "0700") || !dir.exists(temp_dir)) {
    stop("Could not create a private dsvert-mpc temporary directory",
         call. = FALSE)
  }
  Sys.chmod(temp_dir, mode = "0700")
  input_file <- file.path(temp_dir, "input.json")
  output_file <- file.path(temp_dir, "output.json")
  stderr_file <- file.path(temp_dir, "stderr.txt")
  paths <- c(input_file, output_file, stderr_file)
  if (!all(vapply(paths, file.create, logical(1L)))) {
    unlink(temp_dir, recursive = TRUE, force = TRUE)
    stop("Could not create private dsvert-mpc temporary files",
         call. = FALSE)
  }
  Sys.chmod(paths, mode = "0600")

  .secure_unlink <- function(path) {
    if (!file.exists(path) || isTRUE(file.info(path)$isdir) ||
        nzchar(Sys.readlink(path))) return(invisible(NULL))
    # Best effort only: private permissions are the primary local protection;
    # flash media and journalled filesystems cannot promise physical erasure.
    wipe <- function() {
      size <- as.numeric(file.info(path)$size)
      if (is.finite(size) && size > 0) {
        connection <- file(path, "r+b")
        on.exit(close(connection), add = TRUE)
        block_size <- 1024L * 1024L
        block <- raw(block_size)
        remaining <- size
        while (remaining > 0) {
          count <- as.integer(min(remaining, block_size))
          writeBin(block[seq_len(count)], connection, useBytes = TRUE)
          remaining <- remaining - count
        }
        flush(connection)
      }
      invisible(NULL)
    }
    tryCatch(wipe(), error = function(e) NULL)
    unlink(path, force = TRUE)
    invisible(NULL)
  }

  on.exit({
    for (path in paths) .secure_unlink(path)
    unlink(temp_dir, recursive = TRUE, force = TRUE)
  })

  # Write input JSON to file using writeLines to avoid jsonlite::write_json

  # encoding quirks that can corrupt base64 strings in multi-round chains
  # Seventeen significant digits are sufficient for an IEEE-754 double to
  # round-trip exactly.  The jsonlite default (four digits) can otherwise
  # change an accounted DP epsilon or a public numeric parameter in transit.
  json_str <- .dsvert_mpc_encode_json(input_data)
  writeLines(json_str, input_file, useBytes = TRUE)
  Sys.chmod(input_file, mode = "0600")

  # Call dsvert-mpc with file-based I/O (avoids C stack overflow on large output)
  status <- system2(
    command = bin_path,
    args = command,
    stdin = input_file,
    stdout = output_file,
    stderr = stderr_file
  )

  # Check for errors
  if (status != 0) {
    err_msg <- if (file.exists(output_file)) readLines(output_file, warn = FALSE) else ""
    stderr_msg <- if (file.exists(stderr_file)) readLines(stderr_file, warn = FALSE) else ""
    stop("dsvert-mpc failed with status ", status, ": ",
         paste(c(err_msg, stderr_msg), collapse = "\n"), call. = FALSE)
  }

  # Parse output from file (avoids loading huge string into R)
  output <- jsonlite::read_json(
    output_file, simplifyVector = simplify_output)

  # Normalize base64 strings: strip whitespace/encoding artifacts that
  # accumulate across chained Beaver rounds (round k output -> round k+1 input)
  for (nm in names(output)) {
    if (is.character(output[[nm]]) && length(output[[nm]]) == 1) {
      output[[nm]] <- trimws(output[[nm]])
      Encoding(output[[nm]]) <- "unknown"
    }
  }

  # Check for error in output
  if (!is.null(output$error) && nchar(output$error) > 0) {
    stop("dsvert-mpc error: ", output$error, call. = FALSE)
  }

  return(output)
}

#' Check if a compatible MPC runtime is available
#'
#' Availability requires the exact runtime manifest, API version, DP sampler,
#' exact-GC capability contract, and (for packaged artifacts) SHA-256 checksum
#' expected by this package. Mere file existence is not sufficient.
#' The checksum detects release-packaging drift; it is not a signature and
#' cannot defend against an administrator replacing both artifact and manifest.
#'
#' @return TRUE if a compatible dsvert-mpc runtime is available, FALSE otherwise
#' @export
mpcAvailable <- function() {
  tryCatch({
    .dsvert_mpc_require_capabilities(c(
      "dp_noise_int64", "dp_gaussian_int64", "exact_gc"))
    TRUE
  }, error = function(e) {
    FALSE
  })
}

#' Get MPC tool version
#'
#' Reads the validated compatibility manifest and fails closed when the
#' runtime API does not match this package.
#'
#' @return Compatible version string of dsvert-mpc
#' @keywords internal
mpcVersion <- function() {
  .dsvert_mpc_runtime_manifest()$runtime_version
}

# ============================================================================
# Column Discovery (Smart UX)
# ============================================================================

#' List custodian-published columns for a policy-bound data frame
#'
#' Returns only the patient-key name and bounded analysis-column names that the
#' custodian published for this local dataset in the capsule policy.  This
#' metadata endpoint does not resolve or inspect the protected data frame.
#' It is used by the client for automatic variable-to-server mapping.
#'
#' @param data_name Character. Name of the data frame in the DataSHIELD session.
#' @return List with columns (character vector of column names).
#' @export
dsvertColNamesDS <- function(data_name) {
  .validate_data_name(data_name)
  policy <- .dsvert_dp_policy()
  mapping <- .dsvert_dp_capsule_manifest_local_mapping(policy)$datasets
  if (!data_name %in% names(mapping)) {
    .dsvert_dp_capsule_manifest_abort(
      "unknown_policy_dataset",
      "The requested dataset is not published in the custodian capsule policy")
  }
  columns <- sort(
    unique(c(policy$patient_column, mapping[[data_name]])), method = "radix")
  list(columns = columns)
}

#' Legacy in-place NA omission helper
#'
#' Compatibility helper that performs `complete.cases()` on selected columns
#' and mutates the named server-side data frame. It is retained for existing
#' deployments but is no longer registered as a product AggregateMethod and is
#' not used by `ds.psiAlign()`. PSI now applies its explicit missing-data policy
#' inside the protocol without modifying the source table.
#'
#' Equivalent to R's na.action = na.omit in glm().
#'
#' @param data_name Character. Name of the data frame.
#' @param vars Character vector. Column names to check for NAs.
#'   If NULL, checks all columns except id/patient_id.
#' @return List with n_before, n_after, n_dropped.
dsvertNaOmitDS <- function(data_name, vars = NULL) {
  .validate_data_name(data_name)
  d <- get(data_name, envir = parent.frame(), inherits = TRUE)
  if (!is.data.frame(d)) stop(paste0("'", data_name, "' is not a data frame"), call. = FALSE)
  n_before <- nrow(d)
  check_vars <- if (!is.null(vars)) intersect(vars, names(d))
                else setdiff(names(d), c("id", "patient_id"))
  if (length(check_vars) > 0) {
    complete <- complete.cases(d[, check_vars, drop = FALSE])
    d <- d[complete, , drop = FALSE]
  }
  assign(data_name, d, envir = parent.frame())
  list(n_before = n_before, n_after = nrow(d), n_dropped = n_before - nrow(d))
}

# ============================================================================
# Ed25519 Identity (Pinned Peers)
# ============================================================================

.dsvert_identity_test_mode <- function() {
  # Production code has no environment variable or R option that can weaken
  # identity persistence. Package tests replace this private binding only in
  # their already-loaded test namespace; that replacement is never installed.
  FALSE
}

#' Get the persistent identity seed
#' @return Character. Base64-encoded seed.
#' @keywords internal
.get_identity_seed <- function() {
  test_mode <- .dsvert_identity_test_mode()
  configured <- .dsvert_identity_seed_configuration(
    allow_test = test_mode)
  # Package tests emulate several peers in one R process by swapping this
  # option. Production rejects that option before consulting recovery state.
  if (!is.null(configured) && isTRUE(test_mode)) {
    return(configured)
  }

  seed_path <- .dsvert_identity_seed_path()
  if (isTRUE(test_mode) && file.exists(seed_path)) {
    persisted <- .dsvert_validate_identity_seed_file(seed_path)
    if (!is.null(configured) && !identical(configured, persisted)) {
      stop(
        "The configured identity seed conflicts with the persistent identity",
        call. = FALSE)
    }
    return(persisted)
  }
  recovery_root <- if (!file.exists(seed_path)) {
    .dsvert_dp_noise_root_for_identity_recovery()
  } else {
    NULL
  }
  # This is the runtime bootstrap boundary. Package installation and .onLoad
  # never call it, so an image can safely load dsVert without minting a shared
  # peer identity. The initializer validates an existing seed/receipt or uses
  # one locked, atomic 256-bit CSPRNG draw on a genuinely empty state root.
  .dsvert_init_identity_seed(
    seed_path = seed_path, noise_root_for_recovery = recovery_root)
  persisted <- .dsvert_validate_identity_seed_file(seed_path)
  if (!is.null(configured) && !identical(configured, persisted)) {
    stop(
      "The configured identity seed conflicts with the persistent identity",
      call. = FALSE)
  }
  persisted
}

#' Derive Ed25519 identity keypair from seed
#' @return List with identity_pk and identity_sk (standard base64).
#' @keywords internal
.get_identity_keypair <- function() {
  result <- .callMpcTool(
    "derive-identity", list(seed = .get_identity_seed()))
  if (!is.list(result) || is.null(names(result)) || anyNA(names(result)) ||
      anyDuplicated(names(result)) ||
      !setequal(names(result), c("identity_pk", "identity_sk"))) {
    stop("The persistent Ed25519 identity derivation returned an invalid keypair",
         call. = FALSE)
  }
  public <- .dsvert_normalize_crypto_b64(
    result$identity_pk, 32L, "Ed25519 identity public key")
  private <- .dsvert_normalize_crypto_b64(
    result$identity_sk, 64L, "Ed25519 identity private key")
  public_raw <- jsonlite::base64_dec(public)
  private_raw <- jsonlite::base64_dec(private)
  if (!identical(private_raw[33:64], public_raw)) {
    stop("The persistent Ed25519 identity keypair is inconsistent",
         call. = FALSE)
  }
  list(identity_pk = public, identity_sk = private)
}

#' Sign a transport PK with the identity SK
#' @return Character. Standard base64 signature.
#' @keywords internal
.sign_transport_pk <- function(transport_pk_b64, identity_sk_b64) {
  result <- .callMpcTool("sign-transport", list(
    transport_pk = transport_pk_b64, identity_sk = identity_sk_b64))
  result$signature
}

#' Verify a peer's transport PK signature
#' @return Logical.
#' @keywords internal
.verify_peer_identity <- function(transport_pk_b64, identity_pk_b64, signature_b64) {
  result <- .callMpcTool("verify-transport", list(
    transport_pk = transport_pk_b64, identity_pk = identity_pk_b64,
    signature = signature_b64))
  isTRUE(result$valid)
}

#' Parse a security-sensitive Boolean option without fail-open coercion
#' @keywords internal
.dsvert_security_boolean <- function(value, what, default) {
  if (is.null(value)) return(default)
  if (length(value) != 1L || is.na(value))
    stop("Invalid ", what, ": expected TRUE or FALSE.", call. = FALSE)
  if (is.logical(value)) return(value)
  if (is.numeric(value) && is.finite(value) && value %in% c(0, 1))
    return(as.logical(value))
  if (is.character(value) && value %in% c("TRUE", "FALSE"))
    return(identical(value, "TRUE"))
  stop("Invalid ", what, ": expected TRUE or FALSE.", call. = FALSE)
}

#' Validate a consortium logical peer name
#' @keywords internal
.dsvert_validate_logical_peer_name <- function(name) {
  if (!is.character(name) || length(name) != 1L || is.na(name) ||
      nchar(name, type = "bytes") > 128L ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._-]*$", name)) {
    stop("Invalid logical peer name in trusted-peer configuration.",
         call. = FALSE)
  }
  name
}

# Read the custodian-configured local logical peer name, when present.
.dsvert_configured_local_peer_name <- function() {
  name <- getOption("dsvert.peer_name")
  if (is.null(name)) name <- getOption("default.dsvert.peer_name")
  if (is.null(name)) return(NULL)
  # DESCRIPTION uses an empty default to mean that a non-DP deployment has
  # not declared a custodian role name. Invalid non-empty values still fail.
  if (is.character(name) && length(name) == 1L && !is.na(name) &&
      !nzchar(name)) return(NULL)
  .dsvert_validate_logical_peer_name(name)
}

# Authenticated protocol roles must be anchored in server configuration.  An
# analyst/relay may discover public identities, but it must never be able to
# choose the logical name under which this server signs or accepts a peer map.
.dsvert_require_configured_local_peer_name <- function() {
  name <- .dsvert_configured_local_peer_name()
  if (is.null(name)) {
    stop(
      "Authenticated peer binding requires a server-authoritative logical ",
      "site name. Server administrator: persist one unique dsvert.peer_name ",
      "for this site in the DataSHIELD service package profile and restart ",
      "the service. Public identity discovery with ds.getIdentityPks() ",
      "remains available before configuration; never accept a logical site ",
      "name supplied only by the analyst/relay.",
      call. = FALSE)
  }
  name
}

#' Decode and canonicalise a fixed-size cryptographic Base64 field
#' @keywords internal
.dsvert_normalize_crypto_b64 <- function(value, expected_bytes, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || grepl("[[:space:]]", value)) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  if (grepl("[+/]", value) && grepl("[-_]", value))
    stop("Invalid mixed-alphabet ", what, ".", call. = FALSE)
  if (!grepl("^[A-Za-z0-9+/_-]+={0,2}$", value) ||
      nchar(sub("=+$", "", value)) %% 4L == 1L) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  unpadded_url <- sub("=+$", "", value)
  unpadded_url <- gsub("+", "-", unpadded_url, fixed = TRUE)
  unpadded_url <- gsub("/", "_", unpadded_url, fixed = TRUE)
  decoded <- tryCatch(
    jsonlite::base64_dec(.base64url_to_base64(unpadded_url)),
    error = function(e) NULL
  )
  if (is.null(decoded) || length(decoded) != expected_bytes) {
    stop("Invalid ", what, " length.", call. = FALSE)
  }
  canonical <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(decoded)))
  if (!identical(canonical, unpadded_url))
    stop("Invalid or non-canonical ", what, ".", call. = FALSE)
  gsub("[\r\n]", "", jsonlite::base64_enc(decoded))
}

.DSVERT_PEER_NOT_RECOGNIZED_VERSION <-
  "DSVERT_PEER_NOT_RECOGNIZED_V1"

.dsvert_identity_fingerprint <- function(identity_pk) {
  canonical <- .dsvert_normalize_crypto_b64(
    identity_pk, 32L, "Ed25519 identity public key")
  digest::digest(
    jsonlite::base64_dec(canonical), algo = "sha256", serialize = FALSE)
}

.dsvert_peer_not_recognized_condition <- function(
    peer_name, observed_identity_pk, expected_identity_pk = NULL,
    reason = "Pinned identity mismatch") {
  peer_name <- .dsvert_validate_logical_peer_name(peer_name)
  observed <- .dsvert_identity_fingerprint(observed_identity_pk)
  expected <- if (is.null(expected_identity_pk)) {
    "unconfigured"
  } else {
    .dsvert_identity_fingerprint(expected_identity_pk)
  }
  token <- paste0(
    .DSVERT_PEER_NOT_RECOGNIZED_VERSION,
    "|peer=", peer_name,
    "|expected=", expected,
    "|observed=", observed)
  mismatch <- if (identical(expected, "unconfigured")) {
    paste0("logical peer '", peer_name,
           "' has no name-bound Ed25519 pin. Observed SHA-256 ", observed)
  } else {
    paste0("logical peer '", peer_name,
           "' does not match its name-bound Ed25519 pin. Expected SHA-256 ",
           expected, "; observed ", observed)
  }
  message <- paste0(
    token, " peer_not_recognized: ", reason,
    ". ", mismatch, ". Server administrator: from a trusted administrative ",
    "dsVertClient session, call ds.getIdentityPks(), then verify the observed ",
    "fingerprint out of band directly at the affected site's console. On each ",
    "other participating server that pins '", peer_name, "', persist the new ",
    "name-bound dsvert.trusted_peers (or dsvert.trusted_peer_", peer_name,
    ") value; the affected server must not pin its own identity. Restart or ",
    "reconnect the affected DataSHIELD services and sessions, then retry. ",
    "Never approve a replacement key solely from the analyst/relay.")
  structure(list(
    message = message, call = NULL, code = "peer_not_recognized",
    protocol = .DSVERT_PEER_NOT_RECOGNIZED_VERSION,
    peer_name = peer_name,
    expected_fingerprint_sha256 = expected,
    observed_fingerprint_sha256 = observed,
    admin_action = paste0(
      "verify_out_of_band_then_update_name_bound_pin_and_restart")),
    class = c("dsvert_peer_not_recognized", "error", "condition"))
}

.dsvert_stop_peer_not_recognized <- function(...) {
  stop(.dsvert_peer_not_recognized_condition(...))
}

#' Get the name-bound map of trusted peer identity PKs
#' @return Named character vector mapping logical peer names to base64 PKs.
#' @keywords internal
.get_trusted_peers <- function() {
  peers <- character(0)

  # Source 1: named vector/list logical peer name -> Ed25519 identity PK.
  # Historical comma-separated values have no name/role binding, so a relay
  # could swap two legitimate peers. That format is never accepted.
  tp <- getOption("dsvert.trusted_peers")
  if (is.null(tp)) tp <- getOption("default.dsvert.trusted_peers")
  if (!is.null(tp) && length(tp)) {
    if (is.list(tp)) tp <- unlist(tp, use.names = TRUE)
    if (!is.atomic(tp) || anyNA(tp))
      stop("Trusted peer keys must be non-missing character strings.",
           call. = FALSE)
    tp_names <- names(tp)
    tp <- as.character(tp)
    if (!is.null(tp_names)) names(tp) <- tp_names
    if (length(tp) == 1L && grepl(",", tp, fixed = TRUE) &&
        (is.null(names(tp)) || !nzchar(names(tp)[1L]))) {
      tp <- trimws(strsplit(tp, ",", fixed = TRUE)[[1L]])
    }
    tp <- tp[nzchar(trimws(tp))]
    tp <- trimws(tp)
    is_bound <- length(tp) == 0L ||
      (!is.null(names(tp)) && all(nzchar(names(tp))))
    if (!is_bound) {
      stop(
        "Trusted peer configuration must be name-bound: provide a named ",
        "vector/list logical_peer_name -> Ed25519 identity PK (or individual ",
        "dsvert.trusted_peer_<name> options). Flat or unnamed pin lists are ",
        "ambiguous and are not supported.", call. = FALSE)
    }
    if (is_bound && length(tp)) {
      if (anyDuplicated(names(tp)))
        stop("Trusted logical peer names must be unique.", call. = FALSE)
      names(tp) <- vapply(names(tp), .dsvert_validate_logical_peer_name,
                          character(1L), USE.NAMES = FALSE)
    }
    peers <- tp
  }

  # Source 2: dsvert.trusted_peer_<logical-name> individual options.
  all_opts <- names(options())
  peer_opts <- all_opts[grepl(
    "^(default\\.)?dsvert\\.trusted_peer_", all_opts)]
  peer_opts <- peer_opts[order(!startsWith(peer_opts, "default."))]
  for (opt in peer_opts) {
    val <- getOption(opt)
    peer_name <- sub("^(default\\.)?dsvert\\.trusted_peer_", "", opt)
    peer_name <- .dsvert_validate_logical_peer_name(peer_name)
    if (is.null(val)) next
    if (!is.character(val) || length(val) != 1L || is.na(val) ||
        !nzchar(trimws(val))) {
      stop("Trusted peer keys must be non-missing character strings.",
           call. = FALSE)
    }
    peers[peer_name] <- trimws(val)
  }

  peers <- peers[nzchar(peers)]
  if (length(peers) == 0)
    stop("peer_not_recognized: no name-bound trusted peers are configured. ",
         "Server administrator: obtain identities with ds.getIdentityPks(), ",
         "verify every fingerprint out of band at the corresponding site's ",
         "console, then configure dsvert.trusted_peers or ",
         "dsvert.trusted_peer_<name> and restart the service. Never approve a ",
         "peer key solely from the analyst/relay.",
         call. = FALSE)
  # Normalize to standard base64 (admin may paste base64url from
  # ds.getIdentityPks). One identity cannot occupy two logical roles.
  normalized <- vapply(
    peers, .dsvert_normalize_crypto_b64, character(1L),
    expected_bytes = 32L, what = "Ed25519 identity public key",
    USE.NAMES = TRUE)
  if (anyDuplicated(unname(normalized))) {
    stop("Each trusted logical peer must have a distinct pinned identity",
         call. = FALSE)
  }
  normalized
}

#' Verify all peer identities (signatures + trusted list)
#'
#' D-INV-5 enforcement. The Ed25519-signature + `trusted_peers`
#' pinned-config check protects against three distinct adversaries
#' that mTLS alone does NOT cover:
#'
#'   (a) Transport-key substitution. An active relay cannot replace a
#'       server's ephemeral X25519 key without forging its Ed25519 signature.
#'       Payload integrity is then provided by the authenticated encryption
#'       under that verified key. The legacy primitive path does not provide
#'       per-message non-repudiation; the typed relay substrate adds signed,
#'       context-bound envelopes before it can be promoted.
#'
#'   (b) Rogue server injection. A compromised study admin or
#'       attacker with a valid TLS certificate can attempt to add
#'       a server to the connection pool. Without `trusted_peers`,
#'       the MPC protocol has no way to distinguish "the legitimate
#'       study server" from "any server with a valid TLS cert" --
#'       the rogue server would either receive legitimate shares or
#'       inject replay/malformed-computation traces designed to
#'       leak structure, and its TLS certificate alone would NOT
#'       trip the standard mutual-TLS check. The pinned-public-key
#'       allow-list in `trusted_peers` prevents this: only servers
#'       whose identity PK appears in the pre-distributed config can
#'       sit in the pool.
#'
#'   (c) Logical-role binding. A name-bound pin prevents two legitimate peers
#'       from being swapped into one another's protocol roles. Flat allow-lists
#'       do not provide this property and are not accepted. The local role is
#'       read exclusively from persistent server configuration through
#'       `dsvert.peer_name`, never inferred from a relay-supplied map.
#'
#' @param identity_info Named list: server -> list(identity_pk, signature) (base64url).
#' @param transport_keys Named list: server -> transport_pk (base64url).
#' @param own_identity_pk Character. This server's identity PK (standard base64).
#' @keywords internal
.verify_all_peer_identities <- function(identity_info, transport_keys,
                                         own_identity_pk) {
  configured_own_name <- .dsvert_require_configured_local_peer_name()
  trusted_peers <- .get_trusted_peers()
  if (!is.list(identity_info) || !length(identity_info) ||
      is.null(names(identity_info)) || any(!nzchar(names(identity_info))) ||
      anyDuplicated(names(identity_info))) {
    stop("Identity handshake must be a uniquely name-bound map.",
         call. = FALSE)
  }
  if (!is.list(transport_keys) || !length(transport_keys) ||
      is.null(names(transport_keys)) || any(!nzchar(names(transport_keys))) ||
      anyDuplicated(names(transport_keys)) ||
      !setequal(names(identity_info), names(transport_keys))) {
    stop("Transport and identity handshakes must name exactly the same peers.",
         call. = FALSE)
  }
  peer_names <- vapply(names(identity_info),
                       .dsvert_validate_logical_peer_name, character(1L),
                       USE.NAMES = FALSE)
  if (!identical(peer_names, names(identity_info)))
    stop("Invalid logical peer name in identity handshake.", call. = FALSE)
  own_identity_pk <- .dsvert_normalize_crypto_b64(
    own_identity_pk, 32L, "own Ed25519 identity public key")
  verified <- character(0)
  identity_owners <- character(0)
  own_bindings <- 0L
  own_binding_name <- NULL
  for (srv in names(identity_info)) {
    info <- identity_info[[srv]]
    tk <- transport_keys[[srv]]
    if (!is.list(info) || !all(c("identity_pk", "signature") %in% names(info)) ||
        length(info$identity_pk) != 1L || length(info$signature) != 1L ||
        is.null(tk)) {
      stop("Malformed signed identity entry for '", srv, "'.", call. = FALSE)
    }

    id_pk <- .dsvert_normalize_crypto_b64(
      info$identity_pk, 32L, paste0("identity public key for '", srv, "'"))
    sig <- .dsvert_normalize_crypto_b64(
      info$signature, 64L, paste0("transport signature for '", srv, "'"))
    tk_b64 <- .dsvert_normalize_crypto_b64(
      tk, 32L, paste0("transport public key for '", srv, "'"))

    prior_owner <- names(identity_owners)[match(id_pk, identity_owners)]
    if (length(prior_owner) && !is.na(prior_owner) &&
        !identical(prior_owner, srv)) {
      stop("Identity key reused under multiple logical peer names ('",
           prior_owner, "' and '", srv, "').", call. = FALSE)
    }
    identity_owners[[srv]] <- id_pk

    # Every entry, including self, must authenticate its advertised transport
    # key. Skipping self here would let the relay substitute that key silently.
    if (!.verify_peer_identity(tk_b64, id_pk, sig))
      stop("Identity verification failed for '", srv,
           "': invalid signature on transport PK.", call. = FALSE)

    if (id_pk == own_identity_pk) {
      own_bindings <- own_bindings + 1L
      own_binding_name <- srv
      next
    }

    # Every non-self identity must match its exact logical-name pin.
    if (!srv %in% names(trusted_peers)) {
      .dsvert_stop_peer_not_recognized(
        srv, id_pk, reason = "Untrusted logical peer name")
    }
    if (!identical(id_pk, unname(trusted_peers[[srv]]))) {
      .dsvert_stop_peer_not_recognized(
        srv, id_pk, unname(trusted_peers[[srv]]),
        reason = "Pinned identity mismatch")
    }

    # This transport key passed signature + trusted-list verification.
    verified[[srv]] <- tk_b64
  }
  if (own_bindings != 1L) {
    stop("Identity handshake must bind this server exactly once.",
         call. = FALSE)
  }
  if (!identical(own_binding_name, configured_own_name)) {
    stop("Identity handshake relabels this server: the own identity must be ",
         "bound to configured dsvert.peer_name '", configured_own_name, "'.",
         call. = FALSE)
  }
  if (!setequal(names(verified), names(trusted_peers))) {
    stop("Pinned peer set mismatch: the handshake must contain exactly the ",
         "configured logical peers", call. = FALSE)
  }
  # The transport public keys (standard base64) that passed verification, so the
  # caller can pin exactly this set and never an extra unverified key that may
  # ride along in transport_keys.
  invisible(verified)
}

#' Enforce K-arity at server side (defense-in-depth)
#'
#' Refuses calls into a K-specific MPC primitive when the calling
#' deployment's K does not match `expected_K`. The K value is derived
#' from `ss$peer_transport_pks`, populated by `mpcStoreTransportKeysDS`
#' AFTER Ed25519 signature verification + trusted-peers list check
#' performed by `.verify_all_peer_identities` (mpcUtils.R:530-556).
#' `length(peer_transport_pks) + 1L` therefore equals the
#' cryptographically verified party count (this server + verified
#' peers); a malicious or misconfigured client cannot forge it.
#'
#' Pattern: each K-specific *DS function calls
#' `.k2_enforce_K(ss, expected_K = 2L, "fnName")` immediately after
#' resolving its session state. The check is silent when
#' `peer_transport_pks` is unset (e.g., the function is invoked before
#' the transport-key handshake -- that path is already guarded by
#' `mpcStoreTransportKeysDS` and mandatory name-bound peer pinning; this helper
#' is defense-in-depth, not the first line).
#'
#' @param ss MPC session state (output of `.S(session_id)`).
#' @param expected_K Integer expected K (e.g. 2L for K=2-only paths).
#' @param fn_name Optional function name embedded in the error message
#'   to aid log-trace attribution.
#' @return `TRUE` invisibly on success; `stop(...)` on K mismatch.
#' @keywords internal
.k2_enforce_K <- function(ss, expected_K, fn_name = NULL) {
  if (!is.null(ss$peer_transport_pks) &&
      length(ss$peer_transport_pks) + 1L != as.integer(expected_K)) {
    stop("K mismatch \u2014 server refuses cross-K primitive (",
         if (!is.null(fn_name)) paste0(fn_name, ": ") else "",
         "expected K=", as.integer(expected_K),
         ", got K=", length(ss$peer_transport_pks) + 1L, ")",
         call. = FALSE)
  }
  invisible(TRUE)
}

#' Query this server's identity public key
#'
#' Returns the Ed25519 identity PK. Used by admins to discover PKs
#' for configuring trusted_peers lists across a consortium.
#' This provisioning endpoint remains available before `dsvert.peer_name` is
#' configured; authenticated binds do not.
#'
#' @return List with identity_pk (base64url).
#' @export
dsvertIdentityPkDS <- function() {
  identity <- .get_identity_keypair()
  list(identity_pk = base64_to_base64url(identity$identity_pk))
}
