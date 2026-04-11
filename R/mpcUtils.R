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
#' @keywords internal

# ---------------------------------------------------------------------------
# Disclosure Control Settings (following dsBase pattern)
# ---------------------------------------------------------------------------
# dsBase uses listDisclosureSettingsDS() with a two-tier fallback:
#   getOption("nfilter.glm") -> getOption("default.nfilter.glm")
# We follow the same pattern so Opal administrators can override per-profile.
# Defaults are declared in DESCRIPTION (Options section).
# ---------------------------------------------------------------------------

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

  # Check each X column
  for (j in seq_len(ncol(X))) {
    .check_binary_cells(X[, j], paste0("predictor '", colnames(X)[j], "'"))
  }

  TRUE
}

#' Validate that a data_name is a safe R identifier
#'
#' Prevents command injection via eval(parse(text = ...)) by ensuring
#' data_name contains only letters, digits, dots, and underscores.
#'
#' @param data_name Character. Name to validate.
#' @return TRUE if valid, otherwise stops with an error.
#' @keywords internal
.validate_data_name <- function(data_name) {
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
#' @export
base64_to_base64url <- function(x) {
  # Replace standard base64 characters with URL-safe ones
  x <- gsub("+", "-", x, fixed = TRUE)
  x <- gsub("/", "_", x, fixed = TRUE)
  # Remove padding
  x <- gsub("=", "", x, fixed = TRUE)
  x
}

#' Find the dsvert-mpc binary
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

  # Look for binary in package installation (platform-specific)
  tryCatch({
    bin_path <- system.file("bin", subdir, binary_name, package = "dsVert")
  }, error = function(e) {})

  # Fallback: look in development locations
  if (bin_path == "" || !file.exists(bin_path)) {
    # Try relative to this file (for development)
    dev_paths <- c(
      file.path(getwd(), "inst", "bin", subdir, binary_name),
      file.path(dirname(getwd()), "dsVert", "inst", "bin", subdir, binary_name)
    )

    for (dp in dev_paths) {
      if (file.exists(dp)) {
        bin_path <- dp
        break
      }
    }
  }

  # Additional fallback: check R option (dsBase pattern), then env var
  if (bin_path == "" || !file.exists(bin_path)) {
    opt_path <- getOption("dsvert.mpc_binary")
    if (is.null(opt_path)) opt_path <- getOption("default.dsvert.mpc_binary")
    if (!is.null(opt_path) && opt_path != "" && file.exists(opt_path)) {
      bin_path <- opt_path
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

  # Ensure binary is executable (Unix only)
  if (os != "windows") {
    Sys.chmod(bin_path, mode = "0755")
  }

  return(bin_path)
}

#' Call dsvert-mpc with JSON input
#'
#' @param command The dsvert-mpc subcommand to run
#' @param input_data List that will be converted to JSON input
#' @return Parsed JSON output from dsvert-mpc
#' @keywords internal
.callMpcTool <- function(command, input_data) {
  bin_path <- .findMpcBinary()

  # Create temporary files for input and output.
  # Security: temp files may contain cryptographic keys or ciphertext.
  # We overwrite file contents before unlinking to prevent recovery from
  # /tmp by other processes (defense in depth).
  input_file <- tempfile(fileext = ".json")
  output_file <- tempfile(fileext = ".json")
  stderr_file <- tempfile(fileext = ".txt")

  .secure_unlink <- function(path) {
    if (file.exists(path)) {
      # Overwrite with zeros before deletion
      tryCatch({
        sz <- file.info(path)$size
        if (!is.na(sz) && sz > 0) {
          con <- file(path, "wb")
          writeBin(raw(as.integer(min(sz, 1e7))), con)
          close(con)
        }
      }, error = function(e) NULL)
      unlink(path)
    }
  }

  on.exit({
    .secure_unlink(input_file)
    .secure_unlink(output_file)
    .secure_unlink(stderr_file)
  })

  # Write input JSON to file using writeLines to avoid jsonlite::write_json

  # encoding quirks that can corrupt base64 strings in multi-round chains
  json_str <- jsonlite::toJSON(input_data, auto_unbox = TRUE, null = "null")
  writeLines(as.character(json_str), input_file, useBytes = TRUE)

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
  output <- jsonlite::read_json(output_file, simplifyVector = TRUE)

  # Normalize base64 strings: strip whitespace/encoding artifacts that
  # accumulate across chained Beaver rounds (round k output → round k+1 input)
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

#' Check if MPC binary is available
#'
#' @return TRUE if dsvert-mpc binary is available, FALSE otherwise
#' @export
mpcAvailable <- function() {
  tryCatch({
    bin_path <- .findMpcBinary()
    file.exists(bin_path)
  }, error = function(e) {
    FALSE
  })
}

#' Get MPC tool version
#'
#' @return Version string of dsvert-mpc
#' @export
mpcVersion <- function() {
  bin_path <- .findMpcBinary()

  # Capture stdout directly
  result <- system2(
    command = bin_path,
    args = "version",
    stdout = TRUE,
    stderr = TRUE
  )

  output <- jsonlite::fromJSON(paste(result, collapse = "\n"))
  return(output$version)
}

# ============================================================================
# Column Discovery (Smart UX)
# ============================================================================

#' List column names of a server-side data frame
#'
#' Returns the column names available on this server for the given data frame.
#' Used by the client for automatic variable-to-server mapping.
#'
#' @param data_name Character. Name of the data frame in the DataSHIELD session.
#' @return List with columns (character vector of column names).
#' @export
dsvertColNamesDS <- function(data_name) {
  d <- eval(parse(text = data_name), envir = parent.frame())
  if (!is.data.frame(d)) stop(paste0("'", data_name, "' is not a data frame"), call. = FALSE)
  list(columns = names(d))
}

# ============================================================================
# Ed25519 Identity (Pinned Peers)
# ============================================================================

#' Get the identity seed (R option or filesystem)
#' @return Character. Base64-encoded seed.
#' @keywords internal
.get_identity_seed <- function() {
  # Priority 1: R option (admin override for non-persistent containers)
  seed <- getOption("dsvert.identity_seed")
  if (is.null(seed)) seed <- getOption("default.dsvert.identity_seed")
  if (!is.null(seed) && nzchar(seed)) return(seed)

  # Priority 2: filesystem (auto-generated by .onLoad)
  seed_path <- file.path(Sys.getenv("HOME"), ".dsvert", "identity.seed")
  if (file.exists(seed_path)) return(trimws(readLines(seed_path, n = 1L, warn = FALSE)))

  stop("Identity seed not found. Neither dsvert.identity_seed R option nor ",
       seed_path, " exists.", call. = FALSE)
}

#' Derive Ed25519 identity keypair from seed
#' @return List with identity_pk and identity_sk (standard base64).
#' @keywords internal
.get_identity_keypair <- function() {
  .callMpcTool("derive-identity", list(seed = .get_identity_seed()))
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

#' Get the set of trusted peer identity PKs
#' @return Character vector of base64 PKs, or NULL if enforcement disabled.
#' @keywords internal
.get_trusted_peers <- function() {
  require_tp <- getOption("dsvert.require_trusted_peers")
  if (is.null(require_tp)) require_tp <- getOption("default.dsvert.require_trusted_peers")
  if (is.null(require_tp)) require_tp <- TRUE
  if (!isTRUE(as.logical(require_tp))) return(NULL)

  peers <- character(0)

  # Source 1: dsvert.trusted_peers (comma-separated)
  tp <- getOption("dsvert.trusted_peers")
  if (is.null(tp)) tp <- getOption("default.dsvert.trusted_peers")
  if (!is.null(tp) && nzchar(tp))
    peers <- c(peers, trimws(strsplit(tp, ",")[[1]]))

  # Source 2: dsvert.trusted_peer_* (individual options, accumulated)
  all_opts <- names(options())
  for (opt in all_opts[grepl("^(default\\.)?dsvert\\.trusted_peer_", all_opts)]) {
    val <- getOption(opt)
    if (!is.null(val) && nzchar(val)) peers <- c(peers, trimws(val))
  }

  peers <- unique(peers[nzchar(peers)])
  if (length(peers) == 0)
    stop("dsvert.require_trusted_peers=TRUE but no trusted peers configured. ",
         "Set dsvert.trusted_peers or dsvert.trusted_peer_* options, ",
         "or set dsvert.require_trusted_peers=FALSE for dev/testing.",
         call. = FALSE)
  # Normalize to standard base64 (admin may paste base64url from ds.getIdentityPks)
  vapply(peers, .base64url_to_base64, character(1), USE.NAMES = FALSE)
}

#' Verify all peer identities (signatures + trusted list)
#' @param identity_info Named list: server -> list(identity_pk, signature) (base64url).
#' @param transport_keys Named list: server -> transport_pk (base64url).
#' @param own_identity_pk Character. This server's identity PK (standard base64).
#' @keywords internal
.verify_all_peer_identities <- function(identity_info, transport_keys,
                                         own_identity_pk) {
  trusted_peers <- .get_trusted_peers()
  for (srv in names(identity_info)) {
    info <- identity_info[[srv]]
    tk <- transport_keys[[srv]]
    if (is.null(info) || is.null(tk)) next

    id_pk <- .base64url_to_base64(info$identity_pk)
    sig   <- .base64url_to_base64(info$signature)
    tk_b64 <- .base64url_to_base64(tk)

    # Skip own identity
    if (id_pk == own_identity_pk) next

    # Verify signature
    if (!.verify_peer_identity(tk_b64, id_pk, sig))
      stop("Identity verification failed for '", srv,
           "': invalid signature on transport PK.", call. = FALSE)

    # Check trusted list (if enforcement on)
    if (!is.null(trusted_peers) && !id_pk %in% trusted_peers)
      stop("Untrusted peer '", srv, "': identity PK not in trusted_peers.",
           call. = FALSE)
  }
  invisible(TRUE)
}

#' Query this server's identity public key
#'
#' Returns the Ed25519 identity PK. Used by admins to discover PKs
#' for configuring trusted_peers lists across a consortium.
#'
#' @return List with identity_pk (base64url).
#' @export
dsvertIdentityPkDS <- function() {
  identity <- .get_identity_keypair()
  list(identity_pk = base64_to_base64url(identity$identity_pk))
}
