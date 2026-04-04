#' @title K=2 MPC Backend for Binomial/Poisson GLMs
#' @description Server-side functions for the dedicated two-party MPC backend.
#'   The sidecar binary (k2-mpc-tool) executes the full training loop internally
#'   over a direct mTLS channel between the two servers. Only final coefficients
#'   and scalar diagnostics are returned — no per-iteration gradients, no
#'   observation-level eta/mu/residual.
#'
#' @details
#' This backend replaces HE-Link for K=2 binomial and Poisson GLMs.
#' The sidecar uses:
#' \itemize{
#'   \item Binomial: secure sigmoid (Agarwal et al. 2022) via fss_machine_learning
#'   \item Poisson: secure exponentiation (Kelkar et al. 2022) via fss_machine_learning
#' }
#'
#' @name k2-mpc-backend
NULL

# ============================================================================
# Step 1: Prepare local data + sidecar configuration
# ============================================================================

#' Prepare K=2 MPC job
#'
#' Validates the job, creates job-scoped storage, writes local data in binary
#' fixed-point format, and allocates sidecar endpoint.
#'
#' @param data_name Character. Standardized data frame name.
#' @param y_var Character or NULL. Response variable (label server only).
#' @param x_vars Character vector. Feature column names on this server.
#' @param family Character. "binomial" or "poisson".
#' @param role Character. "label" or "nonlabel".
#' @param job_id Character. Unique job identifier.
#' @param manifest Character. Canonical manifest hash for peer validation.
#' @param lambda Numeric. L2 regularization.
#' @param max_iter Integer. Maximum iterations.
#' @param tol Numeric. Convergence tolerance.
#' @param step_size Numeric or NULL. Learning rate (NULL = auto).
#' @param frac_bits Integer. Fixed-point fractional bits.
#' @param session_id Character or NULL.
#'
#' @return List with sidecar endpoint metadata (host, port, cert fingerprint, role).
#' @export
k2MpcPrepareDS <- function(data_name, y_var = NULL, x_vars, family, role,
                            job_id, manifest, lambda = 1e-4,
                            max_iter = 200L, tol = 1e-6,
                            step_size = NULL, frac_bits = 20L,
                            session_id = NULL) {
  ss <- .S(session_id)

  # Validate
  if (!family %in% c("binomial", "poisson"))
    stop("K=2 MPC backend only supports binomial and poisson", call. = FALSE)
  if (!role %in% c("label", "nonlabel"))
    stop("role must be 'label' or 'nonlabel'", call. = FALSE)

  # Resolve data
  data <- .resolveData(data_name, parent.frame(), session_id)
  X <- as.matrix(data[, x_vars, drop = FALSE])
  n <- nrow(X)
  p_local <- ncol(X)

  # Disclosure controls
  privacy_level <- getOption("datashield.privacyLevel", 5)
  if (n < privacy_level)
    stop("Insufficient observations for privacy-preserving analysis", call. = FALSE)
  .check_glm_disclosure(X)

  # Get y if label
  y <- NULL
  if (role == "label" && !is.null(y_var)) {
    y <- as.numeric(data[[y_var]])
    .check_glm_disclosure(X, y)
  }

  # Create job-scoped storage
  job_dir <- file.path(tempdir(), paste0("k2mpc_", job_id))
  dir.create(job_dir, recursive = TRUE, showWarnings = FALSE)

  # Write local input in binary format
  # Format: header (n, p_local, frac_bits, has_y) + X matrix + optional y
  input_file <- file.path(job_dir, "input.bin")
  con <- file(input_file, "wb")
  writeBin(as.integer(c(n, p_local, frac_bits, !is.null(y))), con, size = 4L)
  # Write X row-major as float64
  for (i in seq_len(n)) {
    writeBin(as.double(X[i, ]), con, size = 8L)
  }
  if (!is.null(y)) {
    writeBin(as.double(y), con, size = 8L)
  }
  close(con)

  # Find k2-mpc-tool binary
  k2_binary <- .findK2MpcTool()

  # Allocate port for sidecar
  base_port <- getOption("dsvert.k2_mpc_base_port", 9100L)
  # Use job_id hash to pick a port offset (avoid collisions)
  port_offset <- abs(as.integer(chartr("abcdef", "123456",
    substr(digest::digest(job_id, algo = "md5"), 1, 4)))) %% 100
  sidecar_port <- base_port + port_offset

  # TLS configuration
  tls_cert <- getOption("dsvert.k2_mpc_tls_cert", NULL)
  tls_key <- getOption("dsvert.k2_mpc_tls_key", NULL)
  tls_ca <- getOption("dsvert.k2_mpc_tls_ca", NULL)

  # Get host
  sidecar_host <- getOption("dsvert.k2_mpc_host", "localhost")

  # Compute cert fingerprint
  cert_fingerprint <- ""
  if (!is.null(tls_cert) && file.exists(tls_cert)) {
    cert_fingerprint <- digest::digest(readBin(tls_cert, "raw", n = 1e6), algo = "sha256")
  }

  # Store job state
  ss$k2mpc_job_id <- job_id
  ss$k2mpc_job_dir <- job_dir
  ss$k2mpc_input_file <- input_file
  ss$k2mpc_role <- role
  ss$k2mpc_family <- family
  ss$k2mpc_manifest <- manifest
  ss$k2mpc_port <- sidecar_port
  ss$k2mpc_lambda <- lambda
  ss$k2mpc_max_iter <- max_iter
  ss$k2mpc_tol <- tol
  ss$k2mpc_step_size <- step_size
  ss$k2mpc_frac_bits <- frac_bits
  ss$k2mpc_binary <- k2_binary

  list(
    host = sidecar_host,
    port = sidecar_port,
    cert_fingerprint = cert_fingerprint,
    role = role,
    manifest_hash = manifest,
    n_obs = n,
    p_local = p_local
  )
}

# ============================================================================
# Step 2: Store peer endpoint info
# ============================================================================

#' Store peer's sidecar endpoint for K=2 MPC
#'
#' Validates peer metadata (job_id, manifest, role pairing) and stores
#' the peer endpoint for the sidecar to connect to.
#'
#' @param job_id Character. Must match the prepared job.
#' @param peer_info List with: host, port, cert_fingerprint, role, manifest_hash.
#' @param session_id Character or NULL.
#'
#' @return List with validated = TRUE.
#' @export
k2MpcStorePeerDS <- function(job_id, peer_info, session_id = NULL) {
  ss <- .S(session_id)

  # Validate job_id
  if (is.null(ss$k2mpc_job_id) || ss$k2mpc_job_id != job_id)
    stop("Job ID mismatch or no job prepared", call. = FALSE)

  # Validate manifest
  if (peer_info$manifest_hash != ss$k2mpc_manifest)
    stop("Manifest hash mismatch — possible data integrity issue", call. = FALSE)

  # Validate role pairing (must be complementary)
  if (peer_info$role == ss$k2mpc_role)
    stop("Role conflict: both servers claim the same role", call. = FALSE)

  # Optional: validate peer fingerprint against pinned peers
  if (isTRUE(getOption("dsvert.k2_mpc_require_pinned_peers", FALSE))) {
    # TODO: check peer_info$cert_fingerprint against allowlist
  }

  # Store peer info
  ss$k2mpc_peer_host <- peer_info$host
  ss$k2mpc_peer_port <- peer_info$port
  ss$k2mpc_peer_fingerprint <- peer_info$cert_fingerprint

  list(validated = TRUE)
}

# ============================================================================
# Step 3: Run the MPC sidecar
# ============================================================================

#' Run K=2 MPC sidecar training
#'
#' Launches k2-mpc-tool, blocks until the protocol completes, reads the
#' output, and returns only safe results (final coefficients + diagnostics).
#'
#' @param job_id Character. Must match the prepared job.
#' @param session_id Character or NULL.
#'
#' @return List with: beta (local block), intercept (label only), iterations,
#'   converged, deviance (label only), runtime_seconds.
#' @export
k2MpcRunDS <- function(job_id, session_id = NULL) {
  ss <- .S(session_id)

  if (is.null(ss$k2mpc_job_id) || ss$k2mpc_job_id != job_id)
    stop("Job ID mismatch", call. = FALSE)
  if (is.null(ss$k2mpc_peer_host))
    stop("Peer info not stored — call k2MpcStorePeerDS first", call. = FALSE)

  output_file <- file.path(ss$k2mpc_job_dir, "result.json")

  # Build command line (matches researcher's CLI contract)
  args <- c(
    "fit",
    "--job-id", job_id,
    "--protocol-version", "1",
    "--family", ss$k2mpc_family,
    "--role", ss$k2mpc_role,
    "--party-id", if (ss$k2mpc_role == "label") "0" else "1",
    "--peer-host", ss$k2mpc_peer_host,
    "--peer-port", as.character(ss$k2mpc_peer_port),
    "--input-file", ss$k2mpc_input_file,
    "--output-file", output_file,
    "--max-iter", as.character(ss$k2mpc_max_iter),
    "--tol", as.character(ss$k2mpc_tol),
    "--lambda", as.character(ss$k2mpc_lambda),
    "--fixed-point-frac-bits", as.character(ss$k2mpc_frac_bits)
  )

  # Add optional step size
  if (!is.null(ss$k2mpc_step_size))
    args <- c(args, "--step-size", as.character(ss$k2mpc_step_size))

  # Add TLS if configured
  tls_cert <- getOption("dsvert.k2_mpc_tls_cert", NULL)
  tls_key <- getOption("dsvert.k2_mpc_tls_key", NULL)
  tls_ca <- getOption("dsvert.k2_mpc_tls_ca", NULL)
  if (!is.null(tls_cert)) args <- c(args, "--tls-cert", tls_cert)
  if (!is.null(tls_key)) args <- c(args, "--tls-key", tls_key)
  if (!is.null(tls_ca)) args <- c(args, "--tls-ca", tls_ca)

  # Add manifest hash for sidecar handshake
  args <- c(args, "--manifest-hash", ss$k2mpc_manifest)

  # Launch sidecar
  t0 <- proc.time()
  stderr_file <- file.path(ss$k2mpc_job_dir, "stderr.log")

  status <- system2(
    command = ss$k2mpc_binary,
    args = args,
    stdout = "",  # stdout unused, results go to output_file
    stderr = stderr_file,
    timeout = ss$k2mpc_max_iter * 60  # generous timeout
  )

  elapsed <- (proc.time() - t0)[["elapsed"]]

  if (status != 0) {
    stderr_content <- tryCatch(readLines(stderr_file, warn = FALSE),
                               error = function(e) "unable to read stderr")
    stop(sprintf("k2-mpc-tool failed (exit %d): %s",
                 status, paste(tail(stderr_content, 5), collapse = "\n")),
         call. = FALSE)
  }

  # Read result
  if (!file.exists(output_file))
    stop("k2-mpc-tool did not produce output file", call. = FALSE)

  result <- jsonlite::fromJSON(readLines(output_file, warn = FALSE))

  # Return only safe outputs
  safe_output <- list(
    beta = as.numeric(result$beta),
    iterations = as.integer(result$iterations),
    converged = isTRUE(result$converged),
    runtime_seconds = elapsed
  )

  # Label-only outputs
  if (ss$k2mpc_role == "label") {
    if (!is.null(result$intercept))
      safe_output$intercept <- as.numeric(result$intercept)
    if (!is.null(result$deviance))
      safe_output$deviance <- as.numeric(result$deviance)
    if (!is.null(result$null_deviance))
      safe_output$null_deviance <- as.numeric(result$null_deviance)
  }

  safe_output
}

# ============================================================================
# Step 4: Cleanup
# ============================================================================

#' Clean up K=2 MPC job resources
#'
#' Kills the sidecar if still running, removes temp files, clears job state.
#'
#' @param job_id Character.
#' @param session_id Character or NULL.
#'
#' @return TRUE
#' @export
k2MpcCleanupDS <- function(job_id, session_id = NULL) {
  ss <- .S(session_id)

  if (!is.null(ss$k2mpc_job_dir) && dir.exists(ss$k2mpc_job_dir)) {
    # Overwrite sensitive files before deletion
    for (f in list.files(ss$k2mpc_job_dir, full.names = TRUE)) {
      tryCatch({
        sz <- file.info(f)$size
        if (!is.na(sz) && sz > 0) {
          con <- file(f, "wb")
          writeBin(raw(as.integer(min(sz, 1e7))), con)
          close(con)
        }
      }, error = function(e) NULL)
    }
    unlink(ss$k2mpc_job_dir, recursive = TRUE)
  }

  # Clear job state
  for (key in grep("^k2mpc_", ls(ss), value = TRUE)) {
    ss[[key]] <- NULL
  }

  gc(verbose = FALSE)
  TRUE
}

# ============================================================================
# Helper: find k2-mpc-tool binary
# ============================================================================

#' @keywords internal
.findK2MpcTool <- function() {
  # Check option first
  bin <- getOption("dsvert.k2_mpc_binary", NULL)
  if (!is.null(bin) && file.exists(bin)) return(bin)

  # Check in inst/k2-mpc-tool/
  pkg_dir <- system.file("k2-mpc-tool", package = "dsVert")
  if (nchar(pkg_dir) > 0) {
    # Platform-specific
    os <- .Platform$OS.type
    arch <- Sys.info()["machine"]
    if (os == "unix") {
      if (grepl("arm|aarch", arch)) {
        plat <- "linux-arm64"
      } else {
        plat <- "linux-amd64"
      }
      if (Sys.info()["sysname"] == "Darwin") {
        plat <- if (grepl("arm|aarch", arch)) "darwin-arm64" else "darwin-amd64"
      }
    } else {
      plat <- "windows-amd64"
    }

    candidates <- c(
      file.path(pkg_dir, "bin", plat, "k2-mpc-tool"),
      file.path(pkg_dir, "k2-mpc-tool")
    )
    for (c in candidates) {
      if (file.exists(c)) return(c)
    }
  }

  stop("k2-mpc-tool binary not found. Set options(dsvert.k2_mpc_binary = '/path/to/k2-mpc-tool')",
       call. = FALSE)
}
