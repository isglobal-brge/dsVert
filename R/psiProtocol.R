#' @title ECDH-PSI Record Alignment - Server-Side Functions
#' @description These functions implement Elliptic Curve Diffie-Hellman Private Set
#'   Intersection (ECDH-PSI) for privacy-preserving record alignment across vertically
#'   partitioned data. Unlike SHA-256 hashing, ECDH-PSI ensures the client cannot
#'   reverse-engineer patient identifiers from the exchanged messages.
#'
#' @details
#' The protocol exploits the commutativity of scalar multiplication on P-256:
#' \eqn{\alpha \cdot (\beta \cdot H(id)) = \beta \cdot (\alpha \cdot H(id))}.
#'
#' Security holds under the DDH assumption on P-256 (semi-honest model):
#' \itemize{
#'   \item The client sees only opaque elliptic curve points (not reversible)
#'   \item Each target server learns only the intersection with the reference
#'   \item No party can perform dictionary attacks on identifiers
#' }
#'
#' @references
#' De Cristofaro, E. & Tsudik, G. (2010). "Practical Private Set Intersection
#' Protocols with Linear Complexity". \emph{FC 2010}.
#'
#' @name psi-protocol
NULL

# ============================================================================
# Phase 1 / Phase 3 own-masking: Hash IDs to P-256 points, multiply by scalar
# ============================================================================

#' Mask identifiers using ECDH (aggregate function)
#'
#' Hashes identifiers to P-256 curve points and multiplies by a random scalar.
#' The scalar is stored locally and NEVER returned to the client.
#'
#' @param data_name Character. Name of data frame.
#' @param id_col Character. Name of identifier column.
#'
#' @return List with masked_points (base64url) and n (count).
#' @export
psiMaskIdsDS <- function(data_name, id_col) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!id_col %in% names(data)) {
    stop("Column '", id_col, "' not found in data frame", call. = FALSE)
  }

  ids <- as.character(data[[id_col]])

  # Passing scalar="" tells the Go binary to generate a fresh random scalar.
  # The binary hashes each ID to a P-256 curve point using try-and-increment
  # (domain separator "dsVert-PSI-v1"), then multiplies by the scalar.
  result <- .callMheTool("psi-mask", list(
    ids = as.list(ids),
    scalar = ""
  ))

  # SECURITY: the scalar is the server's secret. If the client knew it,
  # they could reverse the hash-to-curve and recover patient IDs from the
  # masked points. Storing it only in .mhe_storage keeps it on-server.
  .mhe_storage$psi_scalar <- result$scalar

  list(
    masked_points = sapply(result$masked_points, base64_to_base64url, USE.NAMES = FALSE),
    n = length(ids)
  )
}

# ============================================================================
# Phase 3 combined: Target processes ref points AND masks own IDs
# ============================================================================

#' Process reference points on target server (aggregate function)
#'
#' Generates own scalar, double-masks reference points (stored locally for
#' Phase 7 matching), and returns own masked IDs to the client.
#'
#' @param data_name Character. Name of data frame.
#' @param id_col Character. Name of identifier column.
#' @param ref_masked_points Character vector. Masked points from reference
#'   server (base64url encoded). Ignored when \code{from_storage = TRUE}.
#' @param from_storage Logical. If \code{TRUE}, read \code{ref_masked_points}
#'   from server-side blob storage (comma-separated, stored via
#'   \code{\link{mheStoreBlobDS}}) instead of inline argument.
#'   Default \code{FALSE}.
#'
#' @return List with own_masked_points (base64url) and n (count).
#' @export
psiProcessTargetDS <- function(data_name, id_col, ref_masked_points = NULL,
                               from_storage = FALSE) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (!is.data.frame(data)) {
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  }
  if (!id_col %in% names(data)) {
    stop("Column '", id_col, "' not found in data frame", call. = FALSE)
  }

  # Read ref_masked_points from blob storage or inline argument
  if (from_storage) {
    blobs <- .mhe_storage$blobs
    if (is.null(blobs) || is.null(blobs[["ref_masked_points"]])) {
      stop("No ref_masked_points blob stored", call. = FALSE)
    }
    ref_masked_points <- strsplit(blobs[["ref_masked_points"]], ",", fixed = TRUE)[[1]]
    .mhe_storage$blobs <- NULL
  }

  ids <- as.character(data[[id_col]])

  # Mask own IDs (generates new random scalar)
  own_result <- .callMheTool("psi-mask", list(
    ids = as.list(ids),
    scalar = ""
  ))

  # Store scalar for later use by psiDoubleMaskDS (never returned)
  .mhe_storage$psi_scalar <- own_result$scalar

  # Convert ref points from base64url to standard base64 for Go tool
  ref_points_std <- sapply(ref_masked_points, .base64url_to_base64, USE.NAMES = FALSE)

  # Double-mask ref points with own scalar
  ref_dm <- .callMheTool("psi-double-mask", list(
    points = as.list(ref_points_std),
    scalar = own_result$scalar
  ))

  # Store double-masked ref points for Phase 7 matching. These are
  # β·(α·H(id)) for each ref ID. In Phase 7, the target will receive
  # α·(β·H(id)) for its own IDs; by commutativity α·β·H(id) = β·α·H(id),
  # matching points identify common IDs. Ref indices track the reference
  # server's row ordering so the target can reorder its data to match.
  .mhe_storage$psi_ref_dm <- ref_dm$double_masked_points
  .mhe_storage$psi_ref_indices <- as.integer(0:(length(ref_masked_points) - 1L))

  # Return own masked points as base64url (for client to relay to ref)
  list(
    own_masked_points = sapply(own_result$masked_points, base64_to_base64url, USE.NAMES = FALSE),
    n = length(ids)
  )
}

# ============================================================================
# Phase 5: Reference server double-masks target points
# ============================================================================

#' Double-mask points using stored scalar (aggregate function)
#'
#' Multiplies received curve points by the scalar generated in Phase 1
#' (stored by psiMaskIdsDS).
#'
#' @param points Character vector. Masked points to double-mask (base64url).
#'   Ignored when \code{from_storage = TRUE}.
#' @param from_storage Logical. If \code{TRUE}, read \code{points} from
#'   server-side blob storage (comma-separated). Default \code{FALSE}.
#'
#' @return List with double_masked_points (base64url).
#' @export
psiDoubleMaskDS <- function(points = NULL, from_storage = FALSE) {
  if (is.null(.mhe_storage$psi_scalar)) {
    stop("PSI scalar not stored. Call psiMaskIdsDS first.", call. = FALSE)
  }

  # Read points from blob storage or inline argument
  if (from_storage) {
    blobs <- .mhe_storage$blobs
    if (is.null(blobs) || is.null(blobs[["target_masked_points"]])) {
      stop("No target_masked_points blob stored", call. = FALSE)
    }
    points <- strsplit(blobs[["target_masked_points"]], ",", fixed = TRUE)[[1]]
    .mhe_storage$blobs <- NULL
  }

  points_std <- sapply(points, .base64url_to_base64, USE.NAMES = FALSE)

  result <- .callMheTool("psi-double-mask", list(
    points = as.list(points_std),
    scalar = .mhe_storage$psi_scalar
  ))

  list(
    double_masked_points = sapply(result$double_masked_points, base64_to_base64url, USE.NAMES = FALSE)
  )
}

# ============================================================================
# Phase 7: Target matches double-masked points and aligns data
# ============================================================================

#' Match and align data using PSI result (assign function)
#'
#' Matches received double-masked own points against stored double-masked
#' reference points. Creates an aligned data frame ordered by reference index.
#'
#' @param data_name Character. Name of data frame to align.
#' @param own_double_masked Character vector. Double-masked own points
#'   from reference server (base64url). Ignored when \code{from_storage = TRUE}.
#' @param from_storage Logical. If \code{TRUE}, read \code{own_double_masked}
#'   from server-side blob storage (comma-separated). Default \code{FALSE}.
#'
#' @return Aligned data frame (assigned to server environment).
#' @export
psiMatchAndAlignDS <- function(data_name, own_double_masked = NULL,
                               from_storage = FALSE) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (is.null(.mhe_storage$psi_ref_dm)) {
    stop("PSI ref double-masked points not stored. Call psiProcessTargetDS first.", call. = FALSE)
  }

  # Read from blob storage or inline argument
  if (from_storage) {
    blobs <- .mhe_storage$blobs
    if (is.null(blobs) || is.null(blobs[["double_masked_points"]])) {
      stop("No double_masked_points blob stored", call. = FALSE)
    }
    own_double_masked <- strsplit(blobs[["double_masked_points"]], ",", fixed = TRUE)[[1]]
    .mhe_storage$blobs <- NULL
  }

  # Convert received points from base64url to standard base64
  own_dm_std <- sapply(own_double_masked, .base64url_to_base64, USE.NAMES = FALSE)

  # Call psi-match: find which own rows match which ref indices
  result <- .callMheTool("psi-match", list(
    own_doubled = as.list(own_dm_std),
    ref_doubled = as.list(.mhe_storage$psi_ref_dm),
    ref_indices = as.list(.mhe_storage$psi_ref_indices)
  ))

  # Store matched ref indices for Phase 8 multi-server intersection
  .mhe_storage$psi_matched_ref_indices <- as.integer(result$matched_ref_indices)

  # Clean up Phase 3 state (no longer needed)
  .mhe_storage$psi_ref_dm <- NULL
  .mhe_storage$psi_ref_indices <- NULL

  if (result$n_matched == 0) {
    stop("PSI: no matching records found", call. = FALSE)
  }

  # Reorder data by matched_own_rows. The Go psi-match command returns
  # results sorted by ref_index, so this reordering aligns the target's
  # rows to the reference server's row order. +1L converts from Go's
  # 0-based indexing to R's 1-based indexing.
  aligned_data <- data[as.integer(result$matched_own_rows) + 1L, , drop = FALSE]
  rownames(aligned_data) <- NULL

  aligned_data
}

# ============================================================================
# Phase 7 for reference server: Self-align (identity)
# ============================================================================

#' Self-align reference server data (assign function)
#'
#' Creates an aligned copy of the data on the reference server. Since
#' the reference defines the index order, this is an identity operation.
#' Stores all row indices as matched for Phase 8.
#'
#' @param data_name Character. Name of data frame.
#'
#' @return Copy of data frame (assigned to server environment).
#' @export
psiSelfAlignDS <- function(data_name) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  # All ref indices are matched (the ref matches itself)
  .mhe_storage$psi_matched_ref_indices <- as.integer(0:(nrow(data) - 1L))

  # Return copy (same order — ref is the reference)
  data
}

# ============================================================================
# Phase 8 helpers: Multi-server intersection
# ============================================================================

#' Get matched reference indices (aggregate function)
#'
#' Returns the set of reference indices that this server matched during
#' PSI alignment. Used by the client to compute the multi-server intersection.
#'
#' @return Integer vector of matched reference indices (0-based).
#' @export
psiGetMatchedIndicesDS <- function() {
  if (is.null(.mhe_storage$psi_matched_ref_indices)) {
    stop("PSI matched indices not available. Run alignment first.", call. = FALSE)
  }
  .mhe_storage$psi_matched_ref_indices
}

#' Filter aligned data to common intersection (assign function)
#'
#' Keeps only the rows corresponding to reference indices that are present
#' on ALL servers. This is the final step of the PSI alignment protocol.
#'
#' @param data_name Character. Name of aligned data frame.
#' @param common_indices Integer vector. Reference indices common to all
#'   servers (0-based). Ignored when \code{from_storage = TRUE}.
#' @param from_storage Logical. If \code{TRUE}, read \code{common_indices}
#'   from server-side blob storage (comma-separated integers).
#'   Default \code{FALSE}.
#'
#' @return Filtered data frame (assigned to server environment).
#' @export
psiFilterCommonDS <- function(data_name, common_indices = NULL,
                              from_storage = FALSE) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())

  if (is.null(.mhe_storage$psi_matched_ref_indices)) {
    stop("PSI matched indices not available.", call. = FALSE)
  }

  # Read from blob storage or inline argument
  if (from_storage) {
    blobs <- .mhe_storage$blobs
    if (is.null(blobs) || is.null(blobs[["common_indices"]])) {
      stop("No common_indices blob stored", call. = FALSE)
    }
    common_indices <- as.integer(strsplit(blobs[["common_indices"]], ",", fixed = TRUE)[[1]])
    .mhe_storage$blobs <- NULL
  } else {
    common_indices <- as.integer(common_indices)
  }
  n_common <- length(common_indices)
  n_original <- nrow(data)

  # Disclosure control: nfilter.subset (dsBase pattern)
  # Prevents creating subsets so small that individuals become identifiable.
  settings <- .dsvert_disclosure_settings()
  if (n_common > 0 && n_common < settings$nfilter.subset) {
    stop(
      "Disclosure control: PSI intersection too small (",
      n_common, " records). Minimum allowed: nfilter.subset = ",
      settings$nfilter.subset, ".",
      call. = FALSE
    )
  }

  # Differencing check (dsBase dataFrameSubsetDS1 pattern):
  # if |original - intersection| is small but nonzero, an attacker could
  # identify the excluded individuals by differencing.
  n_excluded <- n_original - n_common
  if (n_excluded > 0 && n_excluded < settings$nfilter.subset) {
    stop(
      "Disclosure control: PSI exclusion set too small (",
      n_excluded, " excluded records). An attacker could identify excluded ",
      "individuals by differencing. Minimum exclusion: nfilter.subset = ",
      settings$nfilter.subset, ".",
      call. = FALSE
    )
  }

  # After Phase 7, each server has data aligned to the reference order,
  # but different servers may have matched different subsets of ref IDs.
  # Phase 8 intersects these subsets to find IDs present on ALL servers.
  # Here we filter down to only the common rows.
  keep <- .mhe_storage$psi_matched_ref_indices %in% common_indices
  filtered_data <- data[keep, , drop = FALSE]
  rownames(filtered_data) <- NULL

  # Clean up PSI state — scalars and indices are no longer needed.
  # This also prevents accidental reuse in a subsequent PSI call.
  .mhe_storage$psi_scalar <- NULL
  .mhe_storage$psi_matched_ref_indices <- NULL

  filtered_data
}
