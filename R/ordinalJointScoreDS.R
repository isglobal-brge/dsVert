#' @title Secret-share ordinal class masks for the strict joint path
#' @description Outcome-side helper for the non-disclosive ordinal joint
#'   likelihood. It derives one-hot class indicators from cumulative
#'   \code{I(Y <= k)} columns, splits each indicator vector into additive
#'   Ring127 shares, keeps one share locally, and transport-encrypts the
#'   peer share. The analyst/client receives only opaque encrypted blobs and
#'   guarded class counts.
#' @param data_name Name of the aligned data frame.
#' @param indicator_cols Character vector of K-1 cumulative indicator columns.
#' @param level_names Ordered class names.
#' @param output_prefix Prefix for session slots that will hold mask shares.
#' @param peer_pk Transport public key of the peer DCF party.
#' @param session_id MPC session id.
#' @return list(mask_keys, mask_blobs, class_counts).
#' @export
dsvertOrdinalShareClassMasksDS <- function(data_name,
                                            indicator_cols,
                                            level_names,
                                            output_prefix = "ord_mask",
                                            peer_pk,
                                            session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (is.null(peer_pk) || !nzchar(peer_pk))
    stop("peer_pk required", call. = FALSE)
  if (is.null(output_prefix) || !nzchar(output_prefix))
    stop("output_prefix required", call. = FALSE)
  if (!is.character(level_names) || length(level_names) < 3L)
    stop("level_names must contain at least 3 ordered levels", call. = FALSE)
  K <- length(level_names)
  K_minus_1 <- K - 1L
  if (!is.character(indicator_cols) || length(indicator_cols) != K_minus_1)
    stop("indicator_cols must have length K-1", call. = FALSE)

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data))
    stop("Object '", data_name, "' is not a data frame", call. = FALSE)
  n_int <- nrow(data)
  privacy_min <- as.integer(getOption("datashield.privacyLevel", 5L)[[1L]])
  if (n_int < privacy_min)
    stop("Insufficient observations", call. = FALSE)

  ind_mat <- matrix(0L, nrow = n_int, ncol = K_minus_1)
  for (ki in seq_len(K_minus_1)) {
    col <- indicator_cols[ki]
    if (!(col %in% names(data)))
      stop("indicator column '", col, "' not found", call. = FALSE)
    v <- as.integer(data[[col]])
    if (length(v) != n_int || any(!v %in% c(0L, 1L, NA_integer_)))
      stop("indicator column '", col, "' must be binary and length n",
           call. = FALSE)
    if (anyNA(v))
      stop("indicator column '", col, "' contains NA", call. = FALSE)
    ind_mat[, ki] <- v
  }
  class_index <- K - rowSums(ind_mat)
  if (any(class_index < 1L | class_index > K))
    stop("invalid ordinal class derivation from cumulative indicators",
         call. = FALSE)
  class_counts <- as.integer(tabulate(class_index, nbins = K))
  if (any(class_counts > 0L & class_counts < privacy_min)) {
    stop("Disclosure control: ordinal class count below ",
         "datashield.privacyLevel", call. = FALSE)
  }

  ss <- .S(session_id)
  ring <- as.integer(ss$k2_ring %||% 127L)
  if (ring != 127L)
    stop("ordinal strict masks require a Ring127 session", call. = FALSE)
  pk_std <- .base64url_to_base64(peer_pk)
  mask_keys <- sprintf("%s_class_%d", output_prefix, seq_len(K))
  mask_blobs <- character(K)
  for (kk in seq_len(K)) {
    mask <- as.numeric(class_index == kk)
    fp_mask <- .callMpcTool("k2-float-to-fp", list(
      values = mask, frac_bits = 50L, ring = "ring127"))$fp_data
    split <- .callMpcTool("k2-split-fp-share", list(
      data_fp = fp_mask, n = n_int, frac_bits = 50L, ring = "ring127"))
    ss[[mask_keys[kk]]] <- split$own_share
    sealed <- .callMpcTool("transport-encrypt", list(
      data = jsonlite::base64_enc(charToRaw(split$peer_share)),
      recipient_pk = pk_std))
    mask_blobs[kk] <- base64_to_base64url(sealed$sealed)
  }
  names(mask_keys) <- level_names
  names(mask_blobs) <- level_names
  list(stored = TRUE, n = n_int, mask_keys = mask_keys,
       mask_blobs = mask_blobs, class_counts = class_counts)
}

#' @title Receive one strict ordinal class-mask share
#' @description Peer-side counterpart to
#'   \code{dsvertOrdinalShareClassMasksDS}. Decrypts one opaque class-mask
#'   share blob and stores it under \code{output_key}.
#' @param mask_blob_key Session blob slot containing the encrypted mask share.
#' @param output_key Session slot to receive the Ring127 share.
#' @param session_id MPC session id.
#' @return list(stored = TRUE, output_key).
#' @export
dsvertOrdinalReceiveClassMaskDS <- function(mask_blob_key,
                                             output_key,
                                             session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (is.null(mask_blob_key) || !nzchar(mask_blob_key))
    stop("mask_blob_key required", call. = FALSE)
  if (is.null(output_key) || !nzchar(output_key))
    stop("output_key required", call. = FALSE)
  ss <- .S(session_id)
  ring <- as.integer(ss$k2_ring %||% 127L)
  if (ring != 127L)
    stop("ordinal strict masks require a Ring127 session", call. = FALSE)
  blob <- .blob_consume(mask_blob_key, ss)
  if (is.null(blob))
    stop("mask blob missing at '", mask_blob_key, "'", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk))
    stop("transport_sk missing -- call glmRing63TransportInitDS first",
         call. = FALSE)
  dec <- .callMpcTool("transport-decrypt",
                       list(sealed = .base64url_to_base64(blob),
                            recipient_sk = tsk))
  ss[[output_key]] <- rawToChar(jsonlite::base64_dec(dec$data))
  list(stored = TRUE, output_key = output_key)
}

#' @title Extract column j of an nxp Ring127 share matrix into n-vector slot
#' @description The K=2 X share is stored as a single n*p flat row-major
#'   Ring127 share (16 bytes per entry). For `.ring127_vecmul` operations
#'   on per-column X slices, we need length-n session slots. This primitive
#'   gathers row-major indices `[col_idx, p+col_idx, 2p+col_idx, ...]`
#'   from the flat share into a new slot. This is pure local share
#'   rearrangement; the additive-share property is preserved row-by-row.
#' @param matrix_key character. Source flat n*p Ring127 share slot.
#' @param n integer. Number of rows.
#' @param p integer. Number of columns.
#' @param col_idx integer. 1-indexed column to extract.
#' @param output_key character. Destination length-n share slot.
#' @param session_id MPC session id.
#' @return list(stored = TRUE, n, output_key).
#' @export
dsvertOrdinalExtractXColumnDS <- function(matrix_key, n, p, col_idx,
                                            output_key, session_id) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  if (is.null(output_key) || !nzchar(output_key))
    stop("output_key required", call. = FALSE)
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertOrdinalExtractXColumnDS")
  flat <- ss[[matrix_key]]
  if (is.null(flat))
    stop("matrix slot '", matrix_key, "' empty", call. = FALSE)
  n_int <- as.integer(n)
  p_int <- as.integer(p)
  col_int <- as.integer(col_idx)
  if (col_int < 1L || col_int > p_int)
    stop("col_idx must be in [1, p]", call. = FALSE)
  raw_all <- jsonlite::base64_dec(flat)
  expected <- as.integer(n_int * p_int * 16L)
  if (length(raw_all) != expected)
    stop(sprintf("matrix slot expected %d bytes (n=%d, p=%d, 16/elem), got %d",
                  expected, n_int, p_int, length(raw_all)), call. = FALSE)

  col_raw <- raw(n_int * 16L)
  base <- (col_int - 1L) * 16L
  step <- p_int * 16L
  for (i in seq_len(n_int)) {
    src <- base + (i - 1L) * step
    dst <- (i - 1L) * 16L
    col_raw[(dst + 1L):(dst + 16L)] <- raw_all[(src + 1L):(src + 16L)]
  }
  ss[[output_key]] <- jsonlite::base64_enc(col_raw)
  list(stored = TRUE, n = n_int, output_key = output_key)
}
