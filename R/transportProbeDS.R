# Stateless, data-free request-size probe for direct DSI transports.
#
# The caller supplies only public ASCII padding and its digest.  This endpoint
# does not open an MPC session, inspect protected symbols, touch a DP ledger or
# retain any state.  Its sole purpose is to let the client prove that a complete
# connector/proxy/parser path accepts a candidate expression before any opaque
# protocol payload is transmitted.

.DSVERT_TRANSPORT_PROBE_VERSION <- "dsvert-transport-probe-v1"
.DSVERT_TRANSPORT_RESPONSE_PROBE_VERSION <-
  "dsvert-transport-response-probe-v1"
.DSVERT_TRANSPORT_PROBE_ABSOLUTE_MAX <- 8L * 1024L^2
.DSVERT_TRANSPORT_PROBE_MIN <- 16L * 1024L

.dsvert_transport_probe_max_padding <- function() {
  value <- getOption(
    "dsvert.transport_probe_max_padding_bytes",
    .DSVERT_TRANSPORT_PROBE_ABSOLUTE_MAX)
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) ||
      value < .DSVERT_TRANSPORT_PROBE_MIN ||
      value > .DSVERT_TRANSPORT_PROBE_ABSOLUTE_MAX) {
    stop("Invalid server transport-probe byte bound.", call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_transport_probe_max_response <- function() {
  value <- getOption(
    "dsvert.transport_probe_max_response_bytes",
    .DSVERT_TRANSPORT_PROBE_ABSOLUTE_MAX)
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || value != floor(value) ||
      value < .DSVERT_TRANSPORT_PROBE_MIN ||
      value > .DSVERT_TRANSPORT_PROBE_ABSOLUTE_MAX) {
    stop("Invalid server transport-response-probe byte bound.",
         call. = FALSE)
  }
  as.numeric(value)
}

#' Verify one data-free DSI request geometry (AGGREGATE)
#'
#' This control-plane endpoint accepts only public printable-ASCII padding.
#' It verifies the caller-supplied SHA-256 and returns a small typed
#' acknowledgement. It does not access data, MPC sessions, privacy ledgers or
#' persisted state. The byte limit is an availability bound, not a query or
#' privacy-budget limit.
#'
#' @param nonce A fresh public probe identifier.
#' @param padding Public printable-ASCII probe bytes.
#' @param padding_sha256 Lower-case SHA-256 of `padding`.
#' @param response_padding_chars Optional public response-padding size. It is
#'   absent for the byte-identical v1 request probe. A positive value selects
#'   the data-free response-probe extension.
#' @return A small typed acknowledgement of the received padding.
#' @export
dsvertTransportProbeDS <- function(
    nonce, padding, padding_sha256, response_padding_chars = NULL) {
  if (!is.character(nonce) || length(nonce) != 1L || is.na(nonce) ||
      !grepl("^tp_[0-9a-f]{32}$", nonce)) {
    stop("Invalid transport-probe nonce.", call. = FALSE)
  }
  if (!is.character(padding) || length(padding) != 1L || is.na(padding) ||
      !nzchar(padding) ||
      !identical(nchar(padding, type = "chars"),
                 nchar(padding, type = "bytes")) ||
      !grepl("^[ -~]+\\z", padding, perl = TRUE, useBytes = TRUE)) {
    stop("Transport-probe padding must be printable ASCII.", call. = FALSE)
  }
  padding_chars <- nchar(padding, type = "bytes")
  server_max <- .dsvert_transport_probe_max_padding()
  if (!is.finite(padding_chars) || padding_chars > server_max) {
    stop("Transport-probe padding exceeds the server byte bound.",
         call. = FALSE)
  }
  if (!is.character(padding_sha256) || length(padding_sha256) != 1L ||
      is.na(padding_sha256) ||
      !grepl("^[0-9a-f]{64}$", padding_sha256) ||
      !identical(
        digest::digest(padding, algo = "sha256", serialize = FALSE),
        padding_sha256)) {
    stop("Transport-probe payload hash mismatch.", call. = FALSE)
  }
  request_ack <- list(
    version = .DSVERT_TRANSPORT_PROBE_VERSION,
    nonce = nonce,
    padding_chars = as.numeric(padding_chars),
    padding_sha256 = padding_sha256,
    server_max_padding_chars = as.numeric(server_max))
  if (is.null(response_padding_chars)) return(request_ack)

  response_padding_chars <- suppressWarnings(
    as.numeric(response_padding_chars))
  response_max <- .dsvert_transport_probe_max_response()
  if (length(response_padding_chars) != 1L ||
      is.na(response_padding_chars) || !is.finite(response_padding_chars) ||
      response_padding_chars != floor(response_padding_chars) ||
      response_padding_chars < .DSVERT_TRANSPORT_PROBE_MIN ||
      response_padding_chars > response_max) {
    stop("Transport-response-probe padding exceeds the server byte bound.",
         call. = FALSE)
  }
  response_padding <- strrep("R", response_padding_chars)
  list(
    version = .DSVERT_TRANSPORT_RESPONSE_PROBE_VERSION,
    nonce = nonce,
    padding_chars = as.numeric(padding_chars),
    padding_sha256 = padding_sha256,
    server_max_padding_chars = as.numeric(server_max),
    response_padding_chars = as.numeric(response_padding_chars),
    response_padding_sha256 = digest::digest(
      response_padding, algo = "sha256", serialize = FALSE),
    server_max_response_padding_chars = as.numeric(response_max),
    response_padding = response_padding)
}
