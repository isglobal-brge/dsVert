#' @title Ring127 affine combine — server-side local op for Horner/NR
#'   orchestration.
#' @description Computes, on one party's Ring127 shares:
#'   \deqn{out[i] = sign_a \cdot a[i] + sign_b \cdot b[i] +
#'                  (public_const \text{ if party 0 else } 0)}
#'   where \eqn{sign_a, sign_b \in \{-1, 0, +1\}}. The result is stored back
#'   into the session slot named \code{output_key}. No cross-party
#'   communication — the client orchestrates one such call on each party
#'   per Horner / NR iteration.
#'
#'   Called by \code{dsVertClient:::.exp127_round} and
#'   \code{dsVertClient:::.recip127_round} (task #116 step 5c(I-c)). Not
#'   Ring63-applicable; fails fast if invoked in a session whose ring is
#'   not 127.
#'
#' @param a_key Session slot holding the first Ring127 share vector (base64
#'   Uint128 at 16 B/elt). Ignored when \code{sign_a == 0}; may be
#'   \code{NULL} in that case.
#' @param b_key Session slot holding the second Ring127 share vector.
#'   Ignored when \code{sign_b == 0}.
#' @param sign_a Integer in \{-1, 0, +1\}. Sign coefficient for the a slot.
#' @param sign_b Integer in \{-1, 0, +1\}. Sign coefficient for the b slot.
#' @param public_const_fp Base64 string encoding a single Ring127 FP Uint128
#'   (16 B). Added to every element on party 0 only. \code{NULL} for no
#'   constant.
#' @param is_party0 Logical. TRUE for the coordinator (outcome-holder)
#'   party; controls whether \code{public_const_fp} is applied.
#' @param output_key Session slot name to store the resulting share vector.
#' @param n Integer vector length.
#' @param session_id MPC session identifier.
#' @return list(stored = TRUE, output_key, n).
#' @keywords internal
#' @export
# Opal DSL parser chokes on `=`, `+` and `/` inside double-quoted
# string literals. Client converts base64 → base64url; we restore
# standard base64 via the already-existing .base64url_to_base64
# helper in mpcUtils.R (documented since pre-session as the
# canonical "Opal/Rock string parameter" workaround).
.b64_pad <- function(x) {
  if (is.null(x) || !nzchar(x)) return(x)
  .base64url_to_base64(x)
}

k2Ring127AffineCombineDS <- function(a_key = NULL, b_key = NULL,
                                     sign_a = 0L, sign_b = 0L,
                                     public_const_fp = NULL,
                                     is_party0 = FALSE,
                                     output_key,
                                     n,
                                     session_id = NULL) {
  public_const_fp <- .b64_pad(public_const_fp)
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (is.null(output_key) || !nzchar(output_key)) {
    stop("output_key required", call. = FALSE)
  }
  sign_a <- as.integer(sign_a)
  sign_b <- as.integer(sign_b)
  if (!sign_a %in% c(-1L, 0L, 1L))
    stop("sign_a must be -1, 0, or +1", call. = FALSE)
  if (!sign_b %in% c(-1L, 0L, 1L))
    stop("sign_b must be -1, 0, or +1", call. = FALSE)

  ss <- .S(session_id)

  # Only Ring127 sessions may call this (Horner / NR are Ring127-only).
  ring <- as.integer(ss$k2_ring %||% 63L)
  if (ring != 127L) {
    stop("k2Ring127AffineCombineDS invoked with ring=", ring,
         "; only ring=127 is supported (Horner / NR spline-less path).",
         call. = FALSE)
  }

  a_b64 <- ""
  if (sign_a != 0L) {
    if (is.null(a_key) || !nzchar(a_key))
      stop("a_key required when sign_a != 0", call. = FALSE)
    a_b64 <- ss[[a_key]]
    if (is.null(a_b64) || !nzchar(a_b64)) {
      stop("session slot '", a_key, "' is empty", call. = FALSE)
    }
  }
  b_b64 <- ""
  if (sign_b != 0L) {
    if (is.null(b_key) || !nzchar(b_key))
      stop("b_key required when sign_b != 0", call. = FALSE)
    b_b64 <- ss[[b_key]]
    if (is.null(b_b64) || !nzchar(b_b64)) {
      stop("session slot '", b_key, "' is empty", call. = FALSE)
    }
  }

  res <- .callMpcTool("k2-ring127-affine-combine", list(
    a = a_b64, b = b_b64,
    sign_a = sign_a, sign_b = sign_b,
    public_const = public_const_fp %||% "",
    is_party0 = isTRUE(is_party0),
    frac_bits = 50L,
    n = as.integer(n)
  ))
  ss[[output_key]] <- res$result
  list(stored = TRUE, output_key = output_key, n = as.integer(n))
}

#' @title Ring127 local scale by public scalar.
#' @description Element-wise multiplies a Ring127 FP share vector by a
#'   PUBLIC scalar (broadcast). Local op — additive-sharing correctness
#'   under broadcast scaling: both parties locally compute
#'   \code{share'[i] = share[i] * s}, which sums to \code{true[i] * s}.
#'
#'   Used by \code{.exp127_round} for the \code{y = eta * (1/a)} rescale
#'   (a=5, the Chebyshev domain half-width). May also be used by
#'   \code{.recip127_round} for the halfX pre-multiplication step
#'   (y_0 = 1.5 - 0.5 * x_norm).
#'
#' @param in_key Session slot holding the Ring127 FP share vector
#'   (base64 Uint128).
#' @param scalar_fp Base64 string encoding a single Ring127 FP Uint128
#'   (the public scalar). One TruncMulSigned per element, so the
#'   result is FP-consistent (not raw integer).
#' @param output_key Session slot to store the scaled share.
#' @param n Integer vector length.
#' @param session_id MPC session identifier.
#' @return list(stored = TRUE, output_key, n).
#' @keywords internal
#' @export
k2Ring127LocalScaleDS <- function(in_key,
                                  scalar_fp,
                                  output_key,
                                  n,
                                  session_id = NULL) {
  scalar_fp <- .b64_pad(scalar_fp)
  if (is.null(session_id) || !nzchar(session_id)) {
    stop("session_id required", call. = FALSE)
  }
  if (is.null(in_key) || !nzchar(in_key))
    stop("in_key required", call. = FALSE)
  if (is.null(output_key) || !nzchar(output_key))
    stop("output_key required", call. = FALSE)
  if (is.null(scalar_fp) || !nzchar(scalar_fp))
    stop("scalar_fp required (base64 Uint128)", call. = FALSE)

  ss <- .S(session_id)
  ring <- as.integer(ss$k2_ring %||% 63L)
  if (ring != 127L) {
    stop("k2Ring127LocalScaleDS invoked with ring=", ring,
         "; Ring127-only primitive.", call. = FALSE)
  }

  share_b64 <- ss[[in_key]]
  if (is.null(share_b64) || !nzchar(share_b64)) {
    stop("session slot '", in_key, "' is empty", call. = FALSE)
  }

  # Broadcast the single scalar to a length-n vector by repeating the
  # 16 raw bytes, then base64-encode. 16 B * n is small (<4 KB at n<=256).
  raw_scalar <- jsonlite::base64_dec(scalar_fp)
  if (length(raw_scalar) != 16L) {
    stop("scalar_fp must decode to exactly 16 bytes (one Uint128), got ",
         length(raw_scalar), call. = FALSE)
  }
  raw_bcast <- rep(raw_scalar, times = as.integer(n))
  bcast_b64 <- jsonlite::base64_enc(raw_bcast)

  res <- .callMpcTool("k2-fp-vec-mul", list(
    a = share_b64,
    b = bcast_b64,
    frac_bits = 50L,
    ring = "ring127"
  ))
  ss[[output_key]] <- res$result
  list(stored = TRUE, output_key = output_key, n = as.integer(n))
}
