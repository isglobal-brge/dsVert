#' @title Non-disclosive K=2 share-domain primitives for NB full-reg theta MLE
#' @description Server-side functions implementing the non-disclosive
#'   variant of \code{ds.vertNBFullRegTheta(variant="full_reg_nd")} per
#'   the spec in \code{docs/error_bounds/nb_t2_log_primitive_close_well_2026-04-29.md}.
#'   Closes the D-INV-4 violation in the prior \code{full_reg} variant
#'   (which transport-decrypted eta^nl plaintext at the label server) by
#'   keeping eta^nl in Ring127 additive secret shares end-to-end through
#'   the share-domain mu + log(mu+theta) + 1/(theta+mu) Beaver pipeline.
#'
#'   Threat model: K=2 OT-Beaver dishonest-majority (Demmler-Schneider-
#'   Zohner ABY 2015 Sec.III.B). Inter-server channels Ed25519-pinned via
#'   \code{trusted_peers} (\code{mpcUtils.R:530-556}). All entry points
#'   K=2-only via \code{.k2_enforce_K(ss, 2L, ...)}.
#'
#'   Refs: Lawless 1987 *Can. J. Statist.* 15(3):209-225 (NB profile-MLE
#'   theta score); Venables & Ripley 2002 *MASS* Sec.7.4 (\code{glm.nb} Newton);
#'   Catrina & Saxena 2010 *Financial Cryptography* Sec.3.3 (multiplicative
#'   depth ULP propagation); Trefethen ATAP Sec.8 (Bernstein-ellipse rel
#'   error bound); Beaver 1991 *CRYPTO* Sec.3 (precomputed multiplication
#'   triples); Boyle, Couteau & Gilboa 2019 (DCFNet -- for future
#'   per-element argument reduction).
#' @name nb-full-reg-share
NULL


#' @title NL-side: split eta^nl into Ring127 additive shares
#' @description Computes eta^nl = X^nl beta
#'   plaintext locally on the non-label server, FP-encodes in Ring127
#'   (fracBits=50), and splits into uniform additive shares:
#'   \itemize{
#'     \item \code{own_share}: this server retains; stored as
#'           \code{ss$k2_nb_eta_share_fp} (this server's Ring127 share of
#'           eta_total -- for the NL server, eta_total share == eta^nl share
#'           because NL contributes nothing to eta_label or beta_0).
#'     \item \code{peer_share}: returned in the transport-encrypted blob
#'           to be relayed to the label server.
#'   }
#'   The peer share is uniform random in Ring127, leaking no information
#'   about eta^nl.
#'
#'   Disclosure footing: identical to \code{k2ShareInputDS}'s feature
#'   sharing -- uniform Ring127 additive split, transport-encrypted via
#'   the label's Ed25519 transport public key.
#'
#' @param data_name Character. Data frame on this server.
#' @param x_vars Character vector. Non-label feature column names.
#' @param beta_values Numeric vector of length \code{length(x_vars)}.
#' @param target_pk Character. Transport public key (base64url) of the
#'   label server.
#' @param session_id Character.
#' @return List with \code{sealed} (transport-encrypted peer share blob,
#'   base64url) and \code{n} (number of patients).
#' @export
dsvertNBEtaShareDS <- function(data_name, x_vars, beta_values,
                                target_pk, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertNBEtaShareDS")
  if (!is.character(x_vars) || length(x_vars) < 1L)
    stop("x_vars must be a non-empty character vector", call. = FALSE)
  beta_values <- as.numeric(beta_values)
  if (length(beta_values) != length(x_vars))
    stop("beta_values length mismatch x_vars", call. = FALSE)

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  missing_cols <- setdiff(x_vars, names(data))
  if (length(missing_cols) > 0L)
    stop("columns not found: ", paste(missing_cols, collapse = ","),
         call. = FALSE)

  X <- as.matrix(data[, x_vars, drop = FALSE])
  eta_nl <- as.numeric(X %*% beta_values)
  n <- length(eta_nl)
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n < privacy_min)
    stop("Insufficient observations", call. = FALSE)

  # Clamp eta to keep mu = exp(eta) and (mu + theta) within the NR-LOG wide
  # Chebyshev seed domain [0.1, 1000]. With eta in [-5, 5], mu in
  # [0.0067, 148] giving (mu+theta) in [0.5, 153] for theta in [0.5, 5] -- well
  # inside [0.1, 1000]. Tighter than the prior +/-23 clamp, which was
  # safe for the single-Chebyshev-core path but would carry NR-LOG
  # outside its convergence basin.
  eta_nl_clipped <- pmin(pmax(eta_nl, -5), 5)

  # FP-encode in Ring127 fracBits=50 (consistent with downstream
  # Chebyshev exp/log/recip primitives).
  fp_eta <- .callMpcTool("k2-float-to-fp", list(
    values = eta_nl_clipped, frac_bits = 50L, ring = "ring127"))$fp_data

  # Additive split: own_share + peer_share = eta_nl (Ring127 modular).
  split <- .callMpcTool("k2-split-fp-share", list(
    data_fp = fp_eta, n = n, frac_bits = 50L, ring = "ring127"))

  # Store own share -- this server's contribution to eta_total share.
  # For NL, eta_total share == eta^nl share (NL contributes 0 to eta_label + beta_0).
  ss$k2_nb_eta_share_fp <- split$own_share
  ss$k2_nb_eta_n <- n
  ss$k2_ring <- 127L

  # Transport-encrypt peer's share for the label server.
  pk_std <- .base64url_to_base64(target_pk)
  sealed <- .callMpcTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(split$peer_share)),
    recipient_pk = pk_std))
  list(sealed = base64_to_base64url(sealed$sealed), n = n)
}


#' @title Label-side: receive NL's eta^nl share + assemble eta_total share
#' @description Decrypts the relayed Ring127 share blob from the
#'   non-label server (label's share of eta^nl), then computes the label's
#'   own contribution eta_label + beta_0 plaintext from local x_vars + client-
#'   supplied beta_label slice + intercept, FP-encodes it, and adds to the
#'   received share via \code{k2-fp-add}. The result stored under
#'   \code{ss$k2_nb_eta_share_fp} is the label's Ring127 share of
#'   eta_total = eta^nl + eta_label + beta_0.
#'
#'   Sum across parties:
#'   \deqn{\eta^{\mathrm{NL}}_{\mathrm{share}} +
#'         (\eta^{\mathrm{label}}_{\mathrm{share}} + (\eta_{\mathrm{label}} + \beta_0)_{\mathrm{FP}})
#'         = \eta^{\mathrm{nl}} + \eta_{\mathrm{label}} + \beta_0 = \eta_{\mathrm{total}}}
#'   OK correct reconstruction.
#'
#'   Caches y for later \code{Sumpsi(y+theta)} computation under
#'   \code{ss$k2_nb_y}.
#'
#' @param data_name Character.
#' @param y_var Character. Outcome column.
#' @param x_vars_label Character. Label-held feature column names.
#' @param beta_values_label Numeric. beta-slice for those columns.
#' @param beta_intercept Numeric scalar. Intercept (revealed at convergence).
#' @param peer_eta_share_blob_key Character. Session blob slot holding
#'   the relayed Ring127 share blob from the NL server.
#' @param session_id Character.
#' @return List with \code{stored = TRUE}, \code{n}.
#' @export
dsvertNBEtaTotalReceiveDS <- function(data_name, y_var,
                                       x_vars_label, beta_values_label,
                                       beta_intercept,
                                       peer_eta_share_blob_key,
                                       session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertNBEtaTotalReceiveDS")

  blob <- .blob_consume(peer_eta_share_blob_key, ss)
  if (is.null(blob))
    stop("peer eta share blob missing at key '", peer_eta_share_blob_key,
         "'; client must relay from NL server", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  if (is.null(tsk))
    stop("transport secret key missing -- call glmRing63TransportInitDS first",
         call. = FALSE)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  share_label_of_eta_nl <- rawToChar(jsonlite::base64_dec(dec$data))

  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  if (!is.data.frame(data)) stop("not a data frame", call. = FALSE)
  if (!(y_var %in% names(data)))
    stop("y_var '", y_var, "' not in data", call. = FALSE)
  y <- as.numeric(data[[y_var]])
  ok <- !is.na(y); y <- y[ok]
  n <- length(y)
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n < privacy_min)
    stop("Insufficient observations", call. = FALSE)

  if (length(x_vars_label) == 0L) {
    eta_label_plus_int <- rep(as.numeric(beta_intercept), n)
  } else {
    beta_values_label <- as.numeric(beta_values_label)
    if (length(beta_values_label) != length(x_vars_label))
      stop("beta_values_label length mismatch x_vars_label", call. = FALSE)
    Xl <- as.matrix(data[ok, x_vars_label, drop = FALSE])
    eta_label_plus_int <- as.numeric(Xl %*% beta_values_label) +
                          as.numeric(beta_intercept)
  }
  # Same clamp as NL side for consistency (eta in [-5, 5] keeps NR-LOG
  # input in [0.5, 153] subset [0.1, 1000] wide-Chebyshev seed domain).
  eta_label_plus_int <- pmin(pmax(eta_label_plus_int, -5), 5)

  fp_label_part <- .callMpcTool("k2-float-to-fp", list(
    values = eta_label_plus_int, frac_bits = 50L, ring = "ring127"))$fp_data

  # Label's share of eta_total = received_share_of_eta^nl + (eta_label + beta_0)_FP.
  # k2-fp-add Go handler reads input fields {a, b, frac_bits, ring} and
  # writes output field {result} (NOT sum_fp -- sum_fp is k2-fp-sum's).
  add_res <- .callMpcTool("k2-fp-add", list(
    a = share_label_of_eta_nl, b = fp_label_part,
    frac_bits = 50L, ring = "ring127"))
  total_share <- add_res$result
  if (is.null(total_share) || !nzchar(total_share))
    stop("k2-fp-add returned empty result", call. = FALSE)

  ss$k2_nb_eta_share_fp <- total_share
  ss$k2_nb_eta_n <- n
  ss$k2_ring <- 127L
  ss$k2_nb_y <- y          # cache plaintext y for psi(y+theta) later
  list(stored = TRUE, n = n)
}


#' @title NL-side mirror: pin NL's eta_total share + cache n
#' @description Tiny helper invoked after \code{dsvertNBEtaShareDS} so the
#'   NL server's session has the same canonical key (\code{k2_nb_eta_share_fp},
#'   \code{k2_nb_eta_n}) as the label side post-receive. NL's eta_total share
#'   already equals its eta^nl share (NL contributes 0 to eta_label + beta_0); this
#'   function just confirms the slot is populated.
#' @param session_id Character.
#' @return List with \code{stored} (TRUE if shares present; FALSE otherwise),
#'   \code{n}.
#' @export
dsvertNBEtaShareConfirmDS <- function(session_id = NULL) {
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertNBEtaShareConfirmDS")
  ok <- !is.null(ss$k2_nb_eta_share_fp) && !is.null(ss$k2_nb_eta_n)
  list(stored = ok,
       n = if (ok) as.integer(ss$k2_nb_eta_n) else NA_integer_)
}


#' @title Label-side: re-share (y + theta) into Ring127 additive shares
#' @description Per Newton-theta iter, the score formula's last term is
#'   \eqn{\sum_i (y_i + \theta) / (\theta + \mu_i)}. With mu_i in shares
#'   and (y_i + theta) plaintext at label only (y is label's data, theta a
#'   scalar from coord), the Beaver vecmul of \code{share((y+theta)) x
#'   share(1/(theta+mu))} requires (y + theta) to be in shares too. Label
#'   generates a fresh uniform Ring127 mask r per call, keeps
#'   \code{share_label = (y + theta)_FP - r} as its share, and transports
#'   the mask r as the peer's share to NL. After this call:
#'   \itemize{
#'     \item Label's session: \code{k2_nb_yt_share_fp = share_label}
#'     \item NL receives mask via \code{dsvertNBYThetaShareReceiveDS}
#'           and stores it in \code{k2_nb_yt_share_fp}.
#'   }
#'   Both parties hold valid Ring127 additive shares of \code{(y + theta)}
#'   with no per-patient leakage (mask is uniform random; share_label is
#'   masked-by-uniform, also uniform).
#'
#' @param theta Numeric scalar. The current Newton iterate value.
#' @param target_pk Character. Transport PK of the NL server.
#' @param session_id Character.
#' @return List with \code{sealed} (transport-encrypted mask blob,
#'   base64url), \code{n}.
#' @export
dsvertNBYThetaShareDS <- function(theta, target_pk, session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id))
    stop("session_id required", call. = FALSE)
  ss <- .S(session_id)
  .dsvert_validate_recipient_pk(target_pk, ss, "peer")
  .k2_enforce_K(ss, 2L, "dsvertNBYThetaShareDS")
  theta <- as.numeric(theta)
  if (!is.finite(theta) || theta <= 0)
    stop("theta must be finite positive", call. = FALSE)
  y <- ss$k2_nb_y
  if (is.null(y))
    stop("y cache missing -- call dsvertNBEtaTotalReceiveDS first",
         call. = FALSE)
  n <- length(y)
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n < privacy_min)
    stop("Insufficient observations", call. = FALSE)

  # Clamp (y + theta) similarly to eta for FP safety. y is non-negative
  # count data; theta in (0, ~10^2) -- sum stays within Ring127 FP range.
  yt <- y + theta
  fp_yt <- .callMpcTool("k2-float-to-fp", list(
    values = yt, frac_bits = 50L, ring = "ring127"))$fp_data

  # Additive split: own_share + peer_share = (y + theta)_FP.
  split <- .callMpcTool("k2-split-fp-share", list(
    data_fp = fp_yt, n = as.integer(n), frac_bits = 50L,
    ring = "ring127"))

  ss$k2_nb_yt_share_fp <- split$own_share

  pk_std <- .base64url_to_base64(target_pk)
  sealed <- .callMpcTool("transport-encrypt", list(
    data = jsonlite::base64_enc(charToRaw(split$peer_share)),
    recipient_pk = pk_std))
  list(sealed = base64_to_base64url(sealed$sealed), n = n)
}


#' @title NL-side: receive (y + theta) share blob + store under canonical key
#' @description Decrypts the transport blob from
#'   \code{dsvertNBYThetaShareDS} and stores in
#'   \code{ss$k2_nb_yt_share_fp}.
#' @param peer_yt_share_blob_key Character.
#' @param session_id Character.
#' @export
dsvertNBYThetaShareReceiveDS <- function(peer_yt_share_blob_key,
                                          session_id = NULL) {
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertNBYThetaShareReceiveDS")
  blob <- .blob_consume(peer_yt_share_blob_key, ss)
  if (is.null(blob))
    stop("peer (y+theta) share blob missing at key '", peer_yt_share_blob_key,
         "'", call. = FALSE)
  tsk <- .key_get("transport_sk", ss)
  dec <- .callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(blob), recipient_sk = tsk))
  share <- rawToChar(jsonlite::base64_dec(dec$data))
  ss$k2_nb_yt_share_fp <- share
  list(stored = TRUE)
}


#' @title Both-side: scalar share sum reveal helper
#' @description Reads a Ring127 share vector from session under
#'   \code{input_key}, computes its modular sum via \code{k2-fp-sum},
#'   returns the scalar share. Caller adds the two server's
#'   \code{sum_share_fp} via \code{k2-ring63-aggregate} (which routes to
#'   the Ring127 modular-add path when \code{ring="ring127"}) to
#'   reconstruct the float scalar.
#'
#'   Disclosure: this is the standard final-reveal step at the K=2 audit
#'   boundary. Only the scalar SUM is revealed (per-element shares stay
#'   uniform random and are NOT exposed).
#'
#' @param input_key Character. Session slot holding the Ring127 share
#'   vector to reduce.
#' @param session_id Character.
#' @return List with \code{sum_share_fp} (base64url Uint128 scalar
#'   share), \code{n}.
#' @export
dsvertNBSumShareDS <- function(input_key, session_id = NULL) {
  ss <- .S(session_id)
  .k2_enforce_K(ss, 2L, "dsvertNBSumShareDS")
  if (!is.character(input_key) || !nzchar(input_key))
    stop("input_key required", call. = FALSE)
  share <- ss[[input_key]]
  if (is.null(share))
    stop("session slot '", input_key, "' empty -- orchestrator step missing?",
         call. = FALSE)
  s <- .callMpcTool("k2-fp-sum", list(
    fp_data = share, ring = "ring127", frac_bits = 50L))
  list(sum_share_fp = s$sum_fp,
       n = as.integer(ss$k2_nb_eta_n %||% NA_integer_))
}


#' @title Label-side: plaintext Sumpsi(y+theta) and Sumpsi_1(y+theta)
#' @description The score / Hessian terms involving psi(y_i + theta) and
#'   psi_1(y_i + theta) (digamma / trigamma) only require y at label and theta as
#'   a scalar -- no mu_i shares needed. Computed plaintext at the outcome
#'   server and returned as scalars. No per-patient disclosure (only the two
#'   sums). In K>=3, y may come from the outcome server's Ring127 input-sharing
#'   cache; no y or y+theta vector is sent to another party.
#' @param theta Numeric scalar.
#' @param session_id Character.
#' @return List with \code{sum_psi}, \code{sum_tri}, \code{n}.
#' @export
dsvertNBPsiAggregateDS <- function(theta, session_id = NULL) {
  ss <- .S(session_id)
  theta <- as.numeric(theta)
  if (!is.finite(theta) || theta <= 0)
    stop("theta must be finite positive", call. = FALSE)
  y <- ss$k2_nb_y %||% ss$k2_y_raw
  if (is.null(y))
    stop("y cache missing -- call dsvertNBEtaTotalReceiveDS or k2ShareInputDS first",
         call. = FALSE)
  n <- length(y)
  privacy_min <- getOption("datashield.privacyLevel", 5L)
  if (is.numeric(privacy_min) && n < privacy_min)
    return(list(sum_psi = NA_real_, sum_tri = NA_real_, n = n))
  list(sum_psi = sum(digamma(y + theta)),
       sum_tri = sum(trigamma(y + theta)),
       n = n)
}
