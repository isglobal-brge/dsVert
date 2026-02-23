#' @title MHE Threshold Protocol - Server-Side Functions
#' @description These functions implement the Multiparty Homomorphic Encryption (MHE)
#'   protocol with threshold decryption using the CKKS approximate homomorphic
#'   encryption scheme (Lattigo v6). Decryption requires ALL servers to cooperate
#'   by providing their partial decryption shares.
#'
#' @details
#' The protocol proceeds in 6 phases, orchestrated by the client
#' (\code{ds.vertCor} in the dsVertClient package):
#'
#' \enumerate{
#'   \item \strong{Key Generation} (\code{mheInitDS}): Each server generates a
#'     secret key share and a public key share. Party 0 also generates the Common
#'     Reference Polynomial (CRP).
#'   \item \strong{Key Combination} (\code{mheCombineDS} + \code{mheStoreCPKDS}):
#'     Public key shares are aggregated into a Collective Public Key (CPK).
#'   \item \strong{Encryption} (\code{mheEncryptLocalDS}): Each server standardizes
#'     its data and encrypts columns under the CPK.
#'   \item \strong{Local Correlation} (\code{localCorDS}): Within-server correlations
#'     are computed in plaintext.
#'   \item \strong{Cross-Server Correlation} (\code{mheCrossProductEncDS} +
#'     \code{mhePartialDecryptDS}): Encrypted element-wise products are computed,
#'     then each server provides a partial decryption share.
#'   \item \strong{Fusion} (client-side \code{mhe-fuse}): The client fuses all
#'     partial shares to recover the inner products (correlation coefficients).
#' }
#'
#' @section Security:
#' The secret key is split across K servers: \eqn{sk = sk_1 + sk_2 + ... + sk_K}.
#' Decryption requires ALL K partial decryption shares. Neither the client nor
#' any subset of K-1 servers can decrypt individual data.
#'
#' @references
#' Mouchet, C. et al. (2021). "Multiparty Homomorphic Encryption from
#' Ring-Learning-With-Errors". \emph{Proceedings on Privacy Enhancing Technologies}.
#'
#' Cheon, J.H. et al. (2017). "Homomorphic Encryption for Arithmetic of
#' Approximate Numbers". \emph{ASIACRYPT 2017}.
#'
#' @name mhe-full-protocol
NULL

# ---------------------------------------------------------------------------
# Session-Scoped Persistent Storage
# ---------------------------------------------------------------------------
# DataSHIELD aggregate/assign calls run in ephemeral environments, so local
# variables are lost between calls. We use a package-level environment to
# persist state across the multi-step MHE, PSI, and GLM protocols.
#
# SESSION ISOLATION: Each job (identified by session_id) gets its own
# sub-environment within .mhe_sessions. This prevents concurrent jobs from
# interfering with each other (critical for DSLite testing and parallel
# Opal jobs). All server functions receive session_id and access their
# session via .S(session_id).
#
# Stored per-session keys during MHE protocol:
#   $secret_key     - This server's RLWE secret key share (NEVER returned)
#   $party_id       - Integer party index (0-based)
#   $cpk            - Collective Public Key (standard base64)
#   $galois_keys    - Galois rotation keys (standard base64 vector)
#   $relin_key      - Relinearization key (standard base64)
#   $log_n, $log_scale - CKKS parameters
#   $transport_sk, $transport_pk - X25519 keypair
#
# Stored per-session during GLM protocol:
#   $enc_y          - Encrypted response ciphertext (non-label servers)
#   $remote_enc_cols - List of received encrypted columns (correlation)
#   $std_data       - Standardized data frame
#   $std_data_name  - Name key for .resolveData() lookup
#   $glm_eta_label, $glm_eta_other - Eta vectors for deviance
#
# Stored per-session during PSI protocol:
#   $psi_scalar     - P-256 secret scalar (NEVER returned)
#   $psi_ref_dm     - Double-masked reference points
#   $psi_ref_indices - Reference row indices
#   $psi_matched_ref_indices - Matched indices for Phase 8 intersection
#
# Protocol Firewall state (per-session):
#   $op_counter     - Monotonic operation counter
#   $ct_registry    - Named list: ct_hash -> list(op_id, op_type, timestamp)
#
# GLM FSM state (per-session, replaces .glm_fsm):
#   $fsm_session_id - Session ID for FSM validation
#   $fsm_state      - Current FSM state
#   $fsm_iteration  - Current iteration
#   $fsm_n_nonlabel - Expected non-label count
#   $fsm_etas_received - Character vector of received etas
#   $fsm_blocks_completed - Block completion counter
# ---------------------------------------------------------------------------

# Container for all sessions. Each session_id -> sub-environment.
.mhe_sessions <- new.env(parent = emptyenv())

# Legacy fallback for backward compatibility (non-session-scoped callers).
# New code should always use .S(session_id).
.mhe_storage <- new.env(parent = emptyenv())

# Session TTL: 24 hours (very long to avoid premature cleanup)
.SESSION_TTL_SECONDS <- 86400L

#' Get or create a session-scoped storage environment
#'
#' Returns the sub-environment for the given session_id. Creates it if it
#' does not exist. Falls back to the legacy .mhe_storage if session_id is
#' NULL or empty (backward compatibility).
#'
#' Opportunistically reaps expired sessions on creation of new ones.
#'
#' @param session_id Character or NULL. Session identifier.
#' @return An environment for storing session state.
#' @keywords internal
.S <- function(session_id = NULL) {
  if (is.null(session_id) || !nzchar(session_id)) {
    return(.mhe_storage)
  }
  s <- .mhe_sessions[[session_id]]
  if (is.null(s)) {
    s <- new.env(parent = emptyenv())
    s$.created_at <- Sys.time()
    s$.session_id <- session_id
    .mhe_sessions[[session_id]] <- s
    # Opportunistic reap of expired sessions
    .reap_expired_sessions()
  }
  s
}

#' Remove a session and all its state
#'
#' @param session_id Character. Session to clean up.
#' @return TRUE (invisible)
#' @keywords internal
.cleanup_session <- function(session_id) {
  if (!is.null(session_id) && nzchar(session_id)) {
    s <- .mhe_sessions[[session_id]]
    if (!is.null(s)) {
      rm(list = ls(s), envir = s)
    }
    rm(list = session_id, envir = .mhe_sessions)
  }
  gc(verbose = FALSE)
  invisible(TRUE)
}

#' Reap sessions older than TTL
#'
#' Called opportunistically when new sessions are created. Removes
#' sessions whose .created_at timestamp is older than .SESSION_TTL_SECONDS.
#'
#' @keywords internal
.reap_expired_sessions <- function() {
  now <- Sys.time()
  for (sid in ls(.mhe_sessions)) {
    s <- .mhe_sessions[[sid]]
    if (!is.null(s) && !is.null(s$.created_at)) {
      age <- as.numeric(difftime(now, s$.created_at, units = "secs"))
      if (age > .SESSION_TTL_SECONDS) {
        .cleanup_session(sid)
      }
    }
  }
}

# ---------------------------------------------------------------------------
# Protocol Firewall: Ciphertext Registry
# ---------------------------------------------------------------------------
# Prevents the decryption oracle attack (arbitrary ciphertext decryption)
# by requiring every ciphertext to be registered at production time.
# Uses SHA-256 hashes of ciphertext content as keys.
# ---------------------------------------------------------------------------

#' Register a ciphertext as authorized for decryption (producing server)
#'
#' Called by operations that produce ciphertexts (cross-product, GLM gradient).
#' Returns the SHA-256 hash for client-side relay to other servers.
#'
#' @param ct_b64 Character. The ciphertext in standard base64 encoding
#' @param op_type Character. Operation that produced this ciphertext
#' @return Character. SHA-256 hash of the ciphertext
#' @keywords internal
.register_ciphertext <- function(ct_b64, op_type, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$op_counter)) {
    ss$op_counter <- 0L
  }
  if (is.null(ss$ct_registry)) {
    ss$ct_registry <- list()
  }

  ss$op_counter <- ss$op_counter + 1L

  ct_hash <- digest::digest(ct_b64, algo = "sha256", serialize = FALSE)

  ss$ct_registry[[ct_hash]] <- list(
    op_id = ss$op_counter,
    op_type = op_type,
    timestamp = Sys.time()
  )

  ct_hash
}

#' Validate and consume a ciphertext authorization (one-time use)
#' @param ct_b64 Character. The ciphertext in standard base64 encoding
#' @return TRUE if authorized (entry is consumed), stops with error otherwise
#' @keywords internal
.validate_and_consume_ciphertext <- function(ct_b64, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$ct_registry)) {
    stop("Protocol Firewall: no ciphertexts registered. ",
         "Decryption denied.", call. = FALSE)
  }

  ct_hash <- digest::digest(ct_b64, algo = "sha256", serialize = FALSE)

  entry <- ss$ct_registry[[ct_hash]]
  if (is.null(entry)) {
    stop("Protocol Firewall: ciphertext not authorized for decryption. ",
         "Only ciphertexts produced by legitimate operations ",
         "(cross-product, glm-gradient) can be decrypted.", call. = FALSE)
  }

  # One-time use: consume the authorization (anti-replay)
  ss$ct_registry[[ct_hash]] <- NULL

  TRUE
}

#' Initialize MHE keys and transport keypair for this server
#'
#' Generates a CKKS MHE secret/public key share pair and an X25519
#' transport keypair. The secret keys (MHE SK share and transport SK) are
#' stored locally and NEVER returned to the client.
#'
#' Party 0 additionally generates and returns the Common Reference Polynomial
#' (CRP) and the Galois Key Generation (GKG) seed, which must be relayed
#' to all other parties.
#'
#' @param party_id Integer. This server's party ID (0-indexed). Party 0
#'   generates the CRP and GKG seed.
#' @param crp Character or NULL. Common Reference Polynomial from party 0
#'   (base64url). NULL if this is party 0.
#' @param gkg_seed Character or NULL. GKG seed from party 0 (base64url).
#'   NULL if this is party 0.
#' @param num_obs Integer. Number of observations (determines galois key
#'   rotation indices). Default 100.
#' @param log_n Integer. CKKS ring dimension parameter (12, 13, or 14).
#'   Default 12.
#' @param log_scale Integer. CKKS scale parameter controlling precision.
#'   Default 40.
#' @param from_storage Logical. If \code{TRUE}, read \code{crp} and
#'   \code{gkg_seed} from server-side blob storage (previously stored
#'   via \code{\link{mheStoreBlobDS}}) instead of inline arguments.
#'   Used by the client to avoid exceeding DataSHIELD's expression
#'   parser limits with large cryptographic objects. Default \code{FALSE}.
#' @param generate_rlk Logical. Whether to generate relinearization key shares.
#'   Default FALSE.
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{public_key_share}: This server's MHE public key share (base64url)
#'     \item \code{galois_key_shares}: Galois key generation shares (base64url vector)
#'     \item \code{party_id}: Echo of the party ID
#'     \item \code{transport_pk}: X25519 transport public key (base64url)
#'     \item \code{crp}: Common Reference Polynomial (party 0 only, base64url)
#'     \item \code{gkg_seed}: Galois Key Generation seed (party 0 only, base64url)
#'   }
#'
#' @seealso \code{\link{mheStoreTransportKeysDS}} for distributing transport PKs,
#'   \code{\link{mheCombineDS}} for combining public key shares
#' @export
mheInitDS <- function(party_id, crp = NULL, gkg_seed = NULL,
                      num_obs = 100, log_n = 12, log_scale = 40,
                      from_storage = FALSE, generate_rlk = FALSE,
                      session_id = NULL) {
  ss <- .S(session_id)
  input <- list(
    party_id = as.integer(party_id),
    num_obs = as.integer(num_obs),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale),
    generate_rlk = isTRUE(generate_rlk)
  )

  # If not party 0, include CRP and shared GKG seed
  if (from_storage) {
    blobs <- ss$blobs
    if (!is.null(blobs) && !is.null(blobs[["crp"]])) {
      input$crp <- .base64url_to_base64(blobs[["crp"]])
    }
    if (!is.null(blobs) && !is.null(blobs[["gkg_seed"]])) {
      input$gkg_seed <- .base64url_to_base64(blobs[["gkg_seed"]])
    }
    ss$blobs <- NULL
  } else {
    if (party_id > 0 && !is.null(crp)) {
      input$crp <- .base64url_to_base64(crp)
    }
    if (!is.null(gkg_seed)) {
      input$gkg_seed <- .base64url_to_base64(gkg_seed)
    }
  }

  result <- .callMheTool("mhe-setup", input)

  # SECURITY: secret key share is stored locally and NEVER returned to the
  # client. This is the foundation of the threshold property: the collective
  # secret key sk = sk_1 + sk_2 + ... + sk_K is never reconstructed.
  ss$secret_key <- result$secret_key
  ss$party_id <- party_id
  ss$log_n <- log_n
  ss$log_scale <- log_scale

  # Generate X25519 transport keypair for share-wrapping and GLM secure routing.
  # The transport SK is stored locally (NEVER returned); the PK is distributed
  # to all other servers via the client so they can encrypt data for us.
  transport <- .callMheTool("transport-keygen", list())
  ss$transport_sk <- transport$secret_key
  ss$transport_pk <- transport$public_key

  # Store RLK ephemeral SK locally (NEVER returned to client) for round 2
  if (isTRUE(generate_rlk) && !is.null(result$rlk_ephemeral_sk) &&
      nzchar(result$rlk_ephemeral_sk)) {
    ss$rlk_ephemeral_sk <- result$rlk_ephemeral_sk
  }

  # Return only public information: the public key share (safe to combine)
  # and Galois key generation shares (for enabling ciphertext rotations).
  output <- list(
    public_key_share = base64_to_base64url(result$public_key_share),
    galois_key_shares = sapply(result$galois_key_shares, base64_to_base64url, USE.NAMES = FALSE),
    party_id = party_id,
    transport_pk = base64_to_base64url(transport$public_key)
  )

  # RLK round 1 share (sent for aggregation)
  if (isTRUE(generate_rlk) && !is.null(result$rlk_round1_share) &&
      nzchar(result$rlk_round1_share)) {
    output$rlk_round1_share <- base64_to_base64url(result$rlk_round1_share)
  }

  # Party 0 also returns CRP and GKG seed
  if (party_id == 0) {
    output$crp <- base64_to_base64url(result$crp)
    output$gkg_seed <- base64_to_base64url(result$gkg_seed)
  }

  output
}

#' Aggregate RLK round 1 shares (coordinator only)
#'
#' Called on the combining server to aggregate all parties' RLK round 1 shares
#' into a single aggregated round 1. The aggregated round 1 is then distributed
#' to all parties for round 2 generation.
#'
#' @param from_storage Logical. If TRUE, read round 1 shares from blob storage.
#' @param n_parties Integer. Number of parties (used with from_storage).
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with aggregated_round1 (base64url)
#' @export
mheRLKAggregateR1DS <- function(from_storage = FALSE, n_parties = 0,
                                session_id = NULL) {
  ss <- .S(session_id)
  if (from_storage) {
    blobs <- ss$blobs
    if (is.null(blobs)) stop("No blobs stored for RLK R1 aggregation", call. = FALSE)

    r1_shares <- character(n_parties)
    for (i in seq_len(n_parties)) {
      r1_shares[i] <- .base64url_to_base64(blobs[[paste0("rlk_r1_", i - 1)]])
    }
    ss$blobs <- NULL
  } else {
    stop("Direct argument mode not supported for RLK aggregation", call. = FALSE)
  }

  input <- list(
    rlk_round1_shares = as.list(r1_shares),
    log_n = as.integer(ss$log_n %||% 14),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-rlk-aggregate-r1", input)

  # Store aggregated round 1 locally for own round 2 generation
  ss$rlk_aggregated_r1 <- result$aggregated_round1

  list(aggregated_round1 = base64_to_base64url(result$aggregated_round1))
}

#' Generate RLK round 2 share
#'
#' Called on each server after receiving the aggregated round 1 share.
#' Uses this party's stored secret key and ephemeral SK to generate
#' a round 2 share.
#'
#' @param from_storage Logical. If TRUE, read aggregated round 1 from
#'   blob storage. Default FALSE.
#' @param aggregated_round1 Character or NULL. Aggregated round 1 (base64url).
#'   Ignored when from_storage is TRUE.
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with rlk_round2_share (base64url)
#' @export
mheRLKRound2DS <- function(from_storage = FALSE, aggregated_round1 = NULL,
                           session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$secret_key)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$rlk_ephemeral_sk)) {
    stop("RLK ephemeral SK not stored. Call mheInitDS with generate_rlk=TRUE.", call. = FALSE)
  }

  if (from_storage) {
    blobs <- ss$blobs
    if (!is.null(blobs) && !is.null(blobs[["rlk_agg_r1"]])) {
      agg_r1 <- .base64url_to_base64(blobs[["rlk_agg_r1"]])
      ss$blobs <- NULL
    } else if (!is.null(ss$rlk_aggregated_r1)) {
      # Coordinator already has it from mheRLKAggregateR1DS
      agg_r1 <- ss$rlk_aggregated_r1
    } else {
      stop("No aggregated round 1 available", call. = FALSE)
    }
  } else if (!is.null(aggregated_round1)) {
    agg_r1 <- .base64url_to_base64(aggregated_round1)
  } else if (!is.null(ss$rlk_aggregated_r1)) {
    agg_r1 <- ss$rlk_aggregated_r1
  } else {
    stop("No aggregated round 1 provided", call. = FALSE)
  }

  input <- list(
    secret_key = ss$secret_key,
    rlk_ephemeral_sk = ss$rlk_ephemeral_sk,
    aggregated_round1 = agg_r1,
    log_n = as.integer(ss$log_n %||% 14),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-rlk-round2", input)

  # Clean up ephemeral SK (no longer needed after round 2)
  ss$rlk_ephemeral_sk <- NULL

  list(rlk_round2_share = base64_to_base64url(result$rlk_round2_share))
}

#' Combine public key shares into collective public key
#'
#' @param public_key_shares Character vector. Public key shares from all servers
#' @param crp Character. CRP from party 0
#' @param galois_key_shares List of character vectors. Galois key generation
#'   shares from each party.
#' @param gkg_seed Character. Galois key generation seed from party 0.
#' @param num_obs Integer. Number of observations
#' @param log_n Integer. Ring dimension
#' @param log_scale Integer. Scale parameter
#' @param from_storage Logical. If \code{TRUE}, read all inputs (public key
#'   shares, CRP, GKG seed, Galois key shares) from server-side blob storage
#'   instead of inline arguments. Default \code{FALSE}.
#' @param n_parties Integer. Number of parties (used with \code{from_storage}).
#' @param n_gkg_shares Integer. Number of Galois key generation shares per
#'   party (used with \code{from_storage}).
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with collective_public_key and galois_keys
#' @export
mheCombineDS <- function(public_key_shares = NULL, crp = NULL, galois_key_shares = NULL,
                         gkg_seed = NULL, num_obs = 100, log_n = 12, log_scale = 40,
                         from_storage = FALSE, n_parties = 0, n_gkg_shares = 0,
                         session_id = NULL) {
  ss <- .S(session_id)
  if (from_storage) {
    # Read all inputs from blob storage (set via mheStoreBlobDS)
    blobs <- ss$blobs
    if (is.null(blobs)) stop("No blobs stored for combine", call. = FALSE)

    pk_shares <- character(n_parties)
    for (i in seq_len(n_parties)) {
      pk_shares[i] <- .base64url_to_base64(blobs[[paste0("pk_", i - 1)]])
    }
    crp_std <- .base64url_to_base64(blobs[["crp"]])
    gkg_seed_std <- if (!is.null(blobs[["gkg_seed"]])) .base64url_to_base64(blobs[["gkg_seed"]]) else ""

    gkg_shares_std <- list()
    if (n_gkg_shares > 0) {
      for (i in seq_len(n_parties)) {
        party_shares <- character(n_gkg_shares)
        for (j in seq_len(n_gkg_shares)) {
          party_shares[j] <- .base64url_to_base64(blobs[[paste0("gkg_", i - 1, "_", j - 1)]])
        }
        gkg_shares_std[[i]] <- party_shares
      }
    }

    # Read RLK round 1 aggregated + round 2 shares from blob storage (if present)
    rlk_r1_agg_std <- ""
    if (!is.null(blobs[["rlk_agg_r1"]])) {
      rlk_r1_agg_std <- .base64url_to_base64(blobs[["rlk_agg_r1"]])
    } else if (!is.null(ss$rlk_aggregated_r1)) {
      # Coordinator already has it from mheRLKAggregateR1DS
      rlk_r1_agg_std <- ss$rlk_aggregated_r1
    }

    rlk_r2_shares_std <- list()
    for (i in seq_len(n_parties)) {
      key <- paste0("rlk_r2_", i - 1)
      if (!is.null(blobs[[key]])) {
        rlk_r2_shares_std[[length(rlk_r2_shares_std) + 1]] <- .base64url_to_base64(blobs[[key]])
      }
    }

    # Clean up blobs
    ss$blobs <- NULL
  } else {
    # Direct arguments (backward-compatible, small datasets only)
    pk_shares <- sapply(public_key_shares, .base64url_to_base64, USE.NAMES = FALSE)
    crp_std <- .base64url_to_base64(crp)

    gkg_shares_std <- list()
    if (!is.null(galois_key_shares) && length(galois_key_shares) > 0) {
      gkg_shares_std <- lapply(galois_key_shares, function(party_shares) {
        sapply(party_shares, .base64url_to_base64, USE.NAMES = FALSE)
      })
    }

    gkg_seed_std <- ""
    if (!is.null(gkg_seed)) {
      gkg_seed_std <- .base64url_to_base64(gkg_seed)
    }

    rlk_r1_agg_std <- ""
    rlk_r2_shares_std <- list()
  }

  input <- list(
    public_key_shares = as.list(pk_shares),
    galois_key_shares = gkg_shares_std,
    gkg_seed = gkg_seed_std,
    crp = crp_std,
    num_obs = as.integer(num_obs),
    log_n = as.integer(log_n),
    log_scale = as.integer(log_scale)
  )

  # Include RLK data if available
  if (nzchar(rlk_r1_agg_std) && length(rlk_r2_shares_std) > 0) {
    input$rlk_round1_aggregated <- rlk_r1_agg_std
    input$rlk_round2_shares <- rlk_r2_shares_std
  }

  result <- .callMheTool("mhe-combine", input)

  # Store combined keys locally. The CPK is used for encryption;
  # Galois keys enable ciphertext rotations (needed for inner-product
  # computation). The combining server stores these directly; other
  # servers receive them via mheStoreCPKDS.
  ss$cpk <- result$collective_public_key
  ss$galois_keys <- result$galois_keys
  ss$relin_key <- result$relinearization_key

  # Return CPK and Galois keys to client for distribution to other servers.
  gk_out <- NULL
  if (!is.null(result$galois_keys) && length(result$galois_keys) > 0) {
    gk_out <- sapply(result$galois_keys, base64_to_base64url, USE.NAMES = FALSE)
  }

  # Return RLK if generated (non-empty)
  rk_out <- NULL
  if (!is.null(result$relinearization_key) && nzchar(result$relinearization_key)) {
    rk_out <- base64_to_base64url(result$relinearization_key)
  }

  list(
    collective_public_key = base64_to_base64url(result$collective_public_key),
    galois_keys = gk_out,
    relin_key = rk_out
  )
}

#' Store collective public key received from combine step
#'
#' @param cpk Character. Collective public key (base64url)
#' @param galois_keys Character vector. Galois keys (base64url)
#' @param relin_key Character. Relinearization key (base64url)
#' @param from_storage Logical. If \code{TRUE}, read CPK and Galois keys
#'   from server-side blob storage instead of inline arguments.
#'   Default \code{FALSE}.
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return TRUE on success
#' @export
mheStoreCPKDS <- function(cpk = NULL, galois_keys = NULL, relin_key = NULL,
                          from_storage = FALSE, session_id = NULL) {
  ss <- .S(session_id)
  if (from_storage) {
    blobs <- ss$blobs
    if (is.null(blobs)) stop("No blobs stored for CPK", call. = FALSE)

    ss$cpk <- .base64url_to_base64(blobs[["cpk"]])

    # Read Galois keys from blobs gk_0, gk_1, ...
    gk_keys <- sort(grep("^gk_", names(blobs), value = TRUE))
    if (length(gk_keys) > 0) {
      ss$galois_keys <- sapply(gk_keys, function(k) {
        .base64url_to_base64(blobs[[k]])
      }, USE.NAMES = FALSE)
    }

    if (!is.null(blobs[["rk"]])) {
      ss$relin_key <- .base64url_to_base64(blobs[["rk"]])
    }

    ss$blobs <- NULL
  } else {
    ss$cpk <- .base64url_to_base64(cpk)

    if (!is.null(galois_keys)) {
      ss$galois_keys <- sapply(galois_keys, .base64url_to_base64, USE.NAMES = FALSE)
    }
    if (!is.null(relin_key)) {
      ss$relin_key <- .base64url_to_base64(relin_key)
    }
  }

  TRUE
}

#' Encrypt local data columns using stored CPK
#'
#' @param data_name Character. Name of data frame
#' @param variables Character vector. Variables to encrypt
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with encrypted_columns
#' @export
mheEncryptLocalDS <- function(data_name, variables, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$cpk)) {
    stop("CPK not stored. Call mheCombineDS or mheStoreCPKDS first.", call. = FALSE)
  }

  # Get data
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  X <- X[complete.cases(X), , drop = FALSE]

  # Standardize to Z-scores (mean=0, sd=1) before encryption.
  # This is necessary because CKKS has limited multiplicative depth:
  # operating on values near [-1, 1] minimizes precision loss.
  # NaN values (from zero-variance columns) are replaced with 0.
  Z <- scale(X, center = TRUE, scale = TRUE)
  Z[is.nan(Z)] <- 0

  # Convert to row-major format: data[row][col] as Go expects.
  # as.list() is critical: jsonlite's auto_unbox converts length-1 atomic
  # vectors to JSON scalars, but Go expects arrays even for single-column data.
  data_rows <- lapply(seq_len(nrow(Z)), function(i) as.list(as.numeric(Z[i, ])))

  input <- list(
    data = data_rows,
    collective_public_key = ss$cpk,
    log_n = as.integer(ss$log_n %||% 12),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("encrypt-columns", input)

  list(
    encrypted_columns = sapply(result$encrypted_columns, base64_to_base64url, USE.NAMES = FALSE),
    num_rows = result$num_rows,
    num_cols = result$num_cols
  )
}

#' Store a chunk of an encrypted column (for transferring large ciphertexts)
#'
#' @param col_index Integer. Column index (1-based)
#' @param chunk_index Integer. Chunk index (1-based)
#' @param chunk Character. Base64url-encoded chunk of ciphertext
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return TRUE on success
#' @export
mheStoreEncChunkDS <- function(col_index, chunk_index, chunk, session_id = NULL) {
  ss <- .S(session_id)
  key <- paste0("enc_chunks_", col_index)
  if (is.null(ss[[key]])) {
    ss[[key]] <- list()
  }
  ss[[key]][[chunk_index]] <- chunk
  TRUE
}

#' Assemble stored chunks into a complete encrypted column
#'
#' @param col_index Integer. Column index (1-based)
#' @param n_chunks Integer. Total number of chunks
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return TRUE on success
#' @export
mheAssembleEncColumnDS <- function(col_index, n_chunks, session_id = NULL) {
  ss <- .S(session_id)
  key <- paste0("enc_chunks_", col_index)
  chunks <- ss[[key]]
  if (is.null(chunks) || length(chunks) < n_chunks) {
    stop("Missing chunks for column ", col_index, call. = FALSE)
  }

  # Concatenate all chunks and convert from base64url
  full_b64url <- paste0(chunks[1:n_chunks], collapse = "")
  full_b64 <- .base64url_to_base64(full_b64url)

  if (is.null(ss$remote_enc_cols)) {
    ss$remote_enc_cols <- list()
  }
  ss$remote_enc_cols[[col_index]] <- full_b64

  # Clean up chunks
  ss[[key]] <- NULL
  TRUE
}

#' Compute encrypted cross-product using STORED evaluation keys and STORED encrypted columns
#' Returns ENCRYPTED result that requires threshold decryption
#'
#' @param data_name Character. Name of local data frame
#' @param variables Character vector. Local variables (plaintext)
#' @param n_enc_cols Integer. Number of stored encrypted columns to use
#' @param n_obs Integer. Number of observations
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with encrypted_results matrix (base64url encoded ciphertexts)
#' @export
mheCrossProductEncDS <- function(data_name, variables, n_enc_cols, n_obs,
                                 session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$remote_enc_cols) || length(ss$remote_enc_cols) < n_enc_cols) {
    stop("Encrypted columns not stored. Call mheStoreEncChunkDS/mheAssembleEncColumnDS first.", call. = FALSE)
  }

  # Get local data
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  X <- X[complete.cases(X), , drop = FALSE]

  # Standardize
  Z <- scale(X, center = TRUE, scale = TRUE)
  Z[is.nan(Z)] <- 0

  # Convert to column format
  plaintext_cols <- lapply(seq_len(ncol(Z)), function(j) as.numeric(Z[, j]))

  # Use stored encrypted columns (no eval keys needed!)
  enc_cols <- ss$remote_enc_cols[1:n_enc_cols]

  input <- list(
    plaintext_columns = plaintext_cols,
    encrypted_columns = enc_cols,
    log_n = as.integer(ss$log_n %||% 12),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-cross-product", input)

  # Clear stored encrypted columns after use
  ss$remote_enc_cols <- NULL

  # Protocol Firewall: register each produced ciphertext.
  # Returns ct_hashes so the client can relay them to other servers
  # for batch authorization before threshold decryption.
  er <- result$encrypted_results
  ct_hashes <- character(0)

  if (is.matrix(er)) {
    n_rows <- nrow(er)
    n_cols <- ncol(er)
    for (i in seq_len(n_rows)) {
      for (j in seq_len(n_cols)) {
        h <- .register_ciphertext(er[i, j], "cross-product", session_id = session_id)
        ct_hashes <- c(ct_hashes, h)
        er[i, j] <- base64_to_base64url(er[i, j])
      }
    }
  } else {
    n_rows <- length(er)
    n_cols <- if (n_rows > 0) length(er[[1]]) else 0
    for (i in seq_along(er)) {
      for (j in seq_along(er[[i]])) {
        h <- .register_ciphertext(er[[i]][[j]], "cross-product", session_id = session_id)
        ct_hashes <- c(ct_hashes, h)
      }
    }
    er <- lapply(er, function(row) sapply(row, base64_to_base64url, USE.NAMES = FALSE))
  }

  list(
    encrypted_results = er,
    ct_hashes = ct_hashes,
    n_rows = n_rows,
    n_cols = n_cols
  )
}

#' Batch-authorize ciphertexts for decryption on this server
#'
#' Called by the client to authorize a batch of ciphertexts for partial
#' decryption. The ct_hashes are SHA-256 hashes of ciphertexts produced by
#' a legitimate operation on another server. The client relays these hashes
#' (which do not reveal ciphertext content) so that this server knows which
#' ciphertexts are authorized for decryption.
#'
#' This prevents the decryption oracle attack: a client cannot fabricate
#' arbitrary ciphertexts for decryption because the hashes must match
#' ciphertexts produced by actual server-side operations.
#'
#' @param ct_hashes Character vector. SHA-256 hashes of authorized ciphertexts.
#'   Ignored when \code{from_storage = TRUE}.
#' @param op_type Character. Operation type ("cross-product" or "glm-gradient")
#' @param from_storage Logical. If \code{TRUE}, read \code{ct_hashes} from
#'   server-side blob storage (comma-separated) instead of inline argument.
#'   Default \code{FALSE}.
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return Integer. Number of ciphertexts authorized
#' @export
mheAuthorizeCTDS <- function(ct_hashes = NULL, op_type = "cross-product",
                             from_storage = FALSE, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$secret_key)) {
    stop("MHE not initialized. Call mheInitDS first.", call. = FALSE)
  }

  # Read ct_hashes from blob storage or inline argument
  if (from_storage) {
    blobs <- ss$blobs
    if (is.null(blobs) || is.null(blobs[["ct_hashes"]])) {
      stop("No ct_hashes blob stored", call. = FALSE)
    }
    ct_hashes <- strsplit(blobs[["ct_hashes"]], ",", fixed = TRUE)[[1]]
    ss$blobs <- NULL
  }

  if (is.null(ss$ct_registry)) {
    ss$ct_registry <- list()
  }
  if (is.null(ss$op_counter)) {
    ss$op_counter <- 0L
  }

  for (ct_hash in ct_hashes) {
    ss$op_counter <- ss$op_counter + 1L
    ss$ct_registry[[ct_hash]] <- list(
      op_id = ss$op_counter,
      op_type = op_type,
      timestamp = Sys.time()
    )
  }

  length(ct_hashes)
}

#' Store a chunk of a ciphertext for partial decryption
#'
#' @param chunk_index Integer. Chunk index (1-based)
#' @param chunk Character. Base64url-encoded chunk
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return TRUE on success
#' @export
mheStoreCTChunkDS <- function(chunk_index, chunk, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$ct_chunks)) {
    ss$ct_chunks <- list()
  }
  ss$ct_chunks[[chunk_index]] <- chunk
  TRUE
}

#' Compute partial decryption using stored secret key and stored ciphertext chunks
#'
#' Protected by the Protocol Firewall: only ciphertexts that were registered
#' (by the producing server) or authorized (via \code{mheAuthorizeCTDS} with
#' a valid HMAC token) can be decrypted. Each authorization is consumed after
#' one use (anti-replay).
#'
#' @param n_chunks Integer. Number of stored ciphertext chunks
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with decryption_share (chunked as a character vector)
#' @export
mhePartialDecryptDS <- function(n_chunks, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$secret_key)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$ct_chunks) || length(ss$ct_chunks) < n_chunks) {
    stop("Ciphertext chunks not stored. Call mheStoreCTChunkDS first.", call. = FALSE)
  }

  # Reassemble ciphertext from chunks. CKKS ciphertexts can be 50-200KB
  # as base64, exceeding DataSHIELD/R parser limits for single string
  # arguments. The client uses adaptive chunking (default 200KB, auto-reduced
  # on failure) to stay within these limits.
  ct_b64url <- paste0(ss$ct_chunks[1:n_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)

  # Clean up chunks after use to free memory
  ss$ct_chunks <- NULL

  # Protocol Firewall: validate ciphertext is authorized for decryption.
  # This prevents the decryption oracle attack where an adversary submits
  # arbitrary ciphertexts to recover plaintext or secret key information.
  .validate_and_consume_ciphertext(ct_b64, session_id = session_id)

  input <- list(
    ciphertext = ct_b64,
    secret_key = ss$secret_key,
    log_n = as.integer(ss$log_n %||% 12),
    log_scale = as.integer(ss$log_scale %||% 40)
  )

  result <- .callMheTool("mhe-partial-decrypt", input)

  # Return share as chunks (to avoid large return through DataSHIELD)
  share_b64url <- base64_to_base64url(result$decryption_share)

  list(
    decryption_share = share_b64url,
    party_id = ss$party_id
  )
}

# ============================================================================
# Share-Wrapping: Transport key distribution + wrapped partial decrypt + fusion
# ============================================================================

#' Store transport public keys from other servers
#'
#' Called by the client after \code{\link{mheInitDS}} to distribute each
#' server's X25519 transport public key to all other servers. These keys
#' enable two security features:
#' \itemize{
#'   \item \strong{Share-wrapping}: encrypting partial decryption shares
#'     under the fusion server's transport PK so the client cannot read them
#'   \item \strong{GLM Secure Routing}: encrypting eta/mu/w/v vectors
#'     end-to-end between the coordinator and non-label servers
#' }
#'
#' @param transport_keys Named list. Server name -> transport public key
#'   (base64url). Must include a \code{"fusion"} entry identifying the
#'   fusion server's (party 0) transport PK.
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return \code{TRUE} on success
#'
#' @seealso \code{\link{mheInitDS}} which generates the transport keypair,
#'   \code{\link{mhePartialDecryptWrappedDS}} which uses the fusion PK
#' @export
mheStoreTransportKeysDS <- function(transport_keys, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$secret_key)) {
    stop("MHE not initialized. Call mheInitDS first.", call. = FALSE)
  }

  # MHE Key Pinning: validate client-provided PKs against trusted set
  # (mirrors PSI key pinning pattern from psiStoreTransportKeysDS)
  pinning <- .read_dsvert_option("dsvert.mhe_key_pinning", FALSE)
  if (isTRUE(pinning) || identical(tolower(as.character(pinning)), "true")) {
    peers_json <- .read_dsvert_option("dsvert.mhe_peers")
    if (is.null(peers_json) || peers_json == "") {
      stop("dsvert.mhe_key_pinning=TRUE but dsvert.mhe_peers not set. ",
           "Provide a JSON array of trusted MHE transport PKs.", call. = FALSE)
    }
    trusted_pks <- tryCatch(
      jsonlite::fromJSON(peers_json),
      error = function(e) {
        stop("dsvert.mhe_peers is not valid JSON: ", e$message, call. = FALSE)
      }
    )

    own_pk <- ss$transport_pk
    for (name in names(transport_keys)) {
      pk <- .base64url_to_base64(transport_keys[[name]])
      if (pk == own_pk) next  # skip our own PK
      if (!(pk %in% trusted_pks)) {
        stop("MHE Key Pinning: unknown transport PK received for '", name,
             "'. Not in trusted peer set. ",
             "Possible MITM attack.", call. = FALSE)
      }
    }
  }

  # Convert from base64url to standard base64 for internal use
  ss$peer_transport_pks <- lapply(transport_keys, .base64url_to_base64)

  TRUE
}

#' Compute wrapped partial decryption share
#'
#' Same as \code{\link{mhePartialDecryptDS}} but the resulting decryption
#' share is transport-encrypted (wrapped) under the fusion server's X25519
#' public key before being returned. The client receives an opaque blob it
#' cannot read; it relays this blob to the fusion server via
#' \code{\link{mheStoreWrappedShareDS}} for server-side fusion.
#'
#' This eliminates the client's ability to fuse shares locally, preventing
#' share reuse or manipulation by a malicious client.
#'
#' @param n_chunks Integer. Number of stored ciphertext chunks (previously
#'   sent via \code{\link{mheStoreCTChunkDS}}).
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{wrapped_share}: Transport-encrypted decryption share
#'       (base64url). Opaque to the client.
#'     \item \code{party_id}: This server's party ID.
#'   }
#'
#' @seealso \code{\link{mhePartialDecryptDS}} for the unwrapped variant,
#'   \code{\link{mheFuseServerDS}} for server-side fusion
#' @export
mhePartialDecryptWrappedDS <- function(n_chunks, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$secret_key)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$ct_chunks) || length(ss$ct_chunks) < n_chunks) {
    stop("Ciphertext chunks not stored. Call mheStoreCTChunkDS first.", call. = FALSE)
  }

  fusion_pk <- ss$peer_transport_pks[["fusion"]]
  if (is.null(fusion_pk)) {
    stop("Fusion server transport PK not stored. Call mheStoreTransportKeysDS first.",
         call. = FALSE)
  }

  # Reassemble ciphertext from chunks
  ct_b64url <- paste0(ss$ct_chunks[1:n_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)
  ss$ct_chunks <- NULL

  # Protocol Firewall: validate ciphertext is authorized
  .validate_and_consume_ciphertext(ct_b64, session_id = session_id)

  # Compute raw partial decryption share
  input <- list(
    ciphertext = ct_b64,
    secret_key = ss$secret_key,
    log_n = as.integer(ss$log_n %||% 12),
    log_scale = as.integer(ss$log_scale %||% 40)
  )
  result <- .callMheTool("mhe-partial-decrypt", input)

  # Transport-encrypt (wrap) the share under the fusion server's PK.
  # The share is a serialized KeySwitch share in standard base64.
  # After wrapping, the client sees only ciphertext it cannot decrypt.
  sealed <- .callMheTool("transport-encrypt", list(
    data = result$decryption_share,
    recipient_pk = fusion_pk
  ))

  list(
    wrapped_share = base64_to_base64url(sealed$sealed),
    party_id = ss$party_id
  )
}

#' Store a wrapped share on the fusion server
#'
#' Called by the client to relay a transport-encrypted partial decryption
#' share to the fusion server (party 0). The client cannot read the share
#' because it is encrypted under the fusion server's X25519 transport key.
#'
#' Supports chunked transfer: multiple calls with the same \code{party_id}
#' concatenate the data. The full share is assembled when
#' \code{\link{mheFuseServerDS}} is called.
#'
#' @param party_id Integer or character. Party ID of the server that
#'   produced this share.
#' @param share_data Character. The wrapped share data (base64url encoded),
#'   or a chunk of it. Multiple calls with the same \code{party_id}
#'   concatenate the data.
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return \code{TRUE} on success
#'
#' @seealso \code{\link{mhePartialDecryptWrappedDS}} which produces the
#'   wrapped share, \code{\link{mheFuseServerDS}} which consumes them
#' @export
mheStoreWrappedShareDS <- function(party_id, share_data, session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$wrapped_share_parts)) {
    ss$wrapped_share_parts <- list()
  }
  key <- as.character(party_id)
  # Concatenate chunks: multiple calls with the same party_id append data
  if (is.null(ss$wrapped_share_parts[[key]])) {
    ss$wrapped_share_parts[[key]] <- share_data
  } else {
    ss$wrapped_share_parts[[key]] <- paste0(
      ss$wrapped_share_parts[[key]], share_data)
  }
  TRUE
}

#' Fuse partial decryption shares server-side (fusion server only)
#'
#' Called on the fusion server (party 0) after all wrapped shares have been
#' relayed via \code{\link{mheStoreWrappedShareDS}} and the ciphertext
#' stored via \code{\link{mheStoreCTChunkDS}}. This function:
#' \enumerate{
#'   \item Reassembles the ciphertext from stored chunks
#'   \item Validates the ciphertext via the Protocol Firewall (one-time use)
#'   \item Unwraps (transport-decrypts) each wrapped share using its X25519 SK
#'   \item Computes its own partial decryption share (with noise smudging)
#'   \item Aggregates all shares and applies KeySwitch + DecodePublic(logprec=32)
#'   \item Returns only the final sanitized scalar/vector
#' }
#'
#' The client never sees raw decryption shares or unsanitized plaintext.
#'
#' @param n_parties Integer. Total number of MHE parties (including this
#'   fusion server). Used for validation only.
#' @param n_ct_chunks Integer. Number of stored ciphertext chunks.
#' @param num_slots Integer. Number of valid slots to return. Use 0 for a
#'   single scalar (slot 0 only), or n_obs for a vector. Default 0.
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return List with:
#'   \itemize{
#'     \item \code{value}: Decrypted scalar (first slot)
#'     \item \code{values}: Numeric vector of length \code{num_slots}
#'       (present only when \code{num_slots > 0})
#'   }
#'
#' @seealso \code{\link{mheStoreWrappedShareDS}} for storing wrapped shares,
#'   \code{\link{mhePartialDecryptWrappedDS}} for producing wrapped shares
#' @export
mheFuseServerDS <- function(n_parties, n_ct_chunks, num_slots = 0,
                            session_id = NULL) {
  ss <- .S(session_id)
  if (is.null(ss$secret_key)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$transport_sk)) {
    stop("Transport secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$ct_chunks) || length(ss$ct_chunks) < n_ct_chunks) {
    stop("Ciphertext chunks not stored.", call. = FALSE)
  }

  # Reassemble ciphertext from chunks
  ct_b64url <- paste0(ss$ct_chunks[1:n_ct_chunks], collapse = "")
  ct_b64 <- .base64url_to_base64(ct_b64url)
  ss$ct_chunks <- NULL

  # Protocol Firewall: validate ciphertext
  .validate_and_consume_ciphertext(ct_b64, session_id = session_id)

  # Collect wrapped shares (from other servers, stored via mheStoreWrappedShareDS)
  parts <- ss$wrapped_share_parts
  if (is.null(parts) || length(parts) == 0) {
    stop("No wrapped shares stored. Relay shares via mheStoreWrappedShareDS first.",
         call. = FALSE)
  }
  # Convert each assembled share from base64url to base64 (unnamed list for JSON array)
  wrapped_shares <- unname(lapply(parts, .base64url_to_base64))

  # Call mhe-fuse-server: unwrap + own partial decrypt + aggregate + DecodePublic
  result <- .callMheTool("mhe-fuse-server", list(
    ciphertext = ct_b64,
    secret_key = ss$secret_key,
    wrapped_shares = wrapped_shares,
    transport_secret_key = ss$transport_sk,
    num_slots = as.integer(num_slots),
    log_n = as.integer(ss$log_n %||% 12),
    log_scale = as.integer(ss$log_scale %||% 40)
  ))

  # Clean up wrapped shares
  ss$wrapped_share_parts <- NULL

  list(value = result$value, values = result$values)
}

#' Store a blob in server-side storage (with chunking support)
#'
#' Generic function for storing large data on the server via chunked
#' transfer. DataSHIELD's R expression parser imposes a limit on the
#' size of arguments passed inline in \code{call()} expressions.
#' Cryptographic objects (CKKS ciphertexts, EC points, key shares,
#' transport-encrypted blobs) routinely exceed this limit. This
#' function provides a store-and-assemble pattern: the client splits
#' large data into chunks (adaptive size, starting at 200 KB), sends each chunk via a
#' separate \code{datashield.aggregate} call, and the server
#' auto-assembles them when the last chunk arrives. Downstream
#' functions read the assembled blob via \code{from_storage = TRUE}.
#'
#' All data transferred through this mechanism is base64url-encoded
#' (standard base64 uses \code{+} and \code{/}, which the DSOpal
#' expression serializer can misinterpret).
#'
#' This pattern is used throughout the dsVert protocol stack:
#' \itemize{
#'   \item PSI: EC point vectors (\code{psiProcessTargetDS},
#'     \code{psiDoubleMaskDS}, \code{psiMatchAndAlignDS},
#'     \code{psiFilterCommonDS})
#'   \item MHE key setup: CRP, GKG seed, public key shares, Galois
#'     keys (\code{mheInitDS}, \code{mheCombineDS},
#'     \code{mheStoreCPKDS})
#'   \item Threshold decryption: ciphertext chunks, wrapped shares
#'   \item GLM Secure Routing: transport-encrypted vectors (eta,
#'     mu/w/v)
#'   \item Protocol Firewall: CT hash batches
#'     (\code{mheAuthorizeCTDS})
#' }
#'
#' @param key Character. Storage key (e.g., "mwv", "eta_server1")
#' @param chunk Character. The blob data (or a chunk of it)
#' @param chunk_index Integer. Current chunk index (1-based). Default 1.
#' @param n_chunks Integer. Total number of chunks. Default 1 (no chunking).
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When NULL, falls back to legacy global storage.
#'
#' @return TRUE on success
#' @export
mheStoreBlobDS <- function(key, chunk, chunk_index = 1L, n_chunks = 1L,
                           session_id = NULL) {
  ss <- .S(session_id)
  if (n_chunks == 1L) {
    # Single-call mode (no chunking)
    if (is.null(ss$blobs)) ss$blobs <- list()
    ss$blobs[[key]] <- chunk
  } else {
    # Chunked mode
    if (is.null(ss$blob_chunks)) ss$blob_chunks <- list()
    # Reset if n_chunks changed (adaptive retry with different chunk size)
    if (!is.null(ss$blob_chunks[[key]]) &&
        length(ss$blob_chunks[[key]]) != n_chunks) {
      ss$blob_chunks[[key]] <- NULL
    }
    if (is.null(ss$blob_chunks[[key]])) {
      ss$blob_chunks[[key]] <- character(n_chunks)
    }
    ss$blob_chunks[[key]][chunk_index] <- chunk

    # Auto-assemble when all chunks are present
    if (all(nzchar(ss$blob_chunks[[key]]))) {
      if (is.null(ss$blobs)) ss$blobs <- list()
      ss$blobs[[key]] <- paste0(ss$blob_chunks[[key]], collapse = "")
      ss$blob_chunks[[key]] <- NULL
    }
  }
  TRUE
}

#' Get number of observations for a variable
#'
#' @param data_name Character. Name of data frame
#' @param variables Character vector. Variables to check
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. Unused (stateless function) but accepted for API
#'   consistency.
#'
#' @return Integer. Number of complete observations
#' @export
mheGetObsDS <- function(data_name, variables, session_id = NULL) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = parent.frame())
  X <- as.matrix(data[, variables, drop = FALSE])
  sum(complete.cases(X))
}

#' Clean up MHE cryptographic state
#'
#' Removes all cryptographic material from server memory: secret key, CPK,
#' Galois keys, ciphertext registry, and any residual protocol state.
#' Called by the client at the end of each protocol execution to minimize
#' the window during which keys exist in memory.
#'
#' @param session_id Character or NULL. Session identifier for concurrent
#'   job isolation. When not NULL, cleans up only the specified session.
#'   When NULL, falls back to clearing the legacy global storage.
#'
#' @return TRUE on success
#' @export
mheCleanupDS <- function(session_id = NULL) {
  if (!is.null(session_id)) {
    .cleanup_session(session_id)
  } else {
    # Legacy fallback: clear global storage
    rm(list = ls(.mhe_storage), envir = .mhe_storage)
  }
  # Force garbage collection to release memory holding key material
  gc(verbose = FALSE)
  TRUE
}

# Null-coalescing operator
`%||%` <- function(x, y) if (is.null(x)) y else x
