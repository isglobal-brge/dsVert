#' @title MHE Key Generation and Combination
#' @description Key generation, RLK aggregation, public key combination, and
#'   collective public key storage for the MHE threshold protocol.
#' @name mhe-key-setup
NULL

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
    blobs <- .blob_snapshot(ss)
    # Allow party_id to be stored in blobs for parallel init
    if (!is.null(blobs) && !is.null(blobs[["party_id"]])) {
      input$party_id <- as.integer(blobs[["party_id"]])
    }
    if (!is.null(blobs) && !is.null(blobs[["crp"]])) {
      input$crp <- .base64url_to_base64(blobs[["crp"]])
    }
    if (!is.null(blobs) && !is.null(blobs[["gkg_seed"]])) {
      input$gkg_seed <- .base64url_to_base64(blobs[["gkg_seed"]])
    }
    .blob_nuke(ss)
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
  .key_put("secret_key", result$secret_key, ss)
  ss$party_id <- input$party_id
  ss$log_n <- log_n
  ss$log_scale <- log_scale

  # Generate X25519 transport keypair for share-wrapping and GLM secure routing.
  # The transport SK is stored locally (NEVER returned); the PK is distributed
  # to all other servers via the client so they can encrypt data for us.
  transport <- .callMheTool("transport-keygen", list())
  .key_put("transport_sk", transport$secret_key, ss)
  .key_put("transport_pk", transport$public_key, ss)

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
    blobs <- .blob_snapshot(ss)
    if (length(blobs) == 0L) stop("No blobs stored for RLK R1 aggregation", call. = FALSE)

    r1_shares <- character(n_parties)
    for (i in seq_len(n_parties)) {
      r1_shares[i] <- .base64url_to_base64(blobs[[paste0("rlk_r1_", i - 1)]])
    }
    .blob_nuke(ss)
  } else {
    stop("Direct argument mode not supported for RLK aggregation", call. = FALSE)
  }

  input <- list(
    rlk_round1_shares = as.list(r1_shares),
    log_n = as.integer(ss$log_n %||% 13),
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
  if (!.key_exists("secret_key", ss)) {
    stop("Secret key not stored. Call mheInitDS first.", call. = FALSE)
  }
  if (is.null(ss$rlk_ephemeral_sk)) {
    stop("RLK ephemeral SK not stored. Call mheInitDS with generate_rlk=TRUE.", call. = FALSE)
  }

  if (from_storage) {
    blobs <- .blob_snapshot(ss)
    if (length(blobs) > 0L && !is.null(blobs[["rlk_agg_r1"]])) {
      agg_r1 <- .base64url_to_base64(blobs[["rlk_agg_r1"]])
      .blob_nuke(ss)
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
    secret_key = .key_get("secret_key", ss),
    rlk_ephemeral_sk = ss$rlk_ephemeral_sk,
    aggregated_round1 = agg_r1,
    log_n = as.integer(ss$log_n %||% 13),
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
    blobs <- .blob_snapshot(ss)
    if (length(blobs) == 0L) stop("No blobs stored for combine", call. = FALSE)

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
    .blob_nuke(ss)
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
  .key_put("cpk", result$collective_public_key, ss)
  .key_put("galois_keys", result$galois_keys, ss)
  .key_put("relin_key", result$relinearization_key, ss)

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
    blobs <- .blob_snapshot(ss)
    if (length(blobs) == 0L) stop("No blobs stored for CPK", call. = FALSE)

    .key_put("cpk", .base64url_to_base64(blobs[["cpk"]]), ss)

    # Galois keys: individual blobs (gk_0, gk_1, ...)
    gk_keys <- sort(grep("^gk_", names(blobs), value = TRUE))
    if (length(gk_keys) > 0) {
      .key_put("galois_keys", sapply(gk_keys, function(k)
        .base64url_to_base64(blobs[[k]]), USE.NAMES = FALSE), ss)
    }

    if (!is.null(blobs[["rk"]]))
      .key_put("relin_key", .base64url_to_base64(blobs[["rk"]]), ss)

    .blob_nuke(ss)
  } else {
    .key_put("cpk", .base64url_to_base64(cpk), ss)

    if (!is.null(galois_keys)) {
      .key_put("galois_keys", sapply(galois_keys, .base64url_to_base64, USE.NAMES = FALSE), ss)
    }
    if (!is.null(relin_key)) {
      .key_put("relin_key", .base64url_to_base64(relin_key), ss)
    }
  }

  TRUE
}
