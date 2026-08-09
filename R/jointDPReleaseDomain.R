# Persistent, data-independent domain for joint-DP vector release instances.
#
# The sticky-noise root is intentionally long-lived. This independent public
# domain may identify a different candidate only before the first valid START
# irrevocably claims an instance for that capsule. Once claimed, state loss must
# continue or restore that exact instance or fail closed; after publication it
# may only be restored/replayed. A replacement domain cannot authorize fresh
# noise or a second publication. The domain contains no snapshot-derived
# material and is safe to publish.

.DSVERT_JOINT_DP_RELEASE_DOMAIN_VERSION <-
  "dsvert-joint-dp-release-domain-v1"

.dsvert_joint_dp_release_domain_id <- function(
    random_bytes = .dsvert_secure_random_bytes) {
  if (!is.function(random_bytes)) {
    stop("Invalid release-domain entropy source.", call. = FALSE)
  }
  bytes <- tryCatch(random_bytes(32L), error = function(error) NULL)
  if (!is.raw(bytes) || length(bytes) != 32L) {
    stop("Secure operating-system entropy is unavailable for the joint-DP release domain.",
         call. = FALSE)
  }
  paste0("rd_", paste(format(bytes), collapse = ""))
}

.dsvert_joint_dp_release_domain_validate <- function(record) {
  fields <- c(
    "version", "generation", "domain_id", "previous_domain_id",
    "rotation_count", "reason")
  scalar_whole <- function(value, minimum = 0) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value) && value == floor(value) && value >= minimum &&
      value <= 2^53 - 1
  }
  valid_previous <- is.null(record$previous_domain_id) ||
    (is.character(record$previous_domain_id) &&
       length(record$previous_domain_id) == 1L &&
       !is.na(record$previous_domain_id) &&
       grepl("^rd_[0-9a-f]{64}$", record$previous_domain_id))
  recovered_predecessor_gap <- is.list(record) &&
    identical(record$reason, "authenticated_release_recovery") &&
    is.numeric(record$generation) && length(record$generation) == 1L &&
    !is.na(record$generation) && record$generation > 1 &&
    is.null(record$previous_domain_id)
  valid <- is.list(record) && !is.null(names(record)) &&
    !anyNA(names(record)) && !anyDuplicated(names(record)) &&
    setequal(names(record), fields) &&
    identical(record$version, .DSVERT_JOINT_DP_RELEASE_DOMAIN_VERSION) &&
    scalar_whole(record$generation, 1) &&
    is.character(record$domain_id) && length(record$domain_id) == 1L &&
    !is.na(record$domain_id) &&
    grepl("^rd_[0-9a-f]{64}$", record$domain_id) &&
    isTRUE(valid_previous) &&
    scalar_whole(record$rotation_count, 0) &&
    identical(as.numeric(record$rotation_count),
              as.numeric(record$generation) - 1) &&
    is.character(record$reason) && length(record$reason) == 1L &&
    !is.na(record$reason) &&
    grepl("^[a-z][a-z0-9_]{0,127}$", record$reason) &&
    ((record$generation == 1 && is.null(record$previous_domain_id)) ||
       (record$generation > 1 &&
          ((is.character(record$previous_domain_id) &&
              !identical(record$previous_domain_id, record$domain_id)) ||
             isTRUE(recovered_predecessor_gap))))
  if (!isTRUE(valid)) {
    stop("The joint-DP release-domain record is invalid.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(record)
}

.dsvert_joint_dp_release_domain_recover_published_connection <- function(
    connection, secret) {
  config <- .dsvert_joint_dp_release_ledger_config_from_connection(
    connection, secret)
  if (is.null(config)) return(NULL)
  audit <- .dsvert_joint_dp_release_ledger_audit(
    connection, config, secret)
  if (!length(audit$records)) return(NULL)

  published <- audit$records[[length(audit$records)]]
  instance_id <- published$release_instance_id
  capsule <- .dsvert_joint_dp_vector_capsule_load(
    connection, instance_id, secret)
  if (is.null(capsule) || is.null(capsule$release_receipt_json)) {
    return(NULL)
  }
  recoverable_fields <- c(
    "capsule_id", "release_instance_id", "release_contract_hash",
    "transcript_hash", "release_contract", "plan", "designated")
  if (any(vapply(recoverable_fields, function(field) {
        is.null(capsule[[field]])
      }, logical(1L)))) {
    return(NULL)
  }
  contract <- .dsvert_joint_dp_vector_contract_from_record(capsule)
  instance_json <- .dsvert_joint_dp_vector_encode(
    contract$release_contract$release_instance)
  artifact <- .dsvert_joint_dp_release_ledger_artifact(
    config, instance_json, capsule$release_receipt_json)
  release <- .dsvert_joint_dp_vector_decode_json(
    capsule$release_receipt_json, "release-domain recovery receipt")
  .dsvert_joint_dp_vector_release_validate(release, contract)

  consistent <-
    identical(artifact$instance$id, instance_id) &&
    identical(published$release_instance_sha256,
              digest::digest(instance_json, algo = "sha256",
                             serialize = FALSE)) &&
    identical(published$final_release_sha256,
              artifact$final_release_sha256) &&
    identical(published$final_vector_root, artifact$final_vector_root) &&
    identical(
      .dsvert_dp_canonical_query_value(published$local_noise_root),
      .dsvert_dp_canonical_query_value(artifact$local_noise_root))
  if (!isTRUE(consistent)) {
    stop("The published vector evidence contradicts its authenticated release ledger.",
         call. = FALSE)
  }

  hashes <- unlist(release$final_chunk_hashes, use.names = FALSE)
  chunks <- lapply(seq_along(hashes) - 1L, function(index) {
    .dsvert_joint_dp_vector_final_load(
      connection, instance_id, index, secret)
  })
  if (any(vapply(chunks, is.null, logical(1L)))) return(NULL)
  durable_hashes <- vapply(chunks, function(chunk) {
    if (!identical(chunk$chunk_hash,
                   .dsvert_joint_dp_hash(chunk$public_chunk))) {
      stop("A durable final DP chunk contradicts its authenticated content.",
           call. = FALSE)
    }
    chunk$chunk_hash
  }, character(1L))
  if (!identical(unname(durable_hashes), unname(hashes)) ||
      !identical(.dsvert_joint_dp_vector_merkle_root(durable_hashes),
                 published$final_vector_root)) {
    stop("The durable final DP chunks contradict the published vector root.",
         call. = FALSE)
  }

  local_root <- artifact$local_noise_root
  generation <- as.numeric(local_root$release_domain_generation)
  previous_domain_id <- NULL
  if (generation > 1 && length(audit$records) > 1L) {
    previous <- rev(audit$records[-length(audit$records)])
    match <- which(vapply(previous, function(record) {
      root <- record$local_noise_root
      identical(as.numeric(root$release_domain_generation),
                generation - 1) &&
        !identical(root$release_domain_id,
                   local_root$release_domain_id)
    }, logical(1L)))
    if (length(match)) {
      previous_domain_id <-
        previous[[match[[1L]]]]$local_noise_root$release_domain_id
    }
  }
  .dsvert_joint_dp_release_domain_validate(list(
    version = .DSVERT_JOINT_DP_RELEASE_DOMAIN_VERSION,
    generation = generation,
    domain_id = local_root$release_domain_id,
    previous_domain_id = previous_domain_id,
    rotation_count = generation - 1,
    reason = "authenticated_release_recovery"))
}

.dsvert_joint_dp_release_domain_load_connection <- function(
    connection, secret, random_bytes = .dsvert_secure_random_bytes) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT value,row_mac FROM vector_meta",
    "WHERE key='release_domain'"))
  if (nrow(row)) {
    authenticated <- nrow(row) == 1L &&
      .dsvert_joint_dp_dsi_hex_equal(
        row$row_mac[[1L]], .dsvert_joint_dp_vector_row_mac(
          secret, "meta", row$value[[1L]]))
    value <- tryCatch(
      jsonlite::fromJSON(row$value[[1L]], simplifyVector = FALSE),
      error = function(error) NULL)
    value <- tryCatch(
      .dsvert_joint_dp_release_domain_validate(value),
      error = function(error) NULL)
    canonical <- if (is.null(value)) NULL else
      .dsvert_joint_dp_vector_record_json(value)
    if (isTRUE(authenticated) &&
        identical(canonical, row$value[[1L]])) {
      return(value)
    }
    recovered <-
      .dsvert_joint_dp_release_domain_recover_published_connection(
        connection, secret)
    if (!is.null(recovered)) {
      json <- .dsvert_joint_dp_vector_record_json(recovered)
      mac <- .dsvert_joint_dp_vector_row_mac(secret, "meta", json)
      changed <- DBI::dbExecute(connection, paste(
        "UPDATE vector_meta SET value=?,row_mac=?",
        "WHERE key='release_domain'"), params = list(json, mac))
      if (!identical(as.integer(changed), 1L)) {
        stop("The joint-DP release-domain recovery lost its atomic update.",
             call. = FALSE)
      }
      return(recovered)
    }
    # This identifier is public, not key material. If neither the row nor a
    # complete authenticated published vector can prove the prior domain, a
    # fresh identifier may form a different candidate only before that capsule's
    # first valid START claim. A claimed capsule must continue or restore its
    # exact instance, and a published capsule must replay it, or fail closed.
    recovered <- .dsvert_joint_dp_release_domain_validate(list(
      version = .DSVERT_JOINT_DP_RELEASE_DOMAIN_VERSION,
      generation = 1,
      domain_id = .dsvert_joint_dp_release_domain_id(random_bytes),
      previous_domain_id = NULL,
      rotation_count = 0,
      reason = "corrupt_record_recovery"))
    json <- .dsvert_joint_dp_vector_record_json(recovered)
    mac <- .dsvert_joint_dp_vector_row_mac(secret, "meta", json)
    changed <- DBI::dbExecute(connection, paste(
      "UPDATE vector_meta SET value=?,row_mac=?",
      "WHERE key='release_domain'"), params = list(json, mac))
    if (!identical(as.integer(changed), 1L)) {
      stop("The joint-DP release-domain recovery lost its atomic update.",
           call. = FALSE)
    }
    return(recovered)
  }
  recovered <- .dsvert_joint_dp_release_domain_recover_published_connection(
    connection, secret)
  if (!is.null(recovered)) {
    json <- .dsvert_joint_dp_vector_record_json(recovered)
    mac <- .dsvert_joint_dp_vector_row_mac(secret, "meta", json)
    DBI::dbExecute(connection, paste(
      "INSERT INTO vector_meta(key,value,row_mac)",
      "VALUES('release_domain',?,?)"), params = list(json, mac))
    return(recovered)
  }
  value <- .dsvert_joint_dp_release_domain_validate(list(
    version = .DSVERT_JOINT_DP_RELEASE_DOMAIN_VERSION,
    generation = 1,
    domain_id = .dsvert_joint_dp_release_domain_id(random_bytes),
    previous_domain_id = NULL,
    rotation_count = 0,
    reason = "first_vector_store"))
  json <- .dsvert_joint_dp_vector_record_json(value)
  mac <- .dsvert_joint_dp_vector_row_mac(secret, "meta", json)
  DBI::dbExecute(connection, paste(
    "INSERT INTO vector_meta(key,value,row_mac)",
    "VALUES('release_domain',?,?)"), params = list(json, mac))
  value
}

.dsvert_joint_dp_release_domain_current <- function(
    policy, secret, random_bytes = .dsvert_secure_random_bytes) {
  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    .dsvert_joint_dp_release_domain_load_connection(
      connection, secret, random_bytes)
  })
}

.dsvert_joint_dp_release_domain_rotate_connection <- function(
    connection, secret, expected_domain_id, reason,
    random_bytes = .dsvert_secure_random_bytes) {
  if (!is.character(expected_domain_id) ||
      length(expected_domain_id) != 1L || is.na(expected_domain_id) ||
      !grepl("^rd_[0-9a-f]{64}$", expected_domain_id)) {
    stop("Invalid expected joint-DP release domain.", call. = FALSE)
  }
  if (!is.character(reason) || length(reason) != 1L || is.na(reason) ||
      !grepl("^[a-z][a-z0-9_]{0,127}$", reason)) {
    stop("Invalid joint-DP release-domain rotation reason.", call. = FALSE)
  }
  current <- .dsvert_joint_dp_release_domain_load_connection(
    connection, secret, random_bytes)
  # Concurrent/stale recovery requests are idempotent: only the request that
  # still names the active domain may rotate it.
  if (!identical(current$domain_id, expected_domain_id)) return(current)
  next_record <- .dsvert_joint_dp_release_domain_validate(list(
    version = .DSVERT_JOINT_DP_RELEASE_DOMAIN_VERSION,
    generation = current$generation + 1,
    domain_id = .dsvert_joint_dp_release_domain_id(random_bytes),
    previous_domain_id = current$domain_id,
    rotation_count = current$rotation_count + 1,
    reason = reason))
  json <- .dsvert_joint_dp_vector_record_json(next_record)
  mac <- .dsvert_joint_dp_vector_row_mac(secret, "meta", json)
  changed <- DBI::dbExecute(connection, paste(
    "UPDATE vector_meta SET value=?,row_mac=?",
    "WHERE key='release_domain' AND value=?"),
    params = list(
      json, mac, .dsvert_joint_dp_vector_record_json(current)))
  if (!identical(as.integer(changed), 1L)) {
    stop("The joint-DP release-domain rotation lost its atomic update.",
         call. = FALSE)
  }
  next_record
}

.dsvert_joint_dp_release_domain_rotate <- function(
    policy, secret, expected_domain_id, reason,
    random_bytes = .dsvert_secure_random_bytes) {
  .dsvert_joint_dp_vector_with_store(policy, secret, function(connection) {
    .dsvert_joint_dp_vector_transaction(connection, {
      .dsvert_joint_dp_release_domain_rotate_connection(
        connection, secret, expected_domain_id, reason, random_bytes)
    })
  })
}

.dsvert_joint_dp_release_domain_public <- function(record) {
  record <- .dsvert_joint_dp_release_domain_validate(record)
  list(
    version = record$version,
    generation = as.numeric(record$generation),
    domain_id = record$domain_id,
    rotation_count = as.numeric(record$rotation_count),
    automatic_generation = TRUE,
    automatic_rotation = TRUE,
    snapshot_derived = FALSE,
    key_material_exposed = FALSE)
}
