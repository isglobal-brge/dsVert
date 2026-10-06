# Durable, custodian-owned authorization epochs. Nothing in this store is an
# analyst refresh token. Private digests and frozen frames never leave the node.
.DSVERT_PROVENANCE_PROTOCOL <- "dsvert-provenance-epochs-v1"
.DSVERT_PROVENANCE_MAGIC <- charToRaw("DSVEP001")

.dsvert_dp_provenance_require_protocol <- function(privacy_protocol) {
  if (!identical(privacy_protocol, .DSVERT_PROVENANCE_PROTOCOL)) {
    stop("Incompatible dsVert privacy protocol; use dsVertClient 1.4.1.",
         call. = FALSE)
  }
  invisible(TRUE)
}

#' Public provenance protocol capabilities
#' @return Public compatibility information; no source is inspected.
#' @export
dsvertProvenanceCapabilitiesDS <- function() {
  list(protocol = .DSVERT_PROVENANCE_PROTOCOL, version = "1.4.1",
       families = c("psi", "count", "frequency", "synopsis"))
}

.dsvert_dp_provenance_hash <- function(domain, value) {
  digest::digest(charToRaw(paste0(domain, .psi_padded_canonical_json(
    .dsvert_dp_canonical_query_value(value)))),
                 algo = "sha256", serialize = FALSE)
}

.dsvert_dp_provenance_public_hash <- function(public) {
  .dsvert_dp_provenance_hash("dsVert/provenance/source-contract/v1|",
    public[setdiff(names(public), "local_id_column")])
}

.dsvert_dp_provenance_agree <- function(receipts) {
  first <- receipts[[1L]]
  if (!all(vapply(receipts, function(value) {
    identical(value$authorization_epochs, first$authorization_epochs) &&
      identical(value$derivation_policy_id, first$derivation_policy_id)
  }, logical(1L)))) stop("Receipts disagree on source authorization epochs.",
                        call. = FALSE)
  invisible(TRUE)
}

.dsvert_dp_provenance_commitment <- function(attestation, config, peer_name,
                                            request) {
  epochs <- .psi_padded_validate_authorization_epochs(
    attestation$authorization_epochs, unname(config$peer_pins))
  .dsvert_dp_provenance_hash("dsVert/provenance/stable-snapshot/v1|", list(
    protocol = .DSVERT_PROVENANCE_PROTOCOL,
    domain = config$domain, cohort_id = config$cohort_id,
    owner_identity_pk = unname(config$peer_pins[[peer_name]]),
    dataset_id = config$dataset_id, dataset_version = config$dataset_version,
    alignment_purpose = config$alignment_purpose,
    derivation_policy_id = attestation$derivation_policy_id,
    authorization_epochs = epochs, request = request))
}

.dsvert_dp_provenance_source_key <- function(public) {
  if (!is.list(public) || is.null(names(public)) ||
      anyDuplicated(names(public)) || anyNA(names(public))) {
    stop("Invalid authorization source contract.", call. = FALSE)
  }
  .dsvert_dp_provenance_hash("dsVert/provenance/source-index/v1|", public)
}

.dsvert_dp_provenance_failure <- function() {
  stop("The source authorization store is unavailable; custodian recovery is required.",
       call. = FALSE)
}

.dsvert_dp_provenance_migration <- function() {
  stop("Source authorization migration required; the custodian must authorize this import with dsvertAuthorizeSource().",
       call. = FALSE)
}

.dsvert_dp_provenance_paths <- function() {
  # Identity namespacing also makes independently provisioned nodes safe when
  # sharing a test state root. Production node identities are persistent.
  identity <- digest::digest(.get_identity_keypair()$identity_pk,
                            algo = "sha256", serialize = FALSE)
  root <- .dsvert_state_root()
  file <- file.path(root, "privacy", "source-authorizations", identity,
                    "authorizations.state")
  .dsvert_dp_noise_private_directory(
    file, .allow_test_path = isTRUE(.dsvert_identity_test_mode()))
  list(file = file, marker = file.path(root, paste0(
    "source-authorizations-", identity, ".uuid")))
}

.dsvert_dp_provenance_regular <- function(path) {
  file.exists(path) && !.dsvert_dp_path_is_link(path) &&
    file_test("-f", path) &&
    .dsvert_dp_private_mode(path, directory = FALSE) &&
    identical(.dsvert_dp_noise_link_count(path), 1)
}

.dsvert_dp_provenance_mac <- function(bytes) {
  seed <- jsonlite::base64_dec(.get_identity_seed())
  on.exit({ seed[] <- as.raw(0L) }, add = TRUE)
  key <- digest::hmac(seed, charToRaw("dsVert/provenance/store-key/v1"),
                      algo = "sha256", serialize = FALSE, raw = TRUE)
  digest::hmac(key, bytes, algo = "sha256", serialize = FALSE, raw = TRUE)
}

.dsvert_dp_provenance_write <- function(value, path) {
  bytes <- serialize(value, NULL, version = 3L)
  authenticated <- c(.DSVERT_PROVENANCE_MAGIC, bytes)
  envelope <- c(.DSVERT_PROVENANCE_MAGIC,
                .dsvert_dp_provenance_mac(authenticated), bytes)
  temporary <- tempfile(".epoch-", tmpdir = dirname(path))
  on.exit(unlink(temporary), add = TRUE)
  connection <- file(temporary, "wb")
  tryCatch({writeBin(envelope, connection); flush(connection)},
           finally = close(connection))
  Sys.chmod(temporary, "0600")
  .dsvert_identity_require_sync(temporary, "authorization store")
  if (!file.rename(temporary, path)) .dsvert_dp_provenance_failure()
  .dsvert_identity_require_sync(path, "authorization store")
  .dsvert_identity_require_sync(dirname(path), "authorization directory")
  invisible(NULL)
}

.dsvert_dp_provenance_read <- function(path) {
  if (!.dsvert_dp_provenance_regular(path)) .dsvert_dp_provenance_failure()
  bytes <- readBin(path, "raw", n = file.info(path)$size)
  if (length(bytes) < 41L ||
      !identical(bytes[seq_len(8L)], .DSVERT_PROVENANCE_MAGIC)) {
    .dsvert_dp_provenance_failure()
  }
  payload <- bytes[-seq_len(40L)]
  mac <- .dsvert_dp_provenance_mac(c(.DSVERT_PROVENANCE_MAGIC, payload))
  if (!identical(bytes[9L:40L], mac)) .dsvert_dp_provenance_failure()
  # Verify the complete serialized payload before decoding any object. One
  # MAC covers the index and all rows, detecting selective deletion as well.
  tryCatch(unserialize(payload), error = function(e)
    .dsvert_dp_provenance_failure())
}

.dsvert_dp_provenance_transaction <- function(operation, create = FALSE) {
  paths <- .dsvert_dp_provenance_paths()
  .dsvert_dp_alignment_registry_with_lock(paths$file, {
    present <- file.exists(paths$file) || .dsvert_dp_path_is_link(paths$file)
    marked <- file.exists(paths$marker) || .dsvert_dp_path_is_link(paths$marker)
    expected <- getOption("dsvert.dp.provenance_store_uuid", NULL)
    if (xor(present, marked)) .dsvert_dp_provenance_failure()
    if (!present) {
      if (!is.null(expected)) .dsvert_dp_provenance_failure()
      if (!isTRUE(create)) return(NULL)
      uuid <- paste0(format(openssl::rand_bytes(32L)), collapse = "")
      state <- list(protocol = .DSVERT_PROVENANCE_PROTOCOL, uuid = uuid,
        revision = 0, sources = list(), current = list(), pins = list(),
        reservations = 0)
    } else {
      marker <- .dsvert_dp_provenance_read(paths$marker)
      state <- .dsvert_dp_provenance_read(paths$file)
      if (!is.list(state) || !identical(state$protocol,
          .DSVERT_PROVENANCE_PROTOCOL) || !identical(marker$uuid, state$uuid) ||
          (!is.null(expected) && !identical(expected, state$uuid))) {
        .dsvert_dp_provenance_failure()
      }
    }
    result <- operation(state)
    if (isTRUE(result$changed)) {
      result$state$revision <- state$revision + 1
      # A crash between initial marker and store publication fails closed.
      # Recovery never silently generates replacement authorization epochs.
      if (!present) .dsvert_dp_provenance_write(
        list(protocol = .DSVERT_PROVENANCE_PROTOCOL, uuid = state$uuid),
        paths$marker)
      .dsvert_dp_provenance_write(result$state, paths$file)
    }
    result$value
  })
}

.dsvert_dp_provenance_reserve <- function(state, small = FALSE) {
  # A public, fixed maximum per authorization/pin; no private hit or encoded
  # frame size releases credits. Entries are never expired or evicted.
  charge <- if (isTRUE(small)) 8192 else getOption(
    "dsvert.dp.provenance_record_bytes", 64 * 1024^2)
  capacity <- getOption("dsvert.dp.provenance_store_bytes", 1024^3)
  if (!is.numeric(charge) || length(charge) != 1L || !is.finite(charge) ||
      charge < 8192 || !is.numeric(capacity) || length(capacity) != 1L ||
      !is.finite(capacity) || capacity < charge ||
      state$reservations + charge > capacity) {
    stop("The authorization store has no capacity for this public identity.",
         call. = FALSE)
  }
  state$reservations <- state$reservations + charge
  state
}

.dsvert_dp_provenance_lookup <- function(public, epoch = NULL) {
  key <- .dsvert_dp_provenance_source_key(public)
  .dsvert_dp_provenance_transaction(function(state) {
    selected <- if (is.null(epoch)) state$current[[key]] else epoch
    record <- if (is.null(selected)) NULL else state$sources[[selected]]
    if (!is.null(selected) && (is.null(record) ||
        !identical(record$source_key, key))) .dsvert_dp_provenance_failure()
    list(changed = FALSE, value = record)
  })
}

.dsvert_dp_provenance_source <- function(
    public, descriptor, data, event_id = NULL, automatic = FALSE,
    provenance = NULL, epoch = NULL) {
  key <- .dsvert_dp_provenance_source_key(public)
  if (!is.null(event_id) && (!is.character(event_id) || length(event_id) != 1L ||
      is.na(event_id) || !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", event_id))) {
    stop("An authorization event needs a stable custodian event_id.", call. = FALSE)
  }
  answer <- .dsvert_dp_provenance_transaction(function(state) {
    current <- if (is.null(epoch)) state$current[[key]] else epoch
    if (is.null(event_id) && !is.null(current)) {
      record <- state$sources[[current]]
      if (is.null(record) || !identical(record$source_key, key)) {
        .dsvert_dp_provenance_failure()
      }
      return(list(changed = FALSE, value = record))
    }
    if (is.null(event_id) && !isTRUE(automatic)) {
      .dsvert_dp_provenance_migration()
    }
    event <- if (is.null(event_id)) "automatic-first-registration" else event_id
    event_key <- .dsvert_dp_provenance_hash(
      "dsVert/provenance/event/v1|", list(source = key,
        kind = if (is.null(event_id)) "automatic" else "custodian", event = event))
    for (record in state$sources) {
      if (identical(record$event_key, event_key)) {
        return(list(changed = FALSE, value = record))
      }
    }
    state <- .dsvert_dp_provenance_reserve(state)
    # Force only after lookup/reservation. Registered sources never consult
    # today's frame or descriptor and cannot reveal intersection freshness.
    frozen <- data
    if (!is.data.frame(frozen)) stop("Authorization requires a data frame.",
                                    call. = FALSE)
    # The first caller retains this same record after the durable write. Copy
    # columns as well as the frame so by-reference updates to a live source
    # cannot change its captured authorization (including data.table inputs).
    frozen <- unserialize(serialize(frozen, NULL, version = 3L))
    epoch <- paste0(format(openssl::rand_bytes(32L)), collapse = "")
    record <- list(epoch = epoch, source_key = key,
      source_contract_id = .dsvert_dp_provenance_public_hash(public),
      public = public, event_key = event_key, event_id = event,
      descriptor = descriptor, data = frozen,
      snapshot_sha256 = .dsvert_dp_snapshot_digest(frozen),
      provenance = provenance)
    state$sources[[epoch]] <- record
    state$current[[key]] <- epoch
    if (is.null(event_id)) message(
      "dsVert custodian notice: registered source ", key,
      " once in authorization epoch ", epoch, ". Retain the authorization store.")
    list(changed = TRUE, state = state, value = record)
  }, create = !is.null(event_id) || isTRUE(automatic))
  if (is.null(answer)) .dsvert_dp_provenance_migration()
  answer
}

.dsvert_dp_provenance_private_pin <- function(namespace, key, value,
                                              create = FALSE) {
  index <- .dsvert_dp_provenance_hash("dsVert/provenance/private-pin/v1|",
    list(namespace = namespace, key = key))
  result <- .dsvert_dp_provenance_transaction(function(state) {
    record <- state$pins[[index]]
    if (!is.null(record)) {
      if (!identical(record$value, value)) {
        stop("The immutable authorized material failed its private integrity check.",
             call. = FALSE)
      }
      return(list(changed = FALSE, value = TRUE))
    }
    if (!isTRUE(create)) .dsvert_dp_provenance_failure()
    state <- .dsvert_dp_provenance_reserve(state, small = TRUE)
    state$pins[[index]] <- list(value = value)
    list(changed = TRUE, state = state, value = TRUE)
  }, create = create)
  if (is.null(result)) .dsvert_dp_provenance_failure()
  invisible(result)
}

.dsvert_dp_provenance_pin <- function(key, data, metadata = list(),
                                      create = FALSE) {
  index <- .dsvert_dp_provenance_hash("dsVert/provenance/pin/v1|", key)
  result <- .dsvert_dp_provenance_transaction(function(state) {
    record <- state$pins[[index]]
    if (!is.null(record)) {
      if (!identical(record$digest, .dsvert_dp_snapshot_digest(data)) ||
          !identical(record$metadata, metadata)) {
        stop("The immutable authorized material failed its private integrity check.",
             call. = FALSE)
      }
      return(list(changed = FALSE, value = record$data))
    }
    if (!isTRUE(create)) .dsvert_dp_provenance_failure()
    state <- .dsvert_dp_provenance_reserve(state)
    state$pins[[index]] <- list(data = data, metadata = metadata,
                               digest = .dsvert_dp_snapshot_digest(data))
    list(changed = TRUE, state = state, value = data)
  }, create = create)
  if (is.null(result)) .dsvert_dp_provenance_failure()
  result
}

#' Authorize a source as a durable frozen publication
#'
#' Administrative only: never registered on the DataSHIELD allowlist. A new
#' event allocates a fresh random epoch even when the data are unchanged. Reuse
#' event_id only for retries of that exact event. Legacy aligned imports must
#' be migrated once with this command before any upgraded analysis can use them.
#' @param data Custodian-owned current data frame.
#' @param descriptor Private source or dataset descriptor.
#' @param event_id Stable custodian event identifier, reused on retries only.
#' @param kind Either 'dataset' for an aligned import or 'psi' for a raw source.
#' @param patient_column Local privacy-unit column for a dataset import.
#' @param public Optional complete public source contract for provisioning.
#' @param provenance Optional authenticated pre-alignment dependency provenance.
#' @return Private authorization record. Never disclose it to an analyst.
#' @export
dsvertAuthorizeSource <- function(data, descriptor, event_id,
    kind = c("dataset", "psi"), patient_column = NULL,
    public = NULL, provenance = NULL) {
  kind <- match.arg(kind)
  if (is.null(public)) {
    if (identical(kind, "psi")) {
      public <- .psi_padded_authorization_public(descriptor)
    } else {
      if (is.null(patient_column)) patient_column <- getOption(
        "dsvert.dp.patient_column", getOption("default.dsvert.dp.patient_column"))
      public <- .dsvert_dp_dataset_authorization_public(
        descriptor, patient_column)
    }
  }
  normalized_descriptor <- function() {
    if (identical(kind, "dataset")) {
      return(.dsvert_dp_validate_datasets(list(source = descriptor))[[1L]])
    }
    value <- descriptor
    value$snapshot_sha256 <- tolower(.psi_padded_scalar(
      value$snapshot_sha256, "authorized snapshot digest", "^[0-9a-fA-F]{64}$"))
    value
  }
  captured <- NULL
  validated_data <- function() {
    if (!is.null(captured)) return(captured)
    frozen <- .dsvert_dp_freeze_snapshot_frame(data)
    checked <- normalized_descriptor()
    if (!identical(.dsvert_dp_snapshot_digest(frozen),
                   checked$snapshot_sha256)) {
      stop("The source does not match its custodian-approved snapshot.",
           call. = FALSE)
    }
    if (identical(kind, "dataset")) {
      .dsvert_dp_validate_descriptor_alignment(frozen, checked,
                                              patient_column)
    }
    captured <<- frozen
    frozen
  }
  validated_provenance <- function() {
    frozen <- validated_data()
    attestation <- attr(frozen, .PSI_PADDED_ATTESTATION_ATTRIBUTE, exact = TRUE)
    # A current authenticated PSI publication cannot be downgraded to a root
    # that omits its reconstructible upstream dependency vector.
    if (identical(kind, "dataset") && is.list(attestation) &&
        identical(attestation$public$attestation_version, 4L)) {
      attested <- .psi_padded_validate_persistent_attestation(frozen)
      derived <- list(epoch_vector = attested$authorization_epochs,
                      derivation_policy_id = attested$derivation_policy_id)
      if (!is.null(provenance) && !identical(
          .dsvert_dp_canonical_query_value(provenance),
          .dsvert_dp_canonical_query_value(derived))) {
        stop("The supplied dependency provenance disagrees with authenticated PSI.",
             call. = FALSE)
      }
      return(derived)
    }
    if (!is.null(provenance)) {
      stop("Dependency provenance requires a current authenticated PSI publication.",
           call. = FALSE)
    }
    NULL
  }
  .dsvert_dp_provenance_source(public, normalized_descriptor(), validated_data(),
    event_id = event_id, provenance = validated_provenance())
}

#' @rdname dsvertAuthorizeSource
#' @export
dsvertReauthorizeSource <- dsvertAuthorizeSource

#' List retained source authorization publications (custodian only)
#' @return Store UUID and private authorization metadata, without frame bytes.
#' @export
dsvertListSourceAuthorizations <- function() {
  .dsvert_dp_provenance_transaction(function(state) list(changed = FALSE,
    value = list(uuid = state$uuid, sources = lapply(state$sources,
      function(record) record[setdiff(names(record), "data")]))))
}

.dsvert_dp_dataset_authorization_public <- function(descriptor, patient_column) {
  list(kind = "dataset",
       id = .dsvert_dp_scalar_string(descriptor$id, "authorization dataset id"),
       version = .dsvert_dp_scalar_string(
         descriptor$version, "authorization dataset version"),
       local_id_column = .dsvert_dp_scalar_string(
         patient_column, "authorization patient column"))
}

# Stable public derivation semantics deliberately use a fixed domain in place
# of the session fallback study id (including the shared-key key-id input).
.psi_padded_authorization_public <- function(descriptor) {
  public <- list(
    alignment_purpose = descriptor$purpose,
    dataset_id = descriptor$id,
    dataset_version = descriptor$version,
    id_column = if (is.null(descriptor$privacy_unit_id)) descriptor$id_col else
      descriptor$privacy_unit_id)
  public$source_binding_id <- paste0("source_", digest::digest(
    .psi_padded_canonical_json(public), algo = "sha256", serialize = FALSE))
  public <- .psi_padded_validate_source_public(public)
  stable <- .psi_padded_policy("dsvert-stable-derivation-v1", public)$public
  derivation_policy_id <- digest::digest(
    .psi_padded_canonical_json(list(
      version = "dsvert-psi-derivation-policy-v1",
      identifier_canonicalization = "dsvert-canonical-label-v1",
      policy = stable)), algo = "sha256", serialize = FALSE)
  list(kind = "padded-psi-source-v1", source = public,
       derivation_policy_id = derivation_policy_id,
       local_id_column = descriptor$id_col)
}

