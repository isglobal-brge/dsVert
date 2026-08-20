# Private bridge between one completed padded-PSI assignment and the immutable
# DP dataset policy.  The analyst can trigger PSI, but cannot create a registry
# entry: the aligned symbol must already have an exact custodian-owned
# dsvert.dp.datasets template and a live authenticated padded-PSI attestation.

.DSVERT_DP_PADDED_ALIGNMENT_BINDING_VERSION <- 4L
.DSVERT_DP_PADDED_ALIGNMENT_BINDING_PROTOCOL <-
  "dsvert-padded-psi-dp-alignment-binding-v2"
.DSVERT_DP_ALIGNED_REGISTRY_PROTOCOL <-
  "dsvert-private-aligned-dataset-registry-v2"
.DSVERT_DP_ALIGNED_REGISTRY_HMAC_DOMAIN <-
  "dsVert/private-aligned-dataset-registry/hmac-sha256/v2|"
.DSVERT_DP_ALIGNED_REGISTRY_MAX_BYTES <- 256L * 1024L

.dsvert_dp_padded_alignment_binding <- function(
    data, snapshot_sha256 = NULL) {
  alignment <- .psi_validate_alignment_manifest(data)
  attestation <- .psi_padded_validate_persistent_attestation(data)
  local_id_column <- alignment$id_col
  semantic <- list(
    version = .DSVERT_DP_PADDED_ALIGNMENT_BINDING_PROTOCOL,
    alignment_protocol = attestation$alignment_protocol,
    alignment_purpose = attestation$alignment_purpose,
    dataset_id = attestation$dataset_id,
    dataset_version = attestation$dataset_version,
    id_column = attestation$id_column,
    source_binding_id = attestation$source_binding_id,
    pinset_id = attestation$pinset_id,
    peer_count = as.integer(attestation$peer_count),
    reference_peer = attestation$reference_peer,
    compute_peers = as.list(unname(attestation$compute_peers)))
  if (is.null(snapshot_sha256)) {
    snapshot_sha256 <- .dsvert_dp_snapshot_digest(data)
  } else if (!is.character(snapshot_sha256) ||
             length(snapshot_sha256) != 1L || is.na(snapshot_sha256) ||
             !grepl("^[0-9a-f]{64}$", snapshot_sha256)) {
    stop("The precomputed protected snapshot digest is invalid",
         call. = FALSE)
  }
  stable_hash <- digest::digest(
    .psi_padded_canonical_json(list(
      protocol = .DSVERT_DP_PADDED_ALIGNMENT_BINDING_PROTOCOL,
      semantic = semantic)),
    algo = "sha256", serialize = FALSE)
  private_binding <- digest::digest(
    .psi_padded_canonical_json(list(
      protocol = .DSVERT_DP_ALIGNED_REGISTRY_PROTOCOL,
      snapshot_sha256 = snapshot_sha256,
      local_id_column = local_id_column,
      alignment_sha256 = stable_hash,
      semantic = semantic)),
    algo = "sha256", serialize = FALSE)
  list(
    descriptor = list(
      id = attestation$dataset_id,
      version = attestation$dataset_version,
      snapshot_sha256 = snapshot_sha256,
      alignment_manifest_hash = stable_hash,
      alignment_manifest_version =
        .DSVERT_DP_PADDED_ALIGNMENT_BINDING_VERSION),
    semantic = semantic,
    registry_binding_sha256 = private_binding,
    local_id_column = local_id_column,
    alignment = list(
      version = .DSVERT_DP_PADDED_ALIGNMENT_BINDING_VERSION,
      hash = stable_hash, id_col = alignment$id_col))
}

.dsvert_dp_validate_descriptor_alignment <- function(
    data, descriptor, patient_column = NULL, expected_pinset = NULL,
    snapshot_sha256 = NULL) {
  version <- descriptor$alignment_manifest_version
  if (identical(
      as.integer(version), .DSVERT_DP_PADDED_ALIGNMENT_BINDING_VERSION)) {
    binding <- .dsvert_dp_padded_alignment_binding(
      data, snapshot_sha256 = snapshot_sha256)
    if (!identical(binding$descriptor$id, descriptor$id) ||
        !identical(binding$descriptor$version, descriptor$version) ||
        !identical(binding$descriptor$snapshot_sha256,
                   descriptor$snapshot_sha256) ||
        !identical(binding$descriptor$alignment_manifest_hash,
                   descriptor$alignment_manifest_hash)) {
      stop("The protected object does not match its custodian-approved padded PSI binding",
           call. = FALSE)
    }
    if (!is.null(expected_pinset)) {
      expected_pinset_id <- .psi_padded_pinset_id(as.list(expected_pinset))
      compute_peers <- unlist(
        binding$semantic$compute_peers, use.names = FALSE)
      pinset_valid <- identical(
        binding$semantic$pinset_id, expected_pinset_id) &&
        identical(
          as.integer(binding$semantic$peer_count), length(expected_pinset)) &&
        binding$semantic$reference_peer %in% names(expected_pinset) &&
        all(compute_peers %in% names(expected_pinset)) &&
        binding$semantic$reference_peer %in% compute_peers
      if (!isTRUE(pinset_valid)) {
        stop("The protected object's padded PSI binding uses a different pinned peer set",
             call. = FALSE)
      }
    }
    alignment <- binding$alignment
  } else {
    # Explicit legacy descriptors remain readable. Automatic provisioning and
    # the exported helper never create this weaker generic-manifest form.
    alignment <- .psi_validate_alignment_manifest(data)
    if (!identical(alignment$hash, descriptor$alignment_manifest_hash) ||
        !identical(as.integer(alignment$version), as.integer(version))) {
      stop("The protected object does not match its custodian-approved PSI alignment manifest",
           call. = FALSE)
    }
  }
  if (!is.null(patient_column) &&
      !identical(alignment$id_col, patient_column)) {
    stop("The protected object's PSI alignment uses the wrong privacy-unit column",
         call. = FALSE)
  }
  alignment
}

.dsvert_dp_alignment_registry_templates <- function() {
  value <- getOption(
    "dsvert.dp.datasets", getOption("default.dsvert.dp.datasets"))
  if (is.null(value)) return(NULL)
  if (!is.list(value) || !length(value) || is.null(names(value)) ||
      anyNA(names(value)) || any(!nzchar(names(value))) ||
      anyDuplicated(names(value))) {
    stop("dsvert.dp.datasets must be a non-empty, uniquely named list",
         call. = FALSE)
  }
  value
}

.dsvert_dp_alignment_registry_template <- function(data_name) {
  templates <- .dsvert_dp_alignment_registry_templates()
  if (is.null(templates) || is.null(templates[[data_name]])) return(NULL)
  template <- templates[[data_name]]
  if (!is.list(template) || is.null(names(template)) ||
      anyNA(names(template)) || any(!nzchar(names(template))) ||
      anyDuplicated(names(template)) ||
      !all(c("id", "version") %in% names(template))) {
    stop("The aligned symbol has a contradictory custodian DP dataset template",
         call. = FALSE)
  }
  template
}

.dsvert_dp_alignment_registry_path <- function(
    data_name, id, version, pinset_id) {
  fields <- c(data_name, id, version)
  if (any(!vapply(fields, function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)
  }, logical(1L)))) {
    stop("Invalid private aligned-dataset registry identity", call. = FALSE)
  }
  if (!is.character(pinset_id) || length(pinset_id) != 1L ||
      is.na(pinset_id) ||
      !grepl("^pinset_[0-9a-f]{64}$", pinset_id)) {
    stop("Invalid private aligned-dataset registry pinset", call. = FALSE)
  }
  root <- .dsvert_state_root()
  path <- file.path(root, "privacy", "aligned-datasets")
  if (!isTRUE(.dsvert_identity_test_mode())) {
    .dsvert_dp_reject_ephemeral_or_library_path(
      file.path(path, "registry"), "aligned-dataset registry")
  }
  components <- c(root, file.path(root, "privacy"), path)
  for (component in components) {
    if (.dsvert_dp_path_is_link(component)) {
      stop("The private aligned-dataset registry path must not contain symbolic links",
           call. = FALSE)
    }
    if (!dir.exists(component)) {
      created <- dir.create(
        component, recursive = FALSE, mode = "0700", showWarnings = FALSE)
      # Another authenticated attestation may win this exact mkdir race.
      # Treat that as success only after re-checking that a directory now
      # exists; links and permissions are still rejected below.
      if (!isTRUE(created) && !dir.exists(component)) {
        stop("Could not create the private aligned-dataset registry",
             call. = FALSE)
      }
    }
    Sys.chmod(component, mode = "0700")
    if (.dsvert_dp_path_is_link(component) || !dir.exists(component) ||
        !.dsvert_dp_private_mode(component, directory = TRUE)) {
      stop("The private aligned-dataset registry must be owner-only",
           call. = FALSE)
    }
  }
  key <- digest::digest(
    .psi_padded_canonical_json(list(
      data_name = data_name, id = id, version = version,
      pinset_id = pinset_id)),
    algo = "sha256", serialize = FALSE)
  file.path(path, paste0("dataset_", key, ".json"))
}

.dsvert_dp_alignment_registry_hmac <- function(payload_json) {
  if (!is.character(payload_json) || length(payload_json) != 1L ||
      is.na(payload_json) || !nzchar(payload_json)) {
    stop("Invalid private aligned-dataset registry payload", call. = FALSE)
  }
  seed <- jsonlite::base64_dec(.get_identity_seed())
  on.exit({
    if (is.raw(seed) && length(seed)) seed[] <- as.raw(0L)
    seed <- NULL
  }, add = TRUE)
  if (!is.raw(seed) || length(seed) != 32L) {
    stop("The persistent identity cannot authenticate the aligned-dataset registry",
         call. = FALSE)
  }
  digest::hmac(
    key = seed,
    object = charToRaw(paste0(
      .DSVERT_DP_ALIGNED_REGISTRY_HMAC_DOMAIN, payload_json)),
    algo = "sha256", serialize = FALSE, raw = FALSE)
}

.dsvert_dp_alignment_registry_same_hex <- function(left, right) {
  decode <- function(value) {
    if (!is.character(value) || length(value) != 1L || is.na(value) ||
        !grepl("^[0-9a-f]{64}$", value)) return(NULL)
    positions <- seq.int(1L, 63L, by = 2L)
    as.raw(strtoi(substring(value, positions, positions + 1L), base = 16L))
  }
  left <- decode(left)
  right <- decode(right)
  !is.null(left) && !is.null(right) && length(left) == length(right) &&
    !any(bitwXor(as.integer(left), as.integer(right)) != 0L)
}

.dsvert_dp_alignment_registry_payload_validate <- function(value) {
  fields <- c(
    "protocol", "data_name", "local_id_column", "descriptor", "semantic",
    "binding_sha256")
  fail <- function() stop(
    "The private aligned-dataset registry record is invalid", call. = FALSE)
  if (!is.list(value) || !identical(names(value), fields) ||
      !identical(value$protocol, .DSVERT_DP_ALIGNED_REGISTRY_PROTOCOL) ||
      !is.character(value$data_name) || length(value$data_name) != 1L ||
      is.na(value$data_name) ||
      !grepl("^[A-Za-z.][A-Za-z0-9._]{0,127}$", value$data_name) ||
      !is.character(value$local_id_column) ||
      length(value$local_id_column) != 1L ||
      is.na(value$local_id_column) ||
      !grepl("^[A-Za-z._][A-Za-z0-9._]{0,127}$",
             value$local_id_column) ||
      !is.list(value$descriptor) || !is.list(value$semantic) ||
      !is.character(value$binding_sha256) ||
      length(value$binding_sha256) != 1L || is.na(value$binding_sha256) ||
      !grepl("^[0-9a-f]{64}$", value$binding_sha256)) fail()
  descriptor_fields <- c(
    "id", "version", "snapshot_sha256", "alignment_manifest_hash",
    "alignment_manifest_version")
  if (!identical(names(value$descriptor), descriptor_fields) ||
      !identical(as.integer(value$descriptor$alignment_manifest_version),
                 .DSVERT_DP_PADDED_ALIGNMENT_BINDING_VERSION) ||
      !all(vapply(value$descriptor[c(
        "snapshot_sha256", "alignment_manifest_hash")], function(item) {
          is.character(item) && length(item) == 1L && !is.na(item) &&
            grepl("^[0-9a-f]{64}$", item)
        }, logical(1L)))) fail()
  semantic_fields <- c(
    "version", "alignment_protocol", "alignment_purpose", "dataset_id",
    "dataset_version", "id_column", "source_binding_id", "pinset_id",
    "peer_count", "reference_peer", "compute_peers")
  if (!identical(names(value$semantic), semantic_fields) ||
      !identical(value$semantic$version,
                 .DSVERT_DP_PADDED_ALIGNMENT_BINDING_PROTOCOL) ||
      !identical(value$semantic$alignment_protocol,
                 .DSVERT_PSI_PADDED_PROTOCOL) ||
      !identical(value$descriptor$id, value$semantic$dataset_id) ||
      !identical(value$descriptor$version, value$semantic$dataset_version) ||
      !is.list(value$semantic$compute_peers) ||
      length(value$semantic$compute_peers) != 2L) fail()
  source <- value$semantic[c(
    "alignment_purpose", "dataset_id", "dataset_version", "id_column",
    "source_binding_id")]
  tryCatch({
    .psi_padded_validate_source_public(source)
    .psi_padded_scalar(value$semantic$pinset_id, "pinset id",
                       "^pinset_[0-9a-f]{64}$")
    .psi_padded_integer(value$semantic$peer_count, "peer count", 2L, 1000000L)
    .psi_padded_scalar(value$semantic$reference_peer, "reference peer",
                       "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    compute <- unlist(value$semantic$compute_peers, use.names = FALSE)
    if (!is.character(compute) || length(compute) != 2L ||
        anyNA(compute) || anyDuplicated(compute)) fail()
    invisible(lapply(compute, .psi_padded_scalar, what = "compute peer",
                     pattern = "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"))
  }, error = function(error) fail())
  expected <- digest::digest(
    .psi_padded_canonical_json(list(
      protocol = .DSVERT_DP_PADDED_ALIGNMENT_BINDING_PROTOCOL,
      semantic = value$semantic)),
    algo = "sha256", serialize = FALSE)
  private_binding <- digest::digest(
    .psi_padded_canonical_json(list(
      protocol = .DSVERT_DP_ALIGNED_REGISTRY_PROTOCOL,
      snapshot_sha256 = value$descriptor$snapshot_sha256,
      local_id_column = value$local_id_column,
      alignment_sha256 = expected,
      semantic = value$semantic)),
    algo = "sha256", serialize = FALSE)
  if (!identical(private_binding, value$binding_sha256) ||
      !identical(expected, value$descriptor$alignment_manifest_hash)) fail()
  value$descriptor$alignment_manifest_version <-
    .DSVERT_DP_PADDED_ALIGNMENT_BINDING_VERSION
  value$semantic$peer_count <- as.integer(value$semantic$peer_count)
  value
}

.dsvert_dp_alignment_registry_read_locked <- function(path) {
  if (.dsvert_dp_path_is_link(path) || !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1)) {
    stop("The private aligned-dataset registry file is not owner-only",
         call. = FALSE)
  }
  before <- file.info(path, extra_cols = TRUE)
  size <- before$size[[1L]]
  if (!is.numeric(size) || is.na(size) || !is.finite(size) || size < 1 ||
      size > .DSVERT_DP_ALIGNED_REGISTRY_MAX_BYTES) {
    stop("The private aligned-dataset registry file has an invalid size",
         call. = FALSE)
  }
  bytes <- readBin(path, "raw", n = size + 1L)
  after <- file.info(path, extra_cols = TRUE)
  stamp_fields <- c("size", "isdir", "mode", "mtime", "ctime", "uid", "gid")
  if (length(bytes) != size || .dsvert_dp_path_is_link(path) ||
      !file_test("-f", path) ||
      !.dsvert_dp_private_mode(path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(path), 1) ||
      !identical(before[stamp_fields], after[stamp_fields])) {
    stop("The private aligned-dataset registry changed while it was read",
         call. = FALSE)
  }
  encoded <- rawToChar(bytes)
  envelope <- tryCatch(
    jsonlite::fromJSON(encoded, simplifyVector = FALSE),
    error = function(error) NULL)
  if (!is.list(envelope) || !identical(
      names(envelope), c("protocol", "payload_json", "hmac_sha256")) ||
      !identical(envelope$protocol, .DSVERT_DP_ALIGNED_REGISTRY_PROTOCOL) ||
      !is.character(envelope$payload_json) ||
      length(envelope$payload_json) != 1L || is.na(envelope$payload_json) ||
      !.dsvert_dp_alignment_registry_same_hex(
        envelope$hmac_sha256,
        .dsvert_dp_alignment_registry_hmac(envelope$payload_json))) {
    stop("The private aligned-dataset registry authentication failed",
         call. = FALSE)
  }
  payload <- tryCatch(
    jsonlite::fromJSON(envelope$payload_json, simplifyVector = FALSE),
    error = function(error) NULL)
  if (is.null(payload) || !identical(
      .psi_padded_canonical_json(payload), envelope$payload_json)) {
    stop("The private aligned-dataset registry payload is not canonical",
         call. = FALSE)
  }
  .dsvert_dp_alignment_registry_payload_validate(payload)
}

.dsvert_dp_alignment_registry_replaceable <- function(path) {
  file.exists(path) && !.dsvert_dp_path_is_link(path) &&
    file_test("-f", path) &&
    .dsvert_dp_private_mode(path, directory = FALSE) &&
    identical(.dsvert_dp_noise_link_count(path), 1)
}

.dsvert_dp_alignment_registry_with_lock <- function(path, code) {
  lock_path <- paste0(path, ".lock")
  if (.dsvert_dp_path_is_link(lock_path)) {
    stop("The private aligned-dataset registry lock must not be a symbolic link",
         call. = FALSE)
  }
  lock <- filelock::lock(lock_path, timeout = 30000)
  if (is.null(lock)) {
    stop("The private aligned-dataset registry is busy", call. = FALSE)
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  Sys.chmod(lock_path, mode = "0600")
  if (.dsvert_dp_path_is_link(lock_path) ||
      !.dsvert_dp_private_mode(lock_path, directory = FALSE) ||
      !identical(.dsvert_dp_noise_link_count(lock_path), 1)) {
    stop("The private aligned-dataset registry lock is not owner-only",
         call. = FALSE)
  }
  force(code)
}

.dsvert_dp_alignment_registry_commit <- function(data_name, data) {
  template <- .dsvert_dp_alignment_registry_template(data_name)
  if (is.null(template)) return(invisible(NULL))
  # Full explicit descriptors remain supported and need no automatic state.
  if (!setequal(names(template), c("id", "version"))) {
    return(invisible(NULL))
  }
  binding <- .dsvert_dp_padded_alignment_binding(data)
  if (!identical(template$id, binding$descriptor$id) ||
      !identical(template$version, binding$descriptor$version)) {
    stop("The authenticated PSI result contradicts its custodian DP dataset template",
         call. = FALSE)
  }
  patient_column <- getOption(
    "dsvert.dp.patient_column", getOption("default.dsvert.dp.patient_column"))
  if (!is.character(patient_column) || length(patient_column) != 1L ||
      is.na(patient_column) ||
      !identical(patient_column, binding$alignment$id_col)) {
    stop("The authenticated PSI result contradicts the custodian DP privacy-unit column",
         call. = FALSE)
  }
  payload <- list(
    protocol = .DSVERT_DP_ALIGNED_REGISTRY_PROTOCOL,
    data_name = data_name,
    local_id_column = binding$local_id_column,
    descriptor = binding$descriptor,
    semantic = binding$semantic,
    binding_sha256 = binding$registry_binding_sha256)
  payload <- .dsvert_dp_alignment_registry_payload_validate(payload)
  path <- .dsvert_dp_alignment_registry_path(
    data_name, template$id, template$version,
    binding$semantic$pinset_id)
  .dsvert_dp_alignment_registry_with_lock(path, {
    existing <- NULL
    if (file.exists(path) || .dsvert_dp_path_is_link(path)) {
      existing <- tryCatch(
        .dsvert_dp_alignment_registry_read_locked(path),
        error = function(error) {
          # This registry is derived state, not the release ledger.  A live,
          # authenticated PSI result may repair a corrupt owner-only regular
          # record for its exact epoch. Hostile links and modes remain fatal.
          if (!.dsvert_dp_alignment_registry_replaceable(path)) stop(error)
          if (unlink(path, force = TRUE) != 0L || file.exists(path) ||
              .dsvert_dp_path_is_link(path)) {
            stop("Could not retire the corrupt private aligned-dataset registry",
                 call. = FALSE)
          }
          NULL
        })
    }
    if (!is.null(existing)) {
      if (!identical(existing, payload)) {
        stop("The same custodian dataset id/version already has a different authenticated aligned snapshot",
             call. = FALSE)
      }
      invisible(path)
    } else {
      payload_json <- .psi_padded_canonical_json(payload)
      envelope <- .psi_padded_canonical_json(list(
        protocol = .DSVERT_DP_ALIGNED_REGISTRY_PROTOCOL,
        payload_json = payload_json,
        hmac_sha256 = .dsvert_dp_alignment_registry_hmac(payload_json)))
      temporary <- tempfile(
        paste0(".aligned-dataset-", Sys.getpid(), "."),
        tmpdir = dirname(path))
      on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
              add = TRUE)
      connection <- file(temporary, open = "wb")
      on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
              add = TRUE)
      writeBin(charToRaw(envelope), connection)
      flush(connection)
      close(connection)
      Sys.chmod(temporary, mode = "0600")
      .dsvert_identity_require_sync(
        temporary, "private aligned-dataset registry record")
      if (!file.rename(temporary, path)) {
        stop("Could not atomically commit the private aligned-dataset registry",
             call. = FALSE)
      }
      Sys.chmod(path, mode = "0600")
      if (.dsvert_dp_path_is_link(path) || !file_test("-f", path) ||
          !.dsvert_dp_private_mode(path, directory = FALSE) ||
          !identical(.dsvert_dp_noise_link_count(path), 1)) {
        stop("The committed private aligned-dataset registry is not owner-only",
             call. = FALSE)
      }
      .dsvert_identity_require_sync(
        path, "private aligned-dataset registry record")
      .dsvert_identity_require_sync(
        dirname(path), "private aligned-dataset registry directory")
      invisible(path)
    }
  })
}

.dsvert_dp_alignment_registry_resolve_templates <- function(
    datasets, patient_column, pinset) {
  if (!is.list(datasets) || is.null(names(datasets))) return(datasets)
  expected_pinset_id <- .psi_padded_pinset_id(as.list(pinset))
  resolved <- datasets
  for (data_name in names(datasets)) {
    template <- datasets[[data_name]]
    if (!is.list(template) || is.null(names(template)) ||
        !setequal(names(template), c("id", "version"))) next
    path <- .dsvert_dp_alignment_registry_path(
      data_name, template$id, template$version, expected_pinset_id)
    if (!file.exists(path) && !.dsvert_dp_path_is_link(path)) {
      stop("The automatic DP dataset template is awaiting one completed authenticated padded-PSI alignment",
           call. = FALSE)
    }
    payload <- .dsvert_dp_alignment_registry_with_lock(
      path, {
        .dsvert_dp_alignment_registry_read_locked(path)
      })
    valid <- identical(payload$data_name, data_name) &&
      identical(payload$descriptor$id, template$id) &&
      identical(payload$descriptor$version, template$version) &&
      identical(payload$local_id_column, patient_column) &&
      identical(payload$semantic$pinset_id, expected_pinset_id) &&
      identical(as.integer(payload$semantic$peer_count), length(pinset))
    compute_peers <- unlist(
      payload$semantic$compute_peers, use.names = FALSE)
    valid <- valid &&
      payload$semantic$reference_peer %in% names(pinset) &&
      all(compute_peers %in% names(pinset)) &&
      payload$semantic$reference_peer %in% compute_peers
    if (!isTRUE(valid)) {
      stop("The automatic DP dataset registry contradicts the active custodian policy or pinned peer set",
           call. = FALSE)
    }
    resolved[[data_name]] <- payload$descriptor
  }
  resolved
}
