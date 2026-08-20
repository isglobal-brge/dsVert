# Differential-privacy release policy and persistent composition ledger.
#
# This file deliberately keeps privacy configuration server-owned.  None of
# the public DS entry points accepts epsilon, clipping bounds, contribution
# limits, categorical domains, or the ledger path from the analyst.

.DSVERT_DP_MAX_COORDINATES <- 1000000L
.DSVERT_DP_MINIMUM_EPSILON <- 2^-50
.DSVERT_DP_MAXIMUM_EPSILON <- 2^40
.DSVERT_DP_DEFAULT_CAPSULE_DELTA <- 2^-100
.DSVERT_DP_DEFAULT_LIFETIME_MAX_DISTINCT_CAPSULES <- 1
.DSVERT_DP_SNAPSHOT_DIGEST_VERSION <- 2L
.DSVERT_DP_SNAPSHOT_CHUNK_ROWS <- 65536L

# A production DP dataset is an immutable logical snapshot.  The first use in
# each service process validates the full custodian commitment and then locks
# the concrete R binding.  Later queries reuse the validated object and its
# private binding instead of hashing every row again.  The cache never stores
# patient-derived material outside the process and is naturally discarded on
# service restart, where the full validation is repeated.
.dsvert_dp_snapshot_cache <- new.env(parent = emptyenv())

.dsvert_dp_option <- function(name, default = NULL) {
  value <- getOption(paste0("dsvert.dp.", name))
  if (is.null(value)) {
    value <- getOption(paste0("default.dsvert.dp.", name))
  }
  if (is.null(value)) default else value
}

.dsvert_dp_scalar_string <- function(value, name) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(trimws(value))) {
    stop(name, " must be one non-empty string", call. = FALSE)
  }
  trimws(value)
}

.dsvert_dp_scalar_number <- function(value, name, lower = -Inf,
                                     upper = Inf, lower_open = FALSE) {
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value)) {
    stop(name, " must be one finite number", call. = FALSE)
  }
  invalid_lower <- if (lower_open) value <= lower else value < lower
  if (invalid_lower || value > upper) {
    relation <- if (lower_open) ">" else ">="
    stop(name, " must be ", relation, " ", lower, " and <= ", upper,
         call. = FALSE)
  }
  as.numeric(value)
}

.dsvert_canonical_label_values <- function(
    value, name = "label values", allow_na = TRUE,
    allow_blank = TRUE) {
  if (!is.atomic(value) || !is.null(dim(value))) {
    stop(name, " must use one supported atomic representation",
         call. = FALSE)
  }
  declared_class <- attr(value, "class", exact = TRUE)
  factor_value <- identical(declared_class, "factor") ||
    identical(declared_class, c("ordered", "factor"))
  plain_value <- is.null(declared_class)
  result <- if (factor_value) {
    levels <- attr(value, "levels", exact = TRUE)
    codes <- value
    attributes(codes) <- NULL
    if (typeof(codes) != "integer" || !is.character(levels) ||
        anyNA(levels) || anyDuplicated(levels) ||
        any(!is.na(codes) & (codes < 1L | codes > length(levels)))) {
      stop(name, " contains an invalid factor representation",
           call. = FALSE)
    }
    unname(levels[codes])
  } else if (plain_value && is.character(value)) {
    unname(value)
  } else if (plain_value && is.logical(value)) {
    ifelse(is.na(value), NA_character_,
           ifelse(value, "TRUE", "FALSE"))
  } else if (plain_value && typeof(value) == "integer") {
    result <- rep(NA_character_, length(value))
    present <- !is.na(value)
    result[present] <- sprintf("%d", value[present])
    result
  } else if (plain_value && typeof(value) == "double") {
    present <- !is.na(value)
    if (any(!is.finite(value[present])) ||
        any(value[present] != floor(value[present])) ||
        any(abs(value[present]) > 2^53 - 1)) {
      stop(name, " numeric values must be finite exactly representable integers",
           call. = FALSE)
    }
    result <- rep(NA_character_, length(value))
    # Explicit formatting is independent of digits/scipen/OutDec and maps
    # negative zero to the same identifier as zero.
    normalized <- value[present]
    normalized[normalized == 0] <- 0
    result[present] <- sprintf("%.0f", normalized)
    result
  } else {
    stop(name, " must use character, factor, logical, integer, or exact integer-valued double data",
         call. = FALSE)
  }
  result <- enc2utf8(result)
  if (!isTRUE(allow_na) && anyNA(result)) {
    stop(name, " must not contain missing values", call. = FALSE)
  }
  if (!isTRUE(allow_blank) && any(!is.na(result) & !nzchar(trimws(result)))) {
    stop(name, " must not contain blank values", call. = FALSE)
  }
  result
}

.dsvert_dp_categorical_label_values <- function(value, name) {
  # Protected categorical columns may be imported as doubles.  Treat a
  # non-integral, non-finite, or wider-than-53-bit element as an unknown
  # category instead of letting one record select a visible error branch.
  # Privacy-unit identifiers deliberately keep the stricter all-or-nothing
  # validation in .dsvert_canonical_label_values().
  if (is.null(attr(value, "class", exact = TRUE)) &&
      typeof(value) == "double") {
    invalid <- !is.na(value) & (
      !is.finite(value) | value != floor(value) | abs(value) > 2^53 - 1)
    if (any(invalid)) {
      value <- unname(value)
      value[invalid] <- NA_real_
    }
  }
  .dsvert_canonical_label_values(value, name)
}

.dsvert_dp_named_domains <- function(value, name) {
  if (is.null(value)) return(list())
  if (!is.list(value) || is.null(names(value)) ||
      any(!nzchar(names(value))) || anyDuplicated(names(value))) {
    stop(name, " must be a uniquely named list", call. = FALSE)
  }
  value <- value[order(names(value))]
  for (field in names(value)) {
    domain <- value[[field]]
    if (!is.atomic(domain) || !length(domain) || anyNA(domain)) {
      stop(name, " contains an invalid domain", call. = FALSE)
    }
    domain <- unique(.dsvert_canonical_label_values(
      domain, name, allow_na = FALSE, allow_blank = FALSE))
    if (any(!nzchar(domain)) || anyDuplicated(domain)) {
      stop(name, " contains an invalid domain", call. = FALSE)
    }
    value[[field]] <- sort(domain, method = "radix")
  }
  value
}

.dsvert_dp_numeric_bounds <- function(value) {
  if (is.null(value)) return(list())
  if (!is.list(value) || is.null(names(value)) ||
      any(!nzchar(names(value))) || anyDuplicated(names(value))) {
    stop("dsvert.dp.numeric_bounds must be a uniquely named list",
         call. = FALSE)
  }
  value <- value[order(names(value))]
  for (field in names(value)) {
    bounds <- value[[field]]
    if (!is.numeric(bounds) || length(bounds) != 2L || anyNA(bounds) ||
        any(!is.finite(bounds)) || bounds[[1L]] >= bounds[[2L]]) {
      stop("dsvert.dp.numeric_bounds contains invalid bounds",
           call. = FALSE)
    }
    width <- bounds[[2L]] - bounds[[1L]]
    width_squared <- width * width
    if (!is.finite(width) || width <= 0 ||
        !is.finite(width_squared) || width_squared <= 0) {
      stop("dsvert.dp.numeric_bounds requires a finite positive width and ",
           "finite positive squared width", call. = FALSE)
    }
    value[[field]] <- unname(as.numeric(bounds))
  }
  value
}

.dsvert_dp_datasets <- function(value, require_snapshot_digest = TRUE,
                                require_alignment_manifest = TRUE) {
  if (!is.list(value) || !length(value) || is.null(names(value)) ||
      any(!nzchar(names(value))) || anyDuplicated(names(value))) {
    stop("dsvert.dp.datasets must be a non-empty, uniquely named list",
         call. = FALSE)
  }
  value <- value[order(names(value), method = "radix")]
  identities <- character(length(value))
  for (i in seq_along(value)) {
    data_name <- names(value)[[i]]
    .validate_data_name(data_name)
    descriptor <- value[[i]]
    allowed_names <- c(
      "id", "snapshot_sha256", "version",
      "alignment_manifest_hash", "alignment_manifest_version")
    if (!is.list(descriptor) ||
        any(!names(descriptor) %in% allowed_names) ||
        !all(c("id", "version") %in% names(descriptor))) {
      stop("Each dsvert.dp.datasets entry must contain id, version, and the ",
           "custodian snapshot_sha256 binding", call. = FALSE)
    }
    id <- .dsvert_dp_scalar_string(
      descriptor$id, "dsvert.dp.datasets id")
    version <- .dsvert_dp_scalar_string(
      descriptor$version, "dsvert.dp.datasets version")
    valid <- "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
    if (!grepl(valid, id) || !grepl(valid, version)) {
      stop("DP dataset ids and versions contain unsupported characters",
           call. = FALSE)
    }
    snapshot <- descriptor$snapshot_sha256
    if (is.null(snapshot) && isTRUE(require_snapshot_digest)) {
      stop("Every protected DP dataset requires a custodian snapshot_sha256",
           call. = FALSE)
    }
    if (!is.null(snapshot)) {
      snapshot <- tolower(.dsvert_dp_scalar_string(
        snapshot, "dsvert.dp.datasets snapshot_sha256"))
      if (!grepl("^[0-9a-f]{64}$", snapshot)) {
        stop("DP dataset snapshot_sha256 must contain 64 hexadecimal digits",
             call. = FALSE)
      }
    }
    alignment_hash <- descriptor$alignment_manifest_hash
    alignment_version <- descriptor$alignment_manifest_version
    if ((is.null(alignment_hash) || is.null(alignment_version)) &&
        isTRUE(require_alignment_manifest)) {
      stop("Every protected DP dataset requires a custodian-approved ",
           "PSI alignment manifest hash and version", call. = FALSE)
    }
    if (xor(is.null(alignment_hash), is.null(alignment_version))) {
      stop("DP alignment manifest hash and version must be configured ",
           "together", call. = FALSE)
    }
    if (!is.null(alignment_hash)) {
      alignment_hash <- tolower(.dsvert_dp_scalar_string(
        alignment_hash, "dsvert.dp.datasets alignment_manifest_hash"))
      if (!grepl("^[0-9a-f]{64}$", alignment_hash)) {
        stop("DP alignment_manifest_hash must contain 64 hexadecimal digits",
             call. = FALSE)
      }
      if (!is.numeric(alignment_version) || length(alignment_version) != 1L ||
          is.na(alignment_version) || !is.finite(alignment_version) ||
          alignment_version < 1 ||
          alignment_version > .Machine$integer.max ||
          alignment_version != floor(alignment_version)) {
        stop("DP alignment_manifest_version must be a positive integer",
             call. = FALSE)
      }
      alignment_version <- as.integer(alignment_version)
    }
    value[[i]] <- list(
      id = id, version = version, snapshot_sha256 = snapshot,
      alignment_manifest_hash = alignment_hash,
      alignment_manifest_version = alignment_version)
    identities[[i]] <- paste(id, version, sep = "@")
  }
  if (anyDuplicated(identities)) {
    stop("Each protected data name must have a unique DP dataset identity; ",
         "aliases are not allowed", call. = FALSE)
  }
  value
}

.dsvert_dp_cohort_id <- function(value) {
  value <- .dsvert_dp_scalar_string(value, "dsvert.dp.cohort_id")
  if (!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)) {
    stop("dsvert.dp.cohort_id contains unsupported characters",
         call. = FALSE)
  }
  value
}

.dsvert_dp_peer_pinset <- function() {
  configured_peer_name <- getOption("dsvert.peer_name")
  if (is.null(configured_peer_name)) {
    configured_peer_name <- getOption("default.dsvert.peer_name")
  }
  peer_name <- .dsvert_dp_scalar_string(
    configured_peer_name, "dsvert.peer_name")
  if (!grepl("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", peer_name)) {
    stop("dsvert.peer_name contains unsupported characters", call. = FALSE)
  }
  trusted <- .get_trusted_peers()
  if (length(trusted) && any(!grepl(
        "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", names(trusted)))) {
    stop("Trusted DP peer names contain unsupported characters",
         call. = FALSE)
  }
  if (peer_name %in% names(trusted)) {
    stop("The local dsvert.peer_name must not also appear as a trusted peer",
         call. = FALSE)
  }
  identity <- .get_identity_keypair()
  if (!is.list(identity) || is.null(identity$identity_pk)) {
    stop("The local Ed25519 identity is unavailable", call. = FALSE)
  }
  normalize <- function(value) {
    .dsvert_relay_normalize_identity_pk(value)
  }
  pinset <- c(
    stats::setNames(normalize(identity$identity_pk), peer_name),
    vapply(trusted, normalize, character(1L), USE.NAMES = TRUE))
  pinset <- pinset[order(names(pinset), method = "radix")]
  if (anyDuplicated(names(pinset)) || anyDuplicated(unname(pinset))) {
    stop("Every logical DP peer must have one distinct pinned Ed25519 key",
         call. = FALSE)
  }
  list(
    peer_name = peer_name,
    pinset = pinset,
    sha256 = digest::digest(
      .dsvert_dp_canonical_json(as.list(pinset)),
      algo = "sha256", serialize = FALSE))
}

.dsvert_dp_snapshot_columns <- function(data) {
  if (!is.data.frame(data) || anyDuplicated(names(data)) ||
      any(!nzchar(names(data)))) {
    stop("The protected DP snapshot must be a data frame with unique columns",
         call. = FALSE)
  }
  columns <- sort(names(data), method = "radix")
  strip_opal_metadata <- function(column) {
    metadata <- c(
      "opal.value_type", "opal.entity_type", "opal.unit",
      "opal.referenced_entity_type", "opal.mime_type", "opal.repeatable",
      "opal.occurrence_group", "opal.index", "opal.nature")
    required <- c(
      "opal.value_type", "opal.entity_type", "opal.repeatable",
      "opal.index", "opal.nature")
    attribute_names <- names(attributes(column))
    if (is.null(attribute_names)) return(column)
    if (anyNA(attribute_names) || any(!nzchar(attribute_names)) ||
        anyDuplicated(attribute_names)) {
      stop("Protected DP snapshot columns contain invalid or executable attributes",
           call. = FALSE)
    }
    opal_names <- attribute_names[startsWith(attribute_names, "opal.")]
    if (!length(opal_names)) return(column)
    if (any(!opal_names %in% metadata)) {
      stop("Protected DP snapshot columns contain invalid Opal metadata",
           call. = FALSE)
    }
    if (!all(required %in% opal_names)) {
      stop("Protected DP snapshot columns contain incomplete Opal metadata",
           call. = FALSE)
    }

    plain_scalar <- function(value, type) {
      identical(typeof(value), type) && is.null(attributes(value)) &&
        length(value) == 1L && !is.na(value)
    }
    bounded_text <- function(value) {
      plain_scalar(value, "character") && nzchar(value) &&
        nchar(value, type = "bytes") <= 1024L
    }
    value_type <- attr(column, "opal.value_type", exact = TRUE)
    entity_type <- attr(column, "opal.entity_type", exact = TRUE)
    repeatable <- attr(column, "opal.repeatable", exact = TRUE)
    index <- attr(column, "opal.index", exact = TRUE)
    nature <- attr(column, "opal.nature", exact = TRUE)
    valid <- plain_scalar(value_type, "character") && value_type %in% c(
      "binary", "boolean", "date", "datetime", "decimal", "integer",
      "linestring", "locale", "point", "polygon", "text") &&
      bounded_text(entity_type) &&
      plain_scalar(repeatable, "double") && repeatable %in% c(0, 1) &&
      plain_scalar(index, "double") && is.finite(index) &&
      index >= 0 && index <= .Machine$integer.max && index == floor(index) &&
      plain_scalar(nature, "character") && nature %in% c(
        "CATEGORICAL", "CONTINUOUS", "TEMPORAL", "BINARY", "UNDETERMINED")
    optional <- intersect(setdiff(metadata, required), opal_names)
    valid <- isTRUE(valid) && all(vapply(optional, function(name) {
      bounded_text(attr(column, name, exact = TRUE))
    }, logical(1L)))
    if (!valid) {
      stop("Protected DP snapshot columns contain invalid Opal metadata",
           call. = FALSE)
    }
    for (name in opal_names) attr(column, name) <- NULL
    column
  }
  # Bypass data-frame subclass methods: the committed columns must be the
  # same columns later consumed by the mechanisms.
  values <- stats::setNames(lapply(columns, function(column) {
    strip_opal_metadata(.subset2(data, column))
  }), columns)
  unsupported <- vapply(values, function(column) {
    (is.list(column) && !is.data.frame(column)) ||
      !is.atomic(column) || !is.null(dim(column)) ||
      length(column) != nrow(data)
  }, logical(1L))
  if (any(unsupported)) {
    stop("List, matrix, and array columns are not supported in a protected DP snapshot",
         call. = FALSE)
  }

  supported_object <- vapply(values, function(column) {
    declared_class <- attr(column, "class", exact = TRUE)
    is.null(declared_class) ||
      identical(declared_class, "factor") ||
      identical(declared_class, c("ordered", "factor")) ||
      identical(declared_class, "Date") ||
      identical(declared_class, c("POSIXct", "POSIXt")) ||
      identical(declared_class, "difftime")
  }, logical(1L))
  if (any(!supported_object)) {
    stop("Protected DP snapshot columns must use base atomic vectors, factor/ordered, Date, POSIXct, or difftime; custom S3 classes must be converted explicitly",
         call. = FALSE)
  }

  valid_attributes <- vapply(values, function(column) {
    declared_class <- attr(column, "class", exact = TRUE)
    allowed <- if (is.null(declared_class)) {
      "names"
    } else if (identical(declared_class, "factor") ||
               identical(declared_class, c("ordered", "factor"))) {
      c("names", "levels", "class")
    } else if (identical(declared_class, c("POSIXct", "POSIXt"))) {
      c("names", "class", "tzone")
    } else if (identical(declared_class, "difftime")) {
      c("names", "class", "units")
    } else {
      c("names", "class")
    }
    attribute_names <- names(attributes(column))
    if (is.null(attribute_names)) attribute_names <- character()
    if (any(!attribute_names %in% allowed)) return(FALSE)
    if (!is.null(names(column)) &&
        (!is.character(names(column)) ||
         length(names(column)) != length(column))) return(FALSE)
    if (identical(declared_class, "factor") ||
        identical(declared_class, c("ordered", "factor"))) {
      levels <- attr(column, "levels", exact = TRUE)
      codes <- column
      attributes(codes) <- NULL
      if (typeof(codes) != "integer" || !is.character(levels) ||
          anyNA(levels) || anyDuplicated(levels) ||
          any(!is.na(codes) & (codes < 1L | codes > length(levels)))) {
        return(FALSE)
      }
    }
    if (identical(declared_class, "Date") &&
        !typeof(column) %in% c("integer", "double")) return(FALSE)
    if (identical(declared_class, c("POSIXct", "POSIXt"))) {
      timezone <- attr(column, "tzone", exact = TRUE)
      if (!typeof(column) %in% c("integer", "double") ||
          (!is.null(timezone) &&
           (!is.character(timezone) || !length(timezone) ||
            length(timezone) > 3L || anyNA(timezone)))) return(FALSE)
    }
    if (identical(declared_class, "difftime")) {
      units <- attr(column, "units", exact = TRUE)
      if (!typeof(column) %in% c("integer", "double") ||
          !is.character(units) || length(units) != 1L || is.na(units) ||
          !units %in% c("secs", "mins", "hours", "days", "weeks")) {
        return(FALSE)
      }
    }
    TRUE
  }, logical(1L))
  if (any(!valid_attributes)) {
    stop("Protected DP snapshot columns contain invalid or executable attributes",
         call. = FALSE)
  }
  values
}

.dsvert_dp_freeze_snapshot_frame <- function(data) {
  alignment_manifest <- attr(
    data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  padded_attestation <- attr(
    data, .PSI_PADDED_ATTESTATION_ATTRIBUTE, exact = TRUE)
  if (!is.null(padded_attestation)) {
    # Authenticate both frame attributes before copying them.  The generic
    # manifest alone remains available only for explicit legacy descriptors;
    # automatic padded-PSI bindings require the v2 persistent attestation.
    .psi_padded_validate_persistent_attestation(data)
  }
  columns <- .dsvert_dp_snapshot_columns(data)
  result <- structure(
    unname(columns), names = names(columns),
    row.names = base::.set_row_names(nrow(data)), class = "data.frame")
  if (!is.null(alignment_manifest)) {
    attr(result, .PSI_ALIGNMENT_ATTRIBUTE) <- alignment_manifest
  }
  if (!is.null(padded_attestation)) {
    attr(result, .PSI_PADDED_ATTESTATION_ATTRIBUTE) <- padded_attestation
    # Revalidate against the frozen identifier order.  This prevents a custom
    # data-frame implementation from presenting one object during validation
    # and another during the protected snapshot copy.
    .psi_padded_validate_persistent_attestation(result)
  }
  result
}

.dsvert_dp_snapshot_digest <- function(data) {
  row_count <- nrow(data)
  data <- .dsvert_dp_snapshot_columns(data)
  columns <- names(data)
  schema <- lapply(data, function(column) list(
    storage_type = typeof(column),
    class = class(column),
    levels = if (is.factor(column)) levels(column) else NULL,
    timezone = attr(column, "tzone", exact = TRUE)))
  starts <- if (row_count) {
    seq.int(1L, row_count, by = .DSVERT_DP_SNAPSHOT_CHUNK_ROWS)
  } else {
    integer()
  }
  # Hash whole column blocks instead of invoking the serializer once per row.
  # Column order is canonical, block order is retained, and every column uses
  # the same public row boundaries; consequently both patient order and the
  # cross-column row association are committed.  Peak temporary memory is one
  # serialized block rather than the complete data frame.
  column_blocks <- lapply(data, function(column) {
    hashes <- if (!length(starts)) {
      character()
    } else {
      vapply(starts, function(start) {
        end <- min(row_count, start + .DSVERT_DP_SNAPSHOT_CHUNK_ROWS - 1L)
        digest::digest(
          unname(.subset(column, start:end)),
          algo = "sha256", serialize = TRUE,
          serializeVersion = 3L)
      }, character(1L))
    }
    list(length = length(column), blocks = unname(hashes))
  })
  digest::digest(
    list(
      protocol = paste0(
        "dsvert-ordered-column-block-snapshot-v",
        .DSVERT_DP_SNAPSHOT_DIGEST_VERSION),
      row_count = row_count,
      chunk_rows = .DSVERT_DP_SNAPSHOT_CHUNK_ROWS,
      columns = columns,
      schema = schema,
      column_blocks = column_blocks),
    algo = "sha256", serialize = TRUE, serializeVersion = 3L)
}

.dsvert_dp_snapshot_cache_key <- function(policy, data_name,
                                          binding_environment) {
  descriptor <- policy$datasets[[data_name]]
  digest::digest(
    list(
      domain = policy$domain,
      data_name = data_name,
      descriptor = descriptor,
      # The address is process-local and never released.  It prevents a stale
      # fixture or re-created DataSHIELD evaluation environment from inheriting
      # another binding's in-memory validation.
      binding_environment = format(binding_environment)
    ),
    algo = "sha256", serialize = TRUE)
}

.dsvert_dp_binding_environment <- function(data_name, envir) {
  current <- envir
  repeat {
    if (exists(data_name, envir = current, inherits = FALSE)) return(current)
    if (identical(current, emptyenv())) break
    current <- parent.env(current)
  }
  stop("The protected DP object is unavailable", call. = FALSE)
}

.dsvert_dp_resolve_snapshot <- function(policy, data_name, envir, secret) {
  .validate_data_name(data_name)

  # Test-only policies deliberately omit the production snapshot contract.
  # Keep their historical direct resolution so unit fixtures are not frozen.
  if (!isTRUE(policy$require_snapshot_digest)) {
    data <- .dsvert_dp_get_data(data_name, envir)
    return(list(
      data = data,
      dataset = .dsvert_dp_dataset_binding(
        policy, data_name, data, secret),
      memoized_snapshot = FALSE))
  }

  binding_environment <- .dsvert_dp_binding_environment(data_name, envir)
  cache_key <- .dsvert_dp_snapshot_cache_key(
    policy, data_name, binding_environment)
  if (exists(cache_key, envir = .dsvert_dp_snapshot_cache,
             inherits = FALSE)) {
    cached <- get(cache_key, envir = .dsvert_dp_snapshot_cache,
                  inherits = FALSE)
    if (!exists(data_name, envir = cached$binding_environment,
                inherits = FALSE) ||
        bindingIsActive(data_name, cached$binding_environment) ||
        !bindingIsLocked(data_name, cached$binding_environment)) {
      stop("The immutable protected DP snapshot binding changed",
           call. = FALSE)
    }
    return(list(
      data = cached$data,
      dataset = cached$dataset,
      memoized_snapshot = TRUE))
  }

  if (bindingIsActive(data_name, binding_environment)) {
    stop("Protected DP snapshots must not use active bindings",
         call. = FALSE)
  }
  data <- .dsvert_dp_get_data(data_name, binding_environment)
  if (inherits(data, "data.table")) {
    # A locked R binding does not stop data.table's by-reference setters.
    # Freeze an independent copy once; real data.table objects imply that the
    # namespace is installed. A forged class fails closed.
    if (!requireNamespace("data.table", quietly = TRUE)) {
      stop("A protected data.table snapshot requires the data.table package",
           call. = FALSE)
    }
    data <- tryCatch(
      getExportedValue("data.table", "copy")(data),
      error = function(e) {
        stop("The reference-mutable DP snapshot could not be frozen",
             call. = FALSE)
      })
  }
  # Subsequent mechanisms consume an ordinary base data frame with the same
  # audited columns used by the snapshot commitment. This removes custom
  # data-frame dispatch and executable column attributes from the release path.
  data <- .dsvert_dp_freeze_snapshot_frame(data)
  dataset <- .dsvert_dp_dataset_binding(
    policy, data_name, data, secret)

  # Validation above is intentionally completed before changing the binding.
  # R execution is single-threaded here; locking then makes ordinary data-frame
  # replacement impossible and copy-on-modify keeps aliases from changing the
  # cached object. Reference-mutable data.table objects use the independent
  # deep copy created above, so later by-reference edits cannot alter it.
  if (!bindingIsLocked(data_name, binding_environment)) {
    lockBinding(data_name, binding_environment)
  }
  assign(cache_key, list(
    data = data,
    dataset = dataset,
    binding_environment = binding_environment
  ), envir = .dsvert_dp_snapshot_cache)
  list(data = data, dataset = dataset, memoized_snapshot = FALSE)
}

.dsvert_dp_private_mode <- function(path, directory = FALSE) {
  info <- file.info(path)
  if (nrow(info) != 1L || is.na(info$isdir) ||
      !identical(isTRUE(info$isdir), isTRUE(directory))) return(FALSE)
  mode <- suppressWarnings(as.integer(info$mode[[1L]]))
  expected <- if (directory) strtoi("700", base = 8L) else
    strtoi("600", base = 8L)
  owner <- Sys.info()[["user"]]
  owner_ok <- is.character(owner) && length(owner) == 1L && nzchar(owner) &&
    is.character(info$uname[[1L]]) && !is.na(info$uname[[1L]]) &&
    identical(info$uname[[1L]], owner)
  isTRUE(is.finite(mode) && mode == expected && owner_ok)
}

.dsvert_dp_assert_private_file <- function(path, what,
                                           require_private = TRUE) {
  # Inspect type, ownership, mode and hard-link count from one non-following
  # metadata snapshot.  WAL/SHM files may disappear during another process's
  # checkpoint before this process acquires the ledger lock; treating that
  # coherent missing snapshot as absent avoids a false concurrency failure.
  info <- tryCatch(
    fs::file_info(path, follow = FALSE), error = function(e) NULL)
  if (is.null(info) || nrow(info) != 1L) {
    stop("Cannot inspect the differential-privacy ", what,
         call. = FALSE)
  }
  type <- as.character(info$type[[1L]])
  if (is.na(type)) return(invisible(NULL))
  if (identical(type, "symlink")) {
    stop("The differential-privacy ", what,
         " must not be a symbolic link", call. = FALSE)
  }
  if (!identical(type, "file")) {
    stop("The differential-privacy ", what,
         " must be a regular file", call. = FALSE)
  }
  if (isTRUE(require_private)) {
    links <- info$hard_links[[1L]]
    if (identical(.Platform$OS.type, "unix") &&
        (!is.numeric(links) || is.na(links) || !is.finite(links) ||
         !identical(as.numeric(links), 1))) {
      stop("The differential-privacy ", what,
           " must not have hard links", call. = FALSE)
    }
    mode <- suppressWarnings(as.integer(info$permissions[[1L]]))
    mode <- if (length(mode) == 1L && !is.na(mode)) {
      bitwAnd(mode, strtoi("777", base = 8L))
    } else {
      NA_integer_
    }
    owner <- Sys.info()[["user"]]
    observed_owner <- info$user[[1L]]
    owner_ok <- is.character(owner) && length(owner) == 1L &&
      !is.na(owner) && nzchar(owner) &&
      is.character(observed_owner) && length(observed_owner) == 1L &&
      !is.na(observed_owner) && identical(observed_owner, owner)
    if (!isTRUE(owner_ok) || is.na(mode) ||
        mode != strtoi("600", base = 8L)) {
      stop("The differential-privacy ", what,
           " must be owned by the service account with mode 0600",
           call. = FALSE)
    }
  }
  invisible(NULL)
}

.dsvert_dp_chmod_private_files <- function(paths) {
  existing <- paths[file.exists(paths)]
  if (!length(existing)) return(invisible(NULL))
  modes <- vapply(existing, function(path) {
    suppressWarnings(as.integer(file.info(path)$mode[[1L]]))
  }, integer(1L))
  needs_chmod <- !is.finite(modes) |
    modes != strtoi("600", base = 8L)
  if (any(needs_chmod)) {
    Sys.chmod(existing[needs_chmod], mode = "0600")
  }
  invisible(NULL)
}

.dsvert_dp_ledger_path <- function(value, require_private = TRUE) {
  value <- .dsvert_dp_scalar_string(value, "dsvert.dp.ledger_path")
  expanded <- path.expand(value)
  if (!grepl("^/", expanded)) {
    stop("dsvert.dp.ledger_path must be absolute", call. = FALSE)
  }
  parent <- dirname(expanded)
  if (!dir.exists(parent)) {
    stop("The differential-privacy ledger directory does not exist",
         call. = FALSE)
  }
  # Resolve parent aliases once, then use only the canonical path. This removes
  # symlink components such as macOS /var -> /private/var from the path used by
  # filelock and SQLite and prevents a later lookup through the alias.
  canonical_parent <- normalizePath(
    parent, winslash = "/", mustWork = TRUE)
  if (isTRUE(require_private)) {
    if (!identical(.Platform$OS.type, "unix")) {
      stop("The disclosure-safe service requires a POSIX owner-only ledger ",
           "directory", call. = FALSE)
    }
    if (!.dsvert_dp_private_mode(canonical_parent, directory = TRUE)) {
      stop("The differential-privacy ledger directory must be owned by the ",
           "service account with mode 0700", call. = FALSE)
    }
  }
  result <- file.path(canonical_parent, basename(expanded))
  .dsvert_dp_assert_private_file(
    result, "ledger", require_private = require_private)
  result
}

# A missing file-backed noise root may be replaced only after every surviving
# current-schema ledger has passed a read-only audit under the persistent
# identity-derived secret. Legacy joint v1 files and orphan SQLite sidecars are
# continuity evidence, but are not sufficiently authenticated recovery input.
.dsvert_dp_history_file_present <- function(path, what) {
  sidecars <- paste0(path, c("-wal", "-shm", "-journal"))
  present <- file.exists(path) || .dsvert_dp_path_is_link(path)
  sidecar_present <- vapply(sidecars, function(candidate) {
    file.exists(candidate) || .dsvert_dp_path_is_link(candidate)
  }, logical(1L))
  if (!present && any(sidecar_present)) {
    stop("The ", what, " has orphan SQLite sidecars", call. = FALSE)
  }
  if (!present) return(FALSE)
  .dsvert_dp_assert_private_file(path, what, require_private = TRUE)
  for (index in which(sidecar_present)) {
    .dsvert_dp_assert_private_file(
      sidecars[[index]], paste0(what, " sidecar"), require_private = TRUE)
  }
  info <- file.info(path)
  if (nrow(info) != 1L || is.na(info$size) || info$size <= 0) {
    stop("The ", what, " is empty or invalid", call. = FALSE)
  }
  TRUE
}

.dsvert_dp_history_readonly <- function(path, what, audit) {
  before <- .dsvert_dp_ledger_content_stamp(path)
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), path, flags = RSQLite::SQLITE_RO)
  open <- TRUE
  on.exit(if (open) try(DBI::dbDisconnect(connection), silent = TRUE),
          add = TRUE)
  check <- DBI::dbGetQuery(connection, "PRAGMA quick_check")
  if (!is.data.frame(check) || nrow(check) != 1L || ncol(check) != 1L ||
      !identical(check[[1L]][[1L]], "ok")) {
    stop("The ", what, " failed SQLite integrity checking", call. = FALSE)
  }
  value <- audit(connection)
  DBI::dbDisconnect(connection)
  open <- FALSE
  after <- .dsvert_dp_ledger_content_stamp(path)
  if (!identical(before, after)) {
    stop("The ", what, " changed during its recovery audit", call. = FALSE)
  }
  value
}

.dsvert_dp_history_index <- function(value, what) {
  result <- suppressWarnings(as.numeric(value))
  if (length(result) != 1L || is.na(result) || !is.finite(result) ||
      result < 0 || result > 2^53 - 1 || result != floor(result)) {
    stop("The authenticated DP ", what, " is invalid", call. = FALSE)
  }
  result
}

.dsvert_dp_history_decimal <- function(value, what) {
  result <- suppressWarnings(as.numeric(value))
  if (length(result) != 1L || is.na(result) || !is.finite(result) ||
      result < 0) {
    stop("The authenticated DP ", what, " is invalid", call. = FALSE)
  }
  result
}

.dsvert_dp_inactive_joint_history <- function(path, secret) {
  .dsvert_dp_history_readonly(path, "joint DP ledger", function(connection) {
    required_tables <- c(
      "joint_meta", "joint_records", "joint_outputs",
      "joint_allocator_state", "joint_capsule_registry",
      "joint_capsule_registry_state")
    if (!all(required_tables %in% DBI::dbListTables(connection))) {
      stop("The joint DP ledger schema is incomplete", call. = FALSE)
    }
    metadata <- .dsvert_joint_dp_meta_snapshot(
      connection, .DSVERT_JOINT_DP_FAST_META_KEYS)
    if (!all(.DSVERT_JOINT_DP_FAST_META_KEYS %in% names(metadata)) ||
        !identical(metadata[["schema_version"]], "2") ||
        !identical(
          metadata[[.DSVERT_JOINT_DP_ALLOCATOR_STATE_META_KEY]],
          .DSVERT_JOINT_DP_ALLOCATOR_STATE_VERSION)) {
      stop("The joint DP ledger metadata is incomplete", call. = FALSE)
    }
    binding <- .dsvert_joint_dp_allocator_state_binding(
      connection, metadata)
    expected_secret_id <- .dsvert_dp_hmac(secret, list(
      "dsvert-joint-dp-ledger-secret-id-v1", binding$peer_name))
    if (!identical(metadata[["secret_id"]], expected_secret_id)) {
      stop("The joint DP ledger identity binding is invalid", call. = FALSE)
    }
    state <- .dsvert_joint_dp_allocator_state_read(connection, secret)
    .dsvert_joint_dp_allocator_state_assert_binding(
      connection, state, binding)
    next_index <- .dsvert_dp_history_index(
      metadata[["next_index"]], "joint release index")
    rows <- DBI::dbGetQuery(
      connection, "SELECT * FROM joint_records ORDER BY sequence")
    records <- lapply(seq_len(nrow(rows)), function(index) {
      .dsvert_joint_dp_record_decode(rows[index, , drop = FALSE], secret)
    })
    committed <- 0
    expected_chain <- "GENESIS"
    cumulative_epsilon <- 0
    cumulative_delta <- 0
    root_bindings <- list()
    prepared <- NULL
    if (length(records)) for (index in seq_along(records)) {
      record <- records[[index]]
      sequence <- .dsvert_dp_history_index(
        rows$sequence[[index]], "joint record sequence")
      if (identical(record$state, "prepared")) {
        if (!is.null(prepared) || index != length(records) ||
            sequence != committed ||
            !identical(record$previous_chain, expected_chain)) {
          stop("The joint DP prepared tail is inconsistent", call. = FALSE)
        }
        prepared <- list(
          query_id = record$query_id, row_mac = rows$row_mac[[index]])
        next
      }
      if (sequence != committed ||
          !identical(record$previous_chain, expected_chain) ||
          !is.character(record$joint_record_hash) ||
          !grepl("^[0-9a-f]{64}$", record$joint_record_hash) ||
          !identical(record$new_chain, .dsvert_joint_dp_chain_head(
            expected_chain, record$allocation_index,
            record$joint_record_hash, record$epsilon, record$delta))) {
        stop("The joint DP committed chain is inconsistent", call. = FALSE)
      }
      epsilon <- .dsvert_dp_history_decimal(
        record$epsilon, "joint cumulative epsilon")
      delta <- .dsvert_dp_history_decimal(
        record$delta, "joint cumulative delta")
      epoch <- .dsvert_dp_noise_epoch(suppressWarnings(
        as.numeric(record$own_prepare$privacy_epoch)))
      key_id <- .dsvert_dp_noise_key_id(
        record$own_prepare$noise_key_id)
      if (!grepl("^file_[0-9a-f]{64}$", key_id)) {
        stop("The joint DP history does not attest a file-backed noise root",
             call. = FALSE)
      }
      if (!identical(record$own_prepare$peer_name, binding$peer_name)) {
        stop("The joint DP record peer binding is inconsistent",
             call. = FALSE)
      }
      root_bindings[[length(root_bindings) + 1L]] <- list(
        epoch = epoch, key_id = key_id)
      cumulative_epsilon <- cumulative_epsilon + epsilon
      cumulative_delta <- cumulative_delta + delta
      expected_chain <- record$new_chain
      committed <- committed + 1L
    }
    if (!is.null(prepared)) {
      stop("The joint DP ledger has an incomplete prepared allocation",
           call. = FALSE)
    }
    stored_epsilon <- .dsvert_dp_history_decimal(
      metadata[["cumulative_epsilon"]], "joint stored epsilon")
    stored_delta <- .dsvert_dp_history_decimal(
      metadata[["cumulative_delta"]], "joint stored delta")
    eligible <- committed
    if (committed != next_index ||
        !identical(as.numeric(state$committed_count), committed) ||
        !identical(state$chain_head, expected_chain) ||
        !identical(metadata[["chain_head"]], expected_chain) ||
        !isTRUE(all.equal(stored_epsilon, cumulative_epsilon,
                          tolerance = 1e-13)) ||
        !isTRUE(all.equal(stored_delta, cumulative_delta,
                          tolerance = 1e-13)) ||
        !identical(as.numeric(state$registry_eligible_count),
                   as.numeric(eligible))) {
      stop("The joint DP allocator metadata is inconsistent", call. = FALSE)
    }
    if (committed > 0) {
      tail <- rows[committed, , drop = FALSE]
      if (!identical(state$tail_query_id, tail$query_id[[1L]]) ||
          !identical(state$tail_row_mac, tail$row_mac[[1L]])) {
        stop("The authenticated joint DP allocator tail is inconsistent",
             call. = FALSE)
      }
    } else if (!is.null(state$tail_query_id) ||
               !is.null(state$tail_row_mac)) {
      stop("The empty joint DP allocator tail is inconsistent",
           call. = FALSE)
    }
    outputs <- DBI::dbGetQuery(
      connection, "SELECT * FROM joint_outputs ORDER BY query_id")
    decoded_outputs <- lapply(seq_len(nrow(outputs)), function(index) {
      output <- .dsvert_joint_dp_output_decode(
        outputs[index, , drop = FALSE], secret)
      record_index <- match(output$query_id, rows$query_id)
      if (is.na(record_index) ||
          !identical(records[[record_index]]$state, "open_authorized")) {
        stop("The joint DP output has no authorized allocation",
             call. = FALSE)
      }
      output
    })
    if (!identical(as.numeric(state$output_count),
                   as.numeric(length(decoded_outputs)))) {
      stop("The joint DP output count is inconsistent", call. = FALSE)
    }
    if (length(decoded_outputs)) {
      tail_index <- match(state$output_tail_query_id, outputs$query_id)
      if (is.na(tail_index) ||
          !identical(state$output_tail_row_mac,
                     outputs$row_mac[[tail_index]])) {
        stop("The authenticated joint DP output tail is inconsistent",
             call. = FALSE)
      }
    } else if (!is.null(state$output_tail_query_id) ||
               !is.null(state$output_tail_row_mac)) {
      stop("The empty joint DP output tail is inconsistent", call. = FALSE)
    }
    seal <- list(
      source = "joint", policy_hash = binding$policy_hash,
      peer_name = binding$peer_name, count = committed,
      chain_head = expected_chain, cumulative_epsilon = stored_epsilon,
      cumulative_delta = stored_delta,
      allocator_state_mac = digest::digest(
        .dsvert_dp_canonical_json(state), algo = "sha256",
        serialize = FALSE))
    if (!committed) {
      return(list(status = "empty", source = "joint", seal = seal))
    }
    epochs <- vapply(root_bindings, `[[`, numeric(1L), "epoch")
    if (is.unsorted(epochs, strictly = FALSE)) {
      stop("The joint DP release epochs are not monotone", call. = FALSE)
    }
    for (epoch in unique(epochs)) {
      epoch_ids <- unique(vapply(
        root_bindings[epochs == epoch], `[[`, character(1L), "key_id"))
      if (length(epoch_ids) != 1L) {
        stop("The joint DP release epoch has conflicting noise roots",
             call. = FALSE)
      }
    }
    current_epoch <- max(epochs)
    current_ids <- unique(vapply(
      root_bindings[epochs == current_epoch], `[[`, character(1L), "key_id"))
    if (length(current_ids) != 1L) {
      stop("The joint DP release tail has conflicting noise roots",
           call. = FALSE)
    }
    list(
      status = "used", source = "joint", seal = seal,
      privacy_epoch = current_epoch, noise_key_id = current_ids[[1L]],
      noise_key_provider_id = "owner_only_file_v2", count = committed,
      epsilon = stored_epsilon, delta = stored_delta,
      chain_head = expected_chain)
  })
}

.dsvert_dp_inactive_noise_history <- function(ledger_path) {
  ledger_path <- .dsvert_dp_scalar_string(
    ledger_path, "inactive DP ledger path")
  parent <- dirname(ledger_path)
  if (!dir.exists(parent)) return(NULL)
  ledger_path <- file.path(normalizePath(
    parent, winslash = "/", mustWork = TRUE), basename(ledger_path))
  joint_v1 <- paste0(
    ledger_path, ".joint-mpc-single-opening-v1.sqlite")
  if (.dsvert_dp_history_file_present(joint_v1, "legacy joint DP ledger")) {
    stop("A legacy joint DP ledger v1 cannot authorize automatic root recovery",
         call. = FALSE)
  }
  joint_path <- paste0(
    ledger_path, ".joint-mpc-single-opening-v2.sqlite")
  joint_present <- .dsvert_dp_history_file_present(
    joint_path, "joint DP ledger")
  vector_path <- paste0(
    ledger_path, ".joint-dp-vector-v4.sqlite")
  vector_present <- .dsvert_dp_history_file_present(
    vector_path, "joint DP vector release ledger")
  if (!joint_present && !vector_present) return(NULL)
  secret <- .dsvert_dp_secret()
  components <- list()
  if (joint_present) {
    components$joint <- .dsvert_dp_inactive_joint_history(
      joint_path, secret)
  }
  if (vector_present) {
    vector <- .dsvert_joint_dp_release_ledger_history_from_path(
      vector_path, secret)
    if (is.null(vector)) {
      stop("The historical vector store has not been migrated to authenticated release-instance accounting",
           call. = FALSE)
    }
    components$vector <- vector
  }
  used <- components[vapply(
    components, function(value) identical(value$status, "used"),
    logical(1L))]
  if (!length(used)) {
    sources <- sort(names(components), method = "radix")
    material <- list(
      protocol = .DSVERT_DP_AUTHENTICATED_EMPTY_HISTORY_PROTOCOL,
      sources = sources,
      audit_sha256 = digest::digest(
        .dsvert_dp_canonical_json(lapply(components, `[[`, "seal")),
        algo = "sha256", serialize = FALSE),
      ledger_path_sha256 =
        .dsvert_dp_noise_history_path_sha256(ledger_path))
    result <- c(material, list(identity_mac = .dsvert_dp_hmac(
      secret, list(
        "dsvert-authenticated-empty-dp-ledger-history-mac-v1",
        material))))
    secret <- NULL
    return(result)
  }
  secret <- NULL
  epochs <- vapply(used, `[[`, numeric(1L), "privacy_epoch")
  current_epoch <- max(epochs)
  current <- used[epochs == current_epoch]
  if (length(unique(vapply(
      current, `[[`, character(1L), "noise_key_id"))) != 1L ||
      length(unique(vapply(
        current, `[[`, character(1L),
        "noise_key_provider_id"))) != 1L) {
    stop("Authenticated DP ledgers disagree on the current noise-root epoch",
         call. = FALSE)
  }
  count <- sum(vapply(used, `[[`, numeric(1L), "count"))
  epsilon <- sum(vapply(used, `[[`, numeric(1L), "epsilon"))
  delta <- sum(vapply(used, `[[`, numeric(1L), "delta"))
  heads <- lapply(used, function(value) list(
    source = value$source, privacy_epoch = value$privacy_epoch,
    chain_head = value$chain_head))
  combined_head <- if (all(vapply(
      used, function(value) identical(value$chain_head, "GENESIS"),
      logical(1L)))) {
    "GENESIS"
  } else {
    digest::digest(
      .dsvert_dp_canonical_json(heads), algo = "sha256", serialize = FALSE)
  }
  selected <- current[[1L]]
  list(
    privacy_epoch = selected$privacy_epoch,
    noise_key_id = selected$noise_key_id,
    noise_key_provider_id = selected$noise_key_provider_id,
    composition_audit = list(
      source = paste(names(used), collapse = "+"),
      release_count = format(count, scientific = FALSE, trim = TRUE),
      cumulative_epsilon = sprintf("%.17g", epsilon),
      cumulative_delta = sprintf("%.17g", delta),
      chain_head = combined_head))
}

# Read the surviving release ledgers under the identity-derived integrity key.
# This callback is used only when the built-in file-backed noise root needs to
# establish or rotate its identity-authenticated epoch journal. It never
# authorizes an HSM/KMS fallback and never applies an admission/budget gate.
.dsvert_dp_policy_noise_history <- function(policy) {
  secret <- .dsvert_dp_secret()
  file_present <- function(path) {
    if (!file.exists(path) || .dsvert_dp_path_is_link(path) ||
        !utils::file_test("-f", path)) return(FALSE)
    info <- file.info(path)
    nrow(info) == 1L && !is.na(info$size) && info$size > 0
  }
  decimal <- function(value) {
    value <- as.numeric(value)
    if (length(value) != 1L || is.na(value) || !is.finite(value) ||
        value < 0) {
      stop("The authenticated DP composition history is invalid",
           call. = FALSE)
    }
    sprintf("%.17g", value)
  }
  binding <- function(epoch, key_id, provider_id, count, epsilon, delta,
                      chain_head, source) {
    list(
      privacy_epoch = .dsvert_dp_noise_epoch(epoch),
      noise_key_id = .dsvert_dp_noise_key_id(key_id),
      noise_key_provider_id = .dsvert_dp_noise_key_id(
        provider_id, "DP noise provider id"),
      count = as.numeric(count), epsilon = as.numeric(epsilon),
      delta = as.numeric(delta), chain_head = chain_head, source = source)
  }
  histories <- list()

  joint_path <- paste0(
    policy$ledger_path, ".joint-mpc-single-opening-v2.sqlite")
  if (file_present(joint_path)) {
    joint_history <- local({
      probe <- DBI::dbConnect(
        RSQLite::SQLite(), joint_path, flags = RSQLite::SQLITE_RO)
      probe_open <- TRUE
      on.exit(if (probe_open) {
        try(DBI::dbDisconnect(probe), silent = TRUE)
      }, add = TRUE)
      rows <- DBI::dbGetQuery(
        probe, "SELECT * FROM joint_records ORDER BY sequence DESC LIMIT 1")
      if (!nrow(rows)) return(NULL)
      record <- .dsvert_joint_dp_record_decode(rows, secret)
      epoch <- suppressWarnings(as.numeric(
        record$own_prepare$privacy_epoch))
      key_id <- record$own_prepare$noise_key_id
      candidate_policy <- policy
      candidate_policy$noise_root <- list(epoch = epoch, key_id = key_id)
      DBI::dbDisconnect(probe)
      probe_open <- FALSE
      handle <- .dsvert_joint_dp_open_ledger(candidate_policy)
      on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
      audited <- .dsvert_joint_dp_allocator_full_audit(
        handle$connection, candidate_policy, secret,
        allow_legacy_policy_hash = TRUE)
      .dsvert_joint_dp_sync_external_anchor(
        handle$connection, candidate_policy, audited$context, secret)
      state <- audited$state
      binding(
        epoch, key_id, "owner_only_file_v2",
        state$committed_count,
        state$cumulative_epsilon, state$cumulative_delta,
        state$chain_head, "joint")
    })
    if (!is.null(joint_history)) histories$joint <- joint_history
  }

  vector_path <- paste0(
    policy$ledger_path, ".joint-dp-vector-v4.sqlite")
  if (file_present(vector_path)) {
    vector_history <- .dsvert_joint_dp_release_ledger_history_from_path(
      vector_path, secret)
    if (is.null(vector_history)) {
      stop("The vector store has not been migrated to authenticated release-instance accounting",
           call. = FALSE)
    }
    if (identical(vector_history$status, "used")) {
      histories$vector <- binding(
        vector_history$privacy_epoch,
        vector_history$noise_key_id,
        vector_history$noise_key_provider_id,
        vector_history$count,
        vector_history$epsilon,
        vector_history$delta,
        vector_history$chain_head,
        "vector")
    }
  }

  if (!length(histories)) return(NULL)
  epochs <- vapply(histories, `[[`, numeric(1L), "privacy_epoch")
  current <- histories[[which.max(epochs)]]
  same_epoch <- histories[epochs == current$privacy_epoch]
  if (length(unique(vapply(
      same_epoch, `[[`, character(1L), "noise_key_id"))) != 1L ||
      length(unique(vapply(
        same_epoch, `[[`, character(1L),
        "noise_key_provider_id"))) != 1L) {
    stop("Authenticated DP ledgers disagree on the current noise-root epoch",
         call. = FALSE)
  }
  count <- sum(vapply(histories, `[[`, numeric(1L), "count"))
  epsilon <- sum(vapply(histories, `[[`, numeric(1L), "epsilon"))
  delta <- sum(vapply(histories, `[[`, numeric(1L), "delta"))
  heads <- lapply(histories, function(value) {
    list(source = value$source, privacy_epoch = value$privacy_epoch,
         chain_head = value$chain_head)
  })
  combined_head <- if (all(vapply(
      histories, function(value) identical(value$chain_head, "GENESIS"),
      logical(1L)))) {
    "GENESIS"
  } else {
    digest::digest(
      .dsvert_dp_canonical_json(heads), algo = "sha256", serialize = FALSE)
  }
  list(
    privacy_epoch = current$privacy_epoch,
    noise_key_id = current$noise_key_id,
    noise_key_provider_id = current$noise_key_provider_id,
    composition_audit = list(
      source = paste(names(histories), collapse = "+"),
      release_count = format(count, scientific = FALSE, trim = TRUE),
      cumulative_epsilon = decimal(epsilon),
      cumulative_delta = decimal(delta),
      chain_head = combined_head))
}

.dsvert_dp_resolve_designated_noise_peers <- function(value, pinset) {
  peer_names <- sort(names(pinset), method = "radix")
  if (length(peer_names) < 2L || anyNA(peer_names) ||
      any(!nzchar(peer_names)) || anyDuplicated(peer_names)) {
    stop("The complete pinned peer map must contain at least two distinct peers",
         call. = FALSE)
  }
  # A missing optional override must not make an otherwise valid deployment
  # unusable. Every custodian derives the same pair from the canonical full
  # pinset, and the chosen pair remains bound into every signed contract.
  if (is.null(value)) return(peer_names[1:2])
  if (!is.character(value) || length(value) != 2L || anyNA(value) ||
      any(!nzchar(value)) || anyDuplicated(value) ||
      !all(value %in% peer_names)) {
    stop("dsvert.dp.designated_noise_peers, when supplied, must name exactly two distinct members of the complete pinned peer map",
         call. = FALSE)
  }
  sort(value, method = "radix")
}

.dsvert_dp_policy_core_v1 <- function(
    .test_only_skip_snapshot_binding = FALSE,
    .test_only_skip_alignment_binding = FALSE,
    .test_only_allow_nonprivate_ledger = FALSE) {
  test_flags <- c(
    .test_only_skip_snapshot_binding,
    .test_only_skip_alignment_binding,
    .test_only_allow_nonprivate_ledger)
  if (!is.logical(test_flags) || anyNA(test_flags)) {
    stop("Internal DP test flags must be TRUE or FALSE", call. = FALSE)
  }
  # Production has one disclosure-safe mode. Historical enable/disable and
  # geometric-allocation options are deliberately not read here, so setting
  # them cannot create a second policy or alter capsule accuracy.

  cohort_id <- .dsvert_dp_cohort_id(
    .dsvert_dp_option("cohort_id", NULL))
  peer <- .dsvert_dp_peer_pinset()
  total_epsilon <- .dsvert_dp_option("total_epsilon", 1)
  total_delta <- .dsvert_dp_option(
    "total_delta", .DSVERT_DP_DEFAULT_CAPSULE_DELTA)
  total_epsilon <- .dsvert_dp_scalar_number(
    total_epsilon, "dsvert.dp.total_epsilon", 0, Inf, lower_open = TRUE)
  total_delta <- .dsvert_dp_scalar_number(
    total_delta, "dsvert.dp.total_delta", 0, 1)
  if (total_delta >= 1) {
    stop("dsvert.dp.total_delta must be < 1", call. = FALSE)
  }
  if (total_epsilon > 8) {
    stop("dsvert.dp.total_epsilon must be <= 8 under the single safe policy",
         call. = FALSE)
  }
  peer_count <- length(peer$pinset)

  adjacency <- tolower(.dsvert_dp_scalar_string(
    .dsvert_dp_option("adjacency", "add_remove_patient"),
    "dsvert.dp.adjacency"))
  # Configuration compatibility only. All internal/public metadata uses the
  # canonical contract name and no row-level adjacency remains available.
  if (identical(adjacency, "patient_add_remove")) {
    adjacency <- "add_remove_patient"
  }
  if (!adjacency %in% c(
        "add_remove_patient", "replace_one_fixed_cohort")) {
    stop("dsvert.dp.adjacency must be add_remove_patient or replace_one_fixed_cohort",
         call. = FALSE)
  }
  patient_column <- .dsvert_dp_scalar_string(
    .dsvert_dp_option("patient_column", NULL),
    "dsvert.dp.patient_column")
  exact_capacity <- function(name, upper = .DSVERT_DP_MAX_COORDINATES) {
    value <- .dsvert_dp_option(name, NULL)
    if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
        !is.finite(value) || value < 1 || value > upper ||
        value != floor(value)) {
      stop("dsvert.dp.", name,
           " must be a positive custodian-owned integer <= ", upper,
           call. = FALSE)
    }
    as.integer(value)
  }
  unit_capacity <- exact_capacity("unit_capacity")
  max_records_per_unit <- exact_capacity("max_records_per_unit")
  fixed_cohort_size <- .dsvert_dp_option("fixed_cohort_size", NULL)
  if (identical(adjacency, "replace_one_fixed_cohort")) {
    fixed_cohort_size <- exact_capacity("fixed_cohort_size")
    if (!identical(fixed_cohort_size, unit_capacity)) {
      stop("dsvert.dp.fixed_cohort_size must equal dsvert.dp.unit_capacity under replace_one_fixed_cohort",
           call. = FALSE)
    }
  } else if (!is.null(fixed_cohort_size)) {
    stop("dsvert.dp.fixed_cohort_size must be NULL under add_remove_patient",
         call. = FALSE)
  }
  overflow_policy <- tolower(.dsvert_dp_scalar_string(
    .dsvert_dp_option("overflow_policy", NULL),
    "dsvert.dp.overflow_policy"))
  if (!identical(overflow_policy, "reject_snapshot")) {
    stop("dsvert.dp.overflow_policy must be reject_snapshot",
         call. = FALSE)
  }
  contingency_unit_aggregation_policy <- tolower(
    .dsvert_dp_scalar_string(
      .dsvert_dp_option(
        "contingency_unit_aggregation_policy",
        "consistent_cell_else_exclude_v1"),
      "dsvert.dp.contingency_unit_aggregation_policy"))
  if (!identical(
        contingency_unit_aggregation_policy,
        "consistent_cell_else_exclude_v1")) {
    stop(
      "dsvert.dp.contingency_unit_aggregation_policy must be consistent_cell_else_exclude_v1",
      call. = FALSE)
  }
  require_snapshot_digest <- !isTRUE(.test_only_skip_snapshot_binding)
  require_alignment_manifest <- !isTRUE(.test_only_skip_alignment_binding)
  configured_designated <- .dsvert_dp_option(
    "designated_noise_peers", NULL)
  designated_noise_peers <- .dsvert_dp_resolve_designated_noise_peers(
    configured_designated, peer$pinset)

  lock_timeout_ms <- .dsvert_dp_scalar_number(
    .dsvert_dp_option("lock_timeout_ms", 30000),
    "dsvert.dp.lock_timeout_ms", 1, 600000)
  numeric_grid_bits <- .dsvert_dp_scalar_number(
    .dsvert_dp_option("numeric_grid_bits", 16L),
    "dsvert.dp.numeric_grid_bits", 8, 18)
  if (numeric_grid_bits != as.integer(numeric_grid_bits)) {
    stop("dsvert.dp.numeric_grid_bits must be an integer", call. = FALSE)
  }

  domain <- .dsvert_dp_scalar_string(
    .dsvert_dp_option("domain", NULL), "dsvert.dp.domain")
  if (!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", domain)) {
    stop("dsvert.dp.domain contains unsupported characters", call. = FALSE)
  }
  configured_datasets <- .dsvert_dp_option("datasets", NULL)
  if (isTRUE(require_snapshot_digest) &&
      isTRUE(require_alignment_manifest)) {
    configured_datasets <- .dsvert_dp_alignment_registry_resolve_templates(
      configured_datasets, patient_column, peer$pinset)
  }

  policy <- list(
    schema_version = 1L,
    mechanism_version =
      "dsvert-dp-v7-contingency-unit-aggregation-1",
    policy_contract = "unbound_dp_policy_core_v1",
    domain = domain,
    cohort_id = cohort_id,
    peer_name = peer$peer_name,
    own_identity_pk = unname(peer$pinset[[peer$peer_name]]),
    logical_peers = names(peer$pinset),
    peer_pinset = peer$pinset,
    peer_pinset_sha256 = peer$sha256,
    global_total_epsilon = total_epsilon,
    global_total_delta = total_delta,
    peer_count = as.integer(peer_count),
    designated_noise_peers = designated_noise_peers,
    numeric_grid_bits = as.integer(numeric_grid_bits),
    adjacency = adjacency,
    patient_column = patient_column,
    unit_capacity = unit_capacity,
    fixed_cohort_size = fixed_cohort_size,
    max_records_per_unit = max_records_per_unit,
    overflow_policy = overflow_policy,
    contingency_unit_aggregation_policy =
      contingency_unit_aggregation_policy,
    noise_selection = list(
      schema_version = 2L,
      selector = .DSVERT_DP_NOISE_SELECTOR,
      candidates = c(
        "deterministic_granular_laplace_int64_l1",
        paste0("deterministic_approximate_gaussian_int64_l2_",
               "dp_transfer_tv_accounted")),
      capsule_vector_route = list(
        mechanism_version = "dsvert-joint-dp-vector-hybrid-v5",
        selector =
          "formal_fixed_work_backend_minimum_simultaneous_95_radius_v2",
        candidates = c(
          "joint_discrete_laplace_ring128_v3",
          paste0("dyadic_discrete_gaussian_tv_bounded_ring128_v2_",
                 "cks_target_and_tv_transfer_accounted")),
        activation = paste0(
          "conditional_on_signed_capsule_manifest_selection_and_",
          "request_bound_runtime_plan_validation"),
        fallback =
          "explicit_joint_discrete_laplace_when_fixed_plan_unavailable"),
      scalar_objective = "marginal_95_abs",
      vector_objective = "simultaneous_95_abs",
      confidence = 0.95,
      tie_break = .DSVERT_DP_NOISE_TIE_BREAK,
      delta_accounting =
        "laplace_zero_gaussian_fixed_capsule_delta_only"),
    transcript_privacy = .dsvert_dp_transcript_claim()$policy_value,
    snapshot_binding = if (isTRUE(require_snapshot_digest)) {
      "required_private_custodian_sha256"
    } else {
      "internal_test_bypass"
    },
    alignment_binding = if (isTRUE(require_alignment_manifest)) {
      "required_private_ordered_psi_manifest"
    } else {
      "internal_test_bypass"
    },
    require_snapshot_digest = isTRUE(require_snapshot_digest),
    require_alignment_manifest = isTRUE(require_alignment_manifest),
    state_private = !isTRUE(.test_only_allow_nonprivate_ledger),
    datasets = .dsvert_dp_datasets(
      configured_datasets, require_snapshot_digest,
      require_alignment_manifest),
    categorical_levels = .dsvert_dp_named_domains(
      .dsvert_dp_option("categorical_levels", NULL),
      "dsvert.dp.categorical_levels"),
    numeric_bounds = .dsvert_dp_numeric_bounds(
      .dsvert_dp_option("numeric_bounds", NULL)),
    # This is deliberately not part of the public status contract.  It is
    # custodian-owned metadata used only by the server-authoritative capsule
    # manifest bootstrap.  One local dataset needs no mapping; deployments
    # with several local datasets must explicitly partition every bounded
    # analysis column between them.
    capsule_dataset_mapping =
      .dsvert_dp_option("capsule_dataset_mapping", NULL),
    # Server-only primitive selection.  The compatibility default retains the
    # historical schema-wide vector; catalog_v1 is validated against the
    # unanimously signed schema before any protected snapshot is resolved.
    capsule_workload_scope = .dsvert_dp_capsule_scope_policy_binding(
      .dsvert_dp_option("workload_scope", list(mode = "all_schema"))),
    capsule_workload_specs = list(
      describe = .dsvert_dp_option("describe_specs", list()),
      survival = .dsvert_dp_option("survival_specs", list()),
      gaussian = .dsvert_dp_option("gaussian_specs", list()),
      vertical_cross = .dsvert_dp_option("vertical_cross_specs", list()))
  )
  policy$lock_timeout_ms <- as.integer(lock_timeout_ms)
  policy
}

.dsvert_dp_policy_build <- function(
    .test_only_skip_snapshot_binding = FALSE,
    .test_only_skip_alignment_binding = FALSE,
    .test_only_allow_nonprivate_ledger = FALSE) {
  policy <- .dsvert_dp_policy_core_v1(
    .test_only_skip_snapshot_binding,
    .test_only_skip_alignment_binding,
    .test_only_allow_nonprivate_ledger)
  policy$schema_version <- 9L
  policy$policy_contract <- "single_disclosure_safe_capsule_policy_v2"
  lifetime <- .dsvert_dp_option(
    "lifetime_max_distinct_capsules",
    .DSVERT_DP_DEFAULT_LIFETIME_MAX_DISTINCT_CAPSULES)
  if (!is.numeric(lifetime) || length(lifetime) != 1L || is.na(lifetime) ||
      !is.finite(lifetime) || lifetime < 1 || lifetime > 2^53 - 1 ||
      lifetime != floor(lifetime)) {
    stop(paste0(
      "dsvert.dp.lifetime_max_distinct_capsules must be one positive ",
      "integer <= 2^53 - 1"), call. = FALSE)
  }
  policy$lifetime_max_distinct_capsules <- as.numeric(lifetime)
  policy$ledger_private <- policy$state_private
  policy$state_private <- NULL

  anchor_provider <- .dsvert_dp_option("anchor_provider", NULL)
  if (!is.null(anchor_provider) && !is.function(anchor_provider)) {
    stop("dsvert.dp.anchor_provider must be a provider function",
         call. = FALSE)
  }
  anchor_mode <- if (is.null(anchor_provider)) {
    "pinned_peer_global_allocator_pending"
  } else {
    "pinned_peer_global_allocator_pending_plus_external_cas"
  }
  anchor_id <- paste0("dpa1_", digest::digest(
    .dsvert_dp_canonical_json(list(
      domain = policy$domain, cohort_id = policy$cohort_id,
      peer_name = policy$peer_name,
      pinset_sha256 = policy$peer_pinset_sha256)),
    algo = "sha256", serialize = FALSE))
  policy$rollback_protection <- list(
    schema_version = 2L, mode = anchor_mode, anchor_id = anchor_id,
    provider_contract = if (identical(
        anchor_mode, "pinned_peer_global_allocator_pending")) {
      "pinned_ed25519_cross_signed_global_allocator_v1"
    } else {
      paste0(
        "pinned_ed25519_cross_signed_global_allocator_v1_",
        "plus_external_cas_v2")
    },
    external = identical(
      anchor_mode,
      "pinned_peer_global_allocator_pending_plus_external_cas"),
    monotonic = TRUE)
  invisible(.dsvert_joint_dp_lifetime_contract(policy))
  policy$ledger_path <- .dsvert_dp_ledger_path(
    .dsvert_dp_option("ledger_path", NULL),
    require_private = policy$ledger_private)
  policy$anchor_provider <- anchor_provider
  history_policy <- policy
  policy$noise_root <- .dsvert_dp_noise_root(list(
    ledger_path = policy$ledger_path,
    anchor_provider = anchor_provider,
    anchor_id = anchor_id,
    history_provider = function() {
      .dsvert_dp_policy_noise_history(history_policy)
    }))
  policy
}

.dsvert_dp_policy <- function() {
  .dsvert_dp_policy_build()
}

.dsvert_dp_policy_public <- function(policy) {
  accounting_fields <- c(
    "global_total_epsilon", "global_total_delta", "peer_count",
    "designated_noise_peers",
    if (identical(policy$schema_version, 9L)) {
      "lifetime_max_distinct_capsules"
    })
  result <- policy[c(
    "schema_version", "mechanism_version", "policy_contract", "domain",
    "cohort_id",
    "peer_name",
    "own_identity_pk", "logical_peers", "peer_pinset",
    "peer_pinset_sha256",
    accounting_fields,
    "adjacency",
    "numeric_grid_bits", "patient_column", "unit_capacity",
    "fixed_cohort_size", "max_records_per_unit", "overflow_policy",
    "contingency_unit_aggregation_policy",
    "noise_selection",
    "transcript_privacy", "snapshot_binding", "alignment_binding",
    "rollback_protection",
    "categorical_levels", "numeric_bounds"
  )]
  result$datasets <- lapply(policy$datasets, function(dataset) {
    # Exact snapshot and ordered-identifier commitments are integrity secrets,
    # not DP outputs.  The public status carries only a stable, custodian-owned
    # cohort descriptor.  A strict status call validates the private bindings
    # locally before returning this attestation.
    list(
      id = dataset$id,
      version = dataset$version,
      alignment_attested = !is.null(dataset$alignment_manifest_hash),
      alignment_protocol_version = dataset$alignment_manifest_version
    )
  })
  result
}

.dsvert_dp_canonical_json <- function(value) {
  as.character(jsonlite::toJSON(
    value, auto_unbox = TRUE, null = "null", na = "null", digits = 17,
    pretty = FALSE
  ))
}

.dsvert_dp_secret <- function() {
  seed <- tryCatch(jsonlite::base64_dec(.get_identity_seed()),
                   error = function(e) raw(0L))
  if (!is.raw(seed) || length(seed) != 32L) {
    stop("The server identity seed is invalid; the DP ledger cannot open",
         call. = FALSE)
  }
  digest::hmac(
    key = seed, object = charToRaw("dsVert/dp-ledger/key/v1"),
    algo = "sha256", serialize = FALSE, raw = TRUE
  )
}

.dsvert_dp_hmac <- function(secret, value, raw = FALSE) {
  digest::hmac(
    key = secret, object = serialize(value, NULL, version = 3L),
    algo = "sha256", serialize = FALSE, raw = raw
  )
}

.dsvert_dp_policy_hash <- function(policy) {
  digest::digest(
    .dsvert_dp_canonical_json(list(
      public = .dsvert_dp_policy_public(policy),
      snapshot_sha256 = lapply(policy$datasets, `[[`, "snapshot_sha256"),
      alignment_manifest_hash = lapply(
        policy$datasets, `[[`, "alignment_manifest_hash"))),
    algo = "sha256", serialize = FALSE
  )
}

.dsvert_dp_ledger_probe <- function(path) {
  if (!file.exists(path)) return(NULL)
  info <- file.info(path)
  native <- fs::file_info(path, follow = FALSE)
  size <- as.numeric(info$size[[1L]])
  connection <- file(path, open = "rb")
  on.exit(close(connection), add = TRUE)
  head <- readBin(connection, what = "raw", n = min(size, 4096))
  tail <- raw()
  if (size > 4096) {
    seek(connection, where = max(0, size - 4096), origin = "start")
    tail <- readBin(connection, what = "raw", n = min(size, 4096))
  }
  list(
    size = size,
    mode = as.integer(info$mode[[1L]]),
    uid = as.integer(info$uid[[1L]]),
    device_id = as.numeric(native$device_id[[1L]]),
    inode = as.numeric(native$inode[[1L]]),
    hard_links = as.numeric(native$hard_links[[1L]]),
    mtime = format(info$mtime[[1L]], "%Y-%m-%dT%H:%M:%OS6%z"),
    ctime = format(info$ctime[[1L]], "%Y-%m-%dT%H:%M:%OS6%z"),
    boundary_sha256 = digest::digest(
      c(head, tail), algo = "sha256", serialize = FALSE))
}

.dsvert_dp_ledger_content_stamp <- function(path) {
  wal <- paste0(path, "-wal")
  wal_info <- if (file.exists(wal)) file.info(wal) else NULL
  # Opening a clean WAL database creates a zero-byte WAL. Treat it as absent
  # so a close/open cycle does not invalidate the cache. Any committed frame
  # is non-empty and therefore becomes part of the seal.
  wal_probe <- if (!is.null(wal_info) && is.finite(wal_info$size[[1L]]) &&
                   wal_info$size[[1L]] > 0) {
    .dsvert_dp_ledger_probe(wal)
  } else {
    NULL
  }
  digest::digest(
    list(
      protocol = "dsvert-ledger-process-validation-stamp-v1",
      ledger = .dsvert_dp_ledger_probe(path),
      wal = wal_probe),
    algo = "sha256", serialize = TRUE, serializeVersion = 3L)
}

.dsvert_dp_noise_mechanism <-
  "dsvert_dp_v1_deterministic_granular_laplace_int64"
.dsvert_dp_noise_implementation <-
  paste0("dsVert adapted Google Differential Privacy v4.1.0 ",
         "granular Laplace integer mechanism")
.dsvert_dp_gaussian_mechanism <-
  "dsvert_dp_v3_deterministic_approximate_gaussian_int64"
.dsvert_dp_gaussian_implementation <-
  paste0("dsVert adapted Google Differential Privacy v4.1.0 ",
         "approximate Gaussian integer mechanism with a published ",
         "2^-40 scalar total-variation bound")
.DSVERT_DP_NOISE_SELECTOR <- "minimum_conservative_95_radius_v3"
.DSVERT_DP_NOISE_TIE_BREAK <-
  "laplace_unless_gaussian_strictly_improves"
.DSVERT_DP_GAUSSIAN_TV_BOUND_PER_COORDINATE <- 2^-40
.DSVERT_DP_GAUSSIAN_ACCOUNTING_RULE <-
  "analytic_gaussian_delta_plus_dp_transfer_from_total_variation_bound"
.DSVERT_DP_GAUSSIAN_ACCURACY_RULE <-
  "gaussian_tail_alpha_minus_total_variation_union_bound"
.dsvert_dp_exact_integer_limit <- 2^53 - 1

.dsvert_dp_number_equal <- function(left, right) {
  is.numeric(left) && length(left) == 1L && !is.na(left) &&
    is.finite(left) && is.numeric(right) && length(right) == 1L &&
    !is.na(right) && is.finite(right) &&
    identical(as.numeric(left), as.numeric(right))
}

.dsvert_dp_gaussian_implementation_delta_bound <- function(
    coordinate_count, epsilon) {
  if (!is.numeric(coordinate_count) || length(coordinate_count) != 1L ||
      is.na(coordinate_count) || !is.finite(coordinate_count) ||
      coordinate_count < 1 || coordinate_count != floor(coordinate_count) ||
      coordinate_count > .DSVERT_DP_MAX_COORDINATES ||
      !is.numeric(epsilon) || length(epsilon) != 1L || is.na(epsilon) ||
      !is.finite(epsilon) || epsilon < .DSVERT_DP_MINIMUM_EPSILON ||
      epsilon > .DSVERT_DP_MAXIMUM_EPSILON) {
    return(Inf)
  }
  # TV transfer for an (epsilon, delta)-DP ideal law is
  # delta + (1 + exp(epsilon)) * TV, not delta + TV.  Log space avoids
  # overflow and mirrors the outward-rounded Go implementation closely.
  log_bound <- log(coordinate_count) +
    log(.DSVERT_DP_GAUSSIAN_TV_BOUND_PER_COORDINATE) +
    epsilon + log1p(exp(-epsilon))
  if (!is.finite(log_bound) || log_bound >= 0) return(Inf)
  bound <- exp(log_bound)
  if (!is.finite(bound) || bound <= 0 || bound >= 1) Inf else bound
}

.dsvert_dp_gaussian_bound_equal <- function(observed, expected) {
  is.numeric(observed) && length(observed) == 1L && !is.na(observed) &&
    is.finite(observed) && observed > 0 && is.numeric(expected) &&
    length(expected) == 1L && !is.na(expected) && is.finite(expected) &&
    expected > 0 &&
    abs(observed - expected) <=
      4096 * .Machine$double.eps * max(abs(observed), abs(expected))
}

.dsvert_dp_gaussian_achieved_delta <- function(sigma, sensitivity,
                                                epsilon) {
  exponential <- exp(epsilon)
  if (is.infinite(exponential)) return(0)
  a <- sensitivity / (2 * sigma)
  b <- epsilon * sigma / sensitivity
  achieved <- stats::pnorm(a - b) - exponential * stats::pnorm(-a - b)
  if (!is.finite(achieved) || achieved < -1e-15) return(NA_real_)
  max(0, achieved)
}

.dsvert_dp_gaussian_accuracy_radius <- function(sigma, alpha) {
  adjusted <- alpha - .DSVERT_DP_GAUSSIAN_TV_BOUND_PER_COORDINATE
  if (!is.finite(adjusted) || adjusted <= 0 || adjusted >= 1) {
    return(NA_real_)
  }
  radius <- ceiling(abs(stats::qnorm(adjusted / 2)) * sigma)
  if (!is.finite(radius) || radius < 0 ||
      radius > .dsvert_dp_exact_integer_limit) NA_real_ else radius
}

.dsvert_dp_integer_vector <- function(value, name, positive = FALSE) {
  if (!is.numeric(value) || !length(value) || anyNA(value) ||
      any(!is.finite(value)) || any(value != trunc(value)) ||
      any(abs(value) > .dsvert_dp_exact_integer_limit) ||
      (positive && any(value <= 0))) {
    qualifier <- if (positive) "positive " else ""
    stop(name, " must contain exactly representable ", qualifier,
         "integers", call. = FALSE)
  }
  unname(as.numeric(value))
}

.dsvert_dp_laplace_accuracy_radius <- function(sensitivities, epsilons,
                                                alpha) {
  # Mirrors Google DP's integer confidence interval: form the continuous
  # Laplace quantile, then round the symmetric endpoints to int64.  R's
  # floor(abs(z) + 0.5) matches Go's math.Round for the non-negative radius.
  magnitude <- abs((sensitivities / epsilons) * log(alpha))
  radius <- floor(magnitude + 0.5)
  if (anyNA(radius) || any(!is.finite(radius)) ||
      any(radius < 0) || any(radius > .dsvert_dp_exact_integer_limit)) {
    stop("The Laplace accuracy radius is not exactly representable",
         call. = FALSE)
  }
  unname(radius)
}

.dsvert_dp_noise_int64 <- function(values, epsilons, sensitivities, seed,
                                    sampler = NULL) {
  values <- .dsvert_dp_integer_vector(values, "values")
  sensitivities <- .dsvert_dp_integer_vector(
    sensitivities, "sensitivities", positive = TRUE)
  if (!is.numeric(epsilons) || !length(epsilons) || anyNA(epsilons) ||
      any(!is.finite(epsilons)) ||
      any(epsilons < .DSVERT_DP_MINIMUM_EPSILON) ||
      any(epsilons > .DSVERT_DP_MAXIMUM_EPSILON)) {
    stop("epsilons must be finite and between 2^-50 and 2^40", call. = FALSE)
  }
  epsilons <- unname(as.numeric(epsilons))
  if (length(epsilons) != length(values) ||
      length(sensitivities) != length(values)) {
    stop("values, epsilons, and sensitivities must have equal length",
         call. = FALSE)
  }
  if (length(values) > .DSVERT_DP_MAX_COORDINATES) {
    stop("The DP sampler coordinate count exceeds ",
         .DSVERT_DP_MAX_COORDINATES, call. = FALSE)
  }
  if (any((sensitivities / epsilons) / 2^40 > 1) ||
      any((sensitivities / epsilons) / 2^40 == 0)) {
    stop("The DP allocation requires unsupported sampler granularity",
         call. = FALSE)
  }
  if (!is.null(sampler) && !is.function(sampler)) {
    stop("sampler must be NULL or an internal test function", call. = FALSE)
  }
  if (!is.character(seed) || length(seed) != 1L || is.na(seed) ||
      !grepl("^[0-9a-f]{64}$", seed)) {
    stop("seed must contain exactly 32 bytes encoded as lowercase hexadecimal",
         call. = FALSE)
  }
  result <- if (is.null(sampler)) {
    .callMpcTool("dp-noise-int64", list(
      values = as.list(values),
      epsilons = as.list(epsilons),
      sensitivities = as.list(sensitivities),
      seed = seed
    ))
  } else {
    sampler(values = values, epsilons = epsilons,
            sensitivities = sensitivities, seed = seed)
  }
  required <- c(
    "values", "accuracy_95_abs", "accuracy_simultaneous_95_abs",
    "clipped_coordinates", "mechanism", "implementation", "sampler",
    "randomness", "l0_sensitivity", "delta", "marginal_confidence",
    "simultaneous_confidence", "simultaneous_method", "max_granularity",
    "output_lower_bound", "output_upper_bound")
  numeric_scalar <- function(value) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value)
  }
  metadata_valid <- is.list(result) && !is.null(names(result)) &&
    !anyDuplicated(names(result)) && all(required %in% names(result)) &&
    identical(result$mechanism, .dsvert_dp_noise_mechanism) &&
    identical(result$implementation, .dsvert_dp_noise_implementation) &&
    identical(result$sampler, "deterministic_two_sided_geometric") &&
    identical(result$randomness, "HMAC-SHA256/ChaCha20") &&
    numeric_scalar(result$l0_sensitivity) && result$l0_sensitivity == 1 &&
    numeric_scalar(result$delta) && result$delta == 0 &&
    numeric_scalar(result$marginal_confidence) &&
    result$marginal_confidence == 0.95 &&
    numeric_scalar(result$simultaneous_confidence) &&
    result$simultaneous_confidence == 0.95 &&
    identical(result$simultaneous_method, "union_bound") &&
    numeric_scalar(result$max_granularity) &&
    result$max_granularity > 0 && result$max_granularity <= 1 &&
    numeric_scalar(result$output_lower_bound) &&
    result$output_lower_bound == -.dsvert_dp_exact_integer_limit &&
    numeric_scalar(result$output_upper_bound) &&
    result$output_upper_bound == .dsvert_dp_exact_integer_limit
  if (!isTRUE(metadata_valid)) {
    stop("The Google DP sampler returned invalid mechanism metadata",
         call. = FALSE)
  }
  noisy <- .dsvert_dp_integer_vector(result$values, "sampled values")
  accuracy <- .dsvert_dp_integer_vector(
    result$accuracy_95_abs, "accuracy radii")
  simultaneous_accuracy <- .dsvert_dp_integer_vector(
    result$accuracy_simultaneous_95_abs,
    "simultaneous accuracy radii")
  clipped <- result$clipped_coordinates
  expected_marginal <- .dsvert_dp_laplace_accuracy_radius(
    sensitivities, epsilons, 0.05)
  expected_simultaneous <- .dsvert_dp_laplace_accuracy_radius(
    sensitivities, epsilons, 0.05 / length(values))
  if (length(noisy) != length(values) || length(accuracy) != length(values) ||
      length(simultaneous_accuracy) != length(values) ||
      any(accuracy < 0) || any(simultaneous_accuracy < accuracy) ||
      any(accuracy != expected_marginal) ||
      any(simultaneous_accuracy != expected_simultaneous) ||
      !is.numeric(clipped) || length(clipped) != 1L ||
      is.na(clipped) || !is.finite(clipped) || clipped != trunc(clipped) ||
      clipped < 0 || clipped > length(values) ||
      clipped > .Machine$integer.max) {
    stop("The Google DP sampler returned an invalid result", call. = FALSE)
  }
  list(
    values = noisy,
    accuracy_95_abs = accuracy,
    accuracy_simultaneous_95_abs = simultaneous_accuracy,
    marginal_confidence = 0.95,
    simultaneous_confidence = 0.95,
    simultaneous_method = "union_bound",
    clipped_coordinates = as.integer(clipped),
    mechanism = result$mechanism,
    implementation = result$implementation,
    sampler = result$sampler,
    randomness = result$randomness
  )
}

.dsvert_dp_gaussian_int64 <- function(values, epsilon, delta,
                                       l2_sensitivity, seed,
                                       sampler = NULL) {
  values <- .dsvert_dp_integer_vector(values, "values")
  scalar <- function(value) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value)
  }
  if (!scalar(epsilon) || epsilon < .DSVERT_DP_MINIMUM_EPSILON ||
      epsilon > .DSVERT_DP_MAXIMUM_EPSILON) {
    stop("epsilon must be finite and between 2^-50 and 2^40",
         call. = FALSE)
  }
  if (!scalar(delta) || delta <= 0 || delta >= 1) {
    stop("delta must be finite and strictly between zero and one",
         call. = FALSE)
  }
  if (!scalar(l2_sensitivity) || l2_sensitivity <= 0 ||
      l2_sensitivity > .dsvert_dp_exact_integer_limit) {
    stop("l2_sensitivity must be positive, finite, and exactly representable",
         call. = FALSE)
  }
  if (length(values) > .DSVERT_DP_MAX_COORDINATES) {
    stop("The DP sampler coordinate count exceeds ",
         .DSVERT_DP_MAX_COORDINATES, call. = FALSE)
  }
  if (!is.character(seed) || length(seed) != 1L || is.na(seed) ||
      !grepl("^[0-9a-f]{64}$", seed)) {
    stop("seed must contain exactly 32 bytes encoded as lowercase hexadecimal",
         call. = FALSE)
  }
  if (!is.null(sampler) && !is.function(sampler)) {
    stop("sampler must be NULL or an internal test function", call. = FALSE)
  }
  result <- if (is.null(sampler)) {
    .callMpcTool("dp-gaussian-int64", list(
      values = as.list(values), epsilon = as.numeric(epsilon),
      delta = as.numeric(delta),
      l2_sensitivity = as.numeric(l2_sensitivity), seed = seed))
  } else {
    sampler(
      values = values, epsilon = epsilon, delta = delta,
      l2_sensitivity = l2_sensitivity, seed = seed)
  }
  required <- c(
    "values", "accuracy_95_abs", "accuracy_simultaneous_95_abs",
    "clipped_coordinates", "mechanism", "implementation", "sampler",
    "randomness", "epsilon", "delta", "analytic_delta",
    "implementation_delta_bound",
    "implementation_tv_bound_per_coordinate", "accounting_rule",
    "accuracy_accounting", "l2_sensitivity", "sigma",
    "granularity", "marginal_confidence", "simultaneous_confidence",
    "simultaneous_method", "output_lower_bound", "output_upper_bound")
  exact_names <- is.list(result) && !is.null(names(result)) &&
    !anyNA(names(result)) && !anyDuplicated(names(result)) &&
    identical(sort(names(result), method = "radix"),
              sort(required, method = "radix"))
  metadata_valid <- exact_names &&
    identical(result$mechanism, .dsvert_dp_gaussian_mechanism) &&
    identical(result$implementation, .dsvert_dp_gaussian_implementation) &&
    identical(result$sampler, "deterministic_symmetric_binomial") &&
    identical(result$randomness, "HMAC-SHA256/ChaCha20") &&
    scalar(result$epsilon) &&
    .dsvert_dp_number_equal(result$epsilon, as.numeric(epsilon)) &&
    scalar(result$delta) &&
    .dsvert_dp_number_equal(result$delta, as.numeric(delta)) &&
    scalar(result$analytic_delta) && result$analytic_delta > 0 &&
    scalar(result$implementation_delta_bound) &&
    .dsvert_dp_gaussian_bound_equal(
      result$implementation_delta_bound,
      .dsvert_dp_gaussian_implementation_delta_bound(
        length(values), epsilon)) &&
    .dsvert_dp_number_equal(
      result$implementation_tv_bound_per_coordinate,
      .DSVERT_DP_GAUSSIAN_TV_BOUND_PER_COORDINATE) &&
    result$analytic_delta + result$implementation_delta_bound <=
      result$delta &&
    identical(result$accounting_rule,
              .DSVERT_DP_GAUSSIAN_ACCOUNTING_RULE) &&
    identical(result$accuracy_accounting,
              .DSVERT_DP_GAUSSIAN_ACCURACY_RULE) &&
    scalar(result$l2_sensitivity) &&
    .dsvert_dp_number_equal(
      result$l2_sensitivity, as.numeric(l2_sensitivity)) &&
    scalar(result$sigma) && result$sigma > 0 &&
    scalar(result$granularity) && result$granularity > 0 &&
    result$granularity <= 1 &&
    identical(result$granularity,
              2^round(log2(result$granularity))) &&
    scalar(result$marginal_confidence) &&
    result$marginal_confidence == 0.95 &&
    scalar(result$simultaneous_confidence) &&
    result$simultaneous_confidence == 0.95 &&
    identical(result$simultaneous_method, "union_bound") &&
    scalar(result$output_lower_bound) &&
    result$output_lower_bound == -.dsvert_dp_exact_integer_limit &&
    scalar(result$output_upper_bound) &&
    result$output_upper_bound == .dsvert_dp_exact_integer_limit
  if (!isTRUE(metadata_valid)) {
    stop("The Gaussian DP sampler returned invalid mechanism metadata",
         call. = FALSE)
  }
  noisy <- .dsvert_dp_integer_vector(result$values, "sampled values")
  accuracy <- .dsvert_dp_integer_vector(
    result$accuracy_95_abs, "accuracy radii")
  simultaneous_accuracy <- .dsvert_dp_integer_vector(
    result$accuracy_simultaneous_95_abs,
    "simultaneous accuracy radii")
  clipped <- result$clipped_coordinates
  achieved_delta <- .dsvert_dp_gaussian_achieved_delta(
    result$sigma, l2_sensitivity, epsilon)
  expected_marginal <- .dsvert_dp_gaussian_accuracy_radius(
    result$sigma, 0.05)
  expected_simultaneous <- .dsvert_dp_gaussian_accuracy_radius(
    result$sigma, 0.05 / length(values))
  if (length(noisy) != length(values) || length(accuracy) != length(values) ||
      length(simultaneous_accuracy) != length(values) ||
      any(accuracy < 0) || any(simultaneous_accuracy < accuracy) ||
      !is.finite(achieved_delta) ||
      achieved_delta > result$analytic_delta ||
      !is.finite(expected_marginal) ||
      !is.finite(expected_simultaneous) ||
      any(accuracy != expected_marginal) ||
      any(simultaneous_accuracy != expected_simultaneous) ||
      !is.numeric(clipped) || length(clipped) != 1L ||
      is.na(clipped) || !is.finite(clipped) || clipped != trunc(clipped) ||
      clipped < 0 || clipped > length(values) ||
      clipped > .Machine$integer.max) {
    stop("The Gaussian DP sampler returned an invalid result", call. = FALSE)
  }
  list(
    values = noisy,
    accuracy_95_abs = accuracy,
    accuracy_simultaneous_95_abs = simultaneous_accuracy,
    marginal_confidence = 0.95,
    simultaneous_confidence = 0.95,
    simultaneous_method = "union_bound",
    clipped_coordinates = as.integer(clipped),
    mechanism = result$mechanism,
    implementation = result$implementation,
    sampler = result$sampler,
    randomness = result$randomness,
    epsilon = result$epsilon,
    delta = result$delta,
    analytic_delta = result$analytic_delta,
    implementation_delta_bound = result$implementation_delta_bound,
    implementation_tv_bound_per_coordinate =
      result$implementation_tv_bound_per_coordinate,
    accounting_rule = result$accounting_rule,
    accuracy_accounting = result$accuracy_accounting,
    l2_sensitivity = result$l2_sensitivity,
    sigma = result$sigma,
    granularity = result$granularity)
}

.dsvert_dp_noise_selection <- function(
    coordinate_count, laplace_epsilons, laplace_sensitivities,
    gaussian_epsilon, gaussian_delta, gaussian_l2_sensitivity,
    objective = if (coordinate_count == 1L) {
      "marginal_95_abs"
    } else {
      "simultaneous_95_abs"
    }, selector = NULL) {
  if (!is.numeric(coordinate_count) || length(coordinate_count) != 1L ||
      is.na(coordinate_count) || !is.finite(coordinate_count) ||
      coordinate_count != as.integer(coordinate_count) ||
      coordinate_count < 1L ||
      coordinate_count > .DSVERT_DP_MAX_COORDINATES) {
    stop("coordinate_count is outside the DP selector domain", call. = FALSE)
  }
  coordinate_count <- as.integer(coordinate_count)
  sensitivities <- .dsvert_dp_integer_vector(
    laplace_sensitivities, "laplace sensitivities", positive = TRUE)
  if (!is.numeric(laplace_epsilons) || !length(laplace_epsilons) ||
      anyNA(laplace_epsilons) || any(!is.finite(laplace_epsilons)) ||
      any(laplace_epsilons <= 0) ||
      any(laplace_epsilons > .DSVERT_DP_MAXIMUM_EPSILON) ||
      length(laplace_epsilons) != length(sensitivities)) {
    stop("Laplace selector parameters are invalid", call. = FALSE)
  }
  ratios <- sensitivities / laplace_epsilons
  if (anyNA(ratios) || any(ratios <= 0)) {
    stop("Laplace selector scale is not representable", call. = FALSE)
  }
  worst <- which.max(ratios)
  scalar <- function(value) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value)
  }
  if (!scalar(gaussian_epsilon) ||
      gaussian_epsilon < .DSVERT_DP_MINIMUM_EPSILON ||
      gaussian_epsilon > .DSVERT_DP_MAXIMUM_EPSILON ||
      !scalar(gaussian_delta) || gaussian_delta < 0 || gaussian_delta >= 1 ||
      !scalar(gaussian_l2_sensitivity) || gaussian_l2_sensitivity <= 0 ||
      gaussian_l2_sensitivity > .dsvert_dp_exact_integer_limit ||
      !is.character(objective) || length(objective) != 1L ||
      is.na(objective) ||
      !objective %in% c("marginal_95_abs", "simultaneous_95_abs") ||
      (identical(objective, "marginal_95_abs") && coordinate_count != 1L)) {
    stop("Gaussian selector parameters are invalid", call. = FALSE)
  }
  input <- list(
    coordinate_count = coordinate_count,
    laplace_epsilon = as.numeric(laplace_epsilons[[worst]]),
    laplace_l1_sensitivity = as.numeric(sensitivities[[worst]]),
    gaussian_epsilon = as.numeric(gaussian_epsilon),
    gaussian_delta = as.numeric(gaussian_delta),
    gaussian_l2_sensitivity = as.numeric(gaussian_l2_sensitivity),
    objective = objective)
  if (!is.null(selector) && !is.function(selector)) {
    stop("selector must be NULL or an internal test function", call. = FALSE)
  }
  result <- if (is.null(selector)) {
    .callMpcTool("dp-noise-select-int64", input)
  } else {
    do.call(selector, input)
  }
  top_names <- c(
    "schema_version", "selector", "objective", "coordinate_count",
    "laplace", "gaussian", "winner", "winner_mechanism",
    "winning_metric_abs", "winner_delta", "tie_break")
  candidate_names <- c(
    "available", "mechanism", "epsilon", "delta", "sensitivity_norm",
    "sensitivity", "analytic_delta", "implementation_delta_bound",
    "accounting_rule", "accuracy_accounting",
    "marginal_95_abs", "simultaneous_95_abs",
    "nominal_rmse", "sigma", "granularity",
    "analytic_accounting_verified", "unavailable_reason")
  exact_names <- function(value, expected) {
    is.list(value) && !is.null(names(value)) && !anyNA(names(value)) &&
      !anyDuplicated(names(value)) &&
      identical(sort(names(value), method = "radix"),
                sort(expected, method = "radix"))
  }
  integer_scalar <- function(value) {
    scalar(value) && value == trunc(value) && value >= 0 &&
      value <= .dsvert_dp_exact_integer_limit
  }
  candidate_valid <- function(value, mechanism, epsilon, delta,
                              norm, sensitivity) {
    exact_names(value, candidate_names) &&
      is.logical(value$available) && length(value$available) == 1L &&
      !is.na(value$available) && identical(value$mechanism, mechanism) &&
      scalar(value$epsilon) &&
      .dsvert_dp_number_equal(value$epsilon, epsilon) &&
      scalar(value$delta) && .dsvert_dp_number_equal(value$delta, delta) &&
      scalar(value$analytic_delta) && value$analytic_delta >= 0 &&
      scalar(value$implementation_delta_bound) &&
      value$implementation_delta_bound >= 0 &&
      is.character(value$accounting_rule) &&
      length(value$accounting_rule) == 1L &&
      !is.na(value$accounting_rule) && nzchar(value$accounting_rule) &&
      is.character(value$accuracy_accounting) &&
      length(value$accuracy_accounting) == 1L &&
      !is.na(value$accuracy_accounting) && nzchar(value$accuracy_accounting) &&
      identical(value$sensitivity_norm, norm) &&
      scalar(value$sensitivity) &&
      .dsvert_dp_number_equal(value$sensitivity, sensitivity) &&
      integer_scalar(value$marginal_95_abs) &&
      integer_scalar(value$simultaneous_95_abs) &&
      value$simultaneous_95_abs >= value$marginal_95_abs &&
      scalar(value$nominal_rmse) && value$nominal_rmse >= 0 &&
      scalar(value$sigma) && value$sigma >= 0 &&
      scalar(value$granularity) && value$granularity >= 0 &&
      is.logical(value$analytic_accounting_verified) &&
      length(value$analytic_accounting_verified) == 1L &&
      !is.na(value$analytic_accounting_verified) &&
      is.character(value$unavailable_reason) &&
      length(value$unavailable_reason) == 1L &&
      !is.na(value$unavailable_reason) &&
      if (isTRUE(value$available)) {
        value$analytic_accounting_verified && value$nominal_rmse > 0 &&
          value$granularity > 0 && value$granularity <= 1 &&
          value$analytic_delta + value$implementation_delta_bound <=
            value$delta &&
          !nzchar(value$unavailable_reason)
      } else {
        !value$analytic_accounting_verified &&
          nzchar(value$unavailable_reason)
      }
  }
  valid <- exact_names(result, top_names) &&
    identical(result$schema_version, 2L) &&
    identical(result$selector, .DSVERT_DP_NOISE_SELECTOR) &&
    identical(result$objective, objective) &&
    identical(result$coordinate_count, coordinate_count) &&
    candidate_valid(
      result$laplace, .dsvert_dp_noise_mechanism,
      input$laplace_epsilon, 0, "l1",
      input$laplace_l1_sensitivity) &&
    candidate_valid(
      result$gaussian, .dsvert_dp_gaussian_mechanism,
      input$gaussian_epsilon, input$gaussian_delta, "l2",
      input$gaussian_l2_sensitivity) &&
    .dsvert_dp_number_equal(result$laplace$analytic_delta, 0) &&
    .dsvert_dp_number_equal(
      result$laplace$implementation_delta_bound, 0) &&
    identical(
      result$laplace$accounting_rule,
      "pure_dp_no_implementation_slack") &&
    identical(
      result$laplace$accuracy_accounting,
      "exact_granular_laplace_confidence_interval") &&
    .dsvert_dp_gaussian_bound_equal(
      result$gaussian$implementation_delta_bound,
      .dsvert_dp_gaussian_implementation_delta_bound(
        coordinate_count, input$gaussian_epsilon)) &&
    identical(result$gaussian$accounting_rule,
              .DSVERT_DP_GAUSSIAN_ACCOUNTING_RULE) &&
    identical(result$gaussian$accuracy_accounting,
              .DSVERT_DP_GAUSSIAN_ACCURACY_RULE) &&
    (if (isTRUE(result$gaussian$available)) {
       result$gaussian$analytic_delta > 0 &&
         .dsvert_dp_number_equal(
           result$gaussian$analytic_delta,
           input$gaussian_delta -
             result$gaussian$implementation_delta_bound)
     } else {
       .dsvert_dp_number_equal(result$gaussian$analytic_delta, 0)
     }) &&
    result$winner %in% c("laplace", "gaussian", "none") &&
    identical(result$tie_break, .DSVERT_DP_NOISE_TIE_BREAK) &&
    integer_scalar(result$winning_metric_abs) &&
    scalar(result$winner_delta)
  if (!isTRUE(valid)) {
    stop("The DP noise selector returned an invalid certificate",
         call. = FALSE)
  }
  metric_name <- if (identical(objective, "marginal_95_abs")) {
    "marginal_95_abs"
  } else {
    "simultaneous_95_abs"
  }
  gaussian_wins <- isTRUE(result$gaussian$available) &&
    isTRUE(result$gaussian$analytic_accounting_verified) &&
    (!isTRUE(result$laplace$available) ||
       result$gaussian[[metric_name]] < result$laplace[[metric_name]])
  expected_winner <- if (gaussian_wins) {
    "gaussian"
  } else if (isTRUE(result$laplace$available) &&
             isTRUE(result$laplace$analytic_accounting_verified)) {
    "laplace"
  } else {
    "none"
  }
  selected_valid <- if (identical(expected_winner, "none")) {
    identical(result$winner_mechanism, "") &&
      result$winning_metric_abs == 0 && result$winner_delta == 0
  } else {
    selected <- result[[expected_winner]]
    identical(result$winner_mechanism, selected$mechanism) &&
      identical(result$winning_metric_abs, selected[[metric_name]]) &&
      identical(result$winner_delta, selected$delta)
  }
  if (!identical(result$winner, expected_winner) || !selected_valid) {
    stop("The DP noise selector violated its deterministic winner rule",
         call. = FALSE)
  }
  result
}

.dsvert_dp_noise_plan <- function(
    coordinate_count, laplace_epsilons, laplace_sensitivities,
    epsilon, delta, l2_sensitivity,
    objective = if (coordinate_count == 1L) {
      "marginal_95_abs"
    } else {
      "simultaneous_95_abs"
    }) {
  certificate <- .dsvert_dp_noise_selection(
    coordinate_count, laplace_epsilons, laplace_sensitivities,
    epsilon, delta, l2_sensitivity, objective)
  winner <- certificate$winner
  list(
    selector = certificate$selector,
    winner = winner,
    mechanism = paste0(
      "dsvert_sticky_", certificate$selector, "_", winner, "_v1"),
    sensitivity = if (identical(winner, "gaussian")) {
      as.numeric(l2_sensitivity)
    } else {
      as.numeric(max(laplace_sensitivities))
    },
    delta = certificate$winner_delta,
    certificate = certificate)
}

.dsvert_dp_sample_selected_int64 <- function(
    values, laplace_epsilons, laplace_sensitivities,
    epsilon, delta, l2_sensitivity, seed, mechanism_plan) {
  if (!is.list(mechanism_plan) ||
      !identical(mechanism_plan$selector, .DSVERT_DP_NOISE_SELECTOR) ||
      !mechanism_plan$winner %in% c("laplace", "gaussian")) {
    stop("The DP sampling plan is invalid", call. = FALSE)
  }
  if (identical(mechanism_plan$winner, "gaussian")) {
    if (delta <= 0 ||
        !identical(mechanism_plan$certificate$winner_delta, delta)) {
      stop("The selected Gaussian allocation is invalid", call. = FALSE)
    }
    return(.dsvert_dp_gaussian_int64(
      values, epsilon, delta, l2_sensitivity, seed))
  }
  if (delta != 0 || mechanism_plan$certificate$winner_delta != 0) {
    stop("A selected Laplace release must consume zero delta",
         call. = FALSE)
  }
  .dsvert_dp_noise_int64(
    values, laplace_epsilons, laplace_sensitivities, seed)
}

.dsvert_dp_dataset_binding <- function(policy, data_name, data, secret) {
  descriptor <- policy$datasets[[data_name]]
  if (is.null(descriptor)) {
    stop("The protected object is not registered in the custodian-owned DP ",
         "dataset manifest", call. = FALSE)
  }
  snapshot_sha256 <- .dsvert_dp_snapshot_digest(data)
  if (!is.null(descriptor$snapshot_sha256) &&
      !identical(snapshot_sha256, descriptor$snapshot_sha256)) {
    stop("The protected object does not match its custodian-approved DP ",
         "snapshot", call. = FALSE)
  }
  alignment <- NULL
  if (!is.null(descriptor$alignment_manifest_hash)) {
    alignment <- .dsvert_dp_validate_descriptor_alignment(
      data, descriptor, policy$patient_column,
      expected_pinset = policy$peer_pinset,
      snapshot_sha256 = snapshot_sha256)
  } else if (isTRUE(policy$require_alignment_manifest)) {
    stop("The protected object lacks its required PSI alignment binding",
         call. = FALSE)
  }
  public <- list(
    data_name = data_name, id = descriptor$id, version = descriptor$version,
    alignment_manifest_hash = descriptor$alignment_manifest_hash,
    alignment_manifest_version = descriptor$alignment_manifest_version)
  list(
    public = public,
    ledger_key = paste0("dataset_snapshot_", substr(
      .dsvert_dp_hmac(secret, list(policy$domain, public)), 1L, 40L)),
    fingerprint = .dsvert_dp_hmac(
      secret, list("dsvert-dp-snapshot-alignment-v2", public,
                   snapshot_sha256, alignment))
  )
}

.dsvert_dp_canonical_query_value <- function(value) {
  if (is.null(value)) return(NULL)
  if (is.object(value)) {
    stop("The canonical DP query contains an unsupported value type",
         call. = FALSE)
  }
  if (is.list(value)) {
    fields <- names(value)
    if (!is.null(fields)) {
      if (anyNA(fields) || any(!nzchar(fields)) || anyDuplicated(fields)) {
        stop("The canonical DP query contains invalid object fields",
             call. = FALSE)
      }
      value <- value[order(fields, method = "radix")]
    }
    return(lapply(value, .dsvert_dp_canonical_query_value))
  }
  if (!typeof(value) %in% c(
        "logical", "integer", "double", "character")) {
    stop("The canonical DP query contains an unsupported value type",
         call. = FALSE)
  }
  if (!is.null(names(value))) {
    stop("Canonical DP query vectors must be unnamed", call. = FALSE)
  }
  if (anyNA(value) || (is.numeric(value) && any(!is.finite(value)))) {
    stop("The canonical DP query contains a missing or non-finite value",
         call. = FALSE)
  }
  if (is.character(value)) {
    return(enc2utf8(unname(value)))
  }
  if (is.numeric(value)) {
    value <- unname(as.numeric(value))
    # JSON has one numeric type. Normalising signed zero and R's
    # integer/double distinction prevents syntactic rerolls of the same query.
    value[value == 0] <- 0
    return(value)
  }
  unname(value)
}

.dsvert_dp_query_hash <- function(secret, policy, dataset, method, arguments) {
  context <- .dsvert_dp_canonical_query_value(list(
    protocol = "dsvert-canonical-query-hmac-v1",
    schema_version = 1L,
    mechanism_version = policy$mechanism_version,
    domain = policy$domain,
    privacy_epoch = policy$noise_root$epoch,
    noise_key_id = policy$noise_root$key_id,
    dataset = dataset,
    method = method,
    arguments = arguments
  ))
  digest::hmac(
    key = secret,
    object = charToRaw(.dsvert_dp_canonical_json(context)),
    algo = "sha256", serialize = FALSE, raw = FALSE)
}

.dsvert_dp_assert_canonical_query_runtime <- function() {
  expected <-
    "c90fa516eee010896212cf1d716efe8b14faa0fac50d2c452891e45f733335aa"
  observed <- .dsvert_dp_query_hash(
    as.raw(seq_len(32L)),
    list(
      mechanism_version =
        "dsvert-dp-v7-contingency-unit-aggregation-1",
      domain = "study-domain",
      noise_root = list(epoch = 1, key_id = "file_test")),
    list(
      data_name = "protected", id = "cohort", version = "v1",
      alignment_manifest_hash = NULL,
      alignment_manifest_version = NULL),
    "bounded_mean",
    list(
      variable = "x", bounds = c(-0, 1L),
      admission = list(max_records = 1L, capacity = 100L)))
  if (!identical(observed, expected)) {
    stop(
      "The canonical DP query encoder changed; sticky releases are disabled until an explicit protocol migration is installed",
      call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_get_data <- function(data_name, envir) {
  .validate_data_name(data_name)
  data <- get(data_name, envir = envir, inherits = TRUE)
  if (!is.data.frame(data)) {
    stop("The protected object is not a data frame", call. = FALSE)
  }
  data
}

.dsvert_dp_adjacency_multiplier <- function(policy) {
  if (identical(policy$adjacency, "add_remove_patient")) 1L else 2L
}

.dsvert_dp_admission_public <- function(policy) {
  list(
    adjacency = policy$adjacency,
    unit_capacity = policy$unit_capacity,
    fixed_cohort_size = policy$fixed_cohort_size,
    max_records_per_unit = policy$max_records_per_unit,
    overflow_policy = policy$overflow_policy)
}

.dsvert_dp_admission_error <- function() {
  stop("The protected snapshot does not satisfy its custodian-owned DP admission contract",
       call. = FALSE)
}

.dsvert_dp_admit_units <- function(data, policy) {
  if (!is.data.frame(data) ||
      !identical(policy$overflow_policy, "reject_snapshot") ||
      !policy$adjacency %in% c(
        "add_remove_patient", "replace_one_fixed_cohort")) {
    .dsvert_dp_admission_error()
  }
  patient_column <- policy$patient_column
  if (!is.character(patient_column) || length(patient_column) != 1L ||
      is.na(patient_column) || !patient_column %in% names(data) ||
      !is.atomic(data[[patient_column]])) {
    .dsvert_dp_admission_error()
  }
  raw_id <- data[[patient_column]]
  ids <- tryCatch(
    .dsvert_canonical_label_values(
      raw_id, "protected patient identifiers",
      allow_na = TRUE, allow_blank = TRUE),
    error = function(e) .dsvert_dp_admission_error())
  invalid_id <- is.na(ids) | !nzchar(trimws(ids))
  if (length(ids) != nrow(data) || any(invalid_id)) {
    .dsvert_dp_admission_error()
  }
  capacity <- as.integer(policy$unit_capacity)
  max_records <- as.integer(policy$max_records_per_unit)
  if (nrow(data) > as.numeric(capacity) * as.numeric(max_records)) {
    .dsvert_dp_admission_error()
  }
  ids <- enc2utf8(ids)
  unit_ids <- sort(unique(ids), method = "radix")
  unit_count <- length(unit_ids)
  group <- match(ids, unit_ids)
  record_count <- if (unit_count) {
    tabulate(group, nbins = unit_count)
  } else {
    integer()
  }
  invalid_capacity <- unit_count > capacity ||
    any(record_count > max_records) ||
    (identical(policy$adjacency, "replace_one_fixed_cohort") &&
     unit_count != policy$fixed_cohort_size)
  if (isTRUE(invalid_capacity)) .dsvert_dp_admission_error()
  present <- rep(FALSE, capacity)
  if (unit_count) present[seq_len(unit_count)] <- TRUE
  list(
    group = as.integer(group),
    present = present,
    unit_count = as.integer(unit_count),
    work_units = capacity,
    record_count = c(record_count, integer(capacity - unit_count)))
}

.dsvert_dp_coordinate_count <- function(row_levels, col_levels) {
  n_row <- length(row_levels)
  n_col <- length(col_levels)
  if (n_row < 1L || n_col < 1L ||
      n_row > .DSVERT_DP_MAX_COORDINATES ||
      n_col > floor(.DSVERT_DP_MAX_COORDINATES / n_row)) {
    stop("The fixed DP table domain exceeds ",
         .DSVERT_DP_MAX_COORDINATES, " coordinates", call. = FALSE)
  }
  as.integer(n_row * n_col)
}

.dsvert_dp_bounded_pairs <- function(data, policy, row_var, col_var,
                                     admission = NULL) {
  allowed_row <- policy$categorical_levels[[row_var]]
  allowed_col <- policy$categorical_levels[[col_var]]
  if (is.null(allowed_row) || is.null(allowed_col)) {
    stop("The requested categorical variables have no custodian-owned domain",
         call. = FALSE)
  }
  unit_aggregation_policy <-
    policy$contingency_unit_aggregation_policy
  if (!identical(
        unit_aggregation_policy,
        "consistent_cell_else_exclude_v1")) {
    stop("The DP contingency unit aggregation policy is invalid",
         call. = FALSE)
  }
  # Validate the public domain product before indexing protected columns or
  # allocating the histogram. This avoids integer wrap and oversized tabulate
  # allocations even for a malformed custodian policy.
  cell_count <- .dsvert_dp_coordinate_count(allowed_row, allowed_col)
  if (!all(c(row_var, col_var) %in% names(data))) {
    stop("The protected data do not satisfy the configured DP query",
         call. = FALSE)
  }
  row_value <- tryCatch(
    .dsvert_dp_categorical_label_values(
      data[[row_var]], "protected categorical values"),
    error = function(e) {
      stop("The protected data do not satisfy the configured DP query",
           call. = FALSE)
    })
  col_value <- tryCatch(
    .dsvert_dp_categorical_label_values(
      data[[col_var]], "protected categorical values"),
    error = function(e) {
      stop("The protected data do not satisfy the configured DP query",
           call. = FALSE)
    })
  valid <- !is.na(row_value) & !is.na(col_value) &
    row_value %in% allowed_row & col_value %in% allowed_col
  if (is.null(admission)) admission <- .dsvert_dp_admit_units(data, policy)
  row_index <- match(row_value, allowed_row)
  col_index <- match(col_value, allowed_col)
  cell <- ifelse(
    valid,
    row_index + (col_index - 1L) * length(allowed_row),
    NA_integer_)
  selected <- rep(NA_integer_, admission$work_units)
  valid_rows <- which(!is.na(cell))
  if (length(valid_rows)) {
    valid_groups <- admission$group[valid_rows]
    valid_cells <- cell[valid_rows]
    # The configured limits keep this exact composite key below 2^53. Hashing
    # it avoids an O(n log n) row sort for large repeated-record snapshots.
    pair_key <- (as.double(valid_groups) - 1) * cell_count + valid_cells
    distinct_pair <- !duplicated(pair_key)
    distinct_per_group <- tabulate(
      valid_groups[distinct_pair], nbins = admission$work_units)
    first_per_group <- !duplicated(valid_groups)
    first_groups <- valid_groups[first_per_group]
    first_cells <- valid_cells[first_per_group]
    consistent <- distinct_per_group[first_groups] == 1L
    selected[first_groups[consistent]] <- first_cells[consistent]
  }
  list(cell = unname(selected), row_levels = allowed_row,
       col_levels = allowed_col, cell_count = cell_count,
       unit_aggregation_policy = unit_aggregation_policy)
}

.dsvert_dp_bounded_numeric <- function(data, policy, variable,
                                       admission = NULL) {
  bounds <- policy$numeric_bounds[[variable]]
  if (is.null(bounds)) {
    stop("The requested numeric variable has no custodian-owned bounds",
         call. = FALSE)
  }
  if (!variable %in% names(data) || !is.numeric(data[[variable]])) {
    stop("The protected data do not satisfy the configured DP query",
         call. = FALSE)
  }
  values <- as.numeric(data[[variable]])
  if (is.null(admission)) admission <- .dsvert_dp_admit_units(data, policy)
  unit_value <- numeric(admission$work_units)
  valid <- rep(FALSE, admission$work_units)
  finite <- is.finite(values)
  if (any(finite)) {
    rows <- which(finite)
    # Bound every record before patient-level collapse. Averaging unbounded
    # rows and clipping only the resulting mean is not the documented
    # contribution rule and can also overflow before clipping.
    bounded_rows <- pmin(
      bounds[[2L]], pmax(bounds[[1L]], values[rows]))
    ordered <- rows[order(
      admission$group[rows], bounded_rows, rows, method = "radix")]
    bounded_ordered <- pmin(
      bounds[[2L]], pmax(bounds[[1L]], values[ordered]))
    sums <- rowsum(
      matrix(bounded_ordered, ncol = 1L),
      admission$group[ordered], reorder = FALSE)
    groups <- as.integer(rownames(sums))
    counts <- tabulate(
      admission$group[ordered], nbins = admission$unit_count)
    unit_value[groups] <- as.numeric(sums[, 1L]) / counts[groups]
    valid[groups] <- TRUE
  }
  valid <- valid & admission$present
  unit_value[valid] <- pmin(
    bounds[[2L]], pmax(bounds[[1L]], unit_value[valid]))
  list(values = unit_value[valid], unit_values = unit_value,
       valid = valid, present = admission$present, bounds = bounds)
}

.dsvert_dp_quantized_moments <- function(normalised, grid_bits) {
  if (!is.numeric(normalised) || anyNA(normalised) ||
      any(!is.finite(normalised)) || any(normalised < 0 | normalised > 1)) {
    stop("Normalised DP values must be finite and lie in [0,1]",
         call. = FALSE)
  }
  if (!is.numeric(grid_bits) || length(grid_bits) != 1L ||
      is.na(grid_bits) || grid_bits != as.integer(grid_bits) ||
      grid_bits < 8L || grid_bits > 18L) {
    stop("DP numeric grid bits must be an integer in [8,18]",
         call. = FALSE)
  }
  scale <- 2^as.integer(grid_bits)
  # Quantise z and z^2 separately onto a common integer lattice. Adding
  # integer-valued geometric noise to unquantised real sums would reveal the
  # exact fractional part and would not be a DP mechanism.
  q_sum <- round(normalised * scale)
  q_sumsq <- round(normalised^2 * scale)
  max_units <- floor((2^53 - 1) / scale)
  if (length(normalised) > max_units) {
    stop("The bounded cohort is too large for exact DP integer accounting at ",
         "the configured numeric grid", call. = FALSE)
  }
  statistics <- c(
    n = length(normalised), sum = sum(q_sum), sumsq = sum(q_sumsq))
  if (any(statistics != floor(statistics)) || any(abs(statistics) > 2^53 - 1)) {
    stop("The quantised DP sufficient statistics are not exactly representable",
         call. = FALSE)
  }
  list(statistics = statistics, scale = scale,
       max_abs_quantization_per_unit = 0.5 / scale)
}
