# Private Rock-local source resolver for the registered formal-GLM ingress.
#
# This is intentionally not a DataSHIELD entry point.  The K-signed source
# contract chooses a source binding; the server-owned specification chooses the
# only immutable local snapshot that may satisfy it.  The resulting environment
# is a private carrier for the later encrypted block producer, never a wire
# value or an analyst-selectable data source.

.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_SPECS_OPTION <-
  "dsvert.formal_glm.registered_source_specs"
.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_CONTEXT_CLASS <-
  "dsvert_formal_glm_registered_source_context"
.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_PROJECT_VERSION <-
  "dsvert-formal-glm-phase18-source-project-response-v1"
.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_PRIVATE_CARRIER <-
  "rock_local_nonserialized_materializer_inputs_required_v1"

.dsvert_formal_glm_registered_source_abort <- function(message) {
  stop(structure(
    list(message = message, call = NULL, openings_performed = 0L),
    class = c("dsvert_formal_glm_registered_source_error", "error",
              "condition")))
}

.dsvert_formal_glm_registered_source_label <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$", value)) {
    .dsvert_formal_glm_registered_source_abort(
      paste0("Invalid configured formal-GLM ", what, "."))
  }
  enc2utf8(value)
}

.dsvert_formal_glm_registered_source_sha256 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_glm_registered_source_abort(
      paste0("Invalid configured formal-GLM ", what, "."))
  }
  value
}

.dsvert_formal_glm_registered_source_specs <- function() {
  specs <- getOption(.DSVERT_FORMAL_GLM_REGISTERED_SOURCE_SPECS_OPTION)
  if (!is.list(specs) || !length(specs) || is.null(names(specs)) ||
      anyNA(names(specs)) || any(!nzchar(names(specs))) ||
      anyDuplicated(names(specs))) {
    .dsvert_formal_glm_registered_source_abort(
      "The server has no unambiguous registered formal-GLM source configuration.")
  }
  names(specs) <- vapply(
    names(specs), .dsvert_formal_glm_registered_source_label,
    character(1L), what = "source name")
  if (anyDuplicated(names(specs))) {
    .dsvert_formal_glm_registered_source_abort(
      "The server has ambiguous registered formal-GLM source configuration.")
  }
  specs
}

.dsvert_formal_glm_registered_source_descriptor <- function(value) {
  fields <- c(
    "id", "version", "snapshot_sha256", "alignment_manifest_hash",
    "alignment_manifest_version")
  if (!is.list(value) || !identical(names(value), fields)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM source dataset is invalid.")
  }
  value$id <- .dsvert_formal_glm_registered_source_label(value$id, "dataset id")
  value$version <- .dsvert_formal_glm_registered_source_label(
    value$version, "dataset version")
  value$snapshot_sha256 <- .dsvert_formal_glm_registered_source_sha256(
    value$snapshot_sha256, "snapshot digest")
  value$alignment_manifest_hash <- .dsvert_formal_glm_registered_source_sha256(
    value$alignment_manifest_hash, "alignment digest")
  version <- suppressWarnings(as.integer(value$alignment_manifest_version))
  if (length(version) != 1L || is.na(version) || version < 1L) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM alignment version is invalid.")
  }
  value$alignment_manifest_version <- version
  value
}

.dsvert_formal_glm_registered_source_pins <- function(value) {
  if (!is.list(value) || length(value) < 2L || is.null(names(value)) ||
      anyNA(names(value)) || any(!nzchar(names(value))) ||
      anyDuplicated(names(value))) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM peer pinset is invalid.")
  }
  names(value) <- vapply(
    names(value), .dsvert_formal_glm_registered_source_label,
    character(1L), what = "pinned peer")
  pins <- vapply(value, function(pin) {
    if (!is.character(pin) || length(pin) != 1L || is.na(pin)) return(NA_character_)
    raw <- tryCatch(jsonlite::base64_dec(pin), error = function(error) raw())
    valid <- is.raw(raw) && length(raw) == 32L && identical(
      gsub("[\r\n]", "", jsonlite::base64_enc(raw)), pin)
    if (is.raw(raw) && length(raw)) raw[] <- as.raw(0L)
    if (!valid) return(NA_character_)
    pin
  }, character(1L), USE.NAMES = TRUE)
  if (anyNA(pins) || anyDuplicated(names(pins))) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM peer pinset is invalid.")
  }
  as.list(pins)
}

.dsvert_formal_glm_registered_source_b64url <- function(value) {
  sub("=+$", "", chartr("+/", "-_", value), perl = TRUE)
}

.dsvert_formal_glm_registered_source_spec <- function(source) {
  fields <- c(
    "source_name", "source_contract_sha256", "authorization_sha256",
    "logical_snapshot_sha256", "pins", "dataset", "data_name",
    "patient_column", "columns")
  spec <- .dsvert_formal_glm_registered_source_specs()[[source]]
  if (!is.list(spec) || !identical(names(spec), fields)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured registered formal-GLM source is invalid.")
  }
  spec$source_name <- .dsvert_formal_glm_registered_source_label(
    spec$source_name, "source name")
  spec$source_contract_sha256 <- .dsvert_formal_glm_registered_source_sha256(
    spec$source_contract_sha256, "source-contract digest")
  spec$authorization_sha256 <- .dsvert_formal_glm_registered_source_sha256(
    spec$authorization_sha256, "authorization digest")
  spec$logical_snapshot_sha256 <- .dsvert_formal_glm_registered_source_sha256(
    spec$logical_snapshot_sha256, "logical-snapshot digest")
  spec$pins <- .dsvert_formal_glm_registered_source_pins(spec$pins)
  spec$dataset <- .dsvert_formal_glm_registered_source_descriptor(spec$dataset)
  spec$data_name <- .dsvert_formal_glm_registered_source_label(
    spec$data_name, "data binding")
  spec$patient_column <- .dsvert_formal_glm_registered_source_label(
    spec$patient_column, "patient column")
  if (!is.list(spec$columns)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM column map is invalid.")
  }
  if (!length(spec$columns)) {
    spec$columns <- character()
  } else {
    if (is.null(names(spec$columns)) || anyNA(names(spec$columns)) ||
        any(!nzchar(names(spec$columns))) || anyDuplicated(names(spec$columns))) {
      .dsvert_formal_glm_registered_source_abort(
        "The configured formal-GLM column map is invalid.")
    }
    names(spec$columns) <- vapply(
      names(spec$columns), .dsvert_formal_glm_registered_source_label,
      character(1L), what = "source column")
    spec$columns <- stats::setNames(vapply(
      spec$columns, .dsvert_formal_glm_registered_source_label,
      character(1L), what = "physical column"), names(spec$columns))
  }
  if (!identical(spec$source_name, source) ||
      anyDuplicated(unname(spec$columns)) ||
      spec$patient_column %in% unname(spec$columns) ||
      !source %in% names(spec$pins)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM source does not match its local peer.")
  }
  spec
}

.dsvert_formal_glm_registered_source_project <- function(
    source_contract_json, spec, source) {
  if (!is.character(source_contract_json) || length(source_contract_json) != 1L ||
      is.na(source_contract_json) || !nzchar(source_contract_json) ||
      nchar(source_contract_json, type = "bytes") > 32L * 1024L^2) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM source contract is invalid.")
  }
  response <- tryCatch(.callMpcTool("formal-glm-phase18-source-project", list(
    source_contract_json = source_contract_json, pins = spec$pins,
    local_peer_name = source)), error = function(error) NULL)
  fields <- c("version", "authorization_json", "authorization_sha256")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version, .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_PROJECT_VERSION) ||
      !is.character(response$authorization_json) ||
      length(response$authorization_json) != 1L ||
      !is.character(response$authorization_sha256) ||
      length(response$authorization_sha256) != 1L ||
      !identical(response$authorization_sha256, spec$authorization_sha256)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM source projection is invalid.")
  }
  authorization <- tryCatch(jsonlite::fromJSON(
    response$authorization_json, simplifyVector = FALSE),
    error = function(error) NULL)
  if (!is.list(authorization)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM authorization is invalid.")
  }
  list(json = response$authorization_json, value = authorization)
}

.dsvert_formal_glm_registered_source_authorization <- function(
    projected, spec, source) {
  authorization <- projected$value
  source_record <- authorization$local_source
  columns <- authorization$local_columns
  geometry <- authorization$geometry
  if (!identical(authorization$authorization_sha256,
                 spec$authorization_sha256) ||
      !identical(authorization$source_contract_sha256,
                 spec$source_contract_sha256) ||
      !identical(authorization$logical_snapshot_sha256,
                 spec$logical_snapshot_sha256) ||
      !identical(authorization$private_carrier_requirement,
                 .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_PRIVATE_CARRIER) ||
      !identical(authorization$openings_performed, 0L) ||
      !identical(authorization$production_ready, FALSE) ||
      !is.list(source_record) ||
      !identical(source_record$signer_peer_name, source) ||
      !identical(source_record$dataset_id, spec$dataset$id) ||
      !identical(source_record$dataset_version, spec$dataset$version) ||
      !is.list(columns) || !is.list(geometry) ||
      length(geometry$total_capacity) != 1L ||
      is.na(suppressWarnings(as.integer(geometry$total_capacity))) ||
      as.integer(geometry$total_capacity) < 1L) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM authorization does not match its source.")
  }
  identity <- authorization$local_peer_identity
  if (!is.list(identity) || !identical(identity$peer_name, source) ||
      !identical(identity$identity_pk,
                 .dsvert_formal_glm_registered_source_b64url(
                   spec$pins[[source]]))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM authorization has the wrong source identity.")
  }
  logical_columns <- vapply(columns, function(column) {
    if (!is.list(column) || !identical(column$owner, source) ||
        !identical(column$dataset_id, spec$dataset$id) ||
        !identical(column$dataset_version, spec$dataset$version) ||
        !is.character(column$column) || length(column$column) != 1L ||
        is.na(column$column)) return(NA_character_)
    column$column
  }, character(1L))
  configured_columns <- names(spec$columns)
  if (is.null(configured_columns)) configured_columns <- character()
  if (anyNA(logical_columns) || anyDuplicated(logical_columns) ||
      length(logical_columns) != length(spec$columns) ||
      !identical(unname(logical_columns), configured_columns)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM column map differs from the authorization.")
  }
  as.integer(geometry$total_capacity)
}

.dsvert_formal_glm_registered_source_snapshot <- function(
    spec, expected_rows, source_contract_sha256, logical_snapshot_sha256,
    source_environment) {
  if (!is.environment(source_environment)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM source environment is invalid.")
  }
  environment <- tryCatch(
    .dsvert_dp_binding_environment(spec$data_name, source_environment),
    error = function(error) NULL)
  if (is.null(environment) || bindingIsActive(spec$data_name, environment) ||
      !bindingIsLocked(spec$data_name, environment)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM snapshot must be immutable.")
  }
  data <- tryCatch(get(spec$data_name, envir = environment, inherits = FALSE),
                   error = function(error) NULL)
  if (!is.data.frame(data)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM snapshot is unavailable.")
  }
  digest <- .dsvert_dp_snapshot_digest(data)
  if (!identical(digest, spec$dataset$snapshot_sha256)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM snapshot has changed.")
  }
  data <- tryCatch(.dsvert_dp_freeze_snapshot_frame(data),
                   error = function(error) NULL)
  aligned <- tryCatch({
    .dsvert_dp_validate_descriptor_alignment(
      data, spec$dataset, patient_column = spec$patient_column,
      expected_pinset = unlist(spec$pins, use.names = TRUE),
      snapshot_sha256 = digest)
    .dsvert_dp_padded_alignment_binding(data, snapshot_sha256 = digest)
  }, error = function(error) NULL)
  if (is.null(data) || is.null(aligned) ||
      !identical(aligned$descriptor, spec$dataset) || nrow(data) != expected_rows ||
      !all(c(spec$patient_column, unname(spec$columns)) %in% names(data))) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM snapshot is not the pinned PSI source.")
  }
  manifest <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  if (!is.list(manifest) || !is.character(manifest$token) ||
      length(manifest$token) != 1L || is.na(manifest$token) ||
      !nzchar(manifest$token)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM snapshot lacks its private PSI binding.")
  }
  consensus <- digest::hmac(
    key = manifest$token,
    object = charToRaw(.dsvert_dp_canonical_json(list(
      domain = "dsVert/formal-glm/registered-phase18/private-alignment-consensus/v1",
      source_contract_sha256 = source_contract_sha256,
      logical_snapshot_sha256 = logical_snapshot_sha256,
      total_capacity = as.integer(expected_rows)))),
    algo = "sha256", serialize = FALSE, raw = TRUE)
  if (!is.raw(consensus) || length(consensus) != 32L) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured formal-GLM PSI consensus is invalid.")
  }
  rows <- data[, unname(spec$columns), drop = FALSE]
  names(rows) <- names(spec$columns)
  list(rows = rows, consensus = consensus)
}

# Opens one configured registered source.  The resulting environment is kept
# deliberately non-serializable and contains only the authenticated public
# authorization plus the frozen private rows needed by the block producer.
.dsvert_formal_glm_registered_source_open <- function(
    source_contract_json, source_environment = parent.frame()) {
  source <- tryCatch(.dsvert_require_configured_local_peer_name(),
                     error = function(error) NULL)
  if (is.null(source)) {
    .dsvert_formal_glm_registered_source_abort(
      "The configured local peer is unavailable for formal-GLM source work.")
  }
  source <- .dsvert_formal_glm_registered_source_label(source, "local peer")
  spec <- .dsvert_formal_glm_registered_source_spec(source)
  identity <- tryCatch(.get_identity_keypair(), error = function(error) NULL)
  if (!is.list(identity) || !identical(names(identity),
                                       c("identity_pk", "identity_sk")) ||
      !is.character(identity$identity_pk) ||
      length(identity$identity_pk) != 1L ||
      !identical(identity$identity_pk, spec$pins[[source]])) {
    .dsvert_formal_glm_registered_source_abort(
      "The local formal-GLM source identity does not match its pinned peer.")
  }
  projected <- .dsvert_formal_glm_registered_source_project(
    source_contract_json, spec, source)
  capacity <- .dsvert_formal_glm_registered_source_authorization(
    projected, spec, source)
  snapshot <- .dsvert_formal_glm_registered_source_snapshot(
    spec, capacity, projected$value$source_contract_sha256,
    projected$value$logical_snapshot_sha256, source_environment)
  context <- new.env(parent = emptyenv())
  context$alignment_consensus <- snapshot$consensus
  context$authorization <- projected$value
  context$authorization_json <- projected$json
  context$contract_json <- source_contract_json
  context$pins <- spec$pins
  context$source_name <- source
  context$rows <- snapshot$rows
  class(context) <- .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_CONTEXT_CLASS
  context
}

.dsvert_formal_glm_registered_source_context <- function(value) {
  fields <- c(
    "alignment_consensus", "authorization", "authorization_json",
    "contract_json", "pins", "rows", "source_name")
  if (!is.environment(value) ||
      !inherits(value, .DSVERT_FORMAL_GLM_REGISTERED_SOURCE_CONTEXT_CLASS) ||
      !identical(sort(ls(value, all.names = TRUE)), sort(fields)) ||
      !is.raw(value$alignment_consensus) ||
      length(value$alignment_consensus) != 32L ||
      !is.list(value$authorization) || !is.list(value$pins) ||
      !is.data.frame(value$rows)) {
    .dsvert_formal_glm_registered_source_abort(
      "The private registered formal-GLM source context is invalid.")
  }
  value
}

.dsvert_formal_glm_registered_source_block_index <- function(value, total) {
  value <- suppressWarnings(as.integer(value))
  if (length(value) != 1L || is.na(value) || value < 0L || value >= total) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM block index is invalid.")
  }
  value
}

.dsvert_formal_glm_registered_source_local_column <- function(
    authorization, source, column) {
  matches <- Filter(function(value) {
    is.list(value) && identical(value$owner, source) &&
      identical(value$column, column)
  }, authorization$local_columns)
  if (length(matches) != 1L) return(NULL)
  matches[[1L]]
}

.dsvert_formal_glm_registered_source_numeric <- function(value) {
  if (is.null(value) || is.factor(value) || is.object(value) ||
      !is.atomic(value) || length(value) != 1L || is.na(value)) return(NULL)
  tryCatch(.dsvert_formal_glm_phase18_rat(value),
           error = function(error) NULL)
}

.dsvert_formal_glm_registered_source_quantize <- function(
    value, lower, upper, fraction_bits) {
  value <- .dsvert_formal_glm_registered_source_numeric(value)
  if (is.null(value) || !is.character(lower) || length(lower) != 1L ||
      !is.character(upper) || length(upper) != 1L) return(NULL)
  tryCatch(.dsvert_formal_glm_phase18_rat_scaled_integer(
    .dsvert_formal_glm_phase18_rat_round(
      .dsvert_formal_glm_phase18_rat_clamp(value, lower, upper),
      fraction_bits), fraction_bits), error = function(error) NULL)
}

.dsvert_formal_glm_registered_source_scale <- function(fraction_bits) {
  bits <- suppressWarnings(as.integer(fraction_bits))
  if (length(bits) != 1L || is.na(bits) || bits < 0L || bits > 256L) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM fraction lattice is invalid.")
  }
  as.character(.dsvert_formal_glm_phase18_bn(2) ^ bits)
}

.dsvert_formal_glm_registered_source_response <- function(
    authorization, source) {
  matches <- Filter(function(value) {
    is.list(value) && identical(value$owner, source) &&
      identical(value$role, "response")
  }, authorization$local_columns)
  if (length(matches) != 1L) return(NULL)
  matches[[1L]]
}

# Converts one private, already-pinned block to canonical signed integer
# coordinates.  Coordinates owned by another custodian, invalid rows and tail
# padding remain exactly zero.  This helper does not encrypt, persist or emit
# the block; the closed Go source command owns those operations.
.dsvert_formal_glm_registered_source_block <- function(context, block_index) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  authorization <- context$authorization
  geometry <- authorization$geometry
  science <- authorization$science
  terms <- science$term_map
  total <- suppressWarnings(as.integer(geometry$total_capacity))
  block_capacity <- suppressWarnings(as.integer(geometry$block_capacity))
  total_blocks <- suppressWarnings(as.integer(geometry$total_blocks))
  coordinates <- suppressWarnings(as.integer(geometry$coordinate_count))
  fraction_bits <- suppressWarnings(as.integer(science$fraction_bits))
  owners <- unlist(geometry$coordinate_owners, use.names = FALSE)
  if (!is.list(terms) || length(total) != 1L || length(block_capacity) != 1L ||
      length(total_blocks) != 1L || length(coordinates) != 1L ||
      length(fraction_bits) != 1L || anyNA(c(
        total, block_capacity, total_blocks, coordinates, fraction_bits)) ||
      total < 1L || block_capacity < 1L || total_blocks !=
        ceiling(total / block_capacity) || coordinates != length(terms) + 3L ||
      !is.character(owners) || length(owners) != coordinates ||
      anyNA(owners) || any(!nzchar(owners))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM block geometry is invalid.")
  }
  block_index <- .dsvert_formal_glm_registered_source_block_index(
    block_index, total_blocks)
  source <- context$source_name
  scale <- .dsvert_formal_glm_registered_source_scale(fraction_bits)
  values <- rep("0", block_capacity * coordinates)
  validity <- rep(FALSE, block_capacity)
  start <- block_index * block_capacity
  raw_column <- function(column, row) {
    if (!is.character(column) || length(column) != 1L ||
        !column %in% names(context$rows)) return(NULL)
    context$rows[[column]][[row]]
  }
  for (physical in seq_len(block_capacity)) {
    global <- start + physical
    if (global > total) next
    row <- rep("0", coordinates)
    valid <- TRUE
    if (identical(owners[[1L]], source)) {
      row[[1L]] <- scale
    }
    for (index in seq_along(terms)) {
      coordinate <- index + 1L
      if (!identical(owners[[coordinate]], source)) next
      term <- terms[[index]]
      if (!is.list(term) || !identical(term$index, index - 1L) ||
          !is.character(term$kind) || length(term$kind) != 1L) {
        valid <- FALSE
      } else if (identical(term$kind, "intercept")) {
        row[[coordinate]] <- scale
      } else {
        column <- .dsvert_formal_glm_registered_source_local_column(
          authorization, source, term$source_column)
        raw <- raw_column(term$source_column, global)
        if (is.null(column)) {
          valid <- FALSE
        } else if (identical(term$kind, "numeric")) {
          value <- .dsvert_formal_glm_registered_source_quantize(
            raw, column$lower_rational, column$upper_rational, fraction_bits)
          if (is.null(value)) valid <- FALSE else row[[coordinate]] <- value
        } else if (identical(term$kind, "factor_level")) {
          label <- if (is.null(raw) || length(raw) != 1L || is.na(raw)) {
            NA_character_
          } else enc2utf8(as.character(raw))
          levels <- unlist(column$levels, use.names = FALSE)
          if (!is.character(levels) || !length(levels) || anyNA(levels) ||
              !identical(term$source_level %in% levels, TRUE) ||
              is.na(label) || !label %in% levels) {
            valid <- FALSE
          } else if (identical(label, term$source_level)) {
            row[[coordinate]] <- scale
          }
        } else valid <- FALSE
      }
    }
    outcome_coordinate <- length(terms) + 2L
    if (identical(owners[[outcome_coordinate]], source)) {
      outcome <- .dsvert_formal_glm_registered_source_response(
        authorization, source)
      raw <- if (is.null(outcome)) NULL else raw_column(outcome$column, global)
      rational <- .dsvert_formal_glm_registered_source_numeric(raw)
      if (is.null(outcome) || is.null(rational)) {
        valid <- FALSE
      } else if (identical(science$family, "binomial")) {
        if (.dsvert_formal_glm_phase18_rat_cmp(rational, "0") == 0L) {
          row[[outcome_coordinate]] <- "0"
        } else if (.dsvert_formal_glm_phase18_rat_cmp(rational, "1") == 0L) {
          row[[outcome_coordinate]] <- scale
        } else valid <- FALSE
      } else if (identical(science$family, "poisson")) {
        rounded <- .dsvert_formal_glm_phase18_rat_round(rational, 0L)
        if (.dsvert_formal_glm_phase18_rat_cmp(rational, rounded) != 0L) {
          valid <- FALSE
        } else {
          clipped <- .dsvert_formal_glm_phase18_rat_clamp(
            rational, outcome$lower_rational, outcome$upper_rational)
          value <- tryCatch(.dsvert_formal_glm_phase18_rat_scaled_integer(
            clipped, fraction_bits), error = function(error) NULL)
          if (is.null(value)) valid <- FALSE else row[[outcome_coordinate]] <- value
        }
      } else valid <- FALSE
    }
    if (!valid) row[] <- "0"
    validity[[physical]] <- valid
    offset <- (physical - 1L) * coordinates
    values[offset + seq_len(coordinates)] <- row
  }
  list(
    values = values, validity = validity,
    private_consensus = gsub(
      "[\r\n]", "", jsonlite::base64_enc(context$alignment_consensus)),
    block_index = block_index, global_slot_offset = start)
}

.dsvert_formal_glm_registered_source_identity <- function(context) {
  identity <- tryCatch(.get_identity_keypair(), error = function(error) NULL)
  if (!is.list(identity) || !identical(names(identity),
                                       c("identity_pk", "identity_sk")) ||
      !is.character(identity$identity_pk) || length(identity$identity_pk) != 1L ||
      !is.character(identity$identity_sk) || length(identity$identity_sk) != 1L ||
      !identical(identity$identity_pk, context$pins[[context$source_name]]) ||
      !identical(context$authorization$local_peer_identity$identity_pk,
                 .dsvert_formal_glm_registered_source_b64url(
                   identity$identity_pk))) {
    .dsvert_formal_glm_registered_source_abort(
      "The local formal-GLM source signer does not match its authorization.")
  }
  identity
}

# The two designated recipients mint their own signed tickets.  This helper
# carries only the registered contract and the local signer to the closed Go
# command; ticket issuance never touches a source block or an R data object.
.dsvert_formal_glm_registered_source_issue_ticket <- function(context) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "ticket", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk)),
    error = function(error) NULL)
  fields <- c("version", "ticket", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.list(response$ticket) || !is.logical(response$replayed) ||
      length(response$replayed) != 1L || is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM ticket issuer returned invalid output.")
  }
  list(ticket = response$ticket, replayed = response$replayed)
}

# Persists the exact two-ticket set before a recipient accepts an encrypted
# source pair.  The Go command canonicalizes, authenticates and binds the set;
# R returns receipts only and never sees an ingress key or plaintext share.
.dsvert_formal_glm_registered_source_persist_ticket_set <- function(
    context, recipient_tickets) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  if (!is.list(recipient_tickets) || length(recipient_tickets) != 2L ||
      !is.null(names(recipient_tickets))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM recipient ticket set is invalid.")
  }
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "ticket_set", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk,
      recipient_tickets = recipient_tickets)),
    error = function(error) NULL)
  fields <- c("version", "ticket_receipts", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.list(response$ticket_receipts) ||
      length(response$ticket_receipts) != 2L ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM ticket-set store returned invalid output.")
  }
  list(ticket_receipts = response$ticket_receipts, replayed = response$replayed)
}

# Seals the source's public K-block commitment after the closed Go outbox has
# confirmed that every block is durable.  The returned JSON is signed routing
# evidence; it contains no plaintext block, validity bit, consensus or key.
.dsvert_formal_glm_registered_source_seal_local_receipt <- function(
    context, recipient_tickets) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  if (!is.list(recipient_tickets) || length(recipient_tickets) != 2L ||
      !is.null(names(recipient_tickets))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM recipient ticket set is invalid.")
  }
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "local_receipt", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk,
      authorization_json = context$authorization_json,
      recipient_tickets = recipient_tickets)),
    error = function(error) NULL)
  fields <- c("version", "local_receipt_json", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.character(response$local_receipt_json) ||
      length(response$local_receipt_json) != 1L ||
      is.na(response$local_receipt_json) ||
      nchar(response$local_receipt_json, type = "bytes") < 2L ||
      nchar(response$local_receipt_json, type = "bytes") > 4L * 1024L^2 ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM local receipt seal returned invalid output.")
  }
  list(local_receipt_json = response$local_receipt_json,
       replayed = response$replayed)
}

# Commits one opaque, source-signed public receipt into the shared Rock-local
# receipt set.  The receipt is validated by Go; R never decodes it or carries
# a source block, ticket, authorization, or consensus value across this seam.
.dsvert_formal_glm_registered_source_commit_local_receipt <- function(
    context, local_receipt_json) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  if (!is.character(local_receipt_json) || length(local_receipt_json) != 1L ||
      is.na(local_receipt_json) ||
      nchar(local_receipt_json, type = "bytes") < 2L ||
      nchar(local_receipt_json, type = "bytes") > 4L * 1024L^2) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM local receipt is invalid.")
  }
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "receipt_commit", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk,
      local_receipt_json = local_receipt_json)), error = function(error) NULL)
  fields <- c("version", "local_receipt_json", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.character(response$local_receipt_json) ||
      length(response$local_receipt_json) != 1L ||
      is.na(response$local_receipt_json) ||
      !identical(response$local_receipt_json, local_receipt_json) ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM receipt store returned invalid output.")
  }
  list(local_receipt_json = response$local_receipt_json,
       replayed = response$replayed)
}

# Seals the canonical set only after Go has verified all required signed local
# receipts.  The result is public routing evidence, not a model result.
.dsvert_formal_glm_registered_source_seal_receipt_set <- function(context) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "receipt_set", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk)), error = function(error) NULL)
  fields <- c("version", "receipt_set_json", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.character(response$receipt_set_json) ||
      length(response$receipt_set_json) != 1L ||
      is.na(response$receipt_set_json) ||
      nchar(response$receipt_set_json, type = "bytes") < 2L ||
      nchar(response$receipt_set_json, type = "bytes") > 4L * 1024L^2 ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM receipt-set seal returned invalid output.")
  }
  list(receipt_set_json = response$receipt_set_json,
       replayed = response$replayed)
}

# Commits the restart-safe Phase19 binding only from the sealed K receipt set
# and the exact two recipient tickets already persisted by the Go ingress.
# This remains an internal peer-control seam; it never exposes ingress keys,
# encrypted blocks, source rows, or a fitted result.
.dsvert_formal_glm_registered_source_commit_binding <- function(
    context, recipient_tickets) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  if (!is.list(recipient_tickets) || length(recipient_tickets) != 2L ||
      !is.null(names(recipient_tickets))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM recipient ticket set is invalid.")
  }
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "binding", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk,
      recipient_tickets = recipient_tickets)), error = function(error) NULL)
  fields <- c("version", "binding_record_json", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.character(response$binding_record_json) ||
      length(response$binding_record_json) != 1L ||
      is.na(response$binding_record_json) ||
      nchar(response$binding_record_json, type = "bytes") < 2L ||
      nchar(response$binding_record_json, type = "bytes") > 16L * 1024L^2 ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM binding store returned invalid output.")
  }
  binding <- list(binding_record_json = response$binding_record_json,
                  replayed = response$replayed)
  # A binding is the first durable point at which the local host has an exact,
  # signed selector.  Make it reachable now; a failed launch is retryable from
  # the same binding and cannot mint another analysis or release.
  .dsvert_formal_glm_registered_source_provision_job_host(context)
  binding
}

# Provisions the local Phase20 host from the binding already sealed in Rock.
# The Go command derives the private bootstrap internally; R receives only the
# public selector receipt and cannot set a host path, key, result, or worker.
.dsvert_formal_glm_registered_source_provision_job_host <- function(context) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "host_provision", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk)), error = function(error) NULL)
  fields <- c("version", "job_host_receipt", "replayed")
  receipt <- if (is.list(response)) response$job_host_receipt else NULL
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM host provisioner returned invalid output.")
  }
  receipt <- .dsvert_formal_glm_registered_source_job_host_receipt(
    receipt, context$source_name)
  if (!identical(response$replayed, receipt$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM host provisioner returned invalid output.")
  }
  .dsvert_formal_glm_registered_source_ensure_job_host(
    list(job_host_receipt = receipt, replayed = response$replayed))
}

# Validates the public selector issued by the Rock-local provisioner.  It is
# deliberately not a capability: the control command reloads and authenticates
# its private bootstrap from Rock.
.dsvert_formal_glm_registered_source_job_host_receipt <- function(receipt,
                                                                  peer = NULL) {
  fields <- c(
    "version", "peer", "artifact_id", "receipt_set_sha256", "config_sha256",
    "replayed", "production_ready")
  if (!is.list(receipt) || !identical(names(receipt), fields) ||
      !identical(receipt$version,
                 "dsvert-formal-glm-registered-phase20-job-host-provision-v1") ||
      !is.character(receipt$peer) || length(receipt$peer) != 1L ||
      (is.character(peer) && length(peer) == 1L && !is.na(peer) &&
       !identical(receipt$peer, peer)) ||
      !is.character(receipt$artifact_id) || length(receipt$artifact_id) != 1L ||
      !grepl("^[0-9a-f]{64}$", receipt$artifact_id) ||
      !is.character(receipt$receipt_set_sha256) ||
      length(receipt$receipt_set_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", receipt$receipt_set_sha256) ||
      !is.character(receipt$config_sha256) || length(receipt$config_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", receipt$config_sha256) ||
      !is.logical(receipt$replayed) || length(receipt$replayed) != 1L ||
      is.na(receipt$replayed) || !identical(receipt$production_ready, FALSE)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM host provisioner returned invalid output.")
  }
  receipt
}

# The short-lived control command proves liveness without mutating the host.
# Keep its request exact so Go can reject non-canonical or widened payloads.
.dsvert_formal_glm_registered_source_job_host_healthy <- function(receipt) {
  receipt <- .dsvert_formal_glm_registered_source_job_host_receipt(receipt)
  response <- tryCatch(.callMpcTool("formal-glm-job-control", list(
    version = "dsvert-formal-glm-registered-phase20-job-control-v1",
    peer = receipt$peer, artifact_id = receipt$artifact_id,
    receipt_set_sha256 = receipt$receipt_set_sha256,
    action = "health", payload = structure(list(), names = character()))),
    error = function(error) NULL)
  is.list(response) && identical(names(response), c("version", "payload")) &&
    identical(response$version,
              "dsvert-formal-glm-registered-phase20-job-control-v1") &&
    identical(response$payload, structure(list(), names = character()))
}

# Starts only a provisioned host selected by its public receipt.  The process
# handle is intentionally discarded: liveness and later control are always
# reattached through the authenticated Rock-derived control channel.
.dsvert_formal_glm_registered_source_launch_job_host <- function(receipt) {
  receipt <- .dsvert_formal_glm_registered_source_job_host_receipt(receipt)
  binary <- tryCatch(.findMpcBinary(), error = function(error) NULL)
  if (!is.character(binary) || length(binary) != 1L || is.na(binary) ||
      !file.exists(binary)) return(FALSE)
  started <- tryCatch({
    processx::process$new(
      binary, c("formal-glm-job-host", receipt$peer, receipt$artifact_id,
                receipt$receipt_set_sha256),
      env = "current", stdout = NULL, stderr = NULL,
      cleanup = FALSE, cleanup_tree = FALSE)
    TRUE
  }, error = function(error) FALSE)
  isTRUE(started)
}

# Ensures one private host is reachable after durable provisioning.  The fixed
# readiness window is transport startup only; it neither expires nor changes
# the canonical analysis or its sticky randomness.
.dsvert_formal_glm_registered_source_ensure_job_host <- function(
    provisioned, .healthy = .dsvert_formal_glm_registered_source_job_host_healthy,
    .launch = .dsvert_formal_glm_registered_source_launch_job_host) {
  if (!is.list(provisioned) || !identical(names(provisioned),
                                          c("job_host_receipt", "replayed")) ||
      !is.logical(provisioned$replayed) || length(provisioned$replayed) != 1L ||
      is.na(provisioned$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM host provisioner returned invalid output.")
  }
  receipt <- .dsvert_formal_glm_registered_source_job_host_receipt(
    provisioned$job_host_receipt)
  if (!identical(provisioned$replayed, receipt$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM host provisioner returned invalid output.")
  }
  if (isTRUE(.healthy(receipt))) return(provisioned)
  if (!isTRUE(.launch(receipt))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM host could not be started.")
  }
  for (attempt in seq_len(100L)) {
    Sys.sleep(0.05)
    if (isTRUE(.healthy(receipt))) return(provisioned)
  }
  .dsvert_formal_glm_registered_source_abort(
    "The registered formal-GLM host did not become available.")
}

# Sends one already materialized local block to the closed Go ingress.  Tickets
# are signed protocol records from the two designated compute peers; this
# bridge does not mint them and cannot select a recipient, source, path or
# protected value supplied by an analyst.
.dsvert_formal_glm_registered_source_produce_block <- function(
    context, recipient_tickets, block_index) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  if (!is.list(recipient_tickets) || length(recipient_tickets) != 2L ||
      !is.null(names(recipient_tickets))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM recipient ticket set is invalid.")
  }
  block <- .dsvert_formal_glm_registered_source_block(context, block_index)
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "produce", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk,
      authorization_json = context$authorization_json,
      recipient_tickets = recipient_tickets, block_index = block$block_index,
      values = block$values, validity = block$validity,
      private_consensus = block$private_consensus)),
    error = function(error) NULL)
  fields <- c("version", "source_receipt", "pair_json", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.list(response$source_receipt) ||
      !is.character(response$pair_json) || length(response$pair_json) != 1L ||
      !nzchar(response$pair_json) || !is.logical(response$replayed) ||
      length(response$replayed) != 1L || is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM source producer returned invalid output.")
  }
  list(source_receipt = response$source_receipt, pair_json = response$pair_json,
       replayed = response$replayed)
}

# Reads one bounded opaque frame from a pair that is already durable in the
# source's Rock outbox.  The frame is transport material only: R never parses
# a pair, derives a source value, or exposes a data-bearing response directly
# to an analyst-facing method.
.dsvert_formal_glm_registered_source_read_block_chunk <- function(
    context, recipient_tickets, block_index, offset) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  if (!is.list(recipient_tickets) || length(recipient_tickets) != 2L ||
      !is.null(names(recipient_tickets))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM recipient ticket set is invalid.")
  }
  if (!is.numeric(block_index) || length(block_index) != 1L ||
      is.na(block_index) || !is.finite(block_index) ||
      block_index != floor(block_index) ||
      !is.numeric(offset) || length(offset) != 1L || is.na(offset) ||
      !is.finite(offset) || offset != floor(offset)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM encrypted-pair chunk selector is invalid.")
  }
  block_index <- suppressWarnings(as.integer(block_index))
  offset <- suppressWarnings(as.integer(offset))
  if (is.na(block_index) || block_index < 0L || is.na(offset) || offset < 0L ||
      offset > 32L * 1024L^2) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM encrypted-pair chunk selector is invalid.")
  }
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "chunk", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk,
      authorization_json = context$authorization_json,
      recipient_tickets = recipient_tickets, block_index = block_index,
      chunk_offset = offset)), error = function(error) NULL)
  fields <- c("version", "chunk_receipt", "pair_chunk_base64", "replayed")
  receipt_fields <- c(
    "version", "purpose", "handle", "artifact_id",
    "source_contract_sha256", "authorization_sha256", "source",
    "block_index", "pair_sha256", "pair_bytes", "offset",
    "chunk_sha256", "chunk_bytes", "complete", "production_ready")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.list(response$chunk_receipt) ||
      !identical(names(response$chunk_receipt), receipt_fields) ||
      !is.character(response$pair_chunk_base64) ||
      length(response$pair_chunk_base64) != 1L ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM source chunk reader returned invalid output.")
  }
  chunk <- tryCatch(jsonlite::base64_dec(response$pair_chunk_base64),
                    error = function(error) raw())
  canonical_chunk <- gsub("[\\r\\n]", "", jsonlite::base64_enc(chunk))
  receipt <- response$chunk_receipt
  expected_offset <- suppressWarnings(as.integer(receipt$offset))
  expected_bytes <- suppressWarnings(as.integer(receipt$chunk_bytes))
  pair_bytes <- suppressWarnings(as.integer(receipt$pair_bytes))
  if (!length(chunk) || length(chunk) > 1024L^2 ||
      !identical(canonical_chunk, response$pair_chunk_base64) ||
      !is.character(receipt$pair_sha256) || length(receipt$pair_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", receipt$pair_sha256) ||
      !is.character(receipt$chunk_sha256) || length(receipt$chunk_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", receipt$chunk_sha256) ||
      length(expected_offset) != 1L || is.na(expected_offset) ||
      !identical(expected_offset, offset) || length(expected_bytes) != 1L ||
      is.na(expected_bytes) || expected_bytes != length(chunk) ||
      length(pair_bytes) != 1L || is.na(pair_bytes) ||
      pair_bytes < expected_offset + expected_bytes || pair_bytes > 16L * 1024L^2 ||
      !is.logical(receipt$complete) || length(receipt$complete) != 1L ||
      is.na(receipt$complete) ||
      !identical(receipt$complete, pair_bytes == expected_offset + expected_bytes) ||
      !is.logical(receipt$production_ready) ||
      length(receipt$production_ready) != 1L || is.na(receipt$production_ready) ||
      isTRUE(receipt$production_ready)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM source chunk reader returned invalid output.")
  }
  list(chunk_receipt = receipt, pair_chunk = chunk, replayed = response$replayed)
}

# Imports one opaque, source-signed encrypted pair at a designated recipient.
# The Go ingress authenticates the pair and binds it to the closed ticket set;
# R deliberately treats the payload as opaque and returns routing evidence
# only.  This is an internal peer-relay seam, never a DataSHIELD endpoint.
.dsvert_formal_glm_registered_source_import_pair <- function(
    context, recipient_tickets, pair_json) {
  context <- .dsvert_formal_glm_registered_source_context(context)
  if (!is.list(recipient_tickets) || length(recipient_tickets) != 2L ||
      !is.null(names(recipient_tickets))) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM recipient ticket set is invalid.")
  }
  if (!is.character(pair_json) || length(pair_json) != 1L || is.na(pair_json) ||
      nchar(pair_json, type = "bytes") < 2L ||
      nchar(pair_json, type = "bytes") > 32L * 1024L^2) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM encrypted pair is invalid.")
  }
  identity <- .dsvert_formal_glm_registered_source_identity(context)
  response <- tryCatch(.callMpcTool(
    "formal-glm-registered-phase18-source", list(
      version = "dsvert-formal-glm-registered-phase18-source-command-v1",
      action = "import", source_contract_json = context$contract_json,
      pins = context$pins, local_peer_name = context$source_name,
      local_signing_key = identity$identity_sk,
      recipient_tickets = recipient_tickets, pair_json = pair_json)),
    error = function(error) NULL)
  fields <- c("version", "pending_receipt", "replayed")
  if (!is.list(response) || !identical(names(response), fields) ||
      !identical(response$version,
                 "dsvert-formal-glm-registered-phase18-source-command-v1") ||
      !is.list(response$pending_receipt) ||
      !is.logical(response$replayed) || length(response$replayed) != 1L ||
      is.na(response$replayed)) {
    .dsvert_formal_glm_registered_source_abort(
      "The registered formal-GLM pair importer returned invalid output.")
  }
  list(pending_receipt = response$pending_receipt, replayed = response$replayed)
}
