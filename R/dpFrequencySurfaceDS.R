# Public, purpose-bound server surface for stateless sticky Frequency.

.DSVERT_DP_FREQUENCY_CLAIM_MAX_BYTES <- 32L * 1024L^2
.DSVERT_DP_FREQUENCY_CONFIG_MAX_BYTES <- 32L * 1024L^2
.DSVERT_DP_FREQUENCY_RECEIPTS_MAX_BYTES <- 32L * 1024L^2
.DSVERT_DP_FREQUENCY_AUTHORIZATIONS_MAX_BYTES <- 1024L * 1024L

.dsvert_dp_frequency_surface_json_v1 <- function(
    value, what, maximum_bytes) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes) {
    stop("Invalid Frequency ", what, ".", call. = FALSE)
  }
  parsed <- tryCatch(
    jsonlite::fromJSON(value, simplifyVector = FALSE),
    error = function(error) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_analysis_canonical_value_v1(parsed)),
    error = function(error) NULL)
  if (is.null(parsed) || is.null(canonical) ||
      !identical(canonical, value)) {
    stop("Invalid or non-canonical Frequency ", what, ".", call. = FALSE)
  }
  parsed
}

.dsvert_dp_frequency_surface_decode_v1 <- function(
    value, what, maximum_bytes) {
  decoded <- .dsvert_dsi_text_decode(value, what, maximum_bytes)
  .dsvert_dp_frequency_surface_json_v1(decoded, what, maximum_bytes)
}

.dsvert_dp_frequency_surface_config_v1 <- function(value) {
  config <- .dsvert_dp_frequency_surface_decode_v1(
    value, "configuration", .DSVERT_DP_FREQUENCY_CONFIG_MAX_BYTES)
  pins <- config$peer_pins
  if (!is.list(pins) || !length(pins) || is.null(names(pins)) ||
      anyNA(names(pins)) || anyDuplicated(names(pins)) ||
      any(!vapply(pins, function(pin) {
        is.character(pin) && length(pin) == 1L && !is.na(pin)
      }, logical(1L)))) {
    stop("Invalid Frequency configuration.", call. = FALSE)
  }
  config$peer_pins <- unlist(pins, use.names = TRUE)
  .dsvert_dp_frequency_config_validate_v1(config)
}

.dsvert_dp_frequency_surface_array_v1 <- function(
    value, what, maximum_bytes, length = NULL) {
  parsed <- .dsvert_dp_frequency_surface_decode_v1(
    value, what, maximum_bytes)
  valid <- is.list(parsed) && is.null(names(parsed)) &&
    all(vapply(parsed, is.list, logical(1L)))
  if (!is.null(length)) valid <- valid && identical(base::length(parsed), length)
  if (!isTRUE(valid)) {
    stop("Invalid Frequency ", what, ".", call. = FALSE)
  }
  parsed
}

.dsvert_dp_frequency_surface_claim_v1 <- function(value) {
  .dsvert_dp_frequency_surface_decode_v1(
    value, "source Claim", .DSVERT_DP_FREQUENCY_CLAIM_MAX_BYTES)
}

.dsvert_dp_frequency_surface_option_v1 <- function(name, default = NULL) {
  value <- getOption(paste0("dsvert.dp.frequency.", name))
  if (is.null(value)) {
    value <- getOption(paste0("default.dsvert.dp.frequency.", name))
  }
  if (is.null(value)) default else value
}

.dsvert_dp_frequency_surface_pins_v1 <- function(peer_name, identity_pk) {
  peer_name <- .dsvert_dp_frequency_peer_name_v1(peer_name)
  identity_pk <- .dsvert_dp_frequency_identity_pk_v1(
    identity_pk, "local peer identity")
  trusted <- .get_trusted_peers()
  if ((!is.character(trusted) && !is.list(trusted)) ||
      is.null(names(trusted)) ||
      anyNA(names(trusted)) || anyDuplicated(names(trusted)) ||
      peer_name %in% names(trusted)) {
    stop("Invalid Frequency peer pins.", call. = FALSE)
  }
  trusted_count <- length(trusted)
  trusted <- tryCatch(vapply(
    trusted, .dsvert_dp_frequency_identity_pk_v1, character(1L),
    what = "peer identity"), error = function(error) character())
  if (length(trusted) != trusted_count) {
    stop("Invalid Frequency peer pins.", call. = FALSE)
  }
  .dsvert_dp_frequency_peer_pins_v1(c(
    stats::setNames(identity_pk, peer_name), trusted))
}

.dsvert_dp_frequency_surface_context_v1 <- function() {
  identity <- .get_identity_keypair()
  identity$identity_pk <- .dsvert_dp_frequency_identity_pk_v1(
    identity$identity_pk, "local peer identity")
  peer_name <- .dsvert_require_configured_local_peer_name()
  pins <- .dsvert_dp_frequency_surface_pins_v1(
    peer_name, identity$identity_pk)
  owner <- .dsvert_dp_frequency_surface_option_v1("source_owner")
  if (is.null(owner)) {
    stop("The Frequency source owner is unavailable or ambiguous.",
         call. = FALSE)
  }
  settings <- .dsvert_dp_frequency_settings_v1(list(
    domain = .dsvert_dp_frequency_surface_option_v1("domain", ""),
    cohort_id = .dsvert_dp_frequency_surface_option_v1("cohort_id", ""),
    source_owner = owner,
    coordinate_upper_bound =
      .dsvert_dp_frequency_surface_option_v1(
        "coordinate_upper_bound", getOption(
          "dsvert.psi.max_input_ids",
          getOption("default.dsvert.psi.max_input_ids", 1000000L))),
    privacy = list(
      adjacency = .dsvert_dp_frequency_surface_option_v1(
        "adjacency", "add_remove_patient"),
      epsilon = .dsvert_dp_frequency_surface_option_v1("epsilon", 1),
      delta = .dsvert_dp_frequency_surface_option_v1("delta", 1e-6)),
    calibration = list(
      implementation_delta = .dsvert_dp_frequency_surface_option_v1(
        "implementation_delta", 1e-9))))
  if (!settings$source_owner$peer_name %in% names(pins) ||
      !identical(settings$source_owner$identity_pk,
                 unname(pins[[settings$source_owner$peer_name]]))) {
    stop("The Frequency source owner is unavailable or ambiguous.",
         call. = FALSE)
  }
  list(peer_name = peer_name, identity = identity,
       peer_pins = pins, settings = settings)
}

#' Execute one stateless sticky Frequency lifecycle
#'
#' These endpoints compile one signed fixed-domain categorical analysis across
#' the pinned consortium. Only the server-selected source and secondary noise
#' authorities create execution state. Inputs ending in \code{_json} are
#' canonical JSON protected by the package DSI text frame.
#' @details Custodians must configure
#'   \code{dsvert.dp.frequency.source_owner} as exactly one
#'   \code{list(peer_name, identity_pk)} on every peer. Domain, cohort, bound,
#'   adjacency and privacy calibration use the corresponding
#'   \code{dsvert.dp.frequency.*} server options. They are never accepted from
#'   the analyst call.
#'
#' @param data_name Name of an already padded-PSI aligned data frame.
#' @param variable_name Public factor-registry variable name.
#' @param source_claim_json Signed source Claim.
#' @param config_json Compiled Frequency configuration.
#' @param receipts_json Canonical array with one signed receipt per peer.
#' @param session_id Authenticated MPC session identifier.
#' @param operation_id Frequency operation identifier.
#' @param window_index Zero-based fixed-window index.
#' @param public_authorizations_json Canonical two-role authorization array.
#' @return A bounded lifecycle record. Cryptographic phases include their
#'   signed evidence.
#' @name dsvertDPFrequencyLifecycleDS
NULL

#' @rdname dsvertDPFrequencyLifecycleDS
#' @export
dsvertDPFrequencyClaimDS <- function(data_name, variable_name) {
  data_name <- .psi_padded_data_name(data_name)
  context <- .dsvert_dp_frequency_surface_context_v1()
  if (!identical(context$peer_name,
                 context$settings$source_owner$peer_name) ||
      !identical(context$identity$identity_pk,
                 context$settings$source_owner$identity_pk)) {
    stop("Only the configured Frequency source owner may issue its Claim.",
         call. = FALSE)
  }
  data <- get(data_name, envir = parent.frame(), inherits = TRUE)
  .dsvert_dp_frequency_claim_v1(
    data, variable_name, context$peer_name, context$identity,
    context$peer_pins)
}

#' @rdname dsvertDPFrequencyLifecycleDS
#' @export
dsvertDPFrequencyCompileDS <- function(data_name, source_claim_json) {
  data_name <- .psi_padded_data_name(data_name)
  claim <- .dsvert_dp_frequency_surface_claim_v1(source_claim_json)
  context <- .dsvert_dp_frequency_surface_context_v1()
  source_envir <- parent.frame()
  .dsvert_dp_frequency_local_compile_v1(
    claim, context$peer_name, context$peer_pins, context$settings,
    .source_resolver = function() get(
      data_name, envir = source_envir, inherits = TRUE))
}

#' @rdname dsvertDPFrequencyLifecycleDS
#' @export
dsvertDPFrequencyAuthorizeDS <- function(
    config_json, receipts_json, source_claim_json, session_id) {
  config <- .dsvert_dp_frequency_surface_config_v1(config_json)
  receipts <- .dsvert_dp_frequency_surface_array_v1(
    receipts_json, "receipt array", .DSVERT_DP_FREQUENCY_RECEIPTS_MAX_BYTES,
    length = length(config$peer_pins))
  claim <- .dsvert_dp_frequency_surface_claim_v1(source_claim_json)
  .dsvert_dp_frequency_public_authorization_v1(
    .S(session_id), session_id, config, receipts, claim)
}

#' @rdname dsvertDPFrequencyLifecycleDS
#' @export
dsvertDPFrequencySourceWindowDS <- function(
    data_name, session_id, operation_id, window_index,
    public_authorizations_json, source_claim_json) {
  data_name <- .psi_padded_data_name(data_name)
  authorizations <- .dsvert_dp_frequency_surface_array_v1(
    public_authorizations_json, "public authorization array",
    .DSVERT_DP_FREQUENCY_AUTHORIZATIONS_MAX_BYTES, length = 2L)
  claim <- .dsvert_dp_frequency_surface_claim_v1(source_claim_json)
  source_envir <- parent.frame()
  .dsvert_dp_frequency_execution_source_window_v1(
    .S(session_id), session_id, operation_id, window_index,
    authorizations, claim, .source_resolver = function() get(
      data_name, envir = source_envir, inherits = TRUE))
}

#' @rdname dsvertDPFrequencyLifecycleDS
#' @export
dsvertDPFrequencyFinalizeWindowDS <- function(
    session_id, operation_id, window_index, public_authorizations_json) {
  authorizations <- .dsvert_dp_frequency_surface_array_v1(
    public_authorizations_json, "public authorization array",
    .DSVERT_DP_FREQUENCY_AUTHORIZATIONS_MAX_BYTES, length = 2L)
  .dsvert_dp_frequency_execution_finalize_window_v1(
    .S(session_id), session_id, operation_id, window_index, authorizations)
}

#' @rdname dsvertDPFrequencyLifecycleDS
#' @export
dsvertDPFrequencyReplayDS <- function(
    session_id, operation_id, window_index) {
  .dsvert_dp_frequency_execution_replay_window_v1(
    .S(session_id), session_id, operation_id, window_index)
}

#' @rdname dsvertDPFrequencyLifecycleDS
#' @export
dsvertDPFrequencyCleanupDS <- function(session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  storage <- .session_storage()
  ss <- storage[[session_id]]
  if (is.null(ss)) {
    return(list(cleaned = TRUE, state = "already_cleaned"))
  }
  .dsvert_dp_frequency_session_authorization_validate_v1(
    ss, session_id)
  .cleanup_session(session_id)
  list(cleaned = TRUE, state = "cleaned")
}
