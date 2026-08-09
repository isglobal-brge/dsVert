# Internal formal Cox PH capsule contract and central reference.
#
# This file intentionally defines no DataSHIELD entry point.  The historical
# Cox routes are not reused: they expose exact risk-set-derived artifacts and
# do not implement the patient-level DP mechanism specified here.  A sealed
# schema is unanimously signed by the pinned custodians, and every numeric
# privacy bound is recomputed from that schema before any source row is
# materialised.

.DSVERT_FORMAL_COX_SCHEMA_VERSION <- "dsvert-formal-cox-schema-v1"
.DSVERT_FORMAL_COX_SEAL_VERSION <- "dsvert-formal-cox-seal-v1"
.DSVERT_FORMAL_COX_SCHEMA_DOMAIN <- "dsVert/formal-cox/schema/v1|"
.DSVERT_FORMAL_COX_SIGNATURE_DOMAIN <- "dsVert/formal-cox/schema-signature/v1|"
.DSVERT_FORMAL_COX_SENSITIVITY_VERSION <-
  "hung-yu-lemma9-with-left-truncation-extension-v2"
.DSVERT_FORMAL_COX_ALGORITHM <-
  "interactive-projected-noisy-gradient-central-dp-candidate-v1"
.DSVERT_FORMAL_COX_ESTIMAND <-
  "bounded-ridge-grid-breslow-cox-ph-partial-likelihood-v1"
.DSVERT_FORMAL_COX_BLOCKER <- paste(
  "the internal Go exact-GC Cox kernel, finite-support joint Gaussian",
  "sampler, signed provenance adapter and sticky durable opening pass local",
  "K=2/3/4/5 tests and verify the real common-ledger opening tokens, but this",
  "R schema/materializer is not yet executed through recipient-encrypted typed",
  "source fan-in and a real DSI process; the continuous-trajectory/optimizer",
  "error bound and a DP-safe unpenalized identification certificate remain")

.dsvert_formal_cox_abort <- function(message, code = "invalid_formal_cox_contract") {
  stop(structure(
    list(message = message, call = NULL, code = code,
         openings_performed = 0L),
    class = c("dsvert_formal_cox_error", "error", "condition")))
}

.dsvert_formal_cox_hash <- function(domain, value) {
  digest::digest(
    paste0(domain, .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_formal_cox_sha256 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  value
}

.dsvert_formal_cox_label <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z][A-Za-z0-9._:-]{0,127}$", value)) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  enc2utf8(value)
}

.dsvert_formal_cox_integer <- function(value, what, minimum, maximum) {
  value <- suppressWarnings(as.numeric(value))
  if (length(value) != 1L || is.na(value) || !is.finite(value) ||
      value != floor(value) || value < minimum || value > maximum) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  as.numeric(value)
}

.dsvert_formal_cox_l2_norm <- function(value) {
  scale <- max(abs(value))
  if (!is.finite(scale) || scale == 0) return(scale)
  scale * sqrt(sum((value / scale)^2))
}

.dsvert_formal_cox_named <- function(value, what) {
  if (!is.list(value) && !is.atomic(value)) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  if (is.null(names(value)) || anyNA(names(value)) ||
      any(!nzchar(names(value))) || anyDuplicated(names(value))) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  value[order(names(value), method = "radix")]
}

.dsvert_formal_cox_rational <- function(numerator, denominator, what,
                                         zero = FALSE) {
  numerator <- .dsvert_formal_cox_integer(
    numerator, paste0(what, " numerator"), if (zero) 0 else 1, 2^53 - 1)
  denominator <- .dsvert_formal_cox_integer(
    denominator, paste0(what, " denominator"), 1, 2^53 - 1)
  list(numerator = sprintf("%.0f", numerator),
       denominator = sprintf("%.0f", denominator))
}

.dsvert_formal_cox_rational_value <- function(value, what, zero = FALSE) {
  if (!is.list(value) || length(value) != 2L ||
      anyDuplicated(names(value)) || !setequal(names(value),
                                   c("numerator", "denominator"))) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  numerator <- .dsvert_formal_cox_integer(
    value$numerator, paste0(what, " numerator"), if (zero) 0 else 1,
    2^53 - 1)
  denominator <- .dsvert_formal_cox_integer(
    value$denominator, paste0(what, " denominator"), 1, 2^53 - 1)
  numerator / denominator
}

.dsvert_formal_cox_lattice <- function(value, scale, direction, what) {
  if (!is.numeric(value) || !length(value) || anyNA(value) ||
      any(!is.finite(value)) || any(abs(value) > (2^53 - 1) / scale)) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  scaled <- value * scale
  result <- switch(direction,
    lower = floor(scaled), upper = ceiling(scaled), nearest = round(scaled),
    .dsvert_formal_cox_abort("Invalid lattice rounding rule."))
  unname(sprintf("%.0f", result))
}

.dsvert_formal_cox_decode_lattice <- function(value, scale, what) {
  if (!is.character(value) || !length(value) || anyNA(value) ||
      any(!grepl("^-?(0|[1-9][0-9]*)$", value)) || any(value == "-0") ||
      any(nchar(value, type = "bytes") > 32L)) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  decoded <- suppressWarnings(as.numeric(value))
  if (any(!is.finite(decoded)) || any(abs(decoded) > 2^53 - 1) ||
      any(sprintf("%.0f", decoded) != value)) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  decoded / scale
}

.dsvert_formal_cox_pinset <- function(peer_pinset) {
  peer_pinset <- .dsvert_formal_cox_named(peer_pinset, "pinned peer set")
  peer_names <- vapply(names(peer_pinset), function(value) {
    .dsvert_formal_cox_label(value, "pinned peer name")
  }, character(1L))
  names(peer_pinset) <- peer_names
  if (length(peer_pinset) < 2L || length(peer_pinset) > 64L ||
      !all(vapply(peer_pinset, function(value) {
        is.character(value) && length(value) == 1L && !is.na(value)
      }, logical(1L)))) {
    .dsvert_formal_cox_abort("Invalid pinned peer set.")
  }
  pins <- tryCatch(vapply(
    peer_pinset, .dsvert_relay_normalize_identity_pk, character(1L)),
    error = function(error) NULL)
  if (is.null(pins) || anyDuplicated(pins)) {
    .dsvert_formal_cox_abort("Invalid pinned peer identities.")
  }
  as.list(pins[order(names(pins), method = "radix")])
}

.dsvert_formal_cox_compute_peers <- function(pins) {
  peer_ids <- vapply(pins, .dsvert_relay_peer_id, character(1L))
  ordered <- names(sort(peer_ids, method = "radix"))
  ordered[seq_len(2L)]
}

.dsvert_formal_cox_schema_compile <- function(
    artifact_sha256, logical_snapshot_id, peer_pinset,
    outcome_owner, covariate_owners, capacity, time_grid_ticks,
    x_lower, x_upper, covariate_l2_bound, beta_l2_bound,
    minimum_at_risk_per_event,
    iterations = 12L, step_numerator = 1L, step_denominator = 4L,
    ridge_numerator = 0L, ridge_denominator = 100L,
    epsilon_numerator = 2L, epsilon_denominator = 1L,
    delta_numerator = 1L, delta_denominator = 1000000L,
    adjacency = c("add_remove_patient", "replace_one_patient"),
    entry_mode = c("none", "single_interval"), frac_bits = 30L) {
  adjacency <- match.arg(adjacency)
  entry_mode <- match.arg(entry_mode)
  pins <- .dsvert_formal_cox_pinset(peer_pinset)
  owners <- names(pins)
  outcome_owner <- .dsvert_formal_cox_label(
    outcome_owner, "outcome owner")
  if (!outcome_owner %in% owners) {
    .dsvert_formal_cox_abort("The outcome owner is not pinned.")
  }
  covariate_owners <- .dsvert_formal_cox_named(
    as.list(covariate_owners), "covariate ownership")
  covariate_names <- vapply(names(covariate_owners), function(value) {
    .dsvert_formal_cox_label(value, "Cox covariate name")
  }, character(1L))
  names(covariate_owners) <- covariate_names
  if (!length(covariate_owners) || length(covariate_owners) > 64L ||
      !all(vapply(covariate_owners, function(value) {
        is.character(value) && length(value) == 1L && !is.na(value) &&
          value %in% owners
      }, logical(1L)))) {
    .dsvert_formal_cox_abort("Every covariate needs one pinned owner.")
  }
  if ("(Intercept)" %in% names(covariate_owners)) {
    .dsvert_formal_cox_abort("Cox PH has no intercept coefficient.")
  }
  p <- length(covariate_owners)
  if (!is.numeric(x_lower) || !is.numeric(x_upper) ||
      is.null(names(x_lower)) || is.null(names(x_upper)) ||
      !setequal(names(x_lower), names(covariate_owners)) ||
      !setequal(names(x_upper), names(covariate_owners))) {
    .dsvert_formal_cox_abort("Covariate bounds do not match ownership.")
  }
  x_lower <- x_lower[names(covariate_owners)]
  x_upper <- x_upper[names(covariate_owners)]
  if (anyNA(x_lower) || anyNA(x_upper) || any(!is.finite(x_lower)) ||
      any(!is.finite(x_upper)) || any(x_lower >= x_upper)) {
    .dsvert_formal_cox_abort("Invalid covariate bounds.")
  }
  capacity <- .dsvert_formal_cox_integer(
    capacity, "public patient capacity", 2, 1000000)
  frac_bits <- .dsvert_formal_cox_integer(
    frac_bits, "fixed-point precision", 8, 40)
  scale <- 2^frac_bits
  iterations <- .dsvert_formal_cox_integer(
    iterations, "iteration count", 1, 256)
  minimum_at_risk_per_event <- .dsvert_formal_cox_integer(
    minimum_at_risk_per_event, "minimum at-risk count per event tick",
    1, capacity)
  if (!is.numeric(time_grid_ticks) || length(time_grid_ticks) < 2L ||
      length(time_grid_ticks) > 4096L || anyNA(time_grid_ticks) ||
      any(!is.finite(time_grid_ticks)) ||
      any(time_grid_ticks != floor(time_grid_ticks)) ||
      any(abs(time_grid_ticks) > 2^53 - 1) ||
      any(diff(time_grid_ticks) <= 0)) {
    .dsvert_formal_cox_abort("The public Cox time grid is invalid.")
  }
  if (!is.numeric(covariate_l2_bound) ||
      length(covariate_l2_bound) != 1L || is.na(covariate_l2_bound) ||
      !is.finite(covariate_l2_bound) || covariate_l2_bound <= 0 ||
      !is.numeric(beta_l2_bound) || length(beta_l2_bound) != 1L ||
      is.na(beta_l2_bound) || !is.finite(beta_l2_bound) ||
      beta_l2_bound <= 0) {
    .dsvert_formal_cox_abort("Invalid Cox L2 bounds.")
  }
  coordinate_max <- sqrt(sum(pmax(abs(x_lower), abs(x_upper))^2))
  if (covariate_l2_bound > coordinate_max * (1 + 1e-12)) {
    # A looser norm bound is valid, but accepting arbitrary inflation makes
    # accidental loss of utility too easy.  The exact coordinate envelope is
    # already public, so cap to it server-side.
    covariate_l2_bound <- coordinate_max
  }
  if (covariate_l2_bound + 1e-12 <
      min(sqrt(sum(pmin(abs(x_lower), abs(x_upper))^2)), coordinate_max) &&
      all(x_lower * x_upper > 0)) {
    .dsvert_formal_cox_abort("The L2 bound excludes the covariate box.")
  }
  x_lower_lattice <- .dsvert_formal_cox_lattice(
    x_lower, scale, "lower", "covariate lower bounds")
  x_upper_lattice <- .dsvert_formal_cox_lattice(
    x_upper, scale, "upper", "covariate upper bounds")
  names(x_lower_lattice) <- names(x_upper_lattice) <- NULL
  unsigned <- list(
    version = .DSVERT_FORMAL_COX_SCHEMA_VERSION,
    artifact_sha256 = .dsvert_formal_cox_sha256(
      artifact_sha256, "formal Cox artifact hash"),
    logical_snapshot_id = .dsvert_formal_cox_label(
      logical_snapshot_id, "formal Cox logical snapshot id"),
    peer_pinset = pins,
    peer_pinset_sha256 = .dsvert_formal_cox_hash(
      "dsVert/formal-cox/pinset/v1|", pins),
    compute_peers = as.list(.dsvert_formal_cox_compute_peers(pins)),
    outcome_owner = outcome_owner,
    covariate_owners = covariate_owners,
    estimand = .DSVERT_FORMAL_COX_ESTIMAND,
    response = if (identical(entry_mode, "none")) {
      "Surv(stop,status)"
    } else "Surv(entry,stop,status)",
    entry_mode = entry_mode,
    ties = "breslow",
    grid_semantics =
      "ex_ante_public_exact_ticks_no_runtime_snapping_ties_induced_by_grid_v1",
    strata = "single_public_baseline_stratum_only_v1",
    case_weights = "unsupported_unit_weight_only_v1",
    time_dependent_covariates = "unsupported_v1",
    recurrent_events = "unsupported_one_record_one_event_per_patient_v1",
    privacy_unit = "one_patient_one_fixed_capacity_slot_v1",
    adjacency = adjacency,
    adjacency_interpretation =
      "fixed_capacity_replace_one_triple_zero_slot_models_add_remove_v1",
    capacity = sprintf("%.0f", capacity),
    minimum_at_risk_per_event = sprintf(
      "%.0f", minimum_at_risk_per_event),
    time_grid_ticks = as.list(sprintf("%.0f", time_grid_ticks)),
    frac_bits = sprintf("%.0f", frac_bits),
    x_lower_lattice = as.list(stats::setNames(
      x_lower_lattice, names(covariate_owners))),
    x_upper_lattice = as.list(stats::setNames(
      x_upper_lattice, names(covariate_owners))),
    covariate_l2_bound_lattice = .dsvert_formal_cox_lattice(
      covariate_l2_bound, scale, "upper", "covariate L2 bound")[[1L]],
    beta_l2_bound_lattice = .dsvert_formal_cox_lattice(
      beta_l2_bound, scale, "upper", "coefficient L2 bound")[[1L]],
    iterations = sprintf("%.0f", iterations),
    step_size = .dsvert_formal_cox_rational(
      step_numerator, step_denominator, "step size"),
    ridge = .dsvert_formal_cox_rational(
      ridge_numerator, ridge_denominator, "ridge", zero = TRUE),
    epsilon = .dsvert_formal_cox_rational(
      epsilon_numerator, epsilon_denominator, "epsilon"),
    delta = .dsvert_formal_cox_rational(
      delta_numerator, delta_denominator, "delta"),
    algorithm = .DSVERT_FORMAL_COX_ALGORITHM,
    sensitivity_theorem = .DSVERT_FORMAL_COX_SENSITIVITY_VERSION,
    reduction_order = "grid_then_capacity_slot_then_covariate_v1",
    source_layout = "all_sources_same_fixed_ring128_layout_v1",
    alignment = "recipient_shared_exact_gc_consensus_and_mask_required_v3",
    opening = "one_final_sticky_dp_beta_vector_only_v1",
    exact_outputs_forbidden = as.list(c(
      "score", "hessian", "risk_sets", "event_counts", "loglik",
      "baseline_hazard", "row_validity", "alignment_digest")))
  .dsvert_dp_canonical_query_value(unsigned)
}

.dsvert_formal_cox_schema_message <- function(unsigned) {
  charToRaw(paste0(
    .DSVERT_FORMAL_COX_SIGNATURE_DOMAIN,
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_formal_cox_signature_decode <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9_-]{86}$", value)) return(NULL)
  tryCatch(jsonlite::base64_dec(.base64url_to_base64(value)),
           error = function(error) NULL)
}

.dsvert_formal_cox_schema_seal <- function(unsigned, signatures) {
  required <- c(
    "version", "artifact_sha256", "logical_snapshot_id", "peer_pinset",
    "peer_pinset_sha256", "compute_peers", "outcome_owner",
    "covariate_owners", "estimand", "response", "entry_mode", "ties",
    "grid_semantics", "strata", "case_weights", "time_dependent_covariates",
    "recurrent_events", "privacy_unit", "adjacency",
    "adjacency_interpretation", "capacity",
    "minimum_at_risk_per_event", "time_grid_ticks", "frac_bits", "x_lower_lattice",
    "x_upper_lattice", "covariate_l2_bound_lattice",
    "beta_l2_bound_lattice", "iterations", "step_size", "ridge",
    "epsilon", "delta", "algorithm", "sensitivity_theorem",
    "reduction_order", "source_layout", "alignment", "opening",
    "exact_outputs_forbidden")
  if (!is.list(unsigned) || length(unsigned) != length(required) ||
      anyDuplicated(names(unsigned)) ||
      !setequal(names(unsigned), required) ||
      !identical(unsigned$version, .DSVERT_FORMAL_COX_SCHEMA_VERSION)) {
    .dsvert_formal_cox_abort("Invalid unsigned formal Cox schema.")
  }
  pins <- .dsvert_formal_cox_pinset(unsigned$peer_pinset)
  signatures <- .dsvert_formal_cox_named(signatures, "Cox schema signatures")
  if (!setequal(names(signatures), names(pins))) {
    .dsvert_formal_cox_abort(
      "Every pinned custodian must sign the formal Cox schema.",
      "incomplete_formal_cox_approval")
  }
  message <- .dsvert_formal_cox_schema_message(unsigned)
  valid <- vapply(names(pins), function(peer) {
    signature <- .dsvert_formal_cox_signature_decode(signatures[[peer]])
    public <- tryCatch(openssl::read_ed25519_pubkey(
      jsonlite::base64_dec(.base64url_to_base64(pins[[peer]]))),
      error = function(error) NULL)
    is.raw(signature) && length(signature) == 64L && !is.null(public) &&
      isTRUE(tryCatch(openssl::ed25519_verify(message, signature, public),
                      error = function(error) FALSE))
  }, logical(1L))
  if (!all(valid)) {
    .dsvert_formal_cox_abort(
      "A pinned custodian signature on the formal Cox schema is invalid.",
      "invalid_formal_cox_approval")
  }
  signatures <- as.list(vapply(
    signatures[names(pins)], enc2utf8, character(1L)))
  signed <- list(
    version = .DSVERT_FORMAL_COX_SEAL_VERSION,
    unsigned = .dsvert_dp_canonical_query_value(unsigned),
    signatures = signatures)
  signed$schema_sha256 <- .dsvert_formal_cox_hash(
    .DSVERT_FORMAL_COX_SCHEMA_DOMAIN, signed)
  signed
}

.dsvert_formal_cox_schema_validate <- function(schema) {
  if (!is.list(schema) || length(schema) != 4L ||
      anyDuplicated(names(schema)) || !setequal(names(schema),
                                    c("version", "unsigned", "signatures",
                                      "schema_sha256")) ||
      !identical(schema$version, .DSVERT_FORMAL_COX_SEAL_VERSION) ||
      !identical(schema$schema_sha256,
        .dsvert_formal_cox_hash(.DSVERT_FORMAL_COX_SCHEMA_DOMAIN,
          schema[c("version", "unsigned", "signatures")]))) {
    .dsvert_formal_cox_abort(
      "The signed formal Cox schema was modified.",
      "tampered_formal_cox_schema")
  }
  resealed <- .dsvert_formal_cox_schema_seal(
    schema$unsigned, schema$signatures)
  if (!identical(resealed, schema)) {
    .dsvert_formal_cox_abort(
      "The formal Cox schema is not canonical.",
      "noncanonical_formal_cox_schema")
  }
  value <- schema$unsigned
  pins <- .dsvert_formal_cox_pinset(value$peer_pinset)
  expected_compute <- .dsvert_formal_cox_compute_peers(pins)
  compute <- unlist(value$compute_peers, use.names = FALSE)
  owners <- unlist(value$covariate_owners, use.names = FALSE)
  constants_valid <-
    identical(value$estimand, .DSVERT_FORMAL_COX_ESTIMAND) &&
    value$response %in% c("Surv(stop,status)", "Surv(entry,stop,status)") &&
    value$entry_mode %in% c("none", "single_interval") &&
    identical(value$response, if (value$entry_mode == "none") {
      "Surv(stop,status)"
    } else "Surv(entry,stop,status)") &&
    identical(value$ties, "breslow") &&
    identical(value$grid_semantics,
      "ex_ante_public_exact_ticks_no_runtime_snapping_ties_induced_by_grid_v1") &&
    identical(value$strata, "single_public_baseline_stratum_only_v1") &&
    identical(value$case_weights, "unsupported_unit_weight_only_v1") &&
    identical(value$time_dependent_covariates, "unsupported_v1") &&
    identical(value$recurrent_events,
      "unsupported_one_record_one_event_per_patient_v1") &&
    identical(value$privacy_unit,
      "one_patient_one_fixed_capacity_slot_v1") &&
    value$adjacency %in% c("add_remove_patient", "replace_one_patient") &&
    identical(value$adjacency_interpretation,
      "fixed_capacity_replace_one_triple_zero_slot_models_add_remove_v1") &&
    identical(value$algorithm, .DSVERT_FORMAL_COX_ALGORITHM) &&
    identical(value$sensitivity_theorem,
      .DSVERT_FORMAL_COX_SENSITIVITY_VERSION) &&
    identical(value$reduction_order,
      "grid_then_capacity_slot_then_covariate_v1") &&
    identical(value$source_layout,
      "all_sources_same_fixed_ring128_layout_v1") &&
    identical(value$alignment,
      "recipient_shared_exact_gc_consensus_and_mask_required_v3") &&
    identical(value$opening, "one_final_sticky_dp_beta_vector_only_v1")
  logical_snapshot_valid <- tryCatch({
    .dsvert_formal_cox_label(
      value$logical_snapshot_id, "formal Cox logical snapshot id")
    TRUE
  }, error = function(error) FALSE)
  artifact_valid <- tryCatch({
    .dsvert_formal_cox_sha256(
      value$artifact_sha256, "formal Cox artifact hash")
    TRUE
  }, error = function(error) FALSE)
  covariate_names_valid <- tryCatch({
    covariate_names <- names(value$covariate_owners)
    identical(unname(vapply(covariate_names, function(name) {
      .dsvert_formal_cox_label(name, "Cox covariate name")
    }, character(1L))), covariate_names)
  }, error = function(error) FALSE)
  if (!constants_valid || !logical_snapshot_valid || !artifact_valid ||
      !covariate_names_valid ||
      !identical(compute, expected_compute) ||
      !value$outcome_owner %in% names(pins) || !length(owners) ||
      any(!owners %in% names(pins)) ||
      !identical(value$peer_pinset_sha256,
        .dsvert_formal_cox_hash("dsVert/formal-cox/pinset/v1|", pins)) ||
      !identical(unlist(value$exact_outputs_forbidden, use.names = FALSE),
        c("score", "hessian", "risk_sets", "event_counts", "loglik",
          "baseline_hazard", "row_validity", "alignment_digest"))) {
    .dsvert_formal_cox_abort(
      "The signed formal Cox schema has an unsupported scientific contract.",
      "unsupported_formal_cox_contract")
  }
  invisible(schema)
}

.dsvert_formal_cox_schema_numeric <- function(schema) {
  .dsvert_formal_cox_schema_validate(schema)
  value <- schema$unsigned
  frac_bits <- .dsvert_formal_cox_integer(
    value$frac_bits, "fixed-point precision", 8, 40)
  scale <- 2^frac_bits
  covariates <- names(value$covariate_owners)
  if (is.null(covariates) || anyDuplicated(covariates) ||
      !identical(names(value$x_lower_lattice), covariates) ||
      !identical(names(value$x_upper_lattice), covariates)) {
    .dsvert_formal_cox_abort("The signed Cox covariate layout is invalid.")
  }
  lower <- .dsvert_formal_cox_decode_lattice(
    unlist(value$x_lower_lattice, use.names = FALSE), scale,
    "covariate lower bounds")
  upper <- .dsvert_formal_cox_decode_lattice(
    unlist(value$x_upper_lattice, use.names = FALSE), scale,
    "covariate upper bounds")
  names(lower) <- names(upper) <- covariates
  grid_raw <- unlist(value$time_grid_ticks, use.names = FALSE)
  if (!is.character(grid_raw) || length(grid_raw) < 2L ||
      length(grid_raw) > 4096L || anyNA(grid_raw) ||
      any(!grepl("^-?(0|[1-9][0-9]*)$", grid_raw)) ||
      any(grid_raw == "-0")) {
    .dsvert_formal_cox_abort("The signed Cox grid is invalid.")
  }
  grid <- suppressWarnings(as.numeric(grid_raw))
  if (any(!is.finite(grid)) || any(abs(grid) > 2^53 - 1) ||
      any(sprintf("%.0f", grid) != grid_raw) || any(diff(grid) <= 0)) {
    .dsvert_formal_cox_abort("The signed Cox grid is invalid.")
  }
  result <- list(
    capacity = .dsvert_formal_cox_integer(
      value$capacity, "public patient capacity", 2, 1000000),
    minimum_at_risk_per_event = .dsvert_formal_cox_integer(
      value$minimum_at_risk_per_event,
      "minimum at-risk count per event tick", 1,
      .dsvert_formal_cox_integer(
        value$capacity, "public patient capacity", 2, 1000000)),
    frac_bits = frac_bits, scale = scale,
    grid = grid,
    lower = lower, upper = upper,
    covariate_l2_bound = .dsvert_formal_cox_decode_lattice(
      value$covariate_l2_bound_lattice, scale, "covariate L2 bound"),
    beta_l2_bound = .dsvert_formal_cox_decode_lattice(
      value$beta_l2_bound_lattice, scale, "coefficient L2 bound"),
    iterations = .dsvert_formal_cox_integer(
      value$iterations, "iteration count", 1, 256),
    step = .dsvert_formal_cox_rational_value(value$step_size, "step size"),
    ridge = .dsvert_formal_cox_rational_value(value$ridge, "ridge", zero = TRUE),
    epsilon = .dsvert_formal_cox_rational_value(value$epsilon, "epsilon"),
    delta = .dsvert_formal_cox_rational_value(value$delta, "delta"))
  if (any(lower >= upper) || result$covariate_l2_bound <= 0 ||
      result$beta_l2_bound <= 0 || result$step <= 0 || result$ridge < 0 ||
      result$epsilon <= 0 || result$delta <= 0 || result$delta >= 1) {
    .dsvert_formal_cox_abort(
      "The signed Cox numeric contract is invalid.",
      "unbounded_formal_cox_sensitivity")
  }
  result
}

.dsvert_formal_cox_sensitivity_plan <- function(schema) {
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  n <- numeric$capacity
  cz <- numeric$covariate_l2_bound
  cb <- numeric$beta_l2_bound
  if (numeric$delta <= 0 || numeric$delta >= 1 ||
      numeric$epsilon <= 0 || !is.finite(exp(2 * cz * cb))) {
    .dsvert_formal_cox_abort(
      "The signed Cox privacy parameters have no finite sensitivity plan.",
      "unbounded_formal_cox_sensitivity")
  }
  # Hung--Yu Lemma 9 uses fixed-n replace-one adjacency for one complete
  # (T, Delta, Z(.)) triple.  Our public-capacity add/remove model replaces a
  # canonical zero slot with one patient triple, so it is the same neighbour
  # relation, not a second composition of add/remove operations.
  # Its harmonic log(N+1) step assumes the ordinary at-risk process.  With
  # left truncation, risk sets can grow after entry; the universal one-event-
  # per-patient bound sum(d_g/r_g) <= N is used instead.  The signed risk floor
  # is deliberately not used to make this privacy bound smaller.
  reciprocal_risk_sum_bound <- if (schema$unsigned$entry_mode == "none") {
    log(n + 1)
  } else {
    n
  }
  sensitivity <- 4 * cz / n +
    exp(2 * cz * cb) * (2 * cz + cz^2) *
      reciprocal_risk_sum_bound / n
  # This is the interactive RDP calibration used by the primary reference
  # implementation accompanying Hung and Yu.  It is deliberately labelled a
  # candidate until the discrete sampler and exact circuit match it bit for bit.
  sigma <- sensitivity * sqrt(
    numeric$iterations / numeric$epsilon *
      (2 * log(1 / numeric$delta) / numeric$epsilon + 1))
  if (!is.finite(sensitivity) || sensitivity <= 0 ||
      !is.finite(sigma) || sigma <= 0) {
    .dsvert_formal_cox_abort(
      "The signed Cox privacy parameters overflow their noise calibration.",
      "unbounded_formal_cox_sensitivity")
  }
  max_eta <- numeric$covariate_l2_bound * numeric$beta_l2_bound
  max_weight <- exp(max_eta)
  deterministic_update_bound <- numeric$beta_l2_bound + numeric$step *
    (2 * numeric$covariate_l2_bound +
       numeric$ridge * numeric$beta_l2_bound)
  deterministic_max_intermediate <- max(
    n, n * max_weight,
    n * max_weight * max(1, numeric$covariate_l2_bound),
    n * max_weight * max(1, numeric$covariate_l2_bound^2),
    n * max_weight^2 * max(1, numeric$covariate_l2_bound),
    n * max_weight^2 * max(1, numeric$covariate_l2_bound^2),
    numeric$beta_l2_bound, deterministic_update_bound)
  if (!is.finite(deterministic_max_intermediate)) {
    .dsvert_formal_cox_abort(
      "The signed Cox deterministic arithmetic bound overflowed.",
      "formal_cox_deterministic_bound_exceeds_ring4096")
  }
  deterministic_required_bits <-
    ceiling(log2(deterministic_max_intermediate + 1)) +
    2 * numeric$frac_bits + 3L
  if (!is.finite(deterministic_required_bits)) {
    .dsvert_formal_cox_abort(
      "The signed Cox deterministic numeric range is not finite.",
      "unbounded_formal_cox_sensitivity")
  }
  if (deterministic_required_bits > 4096L) {
    .dsvert_formal_cox_abort(
      "The signed Cox deterministic bound exceeds Ring4096.",
      "formal_cox_deterministic_bound_exceeds_ring4096")
  }
  deterministic_backend <- if (deterministic_required_bits <= 126L) {
    "exact_gc_ring128"
  } else {
    ring_bits <- min(4096L, max(128L,
      64L * ceiling(deterministic_required_bits / 64L)))
    paste0("exact_gc_dynamic_ring_", ring_bits)
  }
  list(
    version = "dsvert-formal-cox-sensitivity-plan-v1",
    schema_sha256 = schema$schema_sha256,
    source = .DSVERT_FORMAL_COX_SENSITIVITY_VERSION,
    source_formula = if (schema$unsigned$entry_mode == "none") {
      "4*Cz/N + exp(2*Cz*Cbeta)*(2*Cz+Cz^2)*log(N+1)/N"
    } else {
      "4*Cz/N + exp(2*Cz*Cbeta)*(2*Cz+Cz^2)"
    },
    reciprocal_risk_sum_upper_bound = reciprocal_risk_sum_bound,
    left_truncation_sensitivity = if (schema$unsigned$entry_mode == "none") {
      "not_applicable_hung_yu_lemma9_v1"
    } else {
      "conservative_sum_d_over_r_at_most_N_extension_v1"
    },
    patient_adjacency = schema$unsigned$adjacency,
    normalized_score_l2_sensitivity = sensitivity,
    iterations = numeric$iterations,
    gaussian_sigma_per_internal_iteration = sigma,
    max_linear_predictor_abs = max_eta,
    exp_weight_interval = c(exp(-max_eta), max_weight),
    deterministic_required_bits = deterministic_required_bits,
    deterministic_bound_scope = paste(
      "pre-truncation exact risk-moment, reciprocal-product, ridge and",
      "projected-update envelope; nonlinear circuit schedule still required"),
    deterministic_numeric_backend = deterministic_backend,
    input_materialization_backend = "exact_ring128",
    input_ring128_no_wrap_certificate = TRUE,
    deterministic_iteration_no_wrap_certificate = FALSE,
    exp_input_interval = c(-max_eta, max_eta),
    exp_approximation_max_abs_error =
      "unavailable_until_exact_gc_nonlinear_contract_v1",
    reciprocal_approximation_max_abs_error =
      "unavailable_until_exact_gc_nonlinear_contract_v1",
    final_numeric_error_certificate = FALSE,
    dp_noise_support = "unbounded_integer_support_v1",
    noise_numeric_backend =
      "exact_dynamic_multiprecision_lift_required_v1",
    numeric_backend =
      "deterministic_fast_ring_plus_dynamic_noise_lift_candidate_v1",
    fixed_ring_full_no_wrap_certificate = FALSE,
    truncation = "exact_signed_truncation_inside_gc_required_v1",
    sensitivity_client_override_accepted = FALSE,
    exact_patient_artifact_openings = 0L,
    final_openings_planned = 1L,
    production_ready = FALSE,
    blocker = .DSVERT_FORMAL_COX_BLOCKER)
}

.dsvert_formal_cox_rows_validate <- function(schema, rows) {
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  required <- c("valid", "entry_index", "stop_index", "status",
                names(schema$unsigned$covariate_owners))
  if (!is.data.frame(rows) || length(rows) != length(required) ||
      anyDuplicated(names(rows)) || !setequal(names(rows), required) ||
      nrow(rows) != numeric$capacity) {
    .dsvert_formal_cox_abort("Invalid fixed-shape Cox reference rows.")
  }
  rows <- rows[, required, drop = FALSE]
  if (!is.logical(rows$valid) || anyNA(rows$valid) ||
      !is.numeric(rows$entry_index) || anyNA(rows$entry_index) ||
      !is.numeric(rows$stop_index) || anyNA(rows$stop_index) ||
      any(rows$entry_index != floor(rows$entry_index)) ||
      any(rows$stop_index != floor(rows$stop_index)) ||
      any(rows$entry_index < 0) || any(rows$entry_index >= length(numeric$grid)) ||
      any(rows$stop_index < 1) || any(rows$stop_index > length(numeric$grid)) ||
      !is.numeric(rows$status) || anyNA(rows$status) ||
      any(!rows$status %in% c(0, 1))) {
    .dsvert_formal_cox_abort("Invalid Cox response rows.")
  }
  x <- as.matrix(rows[, names(schema$unsigned$covariate_owners), drop = FALSE])
  storage.mode(x) <- "double"
  if (anyNA(x) || any(!is.finite(x))) {
    .dsvert_formal_cox_abort("Invalid Cox covariate rows.")
  }
  valid <- rows$valid & rows$entry_index < rows$stop_index
  within_box <- rowSums(sweep(x, 2L, numeric$lower, `<`)) == 0 &
    rowSums(sweep(x, 2L, numeric$upper, `>`)) == 0
  within_l2 <- sqrt(rowSums(x^2)) <=
    numeric$covariate_l2_bound + 8 * .Machine$double.eps
  # Protected invalidity is mapped to the canonical zero-weight slot.  A
  # caller must not expose which row failed this deterministic clipping gate.
  valid <- valid & within_box & within_l2
  rows$valid <- valid
  rows$status[!valid] <- 0
  rows$entry_index[!valid] <- 0
  rows$stop_index[!valid] <- 1
  x[!valid, ] <- 0
  rows[, names(schema$unsigned$covariate_owners)] <- x
  rows
}

.dsvert_formal_cox_oracle_at <- function(schema, rows, beta) {
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  rows <- .dsvert_formal_cox_rows_validate(schema, rows)
  p <- length(schema$unsigned$covariate_owners)
  if (!is.numeric(beta) || length(beta) != p || anyNA(beta) ||
      any(!is.finite(beta)) ||
      .dsvert_formal_cox_l2_norm(beta) >
        numeric$beta_l2_bound + 1e-10) {
    .dsvert_formal_cox_abort("The Cox reference coefficient is out of bounds.")
  }
  x <- as.matrix(rows[, names(schema$unsigned$covariate_owners), drop = FALSE])
  eta <- drop(x %*% beta)
  loglik <- 0
  score <- numeric(p)
  information <- matrix(0, p, p)
  risk_count <- event_count <- integer(length(numeric$grid))
  for (g in seq_along(numeric$grid)) {
    risk <- rows$valid & rows$entry_index < g & rows$stop_index >= g
    event <- rows$valid & rows$status == 1 & rows$stop_index == g
    d <- sum(event)
    risk_count[[g]] <- sum(risk)
    event_count[[g]] <- d
    if (!d) next
    if (sum(risk) < numeric$minimum_at_risk_per_event) {
      .dsvert_formal_cox_abort(
        "An event violates the signed Cox at-risk floor.",
        "non_identifiable_formal_cox")
    }
    center <- max(eta[risk])
    weight <- exp(eta[risk] - center)
    xrisk <- x[risk, , drop = FALSE]
    s0 <- sum(weight)
    mean_x <- colSums(xrisk * weight) / s0
    second <- crossprod(xrisk, xrisk * weight) / s0
    event_x <- colSums(x[event, , drop = FALSE])
    loglik <- loglik + sum(eta[event]) - d * (center + log(s0))
    score <- score + event_x - d * mean_x
    information <- information + d * (second - tcrossprod(mean_x))
  }
  penalized_loglik <- loglik - numeric$capacity * numeric$ridge * sum(beta^2) / 2
  penalized_score <- score - numeric$capacity * numeric$ridge * beta
  penalized_information <- information +
    diag(numeric$capacity * numeric$ridge, p)
  structure(list(
    beta = unname(beta), log_partial_likelihood = loglik,
    score = unname(score), observed_information = unname(information),
    penalized_log_partial_likelihood = penalized_loglik,
    penalized_score = unname(penalized_score),
    penalized_information = unname(penalized_information),
    risk_count = risk_count, event_count = event_count,
    internal_only = TRUE, opened = FALSE,
    ties = "breslow", estimand = schema$unsigned$estimand),
    class = "dsvert_formal_cox_central_oracle")
}

.dsvert_formal_cox_oracle_fit <- function(schema, rows, tolerance = 1e-10,
                                           max_iterations = 200L) {
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  rows <- .dsvert_formal_cox_rows_validate(schema, rows)
  p <- length(schema$unsigned$covariate_owners)
  objective <- function(beta) {
    norm <- .dsvert_formal_cox_l2_norm(beta)
    if (norm > numeric$beta_l2_bound) {
      excess <- norm - numeric$beta_l2_bound
      return(.Machine$double.xmax^0.25 + excess^2)
    }
    -.dsvert_formal_cox_oracle_at(
      schema, rows, beta)$penalized_log_partial_likelihood
  }
  gradient <- function(beta) {
    norm <- .dsvert_formal_cox_l2_norm(beta)
    if (norm > numeric$beta_l2_bound) {
      return(beta / norm * (1 + norm - numeric$beta_l2_bound))
    }
    -.dsvert_formal_cox_oracle_at(schema, rows, beta)$penalized_score
  }
  fit <- stats::optim(
    rep(0, p), objective, gradient, method = "BFGS",
    control = list(reltol = tolerance, maxit = as.integer(max_iterations)))
  if (!identical(fit$convergence, 0L) || anyNA(fit$par) ||
      any(!is.finite(fit$par)) || !is.finite(fit$value)) {
    .dsvert_formal_cox_abort(
      "The central Cox validation oracle did not converge.",
      "nonconverged_formal_cox_oracle")
  }
  beta <- fit$par
  norm <- .dsvert_formal_cox_l2_norm(beta)
  if (norm > numeric$beta_l2_bound) {
    beta <- beta * numeric$beta_l2_bound / norm
  }
  at <- .dsvert_formal_cox_oracle_at(schema, rows, beta)
  curvature <- eigen(
    (at$penalized_information + t(at$penalized_information)) /
      (2 * numeric$capacity), symmetric = TRUE, only.values = TRUE)$values
  curvature_tolerance <- max(1e-10, sqrt(.Machine$double.eps) *
    max(1, max(abs(curvature))))
  if (!length(curvature) || min(curvature) <= curvature_tolerance) {
    .dsvert_formal_cox_abort(
      "The bounded grid-Breslow Cox target is not identifiable.",
      "non_identifiable_formal_cox")
  }
  list(
    coefficients = stats::setNames(beta, names(schema$unsigned$covariate_owners)),
    convergence = fit$convergence,
    penalized_score_l2 = .dsvert_formal_cox_l2_norm(at$penalized_score),
    boundary = .dsvert_formal_cox_l2_norm(beta) >=
      numeric$beta_l2_bound * (1 - 1e-8),
    identification = "internal_penalized_curvature_only_not_released_v1",
    minimum_penalized_curvature = min(curvature),
    oracle = at, internal_only = TRUE, opened = FALSE,
    production_ready = FALSE)
}

.dsvert_formal_cox_private_reference <- function(schema, rows, noise) {
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  plan <- .dsvert_formal_cox_sensitivity_plan(schema)
  rows <- .dsvert_formal_cox_rows_validate(schema, rows)
  p <- length(schema$unsigned$covariate_owners)
  if (!is.matrix(noise) || !identical(dim(noise),
                                      c(as.integer(numeric$iterations), p)) ||
      anyNA(noise) || any(!is.finite(noise))) {
    .dsvert_formal_cox_abort(
      "The internal Cox noise matrix has the wrong fixed shape.")
  }
  beta <- numeric(p)
  for (iteration in seq_len(numeric$iterations)) {
    at <- .dsvert_formal_cox_oracle_at(schema, rows, beta)
    step <- at$score / numeric$capacity - numeric$ridge * beta +
      plan$gaussian_sigma_per_internal_iteration * noise[iteration, ]
    beta <- beta + numeric$step * step
    if (any(!is.finite(step)) || any(!is.finite(beta))) {
      .dsvert_formal_cox_abort(
        "The internal Cox validation update exceeded its numeric range.",
        "formal_cox_reference_numeric_overflow")
    }
    norm <- .dsvert_formal_cox_l2_norm(beta)
    if (norm > numeric$beta_l2_bound) {
      beta <- beta * numeric$beta_l2_bound / norm
    }
  }
  # Validation-only central oracle: production must supply these noise values
  # through the joint exact-GC sampler and persist only the final vector.
  list(
    coefficients = stats::setNames(beta, names(schema$unsigned$covariate_owners)),
    mechanism = .DSVERT_FORMAL_COX_ALGORITHM,
    planned_final_openings = 1L, performed_openings = 0L,
    exact_intermediates_returned = FALSE,
    noise_source = "caller_supplied_validation_only_not_production_rng",
    production_ready = FALSE, blocker = .DSVERT_FORMAL_COX_BLOCKER)
}
