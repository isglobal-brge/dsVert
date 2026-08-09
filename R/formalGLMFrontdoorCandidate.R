# Internal server-owned candidate contract for the formal GLM frontdoor.
#
# This file intentionally defines no *DS function and is absent from
# AggregateMethods.  It validates the only public selectors a future endpoint
# may receive, binds them to immutable custodian configuration and emits a
# signed, redacted blocker receipt.  It does not materialise rows, start a
# relay, invoke Phase-1.9 or authorize an opening.

.DSVERT_FORMAL_GLM_FRONTDOOR_SPEC_VERSION <-
  "dsvert-formal-glm-frontdoor-spec-v1"
.DSVERT_FORMAL_GLM_FRONTDOOR_RECEIPT_VERSION <-
  "dsvert-formal-glm-frontdoor-blocked-receipt-v1"
.DSVERT_FORMAL_GLM_FRONTDOOR_RECEIPT_DOMAIN <-
  "dsVert/formal-glm/frontdoor-blocked-receipt/v1|"
.DSVERT_FORMAL_GLM_FRONTDOOR_RELEASE_DOMAIN <-
  "dsVert/formal-glm/phase16/release-adapter/v1"
.DSVERT_FORMAL_GLM_FRONTDOOR_EXECUTION_PATH <-
  "phase18_v2_to_phase19_full_durable_to_phase15_to_joint_dp_one_draw_v1"
.DSVERT_FORMAL_GLM_FRONTDOOR_ASSET_VERSION <-
  "dsvert-formal-glm-frontdoor-execution-assets-v1"
.DSVERT_FORMAL_GLM_FRONTDOOR_BLOCKER <-
  "formal_glm_phase19_durable_r_dsi_release_bridge_not_promoted"

.dsvert_formal_glm_frontdoor_abort <- function(
    message = "The requested formal GLM analysis is unavailable.",
    code = "formal_glm_analysis_unavailable") {
  stop(structure(list(
    message = message, call = NULL, code = code,
    openings_performed = 0L, production_ready = FALSE),
    class = c("dsvert_formal_glm_frontdoor_error", "error", "condition")))
}

.dsvert_formal_glm_frontdoor_label <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)) {
    .dsvert_formal_glm_frontdoor_abort(
      paste0("Invalid formal GLM ", what, "."),
      "invalid_formal_glm_selector")
  }
  enc2utf8(value)
}

.dsvert_formal_glm_frontdoor_sha256 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    .dsvert_formal_glm_frontdoor_abort(
      paste0("Invalid formal GLM ", what, "."),
      "invalid_formal_glm_registry")
  }
  value
}

.dsvert_formal_glm_frontdoor_formula <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > 4096L) {
    .dsvert_formal_glm_frontdoor_abort(
      "Invalid formal GLM registry formula.",
      "invalid_formal_glm_registry")
  }
  formula <- tryCatch(stats::as.formula(value, env = baseenv()),
                      error = function(error) NULL)
  if (is.null(formula) || length(formula) != 3L ||
      !is.symbol(formula[[2L]]) ||
      "." %in% all.names(formula[[3L]], functions = FALSE)) {
    .dsvert_formal_glm_frontdoor_abort(
      "Invalid formal GLM registry formula.",
      "invalid_formal_glm_registry")
  }
  terms <- tryCatch(stats::terms(formula), error = function(error) NULL)
  labels <- if (is.null(terms)) NULL else attr(terms, "term.labels")
  orders <- if (is.null(terms)) NULL else attr(terms, "order")
  plain <- if (is.null(labels)) FALSE else vapply(labels, function(label) {
    expression <- tryCatch(parse(text = label, keep.source = FALSE),
                           error = function(error) NULL)
    length(expression) == 1L && is.symbol(expression[[1L]]) &&
      identical(as.character(expression[[1L]]), label) &&
      grepl("^[A-Za-z][A-Za-z0-9_.]{0,127}$", label)
  }, logical(1L))
  response <- as.character(formula[[2L]])
  if (is.null(terms) ||
      !grepl("^[A-Za-z][A-Za-z0-9_.]{0,127}$", response) ||
      any(!plain) || any(orders != 1L) || anyDuplicated(labels)) {
    .dsvert_formal_glm_frontdoor_abort(
      "Invalid formal GLM registry formula.",
      "invalid_formal_glm_registry")
  }
  predictors <- sort(enc2utf8(labels), method = "radix")
  intercept <- identical(as.integer(attr(terms, "intercept")), 1L)
  canonical <- paste(
    enc2utf8(response), "~",
    paste(c(if (intercept) "1" else "0", predictors), collapse = " + "))
  list(
    canonical = canonical,
    sha256 = digest::digest(
      paste0("dsVert/formal-glm/frontdoor-formula/v1|", canonical),
      algo = "sha256", serialize = FALSE))
}

.dsvert_formal_glm_frontdoor_spec <- function(
    analysis_id, specs = .dsvert_dp_option("formal_glm_specs", list())) {
  analysis_id <- .dsvert_formal_glm_frontdoor_label(
    analysis_id, "analysis id")
  if (!is.list(specs) || is.null(names(specs)) || anyNA(names(specs)) ||
      any(!nzchar(names(specs))) || anyDuplicated(names(specs))) {
    .dsvert_formal_glm_frontdoor_abort(
      "The custodian formal GLM registry is invalid.",
      "invalid_formal_glm_registry")
  }
  raw <- specs[[analysis_id]]
  if (is.null(raw)) {
    # Do not let this internal candidate become an analysis-id discovery
    # oracle.  A syntactically valid unknown id is indistinguishable from a
    # selector mismatch against a registered analysis.
    .dsvert_formal_glm_frontdoor_abort()
  }
  required <- c(
    "version", "analysis_id", "data_name", "family", "formula",
    "schema_sha256", "artifact_sha256", "phase15_plan_sha256",
    "capsule_id", "logical_snapshot_sha256", "release_binding_domain",
    "execution_path", "registry_generation")
  if (!is.list(raw) || is.null(names(raw)) || anyNA(names(raw)) ||
      anyDuplicated(names(raw)) || !setequal(names(raw), required) ||
      !identical(raw$version, .DSVERT_FORMAL_GLM_FRONTDOOR_SPEC_VERSION) ||
      !identical(raw$analysis_id, analysis_id) ||
      !is.character(raw$family) || length(raw$family) != 1L ||
      !raw$family %in% c("binomial", "poisson") ||
      !identical(raw$release_binding_domain,
                 .DSVERT_FORMAL_GLM_FRONTDOOR_RELEASE_DOMAIN) ||
      !identical(raw$execution_path,
                 .DSVERT_FORMAL_GLM_FRONTDOOR_EXECUTION_PATH) ||
      !is.numeric(raw$registry_generation) ||
      length(raw$registry_generation) != 1L ||
      is.na(raw$registry_generation) || !is.finite(raw$registry_generation) ||
      raw$registry_generation < 1 ||
      raw$registry_generation != floor(raw$registry_generation)) {
    .dsvert_formal_glm_frontdoor_abort(
      "The requested formal GLM analysis is unavailable.",
      "invalid_formal_glm_registry")
  }
  raw$data_name <- .dsvert_formal_glm_frontdoor_label(
    raw$data_name, "data name")
  formula <- .dsvert_formal_glm_frontdoor_formula(raw$formula)
  for (field in c(
      "schema_sha256", "artifact_sha256", "phase15_plan_sha256",
      "capsule_id", "logical_snapshot_sha256")) {
    raw[[field]] <- .dsvert_formal_glm_frontdoor_sha256(raw[[field]], field)
  }
  raw$formula <- formula$canonical
  raw$formula_sha256 <- formula$sha256
  raw$registry_generation <- as.numeric(raw$registry_generation)
  raw
}

.dsvert_formal_glm_frontdoor_policy <- function(policy) {
  # Reuse the production joint-DP validator.  In particular, do not trust a
  # caller-supplied digest: the helper normalises every Ed25519 pin, derives
  # the canonical full pinset hash and checks it against policy.  A frontdoor
  # receipt may be signed by any custodian, hence require_designated = FALSE;
  # the two compute/noise peers themselves remain server-selected and bound.
  context <- tryCatch(
    .dsvert_joint_dp_policy_context(policy, require_designated = FALSE),
    error = function(error) NULL)
  if (is.null(context) || !is.list(context$common)) {
    .dsvert_formal_glm_frontdoor_abort(
      "The pinned formal GLM policy is unavailable.",
      "invalid_pinned_consortium")
  }
  pins <- unlist(context$common$ordered_peer_pinset, use.names = TRUE)
  designated <- unlist(
    context$common$designated_noise_peers, use.names = FALSE)
  if (is.null(names(pins)) || length(pins) < 2L ||
      length(designated) != 2L || anyDuplicated(designated) ||
      !all(designated %in% names(pins))) {
    .dsvert_formal_glm_frontdoor_abort(
      "The pinned formal GLM policy is unavailable.",
      "invalid_pinned_consortium")
  }
  list(
    peer_name = context$peer_name,
    custodian_peers = sort(names(pins), method = "radix"),
    designated_peers = sort(unname(designated), method = "radix"),
    pinset_sha256 = context$common$peer_pinset_sha256)
}

.dsvert_formal_glm_frontdoor_run_id <- function(spec, context) {
  digest::digest(
    paste0(
      "dsVert/formal-glm/frontdoor-run/v1|",
      .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(list(
        version = spec$version, analysis_id = spec$analysis_id,
        registry_generation = spec$registry_generation,
        data_name = spec$data_name, family = spec$family,
        formula_sha256 = spec$formula_sha256,
        schema_sha256 = spec$schema_sha256,
        artifact_sha256 = spec$artifact_sha256,
        capsule_id = spec$capsule_id,
        logical_snapshot_sha256 = spec$logical_snapshot_sha256,
        release_binding_domain = spec$release_binding_domain,
        execution_path = spec$execution_path,
        pinset_sha256 = context$pinset_sha256,
        custodian_peers = as.list(context$custodian_peers),
        designated_compute_peers = as.list(context$designated_peers))))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_formal_glm_frontdoor_execution_assets <- function(
    analysis_id,
    assets = .dsvert_dp_option("formal_glm_execution_assets", list())) {
  analysis_id <- .dsvert_formal_glm_frontdoor_label(
    analysis_id, "analysis id")
  if (!is.list(assets) || is.null(names(assets)) || anyNA(names(assets)) ||
      any(!nzchar(names(assets))) || anyDuplicated(names(assets))) {
    .dsvert_formal_glm_frontdoor_abort(
      "The custodian formal GLM execution registry is invalid.",
      "invalid_formal_glm_registry")
  }
  value <- assets[[analysis_id]]
  fields <- c(
    "version", "analysis_id", "manifest_json", "artifact_json",
    "plan_json", "plan_approvals")
  if (is.null(value)) .dsvert_formal_glm_frontdoor_abort()
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(value$version,
                 .DSVERT_FORMAL_GLM_FRONTDOOR_ASSET_VERSION) ||
      !identical(value$analysis_id, analysis_id) ||
      !is.character(value$manifest_json) ||
      length(value$manifest_json) != 1L || is.na(value$manifest_json) ||
      !is.character(value$artifact_json) ||
      length(value$artifact_json) != 1L || is.na(value$artifact_json) ||
      !is.character(value$plan_json) ||
      length(value$plan_json) != 1L || is.na(value$plan_json) ||
      !is.list(value$plan_approvals)) {
    .dsvert_formal_glm_frontdoor_abort(
      "The custodian formal GLM execution registry is invalid.",
      "invalid_formal_glm_registry")
  }
  for (field in c("manifest_json", "artifact_json", "plan_json")) {
    bytes <- nchar(value[[field]], type = "bytes")
    if (!nzchar(value[[field]]) || bytes > 32L * 1024L^2) {
      .dsvert_formal_glm_frontdoor_abort(
        "The custodian formal GLM execution registry is invalid.",
        "invalid_formal_glm_registry")
    }
  }
  value
}

.dsvert_formal_glm_frontdoor_authorize_phase18_candidate <- function(
    analysis_id, data_name, family, formula_sha256,
    .policy = NULL, .specs = NULL, .assets = NULL, .secret = NULL,
    .verifier = .dsvert_relay_verify_message,
    .authorize = .dsvert_formal_glm_phase18_pre_authorize) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.specs)) {
    .specs <- .dsvert_dp_option("formal_glm_specs", list())
  }
  if (is.null(.assets)) {
    .assets <- .dsvert_dp_option("formal_glm_execution_assets", list())
  }
  spec <- .dsvert_formal_glm_frontdoor_spec(analysis_id, .specs)
  context <- .dsvert_formal_glm_frontdoor_policy(.policy)
  data_name <- .dsvert_formal_glm_frontdoor_label(data_name, "data selector")
  formula_sha256 <- .dsvert_formal_glm_frontdoor_sha256(
    formula_sha256, "formula selector")
  if (!is.character(family) || length(family) != 1L || is.na(family) ||
      !family %in% c("binomial", "poisson") ||
      !identical(data_name, spec$data_name) ||
      !identical(family, spec$family) ||
      !identical(formula_sha256, spec$formula_sha256)) {
    .dsvert_formal_glm_frontdoor_abort()
  }
  assets <- .dsvert_formal_glm_frontdoor_execution_assets(
    analysis_id, .assets)
  if (!is.function(.authorize)) {
    .dsvert_formal_glm_frontdoor_abort(
      "The formal GLM Phase-1.8 authorizer is unavailable.",
      "formal_glm_phase18_authorizer_unavailable")
  }
  authorization <- .authorize(
    manifest_json = assets$manifest_json,
    artifact_json = assets$artifact_json,
    plan_json = assets$plan_json,
    plan_approvals = assets$plan_approvals,
    .policy = .policy, .secret = .secret, .verifier = .verifier)
  expected_run_id <- .dsvert_formal_glm_frontdoor_run_id(spec, context)
  pre <- authorization$pre
  artifact_formula <- tryCatch(
    authorization$artifact$estimand$formula,
    error = function(error) NULL)
  valid <- inherits(
    authorization, "dsvert_formal_glm_phase18_pre_authorization") &&
    is.list(pre) &&
    identical(pre$artifact_sha256, spec$artifact_sha256) &&
    identical(pre$plan_sha256, spec$phase15_plan_sha256) &&
    identical(pre$schema_manifest_sha256, spec$schema_sha256) &&
    identical(pre$capsule_id, spec$capsule_id) &&
    identical(pre$snapshot_sha256, spec$logical_snapshot_sha256) &&
    identical(pre$family, spec$family) &&
    identical(pre$run_id, expected_run_id) &&
    identical(artifact_formula, spec$formula) &&
    identical(pre$pinset_sha256, context$pinset_sha256) &&
    identical(
      unlist(pre$custodian_peers, use.names = FALSE),
      context$custodian_peers) &&
    identical(
      unlist(pre$designated_compute_peers, use.names = FALSE),
      context$designated_peers) &&
    identical(as.numeric(pre$custodian_count),
              as.numeric(length(context$custodian_peers))) &&
    identical(as.numeric(pre$openings_performed), 0) &&
    identical(pre$production_ready, FALSE)
  if (!isTRUE(valid)) {
    .dsvert_formal_glm_frontdoor_abort(
      "The formal GLM registry differs from its Phase-1.8 authorization.",
      "formal_glm_registry_phase18_mismatch")
  }
  structure(list(
    analysis_id = spec$analysis_id,
    registry_generation = spec$registry_generation,
    expected_run_id = expected_run_id,
    authorization = authorization,
    openings_performed = 0L, production_ready = FALSE),
    class = "dsvert_formal_glm_frontdoor_phase18_authorization")
}

.dsvert_formal_glm_frontdoor_message <- function(unsigned) {
  charToRaw(paste0(
    .DSVERT_FORMAL_GLM_FRONTDOOR_RECEIPT_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_formal_glm_frontdoor_sign <- function(
    unsigned, policy, signer = NULL) {
  context <- .dsvert_formal_glm_frontdoor_policy(policy)
  message <- .dsvert_formal_glm_frontdoor_message(unsigned)
  signature <- if (is.null(signer)) {
    identity <- .get_identity_keypair()
    expected <- unname(policy$peer_pinset[[context$peer_name]])
    if (!identical(
        .dsvert_relay_normalize_identity_pk(identity$identity_pk),
        .dsvert_relay_normalize_identity_pk(expected))) {
      .dsvert_formal_glm_frontdoor_abort(
        "The runtime identity differs from the pinned formal GLM policy.",
        "runtime_identity_mismatch")
    }
    .dsvert_relay_sign_message(message, identity$identity_sk)
  } else {
    if (!is.function(signer)) {
      .dsvert_formal_glm_frontdoor_abort(
        "Invalid formal GLM receipt signer.",
        "runtime_identity_mismatch")
    }
    signer(message, context$peer_name,
           unname(policy$peer_pinset[[context$peer_name]]))
  }
  if (!is.character(signature) || length(signature) != 1L ||
      is.na(signature) || !grepl("^[A-Za-z0-9_-]{86}$", signature)) {
    .dsvert_formal_glm_frontdoor_abort(
      "Invalid formal GLM receipt signature.",
      "runtime_identity_mismatch")
  }
  c(unsigned, list(signature = signature))
}

.dsvert_formal_glm_frontdoor_prepare_candidate <- function(
    analysis_id, data_name, family, formula_sha256,
    .policy = NULL, .specs = NULL, .signer = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  if (is.null(.specs)) {
    .specs <- .dsvert_dp_option("formal_glm_specs", list())
  }
  spec <- .dsvert_formal_glm_frontdoor_spec(analysis_id, .specs)
  context <- .dsvert_formal_glm_frontdoor_policy(.policy)
  data_name <- .dsvert_formal_glm_frontdoor_label(data_name, "data selector")
  formula_sha256 <- .dsvert_formal_glm_frontdoor_sha256(
    formula_sha256, "formula selector")
  if (!is.character(family) || length(family) != 1L || is.na(family) ||
      !family %in% c("binomial", "poisson") ||
      !identical(data_name, spec$data_name) ||
      !identical(family, spec$family) ||
      !identical(formula_sha256, spec$formula_sha256)) {
    # Keep missing-id and mismatched-selector failures indistinguishable: the
    # candidate must not become a registry-discovery endpoint.
    .dsvert_formal_glm_frontdoor_abort()
  }
  expected_run_id <- .dsvert_formal_glm_frontdoor_run_id(spec, context)
  registry_binding <- .dsvert_dp_canonical_query_value(list(
    version = spec$version, analysis_id = spec$analysis_id,
    data_name = spec$data_name, family = spec$family,
    formula_sha256 = spec$formula_sha256,
    schema_sha256 = spec$schema_sha256,
    artifact_sha256 = spec$artifact_sha256,
    phase15_plan_sha256 = spec$phase15_plan_sha256,
    capsule_id = spec$capsule_id,
    logical_snapshot_sha256 = spec$logical_snapshot_sha256,
    release_binding_domain = spec$release_binding_domain,
    execution_path = spec$execution_path,
    registry_generation = spec$registry_generation,
    expected_run_id = expected_run_id,
    pinset_sha256 = context$pinset_sha256,
    custodian_peers = as.list(context$custodian_peers),
    designated_compute_peers = as.list(context$designated_peers)))
  registry_sha256 <- digest::digest(
    paste0("dsVert/formal-glm/frontdoor-registry-binding/v1|",
           .dsvert_dp_canonical_json(registry_binding)),
    algo = "sha256", serialize = FALSE)
  unsigned <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_FORMAL_GLM_FRONTDOOR_RECEIPT_VERSION,
    phase = "blocked_before_dsi_until_complete_release_bridge",
    purpose = paste0("formal-glm/frontdoor/", registry_sha256),
    analysis_id = spec$analysis_id, data_name = spec$data_name,
    family = spec$family, formula_sha256 = spec$formula_sha256,
    expected_run_id = expected_run_id,
    registry_binding_sha256 = registry_sha256,
    schema_sha256 = spec$schema_sha256,
    artifact_sha256 = spec$artifact_sha256,
    phase15_plan_sha256 = spec$phase15_plan_sha256,
    capsule_id = spec$capsule_id,
    logical_snapshot_sha256 = spec$logical_snapshot_sha256,
    release_binding_domain = spec$release_binding_domain,
    execution_path = spec$execution_path,
    peer_name = context$peer_name,
    pinset_sha256 = context$pinset_sha256,
    custodian_count = length(context$custodian_peers),
    designated_compute_peers = as.list(context$designated_peers),
    server_owned_analysis = TRUE,
    analyst_epsilon_accepted = FALSE,
    analyst_bounds_accepted = FALSE,
    analyst_seed_accepted = FALSE,
    analyst_roles_accepted = FALSE,
    operation_limit = FALSE, request_limit = FALSE,
    history_can_deny_operation = FALSE,
    phase19_worker_started = FALSE, relay_started = FALSE,
    opening_authorized = FALSE, openings_performed = 0L,
    blocker = .DSVERT_FORMAL_GLM_FRONTDOOR_BLOCKER,
    registered_remote_method = FALSE,
    production_ready = FALSE))
  .dsvert_formal_glm_frontdoor_sign(unsigned, .policy, .signer)
}
