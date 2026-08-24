# Lifetime-independent bootstrap and durable publication for one sticky
# stateless synopsis.  The relay transports signed custodian configuration;
# it never supplies privacy parameters, bounds, schema, or peer roles.

.DSVERT_DP_SYNOPSIS_POLICY_VERSION <-
  "dsvert-stateless-catalog-synopsis-policy-v1"
.DSVERT_DP_SYNOPSIS_POLICY_CONTRACT <-
  "stateless_catalog_synopsis_per_artifact_v1"
.DSVERT_DP_SYNOPSIS_BOOTSTRAP_VERSION <-
  "dsvert-stateless-catalog-synopsis-bootstrap-v1"
.DSVERT_DP_SYNOPSIS_BOOTSTRAP_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/bootstrap/v1|"
.DSVERT_DP_SYNOPSIS_BIND_REQUEST_VERSION <-
  "dsvert-stateless-catalog-synopsis-bind-request-v1"
.DSVERT_DP_SYNOPSIS_BIND_SIGNATURE_VERSION <-
  "dsvert-stateless-catalog-synopsis-bind-signature-v1"
.DSVERT_DP_SYNOPSIS_BOUND_MANIFEST_VERSION <-
  "dsvert-stateless-catalog-synopsis-bound-manifest-v1"
.DSVERT_DP_SYNOPSIS_BIND_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/bind/v1|"
.DSVERT_DP_SYNOPSIS_MANIFEST_CACHE_VERSION <-
  "dsvert-stateless-catalog-synopsis-manifest-cache-v1"
.DSVERT_DP_SYNOPSIS_POLICY_SNAPSHOT_VERSION <-
  "dsvert-stateless-catalog-synopsis-policy-snapshot-v1"
.DSVERT_DP_SYNOPSIS_MANIFEST_STORE_SCHEMA_VERSION <-
  "dsvert-stateless-catalog-synopsis-manifest-store-v1"
.DSVERT_DP_SYNOPSIS_COMPILATION_RECORD_VERSION <-
  "dsvert-stateless-catalog-synopsis-compilation-record-v1"
.DSVERT_DP_SYNOPSIS_PUBLICATION_VERSION <-
  "dsvert-stateless-catalog-synopsis-publication-v1"
.DSVERT_DP_SYNOPSIS_FINALIZE_ACK_VERSION <-
  "dsvert-stateless-catalog-synopsis-finalize-ack-v1"
.DSVERT_DP_SYNOPSIS_FINALIZE_ACK_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/finalize-ack/v1|"
.DSVERT_DP_SYNOPSIS_POLICY_FIELDS_V1 <- c(
  "schema_version", "mechanism_version", "policy_contract", "domain",
  "cohort_id", "peer_name", "own_identity_pk", "logical_peers",
  "peer_pinset", "peer_pinset_sha256", "global_total_epsilon",
  "global_total_delta", "peer_count", "designated_noise_peers",
  "numeric_grid_bits", "adjacency", "patient_column", "unit_capacity",
  "fixed_cohort_size", "max_records_per_unit", "overflow_policy",
  "contingency_unit_aggregation_policy", "noise_selection",
  "transcript_privacy", "snapshot_binding", "alignment_binding",
  "require_snapshot_digest", "require_alignment_manifest",
  "state_private", "datasets", "categorical_levels", "numeric_bounds",
  "capsule_dataset_mapping", "capsule_workload_scope",
  "capsule_workload_specs", "lock_timeout_ms", "synopsis_state_path")

.dsvert_dp_synopsis_policy_is_v1 <- function(policy) {
  is.list(policy) && identical(
    policy$policy_contract, .DSVERT_DP_SYNOPSIS_POLICY_CONTRACT)
}

.dsvert_dp_synopsis_state_path_v1 <- function() {
  configured <- .dsvert_dp_option("synopsis_state_path", NULL)
  if (is.null(configured)) {
    configured <- file.path(
      dirname(.dsvert_identity_seed_path()), "dp-synopsis")
  }
  configured <- .dsvert_dp_scalar_string(
    configured, "dsvert.dp.synopsis_state_path")
  expanded <- path.expand(configured)
  if (!grepl("^/", expanded)) {
    stop("dsvert.dp.synopsis_state_path must be absolute", call. = FALSE)
  }
  parent <- dirname(expanded)
  if (!dir.exists(parent)) {
    stop("The synopsis state directory does not exist", call. = FALSE)
  }
  canonical_parent <- normalizePath(
    parent, winslash = "/", mustWork = TRUE)
  if (!identical(.Platform$OS.type, "unix")) {
    stop(paste(
      "The synopsis service requires a POSIX owner-only state",
      "directory"), call. = FALSE)
  }
  if (!.dsvert_dp_private_mode(canonical_parent, directory = TRUE)) {
    stop(paste(
      "The synopsis state directory must be owned by the service account",
      "with mode 0700"), call. = FALSE)
  }
  result <- file.path(canonical_parent, basename(expanded))
  .dsvert_dp_assert_private_file(
    result, "synopsis state", require_private = TRUE)
  result
}

.dsvert_dp_synopsis_policy_v1 <- function() {
  policy <- .dsvert_dp_policy_core_v1()
  policy$schema_version <- 1L
  policy$policy_contract <- .DSVERT_DP_SYNOPSIS_POLICY_CONTRACT
  policy$synopsis_state_path <- .dsvert_dp_synopsis_state_path_v1()
  policy
}

.dsvert_dp_synopsis_policy_snapshot_node_v1 <- function(value) {
  if (is.null(value)) return(list(kind = "null"))
  if (is.object(value)) {
    stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
  }
  if (is.list(value)) {
    fields <- names(value)
    if (!is.null(fields)) {
      if (anyNA(fields) || any(!nzchar(fields)) || anyDuplicated(fields)) {
        stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
      }
      order <- order(fields, method = "radix")
      fields <- fields[order]
      value <- value[order]
    }
    return(list(
      kind = "list",
      names = if (is.null(fields)) NULL else as.list(fields),
      items = unname(lapply(
        value, .dsvert_dp_synopsis_policy_snapshot_node_v1))))
  }
  kind <- typeof(value)
  if (!kind %in% c("logical", "integer", "double", "character") ||
      anyNA(value) || (is.numeric(value) && any(!is.finite(value)))) {
    stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
  }
  fields <- names(value)
  if (!is.null(fields)) {
    if (anyNA(fields) || any(!nzchar(fields)) || anyDuplicated(fields)) {
      stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
    }
    order <- order(fields, method = "radix")
    fields <- fields[order]
    value <- value[order]
  }
  list(
    kind = kind,
    names = if (is.null(fields)) NULL else as.list(fields),
    values = as.list(unname(value)))
}

.dsvert_dp_synopsis_policy_snapshot_node_decode_v1 <- function(value) {
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !is.character(value$kind) ||
      length(value$kind) != 1L || is.na(value$kind)) {
    stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
  }
  kind <- value$kind
  if (identical(kind, "null")) {
    if (!setequal(names(value), "kind")) {
      stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
    }
    return(NULL)
  }
  if (identical(kind, "list")) {
    if (!setequal(names(value), c("kind", "names", "items")) ||
        !is.list(value$items) || !is.null(names(value$items))) {
      stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
    }
    result <- lapply(
      value$items, .dsvert_dp_synopsis_policy_snapshot_node_decode_v1)
  } else {
    if (!kind %in% c("logical", "integer", "double", "character") ||
        !setequal(names(value), c("kind", "names", "values")) ||
        !is.list(value$values) || !is.null(names(value$values)) ||
        !all(vapply(value$values, function(item) {
          is.atomic(item) && length(item) == 1L && !is.na(item) &&
            (!is.numeric(item) || is.finite(item))
        }, logical(1L)))) {
      stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
    }
    result <- switch(kind,
      logical = as.logical(unlist(value$values, use.names = FALSE)),
      integer = as.integer(unlist(value$values, use.names = FALSE)),
      double = as.numeric(unlist(value$values, use.names = FALSE)),
      character = enc2utf8(as.character(unlist(
        value$values, use.names = FALSE))))
    if (anyNA(result) || (is.numeric(result) && any(!is.finite(result)))) {
      stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
    }
  }
  fields <- value$names
  if (!is.null(fields)) {
    if (!is.list(fields) || length(fields) != length(result) ||
        !all(vapply(fields, function(item) {
          is.character(item) && length(item) == 1L && !is.na(item) &&
            nzchar(item)
        }, logical(1L)))) {
      stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
    }
    fields <- unlist(fields, use.names = FALSE)
    if (anyDuplicated(fields) ||
        !identical(fields, sort(fields, method = "radix"))) {
      stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
    }
    names(result) <- fields
  }
  result
}

.dsvert_dp_synopsis_policy_snapshot_v1 <- function(
    policy, expected_state_path = NULL) {
  forbidden <- c(
    "lifetime_max_distinct_capsules", "ledger_path", "ledger_private",
    "noise_root", "anchor_provider", "rollback_protection")
  if (!.dsvert_dp_synopsis_policy_is_v1(policy) ||
      is.null(names(policy)) || anyNA(names(policy)) ||
      anyDuplicated(names(policy)) ||
      !setequal(names(policy), .DSVERT_DP_SYNOPSIS_POLICY_FIELDS_V1) ||
      length(intersect(names(policy), forbidden)) ||
      !identical(policy$state_private, TRUE)) {
    stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
  }
  .dsvert_dp_synopsis_policy_context_v1(policy)
  state_path <- .dsvert_dp_scalar_string(
    policy$synopsis_state_path, "durable synopsis state path")
  if (!is.null(expected_state_path) && !identical(
      state_path, .dsvert_dp_scalar_string(
        expected_state_path, "expected durable synopsis state path"))) {
    stop("The durable synopsis policy targets another state namespace.",
         call. = FALSE)
  }
  policy$synopsis_state_path <- state_path
  wire <- .dsvert_dp_synopsis_policy_snapshot_node_v1(policy)
  unsigned <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_POLICY_SNAPSHOT_VERSION,
    policy = wire))
  .dsvert_dp_canonical_query_value(c(
    unsigned, list(policy_sha256 = digest::digest(
    .dsvert_dp_canonical_json(unsigned),
    algo = "sha256", serialize = FALSE))))
}

.dsvert_dp_synopsis_policy_snapshot_validate_v1 <- function(
    value, expected_state_path = NULL) {
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(
        names(value), c("version", "policy", "policy_sha256")) ||
      !identical(
        value$version, .DSVERT_DP_SYNOPSIS_POLICY_SNAPSHOT_VERSION) ||
      !is.character(value$policy_sha256) ||
      length(value$policy_sha256) != 1L ||
      !grepl("^[0-9a-f]{64}$", value$policy_sha256)) {
    stop("Invalid durable synopsis policy snapshot.", call. = FALSE)
  }
  policy <- .dsvert_dp_synopsis_policy_snapshot_node_decode_v1(value$policy)
  expected <- .dsvert_dp_synopsis_policy_snapshot_v1(
    policy, expected_state_path)
  if (!identical(
        .dsvert_dp_canonical_json(
          .dsvert_dp_canonical_query_value(value)),
        .dsvert_dp_canonical_json(expected))) {
    stop("The durable synopsis policy snapshot failed authentication.",
         call. = FALSE)
  }
  list(
    version = expected$version, policy = policy,
    policy_sha256 = expected$policy_sha256, wire = expected)
}

.dsvert_dp_synopsis_policy_context_v1 <- function(
    policy, .primitive_scope = NULL) {
  required <- c(
    "domain", "cohort_id", "peer_name", "own_identity_pk",
    "peer_pinset", "peer_pinset_sha256", "peer_count",
    "designated_noise_peers", "global_total_epsilon",
    "global_total_delta", "adjacency", "patient_column",
    "unit_capacity", "fixed_cohort_size", "max_records_per_unit",
    "overflow_policy", "contingency_unit_aggregation_policy",
    "numeric_grid_bits", "capsule_workload_scope")
  if (!.dsvert_dp_synopsis_policy_is_v1(policy) ||
      !all(required %in% names(policy))) {
    stop("Invalid stateless synopsis policy.", call. = FALSE)
  }
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  peer <- .dsvert_dp_analysis_scalar_id(
    policy$peer_name, "synopsis policy peer")
  if (!peer %in% names(pins) ||
      !identical(policy$own_identity_pk, unname(pins[[peer]])) ||
      !identical(as.numeric(policy$peer_count), as.numeric(length(pins))) ||
      !identical(policy$peer_pinset_sha256,
                 .dsvert_dp_synopsis_pinset_hash_v1(pins))) {
    stop("Invalid stateless synopsis pinned policy.", call. = FALSE)
  }
  designated <- .dsvert_dp_resolve_designated_noise_peers(
    policy$designated_noise_peers, pins)
  epsilon <- .dsvert_dp_scalar_number(
    policy$global_total_epsilon, "synopsis artifact epsilon",
    0, 8, lower_open = TRUE)
  delta <- .dsvert_dp_scalar_number(
    policy$global_total_delta, "synopsis artifact delta", 0, 1)
  if (delta >= 1) {
    stop("synopsis artifact delta must be < 1", call. = FALSE)
  }
  common <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_POLICY_VERSION,
    privacy_scope = "per_canonical_artifact_v1",
    global_composition_claim = FALSE,
    domain = policy$domain, cohort_id = policy$cohort_id,
    ordered_peer_pinset = as.list(pins),
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    peer_count = as.integer(length(pins)),
    designated_noise_peers = as.list(designated),
    artifact_epsilon = epsilon, artifact_delta = delta,
    adjacency = policy$adjacency,
    patient_column = policy$patient_column,
    unit_capacity = as.integer(policy$unit_capacity),
    fixed_cohort_size = policy$fixed_cohort_size,
    max_records_per_unit = as.integer(policy$max_records_per_unit),
    overflow_policy = policy$overflow_policy,
    contingency_unit_aggregation_policy =
      policy$contingency_unit_aggregation_policy,
    numeric_grid_bits = as.integer(policy$numeric_grid_bits),
    primitive_scope = .dsvert_dp_capsule_scope_policy_binding(
      if (is.null(.primitive_scope)) {
        policy$capsule_workload_scope
      } else {
        .primitive_scope
      }),
    mechanism_version = policy$mechanism_version,
    sticky_release = TRUE, distinct_artifact_gate = FALSE,
    request_limit = FALSE, rate_limit = FALSE, catalog_limit = FALSE))
  list(
    common = common,
    consortium_id = paste0(
      "dpsc1_", .dsvert_joint_dp_hash(common)),
    pins = pins, designated = designated, peer_name = peer,
    local_policy_hash = .dsvert_joint_dp_hash(list(
      version = .DSVERT_DP_SYNOPSIS_POLICY_VERSION,
      common = common, peer_name = peer)))
}

.dsvert_dp_synopsis_workload_scope_v1 <- function(workload) {
  scope <- if (is.list(workload)) workload$primitive_scope else NULL
  mode <- if (is.list(scope)) scope$mode else NULL
  string_array <- function(value) {
    if (is.null(value)) return(character())
    if (is.character(value)) return(unname(value))
    if (is.list(value) && !length(value)) return(character())
    if (is.list(value) && is.null(names(value)) &&
        all(vapply(value, function(item) {
          is.character(item) && length(item) == 1L && !is.na(item)
        }, logical(1L)))) {
      return(unname(unlist(value, use.names = FALSE)))
    }
    value
  }
  strict_missing <- string_array(
    if (is.list(scope)) scope$strict_missing_categorical else NULL)
  if (!is.character(strict_missing) || anyNA(strict_missing) ||
      any(!nzchar(strict_missing)) || anyDuplicated(strict_missing)) {
    stop("Invalid synopsis strict-missing policy projection.", call. = FALSE)
  }
  if (identical(mode, "all_schema")) {
    return(.dsvert_dp_capsule_scope_policy_binding(list(
      mode = "all_schema", strict_missing_categorical = strict_missing)))
  }
  explicit <- tryCatch(
    scope$selection$explicit_catalog, error = function(error) NULL)
  fields <- c(
    "numeric_moments", "categorical_marginals",
    "categorical_pairs", "correlations")
  if (!identical(mode, "catalog_v1") || !is.list(explicit) ||
      !setequal(names(explicit), fields)) {
    stop("Invalid synopsis workload policy projection.", call. = FALSE)
  }
  explicit$numeric_moments <- string_array(explicit$numeric_moments)
  explicit$categorical_marginals <-
    string_array(explicit$categorical_marginals)
  explicit$categorical_pairs <- unname(lapply(
    unname(explicit$categorical_pairs), string_array))
  explicit$correlations <- unname(lapply(
    unname(explicit$correlations), string_array))
  .dsvert_dp_capsule_scope_policy_binding(c(
    list(mode = "catalog_v1", strict_missing_categorical = strict_missing),
    explicit[fields]))
}

.dsvert_dp_synopsis_capsule_identity_v1 <- function(
    policy, logical_snapshot, capsule_schema, admission, bounds, workload) {
  context <- .dsvert_dp_synopsis_policy_context_v1(
    policy, .primitive_scope =
      .dsvert_dp_synopsis_workload_scope_v1(workload))
  logical_snapshot <- .dsvert_joint_dp_logical_snapshot(logical_snapshot)
  if (!is.character(capsule_schema) || length(capsule_schema) != 1L ||
      is.na(capsule_schema) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$", capsule_schema)) {
    stop("Invalid synopsis capsule schema identifier.", call. = FALSE)
  }
  contract <- .dsvert_dp_canonical_query_value(list(
    protocol = "dsvert-stateless-catalog-synopsis-capsule-identity-v1",
    consortium_id = context$consortium_id,
    policy_contract_hash = .dsvert_joint_dp_hash(context$common),
    peer_pinset_sha256 = context$common$peer_pinset_sha256,
    logical_snapshot = logical_snapshot,
    capsule_schema = capsule_schema,
    admission = .dsvert_joint_dp_capsule_component(
      admission, "synopsis admission contract"),
    bounds = .dsvert_joint_dp_capsule_component(
      bounds, "synopsis bounds contract"),
    workload = .dsvert_joint_dp_capsule_component(
      workload, "synopsis workload contract"),
    privacy_epoch_scope = "per_canonical_artifact_sticky_v1"))
  list(capsule_id = .dsvert_joint_dp_hash(contract), contract = contract)
}

.dsvert_dp_synopsis_capsule_identity_validate_v1 <- function(
    policy, logical_snapshot, value) {
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) ||
      !setequal(names(value), c("capsule_id", "contract")) ||
      !is.list(value$contract)) {
    stop("Invalid synopsis capsule identity.", call. = FALSE)
  }
  contract <- value$contract
  expected <- .dsvert_dp_synopsis_capsule_identity_v1(
    policy, logical_snapshot, contract$capsule_schema,
    contract$admission, contract$bounds, contract$workload)
  value <- .dsvert_dp_canonical_query_value(value)
  if (!identical(value, expected)) {
    stop("The synopsis capsule identity does not match its contract.",
         call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_bootstrap_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_BOOTSTRAP_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_synopsis_bind_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  if (is.list(unsigned)) {
    unsigned$manifest_json <- NULL
    unsigned$artifact_commitments <- NULL
  }
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_BIND_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_synopsis_bootstrap_v1 <- function(
    .policy = NULL, .identity = NULL,
    .signer = .dsvert_relay_sign_message) {
  if (is.null(.policy)) .policy <- .dsvert_dp_synopsis_policy_v1()
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  context <- .dsvert_dp_synopsis_policy_context_v1(.policy)
  if (!is.list(.identity) || is.null(.identity$identity_pk) ||
      is.null(.identity$identity_sk) || !is.function(.signer) ||
      !identical(
        .dsvert_relay_normalize_identity_pk(.identity$identity_pk),
        unname(context$pins[[context$peer_name]]))) {
    stop("The synopsis bootstrap identity is not pinned.", call. = FALSE)
  }
  unsigned <- list(
    version = .DSVERT_DP_SYNOPSIS_BOOTSTRAP_VERSION,
    phase = "custodian_policy_bootstrap",
    peer_name = context$peer_name,
    peer_identity_pk = unname(context$pins[[context$peer_name]]),
    policy = context$common,
    draft = .dsvert_dp_capsule_manifest_draft_unsigned(.policy),
    data_access = FALSE, patient_derived_metadata = FALSE,
    request_limit = FALSE, rate_limit = FALSE,
    catalog_limit = FALSE)
  signature <- .signer(
    .dsvert_dp_synopsis_bootstrap_message_v1(unsigned),
    .identity$identity_sk)
  .dsvert_dp_canonical_query_value(c(
    unsigned, list(signature = .dsvert_dp_synopsis_signature_v1(signature))))
}

.dsvert_dp_synopsis_decode_canonical_v1 <- function(
    value, what, maximum_bytes =
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes) {
    stop("Invalid synopsis ", what, ".", call. = FALSE)
  }
  decoded <- tryCatch(jsonlite::fromJSON(
    value, simplifyVector = FALSE), error = function(error) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(decoded)),
    error = function(error) NULL)
  if (!is.list(decoded) || is.null(canonical) ||
      !identical(canonical, value)) {
    stop("Invalid canonical synopsis ", what, ".", call. = FALSE)
  }
  decoded
}

.dsvert_dp_synopsis_bootstrap_validate_v1 <- function(
    value, policy, .verifier = .dsvert_relay_verify_message) {
  fields <- c(
    "version", "phase", "peer_name", "peer_identity_pk", "policy",
    "draft", "data_access", "patient_derived_metadata", "request_limit",
    "rate_limit", "catalog_limit", "signature")
  context <- .dsvert_dp_synopsis_policy_context_v1(policy)
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(value$version, .DSVERT_DP_SYNOPSIS_BOOTSTRAP_VERSION) ||
      !identical(value$phase, "custodian_policy_bootstrap") ||
      !identical(
        .dsvert_dp_canonical_json(value$policy),
        .dsvert_dp_canonical_json(context$common)) ||
      !identical(value$data_access, FALSE) ||
      !identical(value$patient_derived_metadata, FALSE) ||
      !identical(value$request_limit, FALSE) ||
      !identical(value$rate_limit, FALSE) ||
      !identical(value$catalog_limit, FALSE) || !is.function(.verifier)) {
    stop("Invalid signed synopsis bootstrap.", call. = FALSE)
  }
  peer <- .dsvert_dp_analysis_scalar_id(
    value$peer_name, "synopsis bootstrap peer")
  identity <- .dsvert_dp_analysis_identity_pk(
    value$peer_identity_pk, "synopsis bootstrap identity")
  if (!peer %in% names(context$pins) ||
      !identical(identity, unname(context$pins[[peer]])) ||
      !isTRUE(tryCatch(.verifier(
        .dsvert_dp_synopsis_bootstrap_message_v1(value),
        identity, .dsvert_dp_synopsis_signature_v1(value$signature)),
        error = function(error) FALSE))) {
    stop("Synopsis bootstrap signature verification failed.", call. = FALSE)
  }
  if (identical(peer, context$peer_name)) {
    expected <- list(
      version = .DSVERT_DP_SYNOPSIS_BOOTSTRAP_VERSION,
      phase = "custodian_policy_bootstrap",
      peer_name = context$peer_name,
      peer_identity_pk = unname(context$pins[[context$peer_name]]),
      policy = context$common,
      draft = .dsvert_dp_capsule_manifest_draft_unsigned(policy),
      data_access = FALSE, patient_derived_metadata = FALSE,
      request_limit = FALSE, rate_limit = FALSE,
      catalog_limit = FALSE)
    if (!identical(
          .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(
            value[setdiff(names(value), "signature")])),
          .dsvert_dp_canonical_json(
            .dsvert_dp_canonical_query_value(expected)))) {
      stop("The local synopsis bootstrap conflicts with custodian policy.",
           call. = FALSE)
    }
  }
  value
}

.dsvert_dp_synopsis_bootstrap_set_v1 <- function(
    bootstraps, policy, .verifier = .dsvert_relay_verify_message) {
  context <- .dsvert_dp_synopsis_policy_context_v1(policy)
  if (!is.list(bootstraps) || is.null(names(bootstraps)) ||
      anyNA(names(bootstraps)) || anyDuplicated(names(bootstraps)) ||
      !setequal(names(bootstraps), names(context$pins))) {
    stop("Synopsis bootstrap coverage is incomplete.", call. = FALSE)
  }
  verified <- lapply(
    bootstraps, .dsvert_dp_synopsis_bootstrap_validate_v1,
    policy = policy, .verifier = .verifier)
  peers <- vapply(verified, `[[`, character(1L), "peer_name")
  if (anyDuplicated(peers) || !setequal(peers, names(context$pins))) {
    stop("Synopsis bootstrap peer coverage is invalid.", call. = FALSE)
  }
  names(verified) <- peers
  verified[names(context$pins)]
}

.DSVERT_DP_SYNOPSIS_LOCAL_PAIR_REQUEST_VERSION <-
  "dsvert-stateless-catalog-synopsis-local-categorical-pair-request-v1"
.DSVERT_DP_SYNOPSIS_LOCAL_PAIR_SELECTOR_VERSION <-
  "dsvert-stateless-catalog-synopsis-local-categorical-pair-selector-v1"
.DSVERT_DP_SYNOPSIS_LOCAL_PAIR_SELECTOR_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/local-categorical-pair-selector/v1|"
.DSVERT_DP_SYNOPSIS_CROSS_PAIR_REQUEST_VERSION <-
  "dsvert-stateless-catalog-synopsis-cross-categorical-pair-request-v1"
.DSVERT_DP_SYNOPSIS_CROSS_PAIR_SELECTOR_VERSION <-
  "dsvert-stateless-catalog-synopsis-cross-categorical-pair-selector-v1"
.DSVERT_DP_SYNOPSIS_CROSS_PAIR_SELECTOR_DOMAIN <-
  "dsVert/stateless-catalog-synopsis/cross-categorical-pair-selector/v1|"

.dsvert_dp_synopsis_local_pair_request_v1 <- function(value) {
  fields <- c("version", "family", "dataset", "columns", "owner_peer")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(
        value$version, .DSVERT_DP_SYNOPSIS_LOCAL_PAIR_REQUEST_VERSION) ||
      !identical(value$family, "categorical_pairs")) {
    stop("Invalid local categorical Synopsis projection request.",
         call. = FALSE)
  }
  columns <- value$columns
  if (is.list(columns) && is.null(names(columns)) &&
      all(vapply(columns, function(column) {
        is.character(column) && length(column) == 1L && !is.na(column)
      }, logical(1L)))) {
    columns <- unname(unlist(columns, use.names = FALSE))
  }
  if (!is.character(columns) || length(columns) != 2L || anyNA(columns) ||
      !is.null(names(columns))) {
    stop("Invalid local categorical Synopsis projection columns.",
         call. = FALSE)
  }
  columns <- sort(vapply(
    columns, .dsvert_dp_capsule_id, character(1L),
    what = "local categorical Synopsis column"), method = "radix")
  if (anyDuplicated(columns)) {
    stop("A local categorical Synopsis projection needs two columns.",
         call. = FALSE)
  }
  owner <- value$owner_peer
  if (!is.null(owner)) {
    owner <- .dsvert_dp_capsule_id(
      owner, "local categorical Synopsis owner")
  }
  list(
    version = .DSVERT_DP_SYNOPSIS_LOCAL_PAIR_REQUEST_VERSION,
    family = "categorical_pairs",
    dataset = .dsvert_dp_capsule_id(
      value$dataset, "local categorical Synopsis dataset"),
    columns = unname(columns), owner_peer = owner)
}

.dsvert_dp_synopsis_local_pair_selector_hash_v1 <- function(value) {
  digest::digest(charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_LOCAL_PAIR_SELECTOR_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value)))),
  algo = "sha256", serialize = FALSE)
}

.dsvert_dp_synopsis_local_pair_project_components_v1 <- function(
    schema, dataset_name, owner_peer, references, policy) {
  if (!is.list(schema) || !is.list(schema$schema) ||
      !is.list(schema$schema$datasets) ||
      !dataset_name %in% names(schema$schema$datasets) ||
      !is.character(references) || length(references) != 2L ||
      anyNA(references) || anyDuplicated(references)) {
    stop("Invalid local categorical Synopsis projection source.",
         call. = FALSE)
  }
  references <- sort(unname(references), method = "radix")
  source <- schema$schema$datasets[[dataset_name]]
  columns <- source$columns[references]
  valid_columns <- length(columns) == 2L &&
    all(vapply(columns, function(column) {
      is.list(column) && identical(column$kind, "categorical") &&
        identical(column$owner_peer, owner_peer) &&
        is.atomic(column$levels) && length(column$levels) > 0L
    }, logical(1L)))
  if (!isTRUE(valid_columns) ||
      !owner_peer %in% names(source$patient_keys)) {
    stop("Invalid local categorical Synopsis projection source.",
         call. = FALSE)
  }
  columns <- lapply(columns, function(column) {
    .dsvert_dp_capsule_column(column, names(source$patient_keys))
  })
  projected_dataset <- source[c(
    "dataset_id", "dataset_version", "schema_version", "alignment_group")]
  projected_dataset$patient_keys <- source$patient_keys[owner_peer]
  projected_dataset$columns <- columns
  datasets <- stats::setNames(list(projected_dataset), dataset_name)
  families <- c("describe", "survival", "gaussian", "vertical_cross")
  workload <- .dsvert_dp_canonical_query_value(c(
    list(version = .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION),
    stats::setNames(rep(list(list()), length(families)), families)))
  parent_snapshot <- schema$schema$logical_snapshot
  alignment <- tryCatch(
    as.integer(parent_snapshot$alignment_protocol_version),
    error = function(error) NA_integer_)
  if (!is.list(parent_snapshot) ||
      !identical(parent_snapshot$logical_snapshot_id, policy$cohort_id) ||
      length(alignment) != 1L || is.na(alignment) || alignment < 1L ||
      !identical(as.numeric(alignment),
                 as.numeric(parent_snapshot$alignment_protocol_version))) {
    stop("Invalid local categorical Synopsis projection snapshot.",
         call. = FALSE)
  }
  fingerprint <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-logical-snapshot-v1",
    domain = policy$domain, cohort_id = policy$cohort_id,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    alignment_protocol_version = alignment,
    datasets = datasets, workload_contract = workload))
  logical_snapshot <- .dsvert_dp_canonical_query_value(list(
    logical_snapshot_id = policy$cohort_id,
    version = paste0("schema-v1-", fingerprint),
    alignment_protocol_version = alignment))
  projected_schema <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = datasets))
  scope <- .dsvert_dp_capsule_scope_policy_binding(list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(),
    categorical_pairs = list(references), correlations = list()))
  list(
    schema = projected_schema,
    schema_json = .dsvert_dp_canonical_json(projected_schema),
    schema_sha256 = .dsvert_joint_dp_hash(projected_schema),
    workload = workload,
    workload_json = .dsvert_dp_canonical_json(workload),
    workload_sha256 = .dsvert_joint_dp_hash(workload),
    logical_snapshot = logical_snapshot,
    primitive_scope = scope,
    policy_sha256 = .dsvert_joint_dp_hash(
      .dsvert_dp_synopsis_policy_context_v1(
        policy, .primitive_scope = scope)$common))
}

.dsvert_dp_synopsis_local_pair_resolve_v1 <- function(
    request, schema, policy) {
  request <- .dsvert_dp_synopsis_local_pair_request_v1(request)
  if (!is.list(schema) || !is.list(schema$schema) ||
      !is.list(schema$schema$datasets) ||
      !request$dataset %in% names(schema$schema$datasets)) {
    stop("The signed Synopsis schema has no requested categorical dataset.",
         call. = FALSE)
  }
  qualified <- .dsvert_dp_capsule_qualified_columns(schema$schema)
  requested <- request$columns
  candidates <- lapply(requested, function(column) {
    names(qualified)[vapply(qualified, function(candidate) {
      identical(candidate$dataset, request$dataset) &&
        identical(candidate$kind, "categorical") &&
        identical(candidate$column, column) &&
        (is.null(request$owner_peer) ||
           identical(candidate$owner_peer, request$owner_peer))
    }, logical(1L))]
  })
  if (any(lengths(candidates) == 0L)) {
    stop("The requested local categorical pair is absent from signed metadata.",
         call. = FALSE)
  }
  combinations <- expand.grid(
    left = candidates[[1L]], right = candidates[[2L]],
    stringsAsFactors = FALSE)
  valid <- vapply(seq_len(nrow(combinations)), function(index) {
    left <- qualified[[combinations$left[[index]]]]
    right <- qualified[[combinations$right[[index]]]]
    !identical(combinations$left[[index]], combinations$right[[index]]) &&
      identical(left$owner_peer, right$owner_peer) &&
      identical(left$dataset, right$dataset)
  }, logical(1L))
  combinations <- combinations[valid, , drop = FALSE]
  if (nrow(combinations) != 1L) {
    stop("The signed local categorical pair is missing or ambiguous.",
         call. = FALSE)
  }
  references <- sort(unname(c(
    combinations$left[[1L]], combinations$right[[1L]])), method = "radix")
  owner <- qualified[[references[[1L]]]]$owner_peer
  scope <- .dsvert_dp_capsule_scope_policy_binding(
    policy$capsule_workload_scope)
  if (identical(scope$mode, "catalog_v1")) {
    authorized <- .dsvert_dp_capsule_scope_pairs(
      scope$categorical_pairs, qualified, "categorical", "categorical-pair")
    keys <- if (length(authorized)) vapply(
      authorized, function(pair) .dsvert_dp_canonical_json(as.list(pair)),
      character(1L)) else character()
    if (!.dsvert_dp_canonical_json(as.list(references)) %in% keys) {
      stop("The requested categorical pair is not in the signed catalog.",
           call. = FALSE)
    }
  }
  columns <- lapply(references, function(reference) {
    column <- qualified[[reference]]
    list(
      reference = reference, column = column$column,
      levels_sha256 = .dsvert_joint_dp_hash(as.list(column$levels)))
  })
  projection <- .dsvert_dp_synopsis_local_pair_project_components_v1(
    schema, request$dataset, owner, references, policy)
  parent <- list(
    schema_sha256 = projection$schema_sha256,
    workload_contract_sha256 = projection$workload_sha256,
    logical_snapshot = projection$logical_snapshot,
    policy_sha256 = projection$policy_sha256)
  unsigned <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_LOCAL_PAIR_SELECTOR_VERSION,
    family = "categorical_pairs", dataset = request$dataset,
    owner_peer = owner, columns = columns, parent = parent))
  .dsvert_dp_canonical_query_value(c(unsigned, list(
    sha256 = .dsvert_dp_synopsis_local_pair_selector_hash_v1(unsigned))))
}

.dsvert_dp_synopsis_local_pair_selector_validate_v1 <- function(
    value, schema, policy) {
  fields <- c(
    "version", "family", "dataset", "owner_peer", "columns", "parent",
    "sha256")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !is.list(value$columns) || length(value$columns) != 2L ||
      !identical(
        value$version, .DSVERT_DP_SYNOPSIS_LOCAL_PAIR_SELECTOR_VERSION)) {
    stop("Invalid signed-metadata categorical Synopsis selector.",
         call. = FALSE)
  }
  physical <- tryCatch(vapply(
    value$columns, `[[`, character(1L), "column"),
    error = function(error) character())
  expected <- if (length(physical) == 2L) tryCatch(
    .dsvert_dp_synopsis_local_pair_resolve_v1(list(
      version = .DSVERT_DP_SYNOPSIS_LOCAL_PAIR_REQUEST_VERSION,
      family = "categorical_pairs", dataset = value$dataset,
      columns = unname(physical), owner_peer = value$owner_peer),
    schema, policy), error = function(error) NULL) else NULL
  if (is.null(expected) || !identical(
        .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value)),
        .dsvert_dp_canonical_json(expected))) {
    stop("The categorical Synopsis selector is detached from signed metadata.",
         call. = FALSE)
  }
  expected
}

.dsvert_dp_synopsis_local_pair_project_v1 <- function(
    schema, selector, policy) {
  selector <- .dsvert_dp_synopsis_local_pair_selector_validate_v1(
    selector, schema, policy)
  references <- vapply(
    selector$columns, `[[`, character(1L), "reference")
  projection <- .dsvert_dp_synopsis_local_pair_project_components_v1(
    schema, selector$dataset, selector$owner_peer, references, policy)
  projection$primitive_scope <- NULL
  projection$policy_sha256 <- NULL
  projection
}

.dsvert_dp_synopsis_local_pair_scope_v1 <- function(selector) {
  references <- vapply(
    selector$columns, `[[`, character(1L), "reference")
  .dsvert_dp_capsule_scope_policy_binding(list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(),
    categorical_pairs = list(sort(unname(references), method = "radix")),
    correlations = list()))
}

.dsvert_dp_synopsis_cross_pair_request_v1 <- function(value) {
  fields <- c("version", "family", "dataset", "columns")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(
        value$version, .DSVERT_DP_SYNOPSIS_CROSS_PAIR_REQUEST_VERSION) ||
      !identical(value$family, "categorical_pair")) {
    stop("Invalid cross-owner categorical Synopsis projection request.",
         call. = FALSE)
  }
  columns <- value$columns
  if (is.list(columns) && is.null(names(columns)) &&
      all(vapply(columns, function(column) {
        is.character(column) && length(column) == 1L && !is.na(column)
      }, logical(1L)))) {
    columns <- unname(unlist(columns, use.names = FALSE))
  }
  if (!is.character(columns) || length(columns) != 2L || anyNA(columns) ||
      !is.null(names(columns))) {
    stop("Invalid cross-owner categorical Synopsis projection columns.",
         call. = FALSE)
  }
  references <- lapply(columns, function(column) {
    parsed <- tryCatch(.dsvert_dp_capsule_column_reference(
      column, "cross-owner categorical Synopsis column"),
      error = function(error) NULL)
    if (is.null(parsed)) {
      stop("A cross-owner categorical Synopsis column must be a plain column or an exact server$column reference.",
           call. = FALSE)
    }
    identifiers <- c(parsed$owner_peer, parsed$column)
    if (any(!grepl("^[A-Za-z][A-Za-z0-9_.]{0,127}$", identifiers))) {
      stop("A cross-owner categorical Synopsis column must be a plain column or an exact server$column reference.",
           call. = FALSE)
    }
    parsed
  })
  canonical <- vapply(references, `[[`, character(1L), "reference")
  if (anyDuplicated(canonical) ||
      (all(vapply(references, function(reference) {
        is.null(reference$owner_peer)
      }, logical(1L))) &&
       identical(references[[1L]]$column, references[[2L]]$column))) {
    stop("A cross-owner categorical Synopsis projection needs two columns.",
         call. = FALSE)
  }
  columns <- sort(unname(canonical), method = "radix")
  list(
    version = .DSVERT_DP_SYNOPSIS_CROSS_PAIR_REQUEST_VERSION,
    family = "categorical_pair",
    dataset = .dsvert_dp_capsule_id(
      value$dataset, "cross-owner categorical Synopsis dataset"),
    columns = unname(columns))
}

.dsvert_dp_synopsis_cross_pair_selector_hash_v1 <- function(value) {
  digest::digest(charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_CROSS_PAIR_SELECTOR_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value)))),
  algo = "sha256", serialize = FALSE)
}

.dsvert_dp_synopsis_cross_pair_public_id_v1 <- function(columns) {
  semantic <- lapply(columns, function(column) {
    column[c("owner_peer", "dataset", "column")]
  })
  keys <- vapply(semantic, function(column) paste(
    column$owner_peer, column$dataset, column$column, sep = "\r"),
    character(1L))
  semantic <- semantic[order(keys, method = "radix")]
  paste0("categorical_pair_", substr(.dsvert_joint_dp_hash(list(
    version = "dsvert-synopsis-cross-categorical-semantic-id-v1",
    family = "categorical_pair", columns = semantic)), 1L, 48L))
}

.dsvert_dp_synopsis_cross_pair_spec_v1 <- function(schema, request) {
  vertical <- tryCatch(schema$workload$vertical_cross,
                       error = function(error) NULL)
  columns <- tryCatch(.dsvert_dp_capsule_qualified_columns(schema$schema),
                      error = function(error) NULL)
  if (!is.list(vertical) || !length(vertical) || !is.list(columns)) {
    stop("The signed cross-owner categorical pair is missing or ambiguous.",
         call. = FALSE)
  }
  owners <- unique(unlist(lapply(
    schema$schema$datasets, function(dataset) names(dataset$patient_keys)),
    use.names = FALSE))
  normalized <- lapply(names(vertical), function(analysis_id) {
    entry <- vertical[[analysis_id]]
    if (!is.list(entry) || is.null(names(entry)) || anyNA(names(entry)) ||
        anyDuplicated(names(entry)) ||
        !setequal(names(entry), c("owner_peer", "spec")) ||
        !is.character(entry$owner_peer) || length(entry$owner_peer) != 1L ||
        is.na(entry$owner_peer) || !entry$owner_peer %in% owners ||
        !is.list(entry$spec)) {
      stop("The signed cross-owner categorical workload is invalid.",
           call. = FALSE)
    }
    spec <- tryCatch(
      .dsvert_dp_capsule_vertical_specs(
        stats::setNames(list(entry$spec), analysis_id), columns)[[1L]],
      error = function(error) NULL)
    if (is.null(spec)) {
      stop("The signed cross-owner categorical workload is invalid.",
           call. = FALSE)
    }
    list(analysis_id = analysis_id, owner_peer = entry$owner_peer,
         spec = spec)
  })
  requested <- lapply(request$columns, function(reference) {
    .dsvert_dp_capsule_column_reference(
      reference, "cross-owner categorical Synopsis column")
  })
  all_columns <- unname(columns)
  bare_owner_unique <- function(reference) {
    if (!is.null(reference$owner_peer)) return(TRUE)
    matches <- all_columns[vapply(all_columns, function(column) {
      identical(column$column, reference$column)
    }, logical(1L))]
    owners <- unique(vapply(
      matches, `[[`, character(1L), "owner_peer"))
    length(owners) == 1L
  }
  if (!all(vapply(requested, bare_owner_unique, logical(1L)))) {
    stop("A bare cross-owner categorical column must identify one signed owner.",
         call. = FALSE)
  }
  matches <- vapply(normalized, function(candidate) {
    spec <- candidate$spec
    sides <- lapply(c("left", "right"), function(side) {
      reference <- spec[[side]]
      column <- columns[[reference]]
      list(
        dataset = spec[[paste0(side, "_dataset")]],
        owner_peer = column$owner_peer, column = column$column)
    })
    accepts <- function(reference, side) {
      identical(reference$column, side$column) &&
        (is.null(reference$owner_peer) ||
           identical(reference$owner_peer, side$owner_peer))
    }
    bindings <- c(
      accepts(requested[[1L]], sides[[1L]]) &&
        accepts(requested[[2L]], sides[[2L]]),
      accepts(requested[[1L]], sides[[2L]]) &&
        accepts(requested[[2L]], sides[[1L]]))
    identical(spec$version, "v2") &&
      identical(spec$family, "categorical_pair") &&
      request$dataset %in% vapply(
        sides, `[[`, character(1L), "dataset") &&
      sum(bindings) == 1L
  }, logical(1L))
  selected <- normalized[matches]
  if (length(selected) != 1L) {
    stop("The signed cross-owner categorical pair is missing or ambiguous.",
         call. = FALSE)
  }
  selected[[1L]]
}

.dsvert_dp_synopsis_cross_pair_project_components_v1 <- function(
    schema, selected, policy) {
  spec <- selected$spec
  sides <- list(
    left = list(dataset = spec$left_dataset, reference = spec$left,
                owner_peer = spec$left_owner),
    right = list(dataset = spec$right_dataset, reference = spec$right,
                 owner_peer = spec$right_owner))
  if (identical(sides$left$owner_peer, sides$right$owner_peer)) {
    stop("Invalid cross-owner categorical Synopsis projection source.",
         call. = FALSE)
  }
  datasets <- list()
  projected_references <- list()
  for (side_name in names(sides)) {
    side <- sides[[side_name]]
    source <- schema$schema$datasets[[side$dataset]]
    column <- if (is.list(source)) source$columns[[side$reference]] else NULL
    if (!is.list(source) || !is.list(column) ||
        !identical(column$kind, "categorical") ||
        !identical(column$owner_peer, side$owner_peer) ||
        !is.atomic(column$levels) || !length(column$levels) ||
        !side$owner_peer %in% names(source$patient_keys)) {
      stop("Invalid cross-owner categorical Synopsis projection source.",
           call. = FALSE)
    }
    if (is.null(datasets[[side$dataset]])) {
      datasets[[side$dataset]] <- source[c(
        "dataset_id", "dataset_version", "schema_version",
        "alignment_group")]
      datasets[[side$dataset]]$patient_keys <- list()
      datasets[[side$dataset]]$columns <- list()
    }
    datasets[[side$dataset]]$patient_keys[[side$owner_peer]] <-
      source$patient_keys[[side$owner_peer]]
    normalized_column <- .dsvert_dp_capsule_column(
      column, names(source$patient_keys))
    physical <- .dsvert_dp_capsule_column_reference(
      side$reference, "cross-owner categorical projection column")$column
    projected_reference <- paste0(side$owner_peer, "$", physical)
    projected_references[[side_name]] <- projected_reference
    datasets[[side$dataset]]$columns[[projected_reference]] <-
      normalized_column
  }
  datasets <- datasets[order(names(datasets), method = "radix")]
  datasets <- lapply(datasets, function(dataset) {
    dataset$patient_keys <- dataset$patient_keys[
      order(names(dataset$patient_keys), method = "radix")]
    dataset$columns <- dataset$columns[
      order(names(dataset$columns), method = "radix")]
    dataset
  })
  semantic_columns <- lapply(names(sides), function(side_name) {
    side <- sides[[side_name]]
    list(
      owner_peer = side$owner_peer, dataset = side$dataset,
      column = .dsvert_dp_capsule_column_reference(
        side$reference, "cross-owner categorical projection column")$column)
  })
  public_analysis_id <-
    .dsvert_dp_synopsis_cross_pair_public_id_v1(semantic_columns)
  public_owner <- sort(vapply(
    semantic_columns, `[[`, character(1L), "owner_peer"),
    method = "radix")[[1L]]
  raw_spec <- list(
    version = "v2", left_dataset = spec$left_dataset,
    right_dataset = spec$right_dataset,
    left = projected_references$left,
    right = projected_references$right, family = "categorical_pair")
  workload <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION,
    describe = list(), survival = list(), gaussian = list(),
    vertical_cross = stats::setNames(list(list(
      owner_peer = public_owner, spec = raw_spec)),
      public_analysis_id)))
  parent_snapshot <- schema$schema$logical_snapshot
  alignment <- tryCatch(
    as.integer(parent_snapshot$alignment_protocol_version),
    error = function(error) NA_integer_)
  if (!is.list(parent_snapshot) ||
      !identical(parent_snapshot$logical_snapshot_id, policy$cohort_id) ||
      length(alignment) != 1L || is.na(alignment) || alignment < 1L ||
      !identical(as.numeric(alignment),
                 as.numeric(parent_snapshot$alignment_protocol_version))) {
    stop("Invalid cross-owner categorical Synopsis projection snapshot.",
         call. = FALSE)
  }
  fingerprint <- .dsvert_joint_dp_hash(list(
    protocol = "dsvert-biomedical-capsule-logical-snapshot-v1",
    domain = policy$domain, cohort_id = policy$cohort_id,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    alignment_protocol_version = alignment,
    datasets = datasets, workload_contract = workload))
  logical_snapshot <- .dsvert_dp_canonical_query_value(list(
    logical_snapshot_id = policy$cohort_id,
    version = paste0("schema-v1-", fingerprint),
    alignment_protocol_version = alignment))
  projected_schema <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = logical_snapshot,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = datasets))
  scope <- .dsvert_dp_capsule_scope_policy_binding(list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list()))
  list(
    schema = projected_schema,
    schema_json = .dsvert_dp_canonical_json(projected_schema),
    schema_sha256 = .dsvert_joint_dp_hash(projected_schema),
    workload = workload,
    workload_json = .dsvert_dp_canonical_json(workload),
    workload_sha256 = .dsvert_joint_dp_hash(workload),
    logical_snapshot = logical_snapshot, primitive_scope = scope,
    policy_sha256 = .dsvert_joint_dp_hash(
      .dsvert_dp_synopsis_policy_context_v1(
        policy, .primitive_scope = scope)$common))
}

.dsvert_dp_synopsis_cross_pair_resolve_v1 <- function(
    request, schema, policy) {
  request <- .dsvert_dp_synopsis_cross_pair_request_v1(request)
  selected <- .dsvert_dp_synopsis_cross_pair_spec_v1(schema, request)
  projection <- .dsvert_dp_synopsis_cross_pair_project_components_v1(
    schema, selected, policy)
  spec <- selected$spec
  columns <- lapply(c("left", "right"), function(side) {
    dataset <- spec[[paste0(side, "_dataset")]]
    reference <- spec[[side]]
    source <- schema$schema$datasets[[dataset]]
    column <- source$columns[[reference]]
    column <- .dsvert_dp_capsule_column(column, names(source$patient_keys))
    physical <- .dsvert_dp_capsule_column_reference(
      reference, "cross-owner categorical selector column")$column
    list(
      side = side, dataset = dataset,
      reference = paste0(column$owner_peer, "$", physical),
      column = physical, owner_peer = column$owner_peer,
      levels_sha256 = .dsvert_joint_dp_hash(as.list(column$levels)))
  })
  parent <- list(
    schema_sha256 = projection$schema_sha256,
    workload_contract_sha256 = projection$workload_sha256,
    logical_snapshot = projection$logical_snapshot,
    policy_sha256 = projection$policy_sha256)
  unsigned <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_CROSS_PAIR_SELECTOR_VERSION,
    family = "categorical_pair",
    analysis_id = .dsvert_dp_synopsis_cross_pair_public_id_v1(columns),
    columns = columns, parent = parent))
  .dsvert_dp_canonical_query_value(c(unsigned, list(
    sha256 = .dsvert_dp_synopsis_cross_pair_selector_hash_v1(unsigned))))
}

.dsvert_dp_synopsis_cross_pair_selector_validate_v1 <- function(
    value, schema, policy) {
  fields <- c(
    "version", "family", "analysis_id", "columns", "parent", "sha256")
  physical <- tryCatch(vapply(
    value$columns, `[[`, character(1L), "column"),
    error = function(error) character())
  datasets <- tryCatch(vapply(
    value$columns, `[[`, character(1L), "dataset"),
    error = function(error) character())
  expected <- if (is.list(value) && !is.null(names(value)) &&
      !anyNA(names(value)) && !anyDuplicated(names(value)) &&
      setequal(names(value), fields) &&
      identical(value$version,
                .DSVERT_DP_SYNOPSIS_CROSS_PAIR_SELECTOR_VERSION) &&
      length(physical) == 2L && length(datasets) == 2L) tryCatch(
    .dsvert_dp_synopsis_cross_pair_resolve_v1(list(
      version = .DSVERT_DP_SYNOPSIS_CROSS_PAIR_REQUEST_VERSION,
      family = "categorical_pair", dataset = datasets[[1L]],
      columns = vapply(
        value$columns, `[[`, character(1L), "reference")), schema, policy),
    error = function(error) NULL) else NULL
  if (is.null(expected) || !identical(
        .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(value)),
        .dsvert_dp_canonical_json(expected))) {
    stop("The cross-owner categorical Synopsis selector is detached from signed metadata.",
         call. = FALSE)
  }
  expected
}

.dsvert_dp_synopsis_cross_pair_project_v1 <- function(
    schema, selector, policy) {
  selector <- .dsvert_dp_synopsis_cross_pair_selector_validate_v1(
    selector, schema, policy)
  request <- list(
    version = .DSVERT_DP_SYNOPSIS_CROSS_PAIR_REQUEST_VERSION,
    family = "categorical_pair",
    dataset = selector$columns[[1L]]$dataset,
    columns = vapply(selector$columns, `[[`, character(1L), "reference"))
  selected <- .dsvert_dp_synopsis_cross_pair_spec_v1(
    schema, .dsvert_dp_synopsis_cross_pair_request_v1(request))
  projection <- .dsvert_dp_synopsis_cross_pair_project_components_v1(
    schema, selected, policy)
  projection$primitive_scope <- NULL
  projection$policy_sha256 <- NULL
  projection
}

.dsvert_dp_synopsis_cross_pair_scope_v1 <- function(selector) {
  .dsvert_dp_capsule_scope_policy_binding(list(
    mode = "catalog_v1", numeric_moments = character(),
    categorical_marginals = character(), categorical_pairs = list(),
    correlations = list()))
}

.dsvert_dp_synopsis_projection_is_cross_v1 <- function(value) {
  is.list(value) && identical(
    value$version, .DSVERT_DP_SYNOPSIS_CROSS_PAIR_SELECTOR_VERSION)
}

.dsvert_dp_synopsis_projection_resolve_v1 <- function(
    request, schema, policy) {
  if (is.list(request) && identical(
        request$version, .DSVERT_DP_SYNOPSIS_CROSS_PAIR_REQUEST_VERSION)) {
    return(.dsvert_dp_synopsis_cross_pair_resolve_v1(
      request, schema, policy))
  }
  .dsvert_dp_synopsis_local_pair_resolve_v1(request, schema, policy)
}

.dsvert_dp_synopsis_projection_validate_v1 <- function(
    value, schema, policy) {
  if (.dsvert_dp_synopsis_projection_is_cross_v1(value)) {
    return(.dsvert_dp_synopsis_cross_pair_selector_validate_v1(
      value, schema, policy))
  }
  .dsvert_dp_synopsis_local_pair_selector_validate_v1(
    value, schema, policy)
}

.dsvert_dp_synopsis_projection_project_v1 <- function(
    schema, selector, policy) {
  if (.dsvert_dp_synopsis_projection_is_cross_v1(selector)) {
    return(.dsvert_dp_synopsis_cross_pair_project_v1(
      schema, selector, policy))
  }
  .dsvert_dp_synopsis_local_pair_project_v1(schema, selector, policy)
}

.dsvert_dp_synopsis_projection_scope_v1 <- function(selector) {
  if (.dsvert_dp_synopsis_projection_is_cross_v1(selector)) {
    return(.dsvert_dp_synopsis_cross_pair_scope_v1(selector))
  }
  .dsvert_dp_synopsis_local_pair_scope_v1(selector)
}

.dsvert_dp_synopsis_manifest_schema_v1 <- function(bootstraps, policy) {
  context <- .dsvert_dp_synopsis_policy_context_v1(policy)
  column_entries <- unlist(lapply(names(context$pins), function(peer) {
    draft <- bootstraps[[peer]]$draft
    unlist(lapply(names(draft$datasets), function(data_name) {
      columns <- draft$datasets[[data_name]]$columns
      lapply(names(columns), function(reference) {
        parsed <- .dsvert_dp_capsule_column_reference(
          reference, "synopsis bootstrap column")
        list(
          peer = peer, dataset = data_name, raw_reference = reference,
          physical = parsed$column, owner_peer = columns[[reference]]$owner_peer)
      })
    }), recursive = FALSE)
  }), recursive = FALSE)
  physical_counts <- table(vapply(
    column_entries, `[[`, character(1L), "physical"))
  reference_map <- list()
  for (entry in column_entries) {
    if (!identical(entry$owner_peer, entry$peer)) {
      stop("A synopsis bootstrap column names another owner.", call. = FALSE)
    }
    projected <- if (physical_counts[[entry$physical]] > 1L) {
      paste0(entry$peer, "$", entry$physical)
    } else {
      entry$raw_reference
    }
    if (is.null(reference_map[[entry$peer]])) {
      reference_map[[entry$peer]] <- list()
    }
    if (is.null(reference_map[[entry$peer]][[entry$dataset]])) {
      reference_map[[entry$peer]][[entry$dataset]] <- list()
    }
    reference_map[[entry$peer]][[entry$dataset]][[entry$raw_reference]] <-
      projected
  }
  datasets <- list()
  seen_columns <- character()
  alignment_versions <- numeric()
  workload <- list(
    describe = list(), survival = list(), gaussian = list(),
    vertical_cross = list())
  for (peer in names(context$pins)) {
    draft <- bootstraps[[peer]]$draft
    expected <- c(
      "version", "phase", "peer_name", "peer_identity_pk",
      "peer_pinset_sha256", "domain", "cohort_id",
      "dataset_mapping_mode", "datasets", "workload_fragments",
      "data_access", "patient_derived_metadata", "operation_limit",
      "request_limit", "history_can_deny_operation")
    if (!is.list(draft) || is.null(names(draft)) ||
        anyNA(names(draft)) || anyDuplicated(names(draft)) ||
        !setequal(names(draft), expected) ||
        !identical(draft$version,
                   .DSVERT_DP_CAPSULE_MANIFEST_DRAFT_VERSION) ||
        !identical(draft$phase, "custodian_policy_draft") ||
        !identical(draft$peer_name, peer) ||
        !identical(draft$peer_identity_pk, unname(context$pins[[peer]])) ||
        !identical(draft$peer_pinset_sha256,
                   policy$peer_pinset_sha256) ||
        !identical(draft$domain, policy$domain) ||
        !identical(draft$cohort_id, policy$cohort_id) ||
        !is.list(draft$datasets) || !length(draft$datasets) ||
        !is.list(draft$workload_fragments)) {
      stop("A signed synopsis bootstrap contains an invalid draft.",
           call. = FALSE)
    }
    for (data_name in names(draft$datasets)) {
      local <- draft$datasets[[data_name]]
      common <- local[c(
        "dataset_id", "dataset_version", "schema_version",
        "alignment_group")]
      if (is.null(datasets[[data_name]])) {
        datasets[[data_name]] <- c(common, list(
          patient_keys = list(), columns = list()))
      } else if (!identical(datasets[[data_name]][names(common)], common)) {
        stop("Pinned synopsis peers supplied conflicting dataset identities.",
             call. = FALSE)
      }
      if (peer %in% names(datasets[[data_name]]$patient_keys)) {
        stop("A synopsis bootstrap duplicated dataset ownership.",
             call. = FALSE)
      }
      columns <- local$columns
      if (!is.list(columns) || !length(columns) ||
          is.null(names(columns)) || anyNA(names(columns)) ||
          anyDuplicated(names(columns))) {
        stop("Synopsis bootstrap columns are invalid or ambiguous.",
             call. = FALSE)
      }
      columns <- lapply(columns, function(column) {
        if (is.list(column) && identical(column$kind, "categorical") &&
            is.list(column$levels) && is.null(names(column$levels)) &&
            all(vapply(column$levels, function(level) {
              is.character(level) && length(level) == 1L && !is.na(level)
            }, logical(1L)))) {
          column$levels <- unlist(column$levels, use.names = FALSE)
        }
        column
      })
      columns <- lapply(columns, .dsvert_dp_capsule_column,
                        owner_names = names(context$pins))
      projected_names <- unname(vapply(names(columns), function(reference) {
        reference_map[[peer]][[data_name]][[reference]]
      }, character(1L)))
      if (anyNA(projected_names) || any(!nzchar(projected_names)) ||
          anyDuplicated(projected_names) || any(projected_names %in% seen_columns)) {
        stop("Synopsis bootstrap columns are invalid or ambiguous.",
             call. = FALSE)
      }
      names(columns) <- projected_names
      datasets[[data_name]]$patient_keys[[peer]] <- local$patient_column
      datasets[[data_name]]$columns <- c(
        datasets[[data_name]]$columns, columns)
      seen_columns <- c(seen_columns, projected_names)
      alignment_versions <- c(
        alignment_versions, as.numeric(local$alignment_protocol_version))
    }
    for (family in names(workload)) {
      fragments <- draft$workload_fragments[[family]]
      if (is.null(fragments)) fragments <- list()
      if (!is.list(fragments) ||
          length(intersect(names(workload[[family]]), names(fragments)))) {
        stop("Synopsis workload fragment ownership is ambiguous.",
             call. = FALSE)
      }
      for (analysis_id in names(fragments)) {
        workload[[family]][[analysis_id]] <- list(
          owner_peer = peer, spec = fragments[[analysis_id]])
      }
    }
  }
  if (!length(alignment_versions) || anyNA(alignment_versions) ||
      length(unique(alignment_versions)) != 1L) {
    stop("Pinned synopsis datasets disagree on alignment version.",
         call. = FALSE)
  }
  datasets <- datasets[order(names(datasets), method = "radix")]
  datasets <- lapply(datasets, function(dataset) {
    dataset$patient_keys <- dataset$patient_keys[
      order(names(dataset$patient_keys), method = "radix")]
    dataset$columns <- dataset$columns[
      order(names(dataset$columns), method = "radix")]
    dataset
  })
  resolve_reference <- function(
      data_name, value, default_owner, what) {
    parsed <- .dsvert_dp_capsule_column_reference(value, what)
    dataset <- datasets[[data_name]]
    candidates <- if (is.list(dataset) && is.list(dataset$columns)) {
      names(dataset$columns)[vapply(names(dataset$columns), function(reference) {
        column <- dataset$columns[[reference]]
        physical <- .dsvert_dp_capsule_column_reference(
          reference, "signed synopsis column")$column
        identical(physical, parsed$column) &&
          (is.null(parsed$owner_peer) ||
             identical(column$owner_peer, parsed$owner_peer))
      }, logical(1L))]
    } else character()
    if (length(candidates) > 1L && is.null(parsed$owner_peer) &&
        !is.null(default_owner)) {
      owned <- candidates[vapply(candidates, function(reference) {
        identical(dataset$columns[[reference]]$owner_peer, default_owner)
      }, logical(1L))]
      if (length(owned) == 1L) candidates <- owned
    }
    if (length(candidates) != 1L) {
      stop("A synopsis workload column is missing or ambiguous.",
           call. = FALSE)
    }
    candidates[[1L]]
  }
  for (family in names(workload)) {
    for (analysis_id in names(workload[[family]])) {
      entry <- workload[[family]][[analysis_id]]
      spec <- entry$spec
      owner <- entry$owner_peer
      if (identical(family, "describe")) {
        old <- spec$variables
        spec$variables <- unname(vapply(old, function(reference) {
          resolve_reference(spec$dataset, reference, owner,
                            "describe column")
        }, character(1L)))
        if (is.list(spec$histogram_grids) && !is.null(
              names(spec$histogram_grids))) {
          names(spec$histogram_grids) <- spec$variables[match(
            names(spec$histogram_grids), old)]
        }
      } else if (identical(family, "survival")) {
        for (field in c("time", "event", "entry")) {
          if (!is.null(spec[[field]])) spec[[field]] <- resolve_reference(
            spec$dataset, spec[[field]], owner, "survival column")
        }
      } else if (identical(family, "gaussian")) {
        spec$outcome <- resolve_reference(
          spec$dataset, spec$outcome, owner, "Gaussian outcome")
        if (identical(spec$version, "random_intercept_v1")) {
          spec$cluster <- resolve_reference(
            spec$dataset, spec$cluster, owner, "LMM cluster")
        } else {
          spec$predictors <- unname(vapply(spec$predictors, function(reference) {
            resolve_reference(spec$dataset, reference, owner,
                              "Gaussian predictor")
          }, character(1L)))
        }
      } else if (identical(family, "vertical_cross")) {
        spec$left <- resolve_reference(
          spec$left_dataset, spec$left, owner, "vertical-cross left column")
        spec$right <- resolve_reference(
          spec$right_dataset, spec$right, owner,
          "vertical-cross right column")
      }
      entry$spec <- spec
      workload[[family]][[analysis_id]] <- entry
    }
  }
  workload <- lapply(workload, function(entries) {
    if (!length(entries)) return(list())
    entries[order(names(entries), method = "radix")]
  })
  workload <- .dsvert_dp_canonical_query_value(c(
    list(version = .DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION),
    workload))
  snapshot <- .dsvert_dp_capsule_manifest_expected_snapshot(
    policy, datasets, unique(alignment_versions), workload)
  schema <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_CAPSULE_SCHEMA_VERSION,
    logical_snapshot = snapshot,
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = datasets))
  list(
    schema = schema, schema_json = .dsvert_dp_canonical_json(schema),
    schema_sha256 = .dsvert_joint_dp_hash(schema),
    workload = workload,
    workload_json = .dsvert_dp_canonical_json(workload),
    workload_sha256 = .dsvert_joint_dp_hash(workload),
    logical_snapshot = snapshot)
}

.dsvert_dp_synopsis_manifest_store_path_v1 <- function(policy) {
  path <- paste0(policy$synopsis_state_path, ".manifest-v1.sqlite")
  .dsvert_dp_assert_private_file(
    path, "synopsis manifest store",
    require_private = isTRUE(policy$state_private))
  path
}

.dsvert_dp_synopsis_store_backpressure_v1 <- function(scope, parent) {
  condition <- structure(list(
    message = paste0(
      "[dsvert_resource_backpressure:v1] resource_backpressure: ", scope,
      " is temporarily busy; retry the identical durable operation."),
    call = NULL, code = "resource_backpressure", retryable = TRUE,
    scope = scope, retained_bytes = NA_real_, requested_bytes = 0,
    capacity_bytes = NA_real_, parent = parent),
    class = c("dsvert_resource_backpressure", "error", "condition"))
  stop(condition)
}

.dsvert_dp_synopsis_store_busy_v1 <- function(error, scope) {
  message <- if (inherits(error, "condition")) {
    conditionMessage(error)
  } else {
    ""
  }
  sqlite_busy <- grepl(
    "(^|[^[:alpha:]])(database is (locked|busy)|SQLITE_(BUSY|LOCKED))",
    message, ignore.case = TRUE, perl = TRUE)
  if (!isTRUE(sqlite_busy)) stop(error)
  .dsvert_dp_synopsis_store_backpressure_v1(scope, error)
}

.dsvert_dp_synopsis_manifest_mac_v1 <- function(
    secret, domain, value) {
  if (!is.raw(secret) || length(secret) != 32L ||
      !is.character(domain) || length(domain) != 1L || is.na(domain) ||
      !is.character(value) || length(value) != 1L || is.na(value)) {
    stop("Invalid synopsis manifest authentication input.", call. = FALSE)
  }
  digest::hmac(
    key = secret, object = charToRaw(paste0(
      "dsVert/stateless-catalog-synopsis/manifest-store/v1|",
      domain, "|", value)),
    algo = "sha256", serialize = FALSE, raw = FALSE)
}

.dsvert_dp_synopsis_manifest_local_authority_v1 <- function(
    policy, secret) {
  context <- .dsvert_dp_synopsis_policy_context_v1(policy)
  private <- .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_POLICY_VERSION,
    common = context$common,
    local_draft = .dsvert_dp_capsule_manifest_draft_unsigned(policy),
    private_datasets = policy$datasets,
    peer_name = policy$peer_name)))
  .dsvert_dp_synopsis_manifest_mac_v1(
    secret, "local-authority", private)
}

.dsvert_dp_synopsis_manifest_schema_statements_v1 <- function() c(
  paste(
      "CREATE TABLE synopsis_manifest_meta (key TEXT PRIMARY KEY,",
      "value TEXT NOT NULL, row_mac TEXT NOT NULL) WITHOUT ROWID"),
  paste(
      "CREATE TABLE synopsis_manifests (",
      "cache_key TEXT PRIMARY KEY, manifest_sha256 TEXT NOT NULL UNIQUE,",
      "record_json TEXT NOT NULL, row_mac TEXT NOT NULL) WITHOUT ROWID"),
  paste(
      "CREATE TABLE synopsis_compilations (",
      "manifest_sha256 TEXT PRIMARY KEY, artifact_key TEXT NOT NULL UNIQUE,",
      "complete INTEGER NOT NULL CHECK(complete IN (0,1)),",
      "record_json TEXT NOT NULL, row_mac TEXT NOT NULL) WITHOUT ROWID"))

.dsvert_dp_synopsis_manifest_schema_rows_v1 <- function(connection) {
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT type,name,tbl_name,sql FROM sqlite_master",
    "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,tbl_name,name"))
  rows$sql <- vapply(rows$sql, function(value) {
    if (is.na(value)) return(NA_character_)
    gsub("[[:space:]]+", " ", trimws(value), perl = TRUE)
  }, character(1L))
  rownames(rows) <- NULL
  rows
}

.dsvert_dp_synopsis_manifest_schema_expected_v1 <- local({
  value <- NULL
  function() {
    if (!is.null(value)) return(value)
    connection <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
    on.exit(DBI::dbDisconnect(connection), add = TRUE)
    for (statement in .dsvert_dp_synopsis_manifest_schema_statements_v1()) {
      DBI::dbExecute(connection, statement)
    }
    value <<- .dsvert_dp_synopsis_manifest_schema_rows_v1(connection)
    value
  }
})

.dsvert_dp_synopsis_manifest_store_validate_v1 <- function(
    connection, secret) {
  if (!identical(
      .dsvert_dp_synopsis_manifest_schema_rows_v1(connection),
      .dsvert_dp_synopsis_manifest_schema_expected_v1())) {
    stop(paste(
      "Unsupported synopsis manifest-store schema; an explicit",
      "authenticated migration is required."), call. = FALSE)
  }
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT key,value,row_mac FROM synopsis_manifest_meta",
    "ORDER BY key"))
  expected_meta <- list(
    schema_version = .DSVERT_DP_SYNOPSIS_MANIFEST_STORE_SCHEMA_VERSION,
    store_binding = .dsvert_joint_dp_hash(list(
      protocol = .DSVERT_DP_SYNOPSIS_MANIFEST_STORE_SCHEMA_VERSION,
      purpose = "authenticated_manifest_and_compilation_replay")))
  valid <- nrow(rows) == length(expected_meta) &&
    setequal(rows$key, names(expected_meta)) && all(vapply(
      seq_len(nrow(rows)), function(index) {
        key <- rows$key[[index]]
        identical(rows$value[[index]], expected_meta[[key]]) &&
          .dsvert_joint_dp_dsi_hex_equal(
            rows$row_mac[[index]],
            .dsvert_dp_synopsis_manifest_mac_v1(
              secret, "meta", paste0(key, "|", rows$value[[index]])))
      }, logical(1L)))
  if (!isTRUE(valid)) {
    stop("The synopsis manifest-store metadata failed authentication.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_dp_synopsis_manifest_store_schema_v1 <- function(
    connection, secret) {
  rows <- .dsvert_dp_synopsis_manifest_schema_rows_v1(connection)
  if (!nrow(rows)) {
    DBI::dbExecute(connection, "BEGIN IMMEDIATE")
    committed <- FALSE
    on.exit(if (!committed) try(
      DBI::dbRollback(connection), silent = TRUE), add = TRUE)
    for (statement in .dsvert_dp_synopsis_manifest_schema_statements_v1()) {
      DBI::dbExecute(connection, statement)
    }
    meta <- list(
      schema_version = .DSVERT_DP_SYNOPSIS_MANIFEST_STORE_SCHEMA_VERSION,
      store_binding = .dsvert_joint_dp_hash(list(
        protocol = .DSVERT_DP_SYNOPSIS_MANIFEST_STORE_SCHEMA_VERSION,
        purpose = "authenticated_manifest_and_compilation_replay")))
    for (key in names(meta)) {
      DBI::dbExecute(connection, paste(
        "INSERT INTO synopsis_manifest_meta(key,value,row_mac)",
        "VALUES(?,?,?)"), params = list(
          key, meta[[key]], .dsvert_dp_synopsis_manifest_mac_v1(
            secret, "meta", paste0(key, "|", meta[[key]]))))
    }
    DBI::dbCommit(connection)
    committed <- TRUE
  }
  .dsvert_dp_synopsis_manifest_store_validate_v1(connection, secret)
}

.dsvert_dp_synopsis_store_readonly_with_v1 <- function(
    path, what, require_private, validate, code) {
  if (!is.character(path) || length(path) != 1L || is.na(path) ||
      !nzchar(path) || !is.character(what) || length(what) != 1L ||
      is.na(what) || !nzchar(what) || !is.function(validate) ||
      !is.function(code)) {
    stop("Invalid synopsis read-only store dependency.", call. = FALSE)
  }
  paths <- c(
    store = path, lock = paste0(path, ".lock"),
    wal = paste0(path, "-wal"), shm = paste0(path, "-shm"),
    journal = paste0(path, "-journal"))
  for (label in names(paths)) {
    candidate <- paths[[label]]
    if (.dsvert_dp_path_is_link(candidate) || file.exists(candidate)) {
      .dsvert_dp_assert_private_file(
        candidate, paste(what, label), require_private)
    }
  }
  if (!file.exists(path)) {
    if (any(vapply(paths[-1L], function(candidate) {
      .dsvert_dp_path_is_link(candidate) || file.exists(candidate)
    }, logical(1L)))) {
      stop("The differential-privacy ", what,
           " has orphaned SQLite sidecars", call. = FALSE)
    }
    stop(.dsvert_phase_not_ready_condition())
  }
  connection <- tryCatch(
    DBI::dbConnect(
      RSQLite::SQLite(), path, flags = RSQLite::SQLITE_RO,
      synchronous = NULL, loadable.extensions = FALSE,
      default.extensions = FALSE),
    error = function(error) {
      if (!file.exists(path)) stop(.dsvert_phase_not_ready_condition())
      .dsvert_dp_synopsis_store_busy_v1(error, what)
    })
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  tryCatch({
    DBI::dbExecute(connection, "PRAGMA query_only=ON")
    DBI::dbBegin(connection)
    completed <- FALSE
    on.exit(if (!completed) try(
      DBI::dbRollback(connection), silent = TRUE), add = TRUE)
    validate(connection)
    value <- code(connection)
    DBI::dbCommit(connection)
    completed <- TRUE
    value
  }, error = function(error) {
    .dsvert_dp_synopsis_store_busy_v1(error, what)
  })
}

.dsvert_dp_synopsis_manifest_store_readonly_with_v1 <- function(
    policy, secret, code) {
  if (!.dsvert_dp_synopsis_policy_is_v1(policy) ||
      !is.function(code)) {
    stop("Invalid synopsis manifest store dependency.", call. = FALSE)
  }
  path <- .dsvert_dp_synopsis_manifest_store_path_v1(policy)
  .dsvert_dp_synopsis_store_readonly_with_v1(
    path, "synopsis manifest store", isTRUE(policy$state_private),
    function(connection) {
      .dsvert_dp_synopsis_manifest_store_validate_v1(connection, secret)
    }, code)
}

.dsvert_dp_synopsis_manifest_store_with_v1 <- function(
    policy, secret, code) {
  if (!.dsvert_dp_synopsis_policy_is_v1(policy) ||
      !is.function(code)) {
    stop("Invalid synopsis manifest store dependency.", call. = FALSE)
  }
  path <- .dsvert_dp_synopsis_manifest_store_path_v1(policy)
  private <- isTRUE(policy$state_private)
  paths <- c(
    store = path, lock = paste0(path, ".lock"),
    wal = paste0(path, "-wal"), shm = paste0(path, "-shm"))
  for (label in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[label]], paste("synopsis manifest store", label), private)
  }
  previous_umask <- Sys.umask("0077")
  on.exit(Sys.umask(previous_umask), add = TRUE)
  lock <- filelock::lock(
    paths[["lock"]], timeout = policy$lock_timeout_ms %||% 30000)
  if (is.null(lock)) {
    .dsvert_dp_synopsis_store_backpressure_v1(
      "synopsis manifest store lock",
      simpleError("The synopsis manifest store lock acquisition timed out."))
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  connection <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(connection), add = TRUE)
  DBI::dbExecute(connection, "PRAGMA busy_timeout=30000")
  DBI::dbExecute(connection, "PRAGMA journal_mode=WAL")
  DBI::dbExecute(connection, "PRAGMA synchronous=FULL")
  tryCatch({
    .dsvert_dp_synopsis_manifest_store_schema_v1(connection, secret)
    .dsvert_dp_chmod_private_files(paths)
    code(connection)
  }, error = function(error) {
    .dsvert_dp_synopsis_store_busy_v1(
      error, "synopsis manifest store")
  })
}

.dsvert_dp_synopsis_manifest_record_decode_v1 <- function(
    row, secret, expected_cache_key = NULL,
    expected_manifest_sha256 = NULL) {
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !all(c("cache_key", "manifest_sha256", "record_json", "row_mac") %in%
           names(row))) {
    stop("Invalid synopsis manifest record.", call. = FALSE)
  }
  record <- tryCatch(jsonlite::fromJSON(
    row$record_json[[1L]], simplifyVector = FALSE),
    error = function(error) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(record),
                        error = function(error) NULL)
  fields <- c(
    "version", "cache_key", "public_capsule_key",
    "local_authority_sha256", "schema_sha256",
    "workload_contract_sha256", "manifest_sha256", "manifest_json",
    "policy_snapshot")
  snapshot <- tryCatch(
    .dsvert_dp_synopsis_policy_snapshot_validate_v1(
      record$policy_snapshot), error = function(error) NULL)
  valid <- is.list(record) && !is.null(names(record)) &&
    !anyNA(names(record)) && !anyDuplicated(names(record)) &&
    setequal(names(record), fields) &&
    identical(record$version,
              .DSVERT_DP_SYNOPSIS_MANIFEST_CACHE_VERSION) &&
    identical(canonical, row$record_json[[1L]]) &&
    identical(record$cache_key, row$cache_key[[1L]]) &&
    identical(record$manifest_sha256, row$manifest_sha256[[1L]]) &&
    identical(record$manifest_sha256, digest::digest(
      record$manifest_json, algo = "sha256", serialize = FALSE)) &&
    !is.null(snapshot) && identical(
      record$local_authority_sha256,
      .dsvert_dp_synopsis_manifest_local_authority_v1(
        snapshot$policy, secret)) &&
    .dsvert_joint_dp_dsi_hex_equal(
      row$row_mac[[1L]], .dsvert_dp_synopsis_manifest_mac_v1(
        secret, "record", row$record_json[[1L]])) &&
    (is.null(expected_cache_key) ||
       identical(record$cache_key, expected_cache_key)) &&
    (is.null(expected_manifest_sha256) ||
       identical(record$manifest_sha256, expected_manifest_sha256))
  if (!isTRUE(valid)) {
    stop("The synopsis manifest store failed authentication.",
         call. = FALSE)
  }
  record
}

.dsvert_dp_synopsis_manifest_cache_get_v1 <- function(
    policy, secret, cache_key = NULL, manifest_sha256 = NULL) {
  if (xor(is.null(cache_key), is.null(manifest_sha256)) == FALSE) {
    stop("Exactly one synopsis manifest selector is required.",
         call. = FALSE)
  }
  .dsvert_dp_synopsis_manifest_store_with_v1(
    policy, secret, function(connection) {
      field <- if (is.null(cache_key)) "manifest_sha256" else "cache_key"
      selector <- if (is.null(cache_key)) manifest_sha256 else cache_key
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT cache_key,manifest_sha256,record_json,row_mac",
        "FROM synopsis_manifests WHERE", field, "=?"),
        params = list(selector))
      if (!nrow(row)) return(NULL)
      .dsvert_dp_synopsis_manifest_record_decode_v1(
        row, secret, expected_cache_key = cache_key,
        expected_manifest_sha256 = manifest_sha256)
    })
}

.dsvert_dp_synopsis_manifest_cache_get_readonly_v1 <- function(
    policy, secret, cache_key = NULL, manifest_sha256 = NULL) {
  if (xor(is.null(cache_key), is.null(manifest_sha256)) == FALSE) {
    stop("Exactly one synopsis manifest selector is required.",
         call. = FALSE)
  }
  .dsvert_dp_synopsis_manifest_store_readonly_with_v1(
    policy, secret, function(connection) {
      field <- if (is.null(cache_key)) "manifest_sha256" else "cache_key"
      selector <- if (is.null(cache_key)) manifest_sha256 else cache_key
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT cache_key,manifest_sha256,record_json,row_mac",
        "FROM synopsis_manifests WHERE", field, "=?"),
        params = list(selector))
      if (!nrow(row)) return(NULL)
      .dsvert_dp_synopsis_manifest_record_decode_v1(
        row, secret, expected_cache_key = cache_key,
        expected_manifest_sha256 = manifest_sha256)
    })
}

.dsvert_dp_synopsis_manifest_cache_put_v1 <- function(
    policy, secret, record) {
  snapshot <- .dsvert_dp_synopsis_policy_snapshot_validate_v1(
    record$policy_snapshot, policy$synopsis_state_path)
  expected_snapshot <- .dsvert_dp_synopsis_policy_snapshot_v1(policy)
  if (!identical(
        .dsvert_dp_canonical_json(snapshot$wire),
        .dsvert_dp_canonical_json(expected_snapshot)) ||
      !identical(
        record$local_authority_sha256,
        .dsvert_dp_synopsis_manifest_local_authority_v1(policy, secret))) {
    stop("The synopsis manifest policy snapshot is inconsistent.",
         call. = FALSE)
  }
  json <- .dsvert_dp_canonical_json(record)
  mac <- .dsvert_dp_synopsis_manifest_mac_v1(secret, "record", json)
  .dsvert_dp_synopsis_manifest_store_with_v1(
    policy, secret, function(connection) {
      DBI::dbExecute(connection, "BEGIN IMMEDIATE")
      committed <- FALSE
      on.exit(if (!committed) try(
        DBI::dbRollback(connection), silent = TRUE), add = TRUE)
      DBI::dbExecute(connection, paste(
        "INSERT OR IGNORE INTO synopsis_manifests(",
        "cache_key,manifest_sha256,record_json,row_mac) VALUES(?,?,?,?)"),
        params = list(
          record$cache_key, record$manifest_sha256, json, mac))
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT cache_key,manifest_sha256,record_json,row_mac",
        "FROM synopsis_manifests WHERE cache_key=?"),
        params = list(record$cache_key))
      observed <- .dsvert_dp_synopsis_manifest_record_decode_v1(
        row, secret, expected_cache_key = record$cache_key)
      if (!identical(
            .dsvert_dp_canonical_json(observed),
            .dsvert_dp_canonical_json(record))) {
        stop("A conflicting synopsis manifest is already memoized.",
             call. = FALSE)
      }
      DBI::dbCommit(connection)
      committed <- TRUE
      observed
    })
}

.dsvert_dp_synopsis_policy_for_manifest_v1 <- function(
    manifest_sha256, secret, state_path = NULL, .with_manifest = FALSE) {
  if (!is.logical(.with_manifest) || length(.with_manifest) != 1L ||
      is.na(.with_manifest)) {
    stop("Invalid synopsis policy-context selector.", call. = FALSE)
  }
  if (is.null(state_path)) {
    state_path <- .dsvert_dp_synopsis_state_path_v1()
  }
  locator <- list(
    policy_contract = .DSVERT_DP_SYNOPSIS_POLICY_CONTRACT,
    synopsis_state_path = .dsvert_dp_scalar_string(
      state_path, "durable synopsis state path"),
    state_private = TRUE, lock_timeout_ms = 30000L)
  record <- .dsvert_dp_synopsis_manifest_cache_get_readonly_v1(
    locator, secret, manifest_sha256 = .dsvert_dp_synopsis_hex_v1(
      manifest_sha256, "durable policy manifest selector"))
  if (is.null(record)) stop(.dsvert_phase_not_ready_condition())
  snapshot <- .dsvert_dp_synopsis_policy_snapshot_validate_v1(
    record$policy_snapshot, locator$synopsis_state_path)
  if (isTRUE(.with_manifest)) {
    return(list(policy = snapshot$policy, manifest_json = record$manifest_json))
  }
  snapshot$policy
}

.dsvert_dp_synopsis_compilation_record_decode_v1 <- function(
    row, secret) {
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !all(c("manifest_sha256", "artifact_key", "complete",
             "record_json", "row_mac") %in% names(row))) {
    stop("Invalid synopsis compilation record.", call. = FALSE)
  }
  record <- tryCatch(jsonlite::fromJSON(
    row$record_json[[1L]], simplifyVector = FALSE),
    error = function(error) NULL)
  canonical <- tryCatch(.dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(record)),
    error = function(error) NULL)
  fields <- c(
    "version", "manifest_sha256", "artifact_key", "artifact",
    "local_receipt", "receipts", "receipt_set_sha256", "complete")
  valid <- is.list(record) && !is.null(names(record)) &&
    !anyNA(names(record)) && !anyDuplicated(names(record)) &&
    setequal(names(record), fields) &&
    identical(record$version,
              .DSVERT_DP_SYNOPSIS_COMPILATION_RECORD_VERSION) &&
    identical(canonical, row$record_json[[1L]]) &&
    identical(record$manifest_sha256, row$manifest_sha256[[1L]]) &&
    identical(record$artifact_key, row$artifact_key[[1L]]) &&
    identical(isTRUE(record$complete),
              identical(as.integer(row$complete[[1L]]), 1L)) &&
    .dsvert_joint_dp_dsi_hex_equal(
      row$row_mac[[1L]], .dsvert_dp_synopsis_manifest_mac_v1(
        secret, "compilation", row$record_json[[1L]]))
  if (!isTRUE(valid)) {
    stop("The synopsis compilation store failed authentication.",
         call. = FALSE)
  }
  record
}

.dsvert_dp_synopsis_compilation_get_v1 <- function(
    policy, secret, manifest_sha256 = NULL, artifact_key = NULL) {
  if (xor(is.null(manifest_sha256), is.null(artifact_key)) == FALSE) {
    stop("Exactly one synopsis compilation selector is required.",
         call. = FALSE)
  }
  .dsvert_dp_synopsis_manifest_store_with_v1(
    policy, secret, function(connection) {
      field <- if (is.null(manifest_sha256)) {
        "artifact_key"
      } else {
        "manifest_sha256"
      }
      selector <- artifact_key %||% manifest_sha256
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT manifest_sha256,artifact_key,complete,record_json,row_mac",
        "FROM synopsis_compilations WHERE", field, "=?"),
        params = list(selector))
      if (!nrow(row)) return(NULL)
      .dsvert_dp_synopsis_compilation_record_decode_v1(row, secret)
    })
}

.dsvert_dp_synopsis_compilation_get_readonly_v1 <- function(
    policy, secret, manifest_sha256 = NULL, artifact_key = NULL) {
  if (xor(is.null(manifest_sha256), is.null(artifact_key)) == FALSE) {
    stop("Exactly one synopsis compilation selector is required.",
         call. = FALSE)
  }
  .dsvert_dp_synopsis_manifest_store_readonly_with_v1(
    policy, secret, function(connection) {
      field <- if (is.null(manifest_sha256)) {
        "artifact_key"
      } else {
        "manifest_sha256"
      }
      selector <- artifact_key %||% manifest_sha256
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT manifest_sha256,artifact_key,complete,record_json,row_mac",
        "FROM synopsis_compilations WHERE", field, "=?"),
        params = list(selector))
      if (!nrow(row)) return(NULL)
      .dsvert_dp_synopsis_compilation_record_decode_v1(row, secret)
    })
}

.dsvert_dp_synopsis_compilation_put_v1 <- function(
    policy, secret, record) {
  json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(record))
  same_record <- function(left, right) identical(
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(left)),
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(right)))
  mac <- .dsvert_dp_synopsis_manifest_mac_v1(
    secret, "compilation", json)
  .dsvert_dp_synopsis_manifest_store_with_v1(
    policy, secret, function(connection) {
      DBI::dbExecute(connection, "BEGIN IMMEDIATE")
      committed <- FALSE
      on.exit(if (!committed) try(
        DBI::dbRollback(connection), silent = TRUE), add = TRUE)
      prior <- DBI::dbGetQuery(connection, paste(
        "SELECT manifest_sha256,artifact_key,complete,record_json,row_mac",
        "FROM synopsis_compilations WHERE manifest_sha256=?"),
        params = list(record$manifest_sha256))
      if (nrow(prior)) {
        existing <- .dsvert_dp_synopsis_compilation_record_decode_v1(
          prior, secret)
        if (!identical(existing$artifact_key, record$artifact_key)) {
          stop(paste(
            "The immutable synopsis manifest produced a different artifact;",
            "rotate its custodian snapshot version before retrying."),
          call. = FALSE)
        }
        same <- c("manifest_sha256", "artifact_key", "artifact",
                  "local_receipt")
        if (isTRUE(existing$complete)) {
          if (!same_record(existing[same], record[same]) ||
              (isTRUE(record$complete) &&
               !same_record(existing, record))) {
            stop("Conflicting synopsis compilation replay.",
                 call. = FALSE)
          }
          return(existing)
        }
        if (!isTRUE(record$complete)) {
          if (!same_record(existing[same], record[same])) {
            stop("Conflicting synopsis compilation replay.",
                 call. = FALSE)
          }
          return(existing)
        }
        DBI::dbExecute(connection, paste(
          "UPDATE synopsis_compilations SET complete=1,record_json=?,",
          "row_mac=? WHERE manifest_sha256=?"),
          params = list(json, mac, record$manifest_sha256))
      } else {
        DBI::dbExecute(connection, paste(
          "INSERT INTO synopsis_compilations(",
          "manifest_sha256,artifact_key,complete,record_json,row_mac)",
          "VALUES(?,?,?,?,?)"), params = list(
            record$manifest_sha256, record$artifact_key,
            as.integer(isTRUE(record$complete)), json, mac))
      }
      row <- DBI::dbGetQuery(connection, paste(
        "SELECT manifest_sha256,artifact_key,complete,record_json,row_mac",
        "FROM synopsis_compilations WHERE manifest_sha256=?"),
        params = list(record$manifest_sha256))
      observed <- .dsvert_dp_synopsis_compilation_record_decode_v1(
        row, secret)
      if (!same_record(observed, record)) {
        stop("Conflicting synopsis compilation persistence.",
             call. = FALSE)
      }
      DBI::dbCommit(connection)
      committed <- TRUE
      observed
    })
}

.dsvert_dp_synopsis_compilation_register_v1 <- function(
    manifest_sha256, artifact, local_receipt, policy, secret,
    receipts = NULL, receipt_set_sha256 = NULL) {
  manifest_sha256 <- .dsvert_dp_synopsis_hex_v1(
    manifest_sha256, "compilation manifest hash")
  artifact_key <- .dsvert_dp_synopsis_hex_v1(
    artifact$artifact_key, "compilation artifact key")
  complete <- !is.null(receipts)
  if (isTRUE(complete)) {
    receipt_set_sha256 <- .dsvert_dp_synopsis_hex_v1(
      receipt_set_sha256, "compilation receipt-set hash")
  } else {
    receipts <- NULL
    receipt_set_sha256 <- NULL
  }
  record <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_COMPILATION_RECORD_VERSION,
    manifest_sha256 = manifest_sha256, artifact_key = artifact_key,
    artifact = artifact, local_receipt = local_receipt,
    receipts = receipts, receipt_set_sha256 = receipt_set_sha256,
    complete = isTRUE(complete)))
  .dsvert_dp_synopsis_compilation_put_v1(policy, secret, record)
}

.dsvert_dp_synopsis_publication_authority_v1 <- function(
    artifact, policy, require_local = FALSE) {
  semantic <- .dsvert_dp_analysis_synopsis_semantic_validate_v1(
    artifact$semantic)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  roles <- semantic$noise_authority_roles
  identities <- unlist(roles$authority_ids, use.names = FALSE)
  peers <- names(pins)[match(identities, unname(pins))]
  role_names <- unlist(roles$role_order, use.names = FALSE)
  if (length(peers) != 2L || anyNA(peers) || anyDuplicated(peers) ||
      length(role_names) != 2L) {
    stop("Invalid synopsis publication authorities.", call. = FALSE)
  }
  local_peer <- .dsvert_dp_analysis_scalar_id(
    policy$peer_name, "synopsis publication peer")
  position <- match(local_peer, peers)
  if (is.na(position)) {
    if (isTRUE(require_local)) {
      stop("Published replay is available from a noise authority.",
           call. = FALSE)
    }
    position <- 1L
  }
  list(
    peer_name = peers[[position]],
    identity_pk = identities[[position]],
    role = role_names[[position]])
}

.dsvert_dp_synopsis_publication_context_v1 <- function(
    record, policy, secret,
    .cache_get = .dsvert_dp_synopsis_manifest_cache_get_readonly_v1) {
  if (!is.list(record) || !isTRUE(record$complete) ||
      !is.list(record$artifact) || !is.list(record$receipts)) {
    stop("The synopsis publication is not K-wide compiled.", call. = FALSE)
  }
  manifest_json <- .dsvert_dp_synopsis_cached_manifest_v1(
    record$manifest_sha256, policy, secret, .cache_get)
  manifest <- .dsvert_dp_capsule_source_manifest(manifest_json)
  artifact <- .dsvert_dp_synopsis_compact_artifact_validate_v1(
    record$artifact, policy, manifest)
  pins <- .dsvert_dp_synopsis_peer_pins_v1(policy$peer_pinset)
  expected <- list(
    version = .DSVERT_DP_SYNOPSIS_COMPILE_RECEIPT_VERSION,
    peer_name = names(pins)[[1L]],
    peer_identity_pk = unname(pins[[1L]]),
    manifest_sha256 = record$manifest_sha256,
    artifact_key = artifact$artifact_key,
    source_claim_set_sha256 =
      artifact$semantic$source_claim_set_sha256,
    full_plan_sha256 = artifact$physical_plan$full_plan_sha256)
  verified <- lapply(
    record$receipts, .dsvert_dp_synopsis_compile_receipt_verify_v1,
    expected = expected, pins = pins)
  peers <- vapply(verified, `[[`, character(1L), "peer_name")
  names(verified) <- peers
  if (anyDuplicated(peers) || !setequal(peers, names(pins))) {
    stop("The synopsis publication compile coverage is invalid.",
         call. = FALSE)
  }
  verified <- verified[names(pins)]
  same_local_receipt <- identical(
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(record$local_receipt)),
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(
      verified[[policy$peer_name]])))
  if (!identical(
        record$receipt_set_sha256,
        .dsvert_dp_synopsis_compile_receipt_set_hash_v1(verified)) ||
      !same_local_receipt) {
    stop("The synopsis publication compilation is inconsistent.",
         call. = FALSE)
  }
  authorization <- list(
    version = .DSVERT_DP_SYNOPSIS_AUTHORIZATION_VERSION,
    session_id = "00000000-0000-4000-8000-000000000000",
    manifest_sha256 = record$manifest_sha256,
    artifact = artifact, artifact_key = artifact$artifact_key,
    source_claim_set_sha256 =
      artifact$semantic$source_claim_set_sha256,
    receipt_peers = as.list(names(verified)),
    receipt_set_sha256 = record$receipt_set_sha256,
    local_authority = .dsvert_dp_synopsis_publication_authority_v1(
      artifact, policy))
  authorization$authorization_sha256 <-
    .dsvert_dp_synopsis_authorization_hash_v1(authorization, secret)
  context <- .dsvert_dp_synopsis_execution_context_from_authorization_v1(
    authorization, policy, secret, .cache_get)
  list(
    record = record, manifest_json = manifest_json,
    manifest = manifest, artifact = artifact,
    receipts = verified, authorization = authorization,
    context = context)
}

.dsvert_dp_synopsis_publication_pair_v1 <- function(
    first_publication_json, second_publication_json, policy, secret,
    expected_manifest_sha256 = NULL, expected_artifact_key = NULL,
    .verifier = .dsvert_relay_verify_message) {
  values <- list(
    .dsvert_dp_synopsis_decode_canonical_v1(
      first_publication_json, "first publication",
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES),
    .dsvert_dp_synopsis_decode_canonical_v1(
      second_publication_json, "second publication",
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES))
  fields <- c(
    "version", "published", "manifest_sha256", "artifact",
    "artifact_key", "compile_receipts", "receipt_set_sha256",
    "public_chunk_count", "release_receipt", "durable_publication",
    "session_required", "source_store_read", "request_limit",
    "rate_limit", "catalog_limit")
  valid <- vapply(values, function(value) {
    is.list(value) && !is.null(names(value)) && !anyNA(names(value)) &&
      !anyDuplicated(names(value)) && setequal(names(value), fields) &&
      identical(value$version, .DSVERT_DP_SYNOPSIS_PUBLICATION_VERSION) &&
      identical(value$published, TRUE) && is.list(value$artifact) &&
      is.list(value$compile_receipts) &&
      is.list(value$release_receipt) &&
      .dsvert_dp_synopsis_integer_v1(
        value$public_chunk_count, 1, .DSVERT_DP_MAX_COORDINATES) &&
      identical(value$durable_publication, TRUE) &&
      identical(value$session_required, FALSE) &&
      identical(value$source_store_read, FALSE) &&
      identical(value$request_limit, FALSE) &&
      identical(value$rate_limit, FALSE) &&
      identical(value$catalog_limit, FALSE)
  }, logical(1L))
  if (!all(valid)) {
    stop("Invalid durable synopsis publication envelope.", call. = FALSE)
  }
  values <- lapply(values, .dsvert_dp_canonical_query_value)
  common_fields <- setdiff(fields, "release_receipt")
  if (!identical(values[[1L]][common_fields],
                 values[[2L]][common_fields])) {
    stop("The durable synopsis publications do not agree.", call. = FALSE)
  }
  value <- values[[1L]]
  manifest_sha256 <- .dsvert_dp_synopsis_hex_v1(
    value$manifest_sha256, "publication manifest hash")
  artifact_key <- .dsvert_dp_synopsis_hex_v1(
    value$artifact_key, "publication artifact key")
  receipt_set_sha256 <- .dsvert_dp_synopsis_hex_v1(
    value$receipt_set_sha256, "publication receipt-set hash")
  if (!is.null(expected_manifest_sha256) && !identical(
      manifest_sha256, .dsvert_dp_synopsis_hex_v1(
        expected_manifest_sha256, "expected publication manifest hash"))) {
    stop("The publication targets a different synopsis manifest.",
         call. = FALSE)
  }
  if (!is.null(expected_artifact_key) && !identical(
      artifact_key, .dsvert_dp_synopsis_hex_v1(
        expected_artifact_key, "expected publication artifact key"))) {
    stop("The publication targets a different synopsis artifact.",
         call. = FALSE)
  }
  receipt_peers <- vapply(value$compile_receipts, function(receipt) {
    peer <- if (is.list(receipt)) receipt$peer_name else NULL
    if (!is.character(peer) || length(peer) != 1L || is.na(peer)) ""
    else peer
  }, character(1L))
  local_peer <- .dsvert_dp_analysis_scalar_id(
    policy$peer_name, "publication compilation peer")
  if (anyDuplicated(receipt_peers) || !local_peer %in% receipt_peers) {
    stop("Invalid publication compilation coverage.", call. = FALSE)
  }
  names(value$compile_receipts) <- receipt_peers
  record <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_DP_SYNOPSIS_COMPILATION_RECORD_VERSION,
    manifest_sha256 = manifest_sha256,
    artifact_key = artifact_key,
    artifact = value$artifact,
    local_receipt = value$compile_receipts[[local_peer]],
    receipts = value$compile_receipts,
    receipt_set_sha256 = receipt_set_sha256,
    complete = TRUE))
  publication <- .dsvert_dp_synopsis_publication_context_v1(
    record, policy, secret)
  if (!identical(publication$artifact$artifact_key, artifact_key)) {
    stop("The publication artifact binding is invalid.", call. = FALSE)
  }
  releases <- .dsvert_dp_synopsis_execution_release_set_v1(
    values[[1L]]$release_receipt, values[[2L]]$release_receipt,
    publication$context, policy, .verifier)
  if (!identical(as.numeric(value$public_chunk_count), as.numeric(
      publication$context$contract$value$geometry$public_chunk_count))) {
    stop("The publication chunk geometry is invalid.", call. = FALSE)
  }
  list(
    record = record, publication = publication,
    releases = releases, envelopes = values)
}

.dsvert_dp_synopsis_publication_manifest_v1 <- function(
    publication_json) {
  value <- .dsvert_dp_synopsis_decode_canonical_v1(
    publication_json, "publication policy selector",
    .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES)
  if (!is.list(value) || !identical(
      value$version, .DSVERT_DP_SYNOPSIS_PUBLICATION_VERSION)) {
    stop("Invalid durable synopsis publication envelope.", call. = FALSE)
  }
  .dsvert_dp_synopsis_hex_v1(
    value$manifest_sha256, "publication policy manifest selector")
}

.dsvert_dp_synopsis_publication_v1 <- function(
    manifest_sha256, .policy = NULL, .secret = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  manifest_sha256 <- .dsvert_dp_synopsis_hex_v1(
    manifest_sha256, "publication manifest hash")
  if (is.null(.policy)) {
    .policy <- .dsvert_dp_synopsis_policy_for_manifest_v1(
      manifest_sha256, .secret)
  }
  record <- .dsvert_dp_synopsis_compilation_get_readonly_v1(
    .policy, .secret, manifest_sha256 = manifest_sha256)
  if (is.null(record) || !isTRUE(record$complete)) {
    stop(.dsvert_phase_not_ready_condition())
  }
  publication <- .dsvert_dp_synopsis_publication_context_v1(
    record, .policy, .secret)
  context <- publication$context
  durable <- .dsvert_dp_synopsis_execution_with_store_readonly_v1(
    .policy, .secret, function(connection) {
      result_rows <- DBI::dbGetQuery(connection, paste(
        "SELECT record_json,row_mac FROM synopsis_releases",
        "WHERE artifact_key=?"),
        params = list(publication$artifact$artifact_key))
      if (!nrow(result_rows)) return(NULL)
      raw <- .dsvert_dp_synopsis_execution_record_decode_v1(
        result_rows, .secret, "releases",
        publication$artifact$artifact_key, "publication RELEASE",
        .DSVERT_DP_SYNOPSIS_EXECUTION_RESULT_MAX_RECORD_BYTES)
      .dsvert_dp_synopsis_execution_release_load_v1(
        connection, .secret, context, raw$result_set_sha256,
        .policy, .dsvert_relay_verify_message)
    })
  if (is.null(durable)) stop(.dsvert_phase_not_ready_condition())
  list(
    version = .DSVERT_DP_SYNOPSIS_PUBLICATION_VERSION,
    published = TRUE, manifest_sha256 = manifest_sha256,
    artifact = publication$artifact,
    artifact_key = publication$artifact$artifact_key,
    compile_receipts = publication$receipts,
    receipt_set_sha256 = record$receipt_set_sha256,
    public_chunk_count = as.integer(
      durable$receipt$public_chunk_count),
    release_receipt = durable$receipt,
    durable_publication = TRUE,
    session_required = FALSE, source_store_read = FALSE,
    request_limit = FALSE, rate_limit = FALSE,
    catalog_limit = FALSE)
}

.dsvert_dp_synopsis_publication_replay_v1 <- function(
    artifact_key, first_release_json, second_release_json,
    public_chunk_index, .policy = NULL, .secret = NULL,
    .verifier = .dsvert_relay_verify_message) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (is.null(.policy)) {
    .policy <- .dsvert_dp_synopsis_policy_for_manifest_v1(
      .dsvert_dp_synopsis_publication_manifest_v1(first_release_json),
      .secret)
  }
  pair <- .dsvert_dp_synopsis_publication_pair_v1(
    first_release_json, second_release_json, .policy, .secret,
    expected_artifact_key = artifact_key, .verifier = .verifier)
  publication <- pair$publication
  context <- publication$context
  local_authority <- .dsvert_dp_synopsis_publication_authority_v1(
    publication$artifact, .policy, require_local = TRUE)
  if (!identical(context$authorization$local_authority,
                 local_authority)) {
    stop("Invalid local publication authority.", call. = FALSE)
  }
  releases <- pair$releases
  public_chunk <- .dsvert_dp_synopsis_execution_public_chunk_v1(
    context, public_chunk_index)
  own <- releases[[local_authority$peer_name]]
  durable <- .dsvert_dp_synopsis_execution_with_store_readonly_v1(
    .policy, .secret, function(connection) list(
      release = .dsvert_dp_synopsis_execution_release_load_v1(
        connection, .secret, context, own$result_set_sha256,
        .policy, .verifier),
      public = .dsvert_dp_synopsis_execution_public_load_v1(
        connection, .secret, context, own$result_set_sha256,
        public_chunk)))
  if (is.null(durable$release) || is.null(durable$public) ||
      !identical(
        .dsvert_dp_synopsis_execution_record_json_v1(own),
        .dsvert_dp_synopsis_execution_record_json_v1(
          durable$release$receipt))) {
    stop("The signed synopsis publication is unavailable locally.",
         call. = FALSE)
  }
  hashes <- unlist(own$final_chunk_hashes, use.names = FALSE)
  if (!identical(
        durable$public$chunk_sha256,
        hashes[[public_chunk$index + 1L]])) {
    stop("The published synopsis chunk conflicts with its RELEASE.",
         call. = FALSE)
  }
  list(
    version = .DSVERT_DP_SYNOPSIS_EXECUTION_REPLAY_VERSION,
    phase = "synopsis_public_chunk_replayed",
    execution_id = context$execution_id,
    artifact_key = publication$artifact$artifact_key,
    contract_sha256 = context$contract$sha256,
    attempt_sha256 = context$attempt$sha256,
    source_contract_sha256 =
      context$attempt$value$source_contract_sha256,
    result_set_sha256 = own$result_set_sha256,
    final_vector_root = own$final_vector_root,
    public_chunk_index = public_chunk$index,
    public_chunk_count = as.integer(
      context$contract$value$geometry$public_chunk_count),
    chunk_sha256 = durable$public$chunk_sha256,
    chunk = durable$public$public_chunk,
    merkle_proof = .dsvert_joint_dp_vector_merkle_proof(
      hashes, public_chunk$index),
    durable_replay = TRUE, source_store_read = FALSE,
    sampler_invoked = FALSE, finalizer_invoked = FALSE,
    transport_read = FALSE)
}

.dsvert_dp_synopsis_finalize_ack_message_v1 <- function(value) {
  unsigned <- value[setdiff(names(value), "signature")]
  charToRaw(paste0(
    .DSVERT_DP_SYNOPSIS_FINALIZE_ACK_DOMAIN,
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_dp_synopsis_finalize_ack_v1 <- function(
    manifest_sha256, first_release_json, second_release_json,
    .policy = NULL, .secret = NULL, .identity = NULL,
    .verifier = .dsvert_relay_verify_message,
    .signer = .dsvert_relay_sign_message,
    .source_compactor =
      .dsvert_dp_capsule_source_compact_after_vector_release_internal) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  manifest_sha256 <- .dsvert_dp_synopsis_hex_v1(
    manifest_sha256, "finalize manifest hash")
  if (is.null(.policy)) {
    .policy <- .dsvert_dp_synopsis_policy_for_manifest_v1(
      manifest_sha256, .secret)
  }
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  pair <- .dsvert_dp_synopsis_publication_pair_v1(
    first_release_json, second_release_json, .policy, .secret,
    expected_manifest_sha256 = manifest_sha256,
    .verifier = .verifier)
  publication <- pair$publication
  context <- publication$context
  releases <- pair$releases
  local_peer <- .dsvert_dp_analysis_scalar_id(
    .policy$peer_name, "finalize acknowledgement peer")
  pins <- .dsvert_dp_synopsis_peer_pins_v1(.policy$peer_pinset)
  if (!is.list(.identity) || is.null(.identity$identity_pk) ||
      is.null(.identity$identity_sk) || !is.function(.signer) ||
      !identical(
        .dsvert_relay_normalize_identity_pk(.identity$identity_pk),
        unname(pins[[local_peer]]))) {
    stop("The FinalizeAck identity is not pinned.", call. = FALSE)
  }
  record <- pair$record
  .dsvert_dp_synopsis_compilation_register_v1(
    record$manifest_sha256, record$artifact, record$local_receipt,
    .policy, .secret, receipts = record$receipts,
    receipt_set_sha256 = record$receipt_set_sha256)
  if (local_peer %in% names(releases)) {
    own <- releases[[local_peer]]
    durable <- .dsvert_dp_synopsis_execution_with_store_readonly_v1(
      .policy, .secret, function(connection) {
        .dsvert_dp_synopsis_execution_release_load_v1(
          connection, .secret, context, own$result_set_sha256,
          .policy, .verifier)
      })
    if (is.null(durable) || !identical(
          .dsvert_dp_synopsis_execution_record_json_v1(own),
          .dsvert_dp_synopsis_execution_record_json_v1(durable$receipt))) {
      stop("FinalizeAck requires the durable local synopsis publication.",
           call. = FALSE)
    }
  }
  source_contract <- context$source_contract
  ordered <- releases[order(names(releases), method = "radix")]
  reference <- ordered[[1L]]
  authorization <- list(
    version = .DSVERT_DP_CAPSULE_SOURCE_COMPACTION_AUTH_VERSION,
    capsule_id = source_contract$capsule_id,
    source_contract_hash = .dsvert_joint_dp_hash(source_contract),
    release_instance_id = context$execution_id,
    release_contract_hash = context$contract$sha256,
    final_vector_root = reference$final_vector_root,
    result_set_hash = reference$result_set_sha256,
    final_chunk_commitments_sha256 = .dsvert_joint_dp_hash(
      reference$final_chunk_hashes),
    release_receipts_sha256 = .dsvert_joint_dp_hash(lapply(
      ordered, .dsvert_dp_canonical_query_value)),
    durable_release_receipts_verified = TRUE,
    public_release_memoized = TRUE,
    final_chunks_retained = TRUE)
  authorization <-
    .dsvert_dp_capsule_source_compaction_authorization_seal(
      .dsvert_dp_canonical_query_value(authorization), .secret)
  compacted <- .source_compactor(
    .policy, publication$manifest_json, authorization, .secret,
    source_contract = source_contract)
  peer <- local_peer
  unsigned <- list(
    version = .DSVERT_DP_SYNOPSIS_FINALIZE_ACK_VERSION,
    artifact_key = publication$artifact$artifact_key,
    manifest_sha256 = manifest_sha256,
    peer_name = peer, peer_identity_pk = unname(pins[[peer]]),
    release_receipts_sha256 = authorization$release_receipts_sha256,
    compaction_authorization_sha256 =
      .dsvert_joint_dp_hash(authorization),
    source_compaction_receipt_sha256 =
      .dsvert_joint_dp_hash(compacted),
    source_intermediates_compacted = TRUE,
    durable_replay_retained = TRUE, idempotent = TRUE,
    session_required = FALSE, request_limit = FALSE,
    rate_limit = FALSE, catalog_limit = FALSE)
  c(unsigned, list(signature = .dsvert_dp_synopsis_signature_v1(.signer(
    .dsvert_dp_synopsis_finalize_ack_message_v1(unsigned),
    .identity$identity_sk))))
}

.dsvert_dp_synopsis_manifest_build_v1 <- function(
    signed_schema, workload, policy, secret,
    local_projection = NULL,
    .verifier = .dsvert_relay_verify_message) {
  requested_scope <- if (is.null(local_projection)) NULL else
    .dsvert_dp_synopsis_projection_scope_v1(local_projection)
  schema_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(signed_schema))
  workload_json <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(workload))
  signed <- .dsvert_dp_capsule_manifest_signed_schema(
    schema_json, workload_json, policy, .verifier,
    .primitive_scope = requested_scope)
  projection_schema <- list(
    schema = signed$validated$unsigned,
    schema_sha256 = signed$validated$sha256,
    workload = signed$workload$value,
    workload_sha256 = signed$workload$sha256,
    logical_snapshot = signed$validated$unsigned$logical_snapshot)
  selector <- if (is.null(local_projection)) NULL else {
    projected_policy <- policy
    projected_policy$capsule_workload_scope <- requested_scope
    .dsvert_dp_synopsis_projection_validate_v1(
      local_projection, projection_schema, projected_policy)
  }
  primitive_scope <- if (is.null(selector)) {
    .dsvert_dp_capsule_scope_policy_binding(policy$capsule_workload_scope)
  } else {
    .dsvert_dp_synopsis_projection_scope_v1(selector)
  }
  local_authority <- .dsvert_dp_synopsis_manifest_local_authority_v1(
    policy, secret)
  public_authority <- list(
    protocol = "dsvert-stateless-catalog-synopsis-public-authority-v1",
    capsule_schema = .DSVERT_DP_CAPSULE_WORKLOAD_VERSION,
    schema_sha256 = signed$validated$sha256,
    workload_contract_sha256 = signed$workload$sha256,
    primitive_scope = primitive_scope)
  cache_authority <- c(list(
    protocol = .DSVERT_DP_SYNOPSIS_MANIFEST_CACHE_VERSION), if (
      is.null(selector)) {
    list(local_policy_sha256 = local_authority)
  } else {
    list(projection_only = TRUE)
  }, list(
    signed_schema = signed$value,
    workload_contract = signed$workload$value,
    primitive_scope = primitive_scope))
  if (!is.null(selector)) {
    public_authority$local_projection_sha256 <- selector$sha256
    cache_authority$local_projection_sha256 <- selector$sha256
  }
  public_capsule_key <- .dsvert_joint_dp_hash(public_authority)
  cache_key <- .dsvert_joint_dp_hash(cache_authority)
  record <- .dsvert_dp_synopsis_manifest_cache_get_v1(
    policy, secret, cache_key = cache_key)
  if (is.null(record)) {
    specs <- if (is.null(selector) ||
        .dsvert_dp_synopsis_projection_is_cross_v1(selector)) {
      signed$workload$specs
    } else list(
      describe = list(), survival = list(), gaussian = list(),
      vertical_cross = list())
    manifest <- .dsvert_dp_capsule_workload_manifest(
      policy, signed$validated$unsigned$logical_snapshot, signed$value,
      describe_specs = specs$describe,
      survival_specs = specs$survival,
      gaussian_specs = specs$gaussian,
      vertical_cross_specs = specs$vertical_cross,
      .signature_verifier = .verifier,
      .primitive_scope = if (is.null(selector)) NULL else primitive_scope)
    manifest_json <- .dsvert_dp_canonical_json(manifest)
    if (nchar(manifest_json, type = "bytes") >
        .DSVERT_DP_CAPSULE_MANIFEST_MAX_MANIFEST_BYTES) {
      stop("The synopsis manifest exceeds its protocol byte bound.",
           call. = FALSE)
    }
    record <- .dsvert_dp_canonical_query_value(list(
      version = .DSVERT_DP_SYNOPSIS_MANIFEST_CACHE_VERSION,
      cache_key = cache_key, public_capsule_key = public_capsule_key,
      local_authority_sha256 = local_authority,
      schema_sha256 = signed$validated$sha256,
      workload_contract_sha256 = signed$workload$sha256,
      manifest_sha256 = digest::digest(
        manifest_json, algo = "sha256", serialize = FALSE),
      manifest_json = manifest_json,
      policy_snapshot = .dsvert_dp_synopsis_policy_snapshot_v1(policy)))
    record <- .dsvert_dp_synopsis_manifest_cache_put_v1(
      policy, secret, record)
  }
  if ((is.null(selector) &&
       !identical(record$local_authority_sha256, local_authority)) ||
      !identical(record$schema_sha256, signed$validated$sha256) ||
      !identical(record$workload_contract_sha256,
                 signed$workload$sha256)) {
    stop("The memoized synopsis manifest has conflicting authority.",
         call. = FALSE)
  }
  manifest <- .dsvert_dp_capsule_source_manifest(record$manifest_json)
  list(
    record = record, manifest = manifest,
    artifact_index = .dsvert_dp_capsule_artifact_commitment_index(
      manifest, policy, record$manifest_sha256))
}

.dsvert_dp_synopsis_bind_v1 <- function(
    bootstrap_set_json, .policy = NULL, .secret = NULL,
    .identity = NULL, .signer = .dsvert_relay_sign_message,
    .verifier = .dsvert_relay_verify_message) {
  if (is.null(.policy)) .policy <- .dsvert_dp_synopsis_policy_v1()
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (is.null(.identity)) .identity <- .get_identity_keypair()
  request <- .dsvert_dp_synopsis_decode_canonical_v1(
    bootstrap_set_json, "bootstrap set")
  base_fields <- c("version", "phase", "bootstraps", "schema_signatures")
  fields <- c(base_fields, if ("local_projection" %in% names(request)) {
    "local_projection"
  } else character())
  if (is.null(names(request)) || anyNA(names(request)) ||
      anyDuplicated(names(request)) || !setequal(names(request), fields) ||
      !identical(request$version,
                 .DSVERT_DP_SYNOPSIS_BIND_REQUEST_VERSION) ||
      !request$phase %in% c("schema_signature", "manifest_build")) {
    stop("Invalid synopsis Bind request.", call. = FALSE)
  }
  bootstraps <- .dsvert_dp_synopsis_bootstrap_set_v1(
    request$bootstraps, .policy, .verifier)
  authorization_schema <- .dsvert_dp_synopsis_manifest_schema_v1(
    bootstraps, .policy)
  local_projection <- if ("local_projection" %in% names(request)) {
    .dsvert_dp_synopsis_projection_validate_v1(
      request$local_projection, authorization_schema, .policy)
  } else NULL
  schema <- if (is.null(local_projection)) {
    authorization_schema
  } else {
    .dsvert_dp_synopsis_projection_project_v1(
      authorization_schema, local_projection, .policy)
  }
  bootstrap_set_sha256 <- .dsvert_joint_dp_hash(list(
    version = .DSVERT_DP_SYNOPSIS_BOOTSTRAP_VERSION,
    bootstraps = unname(bootstraps)))
  context <- .dsvert_dp_synopsis_policy_context_v1(.policy)
  if (!is.list(.identity) || is.null(.identity$identity_pk) ||
      is.null(.identity$identity_sk) || !is.function(.signer) ||
      !identical(
        .dsvert_relay_normalize_identity_pk(.identity$identity_pk),
        unname(context$pins[[context$peer_name]]))) {
    stop("The synopsis Bind identity is not pinned.", call. = FALSE)
  }
  if (identical(request$phase, "schema_signature")) {
    if (!is.null(request$schema_signatures)) {
      stop("Schema-signature Bind must not carry prior signatures.",
           call. = FALSE)
    }
    response <- list(
      version = .DSVERT_DP_SYNOPSIS_BIND_SIGNATURE_VERSION,
      phase = "global_schema_verified",
      peer_name = context$peer_name,
      peer_identity_pk = unname(context$pins[[context$peer_name]]),
      peer_pinset_sha256 = .policy$peer_pinset_sha256,
      bootstrap_set_sha256 = bootstrap_set_sha256,
      schema_sha256 = schema$schema_sha256,
      workload_contract_sha256 = schema$workload_sha256,
      logical_snapshot = schema$logical_snapshot,
      schema_signature = .dsvert_dp_capsule_manifest_identity_signature(
        .dsvert_dp_capsule_schema_message(schema$schema),
        .policy, function(message, peer, pin) {
          .signer(message, .identity$identity_sk)
        }),
      data_access = FALSE, request_limit = FALSE,
      rate_limit = FALSE, catalog_limit = FALSE)
    response$signature <- .dsvert_dp_synopsis_signature_v1(.signer(
      .dsvert_dp_synopsis_bind_message_v1(response),
      .identity$identity_sk))
    return(.dsvert_dp_canonical_query_value(response))
  }
  signatures <- request$schema_signatures
  if (!is.list(signatures) || is.null(names(signatures)) ||
      anyNA(names(signatures)) || anyDuplicated(names(signatures)) ||
      !setequal(names(signatures), names(context$pins))) {
    stop("Synopsis Bind requires one schema signature per pinned peer.",
         call. = FALSE)
  }
  message <- .dsvert_dp_capsule_schema_message(schema$schema)
  valid <- vapply(names(context$pins), function(peer) {
    signature <- tryCatch(
      .dsvert_dp_synopsis_signature_v1(signatures[[peer]]),
      error = function(error) NULL)
    !is.null(signature) && isTRUE(tryCatch(.verifier(
      message, unname(context$pins[[peer]]), signature),
      error = function(error) FALSE))
  }, logical(1L))
  if (!all(valid)) {
    stop("The synopsis global schema signatures are invalid.",
         call. = FALSE)
  }
  signatures <- signatures[names(context$pins)]
  built <- .dsvert_dp_synopsis_manifest_build_v1(
    c(schema$schema, list(signatures = signatures)), schema$workload,
    .policy, .secret, local_projection = local_projection,
    .verifier = .verifier)
  unsigned <- list(
    version = .DSVERT_DP_SYNOPSIS_BOUND_MANIFEST_VERSION,
    phase = "server_authoritative_synopsis_manifest_memoized",
    peer_name = context$peer_name,
    peer_identity_pk = unname(context$pins[[context$peer_name]]),
    peer_pinset_sha256 = .policy$peer_pinset_sha256,
    bootstrap_set_sha256 = bootstrap_set_sha256,
    schema_sha256 = schema$schema_sha256,
    workload_contract_sha256 = schema$workload_sha256,
    manifest_sha256 = built$record$manifest_sha256,
    manifest_bytes = as.numeric(nchar(
      built$record$manifest_json, type = "bytes")),
    capsule_id = built$manifest$capsule_identity$capsule_id,
    artifact_commitment_count = built$artifact_index$count,
    artifact_commitments_root = built$artifact_index$root,
    artifact_commitments = built$artifact_index$value,
    manifest_json = built$record$manifest_json,
    privacy_scope = "per_canonical_artifact_v1",
    global_composition_claim = FALSE,
    durable_memoization = TRUE, deterministic_replay = TRUE,
    data_access = FALSE, request_limit = FALSE,
    rate_limit = FALSE, catalog_limit = FALSE)
  unsigned$signature <- .dsvert_dp_synopsis_signature_v1(.signer(
    .dsvert_dp_synopsis_bind_message_v1(unsigned),
    .identity$identity_sk))
  .dsvert_dp_canonical_query_value(unsigned)
}

dsvertDPSynopsisBootstrapDS <- function() {
  .dsvert_dp_synopsis_remote_public_v1({
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_bootstrap_v1(), "bootstrap")
  })
}

dsvertDPSynopsisBindDS <- function(bootstrap_set_json) {
  .dsvert_dp_synopsis_remote_public_v1({
    json <- .dsvert_dp_synopsis_remote_text_v1(
      bootstrap_set_json, "bootstrap set")
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_bind_v1(json), "Bind")
  })
}

dsvertDPSynopsisPublicationDS <- function(manifest_sha256) {
  .dsvert_dp_synopsis_remote_public_v1({
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_publication_v1(manifest_sha256),
      "publication", .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES)
  })
}

dsvertDPSynopsisPublishedReplayDS <- function(
    artifact_key, first_release_json, second_release_json,
    public_chunk_index) {
  .dsvert_dp_synopsis_remote_public_v1({
    first <- .dsvert_dp_synopsis_remote_text_v1(
      first_release_json, "first publication",
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES)
    second <- .dsvert_dp_synopsis_remote_text_v1(
      second_release_json, "second publication",
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_publication_replay_v1(
        artifact_key, first, second, public_chunk_index),
      "published REPLAY",
      .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
  })
}

dsvertDPSynopsisFinalizeAckDS <- function(
    manifest_sha256, first_release_json, second_release_json) {
  .dsvert_dp_synopsis_remote_public_v1({
    first <- .dsvert_dp_synopsis_remote_text_v1(
      first_release_json, "first finalize publication",
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES)
    second <- .dsvert_dp_synopsis_remote_text_v1(
      second_release_json, "second finalize publication",
      .DSVERT_DP_SYNOPSIS_REMOTE_EVIDENCE_MAX_BYTES)
    .dsvert_dp_synopsis_remote_encode_v1(
      .dsvert_dp_synopsis_finalize_ack_v1(
        manifest_sha256, first, second),
      "FinalizeAck", .DSVERT_DP_SYNOPSIS_REMOTE_RECEIPT_MAX_BYTES)
  })
}
