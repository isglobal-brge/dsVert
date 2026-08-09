# Two-peer, purpose-bound control plane for a future joint MPC DP opening.
#
# This file deliberately contains no DataSHIELD entry point and no statistic
# opening.  It only replicates a global DP allocation between exactly two
# custodian-designated, identity-pinned computation peers selected from the
# complete vertical pinset.  The historical local epsilon/K
# accountant is test-only: production remains fail-closed until an MPC
# PRF/sampler and a complete E2E adapter consume the authorization token and
# durable result state machine defined here.

.DSVERT_JOINT_DP_VERSION <- "dsvert-joint-dp-control-v3"
.DSVERT_JOINT_DP_CAPSULE_VERSION <- "dsvert-joint-dp-capsule-v1"
.DSVERT_JOINT_DP_CAPSULE_IDENTITY_VERSION <-
  "dsvert-joint-dp-capsule-identity-v3"
.DSVERT_JOINT_DP_CAPSULE_PRIVACY_EPOCH_SCOPE <-
  "per_peer_signed_receipts_v1"
.DSVERT_JOINT_DP_LOCAL_POLICY_BINDING_VERSION <-
  "dsvert-joint-dp-local-policy-binding-v2"
.DSVERT_JOINT_DP_PREPARE_VERSION <- "dsvert-joint-dp-prepare-receipt-v1"
.DSVERT_JOINT_DP_COMMIT_VERSION <- "dsvert-joint-dp-commit-receipt-v1"
.DSVERT_JOINT_DP_AUTHORIZE_VERSION <-
  "dsvert-joint-dp-authorize-receipt-v1"
.DSVERT_JOINT_DP_OPEN_VERSION <- "dsvert-joint-dp-opening-token-v1"
.DSVERT_JOINT_DP_RESULT_PREPARE_VERSION <-
  "dsvert-joint-dp-result-prepare-receipt-v2"
.DSVERT_JOINT_DP_RESULT_COMMIT_VERSION <-
  "dsvert-joint-dp-result-commit-receipt-v2"
.DSVERT_JOINT_DP_DELIVERY_VERSION <-
  "dsvert-joint-dp-delivery-token-v2"
.DSVERT_JOINT_DP_SCOPE <- "joint_mpc_single_opening"
.DSVERT_JOINT_DP_CAPABILITY <- "joint_mpc_single_opening_v1"
.DSVERT_JOINT_DP_SAMPLER <- "two_private_hmac_seeds_one_gc_sample_v1"
.DSVERT_JOINT_DP_CONVOLUTION_SAMPLER <-
  "two_independent_full_global_draws_convolution_v1"
.DSVERT_JOINT_DP_STATES <- c(
  "prepared", "locally_committed", "committed", "authorized",
  "open_authorized")
.DSVERT_JOINT_DP_OUTPUT_STATES <- c(
  "result_prepared", "result_committed", "delivery_authorized")
.DSVERT_JOINT_DP_ALLOCATOR_STATE_VERSION <-
  "dsvert-joint-dp-allocator-state-v3"
.DSVERT_JOINT_DP_ALLOCATOR_STATE_META_KEY <- "allocator_state_version"
.DSVERT_JOINT_DP_FAST_META_KEYS <- c(
  "schema_version", .DSVERT_JOINT_DP_ALLOCATOR_STATE_META_KEY,
  "policy_hash", "secret_id", "peer_name", "next_index", "chain_head",
  "cumulative_epsilon", "cumulative_delta")

.dsvert_joint_dp_hash <- function(value) {
  canonical <- .dsvert_dp_canonical_query_value(value)
  digest::digest(
    .dsvert_dp_canonical_json(canonical), algo = "sha256",
    serialize = FALSE)
}

.dsvert_joint_dp_legacy_local_policy_hash <- function(
    context, privacy_epoch, noise_key_id) {
  epoch <- suppressWarnings(as.numeric(privacy_epoch))
  if (!is.list(context) || !is.list(context$common) ||
      !is.character(context$peer_name) || length(context$peer_name) != 1L ||
      is.na(context$peer_name) || !nzchar(context$peer_name) ||
      length(epoch) != 1L || is.na(epoch) || !is.finite(epoch) ||
      epoch < 1 || epoch != floor(epoch) ||
      !is.character(noise_key_id) || length(noise_key_id) != 1L ||
      is.na(noise_key_id) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", noise_key_id)) {
    stop("Invalid legacy joint-DP local policy binding.", call. = FALSE)
  }
  .dsvert_joint_dp_hash(list(
    common = context$common,
    peer_name = context$peer_name,
    privacy_epoch = epoch,
    noise_key_id = noise_key_id))
}

.dsvert_joint_dp_decimal <- function(value, what, minimum = 0,
                                     maximum = Inf, open_minimum = FALSE) {
  invalid_minimum <- if (isTRUE(open_minimum)) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      value <= minimum
  } else {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      value < minimum
  }
  if (!is.numeric(value) || length(value) != 1L || is.na(value) ||
      !is.finite(value) || invalid_minimum || value > maximum) {
    stop("Invalid joint-DP ", what, ".", call. = FALSE)
  }
  formatted <- format(
    as.numeric(value), digits = 17L, scientific = TRUE, trim = TRUE)
  out_dec <- getOption("OutDec", ".")
  if (!identical(out_dec, ".")) {
    formatted <- sub(out_dec, ".", formatted, fixed = TRUE)
  }
  formatted
}

.dsvert_joint_dp_index <- function(value, what = "allocation index") {
  number <- suppressWarnings(as.numeric(value))
  if (length(number) != 1L || is.na(number) || !is.finite(number) ||
      number < 0 || number > 2^53 - 1 || number != floor(number)) {
    stop("Invalid joint-DP ", what, ".", call. = FALSE)
  }
  number
}

.dsvert_joint_dp_lifetime_contract <- function(policy) {
  maximum <- .dsvert_joint_dp_index(
    policy$lifetime_max_distinct_capsules,
    "lifetime maximum distinct capsules")
  if (maximum < 1) {
    stop("The joint-DP lifetime capsule limit must be positive.",
         call. = FALSE)
  }
  epsilon <- .dsvert_joint_dp_release_ledger_decimal(
    policy$global_total_epsilon, "capsule epsilon",
    open_minimum = TRUE, maximum = 8)
  delta <- .dsvert_joint_dp_release_ledger_decimal(
    policy$global_total_delta, "capsule delta",
    maximum = 1 - .Machine$double.eps)
  lifetime_epsilon <- .dsvert_joint_dp_release_ledger_exact_total(
    epsilon, maximum, "lifetime epsilon")
  lifetime_delta <- .dsvert_joint_dp_release_ledger_exact_total(
    delta, maximum, "lifetime delta")
  if (.dsvert_joint_dp_release_ledger_exact_compare(
        lifetime_epsilon, "8", "lifetime epsilon") > 0L ||
      .dsvert_joint_dp_release_ledger_exact_compare(
        lifetime_delta, "1", "lifetime delta") >= 0L) {
    stop(paste(
      "The joint-DP lifetime composition bound must have epsilon <= 8",
      "and delta < 1."), call. = FALSE)
  }
  list(
    maximum_distinct_capsules = maximum,
    epsilon = epsilon,
    delta = delta,
    lifetime_epsilon = lifetime_epsilon,
    lifetime_delta = lifetime_delta)
}

.dsvert_joint_dp_policy_context <- function(
    policy, require_designated = TRUE) {
  if (!is.logical(require_designated) ||
      length(require_designated) != 1L || is.na(require_designated)) {
    stop("Invalid joint-DP designated-peer gate.", call. = FALSE)
  }
  required <- c(
    "domain", "cohort_id", "peer_name", "peer_pinset",
    "peer_pinset_sha256", "global_total_epsilon", "global_total_delta",
    "lifetime_max_distinct_capsules",
    "adjacency", "patient_column", "unit_capacity",
    "max_records_per_unit", "overflow_policy", "noise_root", "ledger_path")
  if (!is.list(policy) || !all(required %in% names(policy)) ||
      !is.character(policy$peer_name) || length(policy$peer_name) != 1L ||
      !is.character(policy$peer_pinset) || length(policy$peer_pinset) < 2L ||
      is.null(names(policy$peer_pinset)) || anyDuplicated(names(policy$peer_pinset)) ||
      anyDuplicated(unname(policy$peer_pinset)) ||
      !identical(sort(names(policy$peer_pinset), method = "radix"),
                 sort(unique(names(policy$peer_pinset)), method = "radix"))) {
    stop("Joint DP requires a complete set of distinct name-pinned peers.",
         call. = FALSE)
  }
  full_pins <- vapply(
    policy$peer_pinset, .dsvert_relay_normalize_identity_pk, character(1L))
  full_pins <- full_pins[order(names(full_pins), method = "radix")]
  if (!is.null(policy$peer_count) &&
      (!is.numeric(policy$peer_count) || length(policy$peer_count) != 1L ||
       is.na(policy$peer_count) || !is.finite(policy$peer_count) ||
       policy$peer_count != length(full_pins))) {
    stop("The joint-DP peer count is inconsistent with the pinned map.",
         call. = FALSE)
  }
  designated <- .dsvert_dp_resolve_designated_noise_peers(
    policy$designated_noise_peers, full_pins)
  if (isTRUE(require_designated) && !policy$peer_name %in% designated) {
    stop("Only a custodian-designated noise peer may run the joint-DP ",
         "allocator.", call. = FALSE)
  }
  pins <- full_pins[designated]
  pin_hash <- digest::digest(
    .dsvert_dp_canonical_json(as.list(full_pins)), algo = "sha256",
    serialize = FALSE)
  if (!identical(pin_hash, policy$peer_pinset_sha256)) {
    stop("The joint-DP pinned-peer digest is inconsistent.", call. = FALSE)
  }
  epsilon <- as.numeric(policy$global_total_epsilon)
  delta <- as.numeric(policy$global_total_delta)
  if (length(epsilon) != 1L || is.na(epsilon) || !is.finite(epsilon) ||
      epsilon <= 0 || epsilon > .DSVERT_DP_MAXIMUM_EPSILON ||
      length(delta) != 1L || is.na(delta) || !is.finite(delta) ||
      delta < 0 || delta >= 1 ||
      !is.list(policy$noise_root) ||
      !is.numeric(policy$noise_root$epoch) ||
      length(policy$noise_root$epoch) != 1L ||
      is.na(policy$noise_root$epoch) || !is.finite(policy$noise_root$epoch) ||
      policy$noise_root$epoch < 1 ||
      policy$noise_root$epoch != floor(policy$noise_root$epoch) ||
      !is.character(policy$noise_root$key_id) ||
      length(policy$noise_root$key_id) != 1L ||
      is.na(policy$noise_root$key_id) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
             policy$noise_root$key_id)) {
    stop("The joint-DP global policy is invalid.", call. = FALSE)
  }
  lifetime <- .dsvert_joint_dp_lifetime_contract(policy)
  common <- .dsvert_dp_canonical_query_value(list(
    protocol = .DSVERT_JOINT_DP_VERSION,
    release_scope = .DSVERT_JOINT_DP_SCOPE,
    capability_id = .DSVERT_JOINT_DP_CAPABILITY,
    domain = policy$domain,
    cohort_id = policy$cohort_id,
    ordered_peer_pinset = as.list(full_pins),
    peer_pinset_sha256 = pin_hash,
    peer_count = length(full_pins),
    designated_noise_peers = designated,
    designated_noise_peer_pinset = as.list(pins),
    epsilon_capsule = epsilon,
    delta_capsule = delta,
    lifetime_max_distinct_capsules =
      lifetime$maximum_distinct_capsules,
    lifetime_epsilon_upper_bound = lifetime$lifetime_epsilon,
    lifetime_delta_upper_bound = lifetime$lifetime_delta,
    privacy_accounting =
      "bounded_distinct_capsules_one_public_instance_each_v1",
    adjacency = policy$adjacency,
    patient_column = policy$patient_column,
    unit_capacity = policy$unit_capacity,
    max_records_per_unit = policy$max_records_per_unit,
    overflow_policy = policy$overflow_policy,
    sampler = .DSVERT_JOINT_DP_SAMPLER))
  consortium_id <- paste0("jdpc1_", .dsvert_joint_dp_hash(common))
  list(
    common = common,
    consortium_id = consortium_id,
    pins = pins,
    peer_name = policy$peer_name,
    lifetime = lifetime,
    local_policy_hash = .dsvert_joint_dp_hash(list(
      version = .DSVERT_JOINT_DP_LOCAL_POLICY_BINDING_VERSION,
      common = common,
      peer_name = policy$peer_name,
      privacy_epoch_scope =
        .DSVERT_JOINT_DP_CAPSULE_PRIVACY_EPOCH_SCOPE)))
}

.dsvert_joint_dp_mechanism <- function(value, policy) {
  required <- c(
    "release_scope", "capability_id", "producer", "purpose",
    "source_context_hash", "mechanism", "mechanism_version", "sampler",
    "sensitivity_norm", "sensitivity", "coordinate_count", "uses_delta",
    "clipping_hash", "ring_bits", "frac_bits")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), required) ||
      !identical(value$release_scope, .DSVERT_JOINT_DP_SCOPE) ||
      !identical(value$capability_id, .DSVERT_JOINT_DP_CAPABILITY) ||
      !value$sampler %in% c(
        .DSVERT_JOINT_DP_SAMPLER, .DSVERT_JOINT_DP_CONVOLUTION_SAMPLER)) {
    stop("Invalid purpose-bound joint-DP mechanism contract.", call. = FALSE)
  }
  scalar_id <- function(x) {
    is.character(x) && length(x) == 1L && !is.na(x) &&
      nchar(x, type = "bytes") <= 128L &&
      grepl("^[A-Za-z0-9][A-Za-z0-9._:/-]*$", x)
  }
  integer_scalar <- function(x, lower, upper) {
    is.numeric(x) && length(x) == 1L && !is.na(x) && is.finite(x) &&
      x >= lower && x <= upper && x == floor(x)
  }
  if (!all(vapply(value[c("producer", "purpose", "mechanism",
                           "mechanism_version")], scalar_id, logical(1L))) ||
      !is.character(value$source_context_hash) ||
      length(value$source_context_hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", value$source_context_hash) ||
      !is.character(value$clipping_hash) ||
      length(value$clipping_hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", value$clipping_hash) ||
      !value$sensitivity_norm %in% c("l1", "l2") ||
      !is.numeric(value$sensitivity) || length(value$sensitivity) != 1L ||
      is.na(value$sensitivity) || !is.finite(value$sensitivity) ||
      value$sensitivity <= 0 ||
      !integer_scalar(value$coordinate_count, 1,
                      .DSVERT_DP_MAX_COORDINATES) ||
      !is.logical(value$uses_delta) || length(value$uses_delta) != 1L ||
      is.na(value$uses_delta) || !integer_scalar(value$ring_bits, 63, 512) ||
      !integer_scalar(value$frac_bits, 0, value$ring_bits - 1L) ||
      (isTRUE(value$uses_delta) && policy$global_total_delta <= 0)) {
    stop("Invalid purpose-bound joint-DP mechanism values.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(value)
}

.dsvert_joint_dp_logical_snapshot <- function(logical_snapshot) {
  snapshot_fields <- c(
    "logical_snapshot_id", "version", "alignment_protocol_version")
  if (!is.list(logical_snapshot) || is.null(names(logical_snapshot)) ||
      anyNA(names(logical_snapshot)) || anyDuplicated(names(logical_snapshot)) ||
      !setequal(names(logical_snapshot), snapshot_fields) ||
      !is.character(logical_snapshot$logical_snapshot_id) ||
      length(logical_snapshot$logical_snapshot_id) != 1L ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
             logical_snapshot$logical_snapshot_id) ||
      !is.character(logical_snapshot$version) ||
      length(logical_snapshot$version) != 1L ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
             logical_snapshot$version) ||
      !is.numeric(logical_snapshot$alignment_protocol_version) ||
      length(logical_snapshot$alignment_protocol_version) != 1L ||
      is.na(logical_snapshot$alignment_protocol_version) ||
      !is.finite(logical_snapshot$alignment_protocol_version) ||
      logical_snapshot$alignment_protocol_version < 1 ||
      logical_snapshot$alignment_protocol_version !=
        floor(logical_snapshot$alignment_protocol_version)) {
    stop("Invalid logical snapshot contract for joint DP.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(logical_snapshot)
}

.dsvert_joint_dp_capsule_component <- function(value, what) {
  forbidden <- c(
    "method", "methods", "argument", "arguments", "operation",
    "operation_id", "query_id", "capsule_id", "capsule_release_id")
  inspect <- function(current) {
    if (!is.list(current)) return(invisible(TRUE))
    fields <- names(current)
    if (!is.null(fields)) {
      if (anyNA(fields) || any(!nzchar(fields)) || anyDuplicated(fields) ||
          any(tolower(fields) %in% forbidden)) {
        stop("Invalid operation-independent joint-DP capsule ", what, ".",
             call. = FALSE)
      }
    }
    lapply(current, inspect)
    invisible(TRUE)
  }
  if (!is.list(value) || !length(value) || is.null(names(value))) {
    stop("Invalid operation-independent joint-DP capsule ", what, ".",
         call. = FALSE)
  }
  inspect(value)
  tryCatch(
    .dsvert_dp_canonical_query_value(value),
    error = function(e) stop(
      "Invalid operation-independent joint-DP capsule ", what, ".",
      call. = FALSE))
}

.dsvert_joint_dp_capsule_identity <- function(
    policy, logical_snapshot, capsule_schema, admission, bounds, workload) {
  # Every pinned data custodian must derive and attest the same global
  # metadata identity.  The designated-peer gate remains on allocator,
  # sampler and finalizer paths, all of which use policy_context's default.
  context <- .dsvert_joint_dp_policy_context(
    policy, require_designated = FALSE)
  logical_snapshot <- .dsvert_joint_dp_logical_snapshot(logical_snapshot)
  if (!is.character(capsule_schema) || length(capsule_schema) != 1L ||
      is.na(capsule_schema) ||
      !grepl("^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$", capsule_schema)) {
    stop("Invalid joint-DP capsule schema identifier.", call. = FALSE)
  }
  admission <- .dsvert_joint_dp_capsule_component(
    admission, "admission contract")
  bounds <- .dsvert_joint_dp_capsule_component(bounds, "bounds contract")
  workload <- .dsvert_joint_dp_capsule_component(
    workload, "workload contract")
  contract <- .dsvert_dp_canonical_query_value(list(
    protocol = .DSVERT_JOINT_DP_CAPSULE_IDENTITY_VERSION,
    consortium_id = context$consortium_id,
    policy_contract_hash = .dsvert_joint_dp_hash(context$common),
    peer_pinset_sha256 = context$common$peer_pinset_sha256,
    logical_snapshot = logical_snapshot,
    capsule_schema = capsule_schema,
    admission = admission,
    bounds = bounds,
    workload = workload,
    privacy_epoch_scope = .DSVERT_JOINT_DP_CAPSULE_PRIVACY_EPOCH_SCOPE))
  list(capsule_id = .dsvert_joint_dp_hash(contract), contract = contract)
}

.dsvert_joint_dp_capsule_identity_validate <- function(
    policy, logical_snapshot, value) {
  required <- c("capsule_id", "contract")
  contract_fields <- c(
    "protocol", "consortium_id", "policy_contract_hash",
    "peer_pinset_sha256", "logical_snapshot", "capsule_schema",
    "admission", "bounds", "workload", "privacy_epoch_scope")
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), required) ||
      !is.character(value$capsule_id) || length(value$capsule_id) != 1L ||
      is.na(value$capsule_id) || !grepl("^[0-9a-f]{64}$", value$capsule_id) ||
      !is.list(value$contract) || is.null(names(value$contract)) ||
      anyNA(names(value$contract)) || anyDuplicated(names(value$contract)) ||
      !setequal(names(value$contract), contract_fields) ||
      !identical(value$contract$protocol,
                 .DSVERT_JOINT_DP_CAPSULE_IDENTITY_VERSION) ||
      !identical(value$contract$privacy_epoch_scope,
                 .DSVERT_JOINT_DP_CAPSULE_PRIVACY_EPOCH_SCOPE)) {
    stop("Invalid joint-DP capsule identity.", call. = FALSE)
  }
  expected <- .dsvert_joint_dp_capsule_identity(
    policy, logical_snapshot,
    value$contract$capsule_schema, value$contract$admission,
    value$contract$bounds, value$contract$workload)
  value <- .dsvert_dp_canonical_query_value(value)
  if (!identical(value, expected)) {
    stop("The joint-DP capsule identity does not match its immutable contract.",
         call. = FALSE)
  }
  value
}

.dsvert_joint_dp_proposal <- function(
    policy, logical_snapshot, method, arguments, protected_fingerprint,
    mechanism, capsule_identity = NULL, .secret = NULL) {
  logical_snapshot <- .dsvert_joint_dp_logical_snapshot(logical_snapshot)
  method <- .dsvert_dp_scalar_string(method, "joint-DP method")
  if (!grepl("^[A-Za-z][A-Za-z0-9._:-]{0,127}$", method)) {
    stop("Invalid joint-DP method.", call. = FALSE)
  }
  if (!is.character(protected_fingerprint) ||
      length(protected_fingerprint) != 1L ||
      is.na(protected_fingerprint) ||
      !grepl("^[0-9a-f]{64}$", protected_fingerprint)) {
    stop("Invalid private snapshot fingerprint for joint DP.", call. = FALSE)
  }
  mechanism <- .dsvert_joint_dp_mechanism(mechanism, policy)
  # Compatibility note: callers still pass method/arguments while the
  # provisional adapters migrate. They are validated above but deliberately
  # excluded from the durable identity. The allocator owns one persistent DP
  # capsule per immutable snapshot/workload. Each peer binds its current
  # privacy epoch in its signed release receipts, never in the shared capsule
  # identity and never as a per-operation privacy quota.
  invisible(.dsvert_dp_canonical_query_value(arguments))
  if (is.null(capsule_identity)) {
    stop("Joint DP requires an explicit server-minted full-capsule identity.",
         call. = FALSE)
  }
  capsule_identity <- .dsvert_joint_dp_capsule_identity_validate(
    policy, logical_snapshot, capsule_identity)
  capsule_mechanism <- capsule_identity$contract$workload$capsule_mechanism
  if (!is.list(capsule_mechanism) ||
      !identical(capsule_mechanism, mechanism)) {
    stop("The joint-DP mechanism is not the identity-bound full-capsule mechanism.",
         call. = FALSE)
  }
  common_query <- .dsvert_dp_canonical_query_value(list(
    protocol = .DSVERT_JOINT_DP_CAPSULE_VERSION,
    capsule_id = capsule_identity$capsule_id,
    capsule_identity = capsule_identity$contract,
    mechanism = mechanism))
  capsule_id <- capsule_identity$capsule_id
  context <- .dsvert_joint_dp_policy_context(policy)
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  snapshot_binding <- .dsvert_dp_hmac(.secret, list(
    protocol = "dsvert-joint-dp-private-capsule-binding-v1",
    consortium_id = context$consortium_id,
    peer_name = context$peer_name,
    capsule_id = capsule_id,
    protected_fingerprint = protected_fingerprint))
  list(
    capsule_id = capsule_id,
    # Wire compatibility alias. It is exactly the capsule ID and never an
    # operation/query counter; remove it only in a future major protocol.
    query_id = capsule_id,
    common_query = common_query,
    mechanism_hash = .dsvert_joint_dp_hash(mechanism),
    sensitivity = as.numeric(mechanism$sensitivity),
    uses_delta = isTRUE(mechanism$uses_delta),
    snapshot_binding = snapshot_binding)
}

.dsvert_joint_dp_ledger_path <- function(policy) {
  path <- paste0(policy$ledger_path, ".joint-mpc-single-opening-v2.sqlite")
  if (identical(path, policy$ledger_path)) {
    stop("The joint and local DP ledgers must be separate.", call. = FALSE)
  }
  path
}

.dsvert_joint_dp_open_ledger <- function(policy) {
  path <- .dsvert_joint_dp_ledger_path(policy)
  private <- isTRUE(policy$ledger_private)
  paths <- c(ledger = path, lock = paste0(path, ".lock"),
             wal = paste0(path, "-wal"), shm = paste0(path, "-shm"))
  for (label in names(paths)) {
    .dsvert_dp_assert_private_file(
      paths[[label]], paste0("joint-DP ledger ", label), private)
  }
  previous_umask <- Sys.umask("0077")
  lock <- tryCatch(
    filelock::lock(paths[["lock"]], timeout = policy$lock_timeout_ms),
    error = function(e) {
      Sys.umask(previous_umask)
      stop(conditionMessage(e), call. = FALSE)
    })
  if (is.null(lock)) {
    Sys.umask(previous_umask)
    stop("The joint-DP ledger is busy.", call. = FALSE)
  }
  connection <- NULL
  tryCatch({
    for (label in names(paths)) {
      .dsvert_dp_assert_private_file(
        paths[[label]], paste0("joint-DP ledger ", label), private)
    }
    connection <- DBI::dbConnect(RSQLite::SQLite(), path)
    DBI::dbExecute(connection, "PRAGMA busy_timeout=30000")
    DBI::dbExecute(connection, "PRAGMA journal_mode=WAL")
    DBI::dbExecute(connection, "PRAGMA synchronous=FULL")
    DBI::dbExecute(connection,
      "CREATE TABLE IF NOT EXISTS joint_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    DBI::dbExecute(connection, paste(
      "CREATE TABLE IF NOT EXISTS joint_records (",
      "query_id TEXT PRIMARY KEY, sequence INTEGER NOT NULL UNIQUE,",
      "state TEXT NOT NULL, record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"))
    DBI::dbExecute(connection, paste(
      "CREATE TABLE IF NOT EXISTS joint_outputs (",
      "query_id TEXT PRIMARY KEY, state TEXT NOT NULL,",
      "output_json TEXT NOT NULL, row_mac TEXT NOT NULL)"))
    DBI::dbExecute(connection, paste(
      "CREATE TABLE IF NOT EXISTS joint_allocator_state (",
      "singleton INTEGER PRIMARY KEY CHECK(singleton = 1),",
      "state_json TEXT NOT NULL, state_mac TEXT NOT NULL)"))
    DBI::dbExecute(connection, paste(
      "CREATE TABLE IF NOT EXISTS joint_capsule_registry (",
      "query_id TEXT PRIMARY KEY,",
      "allocator_sequence INTEGER NOT NULL UNIQUE,",
      "state TEXT NOT NULL, registry_sequence INTEGER UNIQUE,",
      "journal_json TEXT NOT NULL, row_mac TEXT NOT NULL)"))
    DBI::dbExecute(connection, paste(
      "CREATE TABLE IF NOT EXISTS joint_capsule_registry_state (",
      "singleton INTEGER PRIMARY KEY CHECK(singleton = 1),",
      "journal_count INTEGER NOT NULL,",
      "registered_count INTEGER NOT NULL,",
      "registry_head_chain TEXT NOT NULL, state_mac TEXT NOT NULL)"))
    DBI::dbExecute(connection, paste(
      "CREATE INDEX IF NOT EXISTS joint_capsule_registry_pending_idx",
      "ON joint_capsule_registry(state, allocator_sequence)"))
    .dsvert_dp_chmod_private_files(paths)
    for (label in names(paths)) {
      .dsvert_dp_assert_private_file(
        paths[[label]], paste0("joint-DP ledger ", label), private)
    }
    list(connection = connection, lock = lock,
         previous_umask = previous_umask, paths = paths)
  }, error = function(e) {
    if (!is.null(connection)) try(DBI::dbDisconnect(connection), silent = TRUE)
    try(filelock::unlock(lock), silent = TRUE)
    try(Sys.umask(previous_umask), silent = TRUE)
    stop(conditionMessage(e), call. = FALSE)
  })
}

.dsvert_joint_dp_close_ledger <- function(handle) {
  on.exit(try(Sys.umask(handle$previous_umask), silent = TRUE), add = TRUE)
  try(DBI::dbExecute(handle$connection, "PRAGMA wal_checkpoint(TRUNCATE)"),
      silent = TRUE)
  try(DBI::dbDisconnect(handle$connection), silent = TRUE)
  try(.dsvert_dp_chmod_private_files(handle$paths), silent = TRUE)
  try(filelock::unlock(handle$lock), silent = TRUE)
  invisible(NULL)
}

.dsvert_joint_dp_meta_get <- function(connection, key) {
  row <- DBI::dbGetQuery(
    connection, "SELECT value FROM joint_meta WHERE key = ?",
    params = list(key))
  if (!nrow(row)) NULL else row$value[[1L]]
}

.dsvert_joint_dp_meta_snapshot <- function(connection, keys) {
  if (!is.character(keys) || !length(keys) || anyNA(keys) ||
      any(!nzchar(keys)) || anyDuplicated(keys)) {
    stop("Invalid joint-DP metadata snapshot request.", call. = FALSE)
  }
  placeholders <- paste(rep("?", length(keys)), collapse = ",")
  rows <- DBI::dbGetQuery(
    connection,
    paste0("SELECT key, value FROM joint_meta WHERE key IN (",
           placeholders, ")"),
    params = as.list(keys))
  if (anyDuplicated(rows$key) || any(!rows$key %in% keys)) {
    stop("The joint-DP ledger metadata is invalid.", call. = FALSE)
  }
  stats::setNames(as.list(rows$value), rows$key)
}

.dsvert_joint_dp_meta_set <- function(connection, key, value) {
  DBI::dbExecute(connection, paste(
    "INSERT INTO joint_meta(key, value) VALUES(?, ?)",
    "ON CONFLICT(key) DO UPDATE SET value=excluded.value"),
    params = list(key, as.character(value)))
  invisible(NULL)
}

.dsvert_joint_dp_allocator_state_binding <- function(
    connection, metadata = NULL) {
  binding <- if (is.null(metadata)) {
    list(
      schema_version = .dsvert_joint_dp_meta_get(
        connection, "schema_version"),
      policy_hash = .dsvert_joint_dp_meta_get(connection, "policy_hash"),
      peer_name = .dsvert_joint_dp_meta_get(connection, "peer_name"))
  } else {
    list(
      schema_version = metadata[["schema_version"]],
      policy_hash = metadata[["policy_hash"]],
      peer_name = metadata[["peer_name"]])
  }
  if (!identical(binding$schema_version, "2") ||
      !is.character(binding$policy_hash) ||
      length(binding$policy_hash) != 1L || is.na(binding$policy_hash) ||
      !grepl("^[0-9a-f]{64}$", binding$policy_hash) ||
      !is.character(binding$peer_name) ||
      length(binding$peer_name) != 1L || is.na(binding$peer_name) ||
      !nzchar(binding$peer_name)) {
    stop("The joint-DP allocator state has invalid ledger binding.",
         call. = FALSE)
  }
  binding
}

.dsvert_joint_dp_allocator_state_material <- function(
    binding, committed_count, chain_head, cumulative_epsilon,
    cumulative_delta, tail_query_id = NULL, tail_row_mac = NULL,
    prepared_query_id = NULL, prepared_row_mac = NULL,
    registry_eligible_count = 0, output_count = 0,
    output_tail_query_id = NULL, output_tail_row_mac = NULL) {
  committed_count <- .dsvert_joint_dp_index(
    committed_count, "allocator committed count")
  registry_eligible_count <- .dsvert_joint_dp_index(
    registry_eligible_count, "allocator registry-eligible count")
  output_count <- .dsvert_joint_dp_index(
    output_count, "allocator output count")
  epsilon <- .dsvert_joint_dp_decimal(
    suppressWarnings(as.numeric(cumulative_epsilon)),
    "cumulative epsilon", minimum = 0)
  delta <- .dsvert_joint_dp_decimal(
    suppressWarnings(as.numeric(cumulative_delta)),
    "cumulative delta", minimum = 0)
  hash_or_null <- function(value, what) {
    if (is.null(value)) return(NULL)
    if (!is.character(value) || length(value) != 1L || is.na(value) ||
        !grepl("^[0-9a-f]{64}$", value)) {
      stop("Invalid joint-DP allocator ", what, ".", call. = FALSE)
    }
    value
  }
  tail_query_id <- hash_or_null(tail_query_id, "tail query id")
  tail_row_mac <- hash_or_null(tail_row_mac, "tail row MAC")
  prepared_query_id <- hash_or_null(
    prepared_query_id, "prepared query id")
  prepared_row_mac <- hash_or_null(prepared_row_mac, "prepared row MAC")
  output_tail_query_id <- hash_or_null(
    output_tail_query_id, "output-tail query id")
  output_tail_row_mac <- hash_or_null(
    output_tail_row_mac, "output-tail row MAC")
  valid_head <- is.character(chain_head) && length(chain_head) == 1L &&
    !is.na(chain_head) &&
    (identical(chain_head, "GENESIS") ||
     grepl("^[0-9a-f]{64}$", chain_head))
  valid_binding <- is.list(binding) &&
    identical(binding$schema_version, "2") &&
    is.character(binding$policy_hash) && length(binding$policy_hash) == 1L &&
    grepl("^[0-9a-f]{64}$", binding$policy_hash) &&
    is.character(binding$peer_name) && length(binding$peer_name) == 1L &&
    !is.na(binding$peer_name) && nzchar(binding$peer_name)
  if (!isTRUE(valid_binding) || !isTRUE(valid_head) ||
      (committed_count == 0 && !identical(chain_head, "GENESIS")) ||
      (committed_count > 0 && identical(chain_head, "GENESIS")) ||
      !identical(registry_eligible_count, committed_count) ||
      output_count > registry_eligible_count ||
      xor(is.null(tail_query_id), is.null(tail_row_mac)) ||
      xor(is.null(prepared_query_id), is.null(prepared_row_mac)) ||
      xor(is.null(output_tail_query_id), is.null(output_tail_row_mac)) ||
      (committed_count == 0 && !is.null(tail_query_id)) ||
      (committed_count > 0 && is.null(tail_query_id)) ||
      (output_count == 0 && !is.null(output_tail_query_id)) ||
      (output_count > 0 && is.null(output_tail_query_id))) {
    stop("Invalid authenticated joint-DP allocator state.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_ALLOCATOR_STATE_VERSION,
    schema_version = binding$schema_version,
    policy_hash = binding$policy_hash,
    peer_name = binding$peer_name,
    committed_count = as.numeric(committed_count),
    chain_head = chain_head,
    cumulative_epsilon = epsilon,
    cumulative_delta = delta,
    tail_query_id = tail_query_id,
    tail_row_mac = tail_row_mac,
    prepared_query_id = prepared_query_id,
    prepared_row_mac = prepared_row_mac,
    registry_eligible_count = as.numeric(registry_eligible_count),
    output_count = as.numeric(output_count),
    output_tail_query_id = output_tail_query_id,
    output_tail_row_mac = output_tail_row_mac,
    operation_accounting = "one_per_distinct_capsule_allocator_commit",
    operation_limit = TRUE,
    history_can_deny_operation = TRUE))
}

.dsvert_joint_dp_allocator_state_mac <- function(secret, value) {
  if (!is.raw(secret) || length(secret) != 32L) {
    stop("Invalid joint-DP allocator-state secret.", call. = FALSE)
  }
  digest::hmac(
    key = secret,
    object = charToRaw(paste0(
      "dsVert/joint-dp/allocator-state/v3|",
      .dsvert_dp_canonical_json(value))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_allocator_state_read <- function(
    connection, secret, allow_missing = FALSE) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT state_json, state_mac FROM joint_allocator_state",
    "WHERE singleton = 1"))
  if (!nrow(row) && isTRUE(allow_missing)) return(NULL)
  value <- tryCatch({
    if (nrow(row) != 1L) stop("invalid")
    decoded <- jsonlite::fromJSON(
      row$state_json[[1L]], simplifyVector = FALSE)
    required <- c(
      "version", "schema_version", "policy_hash", "peer_name",
      "committed_count", "chain_head", "cumulative_epsilon",
      "cumulative_delta", "tail_query_id", "tail_row_mac",
      "prepared_query_id", "prepared_row_mac",
      "registry_eligible_count", "output_count", "output_tail_query_id",
      "output_tail_row_mac",
      "operation_accounting", "operation_limit",
      "history_can_deny_operation")
    if (!is.list(decoded) || is.null(names(decoded)) ||
        anyDuplicated(names(decoded)) || !setequal(names(decoded), required) ||
        !identical(decoded$version,
                   .DSVERT_JOINT_DP_ALLOCATOR_STATE_VERSION)) {
      stop("invalid")
    }
    expected <- .dsvert_joint_dp_allocator_state_material(
      list(schema_version = decoded$schema_version,
           policy_hash = decoded$policy_hash,
           peer_name = decoded$peer_name),
      decoded$committed_count, decoded$chain_head,
      decoded$cumulative_epsilon, decoded$cumulative_delta,
      decoded$tail_query_id, decoded$tail_row_mac,
      decoded$prepared_query_id, decoded$prepared_row_mac,
      decoded$registry_eligible_count, decoded$output_count,
      decoded$output_tail_query_id, decoded$output_tail_row_mac)
    if (!identical(row$state_json[[1L]],
                   .dsvert_dp_canonical_json(expected)) ||
        !is.character(row$state_mac[[1L]]) ||
        !grepl("^[0-9a-f]{64}$", row$state_mac[[1L]]) ||
        !identical(row$state_mac[[1L]],
                   .dsvert_joint_dp_allocator_state_mac(secret, expected))) {
      stop("invalid")
    }
    expected
  }, error = function(error) NULL)
  if (is.null(value)) {
    stop("The joint-DP allocator state failed its integrity check.",
         call. = FALSE)
  }
  value
}

.dsvert_joint_dp_allocator_state_write <- function(
    connection, secret, value, insert = FALSE) {
  binding <- .dsvert_joint_dp_allocator_state_binding(connection)
  expected <- .dsvert_joint_dp_allocator_state_material(
    binding, value$committed_count, value$chain_head,
    value$cumulative_epsilon, value$cumulative_delta,
    value$tail_query_id, value$tail_row_mac,
    value$prepared_query_id, value$prepared_row_mac,
    value$registry_eligible_count, value$output_count,
    value$output_tail_query_id, value$output_tail_row_mac)
  json <- .dsvert_dp_canonical_json(expected)
  mac <- .dsvert_joint_dp_allocator_state_mac(secret, expected)
  if (isTRUE(insert)) {
    changed <- DBI::dbExecute(connection, paste(
      "INSERT INTO joint_allocator_state(singleton, state_json, state_mac)",
      "VALUES(1, ?, ?)"), params = list(json, mac))
  } else {
    changed <- DBI::dbExecute(connection, paste(
      "UPDATE joint_allocator_state SET state_json = ?, state_mac = ?",
      "WHERE singleton = 1"), params = list(json, mac))
  }
  if (!identical(as.integer(changed), 1L)) {
    stop("The joint-DP allocator state could not be persisted.",
         call. = FALSE)
  }
  expected
}

.dsvert_joint_dp_row_mac <- function(secret, record_json) {
  digest::hmac(
    key = secret, object = charToRaw(paste0(
      "dsVert/joint-dp/ledger-row/v1|", record_json)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_record_decode <- function(row, secret) {
  if (nrow(row) != 1L ||
      !identical(.dsvert_joint_dp_row_mac(secret, row$record_json[[1L]]),
                 row$row_mac[[1L]])) {
    stop("The joint-DP ledger failed its integrity check.", call. = FALSE)
  }
  record <- tryCatch(jsonlite::fromJSON(
    row$record_json[[1L]], simplifyVector = FALSE), error = function(e) NULL)
  required <- c(
    "version", "query_id", "allocation_index", "state",
    "previous_chain", "new_chain", "epsilon", "delta",
    "common_query", "sensitivity", "uses_delta",
    "own_prepare", "peer_prepare", "joint_record_hash", "own_commit",
    "peer_commit", "own_authorization", "peer_authorization",
    "opening_token")
  if (!is.list(record) || is.null(names(record)) || anyDuplicated(names(record)) ||
      !setequal(names(record), required) ||
      !identical(record$version, .DSVERT_JOINT_DP_VERSION) ||
      !identical(record$query_id, row$query_id[[1L]]) ||
      !identical(record$state, row$state[[1L]]) ||
      !record$state %in% .DSVERT_JOINT_DP_STATES ||
      !identical(.dsvert_joint_dp_index(record$allocation_index),
                 as.numeric(row$sequence[[1L]])) ||
      !grepl("^[0-9a-f]{64}$", record$query_id) ||
      !(identical(record$previous_chain, "GENESIS") ||
        grepl("^[0-9a-f]{64}$", record$previous_chain)) ||
      !is.list(record$common_query) ||
      !is.list(record$common_query$mechanism) ||
      !is.list(record$common_query$capsule_identity) ||
      !is.list(record$own_prepare) ||
      !identical(record$query_id, record$own_prepare$capsule_id) ||
      !identical(record$query_id, record$own_prepare$query_id) ||
      !identical(record$query_id, record$common_query$capsule_id) ||
      !identical(record$common_query$protocol,
                 .DSVERT_JOINT_DP_CAPSULE_VERSION) ||
      !identical(.dsvert_joint_dp_hash(
                   record$common_query$capsule_identity),
                 record$query_id) ||
      !is.numeric(record$sensitivity) || length(record$sensitivity) != 1L ||
      is.na(record$sensitivity) || !is.finite(record$sensitivity) ||
      record$sensitivity <= 0 || !is.logical(record$uses_delta) ||
      length(record$uses_delta) != 1L || is.na(record$uses_delta) ||
      !identical(.dsvert_joint_dp_hash(record$common_query$mechanism),
                 record$own_prepare$mechanism_hash)) {
    stop("The joint-DP ledger record is invalid.", call. = FALSE)
  }
  record
}

.dsvert_joint_dp_allocator_state_assert_binding <- function(
    connection, state, binding = NULL) {
  if (is.null(binding)) {
    binding <- .dsvert_joint_dp_allocator_state_binding(connection)
  }
  if (!identical(
        state[c("schema_version", "policy_hash", "peer_name")],
        binding)) {
    stop("The joint-DP allocator state does not match ledger metadata.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_joint_dp_allocator_state_record_transition <- function(
    connection, old_record, record, row_mac, secret, insert) {
  state <- .dsvert_joint_dp_allocator_state_read(
    connection, secret, allow_missing = TRUE)
  if (is.null(state)) return(invisible(NULL))
  .dsvert_joint_dp_allocator_state_assert_binding(connection, state)
  index <- .dsvert_joint_dp_index(record$allocation_index)
  if (isTRUE(insert)) {
    if (!is.null(old_record) || !identical(record$state, "prepared") ||
        !is.null(state$prepared_query_id) ||
        !identical(index, state$committed_count) ||
        !identical(record$previous_chain, state$chain_head)) {
      stop("The joint-DP prepared head conflicts with allocator state.",
           call. = FALSE)
    }
    state$prepared_query_id <- record$query_id
    state$prepared_row_mac <- row_mac
    .dsvert_joint_dp_allocator_state_write(
      connection, secret, state)
    return(invisible(NULL))
  }
  if (is.null(old_record) ||
      !identical(old_record$query_id, record$query_id) ||
      !identical(old_record$allocation_index, record$allocation_index)) {
    stop("The joint-DP allocator update lost its prior state.",
         call. = FALSE)
  }
  transition <- paste(old_record$state, record$state, sep = "->")
  allowed <- c(
    "prepared->locally_committed",
    "locally_committed->committed",
    "committed->authorized",
    "authorized->open_authorized")
  if (!transition %in% allowed) {
    stop("Invalid joint-DP allocator record transition.", call. = FALSE)
  }
  if (identical(transition, "prepared->locally_committed")) {
    expected_chain <- .dsvert_joint_dp_chain_head(
      state$chain_head, record$allocation_index,
      record$joint_record_hash, record$epsilon, record$delta)
    if (!identical(state$prepared_query_id, record$query_id) ||
        !identical(index, state$committed_count) ||
        !identical(record$previous_chain, state$chain_head) ||
        !identical(record$new_chain, expected_chain)) {
      stop("The joint-DP commit conflicts with authenticated allocator state.",
           call. = FALSE)
    }
    state$committed_count <- state$committed_count + 1
    state$chain_head <- record$new_chain
    state$cumulative_epsilon <- as.numeric(state$cumulative_epsilon) +
      as.numeric(record$epsilon)
    state$cumulative_delta <- as.numeric(state$cumulative_delta) +
      as.numeric(record$delta)
    state$tail_query_id <- record$query_id
    state$tail_row_mac <- row_mac
    state$prepared_query_id <- NULL
    state$prepared_row_mac <- NULL
    state$registry_eligible_count <- state$registry_eligible_count + 1
  } else {
    if (index >= state$committed_count) {
      stop("The joint-DP record transition is beyond the committed head.",
           call. = FALSE)
    }
    if (identical(index, state$committed_count - 1)) {
      if (!identical(state$tail_query_id, record$query_id)) {
        stop("The joint-DP allocator tail changed identity.", call. = FALSE)
      }
      state$tail_row_mac <- row_mac
    }
  }
  .dsvert_joint_dp_allocator_state_write(
    connection, secret, state)
  invisible(NULL)
}

.dsvert_joint_dp_record_store <- function(connection, record, secret,
                                           insert = FALSE) {
  record$state <- as.character(record$state)
  json <- .dsvert_dp_canonical_json(record)
  mac <- .dsvert_joint_dp_row_mac(secret, json)
  old_record <- NULL
  if (isTRUE(insert)) {
    DBI::dbExecute(connection, paste(
      "INSERT INTO joint_records(query_id, sequence, state, record_json, row_mac)",
      "VALUES(?, ?, ?, ?, ?)"), params = list(
        record$query_id, .dsvert_joint_dp_index(record$allocation_index),
        record$state, json, mac))
  } else {
    old_row <- DBI::dbGetQuery(connection,
      "SELECT * FROM joint_records WHERE query_id = ?",
      params = list(record$query_id))
    if (nrow(old_row) != 1L) {
      stop("The joint-DP ledger update lost its immutable record.",
           call. = FALSE)
    }
    old_record <- .dsvert_joint_dp_record_decode(old_row, secret)
    changed <- DBI::dbExecute(connection, paste(
      "UPDATE joint_records SET state = ?, record_json = ?, row_mac = ?",
      "WHERE query_id = ?"), params = list(
        record$state, json, mac, record$query_id))
    if (!identical(as.integer(changed), 1L)) {
      stop("The joint-DP ledger update lost its immutable record.",
           call. = FALSE)
    }
  }
  .dsvert_joint_dp_allocator_state_record_transition(
    connection, old_record, record, mac, secret, insert)
  invisible(record)
}

.dsvert_joint_dp_payload_commitment <- function(
    secret, query_id, opening_set_hash, result_contract_hash, payload) {
  if (!is.raw(payload) ||
      !is.raw(secret) || length(secret) != 32L ||
      !all(grepl("^[0-9a-f]{64}$", c(
        query_id, opening_set_hash, result_contract_hash)))) {
    stop("Invalid joint-DP result commitment input.", call. = FALSE)
  }
  header <- .dsvert_dp_canonical_json(list(
    protocol = "dsVert/joint-dp/result-payload-commitment/v2",
    query_id = query_id,
    opening_set_hash = opening_set_hash,
    result_contract_hash = result_contract_hash))
  # This is deliberately a keyed commitment, not SHA256(public || payload).
  # Result shares can have a tiny public domain; an unkeyed digest would let
  # the analyst/relay enumerate that domain.  The persistent local ledger key
  # is never exposed, and the protocol/domain header prevents cross-use.
  digest::hmac(
    key = secret, object = c(charToRaw(header), as.raw(0L), payload),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_output_row_mac <- function(secret, output_json) {
  digest::hmac(
    key = secret, object = charToRaw(paste0(
      "dsVert/joint-dp/output-ledger-row/v2|", output_json)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_output_decode <- function(row, secret) {
  if (nrow(row) != 1L ||
      !identical(
        .dsvert_joint_dp_output_row_mac(secret, row$output_json[[1L]]),
        row$row_mac[[1L]])) {
    stop("The joint-DP result ledger failed its integrity check.",
         call. = FALSE)
  }
  output <- tryCatch(jsonlite::fromJSON(
    row$output_json[[1L]], simplifyVector = FALSE),
    error = function(e) NULL)
  required <- c(
    "version", "query_id", "state", "payload_b64", "payload_commitment",
    "opening_set_hash", "result_contract_hash", "own_opening_token",
    "peer_opening_token", "own_result_prepare", "peer_result_prepare",
    "result_set_hash", "own_delivery_commit", "peer_delivery_commit",
    "delivery_token")
  if (!is.list(output) || is.null(names(output)) ||
      anyDuplicated(names(output)) || !setequal(names(output), required) ||
      !identical(output$version, "dsvert-joint-dp-output-ledger-v2") ||
      !identical(output$query_id, row$query_id[[1L]]) ||
      !identical(output$state, row$state[[1L]]) ||
      !output$state %in% .DSVERT_JOINT_DP_OUTPUT_STATES ||
      !all(grepl("^[0-9a-f]{64}$", c(
        output$query_id, output$payload_commitment, output$opening_set_hash,
      output$result_contract_hash))) ||
      !is.character(output$payload_b64) || length(output$payload_b64) != 1L ||
      is.na(output$payload_b64) || !is.list(output$own_opening_token) ||
      !is.list(output$peer_opening_token) ||
      !is.list(output$own_result_prepare)) {
    stop("The joint-DP result ledger row is invalid.", call. = FALSE)
  }
  payload <- tryCatch(
    jsonlite::base64_dec(output$payload_b64), error = function(e) NULL)
  canonical_b64 <- if (is.raw(payload)) {
    gsub("[\r\n]", "", jsonlite::base64_enc(payload))
  } else {
    NULL
  }
  if (is.null(canonical_b64) ||
      !identical(canonical_b64, output$payload_b64) ||
      !identical(output$payload_commitment,
                 .dsvert_joint_dp_payload_commitment(
                   secret, output$query_id, output$opening_set_hash,
                   output$result_contract_hash, payload))) {
    stop("The joint-DP persisted result payload is invalid.", call. = FALSE)
  }
  output$payload <- payload
  output
}

.dsvert_joint_dp_output_store <- function(connection, output, secret,
                                           insert = FALSE) {
  persisted <- output[setdiff(names(output), "payload")]
  persisted$state <- as.character(persisted$state)
  json <- .dsvert_dp_canonical_json(persisted)
  mac <- .dsvert_joint_dp_output_row_mac(secret, json)
  if (isTRUE(insert)) {
    DBI::dbExecute(connection, paste(
      "INSERT INTO joint_outputs(query_id, state, output_json, row_mac)",
      "VALUES(?, ?, ?, ?)"), params = list(
        persisted$query_id, persisted$state, json, mac))
  } else {
    old_row <- DBI::dbGetQuery(connection,
      "SELECT * FROM joint_outputs WHERE query_id = ?",
      params = list(persisted$query_id))
    if (nrow(old_row) != 1L) {
      stop("The joint-DP result ledger update lost its immutable record.",
           call. = FALSE)
    }
    .dsvert_joint_dp_output_decode(old_row, secret)
    changed <- DBI::dbExecute(connection, paste(
      "UPDATE joint_outputs SET state = ?, output_json = ?, row_mac = ?",
      "WHERE query_id = ?"), params = list(
        persisted$state, json, mac, persisted$query_id))
    if (!identical(as.integer(changed), 1L)) {
      stop("The joint-DP result ledger update lost its immutable record.",
           call. = FALSE)
    }
  }
  state <- .dsvert_joint_dp_allocator_state_read(connection, secret)
  .dsvert_joint_dp_allocator_state_assert_binding(connection, state)
  record <- .dsvert_joint_dp_load(connection, persisted$query_id, secret)
  if (is.null(record) || !identical(record$state, "open_authorized")) {
    stop("The joint-DP result is not eligible for allocator persistence.",
         call. = FALSE)
  }
  if (isTRUE(insert)) {
    # Integrity count only.  It is deliberately exact rather than capped: a
    # delete-and-reinsert rollback must not be hidden as a valid new output.
    state$output_count <- state$output_count + 1
  }
  state$output_tail_query_id <- persisted$query_id
  state$output_tail_row_mac <- mac
  .dsvert_joint_dp_allocator_state_write(connection, secret, state)
  invisible(output)
}

.dsvert_joint_dp_output_load <- function(connection, query_id, secret) {
  row <- DBI::dbGetQuery(connection,
    "SELECT * FROM joint_outputs WHERE query_id = ?", params = list(query_id))
  if (!nrow(row)) NULL else .dsvert_joint_dp_output_decode(row, secret)
}

.dsvert_joint_dp_chain_head <- function(previous_chain, allocation_index,
                                         joint_record_hash, epsilon, delta) {
  .dsvert_joint_dp_hash(list(
    protocol = "dsvert-joint-dp-chain-v1",
    previous_chain = previous_chain,
    allocation_index = as.character(allocation_index),
      joint_record_hash = joint_record_hash,
      epsilon = epsilon, delta = delta))
}

.dsvert_joint_dp_allocator_roles <- function(context) {
  peers <- context$common$designated_noise_peers
  if (!is.character(peers) || length(peers) != 2L || anyNA(peers) ||
      anyDuplicated(peers) || !identical(peers, sort(peers, method = "radix")) ||
      !setequal(peers, names(context$pins))) {
    stop("The joint-DP allocator role assignment is invalid.", call. = FALSE)
  }
  list(leader = peers[[1L]], follower = peers[[2L]])
}

.dsvert_joint_dp_prepare_assignment_fields <- function() {
  c("consortium_id", "capsule_id", "query_id", "mechanism_hash",
    "allocation_index", "epsilon", "delta", "previous_chain")
}

.dsvert_joint_dp_same_prepare_assignment <- function(left, right) {
  fields <- .dsvert_joint_dp_prepare_assignment_fields()
  is.list(left) && is.list(right) && identical(left[fields], right[fields])
}

.dsvert_joint_dp_validate_record_policy <- function(record, policy) {
  expected_epsilon <- policy$global_total_epsilon
  expected_delta <- if (isTRUE(record$uses_delta)) {
    policy$global_total_delta
  } else {
    0
  }
  epsilon_tolerance <- max(1e-15, abs(expected_epsilon) * 1e-13)
  delta_tolerance <- max(1e-15, abs(expected_delta) * 1e-13)
  if (!is.finite(as.numeric(record$epsilon)) ||
      abs(as.numeric(record$epsilon) - expected_epsilon) >
        epsilon_tolerance || !is.finite(as.numeric(record$delta)) ||
      abs(as.numeric(record$delta) - expected_delta) > delta_tolerance ||
      !identical(record$epsilon, record$own_prepare$epsilon) ||
      !identical(record$delta, record$own_prepare$delta) ||
      !identical(record$allocation_index,
                 record$own_prepare$allocation_index)) {
    stop("The joint-DP ledger capsule privacy parameters are invalid.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_joint_dp_validate_prepared_head <- function(
    record, next_index, context) {
  index <- .dsvert_joint_dp_index(record$allocation_index)
  if (!identical(record$state, "prepared") || index != next_index ||
      !is.null(record$new_chain) || !is.null(record$joint_record_hash)) {
    stop("The joint-DP prepared head is invalid.", call. = FALSE)
  }
  roles <- .dsvert_joint_dp_allocator_roles(context)
  if (identical(record$own_prepare$peer_name, roles$leader)) {
    if (!is.null(record$peer_prepare)) {
      stop("The leader prepared head contains an unexpected peer receipt.",
           call. = FALSE)
    }
  } else if (!identical(record$own_prepare$peer_name, roles$follower) ||
      !is.list(record$peer_prepare) ||
      !identical(record$peer_prepare$peer_name, roles$leader) ||
      !.dsvert_joint_dp_same_prepare_assignment(
        record$own_prepare, record$peer_prepare)) {
    stop("The follower prepared head lacks its leader assignment.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_joint_dp_allocator_full_audit <- function(
    connection, policy, secret, verifier = NULL,
    allow_legacy_policy_hash = FALSE) {
  if (!is.logical(allow_legacy_policy_hash) ||
      length(allow_legacy_policy_hash) != 1L ||
      is.na(allow_legacy_policy_hash)) {
    stop("Invalid joint-DP policy-hash migration request.", call. = FALSE)
  }
  context <- .dsvert_joint_dp_policy_context(policy)
  secret_id <- .dsvert_dp_hmac(secret, list(
    "dsvert-joint-dp-ledger-secret-id-v1", context$peer_name))
  schema <- .dsvert_joint_dp_meta_get(connection, "schema_version")
  if (is.null(schema)) {
    tables <- c(
      "joint_meta", "joint_records", "joint_outputs",
      "joint_allocator_state", "joint_capsule_registry",
      "joint_capsule_registry_state")
    nonempty <- vapply(tables, function(table) {
      nrow(DBI::dbGetQuery(
        connection, paste0("SELECT 1 FROM ", table, " LIMIT 1"))) > 0L
    }, logical(1L))
    if (any(nonempty)) {
      stop(paste(
        "The joint-DP ledger has data but lacks its schema binding;",
        "refusing unsafe reinitialization."), call. = FALSE)
    }
    .dsvert_joint_dp_meta_set(connection, "schema_version", "2")
    .dsvert_joint_dp_meta_set(connection, "policy_hash",
                              context$local_policy_hash)
    .dsvert_joint_dp_meta_set(connection, "secret_id", secret_id)
    .dsvert_joint_dp_meta_set(connection, "peer_name", context$peer_name)
    .dsvert_joint_dp_meta_set(connection, "next_index", "0")
    .dsvert_joint_dp_meta_set(connection, "chain_head", "GENESIS")
    .dsvert_joint_dp_meta_set(connection, "cumulative_epsilon", "0")
    .dsvert_joint_dp_meta_set(connection, "cumulative_delta", "0")
    .dsvert_joint_dp_meta_set(
      connection, .DSVERT_JOINT_DP_ALLOCATOR_STATE_META_KEY,
      .DSVERT_JOINT_DP_ALLOCATOR_STATE_VERSION)
    state <- .dsvert_joint_dp_allocator_state_material(
      .dsvert_joint_dp_allocator_state_binding(connection),
      0, "GENESIS", 0, 0,
      registry_eligible_count = 0, output_count = 0)
    .dsvert_joint_dp_allocator_state_write(
      connection, secret, state, insert = TRUE)
    .dsvert_joint_dp_registry_journal_validate_local(
      connection, policy, context, secret)
    return(invisible(list(context = context, state = state)))
  }
  state_marker <- .dsvert_joint_dp_meta_get(
    connection, .DSVERT_JOINT_DP_ALLOCATOR_STATE_META_KEY)
  if (!is.null(state_marker) &&
      !identical(state_marker, .DSVERT_JOINT_DP_ALLOCATOR_STATE_VERSION)) {
    stop("The joint-DP allocator-state version is unsupported.",
         call. = FALSE)
  }
  if (identical(state_marker, .DSVERT_JOINT_DP_ALLOCATOR_STATE_VERSION) &&
      is.null(.dsvert_joint_dp_allocator_state_read(
        connection, secret, allow_missing = TRUE))) {
    stop("The authenticated joint-DP allocator state is missing.",
         call. = FALSE)
  }
  persisted_policy_hash <- .dsvert_joint_dp_meta_get(
    connection, "policy_hash")
  policy_hash_matches <- identical(
    persisted_policy_hash, context$local_policy_hash)
  if (!identical(schema, "2") ||
      (!isTRUE(policy_hash_matches) &&
       !isTRUE(allow_legacy_policy_hash)) ||
      !identical(.dsvert_joint_dp_meta_get(connection, "secret_id"),
                 secret_id) ||
      !identical(.dsvert_joint_dp_meta_get(connection, "peer_name"),
                 context$peer_name)) {
    stop("The joint-DP ledger does not match the immutable local policy.",
         call. = FALSE)
  }
  next_index <- .dsvert_joint_dp_index(
    .dsvert_joint_dp_meta_get(connection, "next_index"), "ledger index")
  rows <- DBI::dbGetQuery(
    connection, "SELECT * FROM joint_records ORDER BY sequence")
  expected_chain <- "GENESIS"
  cumulative_epsilon <- 0
  cumulative_delta <- 0
  committed <- 0
  prepared <- 0
  registry_eligible <- 0
  legacy_policy_hashes <- character()
  if (nrow(rows)) for (i in seq_len(nrow(rows))) {
    record <- .dsvert_joint_dp_record_decode(rows[i, , drop = FALSE], secret)
    own_prepare <- record$own_prepare
    if (is.list(own_prepare) &&
        identical(own_prepare$peer_name, context$peer_name)) {
      candidate <- tryCatch(
        .dsvert_joint_dp_legacy_local_policy_hash(
          context, own_prepare$privacy_epoch, own_prepare$noise_key_id),
        error = function(error) NULL)
      if (!is.null(candidate)) {
        legacy_policy_hashes <- c(legacy_policy_hashes, candidate)
      }
    }
    index <- .dsvert_joint_dp_index(record$allocation_index)
    .dsvert_joint_dp_validate_record_policy(record, policy)
    if (!identical(record$previous_chain, expected_chain)) {
      stop("The joint-DP ledger chain is divergent.", call. = FALSE)
    }
    if (identical(record$state, "prepared")) {
      prepared <- prepared + 1L
      .dsvert_joint_dp_validate_prepared_head(
        record, next_index, context)
    } else {
      if (index != committed || !is.character(record$joint_record_hash) ||
          !grepl("^[0-9a-f]{64}$", record$joint_record_hash) ||
          !identical(record$new_chain, .dsvert_joint_dp_chain_head(
            expected_chain, record$allocation_index,
            record$joint_record_hash, record$epsilon, record$delta))) {
        stop("The joint-DP committed chain is invalid.", call. = FALSE)
      }
      expected_chain <- record$new_chain
      cumulative_epsilon <- cumulative_epsilon + as.numeric(record$epsilon)
      cumulative_delta <- cumulative_delta + as.numeric(record$delta)
      committed <- committed + 1L
      registry_eligible <- registry_eligible + 1L
    }
  }
  outputs <- DBI::dbGetQuery(
    connection, "SELECT * FROM joint_outputs ORDER BY query_id")
  if (nrow(outputs)) for (i in seq_len(nrow(outputs))) {
    output <- .dsvert_joint_dp_output_decode(
      outputs[i, , drop = FALSE], secret)
    record_row <- DBI::dbGetQuery(
      connection, "SELECT * FROM joint_records WHERE query_id = ?",
      params = list(output$query_id))
    if (nrow(record_row) != 1L) {
      stop("The joint-DP result ledger has no allocation record.",
           call. = FALSE)
    }
    record <- .dsvert_joint_dp_record_decode(record_row, secret)
    .dsvert_joint_dp_validate_output_record(
      output, record, policy, context, verifier)
  }
  lifetime_max <- context$lifetime$maximum_distinct_capsules
  if (prepared > 1L || committed != next_index ||
      committed > lifetime_max ||
      (prepared > 0L && committed >= lifetime_max) ||
      !identical(.dsvert_joint_dp_meta_get(connection, "chain_head"),
                 expected_chain) ||
      !isTRUE(all.equal(
        as.numeric(.dsvert_joint_dp_meta_get(connection,
                                             "cumulative_epsilon")),
        cumulative_epsilon, tolerance = 1e-13)) ||
      !isTRUE(all.equal(
        as.numeric(.dsvert_joint_dp_meta_get(connection,
                                             "cumulative_delta")),
        cumulative_delta, tolerance = 1e-13)) ||
      cumulative_epsilon < 0 || cumulative_delta < 0) {
    stop("The joint-DP ledger metadata is inconsistent.", call. = FALSE)
  }
  empty_history <- committed == 0 && prepared == 0 && nrow(outputs) == 0
  if (!isTRUE(policy_hash_matches) &&
      !(isTRUE(empty_history) ||
        persisted_policy_hash %in% unique(legacy_policy_hashes))) {
    stop("The joint-DP ledger does not match the immutable local policy.",
         call. = FALSE)
  }
  registry_audit <- .dsvert_joint_dp_registry_journal_audit(
    connection, policy, context, secret,
    require_enabled = registry_eligible > 0L)
  if (!identical(as.numeric(registry_audit$state$journal_count),
                 as.numeric(registry_eligible))) {
    stop("The cross-signed allocator and capsule-registry journal are incomplete.",
         call. = FALSE)
  }
  tail_row <- if (committed) rows[committed, , drop = FALSE] else NULL
  prepared_row <- if (prepared) rows[nrow(rows), , drop = FALSE] else NULL
  observed_state <- .dsvert_joint_dp_allocator_state_read(
    connection, secret, allow_missing = TRUE)
  output_tail_row <- NULL
  if (nrow(outputs)) {
    if (!is.null(observed_state)) {
      if (is.null(observed_state$output_tail_query_id) ||
          is.null(observed_state$output_tail_row_mac)) {
        stop("The authenticated joint-DP output tail is inconsistent.",
             call. = FALSE)
      }
      output_tail_index <- match(
        observed_state$output_tail_query_id, outputs$query_id)
      if (length(output_tail_index) != 1L || is.na(output_tail_index) ||
          !identical(outputs$row_mac[[output_tail_index]],
                     observed_state$output_tail_row_mac)) {
        stop("The authenticated joint-DP output tail is inconsistent.",
             call. = FALSE)
      }
      output_tail_row <- outputs[output_tail_index, , drop = FALSE]
    } else {
      # A legacy ledger has no mutation-order pointer.  Choose one
      # deterministically after every row has passed the full audit.
      output_tail_row <- outputs[nrow(outputs), , drop = FALSE]
    }
  }
  expected_state <- .dsvert_joint_dp_allocator_state_material(
    .dsvert_joint_dp_allocator_state_binding(connection),
    committed, expected_chain, cumulative_epsilon, cumulative_delta,
    tail_query_id = if (committed) tail_row$query_id[[1L]] else NULL,
    tail_row_mac = if (committed) tail_row$row_mac[[1L]] else NULL,
    prepared_query_id = if (prepared) prepared_row$query_id[[1L]] else NULL,
    prepared_row_mac = if (prepared) prepared_row$row_mac[[1L]] else NULL,
    registry_eligible_count = registry_eligible,
    output_count = nrow(outputs),
    output_tail_query_id = if (nrow(outputs)) {
      output_tail_row$query_id[[1L]]
    } else {
      NULL
    },
    output_tail_row_mac = if (nrow(outputs)) {
      output_tail_row$row_mac[[1L]]
    } else {
      NULL
    })
  if (is.null(observed_state)) {
    .dsvert_joint_dp_allocator_state_write(
      connection, secret, expected_state, insert = TRUE)
  } else if (!identical(observed_state, expected_state)) {
    stop("The authenticated joint-DP allocator state is inconsistent.",
         call. = FALSE)
  }
  if (is.null(state_marker)) {
    .dsvert_joint_dp_meta_set(
      connection, .DSVERT_JOINT_DP_ALLOCATOR_STATE_META_KEY,
      .DSVERT_JOINT_DP_ALLOCATOR_STATE_VERSION)
  }
  invisible(list(
    context = context,
    state = expected_state,
    policy_hash_migration = !isTRUE(policy_hash_matches)))
}

.dsvert_joint_dp_allocator_fast_validate <- function(
    connection, policy, secret, metadata = NULL) {
  context <- .dsvert_joint_dp_policy_context(policy)
  secret_id <- .dsvert_dp_hmac(secret, list(
    "dsvert-joint-dp-ledger-secret-id-v1", context$peer_name))
  if (is.null(metadata)) {
    metadata <- .dsvert_joint_dp_meta_snapshot(
      connection, .DSVERT_JOINT_DP_FAST_META_KEYS)
  }
  if (!identical(metadata[["schema_version"]], "2") ||
      !identical(metadata[[.DSVERT_JOINT_DP_ALLOCATOR_STATE_META_KEY]],
                 .DSVERT_JOINT_DP_ALLOCATOR_STATE_VERSION) ||
      !identical(metadata[["policy_hash"]], context$local_policy_hash) ||
      !identical(metadata[["secret_id"]], secret_id) ||
      !identical(metadata[["peer_name"]], context$peer_name)) {
    stop("The joint-DP ledger does not match the immutable local policy.",
         call. = FALSE)
  }
  state <- .dsvert_joint_dp_allocator_state_read(
    connection, secret, allow_missing = TRUE)
  if (is.null(state)) {
    stop("The authenticated joint-DP allocator state is missing.",
         call. = FALSE)
  }
  binding <- .dsvert_joint_dp_allocator_state_binding(
    connection, metadata)
  .dsvert_joint_dp_allocator_state_assert_binding(
    connection, state, binding)
  next_index <- .dsvert_joint_dp_index(
    metadata[["next_index"]], "ledger index")
  if (!identical(next_index, state$committed_count) ||
      state$committed_count >
        context$lifetime$maximum_distinct_capsules ||
      (!is.null(state$prepared_query_id) &&
       state$committed_count >=
         context$lifetime$maximum_distinct_capsules) ||
      !identical(metadata[["chain_head"]], state$chain_head) ||
      !isTRUE(all.equal(
        as.numeric(metadata[["cumulative_epsilon"]]),
        as.numeric(state$cumulative_epsilon), tolerance = 1e-13)) ||
      !isTRUE(all.equal(
        as.numeric(metadata[["cumulative_delta"]]),
        as.numeric(state$cumulative_delta), tolerance = 1e-13))) {
    stop("The joint-DP ledger metadata is inconsistent.", call. = FALSE)
  }

  expected_last_sequence <- if (!is.null(state$prepared_query_id)) {
    state$committed_count
  } else if (state$committed_count > 0) {
    state$committed_count - 1
  } else {
    NULL
  }
  last_row <- if (is.null(expected_last_sequence)) {
    DBI::dbGetQuery(connection, "SELECT * FROM joint_records LIMIT 1")
  } else {
    DBI::dbGetQuery(connection,
      "SELECT * FROM joint_records WHERE sequence = ?",
      params = list(expected_last_sequence))
  }
  if (is.null(expected_last_sequence)) {
    if (nrow(last_row)) {
      stop("The empty joint-DP allocator has an unexpected record.",
           call. = FALSE)
    }
  } else if (nrow(last_row) != 1L ||
      !identical(as.numeric(last_row$sequence[[1L]]),
                 expected_last_sequence)) {
    stop("The joint-DP allocator tail does not match authenticated state.",
         call. = FALSE)
  }
  if (!is.null(expected_last_sequence) && nrow(DBI::dbGetQuery(
      connection,
      "SELECT 1 FROM joint_records WHERE sequence > ? LIMIT 1",
      params = list(expected_last_sequence)))) {
    stop("The joint-DP allocator has a record beyond its authenticated head.",
         call. = FALSE)
  }

  committed_tail <- NULL
  if (!is.null(state$prepared_query_id)) {
    prepared <- .dsvert_joint_dp_record_decode(last_row, secret)
    .dsvert_joint_dp_validate_record_policy(prepared, policy)
    .dsvert_joint_dp_validate_prepared_head(prepared, next_index, context)
    if (!identical(prepared$query_id, state$prepared_query_id) ||
        !identical(last_row$row_mac[[1L]], state$prepared_row_mac) ||
        !identical(prepared$previous_chain, state$chain_head)) {
      stop("The joint-DP prepared head failed authentication.",
           call. = FALSE)
    }
    if (state$committed_count > 0) {
      committed_tail <- DBI::dbGetQuery(connection,
        "SELECT * FROM joint_records WHERE sequence = ?",
        params = list(state$committed_count - 1))
    }
  } else if (state$committed_count > 0) {
    committed_tail <- last_row
  }
  if (state$committed_count > 0) {
    if (is.null(committed_tail) || nrow(committed_tail) != 1L) {
      stop("The joint-DP committed tail is unavailable.", call. = FALSE)
    }
    record <- .dsvert_joint_dp_record_decode(committed_tail, secret)
    .dsvert_joint_dp_validate_record_policy(record, policy)
    if (identical(record$state, "prepared") ||
        !identical(.dsvert_joint_dp_index(record$allocation_index),
                   state$committed_count - 1) ||
        !identical(record$query_id, state$tail_query_id) ||
        !identical(committed_tail$row_mac[[1L]], state$tail_row_mac) ||
        !is.character(record$joint_record_hash) ||
        !grepl("^[0-9a-f]{64}$", record$joint_record_hash) ||
        !identical(record$new_chain, state$chain_head) ||
        !identical(record$new_chain, .dsvert_joint_dp_chain_head(
          record$previous_chain, record$allocation_index,
          record$joint_record_hash, record$epsilon, record$delta))) {
      stop("The joint-DP committed tail failed authentication.",
           call. = FALSE)
    }
  }
  if (state$output_count == 0) {
    if (nrow(DBI::dbGetQuery(
        connection, "SELECT 1 FROM joint_outputs LIMIT 1"))) {
      stop("The joint-DP allocator has an unauthenticated output row.",
           call. = FALSE)
    }
  } else {
    output_tail <- DBI::dbGetQuery(connection,
      "SELECT * FROM joint_outputs WHERE query_id = ?",
      params = list(state$output_tail_query_id))
    if (nrow(output_tail) != 1L ||
        !identical(output_tail$row_mac[[1L]],
                   state$output_tail_row_mac)) {
      stop("The authenticated joint-DP output tail is unavailable.",
           call. = FALSE)
    }
    .dsvert_joint_dp_output_decode(output_tail, secret)
  }
  .dsvert_joint_dp_registry_journal_validate_local(
    connection, policy, context, secret,
    expected_journal_count = state$registry_eligible_count)
  invisible(list(context = context, state = state))
}

.dsvert_joint_dp_allocator_audit_savepoint <- function(connection, code) {
  name <- "dsvert_allocator_full_audit"
  DBI::dbExecute(connection, paste("SAVEPOINT", name))
  open <- TRUE
  on.exit(if (open) {
    try(DBI::dbExecute(
      connection, paste("ROLLBACK TO SAVEPOINT", name)), silent = TRUE)
    try(DBI::dbExecute(
      connection, paste("RELEASE SAVEPOINT", name)), silent = TRUE)
  }, add = TRUE)
  value <- force(code)
  DBI::dbExecute(connection, paste("RELEASE SAVEPOINT", name))
  open <- FALSE
  value
}

.dsvert_joint_dp_initialize_validate <- function(connection, policy, secret,
                                                  verifier = NULL) {
  metadata <- .dsvert_joint_dp_meta_snapshot(
    connection, .DSVERT_JOINT_DP_FAST_META_KEYS)
  schema <- metadata[["schema_version"]]
  state_marker <- metadata[[.DSVERT_JOINT_DP_ALLOCATOR_STATE_META_KEY]]
  context <- .dsvert_joint_dp_policy_context(policy)
  migrate_policy_hash <- !is.null(schema) &&
    !identical(metadata[["policy_hash"]], context$local_policy_hash)
  result <- if (is.null(schema) || is.null(state_marker) ||
      isTRUE(migrate_policy_hash)) {
    .dsvert_joint_dp_allocator_audit_savepoint(connection, {
      audited <- .dsvert_joint_dp_allocator_full_audit(
        connection, policy, secret, verifier,
        allow_legacy_policy_hash = isTRUE(migrate_policy_hash))
      if (isTRUE(audited$policy_hash_migration)) {
        # Epoch/key identifiers live in signed per-release receipts.  They
        # are intentionally absent from the durable allocator namespace, so
        # rotating a noise root never resets or denies authenticated history.
        .dsvert_joint_dp_meta_set(
          connection, "policy_hash", audited$context$local_policy_hash)
        .dsvert_joint_dp_allocator_state_write(
          connection, secret, audited$state)
        audited <- .dsvert_joint_dp_allocator_fast_validate(
          connection, policy, secret)
      }
      audited
    })
  } else {
    .dsvert_joint_dp_allocator_fast_validate(
      connection, policy, secret, metadata)
  }
  invisible(result$context)
}

.dsvert_joint_dp_allocator_forensic_audit <- function(
    connection, policy, secret, verifier = NULL) {
  result <- .dsvert_joint_dp_allocator_audit_savepoint(connection, {
    .dsvert_joint_dp_allocator_full_audit(
      connection, policy, secret, verifier)
  })
  invisible(result$context)
}

.dsvert_joint_dp_receipt_message <- function(receipt) {
  unsigned <- receipt[setdiff(names(receipt), "signature")]
  charToRaw(paste0(
    "dsVert/joint-dp/signed-receipt/v1|",
    .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(unsigned))))
}

.dsvert_joint_dp_sign <- function(
    receipt, policy, signer = NULL, require_designated = TRUE) {
  context <- .dsvert_joint_dp_policy_context(
    policy, require_designated = require_designated)
  own_pin <- if (isTRUE(require_designated)) {
    unname(context$pins[[context$peer_name]])
  } else if (context$peer_name %in% names(policy$peer_pinset)) {
    .dsvert_relay_normalize_identity_pk(
      unname(policy$peer_pinset[[context$peer_name]]))
  } else {
    stop("The local joint-DP peer is absent from the pinned map.",
         call. = FALSE)
  }
  if (is.null(signer)) {
    identity <- .get_identity_keypair()
    own_pk <- .dsvert_relay_normalize_identity_pk(identity$identity_pk)
    if (!identical(own_pk, own_pin)) {
      stop("Runtime identity does not match the joint-DP pinned identity.",
           call. = FALSE)
    }
    signature <- .dsvert_relay_sign_message(
      .dsvert_joint_dp_receipt_message(receipt), identity$identity_sk)
  } else {
    if (!is.function(signer)) stop("Invalid joint-DP signer.", call. = FALSE)
    signature <- signer(
      .dsvert_joint_dp_receipt_message(receipt), context$peer_name,
      own_pin)
  }
  if (!is.character(signature) || length(signature) != 1L ||
      is.na(signature) || !nzchar(signature) ||
      nchar(signature, type = "bytes") > 512L) {
    stop("The joint-DP receipt signature is invalid.", call. = FALSE)
  }
  c(receipt, list(signature = signature))
}

.dsvert_joint_dp_verify <- function(receipt, policy, expected_version,
                                     expected_phase, verifier = NULL,
                                     require_designated = TRUE) {
  context <- .dsvert_joint_dp_policy_context(
    policy, require_designated = require_designated)
  common_fields <- c(
    "version", "phase", "consortium_id", "peer_name",
    "peer_identity_pk", "capsule_id", "query_id", "allocation_index",
    "signature")
  version_fields <- if (identical(
      expected_version, .DSVERT_JOINT_DP_PREPARE_VERSION)) {
    c("privacy_epoch", "noise_key_id", "mechanism_hash", "epsilon",
      "delta", "previous_chain", "snapshot_binding", "seed_commitment",
      "rollback_mode")
  } else if (identical(expected_version, .DSVERT_JOINT_DP_COMMIT_VERSION)) {
    c("previous_chain", "new_chain", "joint_record_hash",
      "prepare_set_hash", "seed_commitment", "external_anchor")
  } else if (identical(
      expected_version, .DSVERT_JOINT_DP_AUTHORIZE_VERSION)) {
    c("new_chain", "joint_record_hash", "commit_set_hash",
      "peer_commit_stored")
  } else if (identical(expected_version, .DSVERT_JOINT_DP_OPEN_VERSION)) {
    c("new_chain", "joint_record_hash", "authorization_set_hash",
      "seed_commitment", "release_scope", "capability_available")
  } else if (identical(
      expected_version, .DSVERT_JOINT_DP_RESULT_PREPARE_VERSION)) {
    c("opening_set_hash", "result_contract_hash", "payload_commitment",
      "capability_available")
  } else if (identical(
      expected_version, .DSVERT_JOINT_DP_RESULT_COMMIT_VERSION)) {
    c("opening_set_hash", "result_contract_hash", "result_set_hash",
      "payload_commitment", "peer_result_stored", "capability_available")
  } else if (identical(expected_version, .DSVERT_JOINT_DP_DELIVERY_VERSION)) {
    c("result_contract_hash", "result_set_hash", "delivery_commit_set_hash",
      "payload_delivery_available", "capability_available")
  } else {
    character()
  }
  if (!is.list(receipt) || is.null(names(receipt)) || anyNA(names(receipt)) ||
      anyDuplicated(names(receipt)) ||
      !setequal(names(receipt), c(common_fields, version_fields)) ||
      !identical(receipt$version, expected_version) ||
      !identical(receipt$phase, expected_phase) ||
      !identical(receipt$consortium_id, context$consortium_id) ||
      !is.character(receipt$peer_name) || length(receipt$peer_name) != 1L ||
      !receipt$peer_name %in% names(context$pins) ||
      !identical(receipt$peer_identity_pk,
                 unname(context$pins[[receipt$peer_name]])) ||
      !is.character(receipt$signature) || length(receipt$signature) != 1L ||
      is.na(receipt$signature) || !nzchar(receipt$signature)) {
    stop("Invalid signed joint-DP receipt.", call. = FALSE)
  }
  hash_field <- function(name) {
    is.character(receipt[[name]]) && length(receipt[[name]]) == 1L &&
      !is.na(receipt[[name]]) && grepl("^[0-9a-f]{64}$", receipt[[name]])
  }
  base_valid <- hash_field("capsule_id") && hash_field("query_id") &&
    identical(receipt$capsule_id, receipt$query_id) &&
    is.character(receipt$allocation_index) &&
    length(receipt$allocation_index) == 1L &&
    !is.na(receipt$allocation_index) &&
    identical(as.character(.dsvert_joint_dp_index(receipt$allocation_index)),
              receipt$allocation_index)
  phase_valid <- if (identical(
      expected_version, .DSVERT_JOINT_DP_PREPARE_VERSION)) {
    hash_field("mechanism_hash") && hash_field("snapshot_binding") &&
      hash_field("seed_commitment") &&
      (identical(receipt$previous_chain, "GENESIS") ||
       hash_field("previous_chain")) &&
      is.character(receipt$privacy_epoch) &&
      length(receipt$privacy_epoch) == 1L &&
      .dsvert_joint_dp_index(receipt$privacy_epoch, "privacy epoch") >= 1 &&
      is.character(receipt$noise_key_id) &&
      length(receipt$noise_key_id) == 1L &&
      !is.na(receipt$noise_key_id) && nzchar(receipt$noise_key_id) &&
      is.character(receipt$epsilon) && length(receipt$epsilon) == 1L &&
      is.finite(suppressWarnings(as.numeric(receipt$epsilon))) &&
      as.numeric(receipt$epsilon) >= .DSVERT_DP_MINIMUM_EPSILON &&
      is.character(receipt$delta) && length(receipt$delta) == 1L &&
      is.finite(suppressWarnings(as.numeric(receipt$delta))) &&
      as.numeric(receipt$delta) >= 0 && as.numeric(receipt$delta) < 1 &&
      receipt$rollback_mode %in% c(
        "cross_signed_two_peer",
        "cross_signed_two_peer_plus_external_cas")
  } else if (identical(expected_version, .DSVERT_JOINT_DP_COMMIT_VERSION)) {
    (identical(receipt$previous_chain, "GENESIS") ||
     hash_field("previous_chain")) && hash_field("new_chain") &&
      hash_field("joint_record_hash") && hash_field("prepare_set_hash") &&
      hash_field("seed_commitment") &&
      is.logical(receipt$external_anchor) &&
      length(receipt$external_anchor) == 1L && !is.na(receipt$external_anchor)
  } else if (identical(
      expected_version, .DSVERT_JOINT_DP_AUTHORIZE_VERSION)) {
    hash_field("new_chain") && hash_field("joint_record_hash") &&
      hash_field("commit_set_hash") &&
      identical(receipt$peer_commit_stored, TRUE)
  } else if (identical(expected_version, .DSVERT_JOINT_DP_OPEN_VERSION)) {
    hash_field("new_chain") && hash_field("joint_record_hash") &&
      hash_field("authorization_set_hash") && hash_field("seed_commitment") &&
      identical(receipt$release_scope, .DSVERT_JOINT_DP_SCOPE) &&
      identical(receipt$capability_available, FALSE)
  } else if (identical(
      expected_version, .DSVERT_JOINT_DP_RESULT_PREPARE_VERSION)) {
    hash_field("opening_set_hash") && hash_field("result_contract_hash") &&
      hash_field("payload_commitment") &&
      identical(receipt$capability_available, FALSE)
  } else if (identical(
      expected_version, .DSVERT_JOINT_DP_RESULT_COMMIT_VERSION)) {
    hash_field("opening_set_hash") && hash_field("result_contract_hash") &&
      hash_field("result_set_hash") && hash_field("payload_commitment") &&
      identical(receipt$peer_result_stored, TRUE) &&
      identical(receipt$capability_available, FALSE)
  } else if (identical(expected_version, .DSVERT_JOINT_DP_DELIVERY_VERSION)) {
    hash_field("result_contract_hash") && hash_field("result_set_hash") &&
      hash_field("delivery_commit_set_hash") &&
      identical(receipt$payload_delivery_available, FALSE) &&
      identical(receipt$capability_available, FALSE)
  } else {
    FALSE
  }
  if (!isTRUE(base_valid) || !isTRUE(phase_valid)) {
    stop("Invalid signed joint-DP receipt fields.", call. = FALSE)
  }
  valid <- if (is.null(verifier)) {
    .dsvert_relay_verify_message(
      .dsvert_joint_dp_receipt_message(receipt),
      unname(context$pins[[receipt$peer_name]]), receipt$signature)
  } else {
    if (!is.function(verifier)) stop("Invalid joint-DP verifier.", call. = FALSE)
    verifier(
      .dsvert_joint_dp_receipt_message(receipt),
      unname(context$pins[[receipt$peer_name]]), receipt$signature,
      receipt$peer_name)
  }
  if (!isTRUE(valid)) {
    stop("Joint-DP receipt signature verification failed.", call. = FALSE)
  }
  invisible(receipt)
}

.dsvert_joint_dp_receipt_set <- function(left, right, policy, version, phase,
                                          verifier = NULL,
                                          require_designated = TRUE) {
  .dsvert_joint_dp_verify(
    left, policy, version, phase, verifier, require_designated)
  .dsvert_joint_dp_verify(
    right, policy, version, phase, verifier, require_designated)
  context <- .dsvert_joint_dp_policy_context(
    policy, require_designated = require_designated)
  values <- list(left, right)
  names(values) <- vapply(values, `[[`, character(1L), "peer_name")
  if (anyDuplicated(names(values)) ||
      !setequal(names(values), names(context$pins))) {
    stop("Joint DP requires one receipt from each pinned peer.", call. = FALSE)
  }
  values[order(names(values), method = "radix")]
}

.dsvert_joint_dp_output_common <- function(receipts, fields, what) {
  reference <- receipts[[1L]][fields]
  if (!all(vapply(receipts[-1L], function(value) {
    identical(value[fields], reference)
  }, logical(1L)))) {
    stop("The two joint-DP ", what,
         " receipts do not describe one result.", call. = FALSE)
  }
  reference
}

.dsvert_joint_dp_validate_commit_payloads <- function(commits, results) {
  peers <- names(commits)
  if (!identical(peers, names(results)) ||
      !all(vapply(peers, function(peer) {
        identical(commits[[peer]]$payload_commitment,
                  results[[peer]]$payload_commitment)
      }, logical(1L)))) {
    stop("A joint-DP result commit does not match its peer's prepared payload.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_joint_dp_validate_output_record <- function(
    output, record, policy, context = .dsvert_joint_dp_policy_context(policy),
    verifier = NULL) {
  if (!is.list(output) || !is.list(record) ||
      !identical(record$state, "open_authorized") ||
      !identical(output$query_id, record$query_id)) {
    stop("The joint-DP result does not match an open-authorized allocation.",
         call. = FALSE)
  }
  openings <- .dsvert_joint_dp_receipt_set(
    output$own_opening_token, output$peer_opening_token, policy,
    .DSVERT_JOINT_DP_OPEN_VERSION, "open_authorized", verifier)
  opening_common <- .dsvert_joint_dp_output_common(
    openings,
    c("consortium_id", "capsule_id", "query_id", "allocation_index",
      "new_chain", "joint_record_hash", "authorization_set_hash",
      "release_scope", "capability_available"),
    "opening")
  if (!identical(openings[[context$peer_name]], record$opening_token) ||
      !identical(opening_common$query_id, record$query_id) ||
      !identical(opening_common$allocation_index,
                 record$allocation_index) ||
      !identical(output$opening_set_hash,
                 .dsvert_joint_dp_hash(openings))) {
    stop("The joint-DP persisted opening set is inconsistent.",
         call. = FALSE)
  }

  .dsvert_joint_dp_verify(
    output$own_result_prepare, policy,
    .DSVERT_JOINT_DP_RESULT_PREPARE_VERSION, "result_prepared", verifier)
  own_result <- output$own_result_prepare
  if (!identical(own_result$peer_name, context$peer_name) ||
      !identical(own_result$query_id, output$query_id) ||
      !identical(own_result$allocation_index, record$allocation_index) ||
      !identical(own_result$opening_set_hash, output$opening_set_hash) ||
      !identical(own_result$result_contract_hash,
                 output$result_contract_hash) ||
      !identical(own_result$payload_commitment,
                 output$payload_commitment)) {
    stop("The joint-DP local result receipt is inconsistent.", call. = FALSE)
  }

  if (identical(output$state, "result_prepared")) {
    if (!all(vapply(output[c(
      "peer_result_prepare", "result_set_hash", "own_delivery_commit",
      "peer_delivery_commit", "delivery_token")], is.null, logical(1L)))) {
      stop("The joint-DP prepared result contains later-phase state.",
           call. = FALSE)
    }
    return(invisible(output))
  }

  results <- .dsvert_joint_dp_receipt_set(
    output$own_result_prepare, output$peer_result_prepare, policy,
    .DSVERT_JOINT_DP_RESULT_PREPARE_VERSION, "result_prepared", verifier)
  result_common <- .dsvert_joint_dp_output_common(
    results,
    c("consortium_id", "capsule_id", "query_id", "allocation_index",
      "opening_set_hash", "result_contract_hash", "capability_available"),
    "result-prepare")
  if (!identical(result_common$query_id, output$query_id) ||
      !identical(result_common$opening_set_hash, output$opening_set_hash) ||
      !identical(result_common$result_contract_hash,
                 output$result_contract_hash) ||
      !identical(output$result_set_hash, .dsvert_joint_dp_hash(results))) {
    stop("The joint-DP result receipt set is inconsistent.", call. = FALSE)
  }

  .dsvert_joint_dp_verify(
    output$own_delivery_commit, policy,
    .DSVERT_JOINT_DP_RESULT_COMMIT_VERSION, "result_committed", verifier)
  own_commit <- output$own_delivery_commit
  if (!identical(own_commit$peer_name, context$peer_name) ||
      !identical(own_commit$query_id, output$query_id) ||
      !identical(own_commit$allocation_index, record$allocation_index) ||
      !identical(own_commit$opening_set_hash, output$opening_set_hash) ||
      !identical(own_commit$result_contract_hash,
                 output$result_contract_hash) ||
      !identical(own_commit$result_set_hash, output$result_set_hash) ||
      !identical(own_commit$payload_commitment,
                 output$payload_commitment)) {
    stop("The joint-DP local result commit is inconsistent.", call. = FALSE)
  }
  if (identical(output$state, "result_committed")) {
    if (!is.null(output$peer_delivery_commit) ||
        !is.null(output$delivery_token)) {
      stop("The joint-DP committed result contains delivery state.",
           call. = FALSE)
    }
    return(invisible(output))
  }

  commits <- .dsvert_joint_dp_receipt_set(
    output$own_delivery_commit, output$peer_delivery_commit, policy,
    .DSVERT_JOINT_DP_RESULT_COMMIT_VERSION, "result_committed", verifier)
  .dsvert_joint_dp_validate_commit_payloads(commits, results)
  commit_common <- .dsvert_joint_dp_output_common(
    commits,
    c("consortium_id", "capsule_id", "query_id", "allocation_index",
      "opening_set_hash", "result_contract_hash", "result_set_hash",
      "peer_result_stored", "capability_available"),
    "result-commit")
  delivery_commit_set_hash <- .dsvert_joint_dp_hash(commits)
  .dsvert_joint_dp_verify(
    output$delivery_token, policy, .DSVERT_JOINT_DP_DELIVERY_VERSION,
    "delivery_authorized", verifier)
  token <- output$delivery_token
  if (!identical(commit_common$query_id, output$query_id) ||
      !identical(commit_common$result_set_hash, output$result_set_hash) ||
      !identical(token$peer_name, context$peer_name) ||
      !identical(token$query_id, output$query_id) ||
      !identical(token$allocation_index, record$allocation_index) ||
      !identical(token$result_contract_hash,
                 output$result_contract_hash) ||
      !identical(token$result_set_hash, output$result_set_hash) ||
      !identical(token$delivery_commit_set_hash,
                 delivery_commit_set_hash)) {
    stop("The joint-DP delivery authorization is inconsistent.",
         call. = FALSE)
  }
  invisible(output)
}

.dsvert_joint_dp_external_anchor_id <- function(context) {
  paste0("jdpa1_", .dsvert_joint_dp_hash(list(
    consortium_id = context$consortium_id,
    peer_name = context$peer_name,
    identity_pk = unname(context$pins[[context$peer_name]]))))
}

.dsvert_joint_dp_anchor_call <- function(policy, context, action, ...) {
  provider <- policy$anchor_provider
  if (!is.function(provider)) return(NULL)
  tryCatch(do.call(provider, c(list(
    action = action,
    anchor_id = .dsvert_joint_dp_external_anchor_id(context)), list(...))),
    error = function(e) stop(
      "The optional external joint-DP rollback anchor failed.", call. = FALSE))
}

.dsvert_joint_dp_anchor_state <- function(
    value, context, allow_null = FALSE,
    allow_policy_hash_migration = FALSE) {
  if (is.null(value) && isTRUE(allow_null)) return(NULL)
  required <- c("schema_version", "policy_hash", "next_index", "chain_head")
  valid_policy_hash <- is.list(value) && is.character(value$policy_hash) &&
    length(value$policy_hash) == 1L && !is.na(value$policy_hash) &&
    (identical(value$policy_hash, context$local_policy_hash) ||
     (isTRUE(allow_policy_hash_migration) &&
      grepl("^[0-9a-f]{64}$", value$policy_hash)))
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyDuplicated(names(value)) && setequal(names(value), required) &&
    identical(as.numeric(value$schema_version), 2) &&
    isTRUE(valid_policy_hash) &&
    is.numeric(value$next_index) && length(value$next_index) == 1L &&
    !is.na(value$next_index) && is.finite(value$next_index) &&
    value$next_index >= 0 && value$next_index <= 2^53 - 1 &&
    value$next_index == floor(value$next_index) &&
    is.character(value$chain_head) && length(value$chain_head) == 1L &&
    ((value$next_index == 0 && identical(value$chain_head, "GENESIS")) ||
       (value$next_index > 0 && grepl("^[0-9a-f]{64}$", value$chain_head)))
  if (!isTRUE(valid)) {
    stop("The optional external joint-DP anchor returned invalid state.",
         call. = FALSE)
  }
  list(schema_version = 2L, policy_hash = value$policy_hash,
       next_index = as.numeric(value$next_index), chain_head = value$chain_head)
}

.dsvert_joint_dp_sync_external_anchor <- function(connection, policy,
                                                   context, secret) {
  if (!is.function(policy$anchor_provider)) return(invisible(FALSE))
  capabilities <- .dsvert_joint_dp_anchor_call(
    policy, context, "capabilities")
  if (!is.list(capabilities) ||
      !identical(as.numeric(capabilities$schema_version), 2) ||
      !identical(capabilities$external, TRUE) ||
      !identical(capabilities$durable, TRUE) ||
      !identical(capabilities$linearizable_cas, TRUE)) {
    stop("The optional joint-DP anchor lacks durable linearizable CAS.",
         call. = FALSE)
  }
  current <- .dsvert_joint_dp_anchor_state(
    .dsvert_joint_dp_anchor_call(policy, context, "read"), context,
    allow_null = TRUE, allow_policy_hash_migration = TRUE)
  if (is.null(current)) {
    initial <- list(
      schema_version = 2L, policy_hash = context$local_policy_hash,
      next_index = 0, chain_head = "GENESIS")
    outcome <- .dsvert_joint_dp_anchor_call(
      policy, context, "compare_and_swap", expected = NULL,
      replacement = initial)
    if (!is.list(outcome) || !is.logical(outcome$swapped) ||
        length(outcome$swapped) != 1L || is.na(outcome$swapped)) {
      stop("The optional joint-DP anchor returned invalid CAS state.",
           call. = FALSE)
    }
    current <- .dsvert_joint_dp_anchor_state(
      outcome$state, context, allow_policy_hash_migration = TRUE)
  }
  local_index <- .dsvert_joint_dp_index(
    .dsvert_joint_dp_meta_get(connection, "next_index"), "ledger index")
  if (current$next_index > local_index) {
    stop("The external joint-DP anchor is ahead of the local ledger; restore the durable ledger before continuing.",
         call. = FALSE)
  }
  head_at <- function(index) {
    if (index == 0) return("GENESIS")
    row <- DBI::dbGetQuery(connection,
      "SELECT * FROM joint_records WHERE sequence = ?", params = list(index - 1))
    record <- .dsvert_joint_dp_record_decode(row, secret)
    record$new_chain
  }
  if (!identical(current$chain_head, head_at(current$next_index))) {
    stop("The external and local joint-DP anchors diverged.", call. = FALSE)
  }
  if (!identical(current$policy_hash, context$local_policy_hash)) {
    replacement <- list(
      schema_version = 2L, policy_hash = context$local_policy_hash,
      next_index = current$next_index, chain_head = current$chain_head)
    outcome <- tryCatch(.dsvert_joint_dp_anchor_call(
      policy, context, "compare_and_swap", expected = current,
      replacement = replacement), error = identity)
    if (inherits(outcome, "error")) {
      observed <- .dsvert_joint_dp_anchor_state(
        .dsvert_joint_dp_anchor_call(policy, context, "read"), context,
        allow_policy_hash_migration = TRUE)
      if (identical(observed, replacement)) {
        current <- replacement
      } else {
        stop("The external joint-DP anchor policy migration outcome is ambiguous.",
             call. = FALSE)
      }
    } else {
      if (!is.list(outcome) || !is.logical(outcome$swapped) ||
          length(outcome$swapped) != 1L || is.na(outcome$swapped)) {
        stop("The optional joint-DP anchor returned invalid CAS state.",
             call. = FALSE)
      }
      observed <- .dsvert_joint_dp_anchor_state(
        outcome$state, context, allow_policy_hash_migration = TRUE)
      if (isTRUE(outcome$swapped) && !identical(observed, replacement)) {
        stop("The external joint-DP anchor returned a false policy-migration CAS acknowledgement.",
             call. = FALSE)
      }
      if (!isTRUE(outcome$swapped) && !identical(observed, replacement)) {
        stop("The external joint-DP anchor rejected its policy migration.",
             call. = FALSE)
      }
      current <- replacement
    }
  }
  while (current$next_index < local_index) {
    row <- DBI::dbGetQuery(connection,
      "SELECT * FROM joint_records WHERE sequence = ?",
      params = list(current$next_index))
    record <- .dsvert_joint_dp_record_decode(row, secret)
    replacement <- list(
      schema_version = 2L, policy_hash = context$local_policy_hash,
      next_index = current$next_index + 1, chain_head = record$new_chain)
    outcome <- tryCatch(.dsvert_joint_dp_anchor_call(
      policy, context, "compare_and_swap", expected = current,
      replacement = replacement), error = identity)
    if (inherits(outcome, "error")) {
      observed <- .dsvert_joint_dp_anchor_state(
        .dsvert_joint_dp_anchor_call(policy, context, "read"), context)
      if (identical(observed, replacement)) {
        current <- replacement
        next
      }
      stop("The external joint-DP anchor outcome is ambiguous.",
           call. = FALSE)
    }
    if (!is.list(outcome) || !is.logical(outcome$swapped) ||
        length(outcome$swapped) != 1L || is.na(outcome$swapped)) {
      stop("The optional joint-DP anchor returned invalid CAS state.",
           call. = FALSE)
    }
    observed <- .dsvert_joint_dp_anchor_state(outcome$state, context)
    if (!isTRUE(outcome$swapped) && !identical(observed, replacement)) {
      stop("The external joint-DP anchor rejected a committed allocation.",
           call. = FALSE)
    }
    current <- replacement
  }
  invisible(TRUE)
}

.dsvert_joint_dp_transaction <- function(connection, code) {
  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  open <- TRUE
  on.exit(if (open) try(DBI::dbExecute(connection, "ROLLBACK"), silent = TRUE),
          add = TRUE)
  value <- force(code)
  DBI::dbExecute(connection, "COMMIT")
  open <- FALSE
  value
}

.dsvert_joint_dp_load <- function(connection, query_id, secret) {
  row <- DBI::dbGetQuery(connection,
    "SELECT * FROM joint_records WHERE query_id = ?", params = list(query_id))
  if (!nrow(row)) NULL else .dsvert_joint_dp_record_decode(row, secret)
}

.dsvert_joint_dp_phase <- function(hook, phase) {
  if (!is.null(hook)) {
    if (!is.function(hook)) stop("Invalid joint-DP phase hook.", call. = FALSE)
    hook(phase)
  }
  invisible(NULL)
}

.dsvert_joint_dp_prepare <- function(
    policy, proposal, leader_prepare = NULL, .secret = NULL,
    .signer = NULL, .verifier = NULL, .phase_hook = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  required <- c(
    "capsule_id", "query_id", "common_query", "mechanism_hash",
    "sensitivity", "uses_delta", "snapshot_binding")
  query_fields <- c(
    "protocol", "capsule_id", "capsule_identity", "mechanism")
  capsule_identity <- if (is.list(proposal) &&
      is.list(proposal$common_query) &&
      is.list(proposal$common_query$capsule_identity)) {
    tryCatch(.dsvert_joint_dp_capsule_identity_validate(
      policy,
      proposal$common_query$capsule_identity$logical_snapshot,
      list(
        capsule_id = proposal$capsule_id,
        contract = proposal$common_query$capsule_identity)),
      error = function(e) NULL)
  } else {
    NULL
  }
  query_valid <- is.list(proposal) && is.list(proposal$common_query) &&
    !is.null(names(proposal$common_query)) &&
    !anyNA(names(proposal$common_query)) &&
    !anyDuplicated(names(proposal$common_query)) &&
    setequal(names(proposal$common_query), query_fields) &&
    identical(proposal$common_query$protocol,
              .DSVERT_JOINT_DP_CAPSULE_VERSION) &&
    identical(proposal$common_query$capsule_id, proposal$capsule_id) &&
    !is.null(capsule_identity)
  mechanism <- if (isTRUE(query_valid)) {
    tryCatch(.dsvert_joint_dp_mechanism(
      proposal$common_query$mechanism, policy), error = function(e) NULL)
  } else {
    NULL
  }
  capsule_mechanism <- if (!is.null(capsule_identity)) {
    capsule_identity$contract$workload$capsule_mechanism
  } else {
    NULL
  }
  if (!is.list(proposal) || is.null(names(proposal)) ||
      anyDuplicated(names(proposal)) || !setequal(names(proposal), required) ||
      !isTRUE(query_valid) || is.null(mechanism) ||
      !is.list(capsule_mechanism) ||
      !identical(capsule_mechanism, mechanism) ||
      !grepl("^[0-9a-f]{64}$", proposal$capsule_id) ||
      !grepl("^[0-9a-f]{64}$", proposal$query_id) ||
      !identical(proposal$capsule_id, proposal$query_id) ||
      !identical(proposal$query_id,
                 .dsvert_joint_dp_hash(
                   proposal$common_query$capsule_identity)) ||
      !grepl("^[0-9a-f]{64}$", proposal$mechanism_hash) ||
      !identical(proposal$mechanism_hash,
                 .dsvert_joint_dp_hash(mechanism)) ||
      !is.numeric(proposal$sensitivity) || length(proposal$sensitivity) != 1L ||
      is.na(proposal$sensitivity) || !is.finite(proposal$sensitivity) ||
      proposal$sensitivity <= 0 ||
      !identical(as.numeric(proposal$sensitivity),
                 as.numeric(mechanism$sensitivity)) ||
      !is.logical(proposal$uses_delta) ||
      length(proposal$uses_delta) != 1L || is.na(proposal$uses_delta) ||
      !identical(proposal$uses_delta, mechanism$uses_delta) ||
      !grepl("^[0-9a-f]{64}$", proposal$snapshot_binding)) {
    stop("Invalid server-minted joint-DP proposal.", call. = FALSE)
  }
  roles <- .dsvert_joint_dp_allocator_roles(context)
  is_leader <- identical(context$peer_name, roles$leader)
  if (is_leader) {
    if (!is.null(leader_prepare)) {
      stop("The designated allocator leader cannot consume a leader receipt.",
           call. = FALSE)
    }
  } else {
    if (is.null(leader_prepare)) {
      stop("The allocator follower requires the signed leader assignment.",
           call. = FALSE)
    }
    leader_prepare <- .dsvert_joint_dp_verify(
      leader_prepare, policy, .DSVERT_JOINT_DP_PREPARE_VERSION,
      "prepared", .verifier)
    if (!identical(leader_prepare$peer_name, roles$leader) ||
        !identical(leader_prepare$capsule_id, proposal$capsule_id) ||
        !identical(leader_prepare$query_id, proposal$query_id) ||
        !identical(leader_prepare$mechanism_hash,
                   proposal$mechanism_hash)) {
      stop("The signed leader assignment does not match the local proposal.",
           call. = FALSE)
    }
  }
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  connection <- handle$connection
  .dsvert_joint_dp_transaction(connection, {
    .dsvert_joint_dp_initialize_validate(connection, policy, .secret)
  })
  .dsvert_joint_dp_sync_external_anchor(
    connection, policy, context, .secret)
  receipt <- .dsvert_joint_dp_transaction(connection, {
    .dsvert_joint_dp_initialize_validate(connection, policy, .secret)
    existing <- .dsvert_joint_dp_load(connection, proposal$query_id, .secret)
    if (!is.null(existing)) {
      if (!identical(.dsvert_joint_dp_hash(
                       existing$common_query$capsule_identity),
                     proposal$query_id) ||
          !identical(existing$own_prepare$mechanism_hash,
                     proposal$mechanism_hash) ||
          !identical(as.numeric(existing$sensitivity),
                     as.numeric(proposal$sensitivity)) ||
          !identical(existing$uses_delta, proposal$uses_delta) ||
          !identical(existing$own_prepare$snapshot_binding,
                     proposal$snapshot_binding)) {
        stop("The private snapshot or mechanism changed for an existing joint-DP query.",
             call. = FALSE)
      }
      if (!is_leader &&
          (!is.list(existing$peer_prepare) ||
           !identical(existing$peer_prepare, leader_prepare))) {
        stop("The replayed follower assignment differs from its durable leader receipt.",
             call. = FALSE)
      }
      existing$own_prepare
    } else {
      .dsvert_joint_dp_allocator_forensic_audit(
        connection, policy, .secret, .verifier)
      index <- .dsvert_joint_dp_index(
        .dsvert_joint_dp_meta_get(connection, "next_index"), "ledger index")
      if (index >= context$lifetime$maximum_distinct_capsules) {
        stop(.dsvert_dp_lifetime_budget_exhausted_condition())
      }
      occupied <- DBI::dbGetQuery(connection,
        "SELECT query_id FROM joint_records WHERE sequence = ?",
        params = list(index))
      if (nrow(occupied)) {
        stop("A different joint-DP proposal already occupies the consensus head.",
             call. = FALSE)
      }
      epsilon <- policy$global_total_epsilon
      delta <- if (isTRUE(proposal$uses_delta)) {
        policy$global_total_delta
      } else {
        0
      }
      if (!is.finite(epsilon) || epsilon < .DSVERT_DP_MINIMUM_EPSILON ||
          !is.finite(delta) || delta < 0) {
        stop("The joint-DP capsule privacy parameters are not representable.",
             call. = FALSE)
      }
      epsilon_text <- .dsvert_joint_dp_decimal(
        epsilon, "epsilon", .DSVERT_DP_MINIMUM_EPSILON,
        .DSVERT_DP_MAXIMUM_EPSILON)
      delta_text <- .dsvert_joint_dp_decimal(delta, "delta", 0, 1)
      previous_chain <- .dsvert_joint_dp_meta_get(connection, "chain_head")
      if (!is_leader) {
        expected_assignment <- list(
          consortium_id = context$consortium_id,
          capsule_id = proposal$capsule_id,
          query_id = proposal$query_id,
          privacy_epoch = as.character(policy$noise_root$epoch),
          mechanism_hash = proposal$mechanism_hash,
          allocation_index = as.character(index),
          epsilon = epsilon_text, delta = delta_text,
          previous_chain = previous_chain)
        if (!.dsvert_joint_dp_same_prepare_assignment(
              leader_prepare, expected_assignment)) {
          stop("The leader assignment conflicts with the follower consensus head.",
               call. = FALSE)
        }
      }
      seed <- .dsvert_dp_noise_seed(
        policy, proposal$query_id, index,
        paste0("joint-mpc/", proposal$mechanism_hash), epsilon, delta,
        proposal$sensitivity)
      seed_commitment <- digest::digest(paste0(
        "dsVert/joint-dp/private-seed-commitment/v1|", seed),
        algo = "sha256", serialize = FALSE)
      unsigned <- list(
        version = .DSVERT_JOINT_DP_PREPARE_VERSION,
        phase = "prepared",
        consortium_id = context$consortium_id,
        peer_name = context$peer_name,
        peer_identity_pk = unname(context$pins[[context$peer_name]]),
        capsule_id = proposal$capsule_id,
        query_id = proposal$query_id,
        privacy_epoch = as.character(policy$noise_root$epoch),
        noise_key_id = policy$noise_root$key_id,
        mechanism_hash = proposal$mechanism_hash,
        allocation_index = as.character(index),
        epsilon = epsilon_text,
        delta = delta_text,
        previous_chain = previous_chain,
        snapshot_binding = proposal$snapshot_binding,
        seed_commitment = seed_commitment,
        rollback_mode = if (is.function(policy$anchor_provider)) {
          "cross_signed_two_peer_plus_external_cas"
        } else {
          "cross_signed_two_peer"
        })
      own_prepare <- .dsvert_joint_dp_sign(unsigned, policy, .signer)
      record <- list(
        version = .DSVERT_JOINT_DP_VERSION,
        query_id = proposal$query_id,
        allocation_index = as.character(index), state = "prepared",
        previous_chain = previous_chain, new_chain = NULL,
        epsilon = epsilon_text, delta = delta_text,
        common_query = proposal$common_query,
        sensitivity = proposal$sensitivity,
        uses_delta = proposal$uses_delta,
        own_prepare = own_prepare,
        peer_prepare = if (is_leader) NULL else leader_prepare,
        joint_record_hash = NULL, own_commit = NULL, peer_commit = NULL,
        own_authorization = NULL, peer_authorization = NULL,
        opening_token = NULL)
      .dsvert_joint_dp_record_store(
        connection, record, .secret, insert = TRUE)
      own_prepare
    }
  })
  .dsvert_joint_dp_phase(.phase_hook, "after_prepare_commit")
  receipt
}

.dsvert_joint_dp_prepare_common <- function(receipts) {
  fields <- c(
    "consortium_id", "capsule_id", "query_id", "mechanism_hash",
    "allocation_index", "epsilon", "delta", "previous_chain")
  reference <- receipts[[1L]][fields]
  if (!all(vapply(receipts[-1L], function(value) {
    identical(value[fields], reference)
  }, logical(1L)))) {
    stop("The two joint-DP prepare receipts do not describe one allocation.",
         call. = FALSE)
  }
  reference
}

.dsvert_joint_dp_commit <- function(
    policy, left_prepare, right_prepare, .secret = NULL, .signer = NULL,
    .verifier = NULL, .phase_hook = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  prepares <- .dsvert_joint_dp_receipt_set(
    left_prepare, right_prepare, policy, .DSVERT_JOINT_DP_PREPARE_VERSION,
    "prepared", .verifier)
  common <- .dsvert_joint_dp_prepare_common(prepares)
  query_id <- common$query_id
  prepare_set_hash <- .dsvert_joint_dp_hash(prepares)
  privacy_epochs <- vapply(
    prepares, `[[`, character(1L), "privacy_epoch")
  legacy_epoch_consensus <- length(unique(privacy_epochs)) == 1L
  record_protocol <- if (legacy_epoch_consensus) {
    "dsvert-joint-dp-joint-record-v1"
  } else {
    "dsvert-joint-dp-joint-record-v2-independent-peer-epochs"
  }
  record_common <- if (legacy_epoch_consensus) {
    prepares[[1L]][c(
      "consortium_id", "capsule_id", "query_id", "privacy_epoch",
      "mechanism_hash", "allocation_index", "epsilon", "delta",
      "previous_chain")]
  } else common
  peer_fields <- c(
    "peer_name", "peer_identity_pk", "noise_key_id",
    if (!legacy_epoch_consensus) "privacy_epoch" else character(),
    "snapshot_binding", "seed_commitment", "rollback_mode")
  joint_record_hash <- .dsvert_joint_dp_hash(list(
    protocol = record_protocol,
    common = record_common,
    peers = lapply(prepares, function(value) value[peer_fields]),
    prepare_set_hash = prepare_set_hash))
  new_chain <- .dsvert_joint_dp_chain_head(
    common$previous_chain, common$allocation_index, joint_record_hash,
    common$epsilon, common$delta)
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  connection <- handle$connection
  .dsvert_joint_dp_transaction(connection, {
    .dsvert_joint_dp_initialize_validate(connection, policy, .secret)
  })
  .dsvert_joint_dp_sync_external_anchor(
    connection, policy, context, .secret)
  own_commit <- .dsvert_joint_dp_transaction(connection, {
    .dsvert_joint_dp_initialize_validate(connection, policy, .secret)
    record <- .dsvert_joint_dp_load(connection, query_id, .secret)
    if (is.null(record)) {
      stop("The local joint-DP prepare reservation is unavailable.",
           call. = FALSE)
    }
    own_prepare <- prepares[[context$peer_name]]
    peer_prepare <- prepares[[setdiff(names(prepares), context$peer_name)]]
    if (!identical(record$own_prepare, own_prepare) ||
        (!is.null(record$peer_prepare) &&
         !identical(record$peer_prepare, peer_prepare)) ||
        !identical(record$previous_chain, common$previous_chain) ||
        !identical(record$allocation_index, common$allocation_index) ||
        !identical(record$epsilon, common$epsilon) ||
        !identical(record$delta, common$delta)) {
      stop("The peer receipt set conflicts with the local joint-DP reservation.",
           call. = FALSE)
    }
    local_commit <- if (!identical(record$state, "prepared")) {
      if (!identical(record$joint_record_hash, joint_record_hash)) {
        stop("Conflicting replay of a committed joint-DP allocation.",
             call. = FALSE)
      }
      record$own_commit
    } else {
      index <- .dsvert_joint_dp_index(record$allocation_index)
      registry_audit <- .dsvert_joint_dp_registry_journal_audit(
        connection, policy, context, .secret,
        require_enabled = index > 0)
      if (!identical(as.numeric(registry_audit$state$journal_count), index)) {
        stop("The cross-signed allocator and capsule-registry journal are incomplete.",
             call. = FALSE)
      }
      unsigned <- list(
      version = .DSVERT_JOINT_DP_COMMIT_VERSION,
      phase = "committed",
      consortium_id = context$consortium_id,
      peer_name = context$peer_name,
      peer_identity_pk = unname(context$pins[[context$peer_name]]),
      capsule_id = common$capsule_id,
      query_id = query_id,
      allocation_index = common$allocation_index,
      previous_chain = common$previous_chain,
      new_chain = new_chain,
      joint_record_hash = joint_record_hash,
      prepare_set_hash = prepare_set_hash,
      seed_commitment = own_prepare$seed_commitment,
      external_anchor = is.function(policy$anchor_provider))
      local_commit <- .dsvert_joint_dp_sign(unsigned, policy, .signer)
      record$state <- "locally_committed"
      record$new_chain <- new_chain
      record$peer_prepare <- peer_prepare
      record$joint_record_hash <- joint_record_hash
      record$own_commit <- local_commit
      .dsvert_joint_dp_record_store(connection, record, .secret)
      .dsvert_joint_dp_meta_set(connection, "next_index", index + 1)
      .dsvert_joint_dp_meta_set(connection, "chain_head", new_chain)
      .dsvert_joint_dp_meta_set(connection, "cumulative_epsilon", sub(
        getOption("OutDec", "."), ".", format(
          as.numeric(.dsvert_joint_dp_meta_get(connection,
                                               "cumulative_epsilon")) +
            as.numeric(record$epsilon), digits = 17L), fixed = TRUE))
      .dsvert_joint_dp_meta_set(connection, "cumulative_delta", sub(
        getOption("OutDec", "."), ".", format(
          as.numeric(.dsvert_joint_dp_meta_get(connection,
                                               "cumulative_delta")) +
            as.numeric(record$delta), digits = 17L), fixed = TRUE))
      local_commit
    }
    .dsvert_joint_dp_registry_journal_ensure(
      connection, policy, context, record, .secret)
    .dsvert_joint_dp_registry_journal_migrate(
      connection, policy, context, .secret)
    local_commit
  })
  .dsvert_joint_dp_phase(.phase_hook, "after_local_commit")
  .dsvert_joint_dp_sync_external_anchor(
    connection, policy, context, .secret)
  .dsvert_joint_dp_phase(.phase_hook, "after_external_anchor")
  own_commit <- .dsvert_joint_dp_transaction(connection, {
    .dsvert_joint_dp_initialize_validate(connection, policy, .secret)
    record <- .dsvert_joint_dp_load(connection, query_id, .secret)
    if (!record$state %in% c("locally_committed", "committed",
                             "authorized", "open_authorized") ||
        !identical(record$joint_record_hash, joint_record_hash) ||
        !identical(record$own_commit, own_commit)) {
      stop("The committed joint-DP allocation changed before activation.",
           call. = FALSE)
    }
    if (identical(record$state, "locally_committed")) {
      record$state <- "committed"
      .dsvert_joint_dp_record_store(connection, record, .secret)
    }
    record$own_commit
  })
  .dsvert_joint_dp_phase(.phase_hook, "after_commit_activation")
  .dsvert_joint_dp_capsule_registry_reconcile(
    connection, policy, context, .secret, query_id = query_id,
    phase_hook = .phase_hook, verifier = .verifier)
  own_commit
}

.dsvert_joint_dp_commit_common <- function(receipts) {
  fields <- c(
    "consortium_id", "capsule_id", "query_id", "allocation_index",
    "previous_chain", "new_chain", "joint_record_hash", "prepare_set_hash")
  reference <- receipts[[1L]][fields]
  if (!all(vapply(receipts[-1L], function(value) {
    identical(value[fields], reference)
  }, logical(1L)))) {
    stop("The two joint-DP commit receipts do not describe one allocation.",
         call. = FALSE)
  }
  reference
}

.dsvert_joint_dp_authorize <- function(
    policy, left_commit, right_commit, .secret = NULL, .signer = NULL,
    .verifier = NULL, .phase_hook = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  commits <- .dsvert_joint_dp_receipt_set(
    left_commit, right_commit, policy, .DSVERT_JOINT_DP_COMMIT_VERSION,
    "committed", .verifier)
  common <- .dsvert_joint_dp_commit_common(commits)
  commit_set_hash <- .dsvert_joint_dp_hash(commits)
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  authorization <- .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_initialize_validate(handle$connection, policy, .secret)
    record <- .dsvert_joint_dp_load(
      handle$connection, common$query_id, .secret)
    if (is.null(record) ||
        !record$state %in% c("committed", "authorized", "open_authorized") ||
        !identical(record$own_commit, commits[[context$peer_name]]) ||
        !identical(record$joint_record_hash, common$joint_record_hash) ||
        !identical(record$new_chain, common$new_chain)) {
      stop("Joint-DP authorization requires a matching durable local commit.",
           call. = FALSE)
    }
    own_authorization <- if (!is.null(record$own_authorization)) {
      if (!identical(record$peer_commit,
                     commits[[setdiff(names(commits), context$peer_name)]])) {
        stop("Conflicting replay of joint-DP commit receipts.",
             call. = FALSE)
      }
      record$own_authorization
    } else {
      unsigned <- list(
      version = .DSVERT_JOINT_DP_AUTHORIZE_VERSION,
      phase = "authorized",
      consortium_id = context$consortium_id,
      peer_name = context$peer_name,
      peer_identity_pk = unname(context$pins[[context$peer_name]]),
      capsule_id = common$capsule_id,
      query_id = common$query_id,
      allocation_index = common$allocation_index,
      new_chain = common$new_chain,
      joint_record_hash = common$joint_record_hash,
      commit_set_hash = commit_set_hash,
      peer_commit_stored = TRUE)
      own_authorization <- .dsvert_joint_dp_sign(unsigned, policy, .signer)
      record$state <- "authorized"
      record$peer_commit <- commits[[setdiff(names(commits), context$peer_name)]]
      record$own_authorization <- own_authorization
      .dsvert_joint_dp_record_store(handle$connection, record, .secret)
      own_authorization
    }
    .dsvert_joint_dp_registry_journal_ensure(
      handle$connection, policy, context, record, .secret)
    .dsvert_joint_dp_registry_journal_migrate(
      handle$connection, policy, context, .secret)
    own_authorization
  })
  .dsvert_joint_dp_phase(.phase_hook, "after_authorization_commit")
  .dsvert_joint_dp_capsule_registry_reconcile(
    handle$connection, policy, context, .secret,
    query_id = common$query_id, phase_hook = .phase_hook,
    verifier = .verifier)
  authorization
}

.dsvert_joint_dp_authorization_common <- function(receipts) {
  fields <- c(
    "consortium_id", "capsule_id", "query_id", "allocation_index",
    "new_chain", "joint_record_hash", "commit_set_hash")
  reference <- receipts[[1L]][fields]
  if (!all(vapply(receipts[-1L], function(value) {
    identical(value[fields], reference)
  }, logical(1L)))) {
    stop("The two joint-DP authorizations do not describe one allocation.",
         call. = FALSE)
  }
  reference
}

.dsvert_joint_dp_finalize_authorization <- function(
    policy, left_authorization, right_authorization, .secret = NULL,
    .signer = NULL, .verifier = NULL, .phase_hook = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  authorizations <- .dsvert_joint_dp_receipt_set(
    left_authorization, right_authorization, policy,
    .DSVERT_JOINT_DP_AUTHORIZE_VERSION, "authorized", .verifier)
  common <- .dsvert_joint_dp_authorization_common(authorizations)
  authorization_set_hash <- .dsvert_joint_dp_hash(authorizations)
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_capsule_registry_reconcile(
    handle$connection, policy, context, .secret,
    query_id = common$query_id, verifier = .verifier)
  token <- .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_initialize_validate(handle$connection, policy, .secret)
    record <- .dsvert_joint_dp_load(
      handle$connection, common$query_id, .secret)
    if (is.null(record) ||
        !record$state %in% c("authorized", "open_authorized") ||
        !identical(record$own_authorization,
                   authorizations[[context$peer_name]]) ||
        !identical(record$joint_record_hash, common$joint_record_hash) ||
        !identical(record$new_chain, common$new_chain)) {
      stop("Joint-DP opening requires matching cross-signed authorizations.",
           call. = FALSE)
    }
    peer_authorization <- authorizations[[setdiff(
      names(authorizations), context$peer_name)]]
    if (!is.null(record$opening_token)) {
      if (!identical(record$peer_authorization, peer_authorization)) {
        stop("Conflicting replay of joint-DP authorizations.",
             call. = FALSE)
      }
      record$opening_token
    } else {
      unsigned <- list(
      version = .DSVERT_JOINT_DP_OPEN_VERSION,
      phase = "open_authorized",
      consortium_id = context$consortium_id,
      peer_name = context$peer_name,
      peer_identity_pk = unname(context$pins[[context$peer_name]]),
      capsule_id = common$capsule_id,
      query_id = common$query_id,
      allocation_index = common$allocation_index,
      new_chain = common$new_chain,
      joint_record_hash = common$joint_record_hash,
      authorization_set_hash = authorization_set_hash,
      seed_commitment = record$own_prepare$seed_commitment,
      release_scope = .DSVERT_JOINT_DP_SCOPE,
      capability_available = FALSE)
      opening_token <- .dsvert_joint_dp_sign(unsigned, policy, .signer)
      record$state <- "open_authorized"
      record$peer_authorization <- peer_authorization
      record$opening_token <- opening_token
      .dsvert_joint_dp_record_store(handle$connection, record, .secret)
      opening_token
    }
  })
  .dsvert_joint_dp_phase(.phase_hook, "after_open_authorization_commit")
  token
}

.dsvert_joint_dp_result_prepare <- function(
    policy, own_opening_token, peer_opening_token, payload,
    result_contract_hash, .secret = NULL, .signer = NULL,
    .verifier = NULL, .phase_hook = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  if (!is.raw(payload)) {
    stop("The joint-DP result payload must be an exact raw byte string.",
         call. = FALSE)
  }
  if (!is.character(result_contract_hash) ||
      length(result_contract_hash) != 1L ||
      is.na(result_contract_hash) ||
      !grepl("^[0-9a-f]{64}$", result_contract_hash)) {
    stop("The joint-DP result contract hash is invalid.", call. = FALSE)
  }
  context <- .dsvert_joint_dp_policy_context(policy)
  openings <- .dsvert_joint_dp_receipt_set(
    own_opening_token, peer_opening_token, policy,
    .DSVERT_JOINT_DP_OPEN_VERSION, "open_authorized", .verifier)
  if (!identical(openings[[context$peer_name]], own_opening_token)) {
    stop("The local joint-DP opening token is missing.", call. = FALSE)
  }
  common <- .dsvert_joint_dp_output_common(
    openings,
    c("consortium_id", "capsule_id", "query_id", "allocation_index",
      "new_chain", "joint_record_hash", "authorization_set_hash",
      "release_scope", "capability_available"),
    "opening")
  opening_set_hash <- .dsvert_joint_dp_hash(openings)
  payload_commitment <- .dsvert_joint_dp_payload_commitment(
    .secret, common$query_id, opening_set_hash, result_contract_hash, payload)

  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_capsule_registry_reconcile(
    handle$connection, policy, context, .secret,
    query_id = common$query_id, verifier = .verifier)
  receipt <- .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, .secret, .verifier)
    record <- .dsvert_joint_dp_load(
      handle$connection, common$query_id, .secret)
    if (is.null(record) || !identical(record$state, "open_authorized") ||
        !identical(record$opening_token, own_opening_token) ||
        !identical(record$allocation_index, common$allocation_index)) {
      stop("Joint-DP result persistence requires a matching durable opening.",
           call. = FALSE)
    }
    existing <- .dsvert_joint_dp_output_load(
      handle$connection, common$query_id, .secret)
    if (!is.null(existing)) {
      .dsvert_joint_dp_validate_output_record(
        existing, record, policy, context, .verifier)
      if (!identical(existing$payload, payload) ||
          !identical(existing$payload_commitment, payload_commitment) ||
          !identical(existing$opening_set_hash, opening_set_hash) ||
          !identical(existing$result_contract_hash, result_contract_hash) ||
          !identical(existing$own_opening_token, own_opening_token) ||
          !identical(existing$peer_opening_token, peer_opening_token)) {
        stop("Conflicting replay of a persisted joint-DP result payload.",
             call. = FALSE)
      }
      existing$own_result_prepare
    } else {
      unsigned <- list(
        version = .DSVERT_JOINT_DP_RESULT_PREPARE_VERSION,
        phase = "result_prepared",
        consortium_id = context$consortium_id,
        peer_name = context$peer_name,
        peer_identity_pk = unname(context$pins[[context$peer_name]]),
        capsule_id = common$capsule_id,
        query_id = common$query_id,
        allocation_index = common$allocation_index,
        opening_set_hash = opening_set_hash,
        result_contract_hash = result_contract_hash,
        payload_commitment = payload_commitment,
        capability_available = FALSE)
      own_result <- .dsvert_joint_dp_sign(unsigned, policy, .signer)
      output <- list(
        version = "dsvert-joint-dp-output-ledger-v2",
        query_id = common$query_id,
        state = "result_prepared",
        payload_b64 = gsub(
          "[\r\n]", "", jsonlite::base64_enc(payload)),
        payload_commitment = payload_commitment,
        opening_set_hash = opening_set_hash,
        result_contract_hash = result_contract_hash,
        own_opening_token = own_opening_token,
        peer_opening_token = peer_opening_token,
        own_result_prepare = own_result,
        peer_result_prepare = NULL,
        result_set_hash = NULL,
        own_delivery_commit = NULL,
        peer_delivery_commit = NULL,
        delivery_token = NULL)
      .dsvert_joint_dp_output_store(
        handle$connection, output, .secret, insert = TRUE)
      own_result
    }
  })
  .dsvert_joint_dp_phase(.phase_hook, "after_result_persist")
  receipt
}

.dsvert_joint_dp_result_commit <- function(
    policy, left_result, right_result, .secret = NULL, .signer = NULL,
    .verifier = NULL, .phase_hook = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  results <- .dsvert_joint_dp_receipt_set(
    left_result, right_result, policy,
    .DSVERT_JOINT_DP_RESULT_PREPARE_VERSION, "result_prepared", .verifier)
  common <- .dsvert_joint_dp_output_common(
    results,
    c("consortium_id", "capsule_id", "query_id", "allocation_index",
      "opening_set_hash", "result_contract_hash", "capability_available"),
    "result-prepare")
  result_set_hash <- .dsvert_joint_dp_hash(results)
  own_result <- results[[context$peer_name]]
  peer_result <- results[[setdiff(names(results), context$peer_name)]]

  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_capsule_registry_reconcile(
    handle$connection, policy, context, .secret,
    query_id = common$query_id, verifier = .verifier)
  receipt <- .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, .secret, .verifier)
    record <- .dsvert_joint_dp_load(
      handle$connection, common$query_id, .secret)
    output <- .dsvert_joint_dp_output_load(
      handle$connection, common$query_id, .secret)
    if (is.null(record) || is.null(output) ||
        !identical(record$state, "open_authorized") ||
        !identical(output$own_result_prepare, own_result) ||
        !identical(output$opening_set_hash, common$opening_set_hash) ||
        !identical(output$result_contract_hash,
                   common$result_contract_hash)) {
      stop("Joint-DP result commit requires the matching local payload.",
           call. = FALSE)
    }
    if (!is.null(output$own_delivery_commit)) {
      if (!identical(output$peer_result_prepare, peer_result) ||
          !identical(output$result_set_hash, result_set_hash)) {
        stop("Conflicting replay of joint-DP result receipts.",
             call. = FALSE)
      }
      output$own_delivery_commit
    } else {
      unsigned <- list(
        version = .DSVERT_JOINT_DP_RESULT_COMMIT_VERSION,
        phase = "result_committed",
        consortium_id = context$consortium_id,
        peer_name = context$peer_name,
        peer_identity_pk = unname(context$pins[[context$peer_name]]),
        capsule_id = common$capsule_id,
        query_id = common$query_id,
        allocation_index = common$allocation_index,
        opening_set_hash = common$opening_set_hash,
        result_contract_hash = common$result_contract_hash,
        result_set_hash = result_set_hash,
        payload_commitment = output$payload_commitment,
        peer_result_stored = TRUE,
        capability_available = FALSE)
      own_commit <- .dsvert_joint_dp_sign(unsigned, policy, .signer)
      output$state <- "result_committed"
      output$peer_result_prepare <- peer_result
      output$result_set_hash <- result_set_hash
      output$own_delivery_commit <- own_commit
      .dsvert_joint_dp_output_store(
        handle$connection, output, .secret)
      own_commit
    }
  })
  .dsvert_joint_dp_phase(.phase_hook, "after_result_commit")
  receipt
}

.dsvert_joint_dp_finalize_delivery <- function(
    policy, left_commit, right_commit, .secret = NULL, .signer = NULL,
    .verifier = NULL, .phase_hook = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  commits <- .dsvert_joint_dp_receipt_set(
    left_commit, right_commit, policy,
    .DSVERT_JOINT_DP_RESULT_COMMIT_VERSION, "result_committed", .verifier)
  common <- .dsvert_joint_dp_output_common(
    commits,
    c("consortium_id", "capsule_id", "query_id", "allocation_index",
      "opening_set_hash", "result_contract_hash", "result_set_hash",
      "peer_result_stored", "capability_available"),
    "result-commit")
  commit_set_hash <- .dsvert_joint_dp_hash(commits)
  own_commit <- commits[[context$peer_name]]
  peer_commit <- commits[[setdiff(names(commits), context$peer_name)]]

  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_capsule_registry_reconcile(
    handle$connection, policy, context, .secret,
    query_id = common$query_id, verifier = .verifier)
  token <- .dsvert_joint_dp_transaction(handle$connection, {
    .dsvert_joint_dp_initialize_validate(
      handle$connection, policy, .secret, .verifier)
    record <- .dsvert_joint_dp_load(
      handle$connection, common$query_id, .secret)
    output <- .dsvert_joint_dp_output_load(
      handle$connection, common$query_id, .secret)
    if (is.null(record) || is.null(output) ||
        !identical(record$state, "open_authorized") ||
        !identical(output$own_delivery_commit, own_commit) ||
        !identical(output$result_set_hash, common$result_set_hash) ||
        !identical(output$result_contract_hash,
                   common$result_contract_hash)) {
      stop("Joint-DP delivery requires the matching durable result commit.",
           call. = FALSE)
    }
    results <- .dsvert_joint_dp_receipt_set(
      output$own_result_prepare, output$peer_result_prepare, policy,
      .DSVERT_JOINT_DP_RESULT_PREPARE_VERSION, "result_prepared", .verifier)
    .dsvert_joint_dp_validate_commit_payloads(commits, results)
    if (!is.null(output$delivery_token)) {
      if (!identical(output$peer_delivery_commit, peer_commit)) {
        stop("Conflicting replay of joint-DP delivery commits.",
             call. = FALSE)
      }
      output$delivery_token
    } else {
      unsigned <- list(
        version = .DSVERT_JOINT_DP_DELIVERY_VERSION,
        phase = "delivery_authorized",
        consortium_id = context$consortium_id,
        peer_name = context$peer_name,
        peer_identity_pk = unname(context$pins[[context$peer_name]]),
        capsule_id = common$capsule_id,
        query_id = common$query_id,
        allocation_index = common$allocation_index,
        result_contract_hash = common$result_contract_hash,
        result_set_hash = common$result_set_hash,
        delivery_commit_set_hash = commit_set_hash,
        payload_delivery_available = FALSE,
        capability_available = FALSE)
      delivery_token <- .dsvert_joint_dp_sign(unsigned, policy, .signer)
      output$state <- "delivery_authorized"
      output$peer_delivery_commit <- peer_commit
      output$delivery_token <- delivery_token
      .dsvert_joint_dp_output_store(
        handle$connection, output, .secret)
      delivery_token
    }
  })
  .dsvert_joint_dp_phase(.phase_hook, "after_delivery_authorization")
  token
}

.dsvert_joint_dp_delivery_contract <- function(
    policy, own_delivery_token, peer_delivery_token, .secret = NULL,
    .verifier = NULL) {
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  tokens <- .dsvert_joint_dp_receipt_set(
    own_delivery_token, peer_delivery_token, policy,
    .DSVERT_JOINT_DP_DELIVERY_VERSION, "delivery_authorized", .verifier)
  if (!identical(tokens[[context$peer_name]], own_delivery_token)) {
    stop("The local joint-DP delivery token is missing.", call. = FALSE)
  }
  common <- .dsvert_joint_dp_output_common(
    tokens,
    c("consortium_id", "capsule_id", "query_id", "allocation_index",
      "result_contract_hash", "result_set_hash",
      "delivery_commit_set_hash", "payload_delivery_available",
      "capability_available"),
    "delivery")
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_capsule_registry_reconcile(
    handle$connection, policy, context, .secret,
    query_id = common$query_id, verifier = .verifier)
  .dsvert_joint_dp_initialize_validate(
    handle$connection, policy, .secret, .verifier)
  record <- .dsvert_joint_dp_load(
    handle$connection, common$query_id, .secret)
  output <- .dsvert_joint_dp_output_load(
    handle$connection, common$query_id, .secret)
  if (is.null(record) || is.null(output) ||
      !identical(output$state, "delivery_authorized") ||
      !identical(output$delivery_token, own_delivery_token) ||
      !identical(output$result_set_hash, common$result_set_hash)) {
    stop("The joint-DP delivery transcript is not durably authorized.",
         call. = FALSE)
  }
  list(
    schema_version = 1L,
    capability_id = .DSVERT_JOINT_DP_CAPABILITY,
    capability_available = FALSE,
    payload_delivery_available = FALSE,
    unavailable_reason =
      "global_allocator_dsi_result_delivery_adapter_not_e2e_verified",
    consortium_id = context$consortium_id,
    capsule_id = common$capsule_id,
    query_id = common$query_id,
    allocation_index = common$allocation_index,
    result_contract_hash = common$result_contract_hash,
    result_set_hash = common$result_set_hash,
    delivery_commit_set_hash = common$delivery_commit_set_hash,
    payload_persisted = TRUE,
    payload_exposed = FALSE)
}

.dsvert_joint_dp_local_seed <- function(policy, opening_token,
                                         .secret = NULL,
                                         .verifier = NULL) {
  # Internal-only bridge for the future exact-GC PRF/sampler.  It is never a
  # DS method and must not be called until that backend verifies both peers'
  # opening tokens inside the purpose-bound session.
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  .dsvert_joint_dp_verify(
    opening_token, policy, .DSVERT_JOINT_DP_OPEN_VERSION,
    "open_authorized", .verifier)
  if (!identical(opening_token$peer_name, context$peer_name) ||
      !identical(opening_token$capability_available, FALSE)) {
    stop("The joint-DP opening token is not a local pre-promotion token.",
         call. = FALSE)
  }
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_capsule_registry_reconcile(
    handle$connection, policy, context, .secret,
    query_id = opening_token$query_id, verifier = .verifier)
  .dsvert_joint_dp_initialize_validate(handle$connection, policy, .secret)
  record <- .dsvert_joint_dp_load(
    handle$connection, opening_token$query_id, .secret)
  if (is.null(record) || !identical(record$state, "open_authorized") ||
      !identical(record$opening_token, opening_token)) {
    stop("The joint-DP opening token is not durably authorized.",
         call. = FALSE)
  }
  stop("The joint MPC sampler adapter is not promoted; no private seed was returned.",
       call. = FALSE)
}

.dsvert_joint_dp_sampler_contract <- function(
    policy, opening_token, .secret = NULL, .verifier = NULL) {
  # Explicit hand-off contract for the not-yet-promoted exact-GC sampler. It
  # exposes only public commitments and immutable transcript identifiers.
  if (is.null(.secret)) .secret <- .dsvert_dp_secret()
  context <- .dsvert_joint_dp_policy_context(policy)
  .dsvert_joint_dp_verify(
    opening_token, policy, .DSVERT_JOINT_DP_OPEN_VERSION,
    "open_authorized", .verifier)
  if (!identical(opening_token$peer_name, context$peer_name)) {
    stop("The joint-DP sampler contract requires the local opening token.",
         call. = FALSE)
  }
  handle <- .dsvert_joint_dp_open_ledger(policy)
  on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
  .dsvert_joint_dp_capsule_registry_reconcile(
    handle$connection, policy, context, .secret,
    query_id = opening_token$query_id, verifier = .verifier)
  .dsvert_joint_dp_initialize_validate(handle$connection, policy, .secret)
  record <- .dsvert_joint_dp_load(
    handle$connection, opening_token$query_id, .secret)
  if (is.null(record) || !identical(record$state, "open_authorized") ||
      !identical(record$opening_token, opening_token)) {
    stop("The joint-DP sampler transcript is not durably authorized.",
         call. = FALSE)
  }
  mechanism <- record$common_query$mechanism
  list(
    schema_version = 1L,
    capability_id = .DSVERT_JOINT_DP_CAPABILITY,
    capability_available = FALSE,
    unavailable_reason =
      "exact_gc_two_seed_prf_sampler_not_e2e_verified",
    release_scope = .DSVERT_JOINT_DP_SCOPE,
    sampler = .DSVERT_JOINT_DP_SAMPLER,
    seed_combiner =
      "GC-verified commitments; HKDF-SHA256 over both ordered private seeds and transcript hash",
    sampler_output =
      "one global noise vector split into two additive ring shares",
    consortium_id = context$consortium_id,
    ordered_peer_names = names(context$pins),
    peer_pinset_sha256 = policy$peer_pinset_sha256,
    capsule_id = record$query_id,
    query_id = record$query_id,
    allocation_index = record$allocation_index,
    privacy_epoch = record$own_prepare$privacy_epoch,
    previous_chain = record$previous_chain,
    new_chain = record$new_chain,
    joint_record_hash = record$joint_record_hash,
    prepare_set_hash = record$own_commit$prepare_set_hash,
    commit_set_hash = record$own_authorization$commit_set_hash,
    authorization_set_hash = opening_token$authorization_set_hash,
    own_seed_commitment = record$own_prepare$seed_commitment,
    mechanism_hash = record$own_prepare$mechanism_hash,
    producer = mechanism$producer,
    purpose = mechanism$purpose,
    source_context_hash = mechanism$source_context_hash,
    ring_bits = mechanism$ring_bits,
    frac_bits = mechanism$frac_bits,
    coordinate_count = mechanism$coordinate_count,
    sensitivity_norm = mechanism$sensitivity_norm,
    sensitivity = record$sensitivity,
    epsilon = record$epsilon,
    delta = record$delta,
    required_pre_open_state = "two signed open_authorized tokens",
    result_commit_required_before_delivery = TRUE)
}
