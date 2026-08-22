# Read-only public status for the reusable joint-DP capsule control plane.
#
# This schema distinguishes a lifetime privacy-loss gate from a request quota.
# Exact replay is unlimited, while each new capsule reserves one of a bounded
# number of possible public releases. Non-designated custodians attest the full
# pinned policy without opening an allocator ledger.

.DSVERT_JOINT_DP_CAPSULE_STATUS_VERSION <-
  "dsvert-joint-dp-capsule-status-v5"

.dsvert_joint_dp_capsule_status_policy <- function(policy, context) {
  pins <- vapply(
    policy$peer_pinset, .dsvert_relay_normalize_identity_pk, character(1L))
  pins <- pins[order(names(pins), method = "radix")]
  list(
    contract = "immutable_reusable_capsule_v1",
    domain = context$common$domain,
    cohort_id = context$common$cohort_id,
    peer_name = context$peer_name,
    own_identity_pk = unname(pins[[context$peer_name]]),
    peer_pinset = pins,
    peer_pinset_sha256 = context$common$peer_pinset_sha256,
    peer_count = as.integer(context$common$peer_count),
    designated_noise_peers = unname(
      unlist(context$common$designated_noise_peers, use.names = FALSE)),
    capsule_epsilon = as.numeric(context$common$epsilon_capsule),
    capsule_delta = as.numeric(context$common$delta_capsule),
    lifetime_max_distinct_capsules =
      as.numeric(context$common$lifetime_max_distinct_capsules),
    lifetime_epsilon_upper_bound =
      context$common$lifetime_epsilon_upper_bound,
    lifetime_delta_upper_bound = context$common$lifetime_delta_upper_bound,
    adjacency = context$common$adjacency,
    patient_column = context$common$patient_column,
    unit_capacity = as.numeric(context$common$unit_capacity),
    max_records_per_unit = as.numeric(
      context$common$max_records_per_unit),
    overflow_policy = context$common$overflow_policy,
    sampler = context$common$sampler)
}

.dsvert_joint_dp_capsule_status_telemetry <- function(summary) {
  if (is.null(summary)) return(NULL)
  required <- c(
    "capsule_count", "capsule_epsilon", "capsule_delta",
    "lifetime_max_distinct_capsules", "remaining_distinct_capsules",
    "cumulative_epsilon", "cumulative_delta",
    "cumulative_delta_vacuous", "composition_role",
    "registration_policy", "operation_accounting", "operation_limit",
    "history_can_deny_operation")
  scalar_number <- function(value, minimum = 0, open = FALSE) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value) && if (isTRUE(open)) value > minimum else
        value >= minimum
  }
  if (!is.list(summary) || !all(required %in% names(summary)) ||
      !scalar_number(summary$capsule_count) ||
      summary$capsule_count != floor(summary$capsule_count) ||
      !scalar_number(summary$lifetime_max_distinct_capsules, 1) ||
      summary$lifetime_max_distinct_capsules !=
        floor(summary$lifetime_max_distinct_capsules) ||
      summary$capsule_count > summary$lifetime_max_distinct_capsules ||
      !scalar_number(summary$remaining_distinct_capsules) ||
      !identical(
        as.numeric(summary$remaining_distinct_capsules),
        as.numeric(summary$lifetime_max_distinct_capsules -
          summary$capsule_count)) ||
      !scalar_number(summary$capsule_epsilon, open = TRUE) ||
      !scalar_number(summary$capsule_delta) || summary$capsule_delta >= 1 ||
      !scalar_number(summary$cumulative_epsilon) ||
      !scalar_number(summary$cumulative_delta) ||
      !isTRUE(all.equal(
        summary$cumulative_epsilon,
        summary$capsule_count * summary$capsule_epsilon,
        tolerance = 1e-13)) ||
      !isTRUE(all.equal(
        summary$cumulative_delta,
        summary$capsule_count * summary$capsule_delta,
        tolerance = 1e-13)) ||
      !is.logical(summary$cumulative_delta_vacuous) ||
      length(summary$cumulative_delta_vacuous) != 1L ||
      is.na(summary$cumulative_delta_vacuous) ||
      !identical(summary$cumulative_delta_vacuous, FALSE) ||
      summary$cumulative_delta >= 1 ||
      !identical(
        summary$composition_role,
        "basic_composition_authenticated_lifetime_bound") ||
      !identical(
        summary$registration_policy,
        "allocator_admitted_distinct_capsules_up_to_lifetime_limit") ||
      !identical(
        summary$operation_accounting,
        "one_per_distinct_capsule_allocator_commit") ||
      !identical(summary$operation_limit, TRUE) ||
      !identical(summary$history_can_deny_operation, TRUE)) {
    stop("The capsule composition telemetry is invalid.", call. = FALSE)
  }
  list(
    capsules_created = as.numeric(summary$capsule_count),
    lifetime_max_distinct_capsules =
      as.numeric(summary$lifetime_max_distinct_capsules),
    remaining_distinct_capsules =
      as.numeric(summary$remaining_distinct_capsules),
    capsule_epsilon = as.numeric(summary$capsule_epsilon),
    capsule_delta = as.numeric(summary$capsule_delta),
    cumulative_epsilon_upper_bound = as.numeric(
      summary$cumulative_epsilon),
    cumulative_delta_upper_bound = as.numeric(summary$cumulative_delta),
    cumulative_delta_vacuous = isTRUE(summary$cumulative_delta_vacuous),
    composition_role = summary$composition_role,
    registration_policy = summary$registration_policy,
    privacy_budget_gate = TRUE,
    operation_limit = TRUE,
    request_limit = FALSE,
    history_can_deny_new_release = TRUE,
    admission_role = "allocator_reservation_before_protected_access")
}

.dsvert_joint_dp_release_instance_telemetry <- function(
    summary, reservation_summary) {
  if (is.null(summary)) return(NULL)
  required <- c(
    "release_instance_count", "release_epsilon", "release_delta",
    "lifetime_max_distinct_capsules", "remaining_distinct_capsules",
    "cumulative_epsilon", "cumulative_delta",
    "cumulative_delta_vacuous", "composition_role",
    "release_accounting", "replay_accounting", "operation_accounting",
    "operation_limit", "request_limit", "history_can_deny_operation")
  scalar_number <- function(value, minimum = 0, open = FALSE) {
    is.numeric(value) && length(value) == 1L && !is.na(value) &&
      is.finite(value) && if (isTRUE(open)) value > minimum else
        value >= minimum
  }
  if (!is.list(summary) || !all(required %in% names(summary)) ||
      !is.list(reservation_summary) ||
      !all(c("capsule_count", "lifetime_max_distinct_capsules",
             "remaining_distinct_capsules") %in%
           names(reservation_summary)) ||
      !scalar_number(reservation_summary$capsule_count) ||
      reservation_summary$capsule_count !=
        floor(reservation_summary$capsule_count) ||
      !scalar_number(
        reservation_summary$lifetime_max_distinct_capsules, 1) ||
      !scalar_number(reservation_summary$remaining_distinct_capsules) ||
      !identical(
        as.numeric(reservation_summary$remaining_distinct_capsules),
        as.numeric(reservation_summary$lifetime_max_distinct_capsules -
          reservation_summary$capsule_count)) ||
      !scalar_number(summary$release_instance_count) ||
      summary$release_instance_count !=
        floor(summary$release_instance_count) ||
      !scalar_number(summary$lifetime_max_distinct_capsules, 1) ||
      summary$lifetime_max_distinct_capsules !=
        floor(summary$lifetime_max_distinct_capsules) ||
      summary$release_instance_count >
        summary$lifetime_max_distinct_capsules ||
      summary$release_instance_count > reservation_summary$capsule_count ||
      !identical(
        as.numeric(summary$lifetime_max_distinct_capsules),
        as.numeric(reservation_summary$lifetime_max_distinct_capsules)) ||
      !scalar_number(summary$remaining_distinct_capsules) ||
      !identical(
        as.numeric(summary$remaining_distinct_capsules),
        as.numeric(summary$lifetime_max_distinct_capsules -
          summary$release_instance_count)) ||
      !scalar_number(summary$release_epsilon, open = TRUE) ||
      !scalar_number(summary$release_delta) || summary$release_delta >= 1 ||
      !scalar_number(summary$cumulative_epsilon) ||
      !scalar_number(summary$cumulative_delta) ||
      !isTRUE(all.equal(
        summary$cumulative_epsilon,
        summary$release_instance_count * summary$release_epsilon,
        tolerance = 1e-13)) ||
      !isTRUE(all.equal(
        summary$cumulative_delta,
        summary$release_instance_count * summary$release_delta,
        tolerance = 1e-13)) ||
      !identical(summary$cumulative_delta_vacuous, FALSE) ||
      summary$cumulative_delta >= 1 ||
      !identical(summary$composition_role,
                 "basic_composition_authenticated_lifetime_bound") ||
      !identical(summary$release_accounting,
                 "one_public_release_instance_per_capsule_id") ||
      !identical(summary$replay_accounting, "none") ||
      !identical(summary$operation_accounting, "none") ||
      !identical(summary$operation_limit, TRUE) ||
      !identical(summary$request_limit, FALSE) ||
      !identical(summary$history_can_deny_operation, TRUE)) {
    stop("The release-instance composition telemetry is invalid.",
         call. = FALSE)
  }
  list(
    releases_published = as.numeric(summary$release_instance_count),
    lifetime_max_distinct_capsules =
      as.numeric(summary$lifetime_max_distinct_capsules),
    remaining_distinct_capsules =
      as.numeric(reservation_summary$remaining_distinct_capsules),
    release_epsilon = as.numeric(summary$release_epsilon),
    release_delta = as.numeric(summary$release_delta),
    cumulative_epsilon_upper_bound =
      as.numeric(summary$cumulative_epsilon),
    cumulative_delta_upper_bound = as.numeric(summary$cumulative_delta),
    cumulative_delta_vacuous = isTRUE(summary$cumulative_delta_vacuous),
    composition_role = summary$composition_role,
    release_accounting = summary$release_accounting,
    replay_accounting = "same_instance_replay_not_recounted",
    rotation_accounting = paste0(
      "prepublication_rotation_only_postpublication_replay_or_",
      "fail_closed"),
    privacy_budget_gate = TRUE,
    operation_limit = TRUE, request_limit = FALSE,
    history_can_deny_operation = TRUE,
    admission_role = "authenticated_lifetime_gate_before_sampler")
}

.dsvert_joint_dp_capsule_status <- function(
    .policy = NULL, .secret = NULL, .verifier = NULL) {
  if (is.null(.policy)) .policy <- .dsvert_dp_policy()
  context <- .dsvert_joint_dp_policy_context(
    .policy, require_designated = FALSE)
  designated <- context$peer_name %in%
    unname(unlist(context$common$designated_noise_peers, use.names = FALSE))

  summary <- NULL
  release_summary <- NULL
  release_domain <- NULL
  if (isTRUE(designated)) {
    if (is.null(.secret)) .secret <- .dsvert_dp_secret()
    handle <- .dsvert_joint_dp_open_ledger(.policy)
    on.exit(.dsvert_joint_dp_close_ledger(handle), add = TRUE)
    .dsvert_joint_dp_initialize_validate(
      handle$connection, .policy, .secret, .verifier)
    reconciliation <- .dsvert_joint_dp_capsule_registry_reconcile(
      handle$connection, .policy, context, .secret,
      query_id = NULL, verifier = .verifier)
    if (!identical(reconciliation$operation_limit, TRUE) ||
        !identical(reconciliation$history_can_deny_operation, TRUE)) {
      stop("The capsule allocator did not enforce its history gate.",
           call. = FALSE)
    }
    summary <- reconciliation$summary
    release_config <-
      .dsvert_joint_dp_release_ledger_config_from_policy(.policy)
    vector_status <- .dsvert_joint_dp_vector_with_store(
      .policy, .secret, function(connection) {
        list(
          release_summary = .dsvert_joint_dp_release_ledger_status(
            connection, release_config, .secret),
          release_domain =
            .dsvert_joint_dp_release_domain_load_connection(
              connection, .secret))
      })
    release_summary <- vector_status$release_summary
    release_domain <- .dsvert_joint_dp_release_domain_public(
      vector_status$release_domain)
  }

  list(
    version = .DSVERT_JOINT_DP_CAPSULE_STATUS_VERSION,
    enabled = TRUE,
    privacy_contract = list(
      definition = "bounded_lifetime_epsilon_delta_dp",
      scope = paste0(
        "at_most_N_immutable_snapshot_workload_capsules_per_stable_",
        "privacy_accountant_namespace"),
      adversary_model = "authenticated_semi_honest_noncollusion",
      assumptions = paste0(
        "declared_adjacency_bounds_immutable_snapshot_protocol_compliant_",
        "peers_at_least_one_noncolluding_designated_noise_peer_retains_and_",
        "uses_complete_authenticated_monotonic_history_stable_unique_",
        "privacy_accountant_",
        "namespace_per_protected_privacy_universe"),
      simultaneous_designated_history_rollback_protection =
        "not_claimed_without_external_linearizable_cas",
      transcript_security = "computational_mpc_and_csprng",
      malicious_security = FALSE,
      operation_accounting =
        "one_per_distinct_capsule_allocator_commit",
      privacy_budget_gate = TRUE,
      operation_limit = TRUE,
      request_limit = FALSE,
      history_can_deny_operation = TRUE,
      release_instance_accounting =
        "one_public_release_instance_per_capsule_id",
      accuracy_depends_on_request_history = FALSE,
      reuse = "unlimited_sticky_postprocessing",
      new_capsules = "allowed_until_authenticated_lifetime_bound",
      lifetime_max_distinct_capsules =
        as.numeric(context$common$lifetime_max_distinct_capsules),
      lifetime_epsilon_upper_bound =
        context$common$lifetime_epsilon_upper_bound,
      lifetime_delta_upper_bound =
        context$common$lifetime_delta_upper_bound),
    policy = .dsvert_joint_dp_capsule_status_policy(.policy, context),
    noise_root = .dsvert_dp_noise_root_public(.policy$noise_root),
    release_domain = release_domain,
    role = list(
      designated_noise_peer = isTRUE(designated),
      allocator = if (isTRUE(designated)) "authenticated_ready" else
        "not_applicable_policy_attestor"),
    composition_telemetry =
      .dsvert_joint_dp_capsule_status_telemetry(summary),
    release_instance_telemetry =
      .dsvert_joint_dp_release_instance_telemetry(
        release_summary, summary))
}

# Historical lifetime-gated status retained only to authenticate legacy stores
# during migration tests. It is intentionally unregistered and unexported:
# active Synopsis routes attest their per-artifact sticky contract through the
# lifetime-independent bootstrap.
dsvertJointDPCapsuleStatusDS <- function() {
  .dsvert_joint_dp_capsule_status()
}
