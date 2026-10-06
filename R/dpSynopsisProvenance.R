# Public provenance for the complete frozen Synopsis dependency closure.
# The imported-root migration boundary is intentional: historical upstream
# intersections cannot be reconstructed from a generic alignment manifest.
.DSVERT_DP_SYNOPSIS_DEPENDENCY_VERSION <-
  "dsvert-synopsis-authorization-dependency-v1"
.DSVERT_DP_SYNOPSIS_CLOSURE_VERSION <-
  "dsvert-synopsis-authorization-closure-v1"

.dsvert_dp_synopsis_provenance_enabled_v2 <- function(policy) {
  .dsvert_dp_synopsis_policy_is_v1(policy) &&
    isTRUE(policy$require_snapshot_digest)
}

.dsvert_dp_synopsis_dependency_validate_v2 <- function(value) {
  fields <- c("version", "dataset_id", "dataset_version",
    "authorization_epoch", "source_contract_id", "derivation_policy_id",
    "provenance_kind", "authorization_epochs")
  fail <- function() stop("Invalid Synopsis authorization dependency.",
                          call. = FALSE)
  if (!is.list(value) || is.null(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(value$version, .DSVERT_DP_SYNOPSIS_DEPENDENCY_VERSION) ||
      !is.character(value$provenance_kind) ||
      length(value$provenance_kind) != 1L || is.na(value$provenance_kind) ||
      !value$provenance_kind %in% c("padded_psi", "frozen_materialized_root")) {
    fail()
  }
  for (field in c("dataset_id", "dataset_version")) {
    .dsvert_dp_analysis_scalar_id(value[[field]], field)
  }
  for (field in c("authorization_epoch", "source_contract_id",
                  "derivation_policy_id")) {
    .dsvert_dp_synopsis_hex_v1(value[[field]], field)
  }
  epochs <- value$authorization_epochs
  if (!is.list(epochs) || !length(epochs) || !is.null(names(epochs)) ||
      length(epochs) > 4096L) fail()
  identities <- vapply(epochs, function(entry) {
    if (!is.list(entry) || anyDuplicated(names(entry)) ||
        !setequal(names(entry), c("peer_identity", "authorization_epoch",
                                  "source_contract_id"))) fail()
    .dsvert_dp_synopsis_hex_v1(entry$authorization_epoch, "dependency epoch")
    .dsvert_dp_synopsis_hex_v1(entry$source_contract_id, "dependency source")
    .dsvert_dp_analysis_identity_pk(entry$peer_identity, "dependency peer")
  }, character(1L))
  if (anyDuplicated(identities) ||
      anyDuplicated(vapply(epochs, `[[`, character(1L),
                           "authorization_epoch")) ||
      !identical(identities, sort(identities, method = "radix"))) fail()
  if (identical(value$provenance_kind, "frozen_materialized_root") &&
      (length(epochs) != 1L ||
       !identical(epochs[[1L]]$authorization_epoch, value$authorization_epoch) ||
       !identical(epochs[[1L]]$source_contract_id, value$source_contract_id))) fail()
  .dsvert_dp_canonical_query_value(value)
}

.dsvert_dp_synopsis_dependency_v2 <- function(record, policy) {
  provenance <- record$provenance
  padded <- !is.null(provenance)
  epochs <- if (padded) provenance$epoch_vector else list(list(
    peer_identity = policy$own_identity_pk,
    authorization_epoch = record$epoch,
    source_contract_id = record$source_contract_id))
  if (padded) {
    identities <- sort(vapply(epochs, `[[`, character(1L), "peer_identity"),
                       method = "radix")
    if (!identical(identities,
        sort(unname(policy$peer_pinset), method = "radix"))) {
      stop("The registered Synopsis dependency uses another PSI peer set.",
           call. = FALSE)
    }
  }
  derivation <- .dsvert_dp_provenance_hash(
    "dsVert/synopsis/source-derivation/v1|", list(
      version = "dsvert-synopsis-frozen-derivation-v1",
      source_derivation = if (padded) provenance$derivation_policy_id else
        "custodian-authorized-materialized-root-v1",
      domain = policy$domain, cohort_id = policy$cohort_id,
      peer_pinset_sha256 = policy$peer_pinset_sha256,
      mechanism_version = policy$mechanism_version,
      adjacency = policy$adjacency,
      unit_capacity = policy$unit_capacity,
      max_records_per_unit = policy$max_records_per_unit,
      overflow_policy = policy$overflow_policy,
      contingency_unit_aggregation_policy =
        policy$contingency_unit_aggregation_policy))
  .dsvert_dp_synopsis_dependency_validate_v2(list(
    version = .DSVERT_DP_SYNOPSIS_DEPENDENCY_VERSION,
    dataset_id = record$descriptor$id,
    dataset_version = record$descriptor$version,
    authorization_epoch = record$epoch,
    source_contract_id = record$source_contract_id,
    derivation_policy_id = derivation,
    provenance_kind = if (padded) "padded_psi" else "frozen_materialized_root",
    authorization_epochs = epochs))
}

.dsvert_dp_synopsis_registered_policy_v2 <- function(policy) {
  if (!.dsvert_dp_synopsis_provenance_enabled_v2(policy)) return(policy)
  dependencies <- list()
  for (data_name in sort(names(policy$datasets), method = "radix")) {
    public <- .dsvert_dp_dataset_authorization_public(
      policy$datasets[[data_name]], policy$patient_column)
    record <- .dsvert_dp_provenance_lookup(public)
    # Trusted padded-PSI finalization captures every complete v6 frame before
    # exposing it. Never reconstruct a missing authority from today's aligned
    # object: its accept/refuse result can reveal an intersection change.
    if (is.null(record)) .dsvert_dp_provenance_migration()
    # Refreshing descriptor content without an explicit authorization event
    # keeps the frozen publication, including its private manifest authority.
    policy$datasets[[data_name]] <- record$descriptor
    dependencies[[data_name]] <- .dsvert_dp_synopsis_dependency_v2(record, policy)
  }
  policy$authorization_local <- dependencies
  policy$authorization_dependencies <- list(
    version = .DSVERT_DP_SYNOPSIS_CLOSURE_VERSION, dependencies = list())
  policy
}

.dsvert_dp_synopsis_local_dependencies_v2 <- function(policy) {
  if (!.dsvert_dp_synopsis_provenance_enabled_v2(policy)) return(list())
  dependencies <- policy$authorization_local
  if (!is.list(dependencies) || is.null(names(dependencies)) ||
      anyDuplicated(names(dependencies)) ||
      !setequal(names(dependencies), names(policy$datasets))) {
    .dsvert_dp_provenance_migration()
  }
  dependencies <- lapply(dependencies,
                        .dsvert_dp_synopsis_dependency_validate_v2)
  dependencies[order(names(dependencies), method = "radix")]
}

.dsvert_dp_synopsis_closure_validate_v2 <- function(value) {
  if (!is.list(value) || anyDuplicated(names(value)) ||
      !setequal(names(value), c("version", "dependencies")) ||
      !identical(value$version, .DSVERT_DP_SYNOPSIS_CLOSURE_VERSION) ||
      !is.list(value$dependencies) || !is.null(names(value$dependencies))) {
    stop("Invalid Synopsis authorization closure.", call. = FALSE)
  }
  keys <- vapply(value$dependencies, function(entry) {
    if (!is.list(entry) || anyDuplicated(names(entry)) ||
        !setequal(names(entry), c("source_identity", "dataset", "dependency"))) {
      stop("Invalid Synopsis authorization closure entry.", call. = FALSE)
    }
    .dsvert_dp_analysis_identity_pk(entry$source_identity, "dependency owner")
    .dsvert_dp_analysis_scalar_id(entry$dataset, "dependency dataset")
    .dsvert_dp_synopsis_dependency_validate_v2(entry$dependency)
    paste(entry$source_identity, entry$dataset, sep = "|")
  }, character(1L))
  if (anyDuplicated(keys) || !identical(keys, sort(keys, method = "radix"))) {
    stop("Synopsis authorization closure is not canonical.", call. = FALSE)
  }
  .dsvert_dp_canonical_query_value(value)
}

.dsvert_dp_synopsis_closure_v2 <- function(bootstraps, policy) {
  entries <- list()
  for (peer in names(bootstraps)) {
    bootstrap <- bootstraps[[peer]]
    dependencies <- bootstrap$authorization_dependencies
    if (!is.list(dependencies) ||
        (length(dependencies) && (is.null(names(dependencies)) ||
         anyDuplicated(names(dependencies)))) ||
        (.dsvert_dp_synopsis_provenance_enabled_v2(policy) &&
         !all(names(bootstrap$draft$datasets) %in% names(dependencies)))) {
      stop("The signed Synopsis dependency coverage is incomplete.",
           call. = FALSE)
    }
    for (dataset in names(dependencies)) {
      dependency <- .dsvert_dp_synopsis_dependency_validate_v2(
        dependencies[[dataset]])
      draft <- bootstrap$draft$datasets[[dataset]]
      if (!is.null(draft) &&
          (!identical(draft$dataset_id, dependency$dataset_id) ||
           !identical(draft$dataset_version, dependency$dataset_version))) {
        stop("The signed Synopsis dependency conflicts with its dataset.",
             call. = FALSE)
      }
      if (identical(dependency$provenance_kind, "padded_psi")) {
        peers <- vapply(dependency$authorization_epochs, `[[`, character(1L),
                        "peer_identity")
        if (!setequal(peers, unname(policy$peer_pinset))) {
          stop("The signed Synopsis dependency omits a PSI participant.",
               call. = FALSE)
        }
      } else if (!identical(
          dependency$authorization_epochs[[1L]]$peer_identity,
          bootstrap$peer_identity_pk)) {
        stop("The signed Synopsis import names another custodian.",
             call. = FALSE)
      }
      entries[[length(entries) + 1L]] <- list(
        source_identity = bootstrap$peer_identity_pk,
        dataset = dataset, dependency = dependency)
    }
  }
  keys <- vapply(entries, function(entry) paste(
    entry$source_identity, entry$dataset, sep = "|"), character(1L))
  .dsvert_dp_synopsis_closure_validate_v2(list(
    version = .DSVERT_DP_SYNOPSIS_CLOSURE_VERSION,
    dependencies = unname(entries[order(keys, method = "radix")])))
}

.dsvert_dp_synopsis_manifest_dependencies_v2 <- function(policy, manifest) {
  if (!.dsvert_dp_synopsis_provenance_enabled_v2(policy)) return(NULL)
  value <- .dsvert_dp_synopsis_closure_validate_v2(
    manifest$capsule_identity$contract$authorization_dependencies)
  if (!length(value$dependencies) || !identical(value,
      .dsvert_dp_synopsis_effective_dependencies_v2(policy,
        manifest$workload, manifest$admission))) {
    stop("The Synopsis manifest has incomplete authorization provenance.",
         call. = FALSE)
  }
  value
}

.dsvert_dp_synopsis_effective_dependencies_v2 <- function(
    policy, workload, admission) {
  closure <- .dsvert_dp_synopsis_closure_validate_v2(
    policy$authorization_dependencies)
  manifest <- list(workload = workload, admission = admission)
  release <- .dsvert_dp_capsule_coordinate_layout(manifest)
  cross <- .dsvert_dp_gaussian_cross_layout(manifest, release)
  blocks <- c(release$blocks, cross$blocks)
  required <- unique(vapply(blocks, function(block) {
    peer <- block$owner_peer
    dataset <- block$dataset
    if (is.null(peer) || !peer %in% names(policy$peer_pinset) ||
        is.null(dataset)) {
      stop("The public Synopsis layout lacks source dependency provenance.",
           call. = FALSE)
    }
    paste(unname(policy$peer_pinset[[peer]]), dataset, sep = "|")
  }, character(1L)))
  keys <- vapply(closure$dependencies, function(entry) paste(
    entry$source_identity, entry$dataset, sep = "|"), character(1L))
  if (!all(required %in% keys)) {
    stop("The Synopsis authorization closure omits an effective source.",
         call. = FALSE)
  }
  # Every retained dataset carries its complete PSI E, so peers used only for
  # intersection membership remain bound even when they own no output block.
  closure$dependencies <- closure$dependencies[keys %in% required]
  .dsvert_dp_synopsis_closure_validate_v2(closure)
}

.dsvert_dp_synopsis_public_source_commitment_v2 <- function(unsigned) {
  .dsvert_dp_provenance_hash("dsVert/synopsis/public-source/v2|", list(
    version = "dsvert-synopsis-provenance-source-commitment-v1",
    catalog_sha256 = unsigned$catalog_sha256,
    source_identity = unsigned$source_identity_pk))
}

.dsvert_dp_synopsis_private_producer_pin_v2 <- function(unsigned, create) {
  .dsvert_dp_provenance_private_pin("synopsis-source-producer-v1",
    list(catalog_sha256 = unsigned$catalog_sha256,
         source_identity = unsigned$source_identity_pk),
    unsigned$source_vector_commitment, create = create)
  invisible(TRUE)
}
