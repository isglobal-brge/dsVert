test_that("machine-readable remote surface exactly covers server registration", {
  path <- .dsvert_test_package_file(
    "inst", "docs", "remote_surface_classification.json")
  inventory <- jsonlite::read_json(path, simplifyVector = FALSE)
  expect_identical(
    inventory$schema, "dsvert-remote-surface-classification-v3")

  description <- .dsvert_test_package_file("DESCRIPTION")
  registered <- .dsvert_registered_remote_methods(description)
  expect_identical(
    names(inventory$registered_endpoint_classes),
    "production_safe_purpose_bound")
  classified <- unlist(
    inventory$registered_endpoint_classes$production_safe_purpose_bound,
    use.names = FALSE)
  retired_classes <- c(
    "test_or_guarded_migration_internals",
    "quarantined_compatibility_internals",
    "orphan_remove_candidate", "dangerous_remove_candidate")
  expect_setequal(
    names(inventory$retired_registered_surface), retired_classes)
  retired_surface <- unlist(
    inventory$retired_registered_surface, use.names = FALSE)

  expect_identical(anyDuplicated(classified), 0L)
  expect_setequal(classified, registered)
  expect_true(all(classified %in% .dsvert_disclosure_safe_remote_methods))
  expect_identical(anyDuplicated(retired_surface), 0L)
  expect_length(retired_surface, 105L)
  expect_false(any(retired_surface %in% registered))
  expect_false(any(retired_surface %in% getNamespaceExports("dsVert")))
  expect_length(
    inventory$retired_registered_surface$orphan_remove_candidate, 0L)
  expect_length(
    inventory$retired_registered_surface$dangerous_remove_candidate, 0L)

  expect_identical(
    as.integer(inventory$counts$registered_ds_endpoints),
    length(registered))
  expect_identical(
    as.integer(inventory$counts$registered_orphan_endpoints), 0L)
  expect_identical(
    as.integer(inventory$counts$unregistered_client_endpoint_literals), 105L)
  expect_identical(
    as.integer(inventory$counts$reachable_unregistered_client_endpoints), 0L)
  expect_length(
    inventory$client_ast_resolution$reachable_unregistered_endpoints, 0L)

  risk_endpoints <- unlist(lapply(inventory$risk_overlays, function(risk) {
    unlist(risk$endpoints, use.names = FALSE)
  }), use.names = FALSE)
  expect_true(all(risk_endpoints %in% c(registered, retired_surface)))
  blocked_risk_names <- setdiff(
    names(inventory$risk_overlays),
    c("operational_status_only", "padded_psi_threat_boundary",
      "typed_transport_pilot"))
  blocked_risks <- unlist(lapply(blocked_risk_names, function(name) {
    unlist(inventory$risk_overlays[[name]]$endpoints, use.names = FALSE)
  }), use.names = FALSE)
  expect_false(any(blocked_risks %in%
                     classified))

  fields <- read.dcf(description)
  aggregate_raw <- trimws(strsplit(
    fields[1L, "AggregateMethods"], ",", fixed = TRUE)[[1L]])
  aliases <- aggregate_raw[grepl("=", aggregate_raw, fixed = TRUE)]
  documented_aliases <- unlist(
    inventory$registered_argument_constructor_aliases, use.names = FALSE)
  if (is.null(documented_aliases)) documented_aliases <- character()
  expect_setequal(documented_aliases, aliases)
  expect_identical(anyDuplicated(documented_aliases), 0L)

  markdown <- paste(readLines(.dsvert_test_package_file(
    "inst", "docs", "remote_surface_classification.md"),
    warn = FALSE), collapse = "\n")
  expect_match(markdown, "No non-DS alias is registered", fixed = TRUE)
  expect_false(grepl("explicit aliases to their `base` implementations",
                     markdown, fixed = TRUE))

  joint <- inventory$joint_mpc_single_opening
  expect_identical(
    joint$status,
    "stateless_synopsis_release_e2e_verified")
  expect_identical(joint$producer, "stateless.catalog.synopsis.v1")
  expect_identical(joint$finalizer, "dsvertDPSynopsisReleaseDS")
  expect_true(joint$finalizer %in% registered)
  expect_true(joint$finalizer %in% classified)
  expect_match(joint$current_finalizer_contract,
               "state=synopsis_released", fixed = TRUE)
  expect_match(joint$current_finalizer_contract,
               "intermediate_payload_exposed=false", fixed = TRUE)
  expect_match(joint$current_finalizer_contract,
               "durable_replay=true", fixed = TRUE)
})

test_that("internal DS compatibility functions stay outside the remote surface", {
  path <- .dsvert_test_package_file(
    "inst", "docs", "remote_surface_classification.json")
  inventory <- jsonlite::read_json(path, simplifyVector = FALSE)
  previously_internal <- unlist(
    inventory$internal_unregistered, use.names = FALSE)
  retired_surface <- unlist(
    inventory$retired_registered_surface, use.names = FALSE)
  documented <- c(previously_internal, retired_surface)

  description <- .dsvert_test_package_file("DESCRIPTION")
  registered <- .dsvert_registered_remote_methods(description)
  namespace <- asNamespace("dsVert")
  namespace_ds <- ls(namespace, all.names = TRUE)
  namespace_ds <- namespace_ds[
    grepl("^[A-Za-z][A-Za-z0-9.]*DS$", namespace_ds)]
  namespace_ds <- namespace_ds[vapply(namespace_ds, function(name) {
    is.function(get(name, envir = namespace, inherits = FALSE))
  }, logical(1L))]
  actual_internal <- setdiff(namespace_ds, registered)

  expect_setequal(documented, actual_internal)
  expect_identical(anyDuplicated(documented), 0L)
  expect_false(any(documented %in% getNamespaceExports("dsVert")))
  expect_identical(
    as.integer(inventory$counts$internal_unregistered_ds_functions),
    length(actual_internal))

  grouped <- c(unname(unlist(
    inventory$internal_unregistered_risk_groups, use.names = FALSE)),
    retired_surface)
  expect_setequal(grouped, documented)
  expect_identical(anyDuplicated(grouped), 0L)

  retired <- unlist(
    inventory$internal_unregistered_risk_groups[[
      "retired_legacy_dp_and_scalar_control_plane"]],
    use.names = FALSE)
  retired_histogram <- unlist(
    inventory$internal_unregistered_risk_groups[[
      "retired_exact_descriptive_endpoint"]],
    use.names = FALSE)
  retired_contingency <- unlist(
    inventory$internal_unregistered_risk_groups[[
      "retired_exact_contingency_endpoint"]],
    use.names = FALSE)
  retired_legacy_chisq <- unlist(
    inventory$internal_unregistered_risk_groups[[
      "retired_legacy_chisq_and_vector_share_endpoints"]],
    use.names = FALSE)
  retired_correlation <- intersect(
    unlist(inventory$internal_unregistered_risk_groups[[
      "legacy_dcf_or_comparison"]], use.names = FALSE),
    c("glmRing63CorSetZeroYDS", "glmRing63CorSetColDS"))
  expect_setequal(
    c(retired, retired_histogram, retired_contingency,
      retired_legacy_chisq, retired_correlation),
    unlist(inventory$immediate_removal_decision$removed_in_this_audit,
           use.names = FALSE))
  expect_length(retired, 0L)
  expect_identical(retired_histogram, "dsvertHistogramDS")
  expect_identical(retired_contingency, "dsvertContingencyDS")
  expect_length(retired_legacy_chisq, 10L)
  expect_setequal(retired_correlation,
                  c("glmRing63CorSetZeroYDS", "glmRing63CorSetColDS"))
  expect_false(any(c(retired, retired_histogram, retired_contingency,
                     retired_legacy_chisq, retired_correlation) %in%
                     registered))
  expect_false(any(c(retired, retired_histogram, retired_contingency,
                     retired_legacy_chisq, retired_correlation) %in%
                     getNamespaceExports("dsVert")))

  hard_deleted_count <- c(
    "dsvertJointDPCountReplayDS", "dsvertJointDPCountProposalDS",
    "dsvertJointDPCountSourceDS", "dsvertJointDPCountBackendPrepareDS",
    "dsvertJointDPCountBackendTokenDS", "dsvertJointDPCountStartDS",
    "dsvertJointDPCountResultDS", "dsvertJointDPCountFinalShareDS",
    "dsvertJointDPCountReleaseDS")
  hard_deleted_scalar_control <- c(
    "dsvertJointDPPrepareDS", "dsvertJointDPCommitDS",
    "dsvertJointDPAuthorizeDS", "dsvertJointDPOpenDS",
    "dsvertJointDPResultReceiptDS", "dsvertJointDPDeliveryDS",
    "dsvertJointDPDeliveryContractDS")
  hard_deleted <- c(hard_deleted_count, hard_deleted_scalar_control)
  expect_true(all(hard_deleted %in% unlist(
    inventory$immediate_removal_decision$hard_deleted_in_this_audit,
    use.names = FALSE)))
  expect_false(any(vapply(
    hard_deleted, exists, logical(1L),
    envir = namespace, inherits = FALSE)))
})

test_that("the retired exact histogram is not remotely reachable", {
  description <- .dsvert_test_package_file("DESCRIPTION")
  registered <- .dsvert_registered_remote_methods(description)

  expect_false("dsvertHistogramDS" %in% registered)
  expect_false("dsvertHistogramDS" %in% getNamespaceExports("dsVert"))
  expect_true(exists("dsvertHistogramDS", envir = asNamespace("dsVert"),
                     mode = "function", inherits = FALSE))
})

test_that("the orphaned exact contingency table is not remotely reachable", {
  description <- .dsvert_test_package_file("DESCRIPTION")
  registered <- .dsvert_registered_remote_methods(description)

  expect_false("dsvertContingencyDS" %in% registered)
  expect_false("dsvertContingencyDS" %in% getNamespaceExports("dsVert"))
  expect_true(exists("dsvertContingencyDS", envir = asNamespace("dsVert"),
                     mode = "function", inherits = FALSE))
  expect_false("dsvertContingencyDS" %in%
                 unlist(jsonlite::read_json(
                   .dsvert_test_package_file(
                     "inst", "docs", "remote_surface_classification.json"),
                   simplifyVector = FALSE)$registered_endpoint_classes,
                        use.names = FALSE))
})
