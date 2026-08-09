test_that("the installed package exposes one immutable disclosure-safe profile", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  withr::local_envvar(c(DSVERT_REMOTE_SURFACE_ATTESTATION = NA))
  withr::local_options(list(
    dsvert.remote_surface_attestation =
      .dsvert_remote_surface_attestation_expected()))

  expect_identical(.dsvert_release_mode(), "disclosure_safe")
  profile <- dsvertSecurityProfileDS()
  expect_identical(profile$schema_version, 4L)
  expect_identical(profile$release_mode, "disclosure_safe")
  expect_true(profile$disclosure_safe_gate_active)
  expect_false(profile$exact_adaptive_releases_enabled)
  expect_true(profile$deployment_surface_attested)
  expect_identical(profile$remote_surface_profile, "dsvert")
  expect_identical(
    profile$remote_surface_attestation_authority,
    "custodian_owned_deployment_assertion")
  expect_identical(
    profile$remote_surface_attestation_state,
    "verified_custodian_attestation")
  expect_true(profile$formal_dp_claim_eligible)
  expect_identical(profile$route_claims$schema_version, 1L)
  expect_true(
    profile$route_claims[[
      "biomedical_joint_dp_capsule_profile_surface_eligible"]])
  expect_identical(
    profile$route_claims$biomedical_joint_dp_capsule_runtime_readiness,
    "not_evaluated_requires_client_joint_dp_status_handshake")
  expect_false(profile$route_claims$formal_glm_ready)
  expect_false(profile$route_claims$formal_cox_ready)
  expect_false(profile$unconditional_non_reconstruction_guarantee)
  expect_true(profile$mpc_transport_is_opaque_to_analyst)

  withr::local_envvar(c(DSVERT_RELEASE_MODE = "legacy_exact_mpc"))
  withr::local_options(list(
    dsvert.release_mode = "legacy_exact_mpc",
    default.dsvert.release_mode = "legacy_exact_mpc"))
  expect_identical(.dsvert_release_mode(), "disclosure_safe")
  expect_identical(dsvertSecurityProfileDS()$release_mode, "disclosure_safe")
  expect_false(exists(
    ".dsvert_test_set_release_mode", envir = asNamespace("dsVert"),
    inherits = FALSE))
})

test_that("surface readiness fails closed for missing or stale attestation", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  option <- "dsvert.remote_surface_attestation"
  withr::local_envvar(c(DSVERT_REMOTE_SURFACE_ATTESTATION = NA))

  missing <- withr::with_options(
    stats::setNames(list(NULL), option), dsvertSecurityProfileDS())
  expect_false(missing$deployment_surface_attested)
  expect_false(missing$formal_dp_claim_eligible)
  expect_false(
    missing$route_claims[[
      "biomedical_joint_dp_capsule_profile_surface_eligible"]])
  expect_false(missing$route_claims$formal_glm_ready)
  expect_false(missing$route_claims$formal_cox_ready)
  expect_identical(
    missing$remote_surface_attestation_state,
    "missing_custodian_attestation")

  malformed <- withr::with_options(
    stats::setNames(list(c("one", "two")), option),
    dsvertSecurityProfileDS())
  expect_false(malformed$deployment_surface_attested)
  expect_false(malformed$formal_dp_claim_eligible)
  expect_identical(
    malformed$remote_surface_attestation_state,
    "invalid_custodian_attestation")

  mismatched <- withr::with_options(
    stats::setNames(list(
      paste0("dsvert-custodian-surface-attestation-v1:",
             "dsvert-disclosure-safe-v1:",
             paste(rep("0", 64L), collapse = ""))), option),
    dsvertSecurityProfileDS())
  expect_false(mismatched$deployment_surface_attested)
  expect_false(mismatched$formal_dp_claim_eligible)
  expect_identical(
    mismatched$remote_surface_attestation_state,
    "mismatched_custodian_attestation")

  verified <- withr::with_options(
    stats::setNames(
      list(.dsvert_remote_surface_attestation_expected()), option),
    dsvertSecurityProfileDS())
  expect_true(verified$deployment_surface_attested)
  expect_true(verified$formal_dp_claim_eligible)
  expect_identical(
    verified$remote_surface_attestation_state,
    "verified_custodian_attestation")
  expect_match(verified$caveat, "custodian-owned deployment assertion")
  expect_match(verified$caveat, "stale")
  expect_match(verified$caveat, "compatibility alias")
  expect_match(verified$caveat, "neither runtime consortium readiness")
})

test_that("Rock can provision only a server-owned environment attestation", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  expected <- .dsvert_remote_surface_attestation_expected()
  withr::local_options(list(dsvert.remote_surface_attestation = NULL))
  withr::local_envvar(c(DSVERT_REMOTE_SURFACE_ATTESTATION = expected))

  profile <- dsvertSecurityProfileDS()
  expect_true(profile$deployment_surface_attested)
  expect_identical(
    profile$remote_surface_attestation_state,
    "verified_custodian_attestation")

  withr::local_options(list(
    dsvert.remote_surface_attestation = paste0(
      "dsvert-custodian-surface-attestation-v1:",
      "dsvert-disclosure-safe-v1:", strrep("0", 64L))))
  conflict <- dsvertSecurityProfileDS()
  expect_false(conflict$deployment_surface_attested)
  expect_identical(
    conflict$remote_surface_attestation_state,
    "conflicting_custodian_attestation")

  withr::local_options(list(dsvert.remote_surface_attestation = c("a", "b")))
  invalid <- dsvertSecurityProfileDS()
  expect_false(invalid$deployment_surface_attested)
  expect_identical(
    invalid$remote_surface_attestation_state,
    "invalid_custodian_attestation")
})

test_that("server and provisioner attestation canonicalization has a golden vector", {
  description <- tempfile("dsvert-surface-description-")
  withr::defer(unlink(description))
  writeLines(c(
    "Package: dsVert",
    "Version: 1.0.0",
    "AggregateMethods: safeAggregateDS",
    "AssignMethods: safeAssignDS"), description)
  expect_identical(
    .dsvert_remote_surface_attestation_expected(description),
    paste0(
      "dsvert-custodian-surface-attestation-v1:",
      "dsvert-disclosure-safe-v1:",
      "dcca8dcf15580d69dc64893918cf8e78063438497c83d7c8203cd8284a1117b7"))

  writeLines(c(
    "Package: dsVert", "Version: 1.0.0",
    "AggregateMethods: c=base::c"), description)
  expect_error(
    .dsvert_remote_surface_attestation_expected(description),
    "aliases are forbidden")
  expect_error(
    .dsvert_remote_surface_attestation_expected(
      description, profile_name = "default"),
    "unused argument")
})

test_that("the single profile blocks historical shares and generic transport", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  protected <- data.frame(x = seq_len(10L))
  unavailable <- "single disclosure-safe profile"

  expect_error(getObsCountDS("protected"), unavailable)
  expect_error(
    k2GetStoredShareDS("k2_chisq_cross_count_shares",
                       session_id = "safe-gate-test"),
    unavailable)
  expect_error(
    glmRing63TransportInitDS(session_id = "safe-ring-init"),
    unavailable)
  expect_error(mpcGcDS(), unavailable)
  expect_error(mpcCleanupDS("safe-session"), unavailable)
  expect_error(
    mpcStoreBlobDS("arbitrary_share_slot", "opaque",
                   session_id = "safe-generic-blob"),
    unavailable)
  expect_error(
    exactGCVecmulBindInputsDS(
      x_key = "analyst-selected", y_key = "analyst-selected",
      output_key = "analyst-selected", total_n = 1L,
      batch_operation_id = "analyst-selected-operation",
      session_id = "safe-generic-exact-gc"),
    unavailable)

  # This purpose-bound transport endpoint crosses the gate and then rejects
  # its deliberately invalid public session identifier.
  expect_error(
    exactGCTransportInitDS("safe-generic-exact-gc"),
    "canonical lower-case UUID")
})

test_that("an admitted outer call cannot authorize a nested blocked method", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  protected <- data.frame(x = seq_len(10L))
  unavailable <- "single disclosure-safe profile"

  expect_error(
    psiPaddedAttestationDS(data_name = getObsCountDS("protected")),
    unavailable)
  aliased_count <- getObsCountDS
  expect_error(
    psiPaddedAttestationDS(data_name = aliased_count("protected")),
    unavailable)
  expect_error(
    psiPaddedAttestationDS(
      data_name = do.call(aliased_count, list("protected"))),
    unavailable)
  expect_error(
    psiPaddedAttestationDS(
      data_name = get("getObsCountDS", envir = asNamespace("dsVert"))(
        "protected")),
    unavailable)
  expect_error(dsvertBeaverPolicyDS(), unavailable)
  expect_error(
    psiPaddedAttestationDS(data_name = {
      options(dsvert.release_mode = "legacy_exact_mpc")
      getObsCountDS("protected")
    }),
    unavailable)
  expect_identical(.dsvert_release_mode(), "disclosure_safe")
  expect_error(getObsCountDS("protected"), unavailable)
})

test_that("only the purpose-bound padded PSI surface is admitted", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  protected <- data.frame(x = seq_len(10L))
  padded <- c(
    "psiPaddedInitDS", "psiPaddedBindDS", "psiPaddedConfirmDS",
    "psiPaddedPrepareDS", "psiPaddedReferenceExportDS",
    "psiPaddedTargetProcessDS", "psiPaddedReferenceDoubleDS",
    "psiPaddedTargetMatchDS", "psiPaddedMembershipAcceptDS",
    "psiPaddedANDStartDS", "psiPaddedANDFinalizeDS",
    "psiPaddedANDAcceptDS", "psiPaddedFinalPrepareDS",
    "psiPaddedAttestationDS", "psiPaddedRelayExchangeDS",
    "psiPaddedFilterDS")
  legacy <- c(
    "psiInitDS", "psiStoreBlobDS", "psiStoreTransportKeysDS",
    "psiMaskIdsDS", "psiExportMaskedDS", "psiProcessTargetDS",
    "psiDoubleMaskDS", "psiExportMatchedIndicesDS",
    "psiComputeCommonIndicesDS", "psiExportCommonIndicesDS",
    "psiAlignmentManifestDS", "psiMatchAndAlignDS", "psiSelfAlignDS",
    "psiFilterCommonDS", "psiGetMatchedIndicesDS",
    "psiPaddedExactTransportDS")
  expect_true(all(padded %in% .dsvert_disclosure_safe_remote_methods))
  expect_false(any(legacy %in% .dsvert_disclosure_safe_remote_methods))
  expect_true(all(padded %in% getNamespaceExports("dsVert")))
  expect_false(any(legacy %in% getNamespaceExports("dsVert")))
  expect_error(
    psiPaddedAttestationDS("protected"),
    "alignment attestation unavailable")
})

test_that("no environment variable or option enables a retained exact method", {
  .dsvert_test_set_remote_gate("disclosure_safe")
  on.exit(.dsvert_test_set_remote_gate("compatibility_tests"), add = TRUE)
  protected <- data.frame(x = seq_len(10L))
  withr::local_envvar(c(
    DSVERT_RELEASE_MODE = "legacy_exact_mpc",
    DSVERT_TEST_MODE = "true"))
  withr::local_options(list(
    dsvert.release_mode = "legacy_exact_mpc",
    default.dsvert.release_mode = "legacy_exact_mpc"))

  expect_error(getObsCountDS("protected"), "no runtime option can enable")
  expect_identical(.dsvert_release_mode(), "disclosure_safe")
})

test_that("every registered data/session method crosses the central gate", {
  description <- read.dcf(system.file("DESCRIPTION", package = "dsVert"))
  registered <- c(
    trimws(strsplit(description[1L, "AggregateMethods"], ",", fixed = TRUE)[[1L]]),
    trimws(strsplit(description[1L, "AssignMethods"], ",", fixed = TRUE)[[1L]]))
  registered <- registered[!grepl("=", registered, fixed = TRUE)]
  namespace <- asNamespace("dsVert")

  walk <- function(name, seen = character()) {
    if (name %in% seen || !exists(name, namespace, inherits = FALSE)) {
      return(seen)
    }
    value <- get(name, namespace, inherits = FALSE)
    if (!is.function(value)) return(seen)
    seen <- c(seen, name)
    globals <- tryCatch(
      codetools::findGlobals(value, merge = FALSE)$functions,
      error = function(e) character())
    for (global in intersect(globals, ls(namespace, all.names = TRUE))) {
      seen <- walk(global, seen)
    }
    seen
  }

  metadata_only <- c(
    "mpcCleanupDS", "dsvertIdentityPkDS",
    "dsvertNumericPolicyDS", "dsvertSecurityProfileDS",
    "dsvertTransportProbeDS", "dsvertBeaverPolicyDS")
  for (method in setdiff(registered, metadata_only)) {
    calls <- walk(method)
    expect_true(
      any(c(".S", ".validate_data_name",
            ".dsvert_enforce_release_mode") %in% calls),
      info = paste(method, "does not cross a centrally gated boundary"))
  }

  present <- registered[vapply(
    registered, exists, logical(1L), envir = namespace,
    mode = "function", inherits = FALSE)]
  guarded <- vapply(present, function(method) {
    identical(
      attr(get(method, envir = namespace, inherits = FALSE),
           "dsvert.guarded.entrypoint"),
      method)
  }, logical(1L))
  expect_true(all(guarded),
              info = paste(names(guarded)[!guarded], collapse = ", "))
})

test_that("the load-time gate preserves the entrypoint call frame", {
  description <- tempfile("dsvert-gate-description-")
  withr::defer(unlink(description))
  writeLines(c(
    "Package: dsVert",
    "AggregateMethods: frameProbeDS",
    "AssignMethods:"), description)

  namespace <- new.env(parent = baseenv())
  namespace$events <- character()
  gate <- function(entry) {
    events <<- c(events, paste0("gate:", entry))
    invisible(entry)
  }
  probe <- function() {
    events <<- c(events, "body")
    parent.frame()
  }
  environment(gate) <- namespace
  environment(probe) <- namespace
  namespace$.dsvert_enforce_release_mode <- gate
  namespace$frameProbeDS <- probe
  original_formals <- formals(namespace$frameProbeDS)
  original_environment <- environment(namespace$frameProbeDS)

  expect_invisible(
    .dsvert_guard_remote_entrypoints(namespace, description))
  expect_identical(formals(namespace$frameProbeDS), original_formals)
  expect_identical(environment(namespace$frameProbeDS), original_environment)

  caller <- new.env(parent = baseenv())
  caller$frameProbeDS <- namespace$frameProbeDS
  expect_identical(evalq(frameProbeDS(), envir = caller), caller)
  expect_identical(namespace$events, c("gate:frameProbeDS", "body"))

  lockEnvironment(namespace, bindings = TRUE)
  expect_invisible(
    .dsvert_guard_remote_entrypoints(namespace, description))

  sealed <- new.env(parent = baseenv())
  sealed_gate <- function(entry) invisible(entry)
  sealed_probe <- function() parent.frame()
  environment(sealed_gate) <- sealed
  environment(sealed_probe) <- sealed
  sealed$.dsvert_enforce_release_mode <- sealed_gate
  sealed$frameProbeDS <- sealed_probe
  lockEnvironment(sealed, bindings = TRUE)
  expect_error(
    .dsvert_guard_remote_entrypoints(sealed, description),
    "after namespace sealing")
})
