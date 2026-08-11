# Single disclosure-safe profile for the remotely callable surface.
#
# MPC hides intermediate values from the analyst, but an unrestricted exact
# query catalogue can still reconstruct protected records by differencing.
# There is consequently no runtime selector that can enable the historical
# exact/adaptive surface. Only immutable-schema, purpose-bound DP/MPC and
# authenticated peer-transport entry points are admitted. Retained methods
# remain denied until their purpose-bound migration is complete.

.DSVERT_RELEASE_MODE <- "disclosure_safe"
.DSVERT_REMOTE_SURFACE_ID <- "dsvert"
.DSVERT_REMOTE_SURFACE_CONTRACT <- "dsvert-disclosure-safe-v1"
.DSVERT_REMOTE_SURFACE_ATTESTATION_OPTION <-
  "dsvert.remote_surface_attestation"
.DSVERT_REMOTE_SURFACE_ATTESTATION_ENV <-
  "DSVERT_REMOTE_SURFACE_ATTESTATION"
.dsvert_service_bootstrap_state <- new.env(parent = emptyenv())

.dsvert_ensure_service_state <- function() {
  # Tests emulate multiple independent peers inside one R process and supply
  # their own ephemeral identities. They must never write deployment secrets.
  if (isTRUE(.dsvert_identity_test_mode())) return(invisible(NULL))
  if (isTRUE(.dsvert_service_bootstrap_state$ready)) {
    return(invisible(NULL))
  }
  if (isTRUE(.dsvert_service_bootstrap_state$initializing)) {
    stop("Recursive dsVert service-state initialization was detected",
         call. = FALSE)
  }
  .dsvert_service_bootstrap_state$initializing <- TRUE
  on.exit({
    if (exists("initializing", envir = .dsvert_service_bootstrap_state,
               inherits = FALSE)) {
      rm("initializing", envir = .dsvert_service_bootstrap_state)
    }
  }, add = TRUE)
  .dsvert_initialize_service_state()
  .dsvert_service_bootstrap_state$ready <- TRUE
  invisible(NULL)
}

.dsvert_release_mode <- function() {
  .DSVERT_RELEASE_MODE
}

.dsvert_security_gate_state <- new.env(parent = emptyenv())

.dsvert_remote_function_registry <- function(refresh = FALSE) {
  if (!isTRUE(refresh) &&
      !is.null(.dsvert_security_gate_state$remote_functions)) {
    return(.dsvert_security_gate_state$remote_functions)
  }
  namespace <- environment(.dsvert_remote_function_registry)
  candidates <- ls(namespace, all.names = TRUE)
  candidates <- candidates[
    grepl("^[A-Za-z][A-Za-z0-9.]*DS$", candidates)]
  functions <- lapply(candidates, function(name) {
    value <- get(name, envir = namespace, inherits = FALSE)
    if (is.function(value)) value else NULL
  })
  keep <- !vapply(functions, is.null, logical(1L))
  functions <- functions[keep]
  names(functions) <- candidates[keep]
  .dsvert_security_gate_state$remote_functions <- functions
  functions
}

.dsvert_active_remote_methods <- function() {
  registry <- .dsvert_remote_function_registry()
  if (!length(registry)) return(character())
  active <- rev(lapply(seq_len(sys.nframe()), sys.function))
  for (fun in active) {
    matched <- names(registry)[vapply(
      registry, identical, logical(1L), fun)]
    if (length(matched)) return(matched)
  }
  character()
}

.dsvert_disclosure_safe_remote_methods <- c(
  "dsvertSecurityProfileDS",
  "dsvertTransportProbeDS",
  "dsvertIdentityPkDS",
  "dsvertNumericPolicyDS",
  "dsvertColNamesDS",
  "dsvertJointDPCapsuleStatusDS",
  "dsvertDPCountCompileDS",
  "dsvertDPCountAuthorizeDS",
  "dsvertDPCountStartDS",
  "dsvertDPCountFinalShareDS",
  "dsvertDPCountReleaseDS",
  "dsvertDPFrequencyClaimDS",
  "dsvertDPFrequencyCompileDS",
  "dsvertDPFrequencyAuthorizeDS",
  "dsvertDPFrequencySourceWindowDS",
  "dsvertDPFrequencyFinalizeWindowDS",
  "dsvertDPFrequencyReplayDS",
  "dsvertDPFrequencyCleanupDS",
  "psiPaddedInitDS",
  "psiPaddedBindDS",
  "psiPaddedConfirmDS",
  "psiPaddedPrepareDS",
  "psiPaddedReferenceExportDS",
  "psiPaddedTargetProcessDS",
  "psiPaddedReferenceDoubleDS",
  "psiPaddedTargetMatchDS",
  "psiPaddedMembershipAcceptDS",
  "psiPaddedANDStartDS",
  "psiPaddedANDFinalizeDS",
  "psiPaddedANDAcceptDS",
  "psiPaddedFinalPrepareDS",
  "psiPaddedAttestationDS",
  "psiPaddedRelayExchangeDS",
  "psiPaddedFilterDS",
  "mpcTypedBlobStoreDS",
  "mpcTypedBlobReceiptDS",
  "exactGCTransportInitDS",
  "exactGCBindPeersDS",
  "exactGCExchangeDS",
  "exactGCAbortDS",
  "exactGCCleanupDS",
  "exactGCVecmulClaimInputsDS",
  "exactGCVecmulStartDS",
  "exactGCVecmulValidityDS",
  "exactGCVecmulValidityReceiveDS",
  "exactGCVecmulCommitDS",
  "dsvertDPCapsuleManifestDraftDS",
  "dsvertDPCapsuleManifestSignDS",
  "dsvertDPCapsuleManifestBuildDS",
  "dsvertDPCapsuleSourceTicketDS",
  "dsvertDPCapsuleSourcePrepareDS",
  "dsvertDPCapsuleSourceChunkDS",
  "dsvertDPCapsuleSourceAcceptDS",
  "dsvertDPAlignmentMaskStartDS",
  "dsvertDPAlignmentMaskStoreDS",
  "dsvertDPAlignmentMaskSealDS",
  "dsvertDPAlignmentMaskReceiveDS",
  "dsvertDPCategoricalCrossBindDS",
  "dsvertDPCategoricalCrossPrepareDS",
  "dsvertDPCategoricalCrossFinalizeDS",
  "dsvertDPGaussianCrossBindDS",
  "dsvertDPGaussianCrossPrepareDS",
  "dsvertDPGaussianCrossFinalizeDS",
  "dsvertJointDPVectorAllocationProofDS",
  "dsvertJointDPVectorAllocationPrepareDS",
  "dsvertJointDPVectorAllocationCommitDS",
  "dsvertJointDPVectorAllocationAuthorizeDS",
  "dsvertJointDPVectorAllocationOpenDS",
  "dsvertJointDPVectorPrepareDS",
  "dsvertJointDPVectorStartDS",
  "dsvertJointDPVectorResultDS",
  "dsvertJointDPVectorFinalShareDS",
  "dsvertJointDPVectorReleaseDS",
  "dsvertJointDPVectorReplayDS",
  "dsvertJointDPVectorFinalizeAckDS"
)

.dsvert_enforce_release_mode <- function(entry = NULL) {
  # This is the first real server-operation boundary. Package installation and
  # .onLoad remain secret-write-free, while every production DSI entrypoint
  # atomically guarantees the persistent identity before it can return any
  # response. Legacy DP routes initialize their independent noise root lazily
  # through the complete policy boundary.
  .dsvert_ensure_service_state()

  if (is.null(entry)) {
    entries <- .dsvert_active_remote_methods()
  } else {
    if (!is.character(entry) || length(entry) != 1L || is.na(entry) ||
        !grepl("^[A-Za-z][A-Za-z0-9.]*DS$", entry)) {
      stop("Invalid protected entrypoint identity.", call. = FALSE)
    }
    entries <- entry
  }
  # If one closure is bound under multiple DS names, it receives only the
  # intersection of their authority. This prevents an alias from lending an
  # allowlisted name to a blocked endpoint.
  if (!length(entries) ||
      any(!entries %in% .dsvert_disclosure_safe_remote_methods)) {
    stop(
      "This exact or generic release is unavailable in dsVert's single ",
      "disclosure-safe profile. Use a supported purpose-bound DP/MPC method; ",
      "a retained method remains unavailable until its safe migration is ",
      "complete, and no runtime option can enable it.",
      call. = FALSE
    )
  }
  invisible(TRUE)
}

.dsvert_registered_remote_methods <- function(description_path) {
  description <- read.dcf(description_path)
  fields <- intersect(c("AggregateMethods", "AssignMethods"),
                      colnames(description))
  methods <- unlist(lapply(fields, function(field) {
    trimws(strsplit(description[1L, field], ",", fixed = TRUE)[[1L]])
  }), use.names = FALSE)
  methods <- methods[nzchar(methods)]
  aliases <- methods[grepl("=", methods, fixed = TRUE)]
  if (length(aliases)) {
    stop(
      "Remote method aliases are forbidden because they bypass dsVert's ",
      "namespace entrypoint guard: ", paste(aliases, collapse = ", "),
      call. = FALSE)
  }
  unique(methods)
}

.dsvert_remote_surface_contract <- function(
    description_path = system.file("DESCRIPTION", package = "dsVert")) {
  if (!is.character(description_path) || length(description_path) != 1L ||
      is.na(description_path) || !file.exists(description_path)) {
    stop("The installed dsVert DESCRIPTION file is unavailable.",
         call. = FALSE)
  }
  description <- tryCatch(
    read.dcf(description_path),
    error = function(error) stop(
      "The installed dsVert DESCRIPTION file is invalid: ",
      conditionMessage(error), call. = FALSE))
  if (nrow(description) != 1L || !"Package" %in% colnames(description) ||
      is.na(description[1L, "Package"]) ||
      !identical(unname(trimws(description[1L, "Package"])), "dsVert")) {
    stop("The remote-surface contract does not belong to dsVert.",
         call. = FALSE)
  }

  parse_field <- function(field, type) {
    if (!field %in% colnames(description)) {
      return(data.frame(
        name = character(), type = character(), value = character(),
        stringsAsFactors = FALSE))
    }
    raw <- description[1L, field]
    if (is.na(raw)) {
      stop("The dsVert remote-surface contract contains a missing field.",
           call. = FALSE)
    }
    methods <- trimws(strsplit(raw, ",", fixed = TRUE)[[1L]])
    methods <- methods[nzchar(methods)]
    if (any(grepl("=", methods, fixed = TRUE))) {
      stop("Remote method aliases are forbidden.", call. = FALSE)
    }
    if (any(!grepl("^[A-Za-z][A-Za-z0-9.]*DS$", methods))) {
      stop("The dsVert remote-surface contract contains an invalid name.",
           call. = FALSE)
    }
    data.frame(
      name = methods, type = rep(type, length(methods)),
      value = paste0("dsVert::", methods), stringsAsFactors = FALSE)
  }

  contract <- rbind(
    parse_field("AggregateMethods", "aggregate"),
    parse_field("AssignMethods", "assign"))
  if (!nrow(contract)) {
    stop("The dsVert remote-surface allowlist is empty.", call. = FALSE)
  }
  if (anyDuplicated(contract$name) ||
      anyDuplicated(paste(contract$type, contract$name, sep = "\r"))) {
    stop("The dsVert remote-surface contract contains duplicate names.",
         call. = FALSE)
  }
  contract
}

.dsvert_remote_surface_attestation_expected <- function(
    description_path = system.file("DESCRIPTION", package = "dsVert")) {
  contract <- .dsvert_remote_surface_contract(description_path)
  contract <- contract[
    order(contract$type, contract$name, method = "radix"), , drop = FALSE]
  canonical <- paste(
    paste(contract$type, contract$name, contract$value, sep = "\x1f"),
    collapse = "\x1e")
  paste0(
    "dsvert-custodian-surface-attestation-v1:",
    .DSVERT_REMOTE_SURFACE_CONTRACT, ":",
    digest::digest(canonical, algo = "sha256", serialize = FALSE))
}

.dsvert_remote_surface_attestation_status <- function() {
  expected <- tryCatch(
    .dsvert_remote_surface_attestation_expected(),
    error = function(error) error)
  option_value <- getOption(
    .DSVERT_REMOTE_SURFACE_ATTESTATION_OPTION, default = NULL)
  environment_value <- Sys.getenv(
    .DSVERT_REMOTE_SURFACE_ATTESTATION_ENV, unset = NA_character_)
  option_present <- !is.null(option_value)
  environment_present <- !is.na(environment_value) &&
    nzchar(environment_value)
  scalar <- function(value) {
    is.character(value) && length(value) == 1L && !is.na(value) &&
      grepl(
        paste0(
          "^dsvert-custodian-surface-attestation-v1:",
          .DSVERT_REMOTE_SURFACE_CONTRACT, ":[0-9a-f]{64}$"),
        value)
  }
  configured_valid <- (!option_present || scalar(option_value)) &&
    (!environment_present || scalar(environment_value))
  configured <- c(
    if (option_present) option_value else character(),
    if (environment_present) environment_value else character())
  conflicting <- configured_valid && length(unique(configured)) > 1L
  attested <- !inherits(expected, "error") && configured_valid &&
    length(configured) > 0L && !conflicting &&
    identical(configured[[1L]], expected)
  state <- if (inherits(expected, "error")) {
    "server_contract_unavailable"
  } else if (!configured_valid) {
    "invalid_custodian_attestation"
  } else if (!length(configured)) {
    "missing_custodian_attestation"
  } else if (conflicting) {
    "conflicting_custodian_attestation"
  } else if (!attested) {
    "mismatched_custodian_attestation"
  } else {
    "verified_custodian_attestation"
  }
  list(attested = attested, state = state)
}

.dsvert_guard_remote_entrypoints <- function(namespace, description_path) {
  registered <- .dsvert_registered_remote_methods(description_path)
  namespace_ds <- ls(namespace, all.names = TRUE)
  namespace_ds <- namespace_ds[
    grepl("^[A-Za-z][A-Za-z0-9.]*DS$", namespace_ds)]
  namespace_ds <- namespace_ds[vapply(namespace_ds, function(name) {
    is.function(get(name, envir = namespace, inherits = FALSE))
  }, logical(1L))]
  # Guard registered entrypoints and any retained/exported legacy DS closure.
  # The latter cannot be reached as a top-level DataSHIELD method, but guarding
  # it also prevents nested evaluation from performing work before its normal
  # central boundary is reached.
  methods <- unique(c(registered, namespace_ds))
  for (method in methods) {
    if (!exists(method, envir = namespace, inherits = FALSE)) next
    original <- get(method, envir = namespace, inherits = FALSE)
    if (!is.function(original) ||
        identical(attr(original, "dsvert.guarded.entrypoint"), method)) {
      next
    }
    # Prepend the literal guard to the existing closure instead of adding a
    # forwarding wrapper. Many DataSHIELD methods intentionally use
    # parent.frame() to resolve protected symbols in the DSI evaluation frame;
    # an extra wrapper frame would change that security/correctness boundary.
    guarded <- original
    body(guarded) <- substitute({
      .dsvert_enforce_release_mode(METHOD)
      ORIGINAL_BODY
    }, list(METHOD = method, ORIGINAL_BODY = body(original)))
    cmpfun <- get0(
      "cmpfun", envir = asNamespace("compiler"),
      mode = "function", inherits = FALSE)
    if (is.function(cmpfun)) guarded <- cmpfun(guarded)
    attr(guarded, "dsvert.guarded.entrypoint") <- method

    # Both base::loadNamespace() and pkgload run .onLoad before sealing the
    # namespace.  Refuse to mutate a closure if that loader invariant ever
    # changes; bypassing a namespace lock would turn a load-time guard into a
    # runtime namespace patch.
    if (environmentIsLocked(namespace) ||
        bindingIsLocked(method, namespace)) {
      stop(
        "Cannot install the dsVert remote-entrypoint security gate after ",
        "namespace sealing.", call. = FALSE)
    }
    assign(method, guarded, envir = namespace)
  }
  rm(list = ls(.dsvert_security_gate_state, all.names = TRUE),
     envir = .dsvert_security_gate_state)
  invisible(methods)
}

#' Report the disclosure-safe profile
#'
#' dsVert exposes one immutable profile. Historical exact/adaptive releases
#' cannot be enabled by an environment variable, R option or request. Retained
#' methods stay behind the central deny gate until their purpose-bound DP/MPC
#' migration is complete.
#' The logical remote-surface attestation is connector-neutral. It must be
#' provisioned by the custodian after connector-specific administrative tooling
#' verifies that the effective callable inventory exactly matches the installed
#' dsVert contract. Opal may persist it as the server profile option
#' \code{dsvert.remote_surface_attestation}; Rock may receive the same token through
#' the server/container environment variable
#' \code{DSVERT_REMOTE_SURFACE_ATTESTATION}. Neither source is generated
#' automatically or accepted as a client-call argument, and conflicting
#' server-side sources fail closed.
#'
#' @return A public, custodian-owned schema-v4 security-profile description.
#'   The route-specific claims distinguish local profile/surface eligibility
#'   from consortium runtime readiness; the latter requires the client joint-DP
#'   handshake. The top-level compatibility alias `formal_dp_claim_eligible`
#'   applies only to biomedical joint-DP capsule profile/surface eligibility.
#'   It and a client top-level `ready` value never promote formal GLM or formal
#'   Cox: their route-specific `ready` fields remain false while sealed.
#' @export
dsvertSecurityProfileDS <- function() {
  surface <- .dsvert_remote_surface_attestation_status()
  list(
    schema_version = 4L,
    release_mode = .dsvert_release_mode(),
    exact_adaptive_releases_enabled = FALSE,
    disclosure_safe_gate_active = TRUE,
    deployment_surface_attested = surface$attested,
    # Compatibility field: this is a connector-neutral logical surface id,
    # not the name of an Opal profile.
    remote_surface_profile = .DSVERT_REMOTE_SURFACE_ID,
    remote_surface_attestation_authority =
      "custodian_owned_deployment_assertion",
    remote_surface_attestation_state = surface$state,
    formal_dp_claim_eligible = surface$attested,
    route_claims = list(
      schema_version = 1L,
      biomedical_joint_dp_capsule_profile_surface_eligible =
        surface$attested,
      biomedical_joint_dp_capsule_runtime_readiness =
        "not_evaluated_requires_client_joint_dp_status_handshake",
      formal_glm_ready = FALSE,
      formal_glm_state =
        "sealed_no_registered_r_dsi_joint_dp_release_lifecycle",
      formal_cox_ready = FALSE,
      formal_cox_state = paste0(
        "sealed_no_recipient_encrypted_r_dsi_lifecycle_or_",
        "end_to_end_numeric_certificate")),
    unconditional_non_reconstruction_guarantee = FALSE,
    mpc_transport_is_opaque_to_analyst = TRUE,
    caveat = paste(
      "The single release profile cannot be weakened at runtime.",
      "The remote-surface token is a custodian-owned deployment assertion,",
      "not a live introspection proof; it becomes stale if an administrator",
      "changes the effective DataSHIELD callable surface and must then be",
      "reconciled and re-attested with connector-specific admin tooling.",
      "formal_dp_claim_eligible is a compatibility alias for biomedical",
      "joint-DP capsule profile/surface eligibility only; it is neither",
      "runtime consortium readiness nor a formal GLM or Cox readiness claim.",
      "Eligibility also requires immutable DP manifests, a healthy authenticated",
      "ledger, pinned non-colluding peers, and no separate release path.",
      "DP bounds inference risk; it is not a logical impossibility theorem.")
  )
}
