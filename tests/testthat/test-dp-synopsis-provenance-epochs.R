# Production regression for vert01's generic-import intersection oracle.
.synopsis_epoch_setup <- function(env = parent.frame()) {
  state <- tempfile("synopsis-epochs-", tmpdir = Sys.getenv(
    "DSVERT_STATE_DIR", unset = dirname(tempdir())))
  dir.create(state, mode = "0700")
  withr::local_envvar(c(DSVERT_STATE_DIR = state), .local_envir = env)
  withr::local_options(list(dsvert.identity_seed =
    jsonlite::base64_enc(openssl::rand_bytes(32L)),
    dsvert.dp.provenance_store_bytes = 64 * 1024^3), .local_envir = env)
  first <- .get_identity_keypair()
  second <- .callMpcTool("derive-identity", list(
    seed = jsonlite::base64_enc(as.raw(33:64))))
  withr::local_options(list(
    dsvert.peer_name = "peer_a", dsvert.trusted_peers = c(peer_b = second$identity_pk),
    dsvert.dp.domain = "epoch-proof", dsvert.dp.cohort_id = "epoch-cohort",
    dsvert.dp.total_epsilon = 1, dsvert.dp.total_delta = 0,
    dsvert.dp.patient_column = "patient_id", dsvert.dp.unit_capacity = 10L,
    dsvert.dp.max_records_per_unit = 1L, dsvert.dp.overflow_policy = "reject_snapshot",
    dsvert.dp.numeric_grid_bits = 8L, dsvert.dp.numeric_bounds = list(x = c(0, 10)),
    dsvert.dp.categorical_levels = NULL,
    dsvert.dp.capsule_dataset_mapping = NULL,
    dsvert.dp.synopsis_state_path = file.path(state, "synopsis"),
    dsvert.dp.describe_specs = list(primary = list(version = "v1", dataset = "protected",
      variables = "x", histogram_grids = list(x = c(5, 10)),
      allocation = c(count=.2, sum=.3, sumsq=.3, histogram=.2))),
    dsvert.dp.workload_scope = list(mode = "catalog_v1", numeric_moments = "x",
      categorical_marginals = character(), categorical_pairs = list(), correlations = list())),
    .local_envir = env)
  list(state = state, identities = list(peer_a = first, peer_b = second))
}

.synopsis_epoch_import <- function(ids, x) {
  .psi_attach_alignment_manifest(data.frame(patient_id = ids, x = x),
    "patient_id", base64_to_base64url(jsonlite::base64_enc(as.raw(1:32))))
}

.synopsis_epoch_descriptor <- function(data, id = "imported-cohort") {
  alignment <- .psi_validate_alignment_manifest(data)
  list(id=id, version="v1", snapshot_sha256=.dsvert_dp_snapshot_digest(data),
    alignment_manifest_hash=alignment$hash, alignment_manifest_version=alignment$version)
}

.synopsis_epoch_build <- function(identities) {
  policy <- .dsvert_dp_synopsis_policy_v1()
  bootstrap <- .dsvert_dp_synopsis_bootstrap_v1(.policy = policy)
  policy$authorization_dependencies <- .dsvert_dp_synopsis_closure_v2(
    list(peer_a = bootstrap), policy)
  datasets <- lapply(names(policy$datasets), function(name) {
    column <- if (identical(name, "protected")) "x" else "y"
    descriptor <- policy$datasets[[name]]
    list(dataset_id = descriptor$id, dataset_version = descriptor$version,
      schema_version = "schema-v1", alignment_group = "aligned-main",
      patient_keys = list(peer_a = "patient_id"), columns = stats::setNames(list(
        list(kind = "numeric", owner_peer = "peer_a", lower = 0, upper = 10)), column))
  })
  names(datasets) <- names(policy$datasets)
  local_specs <- .dsvert_dp_capsule_manifest_local_specs(policy)
  workload <- .dsvert_dp_canonical_query_value(c(
    list(version=.DSVERT_DP_CAPSULE_WORKLOAD_CONTRACT_VERSION),
    lapply(local_specs,function(entries) lapply(entries,function(spec)
      list(owner_peer="peer_a",spec=spec)))))
  snapshot <- .dsvert_dp_capsule_manifest_expected_snapshot(
    policy,datasets,.PSI_ALIGNMENT_VERSION,workload)
  unsigned <- .dsvert_dp_canonical_query_value(list(
    version=.DSVERT_DP_CAPSULE_SCHEMA_VERSION,logical_snapshot=snapshot,
    peer_pinset_sha256=policy$peer_pinset_sha256,datasets=datasets))
  message <- .dsvert_dp_capsule_schema_message(unsigned)
  schema <- c(unsigned,list(signatures=lapply(identities,function(identity)
    .dsvert_relay_sign_message(message,identity$identity_sk))))
  built <- .dsvert_dp_synopsis_manifest_build_v1(schema,workload,policy,.dsvert_dp_secret())
  retained <- .dsvert_dp_synopsis_policy_for_manifest_v1(
    built$record$manifest_sha256,.dsvert_dp_secret())
  .dsvert_dp_synopsis_local_claim_v1(built$record$manifest_sha256,
    .policy = retained, .secret = .dsvert_dp_secret())
  claim_json <- dsvertDPSynopsisClaimDS(built$record$manifest_sha256)
  claim <- jsonlite::fromJSON(claim_json,simplifyVector=FALSE)$claim
  # Public Claims resolve the authenticated retained policy after a restart.
  claims <- .dsvert_dp_synopsis_source_claim_set_v1(retained,built$manifest,list(claim))
  compiled <- .dsvert_dp_synopsis_local_compile_v1(built$record$manifest_sha256,
    claims, .policy=retained, .secret=.dsvert_dp_secret())
  list(bootstrap=bootstrap,built=built,claim=claim_json,artifact=compiled$artifact,
       receipt=compiled$receipt,
       policy=retained)
}

test_that("legacy cold imports have one content-independent migration response", {
  setup <- .synopsis_epoch_setup()
  current <- .synopsis_epoch_import(c("u1","u2"),c(1,5))
  errors <- lapply(c(FALSE,TRUE),function(inside) {
    before <- if (inside) .synopsis_epoch_import(c("u1","u2","u3"),c(1,5,9)) else current
    withr::local_options(list(dsvert.dp.datasets=list(protected=.synopsis_epoch_descriptor(before))))
    expect_error(.dsvert_dp_synopsis_policy_v1(),
                 "Source authorization migration required", fixed=TRUE)
    tryCatch(dsvertDPSynopsisBootstrapDS(.DSVERT_PROVENANCE_PROTOCOL),
             error=function(e) conditionMessage(e))
  })
  expect_identical(errors[[1L]],errors[[2L]])
  expect_match(errors[[1L]],"Protected capsule operation failed",fixed=TRUE)
  expect_null(dsvertListSourceAuthorizations())
})

test_that("registered legacy imports replay identically in both mutation worlds", {
  for (inside in c(FALSE,TRUE)) {
    setup <- .synopsis_epoch_setup()
    before <- if (inside) .synopsis_epoch_import(c("u1","u2","u3"),c(1,5,9)) else
      .synopsis_epoch_import(c("u1","u2"),c(1,5))
    after <- .synopsis_epoch_import(c("u1","u2"),c(1,5))
    descriptor <- .synopsis_epoch_descriptor(before)
    withr::local_options(list(dsvert.dp.datasets=list(protected=descriptor)))
    authorization <- dsvertAuthorizeSource(before,descriptor,"migration-1",patient_column="patient_id")
    first <- .synopsis_epoch_build(setup$identities)
    # This is vert01's descriptor refresh without an authorization event. The
    # inside-world descriptor changes its private intersection digest only.
    options(dsvert.dp.datasets=list(protected=.synopsis_epoch_descriptor(after)))
    second <- .synopsis_epoch_build(setup$identities)
    expect_identical(second$bootstrap,first$bootstrap)
    expect_identical(second$built$record,first$built$record)
    expect_identical(second$claim,first$claim)
    expect_identical(second$artifact,first$artifact)
    expect_identical(second$receipt,first$receipt)
    public_json <- .dsvert_dp_canonical_json(first$artifact$semantic)
    expect_false(grepl(descriptor$snapshot_sha256, public_json, fixed=TRUE))
    expect_false(grepl(descriptor$alignment_manifest_hash, public_json, fixed=TRUE))
    forged_producer <- list(
      catalog_sha256=first$artifact$semantic$catalog_projection$sha256,
      source_identity_pk=first$policy$own_identity_pk,
      source_vector_commitment=strrep("0",64L))
    expect_error(.dsvert_dp_synopsis_private_producer_pin_v2(
      forged_producer,create=FALSE),"private integrity check")
    resolved <- .dsvert_dp_resolve_snapshot(second$policy,"protected",emptyenv(),.dsvert_dp_secret())
    expect_identical(resolved$data,before)
    retry <- dsvertAuthorizeSource(before,descriptor,"migration-1",patient_column="patient_id")
    expect_identical(retry,authorization)
    next_epoch <- dsvertReauthorizeSource(before,descriptor,"publication-2",patient_column="patient_id")
    expect_false(identical(next_epoch$epoch,authorization$epoch))
    third <- .synopsis_epoch_build(setup$identities)
    expect_false(identical(third$artifact$artifact_key,first$artifact$artifact_key))
    expect_false(identical(third$claim,first$claim))
    expect_false(identical(third$receipt,first$receipt))
    expect_false(identical(third$built$record$manifest_sha256,first$built$record$manifest_sha256))
    expect_identical(dsvertDPSynopsisClaimDS(first$built$record$manifest_sha256),first$claim)
  }
})

test_that("Synopsis effective dependency closure includes secondary sources only when used", {
  setup <- .synopsis_epoch_setup()
  primary <- .synopsis_epoch_import(c("u1","u2"),c(1,5))
  auxiliary <- primary
  names(auxiliary)[[2L]] <- "y"
  # The admitted-count coordinate uses the first dataset in canonical order;
  # choose a later name so this source is truly unused until y is requested.
  descriptors <- list(protected=.synopsis_epoch_descriptor(primary),
                      secondary=.synopsis_epoch_descriptor(auxiliary,"auxiliary-cohort"))
  withr::local_options(list(dsvert.dp.datasets=descriptors,
    dsvert.dp.numeric_bounds=list(x=c(0,10),y=c(0,10)),
    dsvert.dp.capsule_dataset_mapping=list(protected="x",secondary="y")))
  dsvertAuthorizeSource(primary,descriptors$protected,"initial",patient_column="patient_id")
  dsvertAuthorizeSource(auxiliary,descriptors$secondary,"initial",patient_column="patient_id")
  first <- .synopsis_epoch_build(setup$identities)
  dsvertReauthorizeSource(auxiliary,descriptors$secondary,"unused-event",patient_column="patient_id")
  unused <- .synopsis_epoch_build(setup$identities)
  expect_identical(unused$artifact,first$artifact)
  expect_identical(unused$claim,first$claim)
  expect_identical(unused$built$record,first$built$record)
  options(dsvert.dp.workload_scope=list(mode="catalog_v1",numeric_moments=c("x","y"),
    categorical_marginals=character(),categorical_pairs=list(),correlations=list()))
  used <- .synopsis_epoch_build(setup$identities)
  dsvertReauthorizeSource(auxiliary,descriptors$secondary,"used-event",patient_column="patient_id")
  changed <- .synopsis_epoch_build(setup$identities)
  expect_false(identical(changed$artifact$artifact_key,used$artifact$artifact_key))
  expect_false(identical(changed$claim,used$claim))
  expect_length(changed$artifact$semantic$catalog_projection$catalog$authorization_dependencies$dependencies,2L)
})

test_that("Synopsis padded dependencies bind every PSI peer and reject duplicate epochs", {
  epochs <- lapply(1:3, function(index) list(
    peer_identity = base64_to_base64url(jsonlite::base64_enc(as.raw(
      seq_len(32L) + index))), authorization_epoch = strrep(as.character(index),64L),
    source_contract_id = strrep(as.character(index + 3L),64L)))
  epochs <- epochs[order(vapply(epochs,`[[`,character(1L),"peer_identity"),method="radix")]
  pins <- stats::setNames(vapply(epochs,`[[`,character(1L),"peer_identity"),paste0("peer_",1:3))
  policy <- list(peer_pinset=pins, domain="study",cohort_id="cohort",
    peer_pinset_sha256=.dsvert_dp_synopsis_pinset_hash_v1(pins),
    mechanism_version="test-policy",adjacency="add_remove_patient",unit_capacity=10L,
    max_records_per_unit=1L,overflow_policy="reject_snapshot",
    contingency_unit_aggregation_policy="consistent_cell_else_exclude_v1")
  record <- list(epoch=strrep("a",64L),source_contract_id=strrep("b",64L),
    descriptor=list(id="source",version="v1"),provenance=list(
      epoch_vector=epochs,derivation_policy_id=strrep("c",64L)))
  first <- .dsvert_dp_synopsis_dependency_v2(record,policy)
  expect_identical(first$authorization_epochs,.dsvert_dp_canonical_query_value(epochs))
  record$provenance$epoch_vector[[3L]]$authorization_epoch <- strrep("d",64L)
  expect_false(identical(.dsvert_dp_synopsis_dependency_v2(record,policy),first))
  omitted <- record
  omitted$provenance$epoch_vector <- epochs[-3L]
  expect_error(.dsvert_dp_synopsis_dependency_v2(omitted,policy),"peer set")
  duplicate <- first
  duplicate$authorization_epochs[[2L]]$authorization_epoch <-
    duplicate$authorization_epochs[[1L]]$authorization_epoch
  expect_error(.dsvert_dp_synopsis_dependency_validate_v2(duplicate),"authorization dependency")
  malformed <- first
  malformed$provenance_kind <- c("padded_psi","frozen_materialized_root")
  expect_error(.dsvert_dp_synopsis_dependency_validate_v2(malformed),"authorization dependency")
  changed_policy <- policy
  changed_policy$unit_capacity <- 11L
  expect_false(identical(.dsvert_dp_synopsis_dependency_v2(record,changed_policy)$derivation_policy_id,
    .dsvert_dp_synopsis_dependency_v2(record,policy)$derivation_policy_id))
})

test_that("mixed Synopsis protocols fail before authorization capture", {
  expect_error(dsvertDPSynopsisBootstrapDS(),"Incompatible dsVert privacy protocol")
  old <- .dsvert_dp_canonical_json(list(
    bootstraps=list(),phase="schema_signature",schema_signatures=NULL,
    version="dsvert-stateless-catalog-synopsis-bind-request-v1"))
  expect_error(.dsvert_dp_synopsis_bind_v1(old,
    .policy=stop("Private policy resolution was reached")),"Invalid synopsis Bind request")
})

test_that("an aligned seal cannot repair a missing complete source authorization", {
  setup <- .synopsis_epoch_setup()
  pins <- vapply(setup$identities,function(identity)
    base64_to_base64url(identity$identity_pk),character(1L))
  original <- data.frame(patient_id=c("u1","u2","u3"),x=c(1,5,9))
  padded <- .dsvert_test_padded_dp_binding(original,"patient_id","padded-import","v1",pins)
  public <- .dsvert_dp_dataset_authorization_public(padded$descriptor,"patient_id")
  expect_null(.dsvert_dp_provenance_lookup(public))
  # Even an intact private aligned seal is insufficient to recreate a missing
  # full source record. Neither unchanged nor altered current rows are read.
  accessed <- 0L
  symbol <- "provenance_absent_fixture"
  expect_false(exists(symbol,envir=.GlobalEnv,inherits=FALSE))
  makeActiveBinding(symbol,function(value) {
    accessed <<- accessed + 1L
    stop("Current imported content was inspected")
  },.GlobalEnv)
  withr::defer(rm(list=symbol,envir=.GlobalEnv))
  policy <- list(policy_contract=.DSVERT_DP_SYNOPSIS_POLICY_CONTRACT,
    require_snapshot_digest=TRUE,patient_column="patient_id",
    datasets=stats::setNames(list(padded$descriptor),symbol))
  outcomes <- lapply(c(FALSE,TRUE),function(change) {
    descriptor <- padded$descriptor
    if (change) descriptor$snapshot_sha256 <- .dsvert_dp_snapshot_digest(original[1:2,])
    policy$datasets[[symbol]] <- descriptor
    tryCatch(.dsvert_dp_synopsis_registered_policy_v2(policy),
      error=function(e) conditionMessage(e))
  })
  expect_identical(outcomes[[1L]],outcomes[[2L]])
  expect_match(outcomes[[1L]],"Source authorization migration required",fixed=TRUE)
  expect_identical(accessed,0L)
})
