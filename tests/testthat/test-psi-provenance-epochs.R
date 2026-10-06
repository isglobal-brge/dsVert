.psi_epoch_test_state <- function(env = parent.frame()) {
  path <- tempfile("psi-epochs-")
  dir.create(path, mode = "0700")
  withr::local_envvar(c(DSVERT_STATE_DIR = path), .local_envir = env)
  withr::local_options(list(dsvert.identity_seed =
    jsonlite::base64_enc(as.raw(rep(189L, 32L)))), .local_envir = env)
}

test_that("PSI authorizations freeze content, survive reload and rotate only on events", {
  .psi_epoch_test_state()
  original <- data.frame(id = c("member", "outside"), value = c(1L, 2L))
  descriptor <- dsvertPSISourceDescriptor(original, "id", "epoch-cohort", "v1")
  withr::local_options(list(dsvert.psi.authorized_sources = list(D = descriptor)))
  first <- suppressMessages(.psi_padded_authorize_source("D", "id", original))
  expect_match(first$authorization_epoch, "^[0-9a-f]{64}$")
  for (row in 1:2) {
    changed <- original[-row, , drop = FALSE]
    # Both inside/outside changes use exactly the old captured source, including
    # before any analysis result has been requested.
    expect_identical(.psi_padded_authorize_source("D", "id", changed), first)
  }
  expect_identical(.psi_padded_authorize_source("D", "id", NULL), first)
  expect_identical(.psi_padded_authorize_source("D", "id",
    stop("A registered source must not inspect the current object")), first)
  alias_options <- list(D = descriptor, Alias = descriptor)
  withr::local_options(list(dsvert.psi.authorized_sources = alias_options))
  expect_identical(.psi_padded_authorize_source("Alias", "id", original), first)
  # The loader has no process-local authority cache; every call authenticates
  # the durable store, so an independent read returns the complete same frame.
  loaded <- .dsvert_dp_provenance_lookup(.psi_padded_authorization_public(descriptor))
  expect_identical(loaded$epoch, first$authorization_epoch)
  expect_identical(loaded$data, original)
  next_event <- dsvertReauthorizeSource(original, descriptor, "publication-2", kind = "psi")
  expect_false(identical(next_event$epoch, first$authorization_epoch))
  retry <- dsvertReauthorizeSource(original, descriptor, "publication-2", kind = "psi")
  expect_identical(retry, next_event)
  next_load <- .psi_padded_authorize_source("D", "id", original)
  expect_identical(next_load$authorization_epoch, next_event$epoch)
})

test_that("PSI cold raw-source registration preserves approved digest admission", {
  .psi_epoch_test_state()
  original <- data.frame(id = c("p1", "p2"), value = 1:2)
  descriptor <- dsvertPSISourceDescriptor(original, "id", "cold-cohort", "v1")
  withr::local_options(list(dsvert.psi.authorized_sources = list(D = descriptor)))
  expect_error(.psi_padded_authorize_source("D", "id", original[1L, , drop=FALSE]),
               "custodian-approved snapshot")
  expect_null(.dsvert_dp_provenance_lookup(.psi_padded_authorization_public(descriptor)))
})

test_that("already-aligned fallback descriptors have a content-independent migration boundary", {
  .psi_epoch_test_state()
  original <- data.frame(id=c("inside", "outside"), value=1:2)
  raw_descriptor <- dsvertPSISourceDescriptor(
    original, "id", "fallback-import", "v1")
  imported_descriptor <- list(id=raw_descriptor$id, version="v1",
    snapshot_sha256=raw_descriptor$snapshot_sha256,
    alignment_manifest_hash=strrep("a",64L), alignment_manifest_version=1L)
  withr::local_options(list(dsvert.psi.authorized_sources=NULL,
    dsvert.dp.patient_column="id", dsvert.dp.datasets=list(D=imported_descriptor)))
  for (current in list(original, original[1L,,drop=FALSE], NULL)) {
    expect_error(.psi_padded_authorize_source("D","id",current),
                 "Source authorization migration required", fixed=TRUE)
  }
  expect_error(.psi_padded_authorize_source("D","id",
    stop("Migration must precede private data lookup")),
    "Source authorization migration required", fixed=TRUE)
  event <- dsvertAuthorizeSource(original, raw_descriptor,
    "legacy-fallback-publication", kind="psi")
  restored <- .psi_padded_authorize_source("D","id",NULL)
  expect_identical(restored$authorization_epoch,event$epoch)
  expect_identical(restored$data,original)
})

test_that("stable PSI derivation excludes run fallback but binds policy", {
  descriptor <- dsvertPSISourceDescriptor(data.frame(id="p1"), "id", "policy-cohort", "v1")
  withr::local_options(list(dsvert.psi.study_id = "",
    dsvert.psi.pseudonym_mode = "shared_key", dsvert.psi.pseudonym_key = "test-only-key",
    dsvert.psi.padded_missing_policy = "id_only"))
  public <- .psi_padded_authorization_public(descriptor)
  first <- .psi_padded_policy("run-one", public$source)
  second <- .psi_padded_policy("run-two", public$source)
  expect_false(identical(first$policy_id, second$policy_id))
  expect_identical(.psi_padded_authorization_public(descriptor), public)
  options(dsvert.psi.padded_missing_policy = "complete_cases")
  changed <- .psi_padded_authorization_public(descriptor)
  expect_false(identical(changed$derivation_policy_id, public$derivation_policy_id))
})

test_that("explicit PSI policies cannot auto-register legacy aligned imports", {
  .psi_epoch_test_state()
  token <- .dsvert_relay_b64url_encode(as.raw(0:31))
  original <- .psi_attach_alignment_manifest(
    data.frame(id=c("inside","outside"),value=1:2),"id",token)
  descriptor <- dsvertPSISourceDescriptor(
    original,"id","explicit-import","v1")
  withr::local_options(list(dsvert.psi.authorized_sources=list(D=descriptor)))
  changed <- .psi_attach_alignment_manifest(
    data.frame(id="inside",value=1L),"id",token)
  for (frame in list(original,changed)) {
    expect_error(.psi_padded_authorize_source("D","id",frame),
      "Source authorization migration required",fixed=TRUE)
  }
  event <- dsvertAuthorizeSource(original,descriptor,
    "explicit-import-migration",kind="psi")
  expect_identical(.psi_padded_authorize_source("D","id",changed)$data,
                   original)
  expect_identical(.psi_padded_authorize_source("D","id",changed)$authorization_epoch,
                   event$epoch)
})

test_that("PSI complete epoch vectors reject duplicate identities and wrong coverage", {
  epochs <- .psi_padded_test_epoch_vector(count=3L)
  expect_identical(.psi_padded_validate_authorization_epochs(epochs), epochs)
  expect_error(.psi_padded_validate_authorization_epochs(rev(epochs)), "epoch vector")
  duplicate <- epochs
  duplicate[[2L]] <- duplicate[[1L]]
  expect_error(.psi_padded_validate_authorization_epochs(duplicate), "epoch vector")
  expected <- vapply(epochs, `[[`, character(1L), "peer_identity")
  expect_error(.psi_padded_validate_authorization_epochs(epochs[-3L], expected),
               "epoch vector")
  changed <- epochs
  changed[[3L]]$authorization_epoch <- strrep("a",64L)
  expect_false(identical(.psi_padded_canonical_json(changed),
                         .psi_padded_canonical_json(epochs)))
})

test_that("trusted PSI finalization seals all aligned values before first query", {
  .psi_epoch_test_state()
  token <- .dsvert_relay_b64url_encode(as.raw(0:31))
  source <- .psi_padded_test_source_public("id", "sealed-cohort")
  contract <- c(list(protocol=.DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash=strrep("a",64L), attestation_id=paste0("attest_",strrep("b",64L)),
    policy_id=paste0("policy_",strrep("c",64L))), source,
    list(derivation_policy_id=strrep("d",64L),
      authorization_epochs=.psi_padded_test_epoch_vector(),
      pinset_id=paste0("pinset_",strrep("e",64L)), capacity=64L,
      relay_frame_bytes=65536L, inline_max_bytes=65536L,
      peer_names=c("a","b"), reference_peer="a", compute_peers=c("a","b")))
  frame <- data.frame(id=c("p2","p1"), category=factor(c("x","y")), value=c(2L,1L))
  aligned <- .psi_padded_attach_attestation(
    .psi_attach_alignment_manifest(frame,"id",token),contract)
  descriptor <- dsvertDPDatasetDescriptor(aligned,"sealed-cohort","v1")
  authorized <- dsvertAuthorizeSource(aligned,descriptor,
    "custodian-padded-publication",kind="dataset",patient_column="id")
  expect_identical(authorized$provenance$epoch_vector,
                   contract$authorization_epochs)
  expect_identical(authorized$provenance$derivation_policy_id,
                   contract$derivation_policy_id)
  expect_error(dsvertAuthorizeSource(aligned,descriptor,
    "conflicting-padded-publication",kind="dataset",patient_column="id",
    provenance=list(epoch_vector=list(),derivation_policy_id=strrep("f",64L))),
    "provenance")
  changed <- aligned
  changed$category[[1L]] <- "y"
  expect_error(.psi_padded_validate_persistent_attestation(changed),
               "private integrity check")
  reordered <- frame[2:1,,drop=FALSE]
  new_token <- .dsvert_relay_b64url_encode(as.raw(32:63))
  equivalent <- .psi_padded_attach_attestation(
    .psi_attach_alignment_manifest(reordered,"id",new_token),contract)
  expect_identical(.psi_padded_validate_persistent_attestation(equivalent),
                   .psi_padded_validate_persistent_attestation(aligned))
})

test_that("old PSI clients are rejected before private data lookup", {
  expect_error(psiPaddedInitDS("unavailable_private_source", "id", "invalid", "invalid"),
               "Incompatible dsVert privacy protocol")
})
