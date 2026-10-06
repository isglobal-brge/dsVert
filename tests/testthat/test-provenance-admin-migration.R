.admin_migration_production_gate <- function(env = parent.frame()) {
  .dsvert_test_set_remote_gate("disclosure_safe")
  withr::defer(.dsvert_test_set_remote_gate("compatibility_tests"), envir = env)
  identity_test_mode <- .dsvert_identity_test_mode
  .dsvert_test_replace_binding(".dsvert_identity_test_mode", function() FALSE)
  withr::defer(.dsvert_test_replace_binding(
    ".dsvert_identity_test_mode", identity_test_mode), envir = env)
  bootstrap <- as.list(.dsvert_service_bootstrap_state, all.names = TRUE)
  clear_bootstrap <- function() rm(
    list = ls(.dsvert_service_bootstrap_state, all.names = TRUE),
    envir = .dsvert_service_bootstrap_state)
  clear_bootstrap()
  withr::defer({
    clear_bootstrap()
    list2env(bootstrap, envir = .dsvert_service_bootstrap_state)
  }, envir = env)
  # Prefer the runner's state parent. Default /tmp-based R sessions need a
  # private home directory because production forbids ephemeral state roots.
  state_parent <- dirname(Sys.getenv("DSVERT_STATE_DIR", unset = tempdir()))
  root <- tempfile("admin-migration-", tmpdir = state_parent)
  if (!isTRUE(tryCatch({
    .dsvert_dp_reject_ephemeral_or_library_path(file.path(root, "identity.seed"))
    TRUE
  }, error = function(error) FALSE))) {
    root <- tempfile("admin-migration-", tmpdir = path.expand("~"))
  }
  dir.create(root, mode = "0700")
  withr::defer(unlink(root, recursive = TRUE), envir = env)
  withr::local_envvar(c(DSVERT_STATE_DIR = root), .local_envir = env)
  withr::local_options(list(
    dsvert.state_dir = NULL, default.dsvert.state_dir = NULL,
    dsvert.identity_seed = NULL,
    default.dsvert.identity_seed = NULL), .local_envir = env)
  # The default setup replaces this gate. Assert the actual production guard
  # is installed and rejects a call without an allowlisted remote endpoint.
  expect_identical(.dsvert_enforce_release_mode, .dsvert_test_production_gate)
  expect_false(.dsvert_identity_test_mode())
  expect_error(.dsvert_enforce_release_mode(),
               "This exact or generic release is unavailable", fixed = TRUE)
}

test_that("pure descriptor validation does not authorize remote data lookup", {
  .admin_migration_production_gate()
  descriptor <- list(id = "imported-cohort", version = "v1",
    snapshot_sha256 = strrep("A", 64L),
    alignment_manifest_hash = strrep("B", 64L),
    alignment_manifest_version = 1)
  normalized <- .dsvert_dp_validate_datasets(list(protected = descriptor))
  expect_identical(normalized$protected$snapshot_sha256, strrep("a", 64L))
  expect_identical(normalized$protected$alignment_manifest_hash, strrep("b", 64L))
  expect_identical(normalized$protected$alignment_manifest_version, 1L)
  expect_error(.dsvert_dp_validate_datasets(
    stats::setNames(list(descriptor), "protected;injected()")), "Invalid data_name")
  descriptor$snapshot_sha256 <- "invalid"
  expect_error(.dsvert_dp_validate_datasets(list(protected = descriptor)),
               "64 hexadecimal digits")
  expect_error(.validate_data_name("protected"),
               "This exact or generic release is unavailable", fixed = TRUE)
  expect_error(.dsvert_dp_datasets(normalized),
               "This exact or generic release is unavailable", fixed = TRUE)
})

test_that("exported dataset migration succeeds with the production gate active", {
  # Regression for synopsis-admin-migration-proof.R: use the exported APIs,
  # a persistent identity, and the real gate instead of setup's compatibility
  # guard. Neither administrative API is an analyst endpoint.
  .admin_migration_production_gate()
  frame <- .psi_attach_alignment_manifest(
    data.frame(patient_id = c("u1", "u2"), x = c(1, 5)), "patient_id",
    base64_to_base64url(jsonlite::base64_enc(as.raw(1:32))))
  alignment <- .psi_validate_alignment_manifest(frame)
  descriptor <- list(id = "imported-cohort", version = "v1",
    snapshot_sha256 = .dsvert_dp_snapshot_digest(frame),
    alignment_manifest_hash = alignment$hash,
    alignment_manifest_version = alignment$version)
  authorize <- getExportedValue("dsVert", "dsvertAuthorizeSource")
  reauthorize <- getExportedValue("dsVert", "dsvertReauthorizeSource")
  inventory <- getExportedValue("dsVert", "dsvertListSourceAuthorizations")
  expect_null(inventory())
  first <- authorize(frame, descriptor, "migration-1", kind = "dataset",
                     patient_column = "patient_id")
  expect_identical(first$data, frame)
  expect_identical(first$descriptor, descriptor)
  expect_match(first$epoch, "^[0-9a-f]{64}$")
  expect_identical(reauthorize(frame, descriptor, "migration-1", kind = "dataset",
                              patient_column = "patient_id"), first)
  second <- reauthorize(frame, descriptor, "migration-2", kind = "dataset",
                         patient_column = "patient_id")
  expect_false(identical(second$epoch, first$epoch))
  expect_identical(second$data, first$data)
  expect_length(inventory()$sources, 2L)
  public <- .dsvert_dp_dataset_authorization_public(descriptor, "patient_id")
  expect_identical(.dsvert_dp_provenance_lookup(public, first$epoch), first)
  expect_identical(.dsvert_dp_provenance_lookup(public), second)
  # Publication did not relax the analyst gate or add administrative methods.
  expect_error(.dsvert_enforce_release_mode(),
               "This exact or generic release is unavailable", fixed = TRUE)
  expect_error(getObsCountDS("protected"), "no runtime option can enable")
  admin <- c("dsvertAuthorizeSource", "dsvertReauthorizeSource",
             "dsvertListSourceAuthorizations")
  expect_false(any(admin %in% .dsvert_disclosure_safe_remote_methods))
  expect_false(any(admin %in% names(.dsvert_remote_function_registry(refresh = TRUE))))
  expect_false(any(admin %in% .dsvert_registered_remote_methods(
    .dsvert_test_package_file("DESCRIPTION"))))
})
