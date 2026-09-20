# Run inside each synthetic custodian. Only boolean evidence leaves the fresh
# R process; private MAC material and persisted shares never enter a report.
grid_snapshot_lifecycle <- function() {
  fixture <- get(".grid_lifecycle_fixture", .GlobalEnv)
  path <- dsVert:::.dsvert_dp_capsule_source_store_path(fixture$policy)
  copy <- tempfile("synthetic-cold-", tmpdir = dirname(path), fileext = ".sqlite")
  source <- DBI::dbConnect(RSQLite::SQLite(), path)
  on.exit(DBI::dbDisconnect(source), add = TRUE)
  target <- DBI::dbConnect(RSQLite::SQLite(), copy)
  on.exit(DBI::dbDisconnect(target), add = TRUE)
  RSQLite::sqliteCopyDatabase(source, target)
  Sys.chmod(copy, "0600")
  fixture$record_database <- copy
  assign(".grid_lifecycle_fixture", fixture, .GlobalEnv)
  invisible(TRUE)
}

grid_cold_lifecycle <- function(server_dir, signed_contract, signed_schema) {
  fixture <- get(".grid_lifecycle_fixture", .GlobalEnv)
  callr::r(function(server_dir, fixture, signed_contract, signed_schema) {
    pkgload::load_all(server_dir, quiet = TRUE)
    sf <- function(name) get(name, asNamespace("dsVert"), inherits = FALSE)
    sf(".dsvert_dp_glm_grid_profile_admit")(
      signed_contract, fixture$policy, signed_schema)
    manifest <- sf(".dsvert_dp_capsule_source_manifest")(fixture$manifest_json)
    source <- DBI::dbConnect(RSQLite::SQLite(), fixture$record_database)
    on.exit(DBI::dbDisconnect(source), add = TRUE)
    scratch <- DBI::dbConnect(RSQLite::SQLite(), ":memory:")
    on.exit(DBI::dbDisconnect(scratch), add = TRUE)
    RSQLite::sqliteCopyDatabase(source, scratch)
    block <- sf(".dsvert_dp_capsule_coordinate_layout")(manifest)$blocks[["gaussian_models::grid"]]
    chunk <- list(offset = block$start - 1, count = block$length)
    base <- as.raw(rep(7, 16 * block$length))
    inject <- function() sf(".dsvert_dp_glm_grid_cross_inject")(
      scratch, fixture$secret, manifest, fixture$source_contract, chunk, base)
    first <- inject()
    record <- sf(".dsvert_dp_glm_grid_cross_load")(scratch, fixture$secret,
      fixture$source_contract$capsule_id, "grid", 0)
    sf(".dsvert_dp_glm_grid_cross_save")(scratch, fixture$secret, record, 0)
    replay <- inject()
    expected <- sf(".dsvert_dp_capsule_source_add_ring128")(
      base, sf(".exact_gc_standard_b64_raw")(record$share, length(base), "synthetic result"))
    stopifnot(identical(first, expected), identical(replay, first))
    changed <- record
    changed$semantic_key <- paste(rep("0", 64), collapse = "")
    changed_rejected <- inherits(tryCatch(
      sf(".dsvert_dp_glm_grid_cross_save")(scratch, fixture$secret, changed, 0),
      error = identity), "dsvert_dp_public_failure")
    DBI::dbExecute(scratch, "UPDATE source_cross_grid_records SET record_json='{}'")
    tamper_condition <- tryCatch(
      sf(".dsvert_dp_synopsis_remote_public_v1")(inject()), error = identity)
    tamper_rejected <- inherits(tamper_condition, "dsvert_dp_public_failure") &&
      identical(conditionMessage(tamper_condition), sf(".DSVERT_DP_PUBLIC_FAILURE_MESSAGE"))
    stopifnot(changed_rejected, tamper_rejected)
    list(cold_authenticated_admission = TRUE, durable_resume = TRUE,
      exactly_once_original_injection = TRUE, identical_replay = TRUE,
      changed_key_rejected = changed_rejected, record_tamper_rejected = tamper_rejected)
  }, args = list(server_dir, fixture, signed_contract, signed_schema))
}
