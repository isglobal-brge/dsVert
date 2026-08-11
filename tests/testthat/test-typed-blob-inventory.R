test_that("typed blob migration inventory is machine-readable and complete", {
  path <- system.file(
    "docs", "typed_blob_transport_inventory.json", package = "dsVert")
  if (!nzchar(path)) {
    path <- .dsvert_test_package_file(
      "inst", "docs", "typed_blob_transport_inventory.json")
  }
  inventory <- jsonlite::fromJSON(path, simplifyVector = FALSE)
  expect_identical(
    inventory$schema_version, "dsvert-typed-blob-inventory-v1")
  expect_identical(inventory$legacy_endpoint, "mpcStoreBlobDS")
  expect_identical(inventory$typed_endpoint, "mpcTypedBlobStoreDS")
  expect_identical(inventory$receipt_endpoint, "mpcTypedBlobReceiptDS")
  expect_gte(length(inventory$records), 20L)

  required <- c(
    "id", "families", "callers", "slot", "producer", "recipient",
    "shape", "confidentiality", "migration")
  nonempty_strings <- function(value) {
    if (is.list(value)) value <- unlist(value, recursive = TRUE,
                                        use.names = FALSE)
    is.character(value) && length(value) >= 1L &&
      all(!is.na(value)) && all(nzchar(value))
  }
  expect_true(all(vapply(inventory$records, function(record) {
    is.list(record) && identical(sort(names(record)), sort(required)) &&
      all(vapply(record, nonempty_strings, logical(1L)))
  }, logical(1L))))

  ids <- vapply(inventory$records, `[[`, character(1L), "id")
  expect_identical(anyDuplicated(ids), 0L)
  expect_true(all(c(
    "input.peer_x", "input.peer_y", "input.extra_x",
    "gradient.peer_r1", "beaver.vector_share", "beaver.vecmul_masked",
    "iknp.base_points", "iknp.base_ciphertexts", "iknp.u_matrix",
    "iknp.ciphertexts",
    "glm.weight_share", "glm.sqrt_weight_share",
    "analysis_dp.count_final_share"
  ) %in% ids))
  first_wave <- inventory$records[ids %in% c(
    "input.peer_x", "input.peer_y", "input.extra_x",
    "gradient.peer_r1", "beaver.vector_share", "beaver.vecmul_masked",
    "iknp.base_points", "iknp.base_ciphertexts", "iknp.u_matrix",
    "iknp.ciphertexts",
    "glm.weight_share", "glm.sqrt_weight_share")]
  expect_true(all(vapply(first_wave, function(record) {
    identical(record$migration, "migrated-typed-v1")
  }, logical(1L))))
  expect_false("cor.column_parameters" %in% ids)
})
