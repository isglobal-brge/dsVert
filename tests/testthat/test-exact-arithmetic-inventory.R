test_that("residual non-exact arithmetic inventory is complete and enforced", {
  inventory_path <- .dsvert_test_package_file(
    "inst", "docs", "exact_gc_residual_inventory.json")
  inventory <- jsonlite::read_json(inventory_path, simplifyVector = FALSE)
  expect_identical(inventory$schema,
                   "dsvert-exact-arithmetic-inventory-v1")
  expect_identical(inventory$promoted_operations,
                   list("truncate-floor", "count-guard", "clamp-count",
                        "joint-dp-laplace-v2",
                        "joint-dp-vector-laplace-v3"))

  residual <- inventory$residual_commands
  ids <- vapply(residual, `[[`, character(1L), "id")
  expected <- c(
    "k2-beaver-vecmul-round2", "k2-full-iter-r3",
    "k2-ring127-local-scale-share", "k2-cmp-gen", "k2-cmp-round1",
    "k2-cmp-round2", "k2-wide-spline-full")
  expect_setequal(ids, expected)
  expect_identical(anyDuplicated(ids), 0L)
  statuses <- vapply(residual, `[[`, character(1L), "status")
  expect_true(all(grepl("not_promoted$", statuses)))

  blockers <- unlist(inventory$promotion_blockers, use.names = FALSE)
  expect_true(any(grepl("exactGCVecmulBindInputsDS", blockers, fixed = TRUE)))

  glm_blockers <- inventory$glm_adapter_blockers
  expect_setequal(
    vapply(glm_blockers, `[[`, character(1L), "id"),
    c("dynamic_ring_records", "linear_predictor_truncation",
      "nonlinear_chain_provenance", "gradient_matvec_truncation",
      "execution_and_estimator_certificate"))
  expect_true(all(vapply(glm_blockers, function(entry) {
    is.character(entry$current) && length(entry$current) == 1L &&
      nzchar(entry$current) && is.character(entry$required) &&
      length(entry$required) == 1L && nzchar(entry$required)
  }, logical(1L))))
})

test_that("residual arithmetic inventory matches source call sites", {
  package_root <- .dsvert_test_source_root()
  main <- paste(readLines(.dsvert_test_package_file(
    "inst", "dsvert-mpc", "main.go", source_only = TRUE), warn = FALSE),
    collapse = "\n")
  inventory <- jsonlite::read_json(.dsvert_test_package_file(
    "inst", "docs", "exact_gc_residual_inventory.json"),
    simplifyVector = FALSE)
  residual <- inventory$residual_commands
  ids <- vapply(residual, `[[`, character(1L), "id")

  for (entry in residual) {
    expect_match(main, paste0('case "', entry$id, '"'), fixed = TRUE)
    for (caller in entry$server_callers) {
      path <- file.path(package_root, caller)
      expect_true(file.exists(path), info = caller)
      code <- paste(readLines(path, warn = FALSE), collapse = "\n")
      expect_match(code, entry$id, fixed = TRUE)
    }
  }

  client_source <- file.path(
    dirname(package_root), "dsVertClient", "R", "exact_gc_transport.R")
  if (!file.exists(client_source)) {
    skip("the sibling dsVertClient source tree is unavailable for this audit")
  }
  exact_client <- paste(readLines(client_source, warn = FALSE), collapse = "\n")
  expect_false(any(vapply(ids, grepl, logical(1L), x = exact_client,
                          fixed = TRUE)))
})
