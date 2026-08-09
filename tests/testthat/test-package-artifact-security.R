test_that("installed artifacts contain no serialized sessions or secret files", {
  source_inst <- file.path(.dsvert_test_source_roots(), "inst")
  source_inst <- source_inst[dir.exists(source_inst)]
  roots <- if (length(source_inst)) {
    source_inst[[1L]]
  } else {
    package_root <- .dsvert_test_package_file()
    file.path(package_root, c("bin", "docs", "dsvert-mpc"))
  }
  shipped <- unlist(lapply(roots, list.files,
    recursive = TRUE, full.names = TRUE, all.files = TRUE,
    include.dirs = FALSE), use.names = FALSE)
  forbidden <- shipped[grepl(
    paste0("\\.(rds|rda|rdata|rhistory|qs|fst|feather|parquet|",
           "sqlite|sqlite3|db|pem|key|p12|pfx)$"),
    shipped, ignore.case = TRUE)]

  expect_identical(forbidden, character())
})

test_that("runtime third-party notices enter the source package", {
  root <- .dsvert_test_package_file("inst", "dsvert-mpc")
  notices <- c(
    "THIRD_PARTY_NOTICES.md",
    list.files(
      file.path(root, "third_party"),
      pattern = "\\.LICENSE$", full.names = FALSE))
  notices[-1L] <- file.path(
    "third_party", notices[-1L])
  expect_length(notices, 8L)
  expect_true(all(file.exists(file.path(root, notices))))
})

test_that("source build policy retains notices and excludes Go sources", {
  buildignore <- .dsvert_test_package_file(
    ".Rbuildignore", source_only = TRUE)
  root <- dirname(buildignore)
  patterns <- readLines(buildignore, warn = FALSE)
  excluded <- function(path) any(vapply(
    patterns, grepl, logical(1L), x = path,
    ignore.case = TRUE, perl = TRUE))
  notices <- c(
    "inst/dsvert-mpc/THIRD_PARTY_NOTICES.md",
    file.path("inst", "dsvert-mpc", "third_party", list.files(
      file.path(root, "inst", "dsvert-mpc", "third_party"),
      pattern = "\\.LICENSE$", full.names = FALSE)))
  expect_false(any(vapply(notices, excluded, logical(1L))))
  expect_true(excluded("inst/dsvert-mpc/main.go"))
})
