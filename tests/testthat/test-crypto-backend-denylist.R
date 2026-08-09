test_that("the non-private markkurossi VOLE helper is never imported", {
  go_root <- .dsvert_test_package_file(
    "inst", "dsvert-mpc", source_only = TRUE)
  sources <- list.files(
    go_root, pattern = "[.]go$", recursive = TRUE, full.names = TRUE)
  skip_if(!length(sources), "Go source tree is unavailable for this static audit")
  expect_true(length(sources) > 0L)

  imported <- vapply(sources, function(path) {
    text <- paste(readLines(path, warn = FALSE), collapse = "\n")
    grepl(
      '"github[.]com/markkurossi/mpc/vole"', text,
      perl = TRUE)
  }, logical(1L))

  expect_false(any(imported), info = paste(
    "github.com/markkurossi/mpc/vole is not a private VOLE backend:",
    "its receiver multiplication sends the receiver vector to the sender.",
    "Use only a separately reviewed OLE/VOLE implementation."))
})
