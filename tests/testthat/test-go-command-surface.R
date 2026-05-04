go_commands_from_main <- function() {
  candidates <- c(
    file.path("inst", "dsvert-mpc", "main.go"),
    file.path("..", "..", "inst", "dsvert-mpc", "main.go"),
    system.file("dsvert-mpc", "main.go", package = "dsVert"))
  main <- candidates[nzchar(candidates) & file.exists(candidates)][1L]
  if (is.na(main)) {
    main <- ""
  }
  if (!file.exists(main)) {
    skip("Go source tree is not present in installed package")
  }
  txt <- readLines(main, warn = FALSE)
  m <- regmatches(txt, gregexpr('case "([^"]+)":', txt))
  cmds <- unlist(m, use.names = FALSE)
  sub('^case "([^"]+)":$', "\\1", cmds)
}

test_that("Go runtime does not publish legacy or reveal commands", {
  cmds <- go_commands_from_main()

  forbidden <- c(
    "debug",
    "reveal",
    "snapshot",
    "legacy",
    "dump",
    "patient",
    "plaintext",
    "cox-rank",
    "cox-times",
    "cox-meta")
  expect_false(any(grepl(paste(forbidden, collapse = "|"), cmds)))
})

test_that("archived k2-mpc-tool tree is not present", {
  expect_false(dir.exists(file.path("inst", "k2-mpc-tool")))
})
