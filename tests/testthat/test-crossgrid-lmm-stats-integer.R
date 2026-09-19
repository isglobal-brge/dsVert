test_that("LMM sufficient statistics match the tagged Go integer oracle", {
  binary <- Sys.getenv("DSVERT_GROUPED_REFERENCE_BINARY")
  skip_if(!nzchar(binary), "tag-only Go reference binary not supplied")
  output <- tempfile(fileext = ".json")
  on.exit(unlink(output), add = TRUE)
  withr::with_envvar(c(DSVERT_GROUPED_LMM_STATS_FIXTURE = output), {
    status <- system2(binary, c("-test.run=^TestGroupedLMMStatsFixture$"),
                      stdout = TRUE, stderr = TRUE)
    expect_null(attr(status, "status"))
  })
  fixtures <- jsonlite::fromJSON(output, simplifyVector = FALSE)
  expect_length(fixtures, 3L)
  for (item in fixtures) {
    expect_identical(.grouped_lmm_stats_integer(item$rows, item$beta,
      item$Sigma, item$Tau, item$Cap, item$Bits), item$Want)
  }
})
