go_commands_from_main <- function() {
  main <- .dsvert_test_package_file(
    "inst", "dsvert-mpc", "main.go", source_only = TRUE)
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

test_that("Go runtime includes only high-level DP noise commands", {
  cmds <- go_commands_from_main()
  expect_true(all(c(
    "dp-noise-int64", "dp-gaussian-int64", "dp-noise-select-int64") %in%
      cmds))
  expect_true("runtime-capabilities" %in% cmds)
  expect_false(any(grepl("dp-(uniform|seed|raw|debug)", cmds)))
  expect_true("joint-dp-laplace-plan-v2" %in% cmds)
  expect_false(any(grepl("joint-dp-(seed|raw|sample|open)", cmds)))
})

test_that("packaged native runtime advertises the same DP command surface", {
  binary <- .findMpcBinary()
  output <- system2(
    binary, "runtime-capabilities", input = "{}", stdout = TRUE,
    stderr = TRUE)
  expect_identical(attr(output, "status") %||% 0L, 0L)
  manifest <- jsonlite::fromJSON(paste(output, collapse = "\n"),
                                 simplifyVector = FALSE)
  commands <- unlist(lapply(manifest$capabilities, `[[`, "commands"),
                     use.names = FALSE)
  expect_true(all(c(
    "dp-noise-int64", "dp-gaussian-int64", "dp-noise-select-int64") %in%
      commands))
  expect_false(any(grepl("dp-(uniform|seed|raw|debug)", commands)))
  # Only the data-free public planner/compiler are advertised. The joint
  # sampler has no seed/share/sample/open command surface.
  expect_true(all(c(
    "joint-dp-laplace-plan-v2",
    "joint-dp-laplace-worker-contract-v2") %in% commands))
  expect_false(any(grepl("joint-dp-(seed|share|sample|open)", commands)))
})

test_that("joint-DP finite sampler planner remains a data-free preflight", {
  plan <- .dsvert_joint_dp_laplace_plan_v2(
    "5e-1", "5e-7", "2", 4L, bernoulli_bits = 8L)
  expect_identical(plan$capability_available, FALSE)
  expect_identical(plan$sampler, .DSVERT_JOINT_DP_BACKEND_SAMPLER_V2)
  expect_gt(plan$max_geometric_steps, 0)
  expect_equal(plan$bernoulli_trials,
               2L * plan$coordinate_count * plan$max_geometric_steps)
  expect_equal(plan$aes_blocks,
               ceiling(plan$bernoulli_trials * plan$bernoulli_bits / 128))
})

test_that("archived k2-mpc-tool tree is not present", {
  expect_false(dir.exists(file.path(
    .dsvert_test_package_file("inst"), "k2-mpc-tool")))
})
