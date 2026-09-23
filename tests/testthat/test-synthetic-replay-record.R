.synthetic_replay_helpers <- function() {
  env <- new.env(parent = globalenv())
  sys.source(test_path("..", "..", "inst", "cross-grid-v2",
    "integrator-validation", "synthetic_replay_record.R"), env)
  env
}

test_that("synthetic replay records preserve exact integers and all draw inputs", {
  helper <- .synthetic_replay_helpers()
  contract <- list(spec = list(family = "lmm"), signatures = list(a = "a", b = "b"))
  exact <- c("4", "9007199254740993", "9007199254740994")
  calls <- list(list(command = "joint-dp-vector-convolution-share-v4",
    input = list(private_seed = strrep("a", 64), chunk_start = 0,
      coordinate_count = 3, commitment_context = strrep("b", 64))))
  record <- helper$grid_synthetic_replay_record(list(grid = contract), contract,
    list(signatures = list(a = "a", b = "b")), list(unit_capacity = 4),
    exact, exact, 2:3, list(), calls)
  roundtrip <- jsonlite::fromJSON(jsonlite::toJSON(record,
    auto_unbox = TRUE, digits = NA, null = "null"), simplifyVector = FALSE)
  expect_identical(roundtrip$exact_coordinates, as.list(exact))
  expect_identical(roundtrip$exact_candidate_criterion_integers, as.list(exact[2:3]))
  expect_identical(roundtrip$native_calls[[1L]]$input$private_seed, strrep("a", 64))
  expect_identical(roundtrip$signed_workload$grid, contract)
  expect_identical(record$exact_coordinates_sha256,
    digest::digest(charToRaw(paste0(paste(exact, collapse = "\n"), "\n")),
      algo = "sha256", serialize = FALSE))
  expect_error(helper$grid_synthetic_replay_record(list(), contract,
    list(signatures = list(a = "a", b = "b")), list(), as.numeric(exact),
    exact, 2:3, list(), calls))
  expect_error(helper$grid_synthetic_replay_record(list(), contract,
    list(signatures = list(a = "a", b = "b")), list(), exact,
    exact, c(2L, 2L), list(), calls))
})

test_that("native seed capture refuses non-synthetic provisioning", {
  helper <- .synthetic_replay_helpers()
  called <- FALSE
  boot <- helper$grid_synthetic_replay_boot(function(...) { called <<- TRUE })
  expect_error(boot(list(dataset_id = "production"), "unused",
    raw = data.frame(patient_id = "synthetic-1")))
  expect_error(boot(list(dataset_id = "cross-grid-synthetic"), "unused",
    raw = data.frame(patient_id = "real-patient")))
  expect_false(called)
})

test_that("native capture preserves singleton arrays and calls the sampler once", {
  helper <- .synthetic_replay_helpers()
  path <- tempfile()
  on.exit({
    unlink(path)
    rm(list = c(".grid_synthetic_native_calls", ".grid_synthetic_native_path"),
      envir = .GlobalEnv)
  }, add = TRUE)
  assign(".grid_synthetic_native_calls", list(), .GlobalEnv)
  assign(".grid_synthetic_native_path", path, .GlobalEnv)
  invocations <- 0L
  wrapped <- helper$grid_synthetic_capture_native(function(command, input, simplify) {
    invocations <<- invocations + 1L
    expect_false(simplify)
    on.exit(invisible(NULL))
    list(clamped_scaled_values = list("9007199254740993"), parameter = pi)
  })
  output <- wrapped("joint-dp-vector-convolution-finalize-v4", list(chunk_start = 0))
  expect_identical(invocations, 1L)
  expect_identical(output$clamped_scaled_values, "9007199254740993")
  expect_identical(output$parameter, pi)
  captured <- readRDS(path)
  expect_identical(captured[[1L]]$output$clamped_scaled_values, list("9007199254740993"))
})
