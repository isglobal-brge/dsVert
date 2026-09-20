test_that("categorical source cache binds each signed class order", {
  block <- list(input_family = "glm_grid", dataset = "cohort", variable = "y",
    owner_peer = "peer_a", kind = "value", outcome = TRUE,
    levels = c("A", "B"), maximum = 1)
  reversed <- block
  reversed$levels <- rev(block$levels)
  segments <- list(
    list(type = "private", start = 1L, end = 2L, length = 2L, block = block),
    list(type = "private", start = 3L, end = 4L, length = 2L, block = reversed))
  context <- list(local_peer = "peer_a", policy = list(), release = list(),
    manifest = list(bounds = list(numeric_grid_bits = 16)),
    layout = list(transport_coordinate_count = 4),
    snapshots = list(cohort = list(data = data.frame(y = c("A", "B")))))
  local_mocked_bindings(
    .dsvert_dp_gaussian_cross_source_context = function(...) context,
    .dsvert_dp_gaussian_cross_source_segments = function(...) segments,
    .dsvert_dp_admit_units = function(...) list(),
    .dsvert_dp_capsule_bounded_category = function(data, policy, variable, levels, admission)
      list(cell = match(data[[variable]], levels)))
  producer <- .dsvert_dp_gaussian_cross_source_producer(list(), list(), list(),
    compute_commitment = FALSE)
  expect_equal(as.numeric(producer$read_range(1, 4)), c(0, 1, 1, 0))
  expect_equal(as.numeric(producer$read_range(3, 2)), c(1, 0))
  producer$reset()
  expect_equal(as.numeric(producer$read_range(1, 4)), c(0, 1, 1, 0))
})
