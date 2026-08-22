.alignment_mask_test_b64url <- function(value) {
  base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(value)))
}

test_that("alignment-mask geometry is exact for K=2,3,5", {
  contract_hash <- strrep("a", 64L)
  batch <- "op_11111111111111111111111111111111"
  for (k in c(2L, 3L, 5L)) {
    chunk_size <- .dsvert_dp_alignment_mask_chunk_size(k)
    total <- chunk_size + 3L
    parsed <- list(
      sources = paste0("source_", seq_len(k)),
      contract_hash = contract_hash,
      contract = list(coordinate_count = total))
    projection <- list(
      version = "full-v1", source_offset = 0,
      total = as.numeric(total),
      contract = .DSVERT_DP_ALIGNMENT_MASK_FULL_CONTRACT)
    chunk_count <- 2L
    for (index in seq_len(chunk_count)) {
      operation_id <- .dsvert_dp_alignment_mask_operation_id(
        batch, contract_hash, index, chunk_count)
      geometry <- .dsvert_dp_alignment_mask_geometry(
        parsed, projection, batch, operation_id, index, chunk_count)
      expect_identical(geometry$source_count, k)
      expect_identical(geometry$chunk_count, 2L)
      expect_identical(geometry$n,
                       if (index == 1L) chunk_size else 3L)
      expect_identical(
        128L * (3L * geometry$n + 4L * k + 1L) <=
          .DSVERT_EXACT_GC_MAX_CIRCUIT_TYPE_BITS, TRUE)
    }
    expect_error(.dsvert_dp_alignment_mask_geometry(
      parsed, projection, batch,
      .dsvert_dp_alignment_mask_operation_id(
        batch, contract_hash, 1L, chunk_count),
      2L, chunk_count), "chunk contract")
  }
})

test_that("alignment projects only the signed contiguous private suffix", {
  layout <- list(
    enabled = TRUE, private_start = 8193L,
    transport_coordinate_count = 8288L,
    blocks = list(
      left = list(start = 8193L, end = 8240L, length = 48L),
      right = list(start = 8241L, end = 8288L, length = 48L)))
  testthat::local_mocked_bindings(
    .dsvert_dp_gaussian_cross_layout = function(...) layout,
    .package = "dsVert")
  parsed <- list(
    manifest = list(), sources = c("source_a", "source_b"),
    contract_hash = strrep("b", 64L),
    contract = list(coordinate_count = 8288L))
  projections <- .dsvert_dp_alignment_mask_projections(parsed)
  private <- projections[[2L]]
  expect_identical(private$source_offset, 8192)
  expect_identical(private$total, 96)
  expect_identical(private$contract,
                   .DSVERT_DP_ALIGNMENT_MASK_PRIVATE_CONTRACT)
  batch <- "op_11111111111111111111111111111111"
  private_id <- .dsvert_dp_alignment_mask_operation_id(
    batch, parsed$contract_hash, 1L, 1L)
  expect_identical(.dsvert_dp_alignment_mask_projection_for_request(
    parsed, batch, private_id, 1L, 1L), private)
  full_count <- ceiling(8288 / .dsvert_dp_alignment_mask_chunk_size(2L))
  full_id <- .dsvert_dp_alignment_mask_operation_id(
    batch, parsed$contract_hash, 1L, full_count)
  expect_identical(.dsvert_dp_alignment_mask_projection_for_request(
    parsed, batch, full_id, 1L, full_count), projections[[1L]])
})

test_that("each computation peer sees only one XOR share per source", {
  for (k in c(2L, 3L, 5L)) {
    sources <- paste0("source_", seq_len(k))
    shares <- stats::setNames(lapply(seq_len(k), function(index) {
      .alignment_mask_test_b64url(as.raw(
        (seq_len(32L) + index * 17L) %% 256L))
    }), sources)
    state <- list(private_alignment_consensus_shares = shares)
    records <- .dsvert_dp_alignment_mask_digest_records(state, sources)
    expect_type(records, "raw")
    expect_length(records, 32L * k)
    expect_false("private_alignment_consensus_hash" %in% names(state))
    expect_error(.dsvert_dp_alignment_mask_digest_records(
      list(private_alignment_consensus_shares = shares[-1L]), sources),
      "incomplete")
    changed <- shares
    changed[[1L]] <- .alignment_mask_test_b64url(raw(31L))
    expect_error(.dsvert_dp_alignment_mask_digest_records(
      list(private_alignment_consensus_shares = changed), sources),
      "invalid")
  }
})

test_that("alignment terminal response has one uniform semantic failure", {
  make_batch <- function(state) {
    batch <- new.env(parent = emptyenv())
    batch$status <- state
    batch$source_count <- 5L
    batch$total <- 4099
    batch$chunk_count <- 2L
    batch
  }
  for (failure in c(
      "content_mismatch", "shape_mismatch", "phase_mismatch",
      "source_1", "source_2", "source_5")) {
    # The private cause is deliberately absent from the public batch state.
    value <- .dsvert_dp_alignment_mask_terminal_public(
      make_batch("alignment_contract_invalid"))
    expect_identical(names(value), c(
      "capability_id", "version", "state", "terminal_outcome",
      "fixed_transcript", "source_count", "coordinate_count",
      "chunk_count", "alignment_digest_exposed",
      "mismatch_source_exposed", "gate_share_exposed"))
    expect_identical(anyDuplicated(names(value)), 0L)
    expect_identical(value$state, "alignment_contract_invalid")
    expect_identical(value$terminal_outcome,
                     "alignment_contract_invalid")
    expect_false(value$alignment_digest_exposed)
    expect_false(value$mismatch_source_exposed)
    expect_false(value$gate_share_exposed)
    expect_false(failure %in% unlist(value, use.names = FALSE))
  }
})

test_that("alignment batches cannot become readable before terminal success", {
  ss <- new.env(parent = emptyenv())
  ss$.dp_alignment_mask_batches <- new.env(parent = emptyenv())
  batch <- new.env(parent = emptyenv())
  batch$status <- "running"
  batch$capsule_id <- "dpc_11111111111111111111111111111111"
  batch$contract_hash <- strrep("a", 64L)
  ss$.dp_alignment_mask_batches[[
    "op_11111111111111111111111111111111"]] <- batch
  expect_error(.dsvert_dp_alignment_mask_complete_batch(
    ss, batch$capsule_id, batch$contract_hash), "not complete")
  batch$status <- "alignment_contract_invalid"
  expect_error(.dsvert_dp_alignment_mask_complete_batch(
    ss, batch$capsule_id, batch$contract_hash), "not complete")
  batch$status <- "complete"
  expect_identical(.dsvert_dp_alignment_mask_complete_batch(
    ss, batch$capsule_id, batch$contract_hash), batch)
})

test_that("private projection retains global private block coordinates", {
  ss <- new.env(parent = emptyenv())
  ss$.dp_alignment_mask_batches <- new.env(parent = emptyenv())
  batch <- new.env(parent = emptyenv())
  batch$status <- "complete"
  batch$capsule_id <- "dpc_11111111111111111111111111111111"
  batch$contract_hash <- strrep("a", 64L)
  batch$source_offset <- 8192
  batch$total <- 2
  batch$path <- tempfile("dsvert-alignment-mask-")
  on.exit(unlink(batch$path), add = TRUE)
  writeBin(as.raw(seq_len(32L) %% 256L), batch$path)
  ss$.dp_alignment_mask_batches[[
    "op_11111111111111111111111111111111"]] <- batch
  expect_identical(.dsvert_dp_alignment_mask_range(
    ss, batch$capsule_id, batch$contract_hash, 8193L, 2L),
    as.raw(seq_len(32L) %% 256L))
  expect_error(.dsvert_dp_alignment_mask_range(
    ss, batch$capsule_id, batch$contract_hash, 8192L, 1L),
    "range start")
})
