# Server-local adapter for authenticated, already materialized source records.
# The caller must verify source MACs and complete private alignment/validity
# before passing shares. These helpers do not register a public source reader.
.dsvert_dp_cox_cross_source_plan <- function(contract, source_contract_sha256) {
  spec <- contract$spec
  if (!is.character(source_contract_sha256) || length(source_contract_sha256) != 1L ||
      is.na(source_contract_sha256) || !grepl("^[0-9a-f]{64}$", source_contract_sha256) ||
      identical(source_contract_sha256, strrep("0", 64))) .dsvert_dp_cox_grid_cross_fail()
  list(version = "dsvert-cox-staged-source-handoff-v1",
    spec_sha256 = .dsvert_joint_dp_hash(spec),
    source_contract_sha256 = source_contract_sha256,
    profile_sha256 = .dsvert_joint_dp_hash(spec$numeric_contract),
    schema_sha256 = spec$schema_sha256,
    capacity = spec$observation_capacity, grid_bits = spec$numeric_grid_bits,
    caps = as.list(sprintf("%.0f", unlist(spec$sensitivity$maximum_coordinates,
      use.names = FALSE))))
}

.dsvert_dp_cox_cross_source_handoff <- function(contract, policy, schema_manifest,
    source_contract_sha256, owner_predictors, predictor_validity, live_event,
    live_event_validity) {
  contract <- .dsvert_dp_cox_grid_cross_contract_validate(contract, policy, schema_manifest)
  spec <- contract$spec
  plan <- .dsvert_dp_cox_cross_source_plan(contract, source_contract_sha256)
  rows <- spec$padded_capacity
  count <- rows * length(spec$beta_grid)
  owners <- unlist(spec$participating_peers, use.names = FALSE)
  if (!is.list(owner_predictors) || !identical(names(owner_predictors), owners) ||
      !all(vapply(owner_predictors, function(value)
        is.raw(value) && length(value) == 16 * count, logical(1L))) ||
      !is.raw(live_event) || length(live_event) != 32 * rows ||
      !is.raw(predictor_validity) || length(predictor_validity) != count ||
      !is.raw(live_event_validity) || length(live_event_validity) != 2 * rows ||
      any(as.integer(c(predictor_validity, live_event_validity)) > 1L)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  # Sum each authority's authenticated owner contributions in Ring128. Byte
  # arithmetic is exact; never decode f100 words into binary64 or shift shares.
  predictors <- raw(16 * count)
  for (contribution in owner_predictors) {
    carry <- integer(count)
    for (byte in seq_len(16L)) {
      index <- seq.int(byte, length(predictors), by = 16L)
      total <- as.integer(predictors[index]) + as.integer(contribution[index]) + carry
      predictors[index] <- as.raw(total %% 256L)
      carry <- total %/% 256L
    }
  }
  encode <- function(value) gsub("[\r\n]", "", jsonlite::base64_enc(value))
  list(plan = plan,
    predictors = list(Share = encode(predictors), Validity = encode(predictor_validity)),
    live_event = list(Share = encode(live_event), Validity = encode(live_event_validity)))
}

# Private owner-local ordering in original PSI slots. Invalid times and padding
# are terminal, with stable slot order. No times or sort controls are published.
.dsvert_dp_cox_cross_private_routing <- function(times, time_valid, padded_rows) {
  if (!is.numeric(times) || !is.logical(time_valid) || length(times) < 2L ||
      length(times) != length(time_valid) || anyNA(time_valid) ||
      any(!is.finite(times[time_valid])) || length(padded_rows) != 1L ||
      !is.numeric(padded_rows) || !is.finite(padded_rows) ||
      padded_rows != 2^ceiling(log2(length(times)))) .dsvert_dp_cox_grid_cross_fail()
  times[times == 0 & !is.na(times)] <- 0
  times[!time_valid] <- 0
  times <- c(times, rep(0, padded_rows - length(times)))
  valid <- c(time_valid, rep(FALSE, padded_rows - length(time_valid)))
  permutation <- order(!valid, -times, seq_along(times), method = "radix")
  sorted <- times[permutation]
  sorted_valid <- valid[permutation]
  ends <- c(sorted[-length(sorted)] != sorted[-1L] |
    sorted_valid[-length(sorted_valid)] != sorted_valid[-1L], TRUE)
  list(permutation = as.list(as.integer(permutation - 1L)), ends = as.list(ends))
}
