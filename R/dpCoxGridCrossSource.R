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
    predictors <- .dsvert_dp_capsule_source_add_ring128(predictors, contribution)
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

# Multiply Ring128 shares by a public signed f50 coefficient. Base-256 schoolbook
# arithmetic keeps every intermediate below 2^24, including on random shares.
.dsvert_dp_cox_cross_multiply_public <- function(shares, coefficient) {
  if (!is.raw(shares) || !length(shares) || length(shares) %% 16L != 0L ||
      !is.numeric(coefficient) || length(coefficient) != 1L || is.na(coefficient) ||
      !is.finite(coefficient) || coefficient != round(coefficient) ||
      abs(coefficient) > 2^52) .dsvert_dp_cox_grid_cross_fail()
  count <- length(shares) / 16L
  input <- matrix(as.integer(shares), nrow = 16L)
  result <- matrix(0, nrow = 16L, ncol = count)
  magnitude <- abs(coefficient)
  for (offset in 0:6) {
    digit <- magnitude %% 256
    magnitude <- floor(magnitude / 256)
    carry <- numeric(count)
    for (limb in seq_len(16L - offset)) {
      index <- limb + offset
      total <- result[index, ] + input[limb, ] * digit + carry
      result[index, ] <- total %% 256
      carry <- floor(total / 256)
    }
  }
  result <- as.raw(result)
  if (coefficient < 0) {
    result <- as.raw(bitwXor(as.integer(result), 255L))
    one <- raw(length(result)); one[seq.int(1L, length(one), by = 16L)] <- as.raw(1L)
    result <- .dsvert_dp_capsule_source_add_ring128(result, one)
  }
  result
}

# The source loader supplies one authority's authenticated f50 shares, grouped
# by signed owner. No private value is reconstructed while forming complete dots.
.dsvert_dp_cox_cross_owner_predictors <- function(contract, policy, schema_manifest,
                                                owner, values) {
  contract <- .dsvert_dp_cox_grid_cross_contract_validate(contract, policy, schema_manifest)
  spec <- contract$spec
  if (!is.character(owner) || length(owner) != 1L || is.na(owner) ||
      !owner %in% unlist(spec$participating_peers, use.names = FALSE)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  predictors <- unlist(spec$predictor_order, use.names = FALSE)
  owned <- predictors[vapply(spec$predictors[predictors], function(descriptor)
    identical(descriptor$owner_peer, owner), logical(1L))]
  rows <- spec$padded_capacity
  if (!is.list(values) || !identical(names(values), if (length(owned)) owned else NULL) ||
      !all(vapply(values, function(value) is.raw(value) && length(value) == 16 * rows,
        logical(1L)))) .dsvert_dp_cox_grid_cross_fail()
  candidates <- length(spec$beta_encoded)
  dots <- lapply(seq_len(candidates), function(candidate) {
    result <- raw(16 * rows)
    for (variable in owned) {
      text <- spec$beta_encoded[[candidate]][[match(variable, predictors)]]
      coefficient <- as.numeric(text)
      if (!identical(sprintf("%.0f", coefficient), text)) .dsvert_dp_cox_grid_cross_fail()
      result <- .dsvert_dp_capsule_source_add_ring128(result,
        .dsvert_dp_cox_cross_multiply_public(values[[variable]], coefficient))
    }
    result
  })
  # The native packed runner consumes row-major candidate lanes.
  index <- unlist(lapply(seq_len(rows), function(row) {
    unlist(lapply(seq_len(candidates), function(candidate) {
      (candidate - 1L) * 16 * rows + (row - 1L) * 16 + seq_len(16L)
    }), use.names = FALSE)
  }), use.names = FALSE)
  do.call(c, dots)[index]
}

# Fixed-shape source suffix. Observed times stay at their owner; only their
# validity lanes join the private complete-case conjunction. Event values are
# q0 and normalized predictors q50, including when source and compute owners differ.
.dsvert_dp_cox_cross_source_blocks <- function(artifact, cursor) {
  spec <- .dsvert_dp_glm_grid_cross_embedded_contract(artifact)$spec
  if (!identical(spec$family, "cox")) .dsvert_dp_cox_grid_cross_fail()
  blocks <- list()
  descriptors <- c(spec$predictors, setNames(list(spec$event, spec$time),
    c(spec$event$reference, spec$time$reference)))
  for (reference in names(descriptors)) {
    descriptor <- descriptors[[reference]]
    time <- identical(reference, spec$time$reference)
    event <- identical(reference, spec$event$reference)
    for (kind in if (time) "validity" else c("value", "validity")) {
      size <- spec$padded_capacity
      end <- cursor + size - 1
      if (!is.numeric(cursor) || length(cursor) != 1L || !is.finite(cursor) ||
          cursor < 1 || cursor != round(cursor) ||
          end > .DSVERT_DP_GAUSSIAN_CROSS_MAX_TRANSPORT_COORDINATES) {
        .dsvert_dp_cox_grid_cross_fail()
      }
      key <- paste(artifact$analysis_id, reference, kind, sep = "::")
      blocks[[key]] <- list(input_family = "cox_grid", analysis_id = artifact$analysis_id,
        reference = reference, variable = descriptor$column, dataset = descriptor$dataset,
        owner_peer = descriptor$owner_peer, kind = kind, outcome = event,
        private_time_validity = time, lower = descriptor$lower, upper = descriptor$upper,
        start = as.integer(cursor), end = as.integer(end), length = as.integer(size),
        fraction_bits = if (kind == "validity" || event) 0L else 50L,
        maximum = if (kind == "validity" || event) 1 else 2^50)
      cursor <- end + 1
    }
  }
  list(blocks = blocks, cursor = cursor)
}

# Private typed CLI boundary after source receipt/alignment verification. The
# opaque payload contains shares and key material and must never enter a receipt.
.dsvert_dp_cox_cross_prepare_native <- function(handoff, role, session, authorities,
    semantic_key, store_directory, store_key, routing = NULL, routing_digest = "") {
  if (!is.raw(store_key) || length(store_key) != 32L ||
      !is.character(store_directory) || length(store_directory) != 1L ||
      is.na(store_directory) || !dir.exists(store_directory) ||
      .dsvert_dp_path_is_link(store_directory) ||
      !.dsvert_dp_private_mode(store_directory, directory = TRUE)) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  result <- .callMpcTool("cox-loss-staged-prepare-v1", list(
    handoff = handoff, role = role, session = session, authorities = as.list(authorities),
    semantic_key = semantic_key, store_directory = normalizePath(store_directory),
    store_key = gsub("[\r\n]", "", jsonlite::base64_enc(store_key)),
    routing = routing, routing_digest = routing_digest), simplify_output = FALSE)
  .dsvert_dp_glm_grid_cross_fields(result,
    c("stage_plan_digest", "worker_input", "purpose", "vector_len", "routing_digest"))
  digest <- function(value) is.character(value) && length(value) == 1L && !is.na(value) &&
    grepl("^[0-9a-f]{64}$", value) && !identical(value, strrep("0", 64))
  if (!digest(result$stage_plan_digest) || !digest(result$routing_digest) ||
      !is.character(result$purpose) || length(result$purpose) != 1L ||
      is.na(result$purpose) || !grepl("^cox-loss-staged-v1/[0-9a-f]{64}$", result$purpose) ||
      !is.character(result$worker_input) || length(result$worker_input) != 1L ||
      is.na(result$worker_input) || !nzchar(result$worker_input) ||
      nchar(result$worker_input, type = "bytes") > 64 * 1024^2 ||
      !identical(as.numeric(result$vector_len), as.numeric(length(handoff$plan$caps))) ||
      (nzchar(routing_digest) && !identical(result$routing_digest, routing_digest))) {
    .dsvert_dp_cox_grid_cross_fail()
  }
  list(operation = "cox-loss-staged-v1", purpose = result$purpose,
    vector_len = result$vector_len, stage_plan_digest = result$stage_plan_digest,
    routing_digest = result$routing_digest, cox_loss = result$worker_input)
}
