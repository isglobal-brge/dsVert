# Fixed-shape Ring128 source materializer for the sealed formal Cox capsule.
#
# Every custodian emits the same public lane shape to exactly two compute
# peers selected from the full pinned consortium.  A lane value v is encoded
# modulo 2^128 and split as (r, v-r), where r is derived from a source-local
# 256-bit root with a purpose-separated HMAC.  The two recipient bundles must
# eventually be transported separately through the authenticated typed source
# channel.  This internal object instead holds both plaintext-hex share lists;
# it is an executable, non-transportable fixture and is not a remotely
# registered method.

.DSVERT_FORMAL_COX_MATERIALIZER_VERSION <-
  "dsvert-formal-cox-ring128-materializer-v1"
.DSVERT_FORMAL_COX_MATERIALIZER_DOMAIN <-
  "dsVert/formal-cox/ring128-materializer/v1|"
.DSVERT_FORMAL_COX_SHARE_DOMAIN <-
  "dsVert/formal-cox/ring128-share-prf/v1|"
.DSVERT_FORMAL_COX_SNAPSHOT_BINDING_DOMAIN <-
  "dsVert/formal-cox/private-snapshot-binding/v1|"

.dsvert_formal_cox_raw_hex <- function(value) {
  paste(sprintf("%02x", as.integer(value)), collapse = "")
}

.dsvert_formal_cox_hex_raw <- function(value, what = "Ring128 value") {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{32}$", value)) {
    .dsvert_formal_cox_abort(paste0("Invalid ", what, "."))
  }
  starts <- seq.int(1L, 31L, by = 2L)
  as.raw(strtoi(substring(value, starts, starts + 1L), base = 16L))
}

.dsvert_formal_cox_raw_add <- function(left, right) {
  if (!is.raw(left) || !is.raw(right) || length(left) != 16L ||
      length(right) != 16L) {
    .dsvert_formal_cox_abort("Invalid Ring128 addition input.")
  }
  output <- raw(16L)
  carry <- 0L
  for (index in 16:1) {
    total <- as.integer(left[[index]]) + as.integer(right[[index]]) + carry
    output[[index]] <- as.raw(total %% 256L)
    carry <- total %/% 256L
  }
  output
}

.dsvert_formal_cox_raw_negate <- function(value) {
  inverted <- as.raw(bitwXor(as.integer(value), 255L))
  one <- raw(16L)
  one[[16L]] <- as.raw(1L)
  .dsvert_formal_cox_raw_add(inverted, one)
}

.dsvert_formal_cox_signed_raw <- function(value) {
  value <- .dsvert_formal_cox_integer(
    value, "Ring128 signed input", -(2^53 - 1), 2^53 - 1)
  magnitude <- abs(value)
  output <- raw(16L)
  for (index in 16:1) {
    output[[index]] <- as.raw(magnitude %% 256)
    magnitude <- floor(magnitude / 256)
  }
  if (value < 0) .dsvert_formal_cox_raw_negate(output) else output
}

.dsvert_formal_cox_raw_subtract <- function(left, right) {
  .dsvert_formal_cox_raw_add(left, .dsvert_formal_cox_raw_negate(right))
}

.dsvert_formal_cox_raw_signed <- function(value) {
  if (!is.raw(value) || length(value) != 16L) {
    .dsvert_formal_cox_abort("Invalid Ring128 decode input.")
  }
  negative <- bitwAnd(as.integer(value[[1L]]), 128L) != 0L
  magnitude <- if (negative) .dsvert_formal_cox_raw_negate(value) else value
  # This R reference only admits values that fit exactly in an R double.  The
  # production circuit uses 128-bit wires and has no such decoding boundary.
  if (any(as.integer(magnitude[seq_len(9L)]) != 0L)) {
    .dsvert_formal_cox_abort(
      "The reconstructed Ring128 fixture exceeds the exact R reference range.")
  }
  result <- 0
  for (byte in as.integer(magnitude[10:16])) result <- result * 256 + byte
  if (result > 2^53 - 1) {
    .dsvert_formal_cox_abort(
      "The reconstructed Ring128 fixture exceeds the exact R reference range.")
  }
  if (negative) -result else result
}

.dsvert_formal_cox_materializer_root <- function(root) {
  if (!is.raw(root) || length(root) < 32L) {
    .dsvert_formal_cox_abort(
      "The formal Cox source materializer root is unavailable.",
      "formal_cox_source_root_unavailable")
  }
  root
}

.dsvert_formal_cox_private_snapshot_binding <- function(value) {
  if (!is.raw(value) || length(value) != 32L) {
    .dsvert_formal_cox_abort(
      "The source-private Cox snapshot binding is unavailable.",
      "formal_cox_private_snapshot_binding_unavailable")
  }
  value
}

.dsvert_formal_cox_snapshot_bound_root <- function(root, binding) {
  root <- .dsvert_formal_cox_materializer_root(root)
  binding <- .dsvert_formal_cox_private_snapshot_binding(binding)
  digest::hmac(
    key = root,
    object = c(charToRaw(.DSVERT_FORMAL_COX_SNAPSHOT_BINDING_DOMAIN), binding),
    algo = "sha256", serialize = FALSE, raw = TRUE)
}

.dsvert_formal_cox_private_snapshot_mac <- function(
    root, binding, schema, source_name, recipient) {
  bound_root <- .dsvert_formal_cox_snapshot_bound_root(root, binding)
  payload <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(list(
      domain = .DSVERT_FORMAL_COX_SNAPSHOT_BINDING_DOMAIN,
      schema_sha256 = schema$schema_sha256,
      logical_snapshot_id = schema$unsigned$logical_snapshot_id,
      source_name = source_name, recipient = recipient)))
  .dsvert_formal_cox_raw_hex(digest::hmac(
    key = bound_root, object = charToRaw(payload), algo = "sha256",
    serialize = FALSE, raw = TRUE))
}

.dsvert_formal_cox_layout <- function(schema) {
  .dsvert_formal_cox_schema_validate(schema)
  peers <- names(schema$unsigned$peer_pinset)
  c(paste0("validity__", peers), "entry_index", "stop_index", "status",
    paste0("x__", names(schema$unsigned$covariate_owners)))
}

.dsvert_formal_cox_share_mask <- function(bound_root, schema, source_name,
                                           recipient, slot, field, value) {
  if (!is.raw(bound_root) || length(bound_root) != 32L) {
    .dsvert_formal_cox_abort("Invalid source-private Cox share root.")
  }
  if (!is.raw(value) || length(value) != 16L) {
    .dsvert_formal_cox_abort("Invalid source-private Cox lane value.")
  }
  payload <- .dsvert_dp_canonical_json(
    .dsvert_dp_canonical_query_value(list(
      domain = .DSVERT_FORMAL_COX_SHARE_DOMAIN,
      schema_sha256 = schema$schema_sha256,
      logical_snapshot_id = schema$unsigned$logical_snapshot_id,
      source_name = source_name, recipient = recipient,
      slot = as.numeric(slot), field = field,
      private_value_binding = .dsvert_formal_cox_raw_hex(value))))
  digest::hmac(
    key = bound_root, object = charToRaw(payload), algo = "sha256",
    serialize = FALSE, raw = TRUE)[seq_len(16L)]
}

.dsvert_formal_cox_source_block_values <- function(
    schema, source_name, rows, start, count) {
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  source_name <- .dsvert_formal_cox_label(source_name, "Cox source name")
  if (!source_name %in% names(schema$unsigned$peer_pinset)) {
    .dsvert_formal_cox_abort("The Cox source is outside the pinned consortium.")
  }
  start <- .dsvert_formal_cox_integer(
    start, "Cox source block start", 0, numeric$capacity - 1L)
  count <- .dsvert_formal_cox_integer(
    count, "Cox source block count", 1, numeric$capacity - start)
  owners <- unlist(schema$unsigned$covariate_owners, use.names = TRUE)
  outcome <- identical(source_name, schema$unsigned$outcome_owner)
  local_x <- names(owners)[owners == source_name]
  required <- c("valid", if (outcome) {
    c(if (schema$unsigned$entry_mode == "single_interval") "entry_tick",
      "stop_tick", "status")
  }, local_x)
  if (!is.data.frame(rows) || length(rows) != length(required) ||
      anyDuplicated(names(rows)) || !setequal(names(rows), required) ||
      nrow(rows) != numeric$capacity) {
    .dsvert_formal_cox_abort(
      "The local Cox source rows do not match their fixed public shape.")
  }
  rows <- rows[, required, drop = FALSE]
  if (!is.logical(rows$valid) || anyNA(rows$valid)) {
    .dsvert_formal_cox_abort("The local Cox validity lane is malformed.")
  }
  rows <- rows[seq.int(start + 1L, length.out = count), , drop = FALSE]
  valid <- rows$valid
  values <- matrix(0, nrow = count,
                   ncol = length(.dsvert_formal_cox_layout(schema)),
                   dimnames = list(NULL, .dsvert_formal_cox_layout(schema)))
  values[, paste0("validity__", source_name)] <- as.numeric(valid)
  if (outcome) {
    stop_value <- suppressWarnings(as.numeric(rows$stop_tick))
    status <- suppressWarnings(as.numeric(rows$status))
    stop_index <- match(stop_value, numeric$grid)
    response_valid <- is.finite(stop_value) & !is.na(stop_index) &
      is.finite(status) & status %in% c(0, 1)
    entry_index <- rep(0L, count)
    if (schema$unsigned$entry_mode == "single_interval") {
      entry_value <- suppressWarnings(as.numeric(rows$entry_tick))
      entry_index <- match(entry_value, numeric$grid)
      response_valid <- response_valid & is.finite(entry_value) &
        !is.na(entry_index) & entry_index < stop_index
    }
    valid <- valid & response_valid
    values[, "entry_index"] <- ifelse(valid, entry_index, 0)
    values[, "stop_index"] <- ifelse(valid, stop_index, 1)
    values[, "status"] <- ifelse(valid, status, 0)
  }
  if (length(local_x)) {
    x <- as.matrix(rows[, local_x, drop = FALSE])
    suppressWarnings(storage.mode(x) <- "double")
    local_valid <- apply(is.finite(x), 1L, all)
    for (column in local_x) {
      local_valid <- local_valid &
        x[, column] >= numeric$lower[[column]] &
        x[, column] <= numeric$upper[[column]]
    }
    valid <- valid & local_valid
    for (column in local_x) {
      values[, paste0("x__", column)] <- ifelse(
        valid, round(x[, column] * numeric$scale), 0)
    }
  }
  # Each source owns its own validity bit.  Exact GC ANDs every source bit and
  # also checks the global L2 norm, response domain, alignment consensus and
  # at-risk floor before a row can influence a score.
  values[, paste0("validity__", source_name)] <- as.numeric(valid)
  values
}

# The bridge to the recipient-encrypted Go producer consumes one local block
# at a time.  This helper deliberately returns only canonical local lattice
# lines: it neither derives masks nor materialises either recipient share.
.dsvert_formal_cox_source_block_decimal_lines <- function(
    schema, source_name, rows, block_index, block_capacity) {
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  block_capacity <- .dsvert_formal_cox_integer(
    block_capacity, "Cox physical block capacity", 1, numeric$capacity)
  blocks <- ceiling(numeric$capacity / block_capacity)
  block_index <- .dsvert_formal_cox_integer(
    block_index, "Cox source block index", 0, blocks - 1L)
  start <- block_index * block_capacity
  count <- min(block_capacity, numeric$capacity - start)
  values <- .dsvert_formal_cox_source_block_values(
    schema, source_name, rows, start, count)
  lines <- as.vector(t(values))
  if (any(!is.finite(lines)) || any(lines != floor(lines)) ||
      any(abs(lines) > 2^53 - 1)) {
    .dsvert_formal_cox_abort(
      "The local Cox source block exceeds the exact decimal transport range.")
  }
  lines[lines == 0] <- 0
  unname(sprintf("%.0f", lines))
}

.dsvert_formal_cox_source_rows <- function(schema, source_name, rows) {
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  .dsvert_formal_cox_source_block_values(
    schema, source_name, rows, start = 0, count = numeric$capacity)
}

.dsvert_formal_cox_bundle_mac <- function(root, unsigned) {
  .dsvert_formal_cox_raw_hex(digest::hmac(
    key = .dsvert_formal_cox_materializer_root(root),
    object = charToRaw(paste0(
      .DSVERT_FORMAL_COX_MATERIALIZER_DOMAIN,
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(unsigned)))),
    algo = "sha256", serialize = FALSE, raw = TRUE))
}

.dsvert_formal_cox_materialize_source <- function(
    schema, source_name, rows, source_root, private_snapshot_binding) {
  .dsvert_formal_cox_schema_validate(schema)
  source_root <- .dsvert_formal_cox_materializer_root(source_root)
  private_snapshot_binding <- .dsvert_formal_cox_private_snapshot_binding(
    private_snapshot_binding)
  source_name <- .dsvert_formal_cox_label(source_name, "Cox source name")
  if (!source_name %in% names(schema$unsigned$peer_pinset)) {
    .dsvert_formal_cox_abort("The Cox source is outside the pinned consortium.")
  }
  plan <- .dsvert_formal_cox_sensitivity_plan(schema)
  if (!identical(plan$input_materialization_backend, "exact_ring128")) {
    .dsvert_formal_cox_abort(
      "This Cox source cannot be represented by the Ring128 input backend.",
      "formal_cox_ring128_insufficient")
  }
  values <- .dsvert_formal_cox_source_rows(schema, source_name, rows)
  layout <- colnames(values)
  recipients <- unlist(schema$unsigned$compute_peers, use.names = FALSE)
  bound_root <- .dsvert_formal_cox_snapshot_bound_root(
    source_root, private_snapshot_binding)
  share_values <- stats::setNames(vector("list", 2L), recipients)
  first_share <- second_share <- character(length(values))
  cursor <- 1L
  for (slot in seq_len(nrow(values))) {
    for (field in layout) {
      value <- .dsvert_formal_cox_signed_raw(values[slot, field])
      mask <- .dsvert_formal_cox_share_mask(
        bound_root, schema, source_name, recipients[[1L]], slot, field,
        value)
      first_share[[cursor]] <- .dsvert_formal_cox_raw_hex(mask)
      second_share[[cursor]] <- .dsvert_formal_cox_raw_hex(
        .dsvert_formal_cox_raw_subtract(value, mask))
      cursor <- cursor + 1L
    }
  }
  share_values[[recipients[[1L]]]] <- as.list(first_share)
  share_values[[recipients[[2L]]]] <- as.list(second_share)
  unsigned <- list(
    version = .DSVERT_FORMAL_COX_MATERIALIZER_VERSION,
    schema_sha256 = schema$schema_sha256,
    logical_snapshot_id = schema$unsigned$logical_snapshot_id,
    source_name = source_name,
    source_identity_pk = schema$unsigned$peer_pinset[[source_name]],
    peer_pinset_sha256 = schema$unsigned$peer_pinset_sha256,
    compute_peers = as.list(recipients),
    capacity = schema$unsigned$capacity,
    ring_bits = "128", frac_bits = schema$unsigned$frac_bits,
    layout = as.list(layout),
    coordinate_count = sprintf("%.0f", length(values)),
    recipient_shares = share_values,
    recipient_private_snapshot_binding_macs = stats::setNames(
      lapply(recipients, function(recipient) {
        .dsvert_formal_cox_private_snapshot_mac(
          source_root, private_snapshot_binding, schema, source_name,
          recipient)
      }), recipients),
    transcript_shape = "fixed_by_signed_schema_only_v1",
    alignment_gate = schema$unsigned$alignment,
    fixture_transport = "test_fixture_plaintext_not_transportable_v1",
    recipient_shares_sealed = FALSE,
    opening = "none_test_fixture_plaintext_both_recipient_shares_v1",
    registered_remote_method = FALSE,
    production_ready = FALSE,
    blocker = .DSVERT_FORMAL_COX_BLOCKER)
  unsigned <- .dsvert_dp_canonical_query_value(unsigned)
  c(unsigned, list(local_seal_mac =
    .dsvert_formal_cox_bundle_mac(source_root, unsigned)))
}

.dsvert_formal_cox_materialization_validate <- function(
    bundle, schema, source_root, private_snapshot_binding) {
  .dsvert_formal_cox_schema_validate(schema)
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  expected_layout <- .dsvert_formal_cox_layout(schema)
  expected_coordinates <- length(expected_layout) * numeric$capacity
  required <- c(
    "version", "schema_sha256", "logical_snapshot_id", "source_name",
    "source_identity_pk", "peer_pinset_sha256", "compute_peers",
    "capacity", "ring_bits", "frac_bits", "layout", "coordinate_count",
    "recipient_shares", "recipient_private_snapshot_binding_macs",
    "transcript_shape", "alignment_gate", "fixture_transport",
    "recipient_shares_sealed", "opening",
    "registered_remote_method", "production_ready", "blocker",
    "local_seal_mac")
  source_name_valid <- tryCatch({
    identical(.dsvert_formal_cox_label(
      bundle$source_name, "Cox source name"), bundle$source_name) &&
      bundle$source_name %in% names(schema$unsigned$peer_pinset)
  }, error = function(error) FALSE)
  if (!is.list(bundle) || length(bundle) != length(required) ||
      anyDuplicated(names(bundle)) || !setequal(names(bundle), required) ||
      !identical(bundle$version, .DSVERT_FORMAL_COX_MATERIALIZER_VERSION) ||
      !identical(bundle$schema_sha256, schema$schema_sha256) ||
      !identical(bundle$logical_snapshot_id,
        schema$unsigned$logical_snapshot_id) ||
      !source_name_valid ||
      !identical(bundle$source_identity_pk,
        schema$unsigned$peer_pinset[[bundle$source_name]]) ||
      !identical(bundle$peer_pinset_sha256,
        schema$unsigned$peer_pinset_sha256) ||
      !identical(unlist(bundle$compute_peers, use.names = FALSE),
        unlist(schema$unsigned$compute_peers, use.names = FALSE)) ||
      !identical(unlist(bundle$layout, use.names = FALSE),
        expected_layout) ||
      !identical(bundle$capacity, schema$unsigned$capacity) ||
      !identical(bundle$coordinate_count,
        sprintf("%.0f", expected_coordinates)) ||
      !identical(bundle$ring_bits, "128") ||
      !identical(bundle$frac_bits, schema$unsigned$frac_bits) ||
      !identical(bundle$transcript_shape,
        "fixed_by_signed_schema_only_v1") ||
      !identical(bundle$alignment_gate, schema$unsigned$alignment) ||
      !identical(bundle$fixture_transport,
        "test_fixture_plaintext_not_transportable_v1") ||
      !identical(bundle$recipient_shares_sealed, FALSE) ||
      !identical(bundle$opening,
        "none_test_fixture_plaintext_both_recipient_shares_v1") ||
      !identical(bundle$registered_remote_method, FALSE) ||
      !identical(bundle$production_ready, FALSE) ||
      !identical(bundle$blocker, .DSVERT_FORMAL_COX_BLOCKER)) {
    .dsvert_formal_cox_abort(
      "The formal Cox source materialization has the wrong binding.",
      "tampered_formal_cox_materialization")
  }
  recipients <- unlist(schema$unsigned$compute_peers, use.names = FALSE)
  expected_snapshot_macs <- stats::setNames(
    lapply(recipients, function(recipient) {
      .dsvert_formal_cox_private_snapshot_mac(
        source_root, private_snapshot_binding, schema, bundle$source_name,
        recipient)
    }), recipients)
  observed_snapshot_macs <- bundle$recipient_private_snapshot_binding_macs
  if (!is.list(observed_snapshot_macs) ||
      !setequal(names(observed_snapshot_macs), recipients) ||
      !identical(observed_snapshot_macs[sort(names(observed_snapshot_macs))],
                 expected_snapshot_macs[sort(names(expected_snapshot_macs))])) {
    .dsvert_formal_cox_abort(
      "The formal Cox source materialization targets another private snapshot.",
      "replayed_formal_cox_private_snapshot")
  }
  unsigned <- bundle[setdiff(names(bundle), "local_seal_mac")]
  if (!identical(bundle$local_seal_mac,
                 .dsvert_formal_cox_bundle_mac(source_root, unsigned))) {
    .dsvert_formal_cox_abort(
      "The formal Cox source materialization failed authentication.",
      "tampered_formal_cox_materialization")
  }
  shares <- bundle$recipient_shares
  if (!is.list(shares) || !setequal(names(shares),
      unlist(schema$unsigned$compute_peers, use.names = FALSE)) ||
      !all(vapply(shares, function(value) {
        is.list(value) && length(value) == expected_coordinates &&
          all(vapply(value, function(item) {
            is.character(item) && length(item) == 1L && !is.na(item) &&
              grepl("^[0-9a-f]{32}$", item)
          }, logical(1L)))
      }, logical(1L)))) {
    .dsvert_formal_cox_abort(
      "The formal Cox source share shape is invalid.",
      "tampered_formal_cox_materialization")
  }
  invisible(bundle)
}

.dsvert_formal_cox_reconstruct_fixture <- function(
    schema, bundles, source_roots, private_snapshot_bindings) {
  .dsvert_formal_cox_schema_validate(schema)
  peers <- names(schema$unsigned$peer_pinset)
  if (!is.list(bundles) || !is.list(source_roots) ||
      !is.list(private_snapshot_bindings) ||
      !setequal(names(bundles), peers) ||
      !setequal(names(source_roots), peers) ||
      !setequal(names(private_snapshot_bindings), peers)) {
    .dsvert_formal_cox_abort("The Cox vertical fixture is incomplete.")
  }
  invisible(lapply(peers, function(peer) {
    .dsvert_formal_cox_materialization_validate(
      bundles[[peer]], schema, source_roots[[peer]],
      private_snapshot_bindings[[peer]])
  }))
  layout <- .dsvert_formal_cox_layout(schema)
  numeric <- .dsvert_formal_cox_schema_numeric(schema)
  recipients <- unlist(schema$unsigned$compute_peers, use.names = FALSE)
  result <- matrix(0, nrow = numeric$capacity, ncol = length(layout),
                   dimnames = list(NULL, layout))
  cursor <- 1L
  for (slot in seq_len(numeric$capacity)) {
    for (field in layout) {
      role_sum <- list(raw(16L), raw(16L))
      for (peer in peers) {
        for (role in seq_along(recipients)) {
          share <- .dsvert_formal_cox_hex_raw(
            bundles[[peer]]$recipient_shares[[recipients[[role]]]][[cursor]],
            "Cox fixture share")
          role_sum[[role]] <- .dsvert_formal_cox_raw_add(
            role_sum[[role]], share)
        }
      }
      result[slot, field] <- .dsvert_formal_cox_raw_signed(
        .dsvert_formal_cox_raw_add(role_sum[[1L]], role_sum[[2L]]))
      cursor <- cursor + 1L
    }
  }
  validity <- result[, paste0("validity__", peers), drop = FALSE]
  rows <- data.frame(
    valid = rowSums(validity == 1) == length(peers),
    entry_index = result[, "entry_index"],
    stop_index = result[, "stop_index"],
    status = result[, "status"], check.names = FALSE)
  for (column in names(schema$unsigned$covariate_owners)) {
    rows[[column]] <- result[, paste0("x__", column)] / numeric$scale
  }
  .dsvert_formal_cox_rows_validate(schema, rows)
}
