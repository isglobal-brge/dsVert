# Fixed-capacity, pinned-peer PSI building blocks.
#
# This is the purpose-bound implementation behind the sole public PSI route.
# Its registered surface is intentionally limited to the fixed protocol phases.

.DSVERT_PSI_PADDED_PROTOCOL <- "dsvert-pinned-padded-psi-v4"
.DSVERT_PSI_PADDED_MIN_CAPACITY <- 64L
.DSVERT_PSI_PADDED_MAX_CAPACITY <- 1048576L
.DSVERT_PSI_PADDED_SELECTION_MAGIC <- charToRaw("DVPSEL04")
.DSVERT_PSI_PADDED_AND_PRODUCER <- "psi.padded.membership-sum.v4"
.DSVERT_PSI_PADDED_AND_PURPOSE <- "psi-padded-and-v4"
.PSI_PADDED_ATTESTATION_ATTRIBUTE <- "dsvert.psi.padded.attestation"
.PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE <- "dsvert.psi.padded.factor-registry"
.DSVERT_PSI_PADDED_FACTOR_REGISTRY_VERSION <-
  "dsvert-psi-padded-factor-registry-v1"
.DSVERT_PSI_PADDED_FACTOR_ENTRY_VERSION <-
  "dsvert-psi-padded-factor-entry-v1"
.DSVERT_PSI_PADDED_FACTOR_VARIABLE_DOMAIN <-
  "dsVert/psi-padded/factor-variable/v1|"
.DSVERT_PSI_PADDED_FACTOR_ENTRY_DOMAIN <-
  "dsVert/psi-padded/factor-entry/v1|"
.DSVERT_PSI_PADDED_FACTOR_REGISTRY_DOMAIN <-
  "dsVert/psi-padded/factor-registry/v1|"
.DSVERT_PSI_PADDED_FACTOR_REGISTRY_SIGNATURE_DOMAIN <-
  "dsVert/psi-padded/factor-registry-signature/v1|"
.DSVERT_PSI_PADDED_FACTOR_MAX_COLUMNS <- 4096L
.DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS <- 1000000L
.DSVERT_PSI_PADDED_FACTOR_MAX_METADATA_BYTES <- 16L * 1024L * 1024L

.psi_padded_scalar <- function(value, what, pattern = NULL) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > 512L ||
      (!is.null(pattern) && !grepl(pattern, value, perl = TRUE))) {
    stop("Invalid padded PSI ", what, ".", call. = FALSE)
  }
  value
}

.psi_padded_integer <- function(value, what, lower = 0,
                                upper = .Machine$integer.max) {
  value <- suppressWarnings(as.numeric(value))
  if (length(value) != 1L || is.na(value) || !is.finite(value) ||
      value != floor(value) || value < lower || value > upper) {
    stop("Invalid padded PSI ", what, ".", call. = FALSE)
  }
  as.integer(value)
}

.psi_padded_data_name <- function(value) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[a-zA-Z._][a-zA-Z0-9._]*$", value)) {
    stop("Invalid padded PSI data name.", call. = FALSE)
  }
  value
}

.psi_padded_authorize_source <- function(data_name, id_col, data) {
  data_name <- .psi_padded_data_name(data_name)
  if (!is.data.frame(data) || !is.character(id_col) ||
      length(id_col) != 1L || is.na(id_col) || !nzchar(id_col) ||
      !id_col %in% names(data)) {
    stop("Invalid padded PSI identifier column.", call. = FALSE)
  }
  sources <- getOption(
    "dsvert.psi.authorized_sources",
    getOption("default.dsvert.psi.authorized_sources"))
  if (is.null(sources)) {
    datasets <- getOption(
      "dsvert.dp.datasets", getOption("default.dsvert.dp.datasets"))
    patient_column <- getOption(
      "dsvert.dp.patient_column",
      getOption("default.dsvert.dp.patient_column"))
    candidate <- if (is.list(datasets)) datasets[[data_name]] else NULL
    if (is.list(candidate) &&
        all(c("id", "version", "snapshot_sha256") %in% names(candidate)) &&
        is.character(patient_column) && length(patient_column) == 1L &&
        !is.na(patient_column)) {
      sources <- stats::setNames(list(list(
        id = candidate$id,
        version = candidate$version,
        id_col = patient_column,
        purpose = "patient-record-alignment-v1",
        snapshot_sha256 = candidate$snapshot_sha256)), data_name)
    }
  }
  if (!is.list(sources) || !length(sources) || is.null(names(sources)) ||
      anyNA(names(sources)) || any(!nzchar(names(sources))) ||
      anyDuplicated(names(sources))) {
    stop(paste0(
      "The custodian-owned padded PSI source policy is unavailable; configure ",
      "dsvert.psi.authorized_sources or a matching dsvert.dp.datasets entry."),
      call. = FALSE)
  }
  descriptor <- sources[[data_name]]
  required <- c("id", "version", "id_col", "purpose", "snapshot_sha256")
  if (!is.list(descriptor) || length(descriptor) != length(required) ||
      !setequal(names(descriptor), required)) {
    stop("The requested padded PSI source is not custodian-authorized.",
         call. = FALSE)
  }
  label <- function(value, what) {
    .psi_padded_scalar(
      value, what, "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
  }
  configured_id_col <- .psi_padded_scalar(
    descriptor$id_col, "authorized identifier column",
    "^[A-Za-z._][A-Za-z0-9._]{0,127}$")
  if (!identical(id_col, configured_id_col)) {
    stop("The requested padded PSI identifier column is not custodian-authorized.",
         call. = FALSE)
  }
  configured_snapshot <- tolower(.psi_padded_scalar(
    descriptor$snapshot_sha256, "authorized snapshot digest",
    "^[0-9a-fA-F]{64}$"))
  actual_snapshot <- .dsvert_dp_snapshot_digest(data)
  if (!identical(actual_snapshot, configured_snapshot)) {
    stop("The requested padded PSI object does not match its custodian-approved snapshot.",
         call. = FALSE)
  }
  public <- list(
    alignment_purpose = label(descriptor$purpose, "alignment purpose"),
    dataset_id = label(descriptor$id, "dataset id"),
    dataset_version = label(descriptor$version, "dataset version"),
    id_column = configured_id_col)
  public$source_binding_id <- paste0("source_", digest::digest(
    .psi_padded_canonical_json(public), algo = "sha256", serialize = FALSE))
  list(
    public = .psi_padded_validate_source_public(public),
    snapshot_sha256 = actual_snapshot)
}

.psi_padded_validate_source_public <- function(value) {
  required <- c(
    "alignment_purpose", "dataset_id", "dataset_version", "id_column",
    "source_binding_id")
  fail <- function() stop("Invalid padded PSI source authorization.",
                          call. = FALSE)
  if (!is.list(value) || !identical(names(value), required)) fail()
  tryCatch({
    .psi_padded_scalar(
      value$alignment_purpose, "alignment purpose",
      "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    .psi_padded_scalar(
      value$dataset_id, "dataset id",
      "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    .psi_padded_scalar(
      value$dataset_version, "dataset version",
      "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    .psi_padded_scalar(
      value$id_column, "identifier column",
      "^[A-Za-z._][A-Za-z0-9._]{0,127}$")
    .psi_padded_scalar(
      value$source_binding_id, "source binding id",
      "^source_[0-9a-f]{64}$")
  }, error = function(e) fail())
  unsigned <- value[setdiff(names(value), "source_binding_id")]
  expected <- paste0("source_", digest::digest(
    .psi_padded_canonical_json(unsigned), algo = "sha256", serialize = FALSE))
  if (!identical(value$source_binding_id, expected)) fail()
  value
}

.psi_padded_capacity_bucket <- function(
    n, max_capacity = .DSVERT_PSI_PADDED_MAX_CAPACITY) {
  n <- .psi_padded_integer(n, "input shape", 0, .Machine$integer.max)
  max_capacity <- .psi_padded_integer(
    max_capacity, "capacity policy", .DSVERT_PSI_PADDED_MIN_CAPACITY,
    .DSVERT_PSI_PADDED_MAX_CAPACITY)
  powers <- 2^(6:20)
  powers <- powers[powers <= max_capacity]
  selected <- powers[powers >= max(n, .DSVERT_PSI_PADDED_MIN_CAPACITY)]
  if (!length(selected)) {
    stop("The padded PSI input exceeds the server capacity policy.",
         call. = FALSE)
  }
  as.integer(selected[[1L]])
}

.psi_padded_validate_capacity <- function(value) {
  value <- .psi_padded_integer(
    value, "capacity", 1L, .DSVERT_PSI_PADDED_MAX_CAPACITY)
  if (value < .DSVERT_PSI_PADDED_MIN_CAPACITY ||
      bitwAnd(value, value - 1L) != 0L) {
    stop("Invalid padded PSI capacity bucket.", call. = FALSE)
  }
  value
}

.psi_padded_select_rows <- function(
    data, id_col, missing_policy = c("id_only", "complete_cases"),
    duplicate_policy = "first") {
  missing_policy <- match.arg(missing_policy)
  if (!is.data.frame(data) || !is.character(id_col) ||
      length(id_col) != 1L || is.na(id_col) || !id_col %in% names(data)) {
    stop("Invalid padded PSI data or identifier column.", call. = FALSE)
  }
  if (!identical(duplicate_policy, "first")) {
    stop("Unsupported padded PSI duplicate identifier policy.",
         call. = FALSE)
  }
  ids <- .dsvert_canonical_label_values(
    data[[id_col]], "padded PSI identifiers", allow_na = TRUE,
    allow_blank = TRUE)
  eligible <- !is.na(ids) & nzchar(ids)
  if (identical(missing_policy, "complete_cases")) {
    eligible <- eligible & stats::complete.cases(data)
  }
  rows <- which(eligible)
  if (length(rows)) {
    rows <- rows[!duplicated(ids[rows])]
  }
  list(rows = as.integer(rows), ids = ids[rows])
}

.psi_padded_real_label <- function(value) {
  value <- .psi_padded_scalar(value, "canonical identifier")
  paste0("R", nchar(value, type = "bytes"), ":", value)
}

.psi_padded_default_dummy <- function(peer_id, snapshot_id, slot,
                                      random_bytes) {
  entropy <- random_bytes(32L)
  if (!is.raw(entropy) || length(entropy) != 32L) {
    stop("Secure entropy returned an invalid padded PSI dummy.",
         call. = FALSE)
  }
  paste0(
    "D", nchar(peer_id, type = "bytes"), ":", peer_id, "|",
    nchar(snapshot_id, type = "bytes"), ":", snapshot_id, "|",
    sprintf("%08x", as.integer(slot)), "|",
    paste(sprintf("%02x", as.integer(entropy)), collapse = ""))
}

.psi_padded_random_stream <- function(random_bytes, block_bytes = 65536L) {
  if (!is.function(random_bytes)) {
    stop("Padded PSI requires a secure random-byte function.", call. = FALSE)
  }
  buffer <- raw(0L)
  offset <- 1L
  function(n) {
    n <- .psi_padded_integer(n, "random request", 1L, block_bytes)
    if (length(buffer) - offset + 1L < n) {
      buffer <<- random_bytes(max(block_bytes, n))
      offset <<- 1L
      if (!is.raw(buffer) || length(buffer) < n) {
        stop("Secure entropy returned an invalid padded PSI shuffle stream.",
             call. = FALSE)
      }
    }
    result <- buffer[seq.int(offset, length.out = n)]
    offset <<- offset + n
    result
  }
}

.psi_padded_secure_permutation <- function(
    n, random_bytes = .dsvert_secure_random_bytes) {
  n <- .psi_padded_integer(n, "shuffle size", 0L,
                           .DSVERT_PSI_PADDED_MAX_CAPACITY)
  if (n < 2L) return(seq_len(n))
  stream <- .psi_padded_random_stream(random_bytes)
  result <- seq_len(n)
  for (upper in seq.int(n, 2L)) {
    limit <- floor(2^32 / upper) * upper
    repeat {
      bytes <- as.integer(stream(4L))
      value <- bytes[[1L]] + 256 * bytes[[2L]] +
        65536 * bytes[[3L]] + 16777216 * bytes[[4L]]
      if (value < limit) break
    }
    selected <- as.integer(value %% upper) + 1L
    tmp <- result[[upper]]
    result[[upper]] <- result[[selected]]
    result[[selected]] <- tmp
  }
  result
}

.psi_padded_prepare_slots <- function(
    ids, rows, capacity, peer_id, snapshot_id,
    random_bytes = .dsvert_secure_random_bytes,
    dummy_factory = .psi_padded_default_dummy) {
  capacity <- .psi_padded_integer(
    capacity, "private slot capacity", 1L,
    .DSVERT_PSI_PADDED_MAX_CAPACITY)
  peer_id <- .psi_padded_scalar(
    peer_id, "peer id", "^(?:peer|dsv1)_[0-9a-f]{64}$")
  snapshot_id <- .psi_padded_scalar(
    snapshot_id, "snapshot id", "^snap_[0-9a-f]{64}$")
  if (!is.character(ids) || anyNA(ids) || any(!nzchar(ids)) ||
      !is.numeric(rows) || length(rows) != length(ids) || anyNA(rows) ||
      any(!is.finite(rows)) || any(rows != floor(rows)) || any(rows < 1) ||
      anyDuplicated(rows) || length(ids) > capacity || !is.function(dummy_factory)) {
    stop("Invalid padded PSI private input set.", call. = FALSE)
  }
  real <- vapply(ids, .psi_padded_real_label, character(1L), USE.NAMES = FALSE)
  if (anyDuplicated(real)) {
    stop("Padded PSI identifiers must be unique after local policy.",
         call. = FALSE)
  }
  dummy_n <- capacity - length(real)
  dummy <- if (dummy_n) vapply(seq_len(dummy_n), function(slot) {
    dummy_factory(peer_id, snapshot_id, slot, random_bytes)
  }, character(1L)) else character()
  labels <- c(real, dummy)
  if (length(labels) != capacity || anyNA(labels) || any(!nzchar(labels)) ||
      anyDuplicated(labels) || (dummy_n && any(dummy %in% real))) {
    stop("Padded PSI dummy domain collision detected before masking.",
         call. = FALSE)
  }
  slot_rows <- c(as.integer(rows), integer(dummy_n))
  slot_valid <- c(rep(TRUE, length(real)), rep(FALSE, dummy_n))
  permutation <- .psi_padded_secure_permutation(capacity, random_bytes)
  list(
    mask_ids = labels[permutation],
    slot_rows = slot_rows[permutation],
    slot_valid = slot_valid[permutation],
    permutation = as.integer(permutation))
}

.psi_padded_pack_bits <- function(bits) {
  if (!is.numeric(bits) && !is.logical(bits)) {
    stop("Invalid padded PSI bit vector.", call. = FALSE)
  }
  bits <- as.integer(bits)
  if (anyNA(bits) || any(!bits %in% 0:1)) {
    stop("Invalid padded PSI bit vector.", call. = FALSE)
  }
  result <- raw(ceiling(length(bits) / 8))
  ones <- which(bits == 1L)
  for (index in ones) {
    byte <- as.integer((index - 1L) %/% 8L) + 1L
    shift <- as.integer((index - 1L) %% 8L)
    result[[byte]] <- as.raw(bitwOr(as.integer(result[[byte]]),
                                    bitwShiftL(1L, shift)))
  }
  result
}

.psi_padded_unpack_bits <- function(value, n) {
  n <- .psi_padded_integer(n, "bit-vector length", 0L,
                           .DSVERT_PSI_PADDED_MAX_CAPACITY)
  if (!is.raw(value) || length(value) != ceiling(n / 8)) {
    stop("Invalid padded PSI packed bit vector.", call. = FALSE)
  }
  result <- integer(n)
  if (n) for (index in seq_len(n)) {
    byte <- as.integer((index - 1L) %/% 8L) + 1L
    shift <- as.integer((index - 1L) %% 8L)
    result[[index]] <- bitwAnd(
      bitwShiftR(as.integer(value[[byte]]), shift), 1L)
  }
  unused <- length(value) * 8L - n
  if (unused > 0L && length(value)) {
    allowed <- bitwShiftL(1L, 8L - unused) - 1L
    if (bitwAnd(as.integer(value[[length(value)]]),
                bitwXor(allowed, 255L)) != 0L) {
      stop("Non-canonical padded PSI packed bit vector.", call. = FALSE)
    }
  }
  result
}

.psi_padded_selection_plan <- function(bits, reference_valid,
                                       canonical_keys = NULL) {
  bits <- as.integer(bits)
  reference_valid <- as.logical(reference_valid)
  if (!length(bits) || length(reference_valid) != length(bits) ||
      anyNA(bits) || any(!bits %in% 0:1) || anyNA(reference_valid)) {
    stop("Invalid padded PSI selection inputs.", call. = FALSE)
  }
  capacity <- length(bits)
  selected <- which(bits == 1L & reference_valid)
  if (!is.null(canonical_keys)) {
    canonical_keys <- suppressWarnings(as.integer(canonical_keys))
    if (length(canonical_keys) != capacity || anyNA(canonical_keys) ||
        any(canonical_keys < 0L) ||
        (length(selected) &&
         (any(canonical_keys[selected] < 1L) ||
          anyDuplicated(canonical_keys[selected])))) {
      stop("Invalid padded PSI canonical reference order.", call. = FALSE)
    }
    if (length(selected)) {
      selected <- selected[order(canonical_keys[selected], method = "radix")]
    }
  }
  ranks <- rep.int(as.integer(capacity), capacity)
  if (length(selected)) ranks[selected] <- seq_along(selected) - 1L
  list(bits = as.integer(seq_len(capacity) %in% selected),
       ranks = as.integer(ranks))
}

.psi_padded_token_raw <- function(token) {
  .psi_validate_alignment_token(token)
  decoded <- jsonlite::base64_dec(.base64url_to_base64(token))
  attributes(decoded) <- NULL
  decoded
}

.psi_padded_pack_selection <- function(plan, capacity, token) {
  capacity <- .psi_padded_integer(capacity, "selection capacity", 1L,
                                   .DSVERT_PSI_PADDED_MAX_CAPACITY)
  if (!is.list(plan) || !identical(sort(names(plan)), c("bits", "ranks")) ||
      length(plan$bits) != capacity || length(plan$ranks) != capacity) {
    stop("Invalid padded PSI selection plan.", call. = FALSE)
  }
  bits <- as.integer(plan$bits)
  ranks <- as.integer(plan$ranks)
  if (anyNA(bits) || any(!bits %in% 0:1) || anyNA(ranks) ||
      any(ranks < 0L | ranks > capacity)) {
    stop("Invalid padded PSI selection plan.", call. = FALSE)
  }
  selected_ranks <- ranks[bits == 1L]
  if (!identical(sort(selected_ranks),
                 as.integer(seq_along(selected_ranks) - 1L)) ||
      any(ranks[bits == 0L] != capacity)) {
    stop("Non-canonical padded PSI selection permutation.", call. = FALSE)
  }
  c(
    .DSVERT_PSI_PADDED_SELECTION_MAGIC,
    writeBin(capacity, raw(), size = 4L, endian = "little"),
    .psi_padded_token_raw(token),
    .psi_padded_pack_bits(bits),
    writeBin(ranks, raw(), size = 4L, endian = "little"))
}

.psi_padded_unpack_selection <- function(value, capacity) {
  capacity <- .psi_padded_integer(capacity, "selection capacity", 1L,
                                   .DSVERT_PSI_PADDED_MAX_CAPACITY)
  bitmap_bytes <- ceiling(capacity / 8)
  expected <- 8L + 4L + 32L + bitmap_bytes + 4L * capacity
  if (!is.raw(value) || length(value) != expected ||
      !identical(value[seq_len(8L)], .DSVERT_PSI_PADDED_SELECTION_MAGIC)) {
    stop("Invalid padded PSI selection payload.", call. = FALSE)
  }
  encoded_capacity <- readBin(
    value[9:12], integer(), n = 1L, size = 4L, endian = "little")
  if (!identical(encoded_capacity, capacity)) {
    stop("Invalid padded PSI selection payload capacity.", call. = FALSE)
  }
  token_raw <- value[13:44]
  token <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(token_raw)))
  bitmap_start <- 45L
  bitmap_end <- bitmap_start + bitmap_bytes - 1L
  bits <- .psi_padded_unpack_bits(value[bitmap_start:bitmap_end], capacity)
  rank_raw <- value[seq.int(bitmap_end + 1L, length.out = 4L * capacity)]
  ranks <- readBin(rank_raw, integer(), n = capacity, size = 4L,
                   endian = "little")
  plan <- list(bits = bits, ranks = as.integer(ranks))
  invisible(.psi_padded_pack_selection(plan, capacity, token))
  c(plan, list(token = token))
}

.psi_padded_materialize_target <- function(
    data, id_col, slot_rows, slot_valid, target_slot_by_ref, plan, token) {
  fail <- function() stop(
    "The authenticated padded PSI result is inconsistent.", call. = FALSE)
  if (!is.data.frame(data) || !is.character(id_col) ||
      length(id_col) != 1L || is.na(id_col) || !id_col %in% names(data)) fail()
  capacity <- length(slot_rows)
  if (!capacity || length(slot_valid) != capacity ||
      length(target_slot_by_ref) != capacity ||
      !is.list(plan) || length(plan$bits) != capacity ||
      length(plan$ranks) != capacity) fail()
  slot_rows <- suppressWarnings(as.integer(slot_rows))
  slot_valid <- as.logical(slot_valid)
  target_slot_by_ref <- suppressWarnings(as.integer(target_slot_by_ref))
  bits <- suppressWarnings(as.integer(plan$bits))
  ranks <- suppressWarnings(as.integer(plan$ranks))
  if (anyNA(slot_rows) || any(slot_rows < 0L | slot_rows > nrow(data)) ||
      anyNA(slot_valid) || anyNA(target_slot_by_ref) ||
      any(target_slot_by_ref < 0L | target_slot_by_ref > capacity) ||
      anyNA(bits) || any(!bits %in% 0:1) || anyNA(ranks)) fail()
  selected_ref <- which(bits == 1L)
  if (length(selected_ref)) {
    selected_ref <- selected_ref[order(ranks[selected_ref], method = "radix")]
    expected_ranks <- seq_along(selected_ref) - 1L
    if (!identical(ranks[selected_ref], as.integer(expected_ranks))) fail()
    target_slots <- target_slot_by_ref[selected_ref] + 1L
    if (any(target_slots < 1L | target_slots > capacity) ||
        any(!slot_valid[target_slots]) || any(slot_rows[target_slots] < 1L) ||
        anyDuplicated(target_slots)) fail()
    rows <- slot_rows[target_slots]
  } else {
    rows <- integer()
  }
  result <- data[rows, , drop = FALSE]
  rownames(result) <- NULL
  tryCatch(.psi_attach_alignment_manifest(result, id_col, token),
           error = function(e) fail())
}

.psi_padded_ring63_validate_bits <- function(bits) {
  bits <- as.integer(bits)
  if (!length(bits) || anyNA(bits) || any(!bits %in% 0:1) ||
      length(bits) > 4096L) {
    stop("Invalid padded PSI Ring63 bit vector.", call. = FALSE)
  }
  bits
}

.psi_padded_ring63_raw <- function(value, what = "Ring63 share") {
  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    stop("Invalid padded PSI ", what, ".", call. = FALSE)
  }
  decoded <- tryCatch(jsonlite::base64_dec(value), error = function(e) NULL)
  if (is.null(decoded) || !is.raw(decoded) || !length(decoded) ||
      length(decoded) %% 8L != 0L) {
    stop("Invalid padded PSI ", what, ".", call. = FALSE)
  }
  top <- seq.int(8L, length(decoded), by = 8L)
  high <- as.integer(decoded[top])
  # Ring63's worker boundary uses canonical signed int64: residues below 2^62
  # are non-negative (00..3f high byte); residues at or above 2^62 are encoded
  # as their negative representative (c0..ff high byte).  40..bf is rejected.
  if (any(high %in% 64:191) ||
      !identical(gsub("[\r\n]", "", jsonlite::base64_enc(decoded)), value)) {
    stop("Non-canonical padded PSI ", what, ".", call. = FALSE)
  }
  negative <- high >= 192L
  if (any(negative)) {
    decoded[top[negative]] <- as.raw(high[negative] - 128L)
  }
  decoded
}

.psi_padded_ring63_b64 <- function(value) {
  if (!is.raw(value) || !length(value) || length(value) %% 8L != 0L) {
    stop("Invalid padded PSI Ring63 records.", call. = FALSE)
  }
  top <- seq.int(8L, length(value), by = 8L)
  if (any(bitwAnd(as.integer(value[top]), 128L) != 0L)) {
    stop("Non-canonical padded PSI Ring63 records.", call. = FALSE)
  }
  wire <- value
  high <- as.integer(wire[top])
  negative <- bitwAnd(high, 64L) != 0L
  if (any(negative)) wire[top[negative]] <- as.raw(high[negative] + 128L)
  gsub("[\r\n]", "", jsonlite::base64_enc(wire))
}

.psi_padded_ring63_add_raw <- function(left, right) {
  if (!is.raw(left) || !is.raw(right) || !length(left) ||
      length(left) != length(right) || length(left) %% 8L != 0L) {
    stop("Invalid padded PSI Ring63 addition.", call. = FALSE)
  }
  result <- raw(length(left))
  for (record in seq_len(length(left) %/% 8L)) {
    carry <- 0L
    first <- (record - 1L) * 8L + 1L
    for (offset in 0:7) {
      base <- if (offset == 7L) 128L else 256L
      total <- as.integer(left[[first + offset]]) +
        as.integer(right[[first + offset]]) + carry
      result[[first + offset]] <- as.raw(total %% base)
      carry <- as.integer(total >= base)
    }
  }
  result
}

.psi_padded_ring63_sub_bits <- function(bits, left) {
  bits <- .psi_padded_ring63_validate_bits(bits)
  if (!is.raw(left) || length(left) != 8L * length(bits)) {
    stop("Invalid padded PSI Ring63 subtraction.", call. = FALSE)
  }
  result <- raw(length(left))
  for (record in seq_along(bits)) {
    borrow <- 0L
    first <- (record - 1L) * 8L + 1L
    for (offset in 0:7) {
      base <- if (offset == 7L) 128L else 256L
      minuend <- if (offset == 0L) bits[[record]] else 0L
      difference <- minuend - as.integer(left[[first + offset]]) - borrow
      if (difference < 0L) {
        difference <- difference + base
        borrow <- 1L
      } else {
        borrow <- 0L
      }
      result[[first + offset]] <- as.raw(difference)
    }
  }
  result
}

.psi_padded_ring63_share_bits <- function(
    bits, random_bytes = .dsvert_secure_random_bytes) {
  bits <- .psi_padded_ring63_validate_bits(bits)
  left <- random_bytes(8L * length(bits))
  if (!is.raw(left) || length(left) != 8L * length(bits)) {
    stop("Secure entropy returned an invalid padded PSI Ring63 share.",
         call. = FALSE)
  }
  top <- seq.int(8L, length(left), by = 8L)
  left[top] <- as.raw(bitwAnd(as.integer(left[top]), 127L))
  right <- .psi_padded_ring63_sub_bits(bits, left)
  list(left = .psi_padded_ring63_b64(left),
       right = .psi_padded_ring63_b64(right))
}

.psi_padded_ring63_sum <- function(values) {
  if (!is.list(values) || !length(values)) {
    stop("Padded PSI Ring63 sum requires at least one share.", call. = FALSE)
  }
  decoded <- lapply(values, .psi_padded_ring63_raw)
  lengths <- vapply(decoded, length, integer(1L))
  if (length(unique(lengths)) != 1L) {
    stop("Padded PSI Ring63 shares have conflicting shapes.", call. = FALSE)
  }
  total <- raw(lengths[[1L]])
  for (value in decoded) total <- .psi_padded_ring63_add_raw(total, value)
  .psi_padded_ring63_b64(total)
}

.psi_padded_ring63_decode_small <- function(value, upper) {
  decoded <- .psi_padded_ring63_raw(value)
  upper <- .psi_padded_integer(upper, "small residue bound", 0L, 255L)
  result <- integer(length(decoded) %/% 8L)
  for (record in seq_along(result)) {
    first <- (record - 1L) * 8L + 1L
    bytes <- as.integer(decoded[seq.int(first, length.out = 8L)])
    if (any(bytes[-1L] != 0L) || bytes[[1L]] > upper) {
      stop("Padded PSI exact comparison produced an invalid residue.",
           call. = FALSE)
    }
    result[[record]] <- bytes[[1L]]
  }
  result
}

.psi_padded_and_reference <- function(left_sum, right_sum, target_count) {
  target_count <- .psi_padded_integer(target_count, "target count", 1L, 255L)
  left <- .psi_padded_ring63_raw(left_sum)
  right <- .psi_padded_ring63_raw(right_sum)
  if (length(left) != length(right)) {
    stop("Padded PSI AND shares have conflicting shapes.", call. = FALSE)
  }
  reconstructed <- .psi_padded_ring63_b64(
    .psi_padded_ring63_add_raw(left, right))
  totals <- .psi_padded_ring63_decode_small(reconstructed, target_count)
  # This is the independent oracle for the purpose-bound exact-GC circuit:
  # compare-signed emits (sum < target_count); PSI consumes its complement.
  as.integer(!(totals < target_count))
}

.psi_padded_pinset_id <- function(pinset) {
  if (!is.list(pinset) || !length(pinset) || is.null(names(pinset)) ||
      anyNA(names(pinset)) || any(!nzchar(names(pinset))) ||
      anyDuplicated(names(pinset)) ||
      any(!vapply(pinset, function(value) {
        is.character(value) && length(value) == 1L && !is.na(value) &&
          nzchar(value)
      }, logical(1L)))) {
    stop("Invalid padded PSI pinned peer set.", call. = FALSE)
  }
  # The identity API historically returned padded Base64 while the DP policy
  # canonicalises the same Ed25519 keys as unpadded Base64url.  Hash canonical
  # key bytes here so the PSI contract and policy cannot derive different
  # pinset epochs from two encodings of the same keys.
  ordered <- lapply(
    pinset[sort(names(pinset), method = "radix")],
    .dsvert_relay_normalize_identity_pk)
  encoded <- paste(vapply(names(ordered), function(name) {
    paste0(nchar(name, type = "bytes"), ":", name, "=",
           nchar(ordered[[name]], type = "bytes"), ":", ordered[[name]])
  }, character(1L)), collapse = "|")
  paste0("pinset_", digest::digest(encoded, algo = "sha256",
                                    serialize = FALSE))
}

.psi_padded_canonical_json <- function(value) {
  .dsvert_dp_canonical_json(value)
}

.psi_padded_b64url_encode <- function(value) {
  if (!is.raw(value)) stop("Invalid padded PSI binary value.", call. = FALSE)
  base64_to_base64url(gsub("[\r\n]", "", jsonlite::base64_enc(value)))
}

.psi_padded_b64url_decode <- function(value, expected = NULL) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > 96L * 1024L * 1024L ||
      !grepl("^[A-Za-z0-9_-]+$", value)) {
    stop("Invalid padded PSI base64url value.", call. = FALSE)
  }
  decoded <- tryCatch(
    jsonlite::base64_dec(.base64url_to_base64(value)),
    error = function(e) NULL)
  if (is.null(decoded) || !is.raw(decoded) ||
      (!is.null(expected) && length(decoded) != expected) ||
      !identical(.psi_padded_b64url_encode(decoded), value)) {
    stop("Invalid padded PSI base64url value.", call. = FALSE)
  }
  decoded
}

.psi_padded_sign_offer <- function(
    peer_name, identity, transport_pk, capacity, session_id, operation_id,
    policy_id, source_authorization, pinset_id, snapshot_id, attestation_nonce,
    relay_frame_bytes = .dsvert_relay_frame_bytes(),
    inline_max_bytes = .psi_padded_inline_max_bytes()) {
  peer_name <- .psi_padded_scalar(
    peer_name, "peer name", "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
  if (!is.list(identity) || is.null(identity$identity_pk) ||
      is.null(identity$identity_sk)) {
    stop("Invalid padded PSI signing identity.", call. = FALSE)
  }
  source_authorization <- .psi_padded_validate_source_public(
    source_authorization)
  unsigned <- c(list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = .dsvert_relay_validate_session_id(session_id),
    operation_id = .dsvert_relay_validate_operation_id(operation_id),
    peer_name = peer_name,
    peer_id = .dsvert_relay_peer_id(identity$identity_pk),
    identity_pk = identity$identity_pk,
    transport_pk = .psi_padded_scalar(transport_pk, "transport key"),
    capacity = .psi_padded_validate_capacity(capacity),
    policy_id = .psi_padded_scalar(
      policy_id, "policy id", "^policy_[0-9a-f]{64}$")),
    source_authorization,
    list(
    pinset_id = .psi_padded_scalar(
      pinset_id, "pinset id", "^pinset_[0-9a-f]{64}$"),
    relay_frame_bytes = .psi_padded_integer(
      relay_frame_bytes, "relay frame size", 16L * 1024L, 64L * 1024L^2),
    inline_max_bytes = .psi_padded_integer(
      inline_max_bytes, "inline byte limit", 16L * 1024L, 64L * 1024L^2),
    snapshot_id = .psi_padded_scalar(
      snapshot_id, "snapshot id", "^snap_[0-9a-f]{64}$"),
    attestation_nonce = .psi_padded_scalar(
      attestation_nonce, "attestation nonce", "^[A-Za-z0-9_-]{43}$")))
  message <- .psi_padded_canonical_json(unsigned)
  signature <- .sign_transport_pk(.psi_text_to_b64(message),
                                  identity$identity_sk)
  list(unsigned = unsigned,
       signature = base64_to_base64url(signature))
}

.psi_padded_verify_offer <- function(offer, expected_name, expected_pk,
                                     expected_pinset_id) {
  fail <- function() stop("Padded PSI offer authentication failed.",
                          call. = FALSE)
  if (!is.list(offer) || !identical(sort(names(offer)),
                                    c("signature", "unsigned")) ||
      !is.list(offer$unsigned)) fail()
  unsigned <- offer$unsigned
  required <- c(
    "protocol", "session_id", "operation_id", "peer_name", "peer_id",
    "identity_pk", "transport_pk", "capacity", "policy_id",
    "alignment_purpose", "dataset_id", "dataset_version", "id_column",
    "source_binding_id", "pinset_id",
    "relay_frame_bytes", "inline_max_bytes", "snapshot_id",
    "attestation_nonce")
  if (!identical(names(unsigned), required) ||
      !identical(unsigned$protocol, .DSVERT_PSI_PADDED_PROTOCOL) ||
      !identical(unsigned$peer_name, expected_name) ||
      !identical(unsigned$identity_pk, expected_pk) ||
      !identical(unsigned$pinset_id, expected_pinset_id) ||
      !identical(unsigned$peer_id,
                 .dsvert_relay_peer_id(expected_pk))) fail()
  tryCatch({
    .dsvert_relay_validate_session_id(unsigned$session_id)
    .dsvert_relay_validate_operation_id(unsigned$operation_id)
    .psi_padded_validate_capacity(unsigned$capacity)
    .psi_padded_scalar(unsigned$policy_id, "policy id",
                       "^policy_[0-9a-f]{64}$")
    .psi_padded_validate_source_public(unsigned[c(
      "alignment_purpose", "dataset_id", "dataset_version", "id_column",
      "source_binding_id")])
    .psi_padded_integer(unsigned$relay_frame_bytes, "relay frame size",
                        16L * 1024L, 64L * 1024L^2)
    .psi_padded_integer(unsigned$inline_max_bytes, "inline byte limit",
                        16L * 1024L, 64L * 1024L^2)
    .psi_padded_scalar(unsigned$snapshot_id, "snapshot id",
                       "^snap_[0-9a-f]{64}$")
    .psi_padded_scalar(unsigned$attestation_nonce, "attestation nonce",
                       "^[A-Za-z0-9_-]{43}$")
    .psi_padded_scalar(unsigned$transport_pk, "transport key")
  }, error = function(e) fail())
  signature <- tryCatch(.base64url_to_base64(offer$signature),
                        error = function(e) fail())
  valid <- tryCatch(.verify_peer_identity(
    .psi_text_to_b64(.psi_padded_canonical_json(unsigned)), expected_pk,
    signature), error = function(e) FALSE)
  if (!isTRUE(valid)) fail()
  unsigned
}

.psi_padded_contract_from_offers <- function(offers, pinset) {
  pinset_id <- .psi_padded_pinset_id(pinset)
  if (!is.list(offers) || is.null(names(offers)) ||
      !setequal(names(offers), names(pinset)) ||
      length(offers) != length(pinset) || length(offers) < 2L) {
    stop("Padded PSI requires the complete pinned peer set.", call. = FALSE)
  }
  verified <- lapply(sort(names(pinset), method = "radix"), function(peer) {
    .psi_padded_verify_offer(offers[[peer]], peer, pinset[[peer]], pinset_id)
  })
  names(verified) <- sort(names(pinset), method = "radix")
  same <- function(field) length(unique(vapply(
    verified, `[[`, character(1L), field))) == 1L
  source_fields <- c(
    "alignment_purpose", "dataset_id", "dataset_version", "id_column",
    "source_binding_id")
  if (!same("session_id") || !same("operation_id") || !same("policy_id") ||
      !all(vapply(source_fields, same, logical(1L))) ||
      !same("pinset_id") || anyDuplicated(vapply(
        verified, `[[`, character(1L), "peer_id")) ||
      anyDuplicated(vapply(verified, `[[`, character(1L), "transport_pk")) ||
      anyDuplicated(vapply(verified, `[[`, character(1L), "snapshot_id"))) {
    stop("Padded PSI offers do not define one authenticated contract.",
         call. = FALSE)
  }
  peer_ids <- vapply(verified, `[[`, character(1L), "peer_id")
  ordered_names <- names(sort(peer_ids, method = "radix"))
  reference <- ordered_names[[1L]]
  base <- c(list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = verified[[1L]]$session_id,
    operation_id = verified[[1L]]$operation_id,
    policy_id = verified[[1L]]$policy_id),
    verified[[1L]][source_fields],
    list(
    pinset_id = pinset_id,
    capacity = as.integer(max(vapply(verified, `[[`, numeric(1L), "capacity"))),
    relay_frame_bytes = as.integer(min(vapply(
      verified, `[[`, numeric(1L), "relay_frame_bytes"))),
    inline_max_bytes = as.integer(min(vapply(
      verified, `[[`, numeric(1L), "inline_max_bytes"))),
    peer_names = ordered_names,
    peer_ids = unname(peer_ids[ordered_names]),
    reference_peer = reference,
    compute_peers = ordered_names[1:2],
    snapshot_ids = unname(vapply(
      verified[ordered_names], `[[`, character(1L), "snapshot_id"))))
  nonce <- .psi_padded_b64url_decode(
    verified[[reference]]$attestation_nonce, 32L)
  attestation_id <- paste0("attest_", digest::digest(
    c(nonce, charToRaw(.psi_padded_canonical_json(base))),
    algo = "sha256", serialize = FALSE))
  unsigned <- c(base, list(attestation_id = attestation_id))
  c(unsigned, list(contract_hash = digest::digest(
    .psi_padded_canonical_json(unsigned), algo = "sha256", serialize = FALSE)))
}

.psi_padded_policy <- function(session_id = "padded-policy",
                               source_authorization) {
  missing_policy <- .psi_scalar_option(
    "dsvert.psi.padded_missing_policy", "id_only")
  if (!missing_policy %in% c("id_only", "complete_cases")) {
    stop("Invalid padded PSI missing-value policy.", call. = FALSE)
  }
  maximum <- .psi_int_option(
    "dsvert.psi.max_input_ids", .DSVERT_PSI_PADDED_MAX_CAPACITY)
  maximum <- min(maximum, .DSVERT_PSI_PADDED_MAX_CAPACITY)
  if (maximum < .DSVERT_PSI_PADDED_MIN_CAPACITY) {
    stop("The padded PSI capacity policy is below its minimum bucket.",
         call. = FALSE)
  }
  maximum <- 2^floor(log(maximum, base = 2))
  pseudonym <- .psi_policy(session_id)
  source_authorization <- .psi_padded_validate_source_public(
    source_authorization)
  private <- c(list(
    missing_policy = missing_policy,
    duplicate_policy = "first",
    pseudonym_mode = pseudonym$pseudonym_mode,
    pseudonym_key = pseudonym$pseudonym_key,
    study_id = pseudonym$study_id,
    study_id_hash = pseudonym$study_id_hash,
    key_id = pseudonym$key_id,
    key_custody = pseudonym$key_custody,
    max_capacity = as.integer(maximum)), source_authorization)
  public <- private[setdiff(names(private), c("pseudonym_key", "study_id"))]
  policy_id <- paste0("policy_", digest::digest(
    .psi_padded_canonical_json(public), algo = "sha256", serialize = FALSE))
  list(private = private, public = public, policy_id = policy_id)
}

.psi_padded_random_id <- function(prefix, random_bytes = .dsvert_secure_random_bytes) {
  entropy <- random_bytes(32L)
  if (!is.raw(entropy) || length(entropy) != 32L) {
    stop("Secure entropy returned an invalid padded PSI identifier.",
         call. = FALSE)
  }
  paste0(prefix, digest::digest(entropy, algo = "sha256", serialize = FALSE))
}

.psi_padded_sign_bootstrap <- function(unsigned, identity_sk) {
  required <- c(
    "protocol", "session_id", "operation_id", "peer_id", "identity_pk",
    "transport_pk", "transport_signature", "capacity_offer", "policy_id",
    "alignment_purpose", "dataset_id", "dataset_version", "id_column",
    "source_binding_id",
    "relay_frame_bytes_offer", "inline_max_bytes_offer", "snapshot_id",
    "attestation_nonce")
  if (!is.list(unsigned) || !identical(names(unsigned), required) ||
      !identical(unsigned$protocol, .DSVERT_PSI_PADDED_PROTOCOL)) {
    stop("Invalid padded PSI bootstrap offer.", call. = FALSE)
  }
  signature <- .sign_transport_pk(
    .psi_text_to_b64(.psi_padded_canonical_json(unsigned)), identity_sk)
  list(unsigned = unsigned, signature = base64_to_base64url(signature))
}

.psi_padded_verify_bootstrap <- function(value) {
  fail <- function() stop("Padded PSI bootstrap authentication failed.",
                          call. = FALSE)
  if (!is.list(value) || !identical(sort(names(value)),
                                    c("signature", "unsigned")) ||
      !is.list(value$unsigned)) fail()
  unsigned <- value$unsigned
  required <- c(
    "protocol", "session_id", "operation_id", "peer_id", "identity_pk",
    "transport_pk", "transport_signature", "capacity_offer", "policy_id",
    "alignment_purpose", "dataset_id", "dataset_version", "id_column",
    "source_binding_id",
    "relay_frame_bytes_offer", "inline_max_bytes_offer", "snapshot_id",
    "attestation_nonce")
  if (!identical(names(unsigned), required) ||
      !identical(unsigned$protocol, .DSVERT_PSI_PADDED_PROTOCOL)) fail()
  tryCatch({
    .dsvert_relay_validate_session_id(unsigned$session_id)
    .dsvert_relay_validate_operation_id(unsigned$operation_id)
    .psi_padded_scalar(unsigned$peer_id, "peer id",
                       "^(?:peer|dsv1)_[0-9a-f]{64}$")
    .psi_padded_scalar(unsigned$identity_pk, "identity key")
    .psi_padded_scalar(unsigned$transport_pk, "transport key")
    .psi_padded_scalar(unsigned$transport_signature, "transport signature")
    .psi_padded_validate_capacity(unsigned$capacity_offer)
    .psi_padded_scalar(unsigned$policy_id, "policy id",
                       "^policy_[0-9a-f]{64}$")
    .psi_padded_validate_source_public(unsigned[c(
      "alignment_purpose", "dataset_id", "dataset_version", "id_column",
      "source_binding_id")])
    .psi_padded_integer(
      unsigned$relay_frame_bytes_offer, "relay frame offer",
      16L * 1024L, 64L * 1024L^2)
    .psi_padded_integer(
      unsigned$inline_max_bytes_offer, "inline-byte offer",
      16L * 1024L, 64L * 1024L^2)
    .psi_padded_scalar(unsigned$snapshot_id, "snapshot id",
                       "^snap_[0-9a-f]{64}$")
    .psi_padded_scalar(unsigned$attestation_nonce, "attestation nonce",
                       "^[A-Za-z0-9_-]{43}$")
  }, error = function(e) fail())
  if (!identical(unsigned$peer_id,
                 .dsvert_relay_peer_id(unsigned$identity_pk))) fail()
  transport_valid <- tryCatch(.verify_peer_identity(
    unsigned$transport_pk, unsigned$identity_pk,
    .base64url_to_base64(unsigned$transport_signature)),
    error = function(e) FALSE)
  offer_valid <- tryCatch(.verify_peer_identity(
    .psi_text_to_b64(.psi_padded_canonical_json(unsigned)),
    unsigned$identity_pk, .base64url_to_base64(value$signature)),
    error = function(e) FALSE)
  if (!isTRUE(transport_valid) || !isTRUE(offer_valid)) fail()
  unsigned
}

.psi_padded_json_b64url <- function(value) {
  .psi_padded_b64url_encode(charToRaw(.psi_padded_canonical_json(value)))
}

.psi_padded_parse_json_b64url <- function(value, what, max_bytes) {
  raw <- .psi_padded_b64url_decode(value)
  if (length(raw) > max_bytes) {
    stop("Oversized padded PSI ", what, ".", call. = FALSE)
  }
  parsed <- tryCatch(jsonlite::fromJSON(
    rawToChar(raw), simplifyVector = FALSE), error = function(e) NULL)
  if (is.null(parsed) ||
      !identical(.psi_padded_json_b64url(parsed), value)) {
    stop("Invalid or non-canonical padded PSI ", what, ".", call. = FALSE)
  }
  parsed
}

.psi_padded_contract_from_bootstraps <- function(offers, connection_names,
                                                 self_identity_pk) {
  if (!is.list(offers) || length(offers) < 2L ||
      !is.character(connection_names) ||
      length(connection_names) != length(offers) || anyNA(connection_names) ||
      any(!grepl("^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$", connection_names)) ||
      anyDuplicated(connection_names)) {
    stop("Padded PSI requires a complete named bootstrap set.", call. = FALSE)
  }
  verified <- lapply(offers, .psi_padded_verify_bootstrap)
  peer_ids <- vapply(verified, `[[`, character(1L), "peer_id")
  identity_pks <- vapply(verified, `[[`, character(1L), "identity_pk")
  transport_pks <- vapply(verified, `[[`, character(1L), "transport_pk")
  names(peer_ids) <- names(identity_pks) <- names(transport_pks) <-
    connection_names
  if (anyDuplicated(peer_ids) || anyDuplicated(identity_pks) ||
      anyDuplicated(transport_pks)) {
    stop("Padded PSI bootstrap identities or transport keys are duplicated.",
         call. = FALSE)
  }
  own_names <- connection_names[identity_pks == self_identity_pk]
  if (length(own_names) != 1L) {
    stop("Padded PSI bootstrap does not bind this server exactly once.",
         call. = FALSE)
  }
  identity_info <- stats::setNames(lapply(seq_along(verified), function(index) {
    list(
      identity_pk = base64_to_base64url(identity_pks[[index]]),
      signature = verified[[index]]$transport_signature)
  }), connection_names)
  transport_keys <- stats::setNames(
    lapply(transport_pks, base64_to_base64url), connection_names)
  # This is the existing name-bound pin barrier. Unknown or rotated identities
  # retain its purpose-built administrator instructions and condition class.
  .verify_all_peer_identities(identity_info, transport_keys, self_identity_pk)
  fields_equal <- function(field) length(unique(vapply(
    verified, `[[`, character(1L), field))) == 1L
  source_fields <- c(
    "alignment_purpose", "dataset_id", "dataset_version", "id_column",
    "source_binding_id")
  if (!fields_equal("session_id") || !fields_equal("operation_id") ||
      !fields_equal("policy_id") ||
      !all(vapply(source_fields, fields_equal, logical(1L)))) {
    stop("Padded PSI bootstraps disagree on their server-owned policy.",
         call. = FALSE)
  }
  ordered_names <- connection_names[order(peer_ids, method = "radix")]
  pinset <- as.list(identity_pks)
  names(pinset) <- connection_names
  pinset_id <- .psi_padded_pinset_id(pinset)
  base <- c(list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = verified[[1L]]$session_id,
    operation_id = verified[[1L]]$operation_id,
    policy_id = verified[[1L]]$policy_id),
    verified[[1L]][source_fields],
    list(
    pinset_id = pinset_id,
    capacity = as.integer(max(vapply(
      verified, `[[`, numeric(1L), "capacity_offer"))),
    relay_frame_bytes = as.integer(min(vapply(
      verified, `[[`, numeric(1L), "relay_frame_bytes_offer"))),
    inline_max_bytes = as.integer(min(vapply(
      verified, `[[`, numeric(1L), "inline_max_bytes_offer"))),
    peer_names = ordered_names,
    peer_ids = unname(peer_ids[ordered_names]),
    reference_peer = ordered_names[[1L]],
    compute_peers = ordered_names[1:2],
    snapshot_ids = unname(vapply(
      verified[match(ordered_names, connection_names)], `[[`, character(1L),
      "snapshot_id"))))
  reference_index <- match(base$reference_peer, connection_names)
  nonce <- .psi_padded_b64url_decode(
    verified[[reference_index]]$attestation_nonce, 32L)
  unsigned <- c(base, list(attestation_id = paste0(
    "attest_", digest::digest(
      c(nonce, charToRaw(.psi_padded_canonical_json(base))),
      algo = "sha256", serialize = FALSE))))
  contract <- c(unsigned, list(contract_hash = digest::digest(
    .psi_padded_canonical_json(unsigned), algo = "sha256", serialize = FALSE)))
  list(
    contract = contract, self_name = own_names[[1L]],
    identity_pks = as.list(identity_pks),
    transport_pks = as.list(transport_pks),
    offers = verified)
}

.psi_padded_contract_receipt <- function(contract, self_name, identity_sk) {
  unsigned <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = contract$contract_hash,
    session_id = contract$session_id,
    operation_id = contract$operation_id,
    peer_name = self_name,
    peer_id = contract$peer_ids[[match(self_name, contract$peer_names)]],
    decision = "accept")
  signature <- .sign_transport_pk(
    .psi_text_to_b64(.psi_padded_canonical_json(unsigned)), identity_sk)
  list(unsigned = unsigned,
       signature = base64_to_base64url(signature))
}

.psi_padded_verify_receipts <- function(receipts, contract, identity_pks) {
  if (!is.list(receipts) || is.null(names(receipts)) ||
      !setequal(names(receipts), contract$peer_names) ||
      length(receipts) != length(contract$peer_names)) {
    stop("Padded PSI requires one receipt from every pinned peer.",
         call. = FALSE)
  }
  for (peer in contract$peer_names) {
    receipt <- receipts[[peer]]
    expected <- list(
      protocol = .DSVERT_PSI_PADDED_PROTOCOL,
      contract_hash = contract$contract_hash,
      session_id = contract$session_id,
      operation_id = contract$operation_id,
      peer_name = peer,
      peer_id = contract$peer_ids[[match(peer, contract$peer_names)]],
      decision = "accept")
    valid <- is.list(receipt) &&
      identical(sort(names(receipt)), c("signature", "unsigned")) &&
      identical(receipt$unsigned, expected) &&
      isTRUE(tryCatch(.verify_peer_identity(
        .psi_text_to_b64(.psi_padded_canonical_json(expected)),
        identity_pks[[peer]], .base64url_to_base64(receipt$signature)),
        error = function(e) FALSE))
    if (!isTRUE(valid)) {
      stop("Padded PSI contract receipt authentication failed.",
           call. = FALSE)
    }
  }
  invisible(TRUE)
}

.psi_padded_assert_source <- function(state, data) {
  if (!is.list(state) || !is.data.frame(data) ||
      !is.character(state$snapshot_digest) ||
      !identical(.dsvert_dp_snapshot_digest(data), state$snapshot_digest)) {
    stop("The padded PSI protected snapshot changed.", call. = FALSE)
  }
  invisible(TRUE)
}

.psi_padded_init_impl <- function(
    ss, data, data_name, id_col, session_id, operation_id,
    random_bytes = .dsvert_secure_random_bytes) {
  if (!is.environment(ss) || !is.data.frame(data)) {
    stop("Invalid padded PSI source.", call. = FALSE)
  }
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  .psi_padded_data_name(data_name)
  if (!is.character(id_col) || length(id_col) != 1L || is.na(id_col) ||
      !nzchar(id_col) || !id_col %in% names(data)) {
    stop("Invalid padded PSI identifier column.", call. = FALSE)
  }
  authorization <- .psi_padded_authorize_source(data_name, id_col, data)
  snapshot_digest <- authorization$snapshot_sha256
  .psi_padded_state_restore(ss, session_id)
  previous <- ss$.psi_padded_state
  if (!is.null(previous)) {
    same <- identical(previous$session_id, session_id) &&
      identical(previous$operation_id, operation_id) &&
      identical(previous$data_name, data_name) &&
      identical(previous$id_col, id_col) &&
      identical(previous$snapshot_digest, snapshot_digest) &&
      identical(previous$source_authorization, authorization$public)
    if (!isTRUE(same)) {
      stop("Conflicting padded PSI initialization retry.", call. = FALSE)
    }
    return(previous$bootstrap)
  }
  policy <- .psi_padded_policy(session_id, authorization$public)
  selected <- .psi_padded_select_rows(
    data, id_col, policy$private$missing_policy,
    policy$private$duplicate_policy)
  capacity <- .psi_padded_capacity_bucket(
    length(selected$rows), policy$private$max_capacity)
  identity <- .get_identity_keypair()
  transport <- .callMpcTool("transport-keygen", list())
  peer_id <- .dsvert_relay_peer_id(identity$identity_pk)
  snapshot_id <- .psi_padded_random_id("snap_", random_bytes)
  attestation_nonce_raw <- random_bytes(32L)
  if (!is.raw(attestation_nonce_raw) || length(attestation_nonce_raw) != 32L) {
    stop("Secure entropy returned an invalid padded PSI attestation nonce.",
         call. = FALSE)
  }
  transport_signature <- .sign_transport_pk(
    transport$public_key, identity$identity_sk)
  unsigned <- c(list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = session_id,
    operation_id = operation_id,
    peer_id = peer_id,
    identity_pk = identity$identity_pk,
    transport_pk = transport$public_key,
    transport_signature = base64_to_base64url(transport_signature),
    capacity_offer = capacity,
    policy_id = policy$policy_id),
    authorization$public,
    list(
    relay_frame_bytes_offer = as.integer(.dsvert_relay_frame_bytes()),
    inline_max_bytes_offer = as.integer(.psi_padded_inline_max_bytes()),
    snapshot_id = snapshot_id,
    attestation_nonce = .psi_padded_b64url_encode(attestation_nonce_raw)))
  bootstrap <- .psi_padded_sign_bootstrap(unsigned, identity$identity_sk)
  ss$.psi_padded_state <- list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = session_id, operation_id = operation_id,
    data_name = data_name, id_col = id_col,
    snapshot_digest = snapshot_digest, snapshot_id = snapshot_id,
    source_authorization = authorization$public,
    policy = policy, selected_rows = selected$rows,
    selected_ids = selected$ids, capacity_offer = capacity,
    self_peer_id = peer_id, identity_pk = identity$identity_pk,
    transport_pk = transport$public_key,
    transport_sk = transport$secret_key,
    bootstrap = bootstrap, phase = "initialized",
    replay_cache = new.env(parent = emptyenv()))
  .psi_padded_state_commit(ss)
  bootstrap
}

.psi_padded_bind_impl <- function(ss, offers, connection_names) {
  if (!is.environment(ss) || !is.list(ss$.psi_padded_state) ||
      !identical(ss$.psi_padded_state$protocol,
                 .DSVERT_PSI_PADDED_PROTOCOL)) {
    stop("Padded PSI state is unavailable.", call. = FALSE)
  }
  state <- ss$.psi_padded_state
  if (!state$phase %in% c("initialized", "bound")) {
    stop("Padded PSI peer binding is out of phase.", call. = FALSE)
  }
  binding <- .psi_padded_contract_from_bootstraps(
    offers, connection_names, state$identity_pk)
  own_offer <- binding$offers[[match(binding$self_name, connection_names)]]
  if (!identical(own_offer, state$bootstrap$unsigned)) {
    stop("Padded PSI peer map substituted this server's bootstrap.",
         call. = FALSE)
  }
  if (!identical(binding$contract$capacity,
                 as.integer(max(vapply(binding$offers, `[[`, numeric(1L),
                                       "capacity_offer"))))) {
    stop("Padded PSI contract capacity is inconsistent.", call. = FALSE)
  }
  if (!is.null(state$contract) &&
      (!identical(state$contract, binding$contract) ||
       !identical(state$self_peer, binding$self_name))) {
    stop("Conflicting padded PSI peer-binding retry.", call. = FALSE)
  }
  state$contract <- binding$contract
  state$self_peer <- binding$self_name
  state$identity_pks <- binding$identity_pks
  state$transport_pks <- binding$transport_pks
  state$phase <- "bound"
  identity <- .get_identity_keypair()
  receipt <- .psi_padded_contract_receipt(
    state$contract, state$self_peer, identity$identity_sk)
  state$receipt <- receipt
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(contract = state$contract, receipt = receipt)
}

.psi_padded_confirm_impl <- function(ss, receipts) {
  state <- .psi_padded_and_state(ss)
  if (!state$phase %in% c("bound", "confirmed")) {
    stop("Padded PSI contract confirmation is out of phase.", call. = FALSE)
  }
  .psi_padded_verify_receipts(receipts, state$contract, state$identity_pks)
  if (!is.null(state$receipts) && !identical(state$receipts, receipts)) {
    stop("Conflicting padded PSI contract-confirmation retry.",
         call. = FALSE)
  }
  state$receipts <- receipts
  state$phase <- "confirmed"
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = state$contract$contract_hash,
    attestation_id = state$contract$attestation_id,
    confirmed = TRUE)
}

.psi_padded_prepare_impl <- function(
    ss, data, random_bytes = .dsvert_secure_random_bytes) {
  state <- .psi_padded_and_state(ss)
  if (!state$phase %in% c("confirmed", "prepared")) {
    stop("Padded PSI preparation is out of phase.", call. = FALSE)
  }
  .psi_padded_assert_source(state, data)
  if (identical(state$phase, "prepared")) {
    return(list(
      protocol = .DSVERT_PSI_PADDED_PROTOCOL,
      contract_hash = state$contract$contract_hash, prepared = TRUE))
  }
  slots <- .psi_padded_prepare_slots(
    state$selected_ids, state$selected_rows, state$contract$capacity,
    state$self_peer_id, state$snapshot_id, random_bytes = random_bytes)
  masked <- .callMpcTool("psi-mask", list(
    ids = as.list(slots$mask_ids), scalar = "",
    pseudonym_mode = state$policy$private$pseudonym_mode,
    pseudonym_key = state$policy$private$pseudonym_key,
    study_id = state$policy$private$study_id))
  if (!is.list(masked) || length(masked$masked_points) != state$contract$capacity ||
      !is.character(masked$scalar) || length(masked$scalar) != 1L ||
      !nzchar(masked$scalar)) {
    stop("Padded PSI masking backend returned the wrong fixed shape.",
         call. = FALSE)
  }
  state$mask_ids <- NULL
  state$slot_rows <- slots$slot_rows
  state$slot_valid <- slots$slot_valid
  state$masked_points <- unname(masked$masked_points)
  state$scalar <- masked$scalar
  state$phase <- "prepared"
  state$pairwise <- list()
  state$membership_received <- list()
  state$global_membership_chunks <- list()
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = state$contract$contract_hash, prepared = TRUE)
}

# Handshake entrypoints use bounded canonical scalar JSON, avoiding
# DataSHIELD parser-dependent nested-list behaviour.
#' @export
#' @noRd
psiPaddedInitDS <- function(data_name, id_col, session_id, operation_id) {
  .psi_padded_data_name(data_name)
  data <- get(data_name, envir = parent.frame(), inherits = TRUE)
  tryCatch(
    .psi_padded_init_impl(
      .S(session_id), data, data_name, id_col, session_id, operation_id),
    error = function(e) stop("Padded PSI initialization failed.",
                             call. = FALSE))
}

#' @export
#' @noRd
psiPaddedBindDS <- function(offers_b64url, connection_names_b64url,
                            session_id) {
  offers <- .psi_padded_parse_json_b64url(
    offers_b64url, "bootstrap set", 1024L * 1024L)
  connection_names <- .psi_padded_parse_json_b64url(
    connection_names_b64url, "connection-name set", 64L * 1024L)
  # Preserve the existing actionable unknown-pin condition instead of
  # flattening it into an opaque protocol failure.
  .psi_padded_bind_impl(.S(session_id), offers, unlist(connection_names,
                                                       use.names = FALSE))
}

#' @export
#' @noRd
psiPaddedConfirmDS <- function(receipts_b64url, session_id) {
  receipts <- .psi_padded_parse_json_b64url(
    receipts_b64url, "contract receipt set", 1024L * 1024L)
  tryCatch(
    .psi_padded_confirm_impl(.S(session_id), receipts),
    error = function(e) stop("Padded PSI contract confirmation failed.",
                             call. = FALSE))
}

#' @export
#' @noRd
psiPaddedPrepareDS <- function(data_name, session_id) {
  .psi_padded_data_name(data_name)
  data <- get(data_name, envir = parent.frame(), inherits = TRUE)
  tryCatch(
      .psi_padded_prepare_impl(.S(session_id), data),
    error = function(e) stop("Padded PSI preparation failed.",
                             call. = FALSE))
}

.psi_padded_targets <- function(contract) {
  setdiff(contract$peer_names, contract$reference_peer)
}

.psi_padded_target_index <- function(contract, target) {
  targets <- .psi_padded_targets(contract)
  index <- match(target, targets)
  if (is.na(index)) stop("Invalid padded PSI target peer.", call. = FALSE)
  as.integer(index)
}

.psi_padded_pair_context <- function(state, kind, sender, recipient, sequence) {
  snapshots <- .psi_padded_contract_snapshot_map(state$contract)
  list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = state$contract$session_id,
    operation_id = state$contract$operation_id,
    message_kind = kind,
    sequence = as.integer(sequence),
    sender = sender, recipient = recipient,
    sender_snapshot_id = snapshots[[sender]],
    recipient_snapshot_id = snapshots[[recipient]],
    contract_hash = state$contract$contract_hash,
    pinset_id = state$contract$pinset_id)
}

.psi_padded_pack_points_raw <- function(points, capacity) {
  capacity <- .psi_padded_validate_capacity(capacity)
  if (!is.character(points) || length(points) != capacity || anyNA(points)) {
    stop("Invalid padded PSI fixed point vector.", call. = FALSE)
  }
  packed <- .callMpcTool("psi-pack-points", list(points = as.list(points)))$packed
  decoded <- tryCatch(jsonlite::base64_dec(packed), error = function(e) NULL)
  if (is.null(decoded) || !is.raw(decoded) ||
      length(decoded) != 4L + 33L * capacity) {
    stop("Padded PSI point packer returned the wrong fixed shape.",
         call. = FALSE)
  }
  decoded
}

.psi_padded_unpack_points_raw <- function(value, capacity) {
  capacity <- .psi_padded_validate_capacity(capacity)
  if (!is.raw(value) || length(value) != 4L + 33L * capacity) {
    stop("Invalid padded PSI fixed point payload.", call. = FALSE)
  }
  packed <- gsub("[\r\n]", "", jsonlite::base64_enc(value))
  points <- .callMpcTool("psi-unpack-points", list(packed = packed))$points
  if (!is.character(points) || length(points) != capacity || anyNA(points)) {
    stop("Padded PSI point unpacker returned the wrong fixed shape.",
         call. = FALSE)
  }
  unname(points)
}

.psi_padded_match_map <- function(
    matched_own_rows, matched_ref_indices, own_slot_valid, ref_slot_valid,
    capacity) {
  capacity <- .psi_padded_validate_capacity(capacity)
  own <- suppressWarnings(as.integer(matched_own_rows))
  ref <- suppressWarnings(as.integer(matched_ref_indices))
  own_slot_valid <- as.logical(own_slot_valid)
  ref_slot_valid <- as.logical(ref_slot_valid)
  if (length(own) != length(ref) || length(own_slot_valid) != capacity ||
      length(ref_slot_valid) != capacity || anyNA(own) || anyNA(ref) ||
      any(own < 0L | own >= capacity) || any(ref < 0L | ref >= capacity) ||
      anyNA(own_slot_valid) || anyNA(ref_slot_valid) ||
      anyDuplicated(own) || anyDuplicated(ref)) {
    stop("Invalid padded PSI backend match map.", call. = FALSE)
  }
  # A dummy is never allowed to influence membership, even if a deliberately
  # adversarial test backend reports an equal curve point. This makes dummy
  # collision attacks structurally inert rather than relying only on the
  # negligible hash-to-curve collision probability.
  keep <- if (length(own)) {
    own_slot_valid[own + 1L] & ref_slot_valid[ref + 1L]
  } else logical()
  own <- own[keep]
  ref <- ref[keep]
  bitmap <- integer(capacity)
  mapping <- rep.int(as.integer(capacity), capacity)
  if (length(ref)) {
    bitmap[ref + 1L] <- 1L
    mapping[ref + 1L] <- own
  }
  list(bits = bitmap, target_slot_by_ref = mapping)
}

.psi_padded_reference_export_impl <- function(ss, target) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  if (!identical(state$phase, "prepared") ||
      !identical(state$self_peer, contract$reference_peer)) {
    stop("Padded PSI reference export is out of phase.", call. = FALSE)
  }
  target_index <- .psi_padded_target_index(contract, target)
  pair <- state$pairwise[[target]]
  if (is.list(pair) && !is.null(pair$reference_export)) {
    return(list(protocol = .DSVERT_PSI_PADDED_PROTOCOL,
                envelope = pair$reference_export))
  }
  target_pk <- state$transport_pks[[target]]
  if (is.null(target_pk)) stop("Padded PSI target transport key is unavailable.",
                               call. = FALSE)
  payload <- .psi_padded_pack_points_raw(
    state$masked_points, contract$capacity)
  identity <- .get_identity_keypair()
  envelope <- .psi_padded_seal_envelope(
    payload, .psi_padded_pair_context(
      state, "reference-masked-points", state$self_peer, target,
      1000L + target_index), identity$identity_sk, target_pk)
  if (is.null(pair)) pair <- list()
  pair$reference_export <- envelope
  state$pairwise[[target]] <- pair
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(protocol = .DSVERT_PSI_PADDED_PROTOCOL, envelope = envelope)
}

.psi_padded_target_process_impl <- function(ss, envelope) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  reference <- contract$reference_peer
  if (!identical(state$phase, "prepared") ||
      identical(state$self_peer, reference)) {
    stop("Padded PSI target processing is out of phase.", call. = FALSE)
  }
  target_index <- .psi_padded_target_index(contract, state$self_peer)
  pair <- state$pairwise[[reference]]
  if (is.list(pair) && !is.null(pair$target_export)) {
    if (!identical(pair$reference_envelope, envelope)) {
      stop("Conflicting padded PSI reference-envelope retry.",
           call. = FALSE)
    }
    return(list(protocol = .DSVERT_PSI_PADDED_PROTOCOL,
                envelope = pair$target_export))
  }
  payload <- .psi_padded_open_envelope(
    envelope, .psi_padded_pair_context(
      state, "reference-masked-points", reference, state$self_peer,
      1000L + target_index), state$identity_pks[[reference]],
    state$transport_sk, 4L + 33L * contract$capacity)
  reference_points <- .psi_padded_unpack_points_raw(
    payload, contract$capacity)
  doubled <- .callMpcTool("psi-double-mask", list(
    points = as.list(reference_points), scalar = state$scalar))
  if (!is.character(doubled$double_masked_points) ||
      length(doubled$double_masked_points) != contract$capacity) {
    stop("Padded PSI double-mask backend returned the wrong fixed shape.",
         call. = FALSE)
  }
  own_payload <- .psi_padded_pack_points_raw(
    state$masked_points, contract$capacity)
  identity <- .get_identity_keypair()
  target_export <- .psi_padded_seal_envelope(
    own_payload, .psi_padded_pair_context(
      state, "target-masked-points", state$self_peer, reference,
      2000L + target_index), identity$identity_sk,
    state$transport_pks[[reference]])
  state$pairwise[[reference]] <- list(
    reference_envelope = envelope,
    reference_double_points = unname(doubled$double_masked_points),
    target_export = target_export)
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(protocol = .DSVERT_PSI_PADDED_PROTOCOL, envelope = target_export)
}

.psi_padded_reference_double_impl <- function(ss, target, envelope) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  if (!identical(state$phase, "prepared") ||
      !identical(state$self_peer, contract$reference_peer)) {
    stop("Padded PSI reference double masking is out of phase.",
         call. = FALSE)
  }
  target_index <- .psi_padded_target_index(contract, target)
  pair <- state$pairwise[[target]]
  if (is.list(pair) && !is.null(pair$double_export)) {
    if (!identical(pair$target_envelope, envelope)) {
      stop("Conflicting padded PSI target-envelope retry.", call. = FALSE)
    }
    return(list(protocol = .DSVERT_PSI_PADDED_PROTOCOL,
                envelope = pair$double_export))
  }
  payload <- .psi_padded_open_envelope(
    envelope, .psi_padded_pair_context(
      state, "target-masked-points", target, state$self_peer,
      2000L + target_index), state$identity_pks[[target]],
    state$transport_sk, 4L + 33L * contract$capacity)
  points <- .psi_padded_unpack_points_raw(payload, contract$capacity)
  doubled <- .callMpcTool("psi-double-mask", list(
    points = as.list(points), scalar = state$scalar))
  if (!is.character(doubled$double_masked_points) ||
      length(doubled$double_masked_points) != contract$capacity) {
    stop("Padded PSI double-mask backend returned the wrong fixed shape.",
         call. = FALSE)
  }
  identity <- .get_identity_keypair()
  double_export <- .psi_padded_seal_envelope(
    .psi_padded_pack_points_raw(
      doubled$double_masked_points, contract$capacity),
    .psi_padded_pair_context(
      state, "reference-double-masked-target", state$self_peer, target,
      3000L + target_index), identity$identity_sk,
    state$transport_pks[[target]])
  if (is.null(pair)) pair <- list()
  pair$target_envelope <- envelope
  pair$double_export <- double_export
  state$pairwise[[target]] <- pair
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(protocol = .DSVERT_PSI_PADDED_PROTOCOL, envelope = double_export)
}

.psi_padded_membership_context <- function(state, target, compute_peer) {
  target_index <- .psi_padded_target_index(state$contract, target)
  compute_index <- match(compute_peer, state$contract$compute_peers)
  if (is.na(compute_index)) stop("Invalid padded PSI compute peer.",
                                 call. = FALSE)
  .psi_padded_pair_context(
    state, "membership-share", target, compute_peer,
    4000L + 2L * (target_index - 1L) + compute_index)
}

.psi_padded_target_match_impl <- function(
    ss, envelope, random_bytes = .dsvert_secure_random_bytes) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  reference <- contract$reference_peer
  if (!identical(state$phase, "prepared") ||
      identical(state$self_peer, reference)) {
    stop("Padded PSI target matching is out of phase.", call. = FALSE)
  }
  target_index <- .psi_padded_target_index(contract, state$self_peer)
  pair <- state$pairwise[[reference]]
  if (!is.list(pair) || is.null(pair$reference_double_points)) {
    stop("Padded PSI target pair state is unavailable.", call. = FALSE)
  }
  if (!is.null(pair$membership_exports)) {
    if (!identical(pair$double_envelope, envelope)) {
      stop("Conflicting padded PSI double-mask retry.", call. = FALSE)
    }
    return(list(protocol = .DSVERT_PSI_PADDED_PROTOCOL,
                envelopes = pair$membership_exports))
  }
  payload <- .psi_padded_open_envelope(
    envelope, .psi_padded_pair_context(
      state, "reference-double-masked-target", reference, state$self_peer,
      3000L + target_index), state$identity_pks[[reference]],
    state$transport_sk, 4L + 33L * contract$capacity)
  own_double <- .psi_padded_unpack_points_raw(payload, contract$capacity)
  matched <- .callMpcTool("psi-match", list(
    own_doubled = as.list(own_double),
    ref_doubled = as.list(pair$reference_double_points),
    ref_indices = as.list(seq_len(contract$capacity) - 1L)))
  mapping <- .psi_padded_match_map(
    matched$matched_own_rows, matched$matched_ref_indices,
    state$slot_valid, rep(TRUE, contract$capacity), contract$capacity)
  shares <- .psi_padded_ring63_share_bits(
    mapping$bits, random_bytes = random_bytes)
  share_values <- list(shares$left, shares$right)
  identity <- .get_identity_keypair()
  exports <- lapply(seq_along(contract$compute_peers), function(index) {
    compute <- contract$compute_peers[[index]]
    .psi_padded_seal_envelope(
      .psi_padded_ring63_raw(share_values[[index]], "membership share"),
      .psi_padded_membership_context(state, state$self_peer, compute),
      identity$identity_sk, state$transport_pks[[compute]])
  })
  names(exports) <- contract$compute_peers
  pair$double_envelope <- envelope
  pair$target_slot_by_ref <- mapping$target_slot_by_ref
  pair$membership_exports <- exports
  state$pairwise[[reference]] <- pair
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(protocol = .DSVERT_PSI_PADDED_PROTOCOL, envelopes = exports)
}

.psi_padded_membership_accept_impl <- function(ss, target, envelope) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  if (!identical(state$phase, "prepared") ||
      !state$self_peer %in% contract$compute_peers) {
    stop("Padded PSI membership collection is out of phase.", call. = FALSE)
  }
  targets <- .psi_padded_targets(contract)
  if (!target %in% targets) stop("Invalid padded PSI membership sender.",
                                 call. = FALSE)
  received <- state$membership_received %||% list()
  is_replay <- !is.null(received[[target]])
  if (!is_replay) {
    expected <- targets[[length(received) + 1L]]
    if (!identical(target, expected)) {
      stop("Padded PSI rejected a reordered membership share.",
           call. = FALSE)
    }
  }
  payload <- .psi_padded_open_envelope(
    envelope, .psi_padded_membership_context(
      state, target, state$self_peer), state$identity_pks[[target]],
    state$transport_sk, 8L * contract$capacity)
  encoded <- .psi_padded_ring63_b64(payload)
  receipt <- list(
    payload_sha256 = digest::digest(
      payload, algo = "sha256", serialize = FALSE),
    envelope_sha256 = digest::digest(
      envelope, algo = "sha256", serialize = FALSE))
  if (is_replay) {
    if (!identical(received[[target]], receipt)) {
      stop("Padded PSI rejected a conflicting duplicate membership share.",
           call. = FALSE)
    }
  } else {
    # Aggregate each fixed-width share as it arrives. Only a constant-size
    # receipt per target is retained for replay detection, so the two compute
    # peers use O(B + K) memory instead of retaining O(BK) plaintext shares
    # and ciphertexts.
    if (is.null(state$membership_sum_share)) {
      state$membership_sum_share <- encoded
    } else {
      state$membership_sum_share <- .psi_padded_ring63_sum(list(
        state$membership_sum_share, encoded))
    }
    received[[target]] <- receipt
  }
  state$membership_received <- received
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = contract$contract_hash, accepted = TRUE)
}

#' @export
#' @noRd
psiPaddedReferenceExportDS <- function(target, session_id,
                                       force_relay = FALSE) {
  tryCatch({
    ss <- .S(session_id)
    result <- .psi_padded_reference_export_impl(ss, target)
    state <- .psi_padded_and_state(ss)
    context <- .psi_padded_pair_context(
      state, "reference-masked-points", state$self_peer, target,
      1000L + .psi_padded_target_index(state$contract, target))
    c(list(protocol = .DSVERT_PSI_PADDED_PROTOCOL),
      .psi_padded_publish_envelope(
        ss, result$envelope, context, force_relay))
  }, error = function(e) stop("Padded PSI pair exchange failed.",
                              call. = FALSE))
}

#' @export
#' @noRd
psiPaddedTargetProcessDS <- function(envelope = "",
                                     relay_descriptor_b64url = "",
                                     session_id, force_relay = FALSE) {
  tryCatch({
    ss <- .S(session_id)
    state <- .psi_padded_and_state(ss)
    reference <- state$contract$reference_peer
    target_index <- .psi_padded_target_index(
      state$contract, state$self_peer)
    incoming <- .psi_padded_resolve_envelope(
      ss, envelope,
      .psi_padded_decode_relay_descriptor(relay_descriptor_b64url),
      .psi_padded_pair_context(
        state, "reference-masked-points", reference, state$self_peer,
        1000L + target_index))
    result <- .psi_padded_target_process_impl(ss, incoming)
    context <- .psi_padded_pair_context(
      .psi_padded_and_state(ss), "target-masked-points", state$self_peer,
      reference, 2000L + target_index)
    c(list(protocol = .DSVERT_PSI_PADDED_PROTOCOL),
      .psi_padded_publish_envelope(
        ss, result$envelope, context, force_relay))
  }, error = function(e) stop("Padded PSI pair exchange failed.",
                              call. = FALSE))
}

#' @export
#' @noRd
psiPaddedReferenceDoubleDS <- function(target, envelope = "",
                                       relay_descriptor_b64url = "",
                                       session_id, force_relay = FALSE) {
  tryCatch({
    ss <- .S(session_id)
    state <- .psi_padded_and_state(ss)
    target_index <- .psi_padded_target_index(state$contract, target)
    incoming <- .psi_padded_resolve_envelope(
      ss, envelope,
      .psi_padded_decode_relay_descriptor(relay_descriptor_b64url),
      .psi_padded_pair_context(
        state, "target-masked-points", target, state$self_peer,
        2000L + target_index))
    result <- .psi_padded_reference_double_impl(ss, target, incoming)
    context <- .psi_padded_pair_context(
      .psi_padded_and_state(ss), "reference-double-masked-target",
      state$self_peer, target, 3000L + target_index)
    c(list(protocol = .DSVERT_PSI_PADDED_PROTOCOL),
      .psi_padded_publish_envelope(
        ss, result$envelope, context, force_relay))
  }, error = function(e) stop("Padded PSI pair exchange failed.",
                              call. = FALSE))
}

#' @export
#' @noRd
psiPaddedTargetMatchDS <- function(envelope = "",
                                   relay_descriptor_b64url = "",
                                   session_id, force_relay = FALSE) {
  tryCatch({
    ss <- .S(session_id)
    state <- .psi_padded_and_state(ss)
    reference <- state$contract$reference_peer
    target_index <- .psi_padded_target_index(
      state$contract, state$self_peer)
    incoming <- .psi_padded_resolve_envelope(
      ss, envelope,
      .psi_padded_decode_relay_descriptor(relay_descriptor_b64url),
      .psi_padded_pair_context(
        state, "reference-double-masked-target", reference,
        state$self_peer, 3000L + target_index))
    result <- .psi_padded_target_match_impl(ss, incoming)
    state <- .psi_padded_and_state(ss)
    transports <- lapply(state$contract$compute_peers, function(compute) {
      .psi_padded_publish_envelope(
        ss, result$envelopes[[compute]],
        .psi_padded_membership_context(state, state$self_peer, compute),
        force_relay)
    })
    names(transports) <- state$contract$compute_peers
    list(protocol = .DSVERT_PSI_PADDED_PROTOCOL, transports = transports)
  }, error = function(e) stop("Padded PSI pair exchange failed.",
                              call. = FALSE))
}

#' @export
#' @noRd
psiPaddedMembershipAcceptDS <- function(
    target, envelope = "", relay_descriptor_b64url = "", session_id) {
  tryCatch({
    ss <- .S(session_id)
    state <- .psi_padded_and_state(ss)
    incoming <- .psi_padded_resolve_envelope(
      ss, envelope,
      .psi_padded_decode_relay_descriptor(relay_descriptor_b64url),
      .psi_padded_membership_context(state, target, state$self_peer))
    .psi_padded_membership_accept_impl(ss, target, incoming)
  }, error = function(e) stop("Padded PSI membership exchange failed.",
                              call. = FALSE))
}

.psi_padded_global_membership <- function(state) {
  contract <- state$contract
  chunk_count <- as.integer(ceiling(contract$capacity / 4096L))
  chunks <- state$global_membership_chunks
  if (!is.list(chunks) || !all(as.character(seq_len(chunk_count)) %in%
                               names(chunks))) {
    stop("Padded PSI global membership is incomplete.", call. = FALSE)
  }
  values <- unlist(chunks[as.character(seq_len(chunk_count))],
                   use.names = FALSE)
  values <- as.integer(values)
  if (length(values) != contract$capacity || anyNA(values) ||
      any(!values %in% 0:1)) {
    stop("Padded PSI global membership has the wrong fixed shape.",
         call. = FALSE)
  }
  values
}

.psi_padded_final_context <- function(state, target) {
  target_index <- .psi_padded_target_index(state$contract, target)
  .psi_padded_pair_context(
    state, "final-selection", state$contract$reference_peer, target,
    5000L + target_index)
}

.psi_padded_final_prepare_impl <- function(
    ss, random_bytes = .dsvert_secure_random_bytes) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  if (!identical(state$self_peer, contract$reference_peer)) {
    stop("Padded PSI finalization is restricted to the contract reference.",
         call. = FALSE)
  }
  if (!is.null(state$final_exports)) {
    return(list(
      protocol = .DSVERT_PSI_PADDED_PROTOCOL,
      contract_hash = contract$contract_hash,
      attestation_id = contract$attestation_id,
      envelopes = state$final_exports))
  }
  global <- .psi_padded_global_membership(state)
  plan <- .psi_padded_selection_plan(
    global, state$slot_valid, state$slot_rows)
  token <- base64_to_base64url(gsub(
    "[\r\n]", "", jsonlite::base64_enc(random_bytes(32L))))
  .psi_validate_alignment_token(token)
  packed <- .psi_padded_pack_selection(plan, contract$capacity, token)
  identity <- .get_identity_keypair()
  exports <- lapply(.psi_padded_targets(contract), function(target) {
    .psi_padded_seal_envelope(
      packed, .psi_padded_final_context(state, target), identity$identity_sk,
      state$transport_pks[[target]])
  })
  names(exports) <- .psi_padded_targets(contract)
  state$final_plan <- plan
  state$alignment_token <- token
  state$final_exports <- exports
  state$phase <- "finalized"
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    contract_hash = contract$contract_hash,
    attestation_id = contract$attestation_id,
    envelopes = exports)
}

.psi_padded_filter_impl <- function(ss, data, envelope = NULL) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  .psi_padded_assert_source(state, data)
  if (identical(state$self_peer, contract$reference_peer)) {
    if (!is.null(envelope) || is.null(state$final_plan) ||
        is.null(state$alignment_token)) {
      stop("Invalid padded PSI reference finalization.", call. = FALSE)
    }
    mapping <- seq_len(contract$capacity) - 1L
    plan <- state$final_plan
    token <- state$alignment_token
  } else {
    if (!is.character(envelope) || length(envelope) != 1L || is.na(envelope)) {
      stop("Padded PSI target final selection is unavailable.",
           call. = FALSE)
    }
    packed <- .psi_padded_open_envelope(
      envelope, .psi_padded_final_context(state, state$self_peer),
      state$identity_pks[[contract$reference_peer]], state$transport_sk,
      8L + 4L + 32L + ceiling(contract$capacity / 8L) +
        4L * contract$capacity)
    decoded <- .psi_padded_unpack_selection(packed, contract$capacity)
    plan <- decoded[c("bits", "ranks")]
    token <- decoded$token
    pair <- state$pairwise[[contract$reference_peer]]
    if (!is.list(pair) || is.null(pair$target_slot_by_ref)) {
      stop("Padded PSI target permutation is unavailable.", call. = FALSE)
    }
    mapping <- pair$target_slot_by_ref
  }
  result <- .psi_padded_materialize_target(
    data, state$id_col, state$slot_rows, state$slot_valid, mapping, plan, token)
  result <- .psi_padded_attach_attestation(result, contract)
  identity <- .get_identity_keypair()
  expected_pk <- .dsvert_relay_normalize_identity_pk(
    state$identity_pks[[state$self_peer]])
  if (!identical(
      .dsvert_relay_normalize_identity_pk(identity$identity_pk), expected_pk)) {
    stop("Padded PSI factor registry identity is not the pinned local peer.",
         call. = FALSE)
  }
  result <- .psi_padded_attach_factor_registry_v1(
    result, state$self_peer, identity)
  state$completed_manifest <- attr(
    result, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  state$phase <- "complete"
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  result
}

.psi_padded_public_attestation <- function(contract) {
  if (!is.list(contract) ||
      !identical(contract$protocol, .DSVERT_PSI_PADDED_PROTOCOL) ||
      !is.character(contract$contract_hash) ||
      length(contract$contract_hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", contract$contract_hash) ||
      !is.character(contract$peer_names) || length(contract$peer_names) < 2L ||
      is.null(contract$reference_peer) || is.null(contract$compute_peers)) {
    stop("Invalid padded PSI attestation contract.", call. = FALSE)
  }
  list(
    attestation_version = 2L,
    alignment_attested = TRUE,
    alignment_protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    attestation_id = contract$attestation_id,
    contract_hash = contract$contract_hash,
    policy_id = contract$policy_id,
    alignment_purpose = contract$alignment_purpose,
    dataset_id = contract$dataset_id,
    dataset_version = contract$dataset_version,
    id_column = contract$id_column,
    source_binding_id = contract$source_binding_id,
    pinset_id = contract$pinset_id,
    capacity_bucket = contract$capacity,
    relay_frame_bytes = contract$relay_frame_bytes,
    inline_max_bytes = contract$inline_max_bytes,
    peer_count = length(contract$peer_names),
    reference_peer = contract$reference_peer,
    compute_peers = contract$compute_peers)
}

.psi_padded_attestation_binding <- function(public, token) {
  .psi_validate_alignment_token(token)
  digest::hmac(
    token,
    paste0(
      "dsvert-pinned-padded-psi-attestation-v2|",
      .psi_padded_canonical_json(public)),
    algo = "sha256", serialize = FALSE)
}

.psi_padded_attach_attestation <- function(data, contract) {
  manifest <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  .psi_validate_alignment_manifest(data)
  public <- .psi_padded_public_attestation(contract)
  attr(data, .PSI_PADDED_ATTESTATION_ATTRIBUTE) <- list(
    public = public,
    binding = .psi_padded_attestation_binding(public, manifest$token))
  data
}

.psi_padded_raw_data_frame_shape_v1 <- function(data) {
  if (!is.data.frame(data)) {
    stop("Invalid padded PSI data-frame metadata.", call. = FALSE)
  }
  data_names <- attr(data, "names", exact = TRUE)
  row_count <- tryCatch(
    base::.row_names_info(data, 2L), error = function(error) NA_real_)
  if (!is.character(data_names) || anyNA(data_names) ||
      anyDuplicated(data_names) || !is.numeric(row_count) ||
      length(row_count) != 1L || is.na(row_count) ||
      !is.finite(row_count) || row_count < 0 ||
      row_count != floor(row_count) || row_count > .Machine$integer.max) {
    stop("Invalid padded PSI data-frame metadata.", call. = FALSE)
  }
  list(names = data_names, n = as.integer(row_count))
}

.psi_padded_alignment_metadata_v1 <- function(data) {
  fail <- function() stop(
    "Padded PSI alignment metadata is unavailable.", call. = FALSE)
  shape <- tryCatch(
    .psi_padded_raw_data_frame_shape_v1(data), error = function(error) fail())
  manifest <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  required <- c("version", "token", "id_col", "n", "order_binding", "hash")
  version <- if (is.list(manifest) && length(manifest$version) == 1L) {
    suppressWarnings(as.numeric(manifest$version))
  } else NA_real_
  manifest_n <- if (is.list(manifest) && length(manifest$n) == 1L) {
    suppressWarnings(as.numeric(manifest$n))
  } else NA_real_
  if (!is.list(manifest) || !identical(names(manifest), required) ||
      length(version) != 1L || is.na(version) || !is.finite(version) ||
      version != .PSI_ALIGNMENT_VERSION ||
      !is.character(manifest$id_col) || length(manifest$id_col) != 1L ||
      is.na(manifest$id_col) || !manifest$id_col %in% shape$names ||
      length(manifest_n) != 1L || is.na(manifest_n) ||
      !is.finite(manifest_n) || manifest_n != floor(manifest_n) ||
      manifest_n != shape$n ||
      !is.character(manifest$order_binding) ||
      length(manifest$order_binding) != 1L ||
      !grepl("^[0-9a-f]{64}$", manifest$order_binding) ||
      !is.character(manifest$hash) || length(manifest$hash) != 1L ||
      !grepl("^[0-9a-f]{64}$", manifest$hash)) fail()
  tryCatch(.psi_validate_alignment_token(manifest$token),
           error = function(error) fail())
  list(
    version = .PSI_ALIGNMENT_VERSION,
    hash = manifest$hash,
    n = as.integer(manifest_n),
    id_col = manifest$id_col)
}

.psi_padded_validate_persistent_attestation_impl_v1 <- function(
    data, metadata_only) {
  if (!is.logical(metadata_only) || length(metadata_only) != 1L ||
      is.na(metadata_only)) {
    stop("Invalid padded PSI attestation validation mode.", call. = FALSE)
  }
  if (isTRUE(metadata_only)) {
    .psi_padded_alignment_metadata_v1(data)
  } else {
    .psi_validate_alignment_manifest(data)
  }
  manifest <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  record <- attr(data, .PSI_PADDED_ATTESTATION_ATTRIBUTE, exact = TRUE)
  required <- c("public", "binding")
  if (!is.list(record) || !identical(names(record), required) ||
      !is.list(record$public) || !is.character(record$binding) ||
      length(record$binding) != 1L || is.na(record$binding)) {
    stop("Padded PSI alignment attestation is unavailable.", call. = FALSE)
  }
  public <- record$public
  public_required <- c(
    "attestation_version", "alignment_attested", "alignment_protocol",
    "attestation_id", "contract_hash", "policy_id", "alignment_purpose",
    "dataset_id", "dataset_version", "id_column", "source_binding_id",
    "pinset_id",
    "capacity_bucket", "relay_frame_bytes", "inline_max_bytes",
    "peer_count", "reference_peer", "compute_peers")
  fail <- function() {
    stop("Padded PSI alignment attestation is unavailable.", call. = FALSE)
  }
  if (!identical(names(public), public_required) ||
      !identical(public$attestation_version, 2L) ||
      !identical(public$alignment_attested, TRUE) ||
      !identical(public$alignment_protocol, .DSVERT_PSI_PADDED_PROTOCOL) ||
      !is.character(public$compute_peers) ||
      length(public$compute_peers) != 2L || anyNA(public$compute_peers) ||
      anyDuplicated(public$compute_peers)) fail()
  tryCatch({
    .psi_padded_scalar(public$attestation_id, "attestation id",
                       "^attest_[0-9a-f]{64}$")
    .psi_padded_scalar(public$contract_hash, "contract hash",
                       "^[0-9a-f]{64}$")
    .psi_padded_scalar(public$policy_id, "policy id",
                       "^policy_[0-9a-f]{64}$")
    .psi_padded_validate_source_public(public[c(
      "alignment_purpose", "dataset_id", "dataset_version", "id_column",
      "source_binding_id")])
    .psi_padded_scalar(public$pinset_id, "pinset id",
                       "^pinset_[0-9a-f]{64}$")
    .psi_padded_validate_capacity(public$capacity_bucket)
    .psi_padded_integer(public$relay_frame_bytes, "relay frame size",
                        16L * 1024L, 64L * 1024L^2)
    .psi_padded_integer(public$inline_max_bytes, "inline byte limit",
                        16L * 1024L, 64L * 1024L^2)
    .psi_padded_integer(public$peer_count, "peer count", 2L, 1000000L)
    .psi_padded_scalar(public$reference_peer, "reference peer",
                       "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    invisible(lapply(public$compute_peers, .psi_padded_scalar,
                     what = "compute peer",
                     pattern = "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"))
  }, error = function(e) fail())
  if (!public$reference_peer %in% public$compute_peers ||
      public$peer_count < length(public$compute_peers) ||
      !identical(
        record$binding,
        .psi_padded_attestation_binding(public, manifest$token))) fail()
  public
}

.psi_padded_validate_persistent_attestation <- function(data) {
  .psi_padded_validate_persistent_attestation_impl_v1(
    data, metadata_only = FALSE)
}

.psi_padded_validate_persistent_attestation_metadata_v1 <- function(data) {
  .psi_padded_validate_persistent_attestation_impl_v1(
    data, metadata_only = TRUE)
}

.psi_padded_factor_text_v1 <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value)) {
    stop("Invalid padded PSI factor ", what, ".", call. = FALSE)
  }
  byte_count <- tryCatch(
    nchar(value, type = "bytes"), error = function(error) NA_integer_)
  if (length(byte_count) != 1L || is.na(byte_count) ||
      byte_count < 1L || byte_count > 1024L) {
    stop("Invalid padded PSI factor ", what, ".", call. = FALSE)
  }
  value <- enc2utf8(value)
  if (!nzchar(value) || !isTRUE(validUTF8(value)) ||
      nchar(value, type = "bytes") > 1024L) {
    stop("Invalid padded PSI factor ", what, ".", call. = FALSE)
  }
  value
}

.psi_padded_configured_factor_domains_v1 <- function() {
  value <- getOption("dsvert.dp.categorical_levels")
  if (is.null(value)) {
    value <- getOption("default.dsvert.dp.categorical_levels")
  }
  if (is.null(value)) list() else value
}

.psi_padded_factor_entries_v1 <- function(
    data, public_domains = list(), exclude = character()) {
  shape <- tryCatch(.psi_padded_raw_data_frame_shape_v1(data),
                    error = function(error) NULL)
  if (!is.list(public_domains) ||
      (length(public_domains) &&
      (is.null(names(public_domains)) || anyNA(names(public_domains)))) ||
      length(public_domains) > .DSVERT_PSI_PADDED_FACTOR_MAX_COLUMNS ||
      !is.character(exclude) || anyNA(exclude) || is.null(shape)) {
    stop("Invalid padded PSI factor registry.", call. = FALSE)
  }
  exclude <- enc2utf8(exclude)
  variable_names <- vapply(
    names(public_domains), .psi_padded_factor_text_v1, character(1L),
    what = "variable name")
  if (anyDuplicated(variable_names)) {
    stop("Invalid padded PSI factor registry.", call. = FALSE)
  }
  if (!length(variable_names)) return(list())
  names(public_domains) <- variable_names
  data_names <- enc2utf8(shape$names)
  total_levels <- 0L
  total_bytes <- 0
  entries <- list()
  for (variable_name in variable_names) {
    if (variable_name %in% exclude) next
    index <- which(data_names == variable_name)
    if (!length(index)) next
    declared <- public_domains[[variable_name]]
    column <- if (length(index) == 1L) .subset2(data, index) else NULL
    actual <- if (is.factor(column)) {
      attr(column, "levels", exact = TRUE)
    } else NULL
    if (!is.atomic(declared) || !is.null(dim(declared)) ||
        !length(declared) ||
        length(declared) > .DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS ||
        !is.character(actual) || !length(actual) ||
        length(actual) > .DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS ||
        length(actual) != length(declared) ||
        anyNA(declared) || anyNA(actual)) {
      stop("Invalid padded PSI factor levels.", call. = FALSE)
    }
    declared <- tryCatch(.dsvert_canonical_label_values(
      declared, "padded PSI public factor levels",
      allow_na = FALSE, allow_blank = FALSE),
    error = function(error) {
      stop("Invalid padded PSI factor levels.", call. = FALSE)
    })
    declared <- vapply(
      declared, .psi_padded_factor_text_v1, character(1L),
      what = "level")
    actual <- vapply(
      actual, .psi_padded_factor_text_v1, character(1L), what = "level")
    if (anyDuplicated(declared) || anyDuplicated(actual) ||
        !identical(sort(declared, method = "radix"),
                   sort(actual, method = "radix"))) {
      stop("Invalid padded PSI factor levels.", call. = FALSE)
    }
    total_levels <- total_levels + length(declared)
    total_bytes <- total_bytes +
      nchar(variable_name, type = "bytes") +
      sum(nchar(declared, type = "bytes"))
    if (total_levels > .DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS ||
        total_bytes > .DSVERT_PSI_PADDED_FACTOR_MAX_METADATA_BYTES) {
      stop("Padded PSI factor registry exceeds the metadata limit.",
           call. = FALSE)
    }
    declared <- sort(declared, method = "radix")
    variable_id <- paste0("var_", digest::digest(
      paste0(
        .DSVERT_PSI_PADDED_FACTOR_VARIABLE_DOMAIN,
        .psi_padded_canonical_json(list(variable_name = variable_name))),
      algo = "sha256", serialize = FALSE))
    entries[[length(entries) + 1L]] <- list(
      version = .DSVERT_PSI_PADDED_FACTOR_ENTRY_VERSION,
      variable_name = variable_name,
      variable_id = variable_id,
      levels = as.list(unname(declared)),
      dimension = as.integer(length(declared)))
  }
  if (!length(entries)) return(list())
  ids <- vapply(entries, `[[`, character(1L), "variable_id")
  if (anyDuplicated(ids)) {
    stop("Invalid padded PSI factor registry.", call. = FALSE)
  }
  unname(entries[order(ids, method = "radix")])
}

.psi_padded_factor_domains_from_entries_v1 <- function(entries) {
  required <- c(
    "version", "variable_name", "variable_id", "levels", "dimension")
  if (!is.list(entries) || !is.null(names(entries))) {
    stop("Invalid padded PSI factor registry.", call. = FALSE)
  }
  if (length(entries) > .DSVERT_PSI_PADDED_FACTOR_MAX_COLUMNS) {
    stop("Padded PSI factor registry exceeds the metadata limit.",
         call. = FALSE)
  }
  if (!length(entries)) return(list())
  domains <- list()
  total_levels <- 0L
  total_bytes <- 0
  for (entry in entries) {
    if (!is.list(entry) || !identical(names(entry), required) ||
        !is.list(entry$levels) || !is.null(names(entry$levels))) {
      stop("Invalid padded PSI factor registry.", call. = FALSE)
    }
    level_count <- length(entry$levels)
    if (!level_count ||
        level_count > .DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS ||
        total_levels + level_count >
          .DSVERT_PSI_PADDED_FACTOR_MAX_LEVELS) {
      stop("Padded PSI factor registry exceeds the metadata limit.",
           call. = FALSE)
    }
    total_levels <- total_levels + level_count
    variable_name <- .psi_padded_factor_text_v1(
      entry$variable_name, "variable name")
    total_bytes <- total_bytes + nchar(variable_name, type = "bytes")
    if (total_bytes > .DSVERT_PSI_PADDED_FACTOR_MAX_METADATA_BYTES) {
      stop("Padded PSI factor registry exceeds the metadata limit.",
           call. = FALSE)
    }
    levels <- character(level_count)
    for (index in seq_len(level_count)) {
      levels[[index]] <- .psi_padded_factor_text_v1(
        entry$levels[[index]], "level")
      total_bytes <- total_bytes + nchar(levels[[index]], type = "bytes")
      if (total_bytes > .DSVERT_PSI_PADDED_FACTOR_MAX_METADATA_BYTES) {
        stop("Padded PSI factor registry exceeds the metadata limit.",
             call. = FALSE)
      }
    }
    if (!is.null(domains[[variable_name]])) {
      stop("Invalid padded PSI factor registry.", call. = FALSE)
    }
    domains[[variable_name]] <- levels
  }
  domains
}

.psi_padded_factor_registry_hash_v1 <- function(
    source_binding_id, entries, public_levels_policy) {
  digest::digest(
    paste0(
      .DSVERT_PSI_PADDED_FACTOR_REGISTRY_DOMAIN,
      .psi_padded_canonical_json(list(
        version = .DSVERT_PSI_PADDED_FACTOR_REGISTRY_VERSION,
        source_binding_id = source_binding_id,
        entries = entries,
        public_levels_policy = public_levels_policy))),
    algo = "sha256", serialize = FALSE)
}

.psi_padded_factor_entry_hash_v1 <- function(entry) {
  digest::digest(
    paste0(
      .DSVERT_PSI_PADDED_FACTOR_ENTRY_DOMAIN,
      .psi_padded_canonical_json(entry)),
    algo = "sha256", serialize = FALSE)
}

.psi_padded_factor_registry_message_v1 <- function(unsigned) {
  charToRaw(paste0(
    .DSVERT_PSI_PADDED_FACTOR_REGISTRY_SIGNATURE_DOMAIN,
    .psi_padded_canonical_json(unsigned)))
}

.psi_padded_attach_factor_registry_v1 <- function(
    data, peer_name, identity,
    .signer = .dsvert_relay_sign_message,
    .public_domains = .psi_padded_configured_factor_domains_v1()) {
  public <- .psi_padded_validate_persistent_attestation(data)
  alignment <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  peer_name <- .psi_padded_scalar(
    peer_name, "factor registry peer",
    "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
  if (!is.list(identity) || is.null(identity$identity_pk) ||
      is.null(identity$identity_sk) || !is.function(.signer)) {
    stop("Invalid padded PSI factor registry identity.", call. = FALSE)
  }
  identity_pk <- tryCatch(
    .dsvert_relay_normalize_identity_pk(identity$identity_pk),
    error = function(error) NULL)
  if (is.null(identity_pk)) {
    stop("Invalid padded PSI factor registry identity.", call. = FALSE)
  }
  entries <- .psi_padded_factor_entries_v1(
    data, public_domains = .public_domains, exclude = public$id_column)
  public_levels_policy <- if (length(.public_domains)) {
    "custodian_named_public_factor_domains_v1"
  } else {
    "no_public_factor_domains_v1"
  }
  registry_sha256 <- .psi_padded_factor_registry_hash_v1(
    public$source_binding_id, entries, public_levels_policy)
  unsigned <- list(
    version = .DSVERT_PSI_PADDED_FACTOR_REGISTRY_VERSION,
    peer_name = peer_name,
    peer_identity_pk = identity_pk,
    attestation_id = public$attestation_id,
    contract_hash = public$contract_hash,
    source_binding_id = public$source_binding_id,
    alignment_hash = alignment$hash,
    entries = entries,
    public_levels_policy = public_levels_policy,
    registry_sha256 = registry_sha256)
  if (nchar(.psi_padded_canonical_json(unsigned), type = "bytes") >
      64L * 1024L * 1024L) {
    stop("Padded PSI factor registry exceeds the metadata limit.",
         call. = FALSE)
  }
  signature <- .signer(
    .psi_padded_factor_registry_message_v1(unsigned), identity$identity_sk)
  signature_raw <- tryCatch(
    .dsvert_relay_b64url_decode(signature, "factor registry signature"),
    error = function(error) NULL)
  if (is.null(signature_raw) || length(signature_raw) != 64L) {
    stop("Invalid padded PSI factor registry signature.", call. = FALSE)
  }
  attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE) <- c(
    unsigned, list(signature = signature))
  data
}

.psi_padded_validate_factor_registry_v1 <- function(
    data, expected_peer_name = NULL, expected_identity_pk = NULL,
    .verifier = .dsvert_relay_verify_message,
    metadata_only = FALSE) {
  fail <- function() stop(
    "Padded PSI factor registry authentication failed.", call. = FALSE)
  if (!is.function(.verifier) || !is.logical(metadata_only) ||
      length(metadata_only) != 1L || is.na(metadata_only)) fail()
  public <- tryCatch(if (isTRUE(metadata_only)) {
    .psi_padded_validate_persistent_attestation_metadata_v1(data)
  } else {
    .psi_padded_validate_persistent_attestation(data)
  }, error = function(error) fail())
  alignment <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  record <- attr(data, .PSI_PADDED_FACTOR_REGISTRY_ATTRIBUTE, exact = TRUE)
  required <- c(
    "version", "peer_name", "peer_identity_pk", "attestation_id",
    "contract_hash", "source_binding_id", "alignment_hash", "entries",
    "public_levels_policy", "registry_sha256", "signature")
  if (!is.list(record) || !identical(names(record), required) ||
      !identical(record$version,
                 .DSVERT_PSI_PADDED_FACTOR_REGISTRY_VERSION) ||
      !is.list(record$entries) || !is.null(names(record$entries)) ||
      !identical(record$attestation_id, public$attestation_id) ||
      !identical(record$contract_hash, public$contract_hash) ||
      !identical(record$source_binding_id, public$source_binding_id) ||
      !identical(record$alignment_hash, alignment$hash)) fail()
  peer_name <- tryCatch(.psi_padded_scalar(
    record$peer_name, "factor registry peer",
    "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"), error = function(error) NULL)
  record_identity_pk <- record$peer_identity_pk
  identity_pk <- if (is.character(record_identity_pk) &&
      length(record_identity_pk) == 1L && !is.na(record_identity_pk) &&
      nchar(record_identity_pk, type = "bytes") == 43L &&
      grepl("^[A-Za-z0-9_-]{43}$", record_identity_pk)) {
    tryCatch(.dsvert_relay_normalize_identity_pk(record_identity_pk),
             error = function(error) NULL)
  } else NULL
  expected_peer_name <- tryCatch(.psi_padded_scalar(
    expected_peer_name, "expected factor registry peer",
    "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$"), error = function(error) NULL)
  expected_identity_pk <- tryCatch(
    .dsvert_relay_normalize_identity_pk(expected_identity_pk),
    error = function(error) NULL)
  policy <- record$public_levels_policy
  if (!is.character(policy) || length(policy) != 1L || is.na(policy) ||
      !policy %in% c(
        "custodian_named_public_factor_domains_v1",
        "no_public_factor_domains_v1")) fail()
  entries <- if (identical(
      policy, "custodian_named_public_factor_domains_v1")) {
    tryCatch({
      domains <- .psi_padded_factor_domains_from_entries_v1(record$entries)
      .psi_padded_factor_entries_v1(
        data, public_domains = domains, exclude = public$id_column)
    }, error = function(error) NULL)
  } else list()
  expected_hash <- if (!is.null(entries)) {
    .psi_padded_factor_registry_hash_v1(
      public$source_binding_id, entries, policy)
  } else ""
  if (is.null(peer_name) || is.null(identity_pk) ||
      is.null(expected_peer_name) || is.null(expected_identity_pk) ||
      !identical(peer_name, expected_peer_name) ||
      !identical(identity_pk, expected_identity_pk) ||
      !identical(record$peer_identity_pk, identity_pk) ||
      !identical(record$entries, entries) ||
      !identical(record$registry_sha256, expected_hash) ||
      !grepl("^[0-9a-f]{64}$", record$registry_sha256)) fail()
  unsigned <- record[setdiff(names(record), "signature")]
  signature <- record$signature
  signature_raw <- if (is.character(signature) && length(signature) == 1L &&
      !is.na(signature) && nchar(signature, type = "bytes") == 86L &&
      grepl("^[A-Za-z0-9_-]{86}$", signature)) {
    tryCatch(.dsvert_relay_b64url_decode(
      signature, "factor registry signature"),
    error = function(error) NULL)
  } else NULL
  valid <- !is.null(signature_raw) && length(signature_raw) == 64L &&
    isTRUE(tryCatch(.verifier(
      .psi_padded_factor_registry_message_v1(unsigned), identity_pk,
      record$signature), error = function(error) FALSE))
  if (!valid) fail()
  record
}

.psi_padded_completed_manifest_binding <- function(manifest) {
  if (!is.list(manifest)) {
    stop("Invalid padded PSI completed manifest.", call. = FALSE)
  }
  digest::digest(
    c(charToRaw("dsVert/padded-psi/completed-manifest/v1|"),
      serialize(manifest, NULL, ascii = FALSE, version = 3L)),
    algo = "sha256", serialize = FALSE)
}

.psi_padded_purge_exact_material <- function(ss, contract) {
  if (!is.environment(ss) || !is.list(contract)) return(invisible(FALSE))
  capacity <- .psi_padded_validate_capacity(contract$capacity)
  chunk_count <- as.integer(ceiling(capacity / 4096L))
  for (chunk_index in seq_len(chunk_count)) {
    chunk <- .psi_padded_and_chunk_contract(contract, chunk_index)
    if (is.environment(ss$.exact_gc_ops) &&
        exists(chunk$operation_id, envir = ss$.exact_gc_ops,
               inherits = FALSE)) {
      operation <- ss$.exact_gc_ops[[chunk$operation_id]]
      .exact_gc_abort_state(ss, operation, abort_complete = TRUE)
      rm(list = chunk$operation_id, envir = ss$.exact_gc_ops)
    }
    if (is.list(ss$.exact_gc_inputs)) {
      ss$.exact_gc_inputs[[chunk$source_key]] <- NULL
    }
    if (is.list(ss$.exact_gc_outputs)) {
      ss$.exact_gc_outputs[[chunk$output_key]] <- NULL
    }
  }
  remaining <- !is.environment(ss$.exact_gc_ops) ||
    length(ls(ss$.exact_gc_ops, all.names = TRUE)) == 0L
  if (isTRUE(remaining)) {
    if (is.list(ss$keys)) {
      ss$keys[c("transport_sk", "transport_pk", "identity_pk")] <- NULL
      if (!length(ss$keys)) ss$keys <- NULL
    }
    for (name in c(
      "peer_transport_pks", ".exact_gc_peer_identity_pks",
      ".exact_gc_self_name", ".exact_gc_transport_initialized",
      ".exact_gc_peer_binding_digest", ".exact_gc_peer_binding_contract",
      ".exact_gc_cleanup_capability")) {
      if (exists(name, envir = ss, inherits = FALSE)) {
        rm(list = name, envir = ss)
      }
    }
  }
  invisible(TRUE)
}

.psi_padded_compact_completed_state <- function(ss, manifest) {
  state <- .psi_padded_and_state(ss)
  if (!identical(state$phase, "complete")) return(invisible(FALSE))
  binding <- .psi_padded_completed_manifest_binding(manifest)
  compact <- list(
    protocol = state$protocol,
    session_id = state$session_id,
    operation_id = state$operation_id,
    self_peer_id = state$self_peer_id,
    self_peer = state$self_peer,
    identity_pk = state$identity_pk,
    contract = state$contract,
    phase = "attested",
    completed_manifest_binding = binding,
    journal_state_version = state$journal_state_version,
    journal_created_at = state$journal_created_at,
    journal_last_progress_at = state$journal_last_progress_at)
  ss$.psi_padded_state <- compact
  .psi_padded_state_commit(ss)
  .psi_padded_purge_exact_material(ss, state$contract)
  invisible(TRUE)
}

.psi_padded_attestation_impl <- function(ss = NULL, data) {
  public <- .psi_padded_validate_persistent_attestation(data)
  if (is.null(ss)) return(public)
  state <- .psi_padded_and_state(ss)
  manifest <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
  manifest_matches <- if (identical(state$phase, "complete")) {
    identical(manifest, state$completed_manifest)
  } else if (identical(state$phase, "attested")) {
    identical(.psi_padded_completed_manifest_binding(manifest),
              state$completed_manifest_binding)
  } else {
    FALSE
  }
  if (!isTRUE(manifest_matches) ||
      !identical(public, .psi_padded_public_attestation(state$contract))) {
    stop("Padded PSI alignment attestation is unavailable.", call. = FALSE)
  }
  if (identical(state$phase, "complete")) {
    .psi_padded_compact_completed_state(ss, manifest)
  } else {
    .psi_padded_purge_exact_material(ss, state$contract)
  }
  public
}

#' @export
#' @noRd
psiPaddedFinalPrepareDS <- function(session_id, force_relay = FALSE) {
  tryCatch({
    ss <- .S(session_id)
    result <- .psi_padded_final_prepare_impl(ss)
    state <- .psi_padded_and_state(ss)
    transports <- lapply(.psi_padded_targets(state$contract), function(target) {
      .psi_padded_publish_envelope(
        ss, result$envelopes[[target]],
        .psi_padded_final_context(state, target), force_relay)
    })
    names(transports) <- .psi_padded_targets(state$contract)
    list(
      protocol = .DSVERT_PSI_PADDED_PROTOCOL,
      contract_hash = state$contract$contract_hash,
      attestation_id = state$contract$attestation_id,
      transports = transports)
  }, error = function(e) stop("Padded PSI finalization failed.",
                              call. = FALSE))
}

#' @export
#' @noRd
psiPaddedFilterDS <- function(data_name, envelope = "",
                              relay_descriptor_b64url = "", session_id) {
  .psi_padded_data_name(data_name)
  data <- get(data_name, envir = parent.frame(), inherits = TRUE)
  tryCatch({
    ss <- .S(session_id)
    state <- .psi_padded_and_state(ss)
    incoming <- if (identical(
        state$self_peer, state$contract$reference_peer)) {
      if ((is.character(envelope) && length(envelope) == 1L &&
           nzchar(envelope)) || nzchar(relay_descriptor_b64url)) {
        stop("Invalid padded PSI reference final transport.", call. = FALSE)
      }
      NULL
    } else {
      .psi_padded_resolve_envelope(
        ss, envelope,
        .psi_padded_decode_relay_descriptor(relay_descriptor_b64url),
        .psi_padded_final_context(state, state$self_peer))
    }
    .psi_padded_filter_impl(ss, data, incoming)
  }, error = function(e) stop("Padded PSI finalization failed.",
                              call. = FALSE))
}

#' @export
#' @noRd
psiPaddedAttestationDS <- function(data_name, session_id = "") {
  .psi_padded_data_name(data_name)
  data <- get(data_name, envir = parent.frame(), inherits = TRUE)
  tryCatch({
    read_only <- is.character(session_id) && length(session_id) == 1L &&
      !is.na(session_id) && !nzchar(session_id)
    ss <- if (isTRUE(read_only)) NULL else .S(session_id)
    result <- .psi_padded_attestation_impl(ss, data)
    # Only the live post-assignment attestation may bridge into automatic DP
    # policy state. The later session_id="" status route remains read-only.
    if (!isTRUE(read_only)) {
      .dsvert_dp_alignment_registry_commit(data_name, data)
    }
    result
  }, error = function(e) stop(
    "Padded PSI alignment attestation unavailable.",
    call. = FALSE))
}

.psi_padded_validate_envelope_context <- function(context) {
  required <- c(
    "protocol", "session_id", "operation_id", "message_kind", "sequence",
    "sender", "recipient", "sender_snapshot_id", "recipient_snapshot_id",
    "contract_hash", "pinset_id")
  fail <- function() stop("Invalid padded PSI envelope context.", call. = FALSE)
  if (!is.list(context) || !identical(names(context), required) ||
      !identical(context$protocol, .DSVERT_PSI_PADDED_PROTOCOL)) fail()
  tryCatch({
    .dsvert_relay_validate_session_id(context$session_id)
    .dsvert_relay_validate_operation_id(context$operation_id)
    .psi_padded_scalar(context$message_kind, "message kind",
                       "^[a-z][a-z0-9-]{0,63}$")
    .psi_padded_integer(context$sequence, "message sequence", 0L, 2^31 - 1L)
    .psi_padded_scalar(context$sender, "sender",
                       "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    .psi_padded_scalar(context$recipient, "recipient",
                       "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    .psi_padded_scalar(context$sender_snapshot_id, "sender snapshot",
                       "^snap_[0-9a-f]{64}$")
    .psi_padded_scalar(context$recipient_snapshot_id, "recipient snapshot",
                       "^snap_[0-9a-f]{64}$")
    .psi_padded_scalar(context$contract_hash, "contract hash", "^[0-9a-f]{64}$")
    .psi_padded_scalar(context$pinset_id, "pinset id",
                       "^pinset_[0-9a-f]{64}$")
  }, error = function(e) fail())
  context$sequence <- as.integer(context$sequence)
  context
}

.psi_padded_envelope_message <- function(context, payload_b64url) {
  .psi_padded_canonical_json(list(
    domain = "dsvert-padded-psi-signed-envelope-v4",
    context = .psi_padded_validate_envelope_context(context),
    payload = payload_b64url))
}

.psi_padded_seal_envelope <- function(payload, context, identity_sk,
                                      recipient_transport_pk) {
  if (!is.raw(payload)) stop("Invalid padded PSI envelope payload.",
                             call. = FALSE)
  context <- .psi_padded_validate_envelope_context(context)
  payload_b64url <- .psi_padded_b64url_encode(payload)
  message <- .psi_padded_envelope_message(context, payload_b64url)
  signature <- .sign_transport_pk(.psi_text_to_b64(message), identity_sk)
  plaintext <- .psi_padded_canonical_json(list(
    version = .DSVERT_PSI_PADDED_PROTOCOL,
    context = context,
    payload = payload_b64url,
    signature = base64_to_base64url(signature)))
  sealed <- .callMpcTool("transport-encrypt", list(
    data = .psi_text_to_b64(plaintext), recipient_pk = recipient_transport_pk))
  base64_to_base64url(sealed$sealed)
}

.psi_padded_open_envelope <- function(
    sealed, expected_context, sender_identity_pk, recipient_transport_sk,
    expected_payload_bytes) {
  fail_context <- function() stop("Padded PSI envelope context mismatch.",
                                  call. = FALSE)
  expected_context <- tryCatch(
    .psi_padded_validate_envelope_context(expected_context),
    error = function(e) fail_context())
  opened <- tryCatch(.callMpcTool("transport-decrypt", list(
    sealed = .base64url_to_base64(sealed),
    recipient_sk = recipient_transport_sk)), error = function(e) NULL)
  if (is.null(opened) || is.null(opened$data)) {
    stop("Padded PSI envelope authentication failed.", call. = FALSE)
  }
  parsed <- tryCatch(jsonlite::fromJSON(
    .psi_b64_to_text(opened$data), simplifyVector = FALSE),
    error = function(e) NULL)
  if (!is.list(parsed) || !identical(names(parsed),
      c("version", "context", "payload", "signature")) ||
      !identical(parsed$version, .DSVERT_PSI_PADDED_PROTOCOL)) {
    stop("Invalid padded PSI envelope.", call. = FALSE)
  }
  received_context <- tryCatch(
    .psi_padded_validate_envelope_context(parsed$context),
    error = function(e) fail_context())
  if (!identical(received_context, expected_context)) fail_context()
  payload <- tryCatch(.psi_padded_b64url_decode(
    parsed$payload, expected_payload_bytes), error = function(e) NULL)
  if (is.null(payload)) stop("Invalid padded PSI envelope payload.",
                             call. = FALSE)
  message <- .psi_padded_envelope_message(received_context, parsed$payload)
  signature <- tryCatch(.base64url_to_base64(parsed$signature),
                        error = function(e) "")
  authenticated <- tryCatch(.verify_peer_identity(
    .psi_text_to_b64(message), sender_identity_pk, signature),
    error = function(e) FALSE)
  if (!isTRUE(authenticated)) {
    stop("Padded PSI envelope sender authentication failed.", call. = FALSE)
  }
  payload
}

.psi_padded_accept_once <- function(cache, key, value) {
  if (!is.environment(cache) || identical(environmentName(cache),
                                       "R_EmptyEnv")) {
    stop("Invalid padded PSI replay cache.", call. = FALSE)
  }
  key <- .psi_padded_scalar(
    key, "replay key", "^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
  digest_value <- digest::digest(value, algo = "sha256", serialize = TRUE)
  previous <- cache[[key]]
  if (!is.null(previous)) {
    if (!identical(previous, digest_value)) {
      stop("Padded PSI rejected a conflicting duplicate message.",
           call. = FALSE)
    }
    return(list(accepted = FALSE, replay = TRUE))
  }
  cache[[key]] <- digest_value
  list(accepted = TRUE, replay = FALSE)
}

.psi_padded_contract_snapshot_map <- function(contract) {
  if (!is.list(contract) || !is.character(contract$peer_names) ||
      !is.character(contract$snapshot_ids) ||
      length(contract$peer_names) != length(contract$snapshot_ids) ||
      anyNA(contract$peer_names) || anyNA(contract$snapshot_ids) ||
      anyDuplicated(contract$peer_names)) {
    stop("Invalid padded PSI snapshot contract.", call. = FALSE)
  }
  stats::setNames(contract$snapshot_ids, contract$peer_names)
}

.psi_padded_and_chunk_contract <- function(contract, chunk_index) {
  if (!is.list(contract) ||
      !identical(contract$protocol, .DSVERT_PSI_PADDED_PROTOCOL) ||
      !is.character(contract$contract_hash) ||
      !grepl("^[0-9a-f]{64}$", contract$contract_hash) ||
      !is.character(contract$compute_peers) ||
      length(contract$compute_peers) != 2L ||
      anyNA(contract$compute_peers) || anyDuplicated(contract$compute_peers) ||
      !all(contract$compute_peers %in% contract$peer_names) ||
      !is.character(contract$reference_peer) ||
      length(contract$reference_peer) != 1L ||
      !contract$reference_peer %in% contract$peer_names) {
    stop("Invalid padded PSI AND contract.", call. = FALSE)
  }
  capacity <- .psi_padded_validate_capacity(contract$capacity)
  chunk_count <- as.integer(ceiling(capacity / 4096L))
  chunk_index <- .psi_padded_integer(
    chunk_index, "AND chunk index", 1L, chunk_count)
  offset <- as.integer((chunk_index - 1L) * 4096L)
  vector_len <- as.integer(min(4096L, capacity - offset))
  digest_input <- paste0(
    "dsvert-psi-padded-and-operation-v4|", contract$contract_hash, "|",
    sprintf("%08d", chunk_index), "|", sprintf("%08d", chunk_count))
  operation_id <- paste0("op_", substr(digest::digest(
    digest_input, algo = "sha256", serialize = FALSE), 1L, 32L))
  suffix <- sub("^op_", "", operation_id)
  purpose <- paste0(
    .DSVERT_PSI_PADDED_AND_PURPOSE, ".h-",
    substr(contract$contract_hash, 1L, 16L), ".c-", chunk_index, "-",
    chunk_count)
  list(
    chunk_index = chunk_index, chunk_count = chunk_count, offset = offset,
    vector_len = vector_len, operation_id = operation_id,
    source_key = paste0("exact_gc_in_", suffix),
    output_key = paste0("exact_gc_out_", suffix), purpose = purpose,
    threshold = as.character(length(contract$peer_names) - 1L))
}

.psi_padded_and_state <- function(ss) {
  if (is.environment(ss) && !is.list(ss$.psi_padded_state) &&
      is.character(ss$.session_id) && length(ss$.session_id) == 1L &&
      !is.na(ss$.session_id)) {
    public_session <- sub(
      "__dslite_[0-9a-f]{16}$", "", ss$.session_id, perl = TRUE)
    if (grepl(.DSVERT_RELAY_SESSION_RE, public_session)) {
      .psi_padded_state_restore(ss, public_session)
    }
  }
  if (!is.environment(ss) || !is.list(ss$.psi_padded_state)) {
    stop("Padded PSI state is unavailable.", call. = FALSE)
  }
  state <- ss$.psi_padded_state
  contract <- state$contract
  if (!is.list(contract) ||
      !identical(contract$protocol, .DSVERT_PSI_PADDED_PROTOCOL) ||
      !is.character(state$self_peer) || length(state$self_peer) != 1L ||
      !state$self_peer %in% contract$peer_names) {
    stop("Padded PSI state has the wrong context.", call. = FALSE)
  }
  state
}

.psi_padded_exact_transport_impl <- function(ss) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  if (!identical(state$phase, "prepared") ||
      !state$self_peer %in% contract$compute_peers) {
    stop("Padded PSI exact transport is restricted to prepared compute peers.",
         call. = FALSE)
  }
  peer <- setdiff(contract$compute_peers, state$self_peer)
  if (length(peer) != 1L || is.null(state$transport_pks[[peer]]) ||
      is.null(state$identity_pks[[peer]])) {
    stop("Padded PSI exact transport peer is unavailable.", call. = FALSE)
  }
  identity <- .get_identity_keypair()
  if (!identical(identity$identity_pk, state$identity_pk)) {
    stop("Padded PSI persistent identity changed within the session.",
         call. = FALSE)
  }
  trusted <- .get_trusted_peers()
  if (!identical(trusted[[peer]], state$identity_pks[[peer]])) {
    stop("Padded PSI exact transport peer is no longer name-pinned.",
         call. = FALSE)
  }
  compute_peers <- sort(contract$compute_peers, method = "radix")
  identity_pks <- vapply(
    state$identity_pks[compute_peers],
    .dsvert_relay_normalize_identity_pk, character(1L),
    USE.NAMES = TRUE)
  transport_pks <- vapply(
    state$transport_pks[compute_peers],
    .dsvert_relay_normalize_identity_pk, character(1L),
    USE.NAMES = TRUE)
  binding_contract <- list(
    version = "dsvert-exact-gc-psi-binding-v1",
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    session_id = contract$session_id,
    consortium_id = contract$contract_hash,
    full_peer_pinset_sha256 = sub("^pinset_", "", contract$pinset_id),
    designated_peers = as.list(compute_peers),
    designated_peer_pinset = as.list(identity_pks),
    identity_pks = as.list(identity_pks),
    transport_pks = as.list(transport_pks))
  binding <- .exact_gc_peer_binding_contract_digest(binding_contract)
  existing <- c(
    transport_sk = .key_get("transport_sk", ss),
    transport_pk = .key_get("transport_pk", ss),
    identity_pk = .key_get("identity_pk", ss))
  expected <- c(
    transport_sk = state$transport_sk,
    transport_pk = state$transport_pk,
    identity_pk = state$identity_pk)
  if (length(existing) && !identical(existing, expected)) {
    stop("Conflicting exact transport is already installed in this session.",
         call. = FALSE)
  }
  if (isTRUE(ss$.exact_gc_transport_initialized) &&
      (!identical(ss$.exact_gc_peer_binding_digest, binding) ||
       !identical(ss$.exact_gc_peer_binding_contract, binding_contract) ||
       !identical(ss$peer_transport_pks,
                  stats::setNames(list(state$transport_pks[[peer]]), peer)) ||
       !identical(ss$.exact_gc_self_name, state$self_peer))) {
    stop("Conflicting padded PSI exact transport retry.", call. = FALSE)
  }
  .key_put("transport_sk", state$transport_sk, ss)
  .key_put("transport_pk", state$transport_pk, ss)
  .key_put("identity_pk", state$identity_pk, ss)
  ss$peer_transport_pks <- stats::setNames(
    list(state$transport_pks[[peer]]), peer)
  ss$.exact_gc_peer_identity_pks <- stats::setNames(
    list(state$identity_pks[[peer]]), peer)
  ss$.exact_gc_self_name <- state$self_peer
  ss$.exact_gc_transport_initialized <- TRUE
  ss$.exact_gc_peer_binding_digest <- binding
  ss$.exact_gc_peer_binding_contract <- binding_contract
  list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    contract_hash = contract$contract_hash,
    compute_peer = state$self_peer, peer = peer, bound = TRUE)
}

.psi_padded_and_start_impl <- function(
    ss, chunk_index, binary = .findMpcBinary()) {
  .psi_padded_exact_transport_impl(ss)
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  if (!state$self_peer %in% contract$compute_peers) {
    stop("Padded PSI AND is restricted to the two contract compute peers.",
         call. = FALSE)
  }
  chunk <- .psi_padded_and_chunk_contract(contract, chunk_index)
  full <- .psi_padded_ring63_raw(
    state$membership_sum_share, "membership sum share")
  if (length(full) != 8L * contract$capacity) {
    stop("Padded PSI membership sum has the wrong fixed shape.",
         call. = FALSE)
  }
  first <- 8L * chunk$offset + 1L
  share <- .psi_padded_ring63_b64(
    full[seq.int(first, length.out = 8L * chunk$vector_len)])
  .exact_gc_stage_share(
    ss, chunk$source_key, share, 63L, chunk$vector_len,
    .DSVERT_PSI_PADDED_AND_PRODUCER, "compare-signed", chunk$purpose, 0L,
    "ring-share")
  if (is.null(state$and_chunks)) state$and_chunks <- list()
  key <- as.character(chunk$chunk_index)
  binding <- list(
    contract_hash = contract$contract_hash,
    operation_id = chunk$operation_id, purpose = chunk$purpose,
    vector_len = chunk$vector_len,
    source_digest = digest::digest(share, algo = "sha256", serialize = FALSE))
  previous <- state$and_chunks[[key]]
  if (!is.null(previous) &&
      (!identical(previous$binding, binding) ||
       !previous$status %in% c("started", "output-consumed", "sealed"))) {
    stop("Conflicting padded PSI AND retry.", call. = FALSE)
  }
  if (is.null(previous)) {
    state$and_chunks[[key]] <- list(
      binding = binding, status = "started", output = NULL, envelope = NULL)
    ss$.psi_padded_state <- state
    .psi_padded_state_commit(ss)
  }
  result <- .exact_gc_init_impl(
    ss, contract$session_id, chunk$operation_id,
    .DSVERT_EXACT_GC_CAPABILITY, chunk$source_key, chunk$output_key,
    "compare-signed", 63L, 0L, chunk$vector_len, chunk$purpose,
    threshold = chunk$threshold, binary = binary)
  # The exact worker state contains no source share, comparison result or real
  # cardinality. These public fields are fixed by B and K.
  list(
    capability_id = result$capability_id,
    peer_id = result$peer_id,
    peer_peer_id = result$peer_peer_id,
    operation_id = chunk$operation_id,
    context_hash = result$context_hash,
    role = result$role,
    operation = "compare-signed", ring_bits = 63L, frac_bits = 0L,
    vector_len = chunk$vector_len, threshold = chunk$threshold,
    purpose = chunk$purpose,
    source_producer = .DSVERT_PSI_PADDED_AND_PRODUCER,
    output_kind = "ring-share", chunk_bytes = result$chunk_bytes,
    ttl_seconds = result$ttl_seconds,
    max_runtime_seconds = result$max_runtime_seconds,
    worker_heartbeat = result$worker_heartbeat,
    state = result$state, chunk_index = chunk$chunk_index,
    stored = result$stored, chunk_count = chunk$chunk_count)
}

.psi_padded_and_envelope_context <- function(state, chunk, sender) {
  contract <- state$contract
  snapshots <- .psi_padded_contract_snapshot_map(contract)
  list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    session_id = contract$session_id,
    operation_id = chunk$operation_id,
    message_kind = "and-output-share",
    sequence = as.integer(chunk$chunk_index),
    sender = sender, recipient = contract$reference_peer,
    sender_snapshot_id = snapshots[[sender]],
    recipient_snapshot_id = snapshots[[contract$reference_peer]],
    contract_hash = contract$contract_hash,
    pinset_id = contract$pinset_id)
}

.psi_padded_and_finalize_impl <- function(ss, chunk_index) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  if (!state$self_peer %in% contract$compute_peers) {
    stop("Padded PSI AND is restricted to the two contract compute peers.",
         call. = FALSE)
  }
  chunk <- .psi_padded_and_chunk_contract(contract, chunk_index)
  key <- as.character(chunk$chunk_index)
  stage <- state$and_chunks[[key]]
  if (is.null(stage) || !identical(stage$binding$operation_id,
                                   chunk$operation_id)) {
    stop("Padded PSI AND chunk was not started.", call. = FALSE)
  }
  if (identical(stage$status, "sealed")) {
    return(list(
      protocol = .DSVERT_PSI_PADDED_PROTOCOL,
      chunk_index = chunk$chunk_index, chunk_count = chunk$chunk_count,
      envelope = stage$envelope))
  }
  if (identical(stage$status, "started")) {
    operation <- .exact_gc_operation_state(ss, chunk$operation_id)
    .exact_gc_refresh(ss, operation)
    output <- .exact_gc_consume_output(
      ss, chunk$output_key, chunk$operation_id, "ring-share",
      "compare-signed", chunk$purpose, 63L, 0L, chunk$vector_len,
      .DSVERT_PSI_PADDED_AND_PRODUCER)
    .psi_padded_ring63_raw(output$share, "exact AND output share")
    stage$output <- output$share
    stage$status <- "output-consumed"
    state$and_chunks[[key]] <- stage
    ss$.psi_padded_state <- state
    .psi_padded_state_commit(ss)
  } else if (!identical(stage$status, "output-consumed")) {
    stop("Padded PSI AND chunk has an invalid state.", call. = FALSE)
  }
  reference_pk <- state$transport_pks[[contract$reference_peer]]
  if (is.null(reference_pk)) {
    stop("Padded PSI reference transport key is unavailable.", call. = FALSE)
  }
  identity <- .get_identity_keypair()
  envelope <- .psi_padded_seal_envelope(
    .psi_padded_ring63_raw(stage$output, "exact AND output share"),
    .psi_padded_and_envelope_context(state, chunk, state$self_peer),
    identity$identity_sk, reference_pk)
  stage$envelope <- envelope
  stage$status <- "sealed"
  state$and_chunks[[key]] <- stage
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(
    protocol = .DSVERT_PSI_PADDED_PROTOCOL,
    chunk_index = chunk$chunk_index, chunk_count = chunk$chunk_count,
    envelope = envelope)
}

.psi_padded_and_accept_impl <- function(ss, chunk_index, sender, envelope) {
  state <- .psi_padded_and_state(ss)
  contract <- state$contract
  if (!identical(state$self_peer, contract$reference_peer)) {
    stop("Padded PSI AND collection is restricted to the contract reference.",
         call. = FALSE)
  }
  chunk <- .psi_padded_and_chunk_contract(contract, chunk_index)
  sender <- .psi_padded_scalar(sender, "AND sender")
  if (is.null(state$and_received)) state$and_received <- list()
  key <- as.character(chunk$chunk_index)
  received <- state$and_received[[key]] %||% list()
  is_replay <- !is.null(received[[sender]])
  if (!is_replay) {
    expected_sender <- contract$compute_peers[[length(received) + 1L]]
    if (is.null(expected_sender) || !identical(sender, expected_sender)) {
      stop("Padded PSI rejected a reordered or substituted AND share.",
           call. = FALSE)
    }
  }
  sender_pk <- state$identity_pks[[sender]]
  if (is.null(sender_pk)) {
    stop("Padded PSI AND sender is not a pinned contract peer.",
         call. = FALSE)
  }
  payload <- .psi_padded_open_envelope(
    envelope, .psi_padded_and_envelope_context(state, chunk, sender),
    sender_pk, state$transport_sk, 8L * chunk$vector_len)
  encoded <- .psi_padded_ring63_b64(payload)
  if (is_replay) {
    if (!identical(received[[sender]], encoded)) {
      stop("Padded PSI rejected a conflicting duplicate AND share.",
           call. = FALSE)
    }
    return(list(protocol = .DSVERT_PSI_PADDED_PROTOCOL, accepted = TRUE,
                chunk_index = chunk$chunk_index,
                chunk_count = chunk$chunk_count))
  }
  received[[sender]] <- encoded
  state$and_received[[key]] <- received
  if (length(received) == 2L) {
    ordered <- received[contract$compute_peers]
    reconstructed <- .psi_padded_ring63_b64(.psi_padded_ring63_add_raw(
      .psi_padded_ring63_raw(ordered[[1L]]),
      .psi_padded_ring63_raw(ordered[[2L]])))
    comparison <- .psi_padded_ring63_decode_small(reconstructed, 1L)
    state$global_membership_chunks[[key]] <- as.integer(1L - comparison)
  }
  ss$.psi_padded_state <- state
  .psi_padded_state_commit(ss)
  list(protocol = .DSVERT_PSI_PADDED_PROTOCOL, accepted = TRUE,
       chunk_index = chunk$chunk_index, chunk_count = chunk$chunk_count)
}

#' @export
#' @noRd
psiPaddedANDStartDS <- function(chunk_index, session_id) {
  tryCatch(
    .psi_padded_and_start_impl(.S(session_id), chunk_index),
    error = function(e) stop("Padded PSI exact AND failed.", call. = FALSE))
}

#' @export
#' @noRd
psiPaddedANDFinalizeDS <- function(chunk_index, session_id,
                                  force_relay = FALSE) {
  tryCatch({
    ss <- .S(session_id)
    result <- .psi_padded_and_finalize_impl(ss, chunk_index)
    state <- .psi_padded_and_state(ss)
    chunk <- .psi_padded_and_chunk_contract(state$contract, chunk_index)
    c(list(
      protocol = .DSVERT_PSI_PADDED_PROTOCOL,
      chunk_index = chunk$chunk_index, chunk_count = chunk$chunk_count),
      .psi_padded_publish_envelope(
        ss, result$envelope,
        .psi_padded_and_envelope_context(state, chunk, state$self_peer),
        force_relay))
  }, error = function(e) stop("Padded PSI exact AND failed.",
                              call. = FALSE))
}

#' @export
#' @noRd
psiPaddedANDAcceptDS <- function(
    chunk_index, sender, envelope = "", relay_descriptor_b64url = "",
    session_id) {
  tryCatch({
    ss <- .S(session_id)
    state <- .psi_padded_and_state(ss)
    chunk <- .psi_padded_and_chunk_contract(state$contract, chunk_index)
    incoming <- .psi_padded_resolve_envelope(
      ss, envelope,
      .psi_padded_decode_relay_descriptor(relay_descriptor_b64url),
      .psi_padded_and_envelope_context(state, chunk, sender))
    .psi_padded_and_accept_impl(
      ss, chunk_index, sender, incoming)
  }, error = function(e) stop("Padded PSI exact AND failed.",
                              call. = FALSE))
}
