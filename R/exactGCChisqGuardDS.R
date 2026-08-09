# Purpose-bound exact count guard for the cross-server contingency producer.
# The analyst can orchestrate the opaque transcript, but cannot choose a source
# slot, destination slot, threshold, producer, or output shape.  Passing this
# guard never authorises an exact table opening: it only marks the immutable
# count-share vector as eligible for a future joint DP single opening.

.DSVERT_CHISQ_COUNT_KEY <- "k2_chisq_cross_count_shares"
.DSVERT_CHISQ_COUNT_SOURCE <- "k2_beaver_z"
.DSVERT_CHISQ_COUNT_PRODUCER <- "chisq.cross.count-vector.v1"
.DSVERT_CHISQ_GUARD_PURPOSE <- "chisq.cross.positive-cell-guard.v1"
.DSVERT_CHISQ_GUARD_VERSION <- "dsvert-chisq-cross-guard-v1"
.DSVERT_CHISQ_JOINT_CAPABILITY <- "joint_mpc_single_opening_v1"
.DSVERT_CHISQ_PRODUCT_PRODUCER <- "chisq.cross.cell-product.v1"
.DSVERT_CHISQ_PRODUCT_VERSION <- "dsvert-chisq-cross-cell-product-v1"

.exact_gc_chisq_digest <- function(value) {
  digest::digest(value, algo = "sha256", serialize = FALSE)
}

.exact_gc_chisq_public_hash <- function(value) {
  .exact_gc_vecmul_public_hash(value)
}

.exact_gc_chisq_product_source <- function(
    ss, variable, owner, self_name, peer_name, n, levels) {
  local <- identical(owner, self_name)
  key <- paste0(
    if (local) "k2_onehot_" else "k2_onehot_peer_", variable, "_fp")
  provenance <- ss$.dsvert_shared_onehot_provenance[[key]]
  expected_source <- if (local) "local" else "peer"
  expected_peer <- if (local) NULL else owner
  value <- ss[[key]]
  if (!is.list(provenance) ||
      !identical(provenance$version,
                 .DSVERT_SHARED_ONEHOT_PROVENANCE_VERSION) ||
      !identical(provenance$key, key) ||
      !identical(provenance$variable, variable) ||
      !identical(provenance$n, n) ||
      !identical(provenance$levels, levels) ||
      !identical(provenance$ring_bits, 63L) ||
      !identical(provenance$frac_bits, 20L) ||
      !identical(provenance$source, expected_source) ||
      !identical(provenance$peer_name, expected_peer) ||
      !identical(provenance$value_digest,
                 .dsvert_shared_onehot_digest(value))) {
    stop("The shared one-hot producer provenance is unavailable.",
         call. = FALSE)
  }
  .exact_gc_validate_residue_records(
    value, 63L, as.numeric(n) * levels,
    "purpose-bound shared one-hot vector")
  list(key = key, value = value)
}

.exact_gc_chisq_extract_column <- function(source, n, levels, index) {
  result <- .callMpcTool("k2-fp-extract-column", list(
    fp_data = source, n = n, k = levels, col = index - 1L,
    frac_bits = 20L, ring = "ring63"))$result
  .exact_gc_validate_residue_records(
    result, 63L, n, "purpose-bound one-hot column share")
  result
}

.exact_gc_chisq_product_prepare_impl <- function(
    row_variable, column_variable, row_server, column_server,
    row_index, column_index, n, row_levels, column_levels, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  row_variable <- .dsvert_typed_blob_storage_name(
    row_variable, "cross-contingency row variable")
  column_variable <- .dsvert_typed_blob_storage_name(
    column_variable, "cross-contingency column variable")
  row_server <- .dsvert_validate_logical_peer_name(row_server)
  column_server <- .dsvert_validate_logical_peer_name(column_server)
  if (identical(row_server, column_server)) {
    stop("Cross-contingency products require two distinct peers.",
         call. = FALSE)
  }
  n <- as.integer(.exact_gc_integer(
    n, "cross-contingency row count", 1, .Machine$integer.max))
  row_levels <- as.integer(.exact_gc_integer(
    row_levels, "cross-contingency row levels", 2, 4096))
  column_levels <- as.integer(.exact_gc_integer(
    column_levels, "cross-contingency column levels", 2, 4096))
  total_cells_numeric <- as.numeric(row_levels) * column_levels
  if (!is.finite(total_cells_numeric) || total_cells_numeric > 4096) {
    stop("Cross-contingency table exceeds the fixed exact-circuit domain.",
         call. = FALSE)
  }
  total_cells <- as.integer(total_cells_numeric)
  row_index <- as.integer(.exact_gc_integer(
    row_index, "cross-contingency row index", 1, row_levels))
  column_index <- as.integer(.exact_gc_integer(
    column_index, "cross-contingency column index", 1, column_levels))
  cell_index <- as.integer((row_index - 1L) * column_levels + column_index)
  .dsvert_guard_min_agg_count(n, "cross-contingency exact product")

  ss <- .S(session_id)
  parties <- .exact_gc_vecmul_party_context(ss)
  owners <- c(row_server, column_server)
  if (!setequal(owners, c(parties$self_name, parties$peer_name))) {
    stop("Cross-contingency owners do not match the pinned peer pair.",
         call. = FALSE)
  }
  counts <- ss$.exact_gc_chisq_counts
  expected_cell <- if (is.null(counts)) 1L else {
    if (!is.list(counts) || !identical(counts$status, "collecting") ||
        !identical(counts$total_cells, total_cells)) {
      stop("Cross-contingency count state cannot accept another product.",
           call. = FALSE)
    }
    counts$next_index
  }
  if (!identical(as.integer(expected_cell), cell_index)) {
    stop("Cross-contingency products must be prepared once in fixed order.",
         call. = FALSE)
  }

  row_source <- .exact_gc_chisq_product_source(
    ss, row_variable, row_server, parties$self_name, parties$peer_name,
    n, row_levels)
  column_source <- .exact_gc_chisq_product_source(
    ss, column_variable, column_server, parties$self_name, parties$peer_name,
    n, column_levels)
  context <- list(
    version = .DSVERT_CHISQ_PRODUCT_VERSION,
    session_id = session_id,
    peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    producer = .DSVERT_CHISQ_PRODUCT_PRODUCER,
    row_variable = row_variable, column_variable = column_variable,
    row_server = row_server, column_server = column_server,
    row_index = row_index, column_index = column_index,
    cell_index = cell_index, total_cells = total_cells,
    n = n, row_levels = row_levels, column_levels = column_levels,
    ring_bits = 63L, frac_bits = 20L)
  request_hash <- .exact_gc_chisq_public_hash(context)
  previous <- ss$.exact_gc_chisq_product
  if (!is.null(previous)) {
    if (identical(previous$status, "prepared") &&
        identical(previous$request_hash, request_hash)) {
      manifest <- ss$.exact_gc_vecmul_manifests[[previous$manifest_handle]]
      if (!is.list(manifest) || !identical(manifest$state, "fresh") ||
          !identical(.exact_gc_vecmul_value_digest(ss[[previous$x_key]]),
                     previous$x_digest) ||
          !identical(.exact_gc_vecmul_value_digest(ss[[previous$y_key]]),
                     previous$y_digest) ||
          !identical(.exact_gc_vecmul_value_digest(
                       ss[[previous$output_key]]), "absent")) {
        stop("Cross-contingency product retry changed state.", call. = FALSE)
      }
      .exact_gc_vecmul_validate_manifest_mac(ss, manifest)
      return(previous$public)
    }
    if (!identical(previous$status, "accumulated") ||
        !identical(previous$cell_index + 1L, cell_index)) {
      stop("Cross-contingency product state is already in use.",
           call. = FALSE)
    }
  }

  x_key <- "k2_beaver_x"
  y_key <- "k2_beaver_y"
  output_key <- .DSVERT_CHISQ_COUNT_SOURCE
  if (!is.null(ss[[x_key]]) || !is.null(ss[[y_key]]) ||
      !is.null(ss[[output_key]])) {
    stop("Cross-contingency exact product slots are already in use.",
         call. = FALSE)
  }
  installed <- FALSE
  on.exit(if (!installed) {
    ss[[x_key]] <- NULL
    ss[[y_key]] <- NULL
    ss$.exact_gc_chisq_product <- previous
  }, add = TRUE)
  ss[[x_key]] <- .exact_gc_chisq_extract_column(
    row_source$value, n, row_levels, row_index)
  ss[[y_key]] <- .exact_gc_chisq_extract_column(
    column_source$value, n, column_levels, column_index)
  purpose <- paste0(
    "chisq.cross.cell-product.", substr(request_hash, 1L, 24L), ".",
    sprintf("%04d", cell_index))
  stage <- list(
    version = .DSVERT_CHISQ_PRODUCT_VERSION,
    status = "preparing", request_hash = request_hash,
    context = context, purpose = purpose,
    cell_index = cell_index, total_cells = total_cells, n = n,
    x_key = x_key, y_key = y_key, output_key = output_key,
    x_digest = .exact_gc_vecmul_value_digest(ss[[x_key]]),
    y_digest = .exact_gc_vecmul_value_digest(ss[[y_key]]))
  ss$.exact_gc_chisq_product <- stage
  minted <- .exact_gc_vecmul_mint_manifest(
    ss = ss, session_id = session_id,
    producer = .DSVERT_CHISQ_PRODUCT_PRODUCER,
    purpose = purpose, total_n = n)
  manifest <- ss$.exact_gc_vecmul_manifests[[minted$manifest_handle]]
  plan <- manifest$plan
  public <- c(minted, list(
    producer = .DSVERT_CHISQ_PRODUCT_PRODUCER, purpose = purpose,
    request_hash = request_hash, cell_index = cell_index,
    total_cells = total_cells,
    truncated_bound = plan$truncated_bound,
    rounding_mode = plan$rounding_mode,
    raw_product_headroom = plan$raw_product_headroom,
    output_headroom = plan$output_headroom))
  stage$status <- "prepared"
  stage$manifest_handle <- minted$manifest_handle
  stage$public <- public
  ss$.exact_gc_chisq_product <- stage
  installed <- TRUE
  public
}

#' Prepare one purpose-bound exact cross-contingency cell product (AGGREGATE)
#'
#' The caller selects public variables, owners and cell coordinates only. The
#' server derives both one-hot share slots, extracts the fixed columns, fixes
#' Ring63/f20 bounds and destination, and returns a one-shot opaque manifest.
#'
#' @keywords internal
exactGCChisqProductPrepareDS <- function(
    row_variable, column_variable, row_server, column_server,
    row_index, column_index, n, row_levels, column_levels, session_id) {
  tryCatch(
    .exact_gc_chisq_product_prepare_impl(
      row_variable, column_variable, row_server, column_server,
      row_index, column_index, n, row_levels, column_levels, session_id),
    error = function(e) stop(
      "Cross-contingency exact product preparation failed.", call. = FALSE))
}

.exact_gc_chisq_count_context <- function(session_id, total_cells) {
  list(
    version = "dsvert-chisq-cross-count-vector-v1",
    session_id = session_id,
    producer = .DSVERT_CHISQ_COUNT_PRODUCER,
    purpose = .DSVERT_CHISQ_COUNT_KEY,
    total_cells = as.integer(total_cells),
    ring_bits = 63L,
    frac_bits = 20L)
}

.exact_gc_chisq_decode_standard <- function(value, what) {
  value <- .exact_gc_scalar(value, what)
  if (!grepl(
      "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$",
      value)) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  decoded <- tryCatch(jsonlite::base64_dec(value), error = function(e) NULL)
  canonical <- if (is.null(decoded)) NULL else
    gsub("[\r\n]", "", jsonlite::base64_enc(decoded))
  if (is.null(decoded) || !identical(canonical, value)) {
    stop("Invalid or non-canonical ", what, ".", call. = FALSE)
  }
  decoded
}

.exact_gc_chisq_accumulate_count_impl <- function(
    cell_index, total_cells, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  cell_index <- as.integer(.exact_gc_integer(
    cell_index, "cross-contingency cell index", 1, 4096))
  total_cells <- as.integer(.exact_gc_integer(
    total_cells, "cross-contingency cell count", 1, 4096))
  if (cell_index > total_cells) {
    stop("Cross-contingency cell index exceeds its fixed domain.",
         call. = FALSE)
  }
  ss <- .S(session_id)
  state <- ss$.exact_gc_chisq_counts
  if (!is.null(state) && identical(state$last_index, cell_index)) {
    current <- ss[[.DSVERT_CHISQ_COUNT_KEY]]
    product <- ss$.exact_gc_chisq_product
    if (!identical(state$total_cells, total_cells) ||
        !is.list(product) || !identical(product$status, "accumulated") ||
        !identical(product$cell_index, cell_index) ||
        !identical(product$total_cells, total_cells) ||
        !identical(product$source_digest, state$last_source_digest) ||
        !is.null(ss[[.DSVERT_CHISQ_COUNT_SOURCE]]) ||
        !identical(state$count_digest,
                   .exact_gc_chisq_digest(current))) {
      stop("Conflicting retry for cross-contingency count accumulation.",
           call. = FALSE)
    }
    return(list(stored = TRUE, state = state$status,
                cell_index = cell_index, total_cells = total_cells))
  }
  product <- ss$.exact_gc_chisq_product
  if (!is.list(product) || !identical(product$status, "prepared") ||
      !identical(product$cell_index, cell_index) ||
      !identical(product$total_cells, total_cells) ||
      !identical(product$output_key, .DSVERT_CHISQ_COUNT_SOURCE)) {
    stop("The purpose-bound exact cell product is unavailable.",
         call. = FALSE)
  }
  manifest <- ss$.exact_gc_vecmul_manifests[[product$manifest_handle]]
  if (!is.list(manifest)) {
    stop("The exact cell-product manifest is unavailable.", call. = FALSE)
  }
  .exact_gc_vecmul_validate_manifest_mac(ss, manifest)
  input_stage <- ss$.exact_gc_vecmul_input_stages[[manifest$claimed_batch]]
  source <- ss[[.DSVERT_CHISQ_COUNT_SOURCE]]
  source_digest <- .exact_gc_chisq_digest(source)
  if (!identical(manifest$state, "consumed") ||
      !identical(manifest$producer, .DSVERT_CHISQ_PRODUCT_PRODUCER) ||
      !identical(manifest$purpose, product$purpose) ||
      !is.list(input_stage) || !identical(input_stage$state, "complete") ||
      !identical(input_stage$manifest_handle, product$manifest_handle) ||
      !identical(input_stage$output_key, .DSVERT_CHISQ_COUNT_SOURCE) ||
      !identical(input_stage$output_digest, source_digest)) {
    stop("The exact cell product was not bilaterally committed.",
         call. = FALSE)
  }
  .exact_gc_validate_residue_records(
    source, 63L, product$n, "cross-contingency exact product share")
  .dsvert_guard_min_agg_count(
    product$n, "cross-contingency cell reduction")

  if (is.null(state)) {
    if (cell_index != 1L || !is.null(ss[[.DSVERT_CHISQ_COUNT_KEY]])) {
      stop("Cross-contingency count accumulation must start at cell one.",
           call. = FALSE)
    }
    context <- .exact_gc_chisq_count_context(session_id, total_cells)
    state <- list(
      version = context$version,
      status = "collecting",
      total_cells = total_cells,
      next_index = 1L,
      last_index = 0L,
      last_source_digest = NULL,
      count_digest = "absent",
      public_context = context,
      public_context_hash = .exact_gc_chisq_public_hash(context))
    ss$.exact_gc_chisq_guard_manifests <- list()
    ss$.exact_gc_chisq_guard_stages <- list()
    ss$.exact_gc_chisq_guard_authorization <- NULL
    ss$.exact_gc_chisq_joint_release <- NULL
  }
  if (!identical(state$status, "collecting") ||
      !identical(state$total_cells, total_cells) ||
      !identical(state$next_index, cell_index)) {
    stop("Cross-contingency cells must be accumulated once in fixed order.",
         call. = FALSE)
  }

  scalar <- .callMpcTool("k2-fp-sum", list(
    fp_data = source, ring = "ring63"))$sum_fp
  scalar_raw <- .exact_gc_validate_residue_records(
    scalar, 63L, 1L, "cross-contingency scalar count share")
  previous_raw <- if (cell_index == 1L) raw(0) else
    .exact_gc_validate_residue_records(
      ss[[.DSVERT_CHISQ_COUNT_KEY]], 63L, cell_index - 1L,
      "cross-contingency accumulated count shares")
  count_share <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(c(previous_raw, scalar_raw)))
  .exact_gc_validate_residue_records(
    count_share, 63L, cell_index,
    "cross-contingency accumulated count shares")
  ss[[.DSVERT_CHISQ_COUNT_KEY]] <- count_share
  state$last_index <- cell_index
  state$last_source_digest <- source_digest
  state$next_index <- cell_index + 1L
  state$count_digest <- .exact_gc_chisq_digest(count_share)
  if (cell_index == total_cells) state$status <- "complete"
  ss$.exact_gc_chisq_counts <- state
  product$status <- "accumulated"
  product$source_digest <- source_digest
  product$count_digest <- state$count_digest
  ss$.exact_gc_chisq_product <- product
  ss[[.DSVERT_CHISQ_COUNT_SOURCE]] <- NULL
  ss[[product$x_key]] <- NULL
  ss[[product$y_key]] <- NULL
  list(stored = TRUE, state = state$status,
       cell_index = cell_index, total_cells = total_cells)
}

#' Accumulate one fixed cross-contingency cell share (AGGREGATE)
#'
#' @keywords internal
k2ChisqCrossAccumulateCountDS <- function(
    cell_index, total_cells, session_id) {
  tryCatch(
    .exact_gc_chisq_accumulate_count_impl(
      cell_index, total_cells, session_id),
    error = function(e) stop(
      "Cross-contingency protected accumulation failed.", call. = FALSE))
}

.exact_gc_chisq_threshold_fp <- function() {
  threshold <- as.numeric(.exact_gc_count_threshold())
  # nfilter.tab is bounded by .Machine$integer.max, so scaling by 2^20 stays
  # below 2^51 and is represented exactly by an IEEE-754 double.
  sprintf("%.0f", threshold * 2^20)
}

.exact_gc_chisq_manifest_mac <- function(ss, manifest) {
  secret <- .key_get("transport_sk", ss)
  if (!is.character(secret) || length(secret) != 1L || !nzchar(secret)) {
    stop("Exact-gc transport secret is unavailable.", call. = FALSE)
  }
  body <- manifest[setdiff(names(manifest), "mac")]
  digest::hmac(
    secret, .exact_gc_chisq_public_hash(body),
    algo = "sha256", serialize = FALSE)
}

.exact_gc_chisq_validate_manifest <- function(
    ss, manifest_handle, session_id) {
  if (!is.character(manifest_handle) || length(manifest_handle) != 1L ||
      is.na(manifest_handle) ||
      !grepl(.DSVERT_EXACT_GC_VECMUL_HANDLE_RE, manifest_handle)) {
    stop("Invalid cross-contingency guard manifest handle.", call. = FALSE)
  }
  manifest <- ss$.exact_gc_chisq_guard_manifests[[manifest_handle]]
  if (!is.list(manifest) ||
      !identical(manifest$version, .DSVERT_CHISQ_GUARD_VERSION) ||
      !identical(manifest$session_id, session_id)) {
    stop("Cross-contingency guard manifest is unavailable.", call. = FALSE)
  }
  expected <- .exact_gc_chisq_manifest_mac(ss, manifest)
  if (!is.character(manifest$mac) || !identical(manifest$mac, expected)) {
    stop("Cross-contingency guard manifest authentication failed.",
         call. = FALSE)
  }
  manifest
}

.exact_gc_chisq_prepare_impl <- function(session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  .exact_gc_vecmul_party_context(ss)
  counts <- ss$.exact_gc_chisq_counts
  share <- ss[[.DSVERT_CHISQ_COUNT_KEY]]
  if (!is.list(counts) || !identical(counts$status, "complete") ||
      !identical(counts$count_digest, .exact_gc_chisq_digest(share))) {
    stop("The purpose-bound cross-contingency count vector is unavailable.",
         call. = FALSE)
  }
  .exact_gc_validate_residue_records(
    share, 63L, counts$total_cells,
    "purpose-bound cross-contingency count shares")
  threshold <- .exact_gc_chisq_threshold_fp()
  public <- list(
    version = .DSVERT_CHISQ_GUARD_VERSION,
    session_id = session_id,
    producer = .DSVERT_CHISQ_COUNT_PRODUCER,
    purpose = .DSVERT_CHISQ_GUARD_PURPOSE,
    source_context_hash = counts$public_context_hash,
    peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    ring_bits = 63L, frac_bits = 0L,
    source_frac_bits = 20L,
    vector_len = counts$total_cells,
    threshold = threshold,
    privacy_min = as.integer(as.numeric(.exact_gc_count_threshold())))
  context_hash <- .exact_gc_chisq_public_hash(public)
  handle <- .exact_gc_vecmul_handle()
  now <- as.numeric(Sys.time())
  manifest <- c(public, list(
    handle = handle, context_hash = context_hash,
    source_digest = counts$count_digest,
    created_at = now, expires_at = now + .exact_gc_ttl_seconds(),
    state = "fresh", operation_id = NULL))
  manifest$mac <- .exact_gc_chisq_manifest_mac(ss, manifest)
  if (is.null(ss$.exact_gc_chisq_guard_manifests)) {
    ss$.exact_gc_chisq_guard_manifests <- list()
  }
  ss$.exact_gc_chisq_guard_manifests[[handle]] <- manifest
  list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    manifest_handle = handle,
    context_hash = context_hash,
    producer = public$producer,
    purpose = public$purpose,
    source_context_hash = public$source_context_hash,
    ring_bits = public$ring_bits,
    frac_bits = public$frac_bits,
    source_frac_bits = public$source_frac_bits,
    vector_len = public$vector_len,
    threshold = public$threshold,
    privacy_min = public$privacy_min)
}

#' Prepare the purpose-bound cross-contingency count guard (AGGREGATE)
#'
#' @keywords internal
exactGCChisqGuardPrepareDS <- function(session_id) {
  tryCatch(
    .exact_gc_chisq_prepare_impl(session_id),
    error = function(e) stop("Cross-contingency exact guard failed.",
                             call. = FALSE))
}

.exact_gc_chisq_operation_keys <- function(operation_id) {
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  suffix <- sub("^op_", "", operation_id)
  list(source = paste0("exact_gc_in_", suffix),
       output = paste0("exact_gc_out_", suffix))
}

.exact_gc_chisq_start_impl <- function(
    manifest_handle, operation_id, session_id,
    binary = .findMpcBinary()) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  ss <- .S(session_id)
  manifest <- .exact_gc_chisq_validate_manifest(
    ss, manifest_handle, session_id)
  counts <- ss$.exact_gc_chisq_counts
  share <- ss[[.DSVERT_CHISQ_COUNT_KEY]]
  snapshot_valid <- is.list(counts) &&
    identical(counts$status, "complete") &&
    identical(counts$public_context_hash, manifest$source_context_hash) &&
    identical(.exact_gc_chisq_digest(share), manifest$source_digest) &&
    identical(ss$.exact_gc_peer_binding_digest,
              manifest$peer_binding_digest)
  if (!isTRUE(snapshot_valid)) {
    stop("The cross-contingency count snapshot changed before guard start.",
         call. = FALSE)
  }
  if (identical(manifest$state, "claimed") &&
      identical(manifest$operation_id, operation_id)) {
    stage <- ss$.exact_gc_chisq_guard_stages[[operation_id]]
    if (is.null(stage) || !identical(stage$manifest_handle, manifest_handle)) {
      stop("The cross-contingency guard retry is inconsistent.",
           call. = FALSE)
    }
  } else {
    if (!identical(manifest$state, "fresh") ||
        !is.numeric(manifest$expires_at) ||
        as.numeric(Sys.time()) > manifest$expires_at) {
      stop("The cross-contingency guard manifest expired or was consumed.",
           call. = FALSE)
    }
    keys <- .exact_gc_chisq_operation_keys(operation_id)
    .exact_gc_stage_share(
      ss, keys$source, share, 63L, manifest$vector_len,
      .DSVERT_CHISQ_COUNT_PRODUCER, "count-guard",
      .DSVERT_CHISQ_GUARD_PURPOSE, 0L, "xor-bit-share")
    if (is.null(ss$.exact_gc_chisq_guard_stages)) {
      ss$.exact_gc_chisq_guard_stages <- list()
    }
    ss$.exact_gc_chisq_guard_stages[[operation_id]] <- list(
      state = "staged", manifest_handle = manifest_handle,
      operation_id = operation_id,
      manifest_context_hash = manifest$context_hash,
      source_context_hash = manifest$source_context_hash,
      source_digest = manifest$source_digest,
      vector_len = manifest$vector_len,
      threshold = manifest$threshold,
      result_context_hash = NULL,
      local_share = NULL,
      peer_blob = NULL)
    manifest$state <- "claimed"
    manifest$operation_id <- operation_id
    manifest$mac <- .exact_gc_chisq_manifest_mac(ss, manifest)
    ss$.exact_gc_chisq_guard_manifests[[manifest_handle]] <- manifest
  }
  keys <- .exact_gc_chisq_operation_keys(operation_id)
  .exact_gc_init_impl(
    ss, session_id, operation_id, .DSVERT_EXACT_GC_CAPABILITY,
    keys$source, keys$output, "count-guard", 63L, 0L,
    manifest$vector_len, .DSVERT_CHISQ_GUARD_PURPOSE,
    threshold = manifest$threshold, binary = binary)
}

#' Start the purpose-bound cross-contingency count guard (AGGREGATE)
#'
#' @keywords internal
exactGCChisqGuardStartDS <- function(
    manifest_handle, operation_id, session_id) {
  tryCatch(
    .exact_gc_chisq_start_impl(
      manifest_handle, operation_id, session_id),
    error = function(e) stop("Cross-contingency exact guard failed.",
                             call. = FALSE))
}

.exact_gc_chisq_peer_context <- function(
    ss, session_id, manifest, operation_id, result_context_hash,
    outbound) {
  parties <- .exact_gc_vecmul_party_context(ss)
  own_id <- .dsvert_relay_peer_id(.key_get("identity_pk", ss))
  peer_id <- .dsvert_relay_peer_id(
    ss$.exact_gc_peer_identity_pks[[parties$peer_name]])
  list(
    version = "dsvert-chisq-cross-guard-peer-v1",
    session_id = session_id,
    operation_id = operation_id,
    manifest_context_hash = manifest$context_hash,
    source_context_hash = manifest$source_context_hash,
    result_context_hash = result_context_hash,
    producer = .DSVERT_CHISQ_COUNT_PRODUCER,
    purpose = .DSVERT_CHISQ_GUARD_PURPOSE,
    ring_bits = 63L,
    source_frac_bits = 20L,
    vector_len = manifest$vector_len,
    threshold = manifest$threshold,
    peer_binding_digest = ss$.exact_gc_peer_binding_digest,
    sender_name = if (isTRUE(outbound)) parties$self_name else parties$peer_name,
    recipient_name = if (isTRUE(outbound)) parties$peer_name else parties$self_name,
    sender_peer_id = if (isTRUE(outbound)) own_id else peer_id,
    recipient_peer_id = if (isTRUE(outbound)) peer_id else own_id)
}

.exact_gc_chisq_finalize_impl <- function(
    manifest_handle, operation_id, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  ss <- .S(session_id)
  manifest <- .exact_gc_chisq_validate_manifest(
    ss, manifest_handle, session_id)
  if (!manifest$state %in% c("claimed", "consumed") ||
      !identical(manifest$operation_id, operation_id)) {
    stop("The cross-contingency guard manifest is not claimable.",
         call. = FALSE)
  }
  stage <- ss$.exact_gc_chisq_guard_stages[[operation_id]]
  if (is.null(stage) || !identical(stage$manifest_handle, manifest_handle)) {
    stop("The cross-contingency guard stage is unavailable.", call. = FALSE)
  }
  if (identical(stage$state, "finalized")) {
    return(list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
                state = "sealed", peer_blob = stage$peer_blob))
  }
  if (identical(stage$state, "staged")) {
    keys <- .exact_gc_chisq_operation_keys(operation_id)
    state <- .exact_gc_operation_state(ss, operation_id)
    .exact_gc_refresh(ss, state)
    output <- .exact_gc_consume_output(
      ss, keys$output, operation_id, "xor-bit-share", "count-guard",
      .DSVERT_CHISQ_GUARD_PURPOSE, 63L, 0L, manifest$vector_len,
      .DSVERT_CHISQ_COUNT_PRODUCER)
    local_share <- .exact_gc_standard_b64_raw(
      output$share, 1L, "cross-contingency guard share")
    if (!as.integer(local_share[[1L]]) %in% 0:1) {
      stop("The cross-contingency guard returned a non-canonical share.",
           call. = FALSE)
    }
    # Persist the consumed output before transport sealing.  If sealing or the
    # DSI response fails transiently, an identical retry resumes from this
    # private state instead of attempting to consume the one-shot output again.
    stage$state <- "output-consumed"
    stage$result_context_hash <- output$context_hash
    stage$local_share <- output$share
    ss$.exact_gc_chisq_guard_stages[[operation_id]] <- stage
  } else if (!identical(stage$state, "output-consumed")) {
    stop("The cross-contingency guard stage has an invalid state.",
         call. = FALSE)
  }
  local_share <- .exact_gc_standard_b64_raw(
    stage$local_share, 1L, "cross-contingency guard share")
  if (!as.integer(local_share[[1L]]) %in% 0:1) {
    stop("The cross-contingency guard returned a non-canonical share.",
         call. = FALSE)
  }
  context <- .exact_gc_chisq_peer_context(
    ss, session_id, manifest, operation_id, stage$result_context_hash,
    outbound = TRUE)
  peer_blob <- .exact_gc_checked_mul_seal(
    ss, c(context, list(guard_share = stage$local_share)))
  stage$state <- "finalized"
  stage$peer_blob <- peer_blob
  ss$.exact_gc_chisq_guard_stages[[operation_id]] <- stage
  manifest$state <- "consumed"
  manifest$mac <- .exact_gc_chisq_manifest_mac(ss, manifest)
  ss$.exact_gc_chisq_guard_manifests[[manifest_handle]] <- manifest
  list(capability_id = .DSVERT_EXACT_GC_CAPABILITY,
       state = "sealed", peer_blob = peer_blob)
}

#' Seal the aggregate cross-contingency guard share to its peer (AGGREGATE)
#'
#' @keywords internal
exactGCChisqGuardFinalizeDS <- function(
    manifest_handle, operation_id, session_id) {
  tryCatch(
    .exact_gc_chisq_finalize_impl(
      manifest_handle, operation_id, session_id),
    error = function(e) stop("Cross-contingency exact guard failed.",
                             call. = FALSE))
}

.exact_gc_chisq_authorize_impl <- function(
    manifest_handle, operation_id, peer_blob, session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  ss <- .S(session_id)
  manifest <- .exact_gc_chisq_validate_manifest(
    ss, manifest_handle, session_id)
  stage <- ss$.exact_gc_chisq_guard_stages[[operation_id]]
  payload_digest <- .exact_gc_chisq_digest(peer_blob)
  previous <- ss$.exact_gc_chisq_guard_authorization
  if (!is.null(previous)) {
    if (!identical(previous$operation_id, operation_id) ||
        !identical(previous$peer_payload_digest, payload_digest)) {
      stop("Conflicting cross-contingency guard authorization retry.",
           call. = FALSE)
    }
    result <- list(
      capability_id = .DSVERT_EXACT_GC_CAPABILITY,
      state = previous$state,
      authorized = previous$authorized,
      required_capability = .DSVERT_CHISQ_JOINT_CAPABILITY)
    if (!isTRUE(previous$authorized)) {
      result$failure_code <- "non_identifiable"
    }
    return(result)
  }
  if (!identical(manifest$state, "consumed") ||
      !identical(manifest$operation_id, operation_id) ||
      is.null(stage) || !identical(stage$state, "finalized") ||
      is.null(stage$local_share) || is.null(stage$peer_blob)) {
    stop("The cross-contingency guard result is unavailable.", call. = FALSE)
  }
  expected <- .exact_gc_chisq_peer_context(
    ss, session_id, manifest, operation_id, stage$result_context_hash,
    outbound = FALSE)
  opened <- .exact_gc_checked_mul_open_peer(ss, peer_blob)
  body <- opened$body
  required <- c(names(expected), "guard_share")
  if (!is.list(body) || !identical(sort(names(body)), sort(required)) ||
      !identical(
        .exact_gc_checked_mul_context_digest(body[names(expected)]),
        .exact_gc_checked_mul_context_digest(expected))) {
    stop("Invalid cross-contingency peer guard context.", call. = FALSE)
  }
  peer_identity <- ss$.exact_gc_peer_identity_pks[[expected$sender_name]]
  if (is.null(peer_identity) || !.verify_peer_identity(
      .base64url_to_base64(opened$body_token), peer_identity,
      .base64url_to_base64(opened$signature))) {
    stop("Invalid cross-contingency peer guard signature.", call. = FALSE)
  }
  peer_share <- .exact_gc_standard_b64_raw(
    body$guard_share, 1L, "cross-contingency peer guard share")
  local_share <- .exact_gc_standard_b64_raw(
    stage$local_share, 1L, "cross-contingency local guard share")
  if (!as.integer(peer_share[[1L]]) %in% 0:1 ||
      !as.integer(local_share[[1L]]) %in% 0:1) {
    stop("Invalid cross-contingency guard share.", call. = FALSE)
  }
  authorized <- bitwXor(as.integer(peer_share[[1L]]),
                        as.integer(local_share[[1L]])) == 1L
  counts <- ss$.exact_gc_chisq_counts
  if (!is.list(counts) || !identical(counts$status, "complete") ||
      !identical(counts$count_digest,
                 .exact_gc_chisq_digest(ss[[.DSVERT_CHISQ_COUNT_KEY]])) ||
      !identical(counts$public_context_hash,
                 manifest$source_context_hash)) {
    stop("The guarded cross-contingency count snapshot changed.",
         call. = FALSE)
  }
  authorization <- list(
    version = "dsvert-chisq-cross-guard-authorization-v1",
    state = if (authorized) "guard_passed_waiting_joint_dp" else
      "guard_rejected",
    authorized = authorized,
    failure_code = if (authorized) "" else "non_identifiable",
    operation_id = operation_id,
    manifest_context_hash = manifest$context_hash,
    source_context_hash = manifest$source_context_hash,
    source_digest = counts$count_digest,
    peer_payload_digest = payload_digest,
    required_capability = .DSVERT_CHISQ_JOINT_CAPABILITY)
  ss$.exact_gc_chisq_guard_authorization <- authorization
  ss$.exact_gc_chisq_joint_release <- if (authorized) list(
    version = "dsvert-joint-opening-input-v1",
    state = "prepared",
    capability_id = .DSVERT_CHISQ_JOINT_CAPABILITY,
    policy_scope = "joint_mpc_single_opening",
    producer = .DSVERT_CHISQ_COUNT_PRODUCER,
    purpose = .DSVERT_CHISQ_COUNT_KEY,
    source_context_hash = manifest$source_context_hash,
    source_digest = counts$count_digest,
    vector_len = counts$total_cells,
    ring_bits = 63L,
    frac_bits = 20L,
    guard_operation_id = operation_id,
    guard_context_hash = stage$result_context_hash) else NULL
  stage$local_share <- NULL
  ss$.exact_gc_chisq_guard_stages[[operation_id]] <- stage
  result <- list(
    capability_id = .DSVERT_EXACT_GC_CAPABILITY,
    state = authorization$state,
    authorized = authorized,
    required_capability = .DSVERT_CHISQ_JOINT_CAPABILITY)
  if (!authorized) result$failure_code <- "non_identifiable"
  result
}

#' Verify the peer-only aggregate guard result (AGGREGATE)
#'
#' A successful guard leaves the exact count vector server-side and marks it
#' only for a future joint DP opening. It does not create a read capability.
#'
#' @keywords internal
exactGCChisqGuardAuthorizeDS <- function(
    manifest_handle, operation_id, peer_blob, session_id) {
  tryCatch(
    .exact_gc_chisq_authorize_impl(
      manifest_handle, operation_id, peer_blob, session_id),
    error = function(e) stop("Cross-contingency exact guard failed.",
                             call. = FALSE))
}

# Internal fail-closed rollback for a partially completed count guard.  The
# immutable count vector stays server-private, but every operation-scoped
# source, result, sealed bit share and release authorization is invalidated.
.exact_gc_chisq_abort <- function(ss, operation_id, state = NULL) {
  if (!is.environment(ss)) stop("Invalid exact-gc session state.", call. = FALSE)
  operation_id <- .dsvert_relay_validate_operation_id(operation_id)
  stage <- ss$.exact_gc_chisq_guard_stages[[operation_id]]
  if (is.null(stage)) return(invisible(FALSE))

  if (!is.null(state)) {
    .exact_gc_abort_state(ss, state, abort_complete = TRUE)
  }
  keys <- .exact_gc_chisq_operation_keys(operation_id)
  if (!is.null(ss$.exact_gc_inputs)) ss$.exact_gc_inputs[[keys$source]] <- NULL
  if (!is.null(ss$.exact_gc_outputs)) ss$.exact_gc_outputs[[keys$output]] <- NULL

  manifest_handle <- stage$manifest_handle
  manifest <- ss$.exact_gc_chisq_guard_manifests[[manifest_handle]]
  if (is.list(manifest)) {
    manifest$state <- "aborted"
    manifest$operation_id <- operation_id
    manifest$mac <- tryCatch(
      .exact_gc_chisq_manifest_mac(ss, manifest), error = function(e) NULL)
    if (is.null(manifest$mac)) {
      ss$.exact_gc_chisq_guard_manifests[[manifest_handle]] <- NULL
    } else {
      ss$.exact_gc_chisq_guard_manifests[[manifest_handle]] <- manifest
    }
  }
  stage$state <- "aborted"
  stage$local_share <- NULL
  stage$peer_blob <- NULL
  ss$.exact_gc_chisq_guard_stages[[operation_id]] <- stage

  authorization <- ss$.exact_gc_chisq_guard_authorization
  if (is.list(authorization) &&
      identical(authorization$operation_id, operation_id)) {
    authorization$state <- "aborted"
    authorization$authorized <- FALSE
    ss$.exact_gc_chisq_guard_authorization <- authorization
    ss$.exact_gc_chisq_joint_release <- NULL
  }
  invisible(TRUE)
}

#' Finalize the cross-contingency vector without opening it (AGGREGATE)
#'
#' @return A typed unavailable receipt until the attested joint DP single
#'   opening capability is installed. No share or statistic is returned.
#' @keywords internal
exactGCChisqJointReleaseDS <- function(session_id) {
  session_id <- .dsvert_relay_validate_session_id(session_id)
  ss <- .S(session_id)
  prepared <- ss$.exact_gc_chisq_joint_release
  counts <- ss$.exact_gc_chisq_counts
  valid <- is.list(prepared) && identical(prepared$state, "prepared") &&
    identical(prepared$capability_id, .DSVERT_CHISQ_JOINT_CAPABILITY) &&
    is.list(counts) && identical(counts$status, "complete") &&
    identical(prepared$source_digest, counts$count_digest) &&
    identical(counts$count_digest,
              .exact_gc_chisq_digest(ss[[.DSVERT_CHISQ_COUNT_KEY]]))
  if (!isTRUE(valid)) {
    stop("The purpose-bound cross-contingency release is unavailable.",
         call. = FALSE)
  }
  list(
    released = FALSE,
    state = "joint_mpc_single_opening_required",
    reason = "required_capability_unavailable",
    capability_id = .DSVERT_CHISQ_JOINT_CAPABILITY,
    policy_scope = "joint_mpc_single_opening",
    producer = .DSVERT_CHISQ_COUNT_PRODUCER,
    purpose = .DSVERT_CHISQ_COUNT_KEY,
    vector_len = prepared$vector_len,
    ring_bits = prepared$ring_bits,
    frac_bits = prepared$frac_bits)
}
