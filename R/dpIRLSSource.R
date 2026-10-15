# Custodian-only source binding for the signed two-owner person ABI.
# No source, presence, validity or diagnostic count is returned through DSI.
.DSVERT_DP_IRLS_SOURCE_ABI <- "signed-person-q16-two-owner-valid-v1"

.dsvert_dp_irls_conversion_certificate <- function() list(
  version = "dsvert-irls-binary64-q16-conversion-v1",
  input = "finite-IEEE754-binary64-exact-rational-v1",
  bounds = "signed-real-closed-interval-before-rounding-v1",
  rounding = "nearest-even-v1", fraction_bits = "16",
  absolute_error = list(d = "131072", n = "1"),
  failure_probability = list(d = "1", n = "0"),
  invalid = "zero-person-via-protected-owner-validity-and-v1")

.dsvert_dp_irls_encode_scalar <- function(value, bounds, integer = FALSE) {
  bad <- list(value = "0", valid = FALSE)
  if (!(is.double(value) || is.integer(value)) || is.object(value) ||
      length(value) != 1L || is.na(value) || !is.finite(value)) return(bad)
  # GMP's double conversion is exact (including subnormals). No decimal
  # formatting or floating multiplication occurs before rounding.
  q <- gmp::as.bigq(value)
  if (q < .dsvert_dp_irls_bigq(bounds$lower) ||
      q > .dsvert_dp_irls_bigq(bounds$upper)) return(bad)
  if (integer) {
    if (gmp::denominator(q) != 1) return(bad)
    return(list(value = as.character(gmp::numerator(q)), valid = TRUE))
  }
  q <- q * 65536L
  n <- gmp::numerator(q); d <- gmp::denominator(q)
  z <- n %/% d; remainder <- n - z * d
  if (2L * remainder > d || (2L * remainder == d && z %% 2L != 0)) z <- z + 1L
  list(value = as.character(z), valid = TRUE)
}

.dsvert_dp_irls_source_message <- function(body) charToRaw(paste0(
  "dsvert-v3-irls-authenticated-source-v1|", .dsvert_dp_irls_state_json(body)))

.dsvert_dp_irls_source_seal <- function(contract, owner, data_by_source,
                                        identity_sk) {
  contract <- .dsvert_dp_irls_contract_normalize(contract)
  pair <- unlist(contract$privacy_source$computation_peers, use.names = FALSE)
  if (!owner %in% pair || !is.list(data_by_source) ||
      is.null(names(data_by_source)) || anyDuplicated(names(data_by_source)))
    .dsvert_dp_irls_fail("custodian source binding")
  columns <- Filter(function(z) z$owner == owner, contract$estimand$columns)
  sources <- unique(vapply(columns, `[[`, character(1L), "source_id"))
  if (!length(sources) || !setequal(names(data_by_source), sources))
    .dsvert_dp_irls_fail("custodian source coverage")
  records <- list(); frozen <- list(); alignment <- NULL
  for (source in sources) {
    data <- data_by_source[[source]]
    attestation <- .psi_padded_validate_persistent_attestation(data)
    manifest <- .psi_validate_alignment_manifest(data)
    signed <- contract$privacy_source$closure$dependencies[[
      match(source, unlist(contract$privacy_source$source_ids, use.names = FALSE))]]
    if (is.null(signed) || signed$source_identity != contract$privacy_source$peer_pins[[owner]] ||
        signed$dependency$provenance_kind != "padded_psi" ||
        !identical(.dsvert_dp_irls_json(signed$dependency$authorization_epochs),
                   .dsvert_dp_irls_json(attestation$authorization_epochs)) ||
        attestation$alignment_purpose != contract$privacy_source$alignment_purpose ||
        !setequal(attestation$compute_peers, pair) ||
        nrow(data) > as.integer(contract$privacy_source$capacity))
      .dsvert_dp_irls_fail("frozen PSI epochs or person slots")
    raw_manifest <- attr(data, .PSI_ALIGNMENT_ATTRIBUTE, exact = TRUE)
    if (!is.null(alignment) && !identical(alignment, raw_manifest$hash))
      .dsvert_dp_irls_fail("source person-slot mismatch")
    alignment <- raw_manifest$hash
    wanted <- vapply(Filter(function(z) z$source_id == source, columns),
                     `[[`, character(1L), "column_id")
    if (!all(wanted %in% names(data))) .dsvert_dp_irls_fail("authorized source column")
    # Copy the authorized frozen frame before future analyst assignments can
    # alter the original R symbol. All later reads authenticate this snapshot.
    frozen[[source]] <- unserialize(serialize(data, NULL, version = 3L))
    records[[source]] <- list(dependency = signed,
      snapshot_sha256 = digest::digest(serialize(frozen[[source]], NULL, version = 3L),
        algo = "sha256", serialize = FALSE))
  }
  body <- list(version = "dsvert-v3-irls-authenticated-source-v1",
    root = .dsvert_dp_irls_root(contract), owner = owner,
    source_abi = .DSVERT_DP_IRLS_SOURCE_ABI,
    conversion = .dsvert_dp_irls_conversion_certificate(), records = records,
    # Private: this equality binding is reconstructed only in the circuit.
    person_slot_binding = alignment)
  signature <- .dsvert_relay_sign_message(.dsvert_dp_irls_source_message(body), identity_sk)
  if (!isTRUE(.dsvert_relay_verify_message(.dsvert_dp_irls_source_message(body),
        contract$privacy_source$peer_pins[[owner]], signature)))
    .dsvert_dp_irls_fail("custodian source identity")
  list(body = body, signature = signature, frozen = frozen)
}

.dsvert_dp_irls_ring128_bytes <- function(values) {
  out <- raw(16L * length(values)); modulus <- gmp::as.bigz(2)^128L
  for (i in seq_along(values)) {
    z <- gmp::as.bigz(values[[i]]) %% modulus
    for (j in 0:15) {out[(i-1L)*16L+j+1L] <- as.raw(as.integer(z %% 256L)); z <- z %/% 256L}
  }
  out
}

.dsvert_dp_irls_source_materialize <- function(contract, sealed) {
  body <- sealed$body; owner <- body$owner
  if (!identical(body$root, .dsvert_dp_irls_root(contract)) ||
      !identical(body$source_abi, .DSVERT_DP_IRLS_SOURCE_ABI) ||
      !identical(.dsvert_dp_irls_json(body$conversion),
                 .dsvert_dp_irls_json(.dsvert_dp_irls_conversion_certificate())) ||
      !isTRUE(.dsvert_relay_verify_message(.dsvert_dp_irls_source_message(body),
        contract$privacy_source$peer_pins[[owner]], sealed$signature)))
    .dsvert_dp_irls_fail("authenticated source record")
  for (source in names(body$records)) {
    data <- sealed$frozen[[source]]
    snapshot <- digest::digest(serialize(data, NULL, version = 3L), algo = "sha256", serialize = FALSE)
    if (!identical(snapshot, body$records[[source]]$snapshot_sha256))
      .dsvert_dp_irls_fail("frozen source snapshot")
  }
  n <- as.integer(contract$privacy_source$capacity)
  pair <- unlist(contract$privacy_source$computation_peers, use.names = FALSE)
  owner_index <- match(owner, pair)
  p <- length(contract$estimand$coefficient_order)
  words <- rep("0", n*(p+4L)+4L)
  columns <- Filter(function(z) z$owner == owner, contract$estimand$columns)
  actual <- nrow(sealed$frozen[[columns[[1L]]$source_id]])
  for (row in seq_len(actual)) {
    values <- rep("0", p+4L); valid <- TRUE
    for (column in columns) {
      if (column$role == "predictor") {
        coordinate <- match(column$column_id, unlist(contract$estimand$coefficient_order))
        bounds <- contract$privacy_source$x_bounds[[coordinate]]; index <- 2L+coordinate
      } else if (column$role == "outcome") {
        bounds <- contract$privacy_source$y_bounds; index <- p+3L
      } else if (column$role == "offset") {
        bounds <- contract$privacy_source$offset_bounds; index <- p+4L
      } else .dsvert_dp_irls_fail("uncertified source column role")
      encoded <- .dsvert_dp_irls_encode_scalar(sealed$frozen[[column$source_id]][[column$column_id]][row],
        bounds, integer = column$role == "outcome")
      valid <- valid && encoded$valid; values[[index]] <- encoded$value
    }
    if (!valid) values[] <- "0"
    values[[owner_index]] <- if (valid) "1" else "0"
    # The circuit installs the signed public intercept; its raw source is zero.
    words[(row-1L)*(p+4L)+seq_len(p+4L)] <- values
  }
  encoded <- .dsvert_dp_irls_ring128_bytes(as.list(words))
  binding <- as.raw(strtoi(substring(body$person_slot_binding,
    seq.int(1L,63L,2L), seq.int(2L,64L,2L)), 16L))
  start <- n*(p+4L)*16L + (owner_index-1L)*32L
  encoded[start+seq_len(32L)] <- binding
  list(source_share = gsub("[\r\n]", "", jsonlite::base64_enc(encoded)),
       source_abi = .DSVERT_DP_IRLS_SOURCE_ABI)
}
