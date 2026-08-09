# Authenticated accounting for public vector releases.  Each capsule may have
# exactly one public release instance, exact replay is free, and new capsules
# are denied once the authenticated lifetime privacy bound is exhausted.

.DSVERT_JOINT_DP_RELEASE_LEDGER_VERSION <-
  "dsvert-joint-dp-vector-release-ledger-v1"
.DSVERT_JOINT_DP_RELEASE_LEDGER_RECORD_VERSION <-
  "dsvert-joint-dp-vector-release-record-v1"
.DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1 <-
  "dsvert-joint-dp-vector-release-state-v1"
.DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION <-
  "dsvert-joint-dp-vector-release-state-v2"
.DSVERT_JOINT_DP_RELEASE_LEDGER_ANCHOR_VERSION <-
  "dsvert-joint-dp-vector-release-anchor-v1"

.dsvert_joint_dp_release_ledger_hash <- function(value) {
  digest::digest(
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_release_ledger_hmac <- function(
    secret, family, value) {
  if (!is.raw(secret) || length(secret) != 32L ||
      !is.character(family) || length(family) != 1L ||
      is.na(family) || !nzchar(family)) {
    stop("Invalid vector release-ledger authentication context.",
         call. = FALSE)
  }
  digest::hmac(
    key = secret,
    object = charToRaw(paste0(
      "dsVert/joint-dp/vector-release-ledger/", family, "/v1|",
      .dsvert_dp_canonical_json(
        .dsvert_dp_canonical_query_value(value)))),
    algo = "sha256", serialize = FALSE)
}

.dsvert_joint_dp_release_ledger_string <- function(
    value, what, maximum_bytes = 256L,
    pattern = "^[A-Za-z0-9][A-Za-z0-9._:/-]*$") {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes ||
      (!is.null(pattern) && !grepl(pattern, value, perl = TRUE))) {
    stop("Invalid vector release-ledger ", what, ".", call. = FALSE)
  }
  enc2utf8(value)
}

.dsvert_joint_dp_release_ledger_hex <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value, perl = TRUE)) {
    stop("Invalid vector release-ledger ", what, ".", call. = FALSE)
  }
  value
}

.dsvert_joint_dp_release_ledger_decimal <- function(
    value, what, open_minimum = FALSE, maximum = Inf) {
  number <- suppressWarnings(as.numeric(value))
  valid <- length(number) == 1L && !is.na(number) && is.finite(number) &&
    number <= maximum && if (isTRUE(open_minimum)) number > 0 else number >= 0
  if (!isTRUE(valid)) {
    stop("Invalid vector release-ledger ", what, ".", call. = FALSE)
  }
  if (is.character(value) && length(value) == 1L &&
      grepl("^(0|[1-9][0-9]*)(\\.[0-9]+)?(e[+-][0-9]+)?$",
            value, perl = TRUE)) {
    return(value)
  }
  sub(
    getOption("OutDec", "."), ".",
    format(number, digits = 17L, scientific = TRUE, trim = TRUE),
    fixed = TRUE)
}

.dsvert_joint_dp_release_ledger_count <- function(value, what) {
  number <- suppressWarnings(as.numeric(value))
  if (length(number) != 1L || is.na(number) || !is.finite(number) ||
      number < 0 || number > 2^53 - 1 || number != floor(number)) {
    stop("Invalid vector release-ledger ", what, ".", call. = FALSE)
  }
  number
}

.dsvert_joint_dp_release_ledger_decimal_parts <- function(value, what) {
  value <- .dsvert_joint_dp_release_ledger_decimal(value, what)
  match <- regexec(
    "^([0-9]+)(?:\\.([0-9]+))?(?:e([+-])([0-9]+))?$",
    value, perl = TRUE)
  parts <- regmatches(value, match)[[1L]]
  if (!length(parts)) {
    stop("Invalid vector release-ledger ", what, ".", call. = FALSE)
  }
  fractional <- if (length(parts) >= 3L) parts[[3L]] else ""
  exponent <- 0
  if (length(parts) >= 5L && nzchar(parts[[4L]])) {
    exponent <- suppressWarnings(as.numeric(paste0(
      parts[[4L]], parts[[5L]])))
  }
  if (length(exponent) != 1L || is.na(exponent) || !is.finite(exponent) ||
      exponent != floor(exponent) || abs(exponent) > 4096) {
    stop("Invalid vector release-ledger ", what, " exponent.",
         call. = FALSE)
  }
  coefficient <- paste0(parts[[2L]], fractional)
  coefficient <- sub("^0+", "", coefficient)
  if (!nzchar(coefficient)) {
    return(list(coefficient = "0", exponent = 0))
  }
  trailing <- nchar(coefficient, type = "bytes") -
    nchar(sub("0+$", "", coefficient), type = "bytes")
  if (trailing > 0L) {
    coefficient <- substr(
      coefficient, 1L, nchar(coefficient, type = "bytes") - trailing)
  }
  list(
    coefficient = coefficient,
    exponent = exponent - nchar(fractional, type = "bytes") + trailing)
}

.dsvert_joint_dp_release_ledger_decimal_compose <- function(
    coefficient, exponent, what) {
  if (inherits(coefficient, "bignum")) {
    coefficient <- as.character(coefficient)
  }
  if (!is.character(coefficient) || length(coefficient) != 1L ||
      is.na(coefficient) || !grepl("^[0-9]+$", coefficient) ||
      !is.numeric(exponent) || length(exponent) != 1L ||
      is.na(exponent) || !is.finite(exponent) ||
      exponent != floor(exponent)) {
    stop("Invalid vector release-ledger ", what, ".", call. = FALSE)
  }
  coefficient <- sub("^0+", "", coefficient)
  if (!nzchar(coefficient)) return("0")
  trailing <- nchar(coefficient, type = "bytes") -
    nchar(sub("0+$", "", coefficient), type = "bytes")
  if (trailing > 0L) {
    coefficient <- substr(
      coefficient, 1L, nchar(coefficient, type = "bytes") - trailing)
  }
  exponent <- exponent + trailing
  scientific_exponent <-
    exponent + nchar(coefficient, type = "bytes") - 1
  mantissa <- if (nchar(coefficient, type = "bytes") == 1L) {
    coefficient
  } else {
    paste0(substr(coefficient, 1L, 1L), ".",
           substr(coefficient, 2L, nchar(coefficient, type = "bytes")))
  }
  if (scientific_exponent == 0) return(mantissa)
  paste0(
    mantissa, "e", if (scientific_exponent > 0) "+" else "-",
    sprintf("%.0f", abs(scientific_exponent)))
}

.dsvert_joint_dp_release_ledger_exact_total <- function(
    value, count, what) {
  count <- .dsvert_joint_dp_release_ledger_count(count, "release count")
  parts <- .dsvert_joint_dp_release_ledger_decimal_parts(value, what)
  if (count == 0 || identical(parts$coefficient, "0")) return("0")
  coefficient <-
    openssl::bignum(parts$coefficient) *
      openssl::bignum(sprintf("%.0f", count))
  .dsvert_joint_dp_release_ledger_decimal_compose(
    coefficient, parts$exponent, what)
}

.dsvert_joint_dp_release_ledger_exact_sum <- function(values, what) {
  if (!length(values)) return("0")
  parts <- lapply(values, function(value) {
    .dsvert_joint_dp_release_ledger_decimal_parts(value, what)
  })
  exponent <- min(vapply(parts, `[[`, numeric(1L), "exponent"))
  coefficient <- openssl::bignum(0)
  for (part in parts) {
    term <- openssl::bignum(part$coefficient)
    shift <- part$exponent - exponent
    if (shift > 0) {
      term <- term * openssl::bignum(10)^as.integer(shift)
    }
    coefficient <- coefficient + term
  }
  .dsvert_joint_dp_release_ledger_decimal_compose(
    coefficient, exponent, what)
}

.dsvert_joint_dp_release_ledger_exact_compare <- function(
    left, right, what) {
  parts <- lapply(list(left, right), function(value) {
    .dsvert_joint_dp_release_ledger_decimal_parts(value, what)
  })
  exponent <- min(vapply(parts, `[[`, numeric(1L), "exponent"))
  coefficients <- lapply(parts, function(part) {
    value <- openssl::bignum(part$coefficient)
    shift <- part$exponent - exponent
    if (shift > 0) {
      value <- value * openssl::bignum(10)^as.integer(shift)
    }
    value
  })
  if (coefficients[[1L]] < coefficients[[2L]]) return(-1L)
  if (coefficients[[1L]] > coefficients[[2L]]) return(1L)
  0L
}

# Internal telemetry projection, not a general decimal-to-binary64 converter.
# Its authenticated inputs are bounded by release epsilon <= 8, release delta
# < 1 and release_count <= 2^53 - 1, so every contractual total is finite.
.dsvert_joint_dp_release_ledger_upper_numeric <- function(value, what) {
  parts <- .dsvert_joint_dp_release_ledger_decimal_parts(value, what)
  if (identical(parts$coefficient, "0")) return(0)
  numerator <- openssl::bignum(parts$coefficient)
  denominator <- openssl::bignum(1)
  if (parts$exponent >= 0) {
    numerator <- numerator *
      openssl::bignum(10)^as.integer(parts$exponent)
  } else {
    denominator <- openssl::bignum(10)^as.integer(-parts$exponent)
  }

  compare_power_two <- function(exponent) {
    if (exponent >= 0) {
      left <- numerator
      right <- denominator * openssl::bignum(2)^as.integer(exponent)
    } else {
      left <- numerator * openssl::bignum(2)^as.integer(-exponent)
      right <- denominator
    }
    if (left < right) -1L else if (left > right) 1L else 0L
  }
  coefficient_digits <- nchar(parts$coefficient, type = "bytes")
  prefix_digits <- min(15L, coefficient_digits)
  prefix <- as.numeric(substr(parts$coefficient, 1L, prefix_digits))
  exponent <- floor(
    log2(prefix) +
      (coefficient_digits - prefix_digits + parts$exponent) * log2(10))
  while (compare_power_two(exponent) < 0L) exponent <- exponent - 1L
  while (compare_power_two(exponent + 1L) >= 0L) {
    exponent <- exponent + 1L
  }

  ceiling_quotient <- function(numerator, denominator) {
    (numerator + denominator - openssl::bignum(1)) %/% denominator
  }
  if (exponent < -1022L) {
    significand <- ceiling_quotient(
      numerator * openssl::bignum(2)^1074L, denominator)
    if (significand < openssl::bignum(1)) {
      significand <- openssl::bignum(1)
    }
    if (significand > openssl::bignum(2)^52L) {
      stop("Invalid vector release-ledger ", what, " projection.",
           call. = FALSE)
    }
    upper <- as.numeric(as.character(significand)) * 2^-1074
  } else {
    shift <- exponent - 52L
    if (shift >= 0L) {
      significand <- ceiling_quotient(
        numerator,
        denominator * openssl::bignum(2)^as.integer(shift))
    } else {
      significand <- ceiling_quotient(
        numerator * openssl::bignum(2)^as.integer(-shift), denominator)
    }
    if (significand < openssl::bignum(2)^52L ||
        significand > openssl::bignum(2)^53L) {
      stop("Invalid vector release-ledger ", what, " projection.",
           call. = FALSE)
    }
    upper <- as.numeric(as.character(significand)) * 2^shift
  }
  if (!is.finite(upper) || upper <= 0) {
    stop("Invalid vector release-ledger ", what, " projection.",
         call. = FALSE)
  }
  upper
}

.dsvert_joint_dp_release_ledger_config <- function(
    domain, cohort_id, local_peer_name, consortium_peer_names,
    peer_pinset_sha256, release_epsilon, release_delta,
    lifetime_max_distinct_capsules) {
  domain <- .dsvert_joint_dp_release_ledger_string(
    domain, "domain", 256L)
  cohort_id <- .dsvert_joint_dp_release_ledger_string(
    cohort_id, "cohort id", 256L)
  local_peer_name <- .dsvert_joint_dp_release_ledger_string(
    local_peer_name, "local peer name", 128L,
    "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
  if (!is.character(consortium_peer_names) ||
      length(consortium_peer_names) < 2L ||
      length(consortium_peer_names) > 4096L ||
      anyNA(consortium_peer_names) || anyDuplicated(consortium_peer_names)) {
    stop("Invalid vector release-ledger consortium peers.", call. = FALSE)
  }
  consortium_peer_names <- vapply(
    consortium_peer_names,
    .dsvert_joint_dp_release_ledger_string, character(1L),
    what = "consortium peer name", maximum_bytes = 128L,
    pattern = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
  consortium_peer_names <- sort(
    unname(consortium_peer_names), method = "radix")
  if (!local_peer_name %in% consortium_peer_names) {
    stop("The local peer is absent from the release-ledger consortium.",
         call. = FALSE)
  }
  peer_pinset_sha256 <- .dsvert_joint_dp_release_ledger_hex(
    peer_pinset_sha256, "peer-pinset hash")
  epsilon_text <- .dsvert_joint_dp_release_ledger_decimal(
    release_epsilon, "release epsilon", open_minimum = TRUE, maximum = 8)
  delta_text <- .dsvert_joint_dp_release_ledger_decimal(
    release_delta, "release delta",
    maximum = 1 - .Machine$double.eps)
  lifetime_max_distinct_capsules <-
    .dsvert_joint_dp_release_ledger_count(
      lifetime_max_distinct_capsules,
      "lifetime maximum distinct capsules")
  if (lifetime_max_distinct_capsules < 1) {
    stop("Invalid vector release-ledger lifetime maximum distinct capsules.",
         call. = FALSE)
  }
  lifetime_epsilon <- .dsvert_joint_dp_release_ledger_exact_total(
    epsilon_text, lifetime_max_distinct_capsules,
    "lifetime epsilon")
  lifetime_delta <- .dsvert_joint_dp_release_ledger_exact_total(
    delta_text, lifetime_max_distinct_capsules,
    "lifetime delta")
  if (.dsvert_joint_dp_release_ledger_exact_compare(
        lifetime_epsilon, "8", "lifetime epsilon") > 0L ||
      .dsvert_joint_dp_release_ledger_exact_compare(
        lifetime_delta, "1", "lifetime delta") >= 0L) {
    stop("The vector release-ledger lifetime privacy bound is invalid.",
         call. = FALSE)
  }
  contract <- .dsvert_dp_canonical_query_value(list(
    version = .DSVERT_JOINT_DP_RELEASE_LEDGER_VERSION,
    domain = domain,
    cohort_id = cohort_id,
    local_peer_name = local_peer_name,
    consortium_peer_names = as.list(consortium_peer_names),
    peer_pinset_sha256 = peer_pinset_sha256,
    release_epsilon = epsilon_text,
    release_delta = delta_text,
    lifetime_max_distinct_capsules =
      as.numeric(lifetime_max_distinct_capsules),
    release_accounting =
      "one_public_release_instance_per_capsule_id",
    operation_accounting = "none",
    operation_limit = TRUE,
    request_limit = FALSE,
    history_can_deny_operation = TRUE))
  list(
    version = .DSVERT_JOINT_DP_RELEASE_LEDGER_VERSION,
    ledger_id = .dsvert_joint_dp_release_ledger_hash(contract),
    contract = contract,
    domain = domain,
    cohort_id = cohort_id,
    local_peer_name = local_peer_name,
    consortium_peer_names = consortium_peer_names,
    peer_pinset_sha256 = peer_pinset_sha256,
    release_epsilon = epsilon_text,
    release_delta = delta_text,
    lifetime_max_distinct_capsules =
      as.numeric(lifetime_max_distinct_capsules))
}

.dsvert_joint_dp_release_ledger_validate_config <- function(config) {
  required <- c(
    "version", "ledger_id", "contract", "domain", "cohort_id",
    "local_peer_name", "consortium_peer_names", "peer_pinset_sha256",
    "release_epsilon", "release_delta",
    "lifetime_max_distinct_capsules")
  if (!is.list(config) || is.null(names(config)) || anyNA(names(config)) ||
      anyDuplicated(names(config)) || !setequal(names(config), required) ||
      !identical(config$version,
                 .DSVERT_JOINT_DP_RELEASE_LEDGER_VERSION)) {
    stop("Invalid vector release-ledger configuration.", call. = FALSE)
  }
  expected <- .dsvert_joint_dp_release_ledger_config(
    config$domain, config$cohort_id, config$local_peer_name,
    config$consortium_peer_names, config$peer_pinset_sha256,
    config$release_epsilon, config$release_delta,
    config$lifetime_max_distinct_capsules)
  if (!identical(config, expected)) {
    stop("The vector release-ledger configuration is not canonical.",
         call. = FALSE)
  }
  config
}

.dsvert_joint_dp_release_ledger_config_from_policy <- function(policy) {
  context <- .dsvert_joint_dp_policy_context(
    policy, require_designated = FALSE)
  .dsvert_joint_dp_release_ledger_config(
    domain = context$common$domain,
    cohort_id = context$common$cohort_id,
    local_peer_name = context$peer_name,
    consortium_peer_names = names(policy$peer_pinset),
    peer_pinset_sha256 = context$common$peer_pinset_sha256,
    release_epsilon = context$common$epsilon_capsule,
    release_delta = context$common$delta_capsule,
    lifetime_max_distinct_capsules =
      policy$lifetime_max_distinct_capsules)
}

.dsvert_joint_dp_release_ledger_config_from_contract <- function(contract) {
  fields <- c(
    "version", "domain", "cohort_id", "local_peer_name",
    "consortium_peer_names", "peer_pinset_sha256", "release_epsilon",
    "release_delta", "lifetime_max_distinct_capsules",
    "release_accounting", "operation_accounting", "operation_limit",
    "request_limit", "history_can_deny_operation")
  valid <- is.list(contract) && !is.null(names(contract)) &&
    !anyNA(names(contract)) && !anyDuplicated(names(contract)) &&
    setequal(names(contract), fields) &&
    identical(contract$version,
              .DSVERT_JOINT_DP_RELEASE_LEDGER_VERSION) &&
    identical(contract$release_accounting,
              "one_public_release_instance_per_capsule_id") &&
    identical(contract$operation_accounting, "none") &&
    identical(contract$operation_limit, TRUE) &&
    identical(contract$request_limit, FALSE) &&
    identical(contract$history_can_deny_operation, TRUE) &&
    is.list(contract$consortium_peer_names)
  peers <- if (isTRUE(valid)) unlist(
    contract$consortium_peer_names, use.names = FALSE) else NULL
  config <- if (isTRUE(valid)) tryCatch(
    .dsvert_joint_dp_release_ledger_config(
      contract$domain, contract$cohort_id, contract$local_peer_name,
      peers, contract$peer_pinset_sha256, contract$release_epsilon,
      contract$release_delta,
      contract$lifetime_max_distinct_capsules),
    error = function(error) NULL) else NULL
  canonical <- tryCatch(
    .dsvert_dp_canonical_query_value(contract),
    error = function(error) NULL)
  if (is.null(config) || !identical(config$contract, canonical)) {
    stop("The stored vector release-ledger contract is invalid.",
         call. = FALSE)
  }
  config
}

.dsvert_joint_dp_release_ledger_decode_json <- function(
    value, what, maximum_bytes = 4 * 1024^2) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !nzchar(value) || nchar(value, type = "bytes") > maximum_bytes) {
    stop("Invalid canonical vector release-ledger ", what, ".",
         call. = FALSE)
  }
  decoded <- tryCatch(
    jsonlite::fromJSON(value, simplifyVector = FALSE),
    error = function(error) NULL)
  canonical <- tryCatch(
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(decoded)),
    error = function(error) NULL)
  if (!is.list(decoded) || is.null(canonical) ||
      !identical(canonical, value)) {
    stop("Invalid canonical vector release-ledger ", what, ".",
         call. = FALSE)
  }
  decoded
}

.dsvert_joint_dp_release_ledger_root <- function(value, what) {
  fields <- c(
    "privacy_epoch", "noise_key_id", "provider_id",
    "release_domain_generation", "release_domain_id")
  epoch <- if (is.list(value)) suppressWarnings(
    as.numeric(value$privacy_epoch)) else NA_real_
  generation <- if (is.list(value)) suppressWarnings(
    as.numeric(value$release_domain_generation)) else NA_real_
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), fields) && length(epoch) == 1L &&
    !is.na(epoch) && is.finite(epoch) && epoch >= 1 &&
    epoch <= 2^53 - 1 && epoch == floor(epoch) &&
    length(generation) == 1L && !is.na(generation) &&
    is.finite(generation) && generation >= 1 &&
    generation <= 2^53 - 1 && generation == floor(generation) &&
    is.character(value$release_domain_id) &&
    length(value$release_domain_id) == 1L &&
    !is.na(value$release_domain_id) &&
    grepl("^rd_[0-9a-f]{64}$", value$release_domain_id)
  if (!isTRUE(valid)) {
    stop("Invalid vector release-ledger ", what, ".", call. = FALSE)
  }
  list(
    privacy_epoch = epoch,
    noise_key_id = .dsvert_joint_dp_release_ledger_string(
      value$noise_key_id, paste0(what, " key id"), 256L,
      "^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"),
    provider_id = .dsvert_joint_dp_release_ledger_string(
      value$provider_id, paste0(what, " provider id"), 256L,
      "^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$"),
    release_domain_generation = generation,
    release_domain_id = value$release_domain_id)
}

.dsvert_joint_dp_release_ledger_instance <- function(
    release_instance_json, config = NULL) {
  value <- .dsvert_joint_dp_release_ledger_decode_json(
    release_instance_json, "release instance")
  fields <- c("version", "capsule_id", "peer_noise_roots")
  roots <- value$peer_noise_roots
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) || !setequal(names(value), fields) ||
      !identical(value$version,
                 .DSVERT_JOINT_DP_VECTOR_RELEASE_INSTANCE_VERSION) ||
      !is.list(roots) || is.null(names(roots)) ||
      length(roots) != 2L || anyNA(names(roots)) ||
      anyDuplicated(names(roots)) ||
      !identical(names(roots), sort(names(roots), method = "radix"))) {
    stop("Invalid vector release-ledger release instance.", call. = FALSE)
  }
  capsule_id <- .dsvert_joint_dp_release_ledger_hex(
    value$capsule_id, "capsule id")
  root_names <- vapply(
    names(roots), .dsvert_joint_dp_release_ledger_string,
    character(1L), what = "designated peer name", maximum_bytes = 128L,
    pattern = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
  roots <- stats::setNames(lapply(seq_along(roots), function(index) {
    .dsvert_joint_dp_release_ledger_root(
      roots[[index]], paste0("root for ", root_names[[index]]))
  }), root_names)
  if (anyDuplicated(vapply(
        roots, `[[`, character(1L), "noise_key_id"))) {
    stop("The two vector release-ledger noise roots are not independent.",
         call. = FALSE)
  }
  if (!is.null(config)) {
    config <- .dsvert_joint_dp_release_ledger_validate_config(config)
    if (!all(root_names %in% config$consortium_peer_names) ||
        !config$local_peer_name %in% root_names) {
      stop("The release instance is outside the configured consortium.",
           call. = FALSE)
    }
  }
  canonical <- .dsvert_dp_canonical_query_value(list(
    version = value$version, capsule_id = capsule_id,
    peer_noise_roots = roots))
  json <- .dsvert_dp_canonical_json(canonical)
  if (!identical(json, release_instance_json)) {
    stop("The vector release instance is not canonical.", call. = FALSE)
  }
  list(
    value = canonical, json = json,
    id = .dsvert_joint_dp_release_ledger_hash(canonical),
    designated_noise_peers = root_names)
}

.dsvert_joint_dp_release_ledger_artifact <- function(
    config, release_instance_json, final_release_json) {
  config <- .dsvert_joint_dp_release_ledger_validate_config(config)
  instance <- .dsvert_joint_dp_release_ledger_instance(
    release_instance_json, config)
  final <- .dsvert_joint_dp_release_ledger_decode_json(
    final_release_json, "public release")
  required <- c(
    "peer_name", "capsule_id", "release_instance_id",
    "final_vector_root", "epsilon", "delta")
  if (is.null(names(final)) || anyNA(names(final)) ||
      anyDuplicated(names(final)) || !all(required %in% names(final)) ||
      !identical(final$peer_name, config$local_peer_name) ||
      !identical(final$capsule_id, instance$value$capsule_id) ||
      !identical(final$release_instance_id, instance$id)) {
    stop("The public release is not bound to its release instance.",
         call. = FALSE)
  }
  root <- .dsvert_joint_dp_release_ledger_hex(
    final$final_vector_root, "final vector root")
  epsilon <- .dsvert_joint_dp_release_ledger_decimal(
    final$epsilon, "public release epsilon", open_minimum = TRUE,
    maximum = 8)
  delta <- .dsvert_joint_dp_release_ledger_decimal(
    final$delta, "public release delta",
    maximum = 1 - .Machine$double.eps)
  expected_epsilon <- .dsvert_joint_dp_release_ledger_decimal(
    config$release_epsilon, "configured epsilon", open_minimum = TRUE,
    maximum = 8)
  expected_delta <- .dsvert_joint_dp_release_ledger_decimal(
    config$release_delta, "configured delta",
    maximum = 1 - .Machine$double.eps)
  tolerance <- 64 * .Machine$double.eps
  if (as.numeric(epsilon) > as.numeric(expected_epsilon) *
        (1 + tolerance) ||
      as.numeric(delta) > as.numeric(expected_delta) *
        (1 + tolerance)) {
    stop("The public release exceeds its fixed DP allocation.",
         call. = FALSE)
  }
  local_root <- instance$value$peer_noise_roots[[config$local_peer_name]]
  list(
    instance = instance,
    final_release_sha256 = digest::digest(
      final_release_json, algo = "sha256", serialize = FALSE),
    final_vector_root = root,
    epsilon = expected_epsilon,
    delta = expected_delta,
    local_noise_root = local_root)
}

.dsvert_joint_dp_release_ledger_schema <- function(connection) {
  statements <- c(
    paste("CREATE TABLE IF NOT EXISTS vector_release_ledger_meta (",
          "key TEXT PRIMARY KEY, value TEXT NOT NULL)"),
    paste("CREATE TABLE IF NOT EXISTS vector_release_ledger_records (",
          "release_instance_id TEXT PRIMARY KEY,",
          "sequence INTEGER NOT NULL UNIQUE, capsule_id TEXT NOT NULL,",
          "local_privacy_epoch INTEGER NOT NULL,",
          "local_noise_key_id TEXT NOT NULL,",
          "previous_chain TEXT NOT NULL, chain_hash TEXT NOT NULL UNIQUE,",
          "record_json TEXT NOT NULL, row_mac TEXT NOT NULL)"),
    paste("CREATE UNIQUE INDEX IF NOT EXISTS",
          "vector_release_ledger_capsule_id_unique ON",
          "vector_release_ledger_records(capsule_id)"),
    paste("CREATE TABLE IF NOT EXISTS vector_release_ledger_state (",
          "singleton INTEGER PRIMARY KEY CHECK(singleton = 1),",
          "release_count INTEGER NOT NULL,",
          "cumulative_epsilon TEXT NOT NULL,",
          "cumulative_delta TEXT NOT NULL, head_chain TEXT NOT NULL,",
          "tail_release_instance_id TEXT NOT NULL,",
          "tail_row_mac TEXT NOT NULL, state_mac TEXT NOT NULL)"))
  for (statement in statements) DBI::dbExecute(connection, statement)
  invisible(TRUE)
}

.dsvert_joint_dp_release_ledger_meta <- function(config, secret) {
  config_json <- .dsvert_dp_canonical_json(config$contract)
  c(
    schema_version = "1",
    ledger_id = config$ledger_id,
    config_json = config_json,
    config_mac = .dsvert_joint_dp_release_ledger_hmac(
      secret, "meta", list(
        ledger_id = config$ledger_id, config_json = config_json)))
}

.dsvert_joint_dp_release_ledger_validate_meta <- function(
    connection, config, secret) {
  expected <- .dsvert_joint_dp_release_ledger_meta(config, secret)
  observed <- DBI::dbGetQuery(
    connection,
    "SELECT key,value FROM vector_release_ledger_meta ORDER BY key")
  values <- if (nrow(observed)) {
    stats::setNames(observed$value, observed$key)
  } else {
    character()
  }
  if (nrow(observed) != length(expected) || anyDuplicated(observed$key) ||
      !setequal(observed$key, names(expected)) ||
      !identical(unname(values[names(expected)]), unname(expected))) {
    stop("The vector release-ledger failed policy or metadata authentication.",
         call. = FALSE)
  }
  invisible(TRUE)
}

.dsvert_joint_dp_release_ledger_state_material <- function(
    config, release_count, cumulative_epsilon, cumulative_delta,
    head_chain, tail_release_instance_id, tail_row_mac,
    version = .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION) {
  if (!identical(version, .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION) &&
      !identical(version,
                 .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)) {
    stop("Invalid authenticated vector release-ledger state version.",
         call. = FALSE)
  }
  count <- .dsvert_joint_dp_release_ledger_count(
    release_count, "release count")
  epsilon <- .dsvert_joint_dp_release_ledger_decimal(
    cumulative_epsilon, "cumulative epsilon")
  delta <- .dsvert_joint_dp_release_ledger_decimal(
    cumulative_delta, "cumulative delta")
  empty <- count == 0
  valid_head <- is.character(head_chain) && length(head_chain) == 1L &&
    !is.na(head_chain) && (identical(head_chain, "GENESIS") ||
      grepl("^[0-9a-f]{64}$", head_chain, perl = TRUE))
  valid_tail_id <- is.character(tail_release_instance_id) &&
    length(tail_release_instance_id) == 1L &&
    !is.na(tail_release_instance_id) && (identical(
      tail_release_instance_id, "") ||
      grepl("^[0-9a-f]{64}$", tail_release_instance_id, perl = TRUE))
  valid_tail_mac <- is.character(tail_row_mac) &&
    length(tail_row_mac) == 1L && !is.na(tail_row_mac) &&
    (identical(tail_row_mac, "") ||
      grepl("^[0-9a-f]{64}$", tail_row_mac, perl = TRUE))
  if (!valid_head || !valid_tail_id || !valid_tail_mac ||
      (empty && (!identical(head_chain, "GENESIS") ||
        !identical(tail_release_instance_id, "") ||
        !identical(tail_row_mac, "") || as.numeric(epsilon) != 0 ||
        as.numeric(delta) != 0)) ||
      (!empty && (identical(head_chain, "GENESIS") ||
        !nzchar(tail_release_instance_id) || !nzchar(tail_row_mac)))) {
    stop("Invalid authenticated vector release-ledger state.",
         call. = FALSE)
  }
  list(
    version = version,
    ledger_id = config$ledger_id,
    release_count = count,
    cumulative_epsilon = epsilon,
    cumulative_delta = delta,
    head_chain = head_chain,
    tail_release_instance_id = tail_release_instance_id,
    tail_row_mac = tail_row_mac)
}

.dsvert_joint_dp_release_ledger_write_state <- function(
    connection, config, secret, release_count, cumulative_epsilon,
    cumulative_delta, head_chain, tail_release_instance_id,
    tail_row_mac, insert = FALSE) {
  value <- .dsvert_joint_dp_release_ledger_state_material(
    config, release_count, cumulative_epsilon, cumulative_delta,
    head_chain, tail_release_instance_id, tail_row_mac)
  mac <- .dsvert_joint_dp_release_ledger_hmac(secret, "state", value)
  if (isTRUE(insert)) {
    changed <- DBI::dbExecute(connection, paste(
      "INSERT INTO vector_release_ledger_state(",
      "singleton,release_count,cumulative_epsilon,cumulative_delta,",
      "head_chain,tail_release_instance_id,tail_row_mac,state_mac)",
      "VALUES(1,?,?,?,?,?,?,?)"), params = list(
        value$release_count, value$cumulative_epsilon,
        value$cumulative_delta, value$head_chain,
        value$tail_release_instance_id, value$tail_row_mac, mac))
  } else {
    changed <- DBI::dbExecute(connection, paste(
      "UPDATE vector_release_ledger_state SET release_count=?,",
      "cumulative_epsilon=?,cumulative_delta=?,head_chain=?,",
      "tail_release_instance_id=?,tail_row_mac=?,state_mac=?",
      "WHERE singleton=1"), params = list(
        value$release_count, value$cumulative_epsilon,
        value$cumulative_delta, value$head_chain,
        value$tail_release_instance_id, value$tail_row_mac, mac))
  }
  if (!identical(as.integer(changed), 1L)) {
    stop("The vector release-ledger state update was lost.", call. = FALSE)
  }
  value
}

.dsvert_joint_dp_release_ledger_read_state <- function(
    connection, config, secret) {
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT release_count,cumulative_epsilon,cumulative_delta,head_chain,",
    "tail_release_instance_id,tail_row_mac,state_mac",
    "FROM vector_release_ledger_state WHERE singleton=1"))
  value <- tryCatch({
    if (nrow(row) != 1L) stop("invalid")
    authenticated <- NULL
    for (version in c(
        .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION,
        .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)) {
      material <- .dsvert_joint_dp_release_ledger_state_material(
        config, row$release_count[[1L]], row$cumulative_epsilon[[1L]],
        row$cumulative_delta[[1L]], row$head_chain[[1L]],
        row$tail_release_instance_id[[1L]], row$tail_row_mac[[1L]],
        version = version)
      expected <- .dsvert_joint_dp_release_ledger_hmac(
        secret, "state", material)
      if (identical(row$state_mac[[1L]], expected)) {
        material$state_mac <- expected
        authenticated <- material
        break
      }
    }
    if (is.null(authenticated)) stop("invalid")
    authenticated
  }, error = function(error) NULL)
  if (is.null(value)) {
    stop("The vector release-ledger failed state authentication.",
         call. = FALSE)
  }
  value
}

.dsvert_joint_dp_release_ledger_initialize <- function(
    connection, config, secret) {
  config <- .dsvert_joint_dp_release_ledger_validate_config(config)
  if (!inherits(connection, "DBIConnection") ||
      !is.raw(secret) || length(secret) != 32L) {
    stop("Invalid vector release-ledger initialization context.",
         call. = FALSE)
  }
  .dsvert_joint_dp_release_ledger_schema(connection)
  expected <- .dsvert_joint_dp_release_ledger_meta(config, secret)
  observed <- DBI::dbGetQuery(
    connection,
    "SELECT key,value FROM vector_release_ledger_meta ORDER BY key")
  if (!nrow(observed)) {
    nonempty <- nrow(DBI::dbGetQuery(
      connection,
      "SELECT 1 FROM vector_release_ledger_records LIMIT 1")) > 0L ||
      nrow(DBI::dbGetQuery(
        connection,
        "SELECT 1 FROM vector_release_ledger_state LIMIT 1")) > 0L
    if (isTRUE(nonempty)) {
      stop("The vector release-ledger is missing immutable metadata.",
           call. = FALSE)
    }
    DBI::dbExecute(connection, "BEGIN IMMEDIATE")
    committed <- FALSE
    on.exit(if (!committed) try(
      DBI::dbExecute(connection, "ROLLBACK"), silent = TRUE), add = TRUE)
    for (key in names(expected)) {
      DBI::dbExecute(connection, paste(
        "INSERT INTO vector_release_ledger_meta(key,value)",
        "VALUES(?,?)"), params = list(key, unname(expected[[key]])))
    }
    .dsvert_joint_dp_release_ledger_write_state(
      connection, config, secret, 0, "0", "0", "GENESIS", "", "",
      insert = TRUE)
    DBI::dbExecute(connection, "COMMIT")
    committed <- TRUE
  } else {
    .dsvert_joint_dp_release_ledger_validate_meta(
      connection, config, secret)
  }
  state <- .dsvert_joint_dp_release_ledger_read_state(
    connection, config, secret)
  state <- .dsvert_joint_dp_release_ledger_migrate_state(
    connection, config, secret, state)
  invisible(.dsvert_joint_dp_release_ledger_validate_tail(
    connection, config, secret, state))
}

.dsvert_joint_dp_release_ledger_config_from_connection <- function(
    connection, secret) {
  if (!inherits(connection, "DBIConnection") ||
      !is.raw(secret) || length(secret) != 32L) {
    stop("Invalid vector release-ledger history context.", call. = FALSE)
  }
  tables <- DBI::dbGetQuery(connection, paste(
    "SELECT name FROM sqlite_master WHERE type='table' AND name IN",
    "('vector_release_ledger_meta','vector_release_ledger_records',",
    "'vector_release_ledger_state') ORDER BY name"))$name
  expected_tables <- sort(c(
    "vector_release_ledger_meta", "vector_release_ledger_records",
    "vector_release_ledger_state"), method = "radix")
  if (!length(tables)) return(NULL)
  if (!identical(tables, expected_tables)) {
    stop("The vector release-ledger history is structurally incomplete.",
         call. = FALSE)
  }
  observed <- DBI::dbGetQuery(
    connection,
    "SELECT key,value FROM vector_release_ledger_meta ORDER BY key")
  required <- c("config_json", "config_mac", "ledger_id", "schema_version")
  if (nrow(observed) != length(required) || anyDuplicated(observed$key) ||
      !setequal(observed$key, required)) {
    stop("The vector release-ledger history has invalid metadata.",
         call. = FALSE)
  }
  values <- stats::setNames(observed$value, observed$key)
  contract <- .dsvert_joint_dp_release_ledger_decode_json(
    values[["config_json"]], "stored configuration")
  config <- .dsvert_joint_dp_release_ledger_config_from_contract(contract)
  expected <- .dsvert_joint_dp_release_ledger_meta(config, secret)
  if (!identical(unname(values[names(expected)]), unname(expected))) {
    stop("The vector release-ledger history failed identity authentication.",
         call. = FALSE)
  }
  config
}

.dsvert_joint_dp_release_ledger_record_material <- function(
    config, artifact, sequence, previous_chain) {
  list(
    version = .DSVERT_JOINT_DP_RELEASE_LEDGER_RECORD_VERSION,
    ledger_id = config$ledger_id,
    sequence = .dsvert_joint_dp_release_ledger_count(
      sequence, "release sequence"),
    capsule_id = artifact$instance$value$capsule_id,
    release_instance_id = artifact$instance$id,
    release_instance_sha256 = digest::digest(
      artifact$instance$json, algo = "sha256", serialize = FALSE),
    designated_noise_peers =
      as.list(artifact$instance$designated_noise_peers),
    consortium_peer_count = as.numeric(
      length(config$consortium_peer_names)),
    local_peer_name = config$local_peer_name,
    local_noise_root = artifact$local_noise_root,
    final_release_sha256 = artifact$final_release_sha256,
    final_vector_root = artifact$final_vector_root,
    epsilon = artifact$epsilon,
    delta = artifact$delta,
    previous_chain = previous_chain)
}

.dsvert_joint_dp_release_ledger_record <- function(
    config, artifact, sequence, previous_chain, secret) {
  material <- .dsvert_joint_dp_release_ledger_record_material(
    config, artifact, sequence, previous_chain)
  chain_hash <- .dsvert_joint_dp_release_ledger_hash(material)
  value <- .dsvert_dp_canonical_query_value(c(
    material, list(chain_hash = chain_hash)))
  list(
    value = value,
    json = .dsvert_dp_canonical_json(value),
    chain_hash = chain_hash,
    row_mac = .dsvert_joint_dp_release_ledger_hmac(
      secret, "row", value))
}

.dsvert_joint_dp_release_ledger_validate_record <- function(
    connection, config, secret, row) {
  required <- c(
    "release_instance_id", "sequence", "capsule_id",
    "local_privacy_epoch", "local_noise_key_id", "previous_chain",
    "chain_hash", "record_json", "row_mac")
  if (!is.data.frame(row) || nrow(row) != 1L ||
      !setequal(names(row), required)) {
    stop("The vector release-ledger contains an invalid row.", call. = FALSE)
  }
  value <- tryCatch(
    .dsvert_joint_dp_release_ledger_decode_json(
      row$record_json[[1L]], "stored record"),
    error = function(error) NULL)
  fields <- c(
    "version", "ledger_id", "sequence", "capsule_id",
    "release_instance_id", "release_instance_sha256",
    "designated_noise_peers", "consortium_peer_count",
    "local_peer_name", "local_noise_root", "final_release_sha256",
    "final_vector_root", "epsilon", "delta", "previous_chain",
    "chain_hash")
  valid <- is.list(value) && !is.null(names(value)) &&
    !anyNA(names(value)) && !anyDuplicated(names(value)) &&
    setequal(names(value), fields) &&
    identical(value$version,
              .DSVERT_JOINT_DP_RELEASE_LEDGER_RECORD_VERSION) &&
    identical(value$ledger_id, config$ledger_id)
  if (!isTRUE(valid)) {
    stop("The vector release-ledger failed row integrity or authentication.",
         call. = FALSE)
  }
  local_root <- tryCatch(
    .dsvert_joint_dp_release_ledger_root(
      value$local_noise_root, "stored local root"),
    error = function(error) NULL)
  sequence <- tryCatch(
    .dsvert_joint_dp_release_ledger_count(
      value$sequence, "stored sequence"),
    error = function(error) NULL)
  material <- value[setdiff(names(value), "chain_hash")]
  expected_chain <- .dsvert_joint_dp_release_ledger_hash(material)
  expected_mac <- .dsvert_joint_dp_release_ledger_hmac(
    secret, "row", value)
  valid <- !is.null(local_root) && !is.null(sequence) &&
    identical(value$chain_hash, expected_chain) &&
    identical(row$row_mac[[1L]], expected_mac) &&
    identical(row$release_instance_id[[1L]],
              value$release_instance_id) &&
    identical(as.numeric(row$sequence[[1L]]), sequence) &&
    identical(row$capsule_id[[1L]], value$capsule_id) &&
    identical(as.numeric(row$local_privacy_epoch[[1L]]),
              as.numeric(local_root$privacy_epoch)) &&
    identical(row$local_noise_key_id[[1L]], local_root$noise_key_id) &&
    identical(row$previous_chain[[1L]], value$previous_chain) &&
    identical(row$chain_hash[[1L]], value$chain_hash) &&
    identical(value$local_peer_name, config$local_peer_name) &&
    identical(as.numeric(value$consortium_peer_count),
              as.numeric(length(config$consortium_peer_names))) &&
    length(value$designated_noise_peers) == 2L &&
    config$local_peer_name %in% unlist(
      value$designated_noise_peers, use.names = FALSE) &&
    identical(value$epsilon,
              .dsvert_joint_dp_release_ledger_decimal(
                config$release_epsilon, "configured epsilon",
                open_minimum = TRUE, maximum = 8)) &&
    identical(value$delta,
              .dsvert_joint_dp_release_ledger_decimal(
                config$release_delta, "configured delta",
                maximum = 1 - .Machine$double.eps))
  if (!isTRUE(valid)) {
    stop("The vector release-ledger failed row integrity or authentication.",
         call. = FALSE)
  }
  list(value = value, row_mac = expected_mac)
}

.dsvert_joint_dp_release_ledger_load <- function(
    connection, config, secret, release_instance_id) {
  release_instance_id <- .dsvert_joint_dp_release_ledger_hex(
    release_instance_id, "release-instance id")
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT * FROM vector_release_ledger_records",
    "WHERE release_instance_id=?"), params = list(release_instance_id))
  if (!nrow(row)) return(NULL)
  .dsvert_joint_dp_release_ledger_validate_record(
    connection, config, secret, row)
}

.dsvert_joint_dp_release_ledger_load_capsule <- function(
    connection, config, secret, capsule_id) {
  capsule_id <- .dsvert_joint_dp_release_ledger_hex(
    capsule_id, "capsule id")
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT * FROM vector_release_ledger_records",
    "WHERE capsule_id=?"), params = list(capsule_id))
  if (!nrow(rows)) return(NULL)
  if (nrow(rows) != 1L) {
    stop("The vector release-ledger capsule index is inconsistent.",
         call. = FALSE)
  }
  .dsvert_joint_dp_release_ledger_validate_record(
    connection, config, secret, rows)
}

.dsvert_joint_dp_release_ledger_admit_new_capsule <- function(
    connection, config, secret, capsule_id, state = NULL) {
  config <- .dsvert_joint_dp_release_ledger_validate_config(config)
  if (is.null(state)) {
    state <- .dsvert_joint_dp_release_ledger_read_state(
      connection, config, secret)
    state <- .dsvert_joint_dp_release_ledger_validate_tail(
      connection, config, secret, state)
  }
  existing <- .dsvert_joint_dp_release_ledger_load_capsule(
    connection, config, secret, capsule_id)
  # Keep durable-history denials behind the same fixed transcript token. The
  # wider vector boundary also uses it for an incompatible per-capsule instance
  # claim; distinguishing that claim, a consumed publication slot, and global N
  # exhaustion would leak state and is unnecessary for a terminal client path.
  if (!is.null(existing) ||
      state$release_count >= config$lifetime_max_distinct_capsules) {
    stop(.dsvert_dp_lifetime_budget_exhausted_condition())
  }
  invisible(state)
}

.dsvert_joint_dp_release_ledger_validate_tail <- function(
    connection, config, secret, state = NULL) {
  if (is.null(state)) {
    state <- .dsvert_joint_dp_release_ledger_read_state(
      connection, config, secret)
  }
  tail <- DBI::dbGetQuery(connection, paste(
    "SELECT * FROM vector_release_ledger_records",
    "ORDER BY sequence DESC LIMIT 1"))
  if (state$release_count == 0) {
    if (nrow(tail)) {
      stop("The empty vector release-ledger has an unexpected tail.",
           call. = FALSE)
    }
    return(state)
  }
  if (nrow(tail) != 1L ||
      !identical(as.numeric(tail$sequence[[1L]]),
                 state$release_count - 1)) {
    stop("The vector release-ledger tail is inconsistent.", call. = FALSE)
  }
  verified <- .dsvert_joint_dp_release_ledger_validate_record(
    connection, config, secret, tail)
  if (!identical(verified$value$chain_hash, state$head_chain) ||
      !identical(verified$value$release_instance_id,
                 state$tail_release_instance_id) ||
      !identical(verified$row_mac, state$tail_row_mac)) {
    stop("The vector release-ledger tail failed authentication.",
         call. = FALSE)
  }
  state
}

.dsvert_joint_dp_release_ledger_summary <- function(config, state) {
  release_count <- .dsvert_joint_dp_release_ledger_count(
    state$release_count, "release count")
  if (release_count > config$lifetime_max_distinct_capsules) {
    stop("The vector release-ledger exceeds its authenticated lifetime bound.",
         call. = FALSE)
  }
  release_epsilon <- .dsvert_joint_dp_release_ledger_upper_numeric(
    config$release_epsilon, "release epsilon")
  release_delta <- .dsvert_joint_dp_release_ledger_upper_numeric(
    config$release_delta, "release delta")
  cumulative_epsilon <- .dsvert_joint_dp_release_ledger_upper_numeric(
    state$cumulative_epsilon, "cumulative epsilon")
  cumulative_delta <- .dsvert_joint_dp_release_ledger_upper_numeric(
    state$cumulative_delta, "cumulative delta")
  list(
    version = .DSVERT_JOINT_DP_RELEASE_LEDGER_VERSION,
    ledger_id = config$ledger_id,
    release_instance_count = as.numeric(release_count),
    lifetime_max_distinct_capsules =
      as.numeric(config$lifetime_max_distinct_capsules),
    remaining_distinct_capsules = as.numeric(
      config$lifetime_max_distinct_capsules - release_count),
    release_epsilon = release_epsilon,
    release_delta = release_delta,
    cumulative_epsilon = cumulative_epsilon,
    cumulative_delta = cumulative_delta,
    cumulative_delta_vacuous = cumulative_delta >= 1,
    consortium_peer_count = as.numeric(
      length(config$consortium_peer_names)),
    designated_noise_peer_count = 2,
    composition_role =
      "basic_composition_authenticated_lifetime_bound",
    release_accounting =
      "one_public_release_instance_per_capsule_id",
    replay_accounting = "none",
    operation_accounting = "none",
    operation_limit = TRUE,
    request_limit = FALSE,
    history_can_deny_operation = TRUE,
    capability_available = FALSE)
}

.dsvert_joint_dp_release_ledger_commit_connection <- function(
    connection, config, secret, release_instance_json,
    final_release_json, phase_hook = NULL) {
  if (!is.null(phase_hook) && !is.function(phase_hook)) {
    stop("Invalid vector release-ledger phase hook.", call. = FALSE)
  }
  artifact <- .dsvert_joint_dp_release_ledger_artifact(
    config, release_instance_json, final_release_json)
  state <- .dsvert_joint_dp_release_ledger_read_state(
    connection, config, secret)
  state <- .dsvert_joint_dp_release_ledger_validate_tail(
    connection, config, secret, state)
  existing <- .dsvert_joint_dp_release_ledger_load(
    connection, config, secret, artifact$instance$id)
  if (!is.null(existing)) {
    expected <- .dsvert_joint_dp_release_ledger_record_material(
      config, artifact, existing$value$sequence,
      existing$value$previous_chain)
    observed <- existing$value[setdiff(
      names(existing$value), "chain_hash")]
    if (!identical(
          .dsvert_dp_canonical_query_value(observed),
          .dsvert_dp_canonical_query_value(expected))) {
      stop("The release instance has a conflicting public release.",
           call. = FALSE)
    }
    return(list(
      created = FALSE, record = existing$value,
      summary = .dsvert_joint_dp_release_ledger_summary(config, state)))
  }
  .dsvert_joint_dp_release_ledger_admit_new_capsule(
    connection, config, secret, artifact$instance$value$capsule_id,
    state)
  sequence <- state$release_count
  record <- .dsvert_joint_dp_release_ledger_record(
    config, artifact, sequence, state$head_chain, secret)
  DBI::dbExecute(connection, paste(
    "INSERT INTO vector_release_ledger_records(",
    "release_instance_id,sequence,capsule_id,local_privacy_epoch,",
    "local_noise_key_id,previous_chain,chain_hash,record_json,row_mac)",
    "VALUES(?,?,?,?,?,?,?,?,?)"), params = list(
      record$value$release_instance_id, record$value$sequence,
      record$value$capsule_id,
      record$value$local_noise_root$privacy_epoch,
      record$value$local_noise_root$noise_key_id,
      record$value$previous_chain, record$value$chain_hash,
      record$json, record$row_mac))
  if (is.function(phase_hook)) phase_hook("after_record_insert")
  epsilon <- .dsvert_joint_dp_release_ledger_exact_total(
    config$release_epsilon, sequence + 1, "cumulative epsilon")
  delta <- .dsvert_joint_dp_release_ledger_exact_total(
    config$release_delta, sequence + 1, "cumulative delta")
  state <- .dsvert_joint_dp_release_ledger_write_state(
    connection, config, secret, sequence + 1, epsilon, delta,
    record$value$chain_hash, record$value$release_instance_id,
    record$row_mac)
  if (is.function(phase_hook)) phase_hook("after_state_update")
  stored <- .dsvert_joint_dp_release_ledger_load(
    connection, config, secret, artifact$instance$id)
  list(
    created = TRUE, record = stored$value,
    summary = .dsvert_joint_dp_release_ledger_summary(config, state))
}

.dsvert_joint_dp_release_ledger_commit <- function(
    connection, config, secret, release_instance_json,
    final_release_json, phase_hook = NULL) {
  .dsvert_joint_dp_release_ledger_initialize(
    connection, config, secret)
  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  committed <- FALSE
  on.exit(if (!committed) try(
    DBI::dbExecute(connection, "ROLLBACK"), silent = TRUE), add = TRUE)
  result <- .dsvert_joint_dp_release_ledger_commit_connection(
    connection, config, secret, release_instance_json,
    final_release_json, phase_hook)
  DBI::dbExecute(connection, "COMMIT")
  committed <- TRUE
  if (is.function(phase_hook)) phase_hook("after_commit")
  result
}

.dsvert_joint_dp_release_ledger_status <- function(
    connection, config, secret) {
  .dsvert_joint_dp_release_ledger_initialize(
    connection, config, secret)
  state <- .dsvert_joint_dp_release_ledger_validate_tail(
    connection, config, secret)
  .dsvert_joint_dp_release_ledger_summary(config, state)
}

.dsvert_joint_dp_release_ledger_audit_state <- function(
    connection, config, secret, state,
    arithmetic = c("exact", "legacy"), exact_summary = FALSE) {
  arithmetic <- match.arg(arithmetic)
  expected_version <- if (identical(arithmetic, "exact")) {
    .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION
  } else {
    .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1
  }
  if (!is.list(state) || !identical(state$version, expected_version)) {
    stop("The vector release-ledger state arithmetic version is invalid.",
         call. = FALSE)
  }
  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT * FROM vector_release_ledger_records ORDER BY sequence"))
  if (!identical(as.numeric(nrow(rows)), state$release_count)) {
    stop("The vector release-ledger count does not match authenticated state.",
         call. = FALSE)
  }
  if (state$release_count > config$lifetime_max_distinct_capsules ||
      anyDuplicated(rows$capsule_id)) {
    stop("The vector release-ledger exceeds its authenticated lifetime bound.",
         call. = FALSE)
  }
  previous <- "GENESIS"
  cumulative_epsilon <- if (identical(arithmetic, "legacy")) {
    "0"
  } else {
    .dsvert_joint_dp_release_ledger_exact_total(
      config$release_epsilon, state$release_count,
      "audited cumulative epsilon")
  }
  cumulative_delta <- if (identical(arithmetic, "legacy")) {
    "0"
  } else {
    .dsvert_joint_dp_release_ledger_exact_total(
      config$release_delta, state$release_count,
      "audited cumulative delta")
  }
  records <- vector("list", nrow(rows))
  if (nrow(rows)) for (index in seq_len(nrow(rows))) {
    verified <- .dsvert_joint_dp_release_ledger_validate_record(
      connection, config, secret, rows[index, , drop = FALSE])
    record <- verified$value
    if (!identical(as.numeric(record$sequence),
                   as.numeric(index - 1L)) ||
        !identical(record$previous_chain, previous)) {
      stop("The vector release-ledger chain is discontinuous.",
           call. = FALSE)
    }
    previous <- record$chain_hash
    if (identical(arithmetic, "legacy")) {
      cumulative_epsilon <- .dsvert_joint_dp_release_ledger_decimal(
        as.numeric(cumulative_epsilon) + as.numeric(record$epsilon),
        "audited cumulative epsilon")
      cumulative_delta <- .dsvert_joint_dp_release_ledger_decimal(
        as.numeric(cumulative_delta) + as.numeric(record$delta),
        "audited cumulative delta")
    }
    records[[index]] <- record
  }
  if (!identical(previous, state$head_chain) ||
      !identical(cumulative_epsilon, state$cumulative_epsilon) ||
      !identical(cumulative_delta, state$cumulative_delta)) {
    stop("The vector release-ledger chain or composition state diverged.",
         call. = FALSE)
  }
  .dsvert_joint_dp_release_ledger_validate_tail(
    connection, config, secret, state)
  summary_state <- state
  if (isTRUE(exact_summary) && identical(arithmetic, "legacy")) {
    summary_state$cumulative_epsilon <-
      .dsvert_joint_dp_release_ledger_exact_total(
        config$release_epsilon, state$release_count,
        "audited cumulative epsilon")
    summary_state$cumulative_delta <-
      .dsvert_joint_dp_release_ledger_exact_total(
        config$release_delta, state$release_count,
        "audited cumulative delta")
  }
  list(state = state, records = records,
       summary = .dsvert_joint_dp_release_ledger_summary(
         config, summary_state))
}

.dsvert_joint_dp_release_ledger_migrate_state <- function(
    connection, config, secret, state) {
  if (identical(state$version,
                .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION)) {
    return(state)
  }
  if (!identical(state$version,
                 .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)) {
    stop("The vector release-ledger state arithmetic version is invalid.",
         call. = FALSE)
  }
  DBI::dbExecute(connection, "BEGIN IMMEDIATE")
  committed <- FALSE
  on.exit(if (!committed) try(
    DBI::dbExecute(connection, "ROLLBACK"), silent = TRUE), add = TRUE)
  state <- .dsvert_joint_dp_release_ledger_read_state(
    connection, config, secret)
  if (identical(state$version,
                .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)) {
    .dsvert_joint_dp_release_ledger_audit_state(
      connection, config, secret, state, arithmetic = "legacy")
    state <- .dsvert_joint_dp_release_ledger_write_state(
      connection, config, secret, state$release_count,
      .dsvert_joint_dp_release_ledger_exact_total(
        config$release_epsilon, state$release_count,
        "migrated cumulative epsilon"),
      .dsvert_joint_dp_release_ledger_exact_total(
        config$release_delta, state$release_count,
        "migrated cumulative delta"),
      state$head_chain, state$tail_release_instance_id,
      state$tail_row_mac)
  }
  DBI::dbExecute(connection, "COMMIT")
  committed <- TRUE
  state
}

.dsvert_joint_dp_release_ledger_audit <- function(
    connection, config, secret) {
  config <- .dsvert_joint_dp_release_ledger_validate_config(config)
  # Read-only recovery may encounter an authenticated v1 ledger before the
  # normal writable service opening performs its explicit state migration.
  # Validate its complete legacy recurrence and report the exact contractual
  # total in memory without attempting a write.
  initial <- tryCatch(
    .dsvert_joint_dp_release_ledger_read_state(
      connection, config, secret),
    error = function(error) NULL)
  if (is.list(initial) && identical(
      initial$version,
      .DSVERT_JOINT_DP_RELEASE_LEDGER_STATE_VERSION_V1)) {
    .dsvert_joint_dp_release_ledger_validate_meta(
      connection, config, secret)
    return(.dsvert_joint_dp_release_ledger_audit_state(
      connection, config, secret, initial, arithmetic = "legacy",
      exact_summary = TRUE))
  }
  .dsvert_joint_dp_release_ledger_initialize(
    connection, config, secret)
  state <- .dsvert_joint_dp_release_ledger_read_state(
    connection, config, secret)
  .dsvert_joint_dp_release_ledger_audit_state(
    connection, config, secret, state, arithmetic = "exact")
}

.dsvert_joint_dp_release_ledger_anchor <- function(
    connection, config, secret) {
  config <- .dsvert_joint_dp_release_ledger_validate_config(config)
  audit <- .dsvert_joint_dp_release_ledger_audit(
    connection, config, secret)
  state <- audit$state
  material <- list(
    version = .DSVERT_JOINT_DP_RELEASE_LEDGER_ANCHOR_VERSION,
    ledger_id = config$ledger_id,
    release_count = state$release_count,
    chain_head = state$head_chain,
    tail_release_instance_id = state$tail_release_instance_id)
  c(material, list(anchor_mac =
    .dsvert_joint_dp_release_ledger_hmac(secret, "anchor", material)))
}

.dsvert_joint_dp_release_ledger_validate_anchor <- function(
    config, secret, anchor) {
  fields <- c(
    "version", "ledger_id", "release_count", "chain_head",
    "tail_release_instance_id", "anchor_mac")
  valid <- is.list(anchor) && !is.null(names(anchor)) &&
    !anyNA(names(anchor)) && !anyDuplicated(names(anchor)) &&
    setequal(names(anchor), fields) &&
    identical(anchor$version,
              .DSVERT_JOINT_DP_RELEASE_LEDGER_ANCHOR_VERSION) &&
    identical(anchor$ledger_id, config$ledger_id)
  if (!isTRUE(valid)) {
    stop("The vector release-ledger continuity anchor is invalid.",
         call. = FALSE)
  }
  count <- tryCatch(
    .dsvert_joint_dp_release_ledger_count(
      anchor$release_count, "anchor release count"),
    error = function(error) NULL)
  head <- anchor$chain_head
  tail <- anchor$tail_release_instance_id
  material <- anchor[setdiff(names(anchor), "anchor_mac")]
  expected <- tryCatch(
    .dsvert_joint_dp_release_ledger_hmac(secret, "anchor", material),
    error = function(error) NULL)
  if (is.null(count) || !is.character(head) || length(head) != 1L ||
      is.na(head) || !(identical(head, "GENESIS") ||
        grepl("^[0-9a-f]{64}$", head, perl = TRUE)) ||
      !is.character(tail) || length(tail) != 1L || is.na(tail) ||
      !(identical(tail, "") || grepl("^[0-9a-f]{64}$", tail)) ||
      !identical(anchor$anchor_mac, expected) ||
      (count == 0 && (!identical(head, "GENESIS") || nzchar(tail))) ||
      (count > 0 && (identical(head, "GENESIS") || !nzchar(tail)))) {
    stop("The vector release-ledger continuity anchor failed authentication.",
         call. = FALSE)
  }
  anchor$release_count <- count
  anchor
}

.dsvert_joint_dp_release_ledger_assert_not_rolled_back <- function(
    connection, config, secret, anchor) {
  config <- .dsvert_joint_dp_release_ledger_validate_config(config)
  anchor <- .dsvert_joint_dp_release_ledger_validate_anchor(
    config, secret, anchor)
  current <- .dsvert_joint_dp_release_ledger_anchor(
    connection, config, secret)
  if (current$release_count < anchor$release_count) {
    stop("The vector release-ledger was rolled back below its continuity anchor.",
         call. = FALSE)
  }
  if (anchor$release_count == 0) return(invisible(current))
  row <- DBI::dbGetQuery(connection, paste(
    "SELECT release_instance_id,chain_hash FROM",
    "vector_release_ledger_records WHERE sequence=?"),
    params = list(anchor$release_count - 1))
  if (nrow(row) != 1L ||
      !identical(row$release_instance_id[[1L]],
                 anchor$tail_release_instance_id) ||
      !identical(row$chain_hash[[1L]], anchor$chain_head)) {
    stop("The vector release-ledger diverges from its continuity anchor.",
         call. = FALSE)
  }
  invisible(current)
}

.dsvert_joint_dp_release_ledger_history <- function(
    connection, config, secret) {
  config <- .dsvert_joint_dp_release_ledger_validate_config(config)
  audit <- .dsvert_joint_dp_release_ledger_audit(
    connection, config, secret)
  anchor <- .dsvert_joint_dp_release_ledger_anchor(
    connection, config, secret)
  if (!length(audit$records)) {
    return(list(
      status = "unused", source = "vector_release_instances",
      seal = anchor, count = 0,
      epsilon = 0, delta = 0, chain_head = "GENESIS"))
  }
  roots <- lapply(audit$records, `[[`, "local_noise_root")
  epochs <- vapply(roots, `[[`, numeric(1L), "privacy_epoch")
  current_epoch <- max(epochs)
  current <- roots[epochs == current_epoch]
  key_ids <- unique(vapply(
    current, `[[`, character(1L), "noise_key_id"))
  providers <- unique(vapply(
    current, `[[`, character(1L), "provider_id"))
  if (length(key_ids) != 1L || length(providers) != 1L) {
    stop("The vector release-ledger has conflicting local root history.",
         call. = FALSE)
  }
  summary <- audit$summary
  list(
    status = "used", source = "vector_release_instances",
    seal = anchor, privacy_epoch = current_epoch,
    noise_key_id = key_ids[[1L]],
    noise_key_provider_id = providers[[1L]],
    count = summary$release_instance_count,
    epsilon = summary$cumulative_epsilon,
    delta = summary$cumulative_delta,
    chain_head = audit$state$head_chain,
    composition_audit = list(
      release_count = summary$release_instance_count,
      cumulative_epsilon = summary$cumulative_epsilon,
      cumulative_delta = summary$cumulative_delta))
}

.dsvert_joint_dp_release_ledger_history_from_connection <- function(
    connection, secret) {
  config <- .dsvert_joint_dp_release_ledger_config_from_connection(
    connection, secret)
  if (is.null(config)) {
    return(.dsvert_joint_dp_release_ledger_legacy_history(
      connection, secret))
  }
  .dsvert_joint_dp_release_ledger_history(
    connection, config, secret)
}

# A v4 vector store may predate release-instance accounting.  Root recovery
# runs before a policy can be rebuilt, so authenticate its immutable binding
# and public-release rows directly.  This is a one-time continuity bridge, not
# an admission gate; normal store access immediately backfills the full ledger.
.dsvert_joint_dp_release_ledger_legacy_history <- function(
    connection, secret) {
  if (!inherits(connection, "DBIConnection") ||
      !is.raw(secret) || length(secret) != 32L) {
    stop("Invalid legacy vector history context.", call. = FALSE)
  }
  tables <- DBI::dbGetQuery(connection, paste(
    "SELECT name FROM sqlite_master WHERE type='table' AND name IN",
    "('vector_meta','vector_capsules') ORDER BY name"))$name
  expected_tables <- sort(
    c("vector_meta", "vector_capsules"), method = "radix")
  if (!length(tables)) return(NULL)
  if (!identical(tables, expected_tables)) {
    stop("The historical vector store is structurally incomplete.",
         call. = FALSE)
  }
  marker <- DBI::dbGetQuery(connection, paste(
    "SELECT value,row_mac FROM vector_meta",
    "WHERE key='release_ledger_backfill'"))
  if (nrow(marker)) {
    if (nrow(marker) != 1L ||
        !.dsvert_joint_dp_dsi_hex_equal(
          marker$row_mac[[1L]], .dsvert_joint_dp_vector_row_mac(
            secret, "meta", marker$value[[1L]]))) {
      stop("The vector release-ledger marker failed authentication.",
           call. = FALSE)
    }
    stop("The authenticated vector release ledger was removed after migration; restore the complete authenticated vector store from durable backup.",
         call. = FALSE)
  }
  binding_row <- DBI::dbGetQuery(connection, paste(
    "SELECT value,row_mac FROM vector_meta WHERE key='policy_binding'"))
  if (nrow(binding_row) != 1L ||
      !.dsvert_joint_dp_dsi_hex_equal(
        binding_row$row_mac[[1L]], .dsvert_joint_dp_vector_row_mac(
          secret, "meta", binding_row$value[[1L]]))) {
    stop("The historical vector policy binding failed authentication.",
         call. = FALSE)
  }
  binding <- .dsvert_joint_dp_release_ledger_decode_json(
    binding_row$value[[1L]], "legacy vector policy binding")
  binding_fields <- c(
    "version", "domain", "cohort_id", "peer_name",
    "peer_pinset_sha256", "privacy_epoch_scope")
  if (is.null(names(binding)) || anyNA(names(binding)) ||
      anyDuplicated(names(binding)) ||
      !setequal(names(binding), binding_fields) ||
      !identical(binding$version, .DSVERT_JOINT_DP_VECTOR_STORE_VERSION) ||
      !identical(binding$privacy_epoch_scope,
                 "per_peer_signed_release_instance_v1")) {
    stop("The historical vector policy binding is invalid.",
         call. = FALSE)
  }
  local_peer <- .dsvert_joint_dp_release_ledger_string(
    binding$peer_name, "legacy local peer", 128L,
    "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
  .dsvert_joint_dp_release_ledger_hex(
    binding$peer_pinset_sha256, "legacy peer-pinset hash")

  rows <- DBI::dbGetQuery(connection, paste(
    "SELECT release_instance_id,state,record_json,row_mac",
    "FROM vector_capsules ORDER BY release_instance_id"))
  released <- list()
  for (index in seq_len(nrow(rows))) {
    record <- .dsvert_joint_dp_vector_record_decode(
      rows[index, , drop = FALSE], secret, "vector_capsules",
      "legacy release-history capsule")
    row_id <- .dsvert_joint_dp_release_ledger_hex(
      rows$release_instance_id[[index]], "legacy release-instance id")
    if (!identical(record$version, .DSVERT_JOINT_DP_VECTOR_STORE_VERSION) ||
        !identical(record$release_instance_id, row_id)) {
      stop("A historical vector capsule contradicts its durable key.",
           call. = FALSE)
    }
    if (is.null(record$release_receipt_json)) next
    if (!record$state %in% c("released", "acked") ||
        !is.list(record$release_contract) ||
        !is.list(record$release_contract$release_instance)) {
      stop("A historical public vector release has invalid state.",
           call. = FALSE)
    }
    instance_json <- .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(
        record$release_contract$release_instance))
    instance <- .dsvert_joint_dp_release_ledger_instance(instance_json)
    final <- .dsvert_joint_dp_release_ledger_decode_json(
      record$release_receipt_json, "legacy public vector release")
    required <- c(
      "peer_name", "capsule_id", "release_instance_id",
      "final_vector_root", "epsilon", "delta")
    if (is.null(names(final)) || !all(required %in% names(final)) ||
        !identical(instance$id, row_id) ||
        !identical(record$capsule_id, instance$value$capsule_id) ||
        !identical(final$peer_name, local_peer) ||
        !identical(final$capsule_id, instance$value$capsule_id) ||
        !identical(final$release_instance_id, instance$id) ||
        !local_peer %in% instance$designated_noise_peers) {
      stop("A historical public vector release is not instance-bound.",
           call. = FALSE)
    }
    .dsvert_joint_dp_release_ledger_hex(
      final$final_vector_root, "legacy final-vector root")
    released[[length(released) + 1L]] <- list(
      release_instance_id = instance$id,
      root = instance$value$peer_noise_roots[[local_peer]],
      epsilon = .dsvert_joint_dp_release_ledger_decimal(
        final$epsilon, "legacy public release epsilon",
        open_minimum = TRUE, maximum = 8),
      delta = .dsvert_joint_dp_release_ledger_decimal(
        final$delta, "legacy public release delta",
        maximum = 1 - .Machine$double.eps),
      receipt_sha256 = digest::digest(
        record$release_receipt_json, algo = "sha256", serialize = FALSE),
      row_mac = rows$row_mac[[index]])
  }
  if (length(released) && anyDuplicated(vapply(
        released, `[[`, character(1L), "release_instance_id"))) {
    stop("The historical vector store duplicates a public release instance.",
         call. = FALSE)
  }
  chain <- "GENESIS"
  for (release in released) {
    chain <- .dsvert_joint_dp_release_ledger_hash(list(
      previous_chain = chain,
      release_instance_id = release$release_instance_id,
      receipt_sha256 = release$receipt_sha256,
      row_mac = release$row_mac))
  }
  seal <- list(
    version = "dsvert-joint-dp-vector-legacy-history-seal-v1",
    policy_binding_mac = binding_row$row_mac[[1L]],
    release_count = length(released), chain_head = chain)
  if (!length(released)) {
    return(list(
      status = "unused", source = "vector_release_instances_legacy",
      seal = seal, count = 0, epsilon = 0, delta = 0,
      chain_head = "GENESIS"))
  }
  roots <- lapply(released, `[[`, "root")
  epochs <- vapply(roots, `[[`, numeric(1L), "privacy_epoch")
  current <- roots[epochs == max(epochs)]
  key_ids <- unique(vapply(current, `[[`, character(1L), "noise_key_id"))
  providers <- unique(vapply(current, `[[`, character(1L), "provider_id"))
  if (length(key_ids) != 1L || length(providers) != 1L) {
    stop("The historical vector store has conflicting local root history.",
         call. = FALSE)
  }
  epsilon_text <- .dsvert_joint_dp_release_ledger_exact_sum(
    vapply(released, `[[`, character(1L), "epsilon"),
    "legacy cumulative epsilon")
  delta_text <- .dsvert_joint_dp_release_ledger_exact_sum(
    vapply(released, `[[`, character(1L), "delta"),
    "legacy cumulative delta")
  epsilon <- .dsvert_joint_dp_release_ledger_upper_numeric(
    epsilon_text, "legacy cumulative epsilon")
  delta <- .dsvert_joint_dp_release_ledger_upper_numeric(
    delta_text, "legacy cumulative delta")
  list(
    status = "used", source = "vector_release_instances_legacy",
    seal = seal, privacy_epoch = max(epochs),
    noise_key_id = key_ids[[1L]],
    noise_key_provider_id = providers[[1L]],
    count = length(released), epsilon = epsilon, delta = delta,
    chain_head = chain,
    composition_audit = list(
      release_count = length(released),
      cumulative_epsilon = epsilon,
      cumulative_delta = delta,
      migration = "authenticated_legacy_public_releases"))
}

.dsvert_joint_dp_release_ledger_history_from_path <- function(
    path, secret) {
  if (!is.character(path) || length(path) != 1L || is.na(path) ||
      !nzchar(path) || !is.raw(secret) || length(secret) != 32L) {
    stop("Invalid vector release-ledger history path.", call. = FALSE)
  }
  path <- path.expand(path)
  what <- "joint DP vector release ledger"
  if (!.dsvert_dp_history_file_present(path, what)) return(NULL)
  .dsvert_dp_history_readonly(path, what, function(connection) {
    DBI::dbExecute(connection, "PRAGMA busy_timeout=30000")
    .dsvert_joint_dp_release_ledger_history_from_connection(
      connection, secret)
  })
}

.dsvert_joint_dp_release_recovery_route <- function(
    historical_release_instance_json, active_peer_noise_roots,
    final_available) {
  if (!is.logical(final_available) || length(final_available) != 1L ||
      is.na(final_available)) {
    stop("Invalid vector release recovery final-state flag.", call. = FALSE)
  }
  historical <- .dsvert_joint_dp_release_ledger_instance(
    historical_release_instance_json)
  if (isTRUE(final_available)) {
    return(list(
      action = "replay_final",
      release_instance_id = historical$id,
      release_instance_json = historical$json,
      new_composition_release = FALSE))
  }
  stop(.dsvert_dp_lifetime_budget_exhausted_condition())
}
