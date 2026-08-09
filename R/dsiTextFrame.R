# Canonical text framing for scalar client-to-DSI arguments.  Every emitted
# byte belongs to the deliberately narrow alphabet accepted by DSLite, Opal
# and Armadillo expression parsers.

.DSVERT_DSI_TEXT_PREFIX_R <- "DSV1R_"
.DSVERT_DSI_TEXT_PREFIX_L <- "DSV1L_"
.DSVERT_DSI_TEXT_PREFIX_B <- "DSV1B_"
.DSVERT_DSI_TEXT_MAX_BYTES <- 256 * 1024^2
.DSVERT_DSI_TEXT_CHUNK_BYTES <- 64L * 1024L
.DSVERT_DSI_TEXT_L_BATCH_RUNS <- 2048L
.DSVERT_DSI_TEXT_HEX_VALUES <- rep.int(NA_integer_, 256L)
.DSVERT_DSI_TEXT_HEX_VALUES[1L + c(48:57, 65:70)] <- 0:15

.dsvert_dsi_text_abort <- function(what) {
  stop("Invalid framed DSI text for ", what, ".", call. = FALSE)
}

.dsvert_dsi_text_safe_raw <- function(value) {
  (value >= as.raw(48L) & value <= as.raw(57L)) |
    (value >= as.raw(65L) & value <= as.raw(90L)) |
    (value >= as.raw(97L) & value <= as.raw(122L)) |
    value == as.raw(45L) | value == as.raw(95L)
}

.dsvert_dsi_text_b64_length <- function(bytes) {
  quotient <- bytes %/% 3
  remainder <- bytes %% 3
  4 * quotient + if (remainder == 0) 0 else if (remainder == 1) 2 else 3
}

.dsvert_dsi_text_decimal_digits <- function(value) {
  ifelse(value == 0, 1, floor(log10(value)) + 1)
}

.dsvert_dsi_text_raw_plan <- function(bytes) {
  size <- length(bytes)
  if (!size) return(list(mode = "R", encoded_bytes = 6))
  b_length <- 6 + .dsvert_dsi_text_b64_length(size)
  unsafe_count <- 0
  header_bytes <- 0
  previous <- 0
  chunk_start <- 1L
  while (chunk_start <= size) {
    chunk_end <- min(size, chunk_start + .DSVERT_DSI_TEXT_CHUNK_BYTES - 1L)
    chunk_index <- seq.int(chunk_start, chunk_end)
    safe <- .dsvert_dsi_text_safe_raw(bytes[chunk_index])
    bad <- which(!safe)
    if (length(bad)) {
      bad <- chunk_start - 1 + bad
      runs <- bad - c(previous, head(bad, -1L)) - 1
      unsafe_count <- unsafe_count + length(bad)
      header_bytes <- header_bytes +
        sum(.dsvert_dsi_text_decimal_digits(runs) + 1)
      previous <- tail(bad, 1L)
      if (6 + size + 3 * unsafe_count > b_length) {
        return(list(mode = "B", encoded_bytes = b_length))
      }
    }
    chunk_start <- chunk_end + 1L
  }
  if (!unsafe_count) return(list(mode = "R", encoded_bytes = 6 + size))
  trailing <- size - previous
  if (trailing > 0) {
    header_bytes <- header_bytes +
      .dsvert_dsi_text_decimal_digits(trailing) + 1
  }
  l_length <- 6 + size + unsafe_count + header_bytes
  if (l_length <= b_length) {
    list(mode = "L", encoded_bytes = l_length)
  } else {
    list(mode = "B", encoded_bytes = b_length)
  }
}

.dsvert_dsi_text_plan <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      identical(Encoding(value), "bytes")) {
    .dsvert_dsi_text_abort(what)
  }
  value <- tryCatch(enc2utf8(value), error = function(error) NULL)
  if (is.null(value) || !isTRUE(validUTF8(value))) {
    .dsvert_dsi_text_abort(what)
  }
  size <- nchar(value, type = "bytes")
  if (size > .DSVERT_DSI_TEXT_MAX_BYTES) .dsvert_dsi_text_abort(what)
  if (grepl("^[A-Za-z0-9_-]*$", value, perl = TRUE, useBytes = TRUE)) {
    return(list(mode = "R", value = value, encoded_bytes = 6 + size))
  }
  bytes <- charToRaw(value)
  plan <- .dsvert_dsi_text_raw_plan(bytes)
  c(plan, list(value = value, bytes = bytes))
}

.dsvert_dsi_text_encode_l <- function(plan) {
  bytes <- plan$bytes
  size <- length(bytes)
  encoded <- raw(plan$encoded_bytes)
  encoded[seq_len(6L)] <- charToRaw(.DSVERT_DSI_TEXT_PREFIX_L)
  output_at <- 7L
  previous <- 0L
  chunk_start <- 1L
  while (chunk_start <= size) {
    chunk_end <- min(size, chunk_start + .DSVERT_DSI_TEXT_CHUNK_BYTES - 1L)
    chunk_index <- seq.int(chunk_start, chunk_end)
    safe <- .dsvert_dsi_text_safe_raw(bytes[chunk_index])
    bad <- which(!safe)
    if (length(bad)) {
      bad <- chunk_start - 1L + bad
      for (index in bad) {
        run <- index - previous - 1L
        header <- charToRaw(paste0(run, "-"))
        encoded[seq.int(output_at, length.out = length(header))] <- header
        output_at <- output_at + length(header)
        source_at <- previous + 1L
        remaining <- run
        while (remaining > 0L) {
          amount <- min(.DSVERT_DSI_TEXT_CHUNK_BYTES, remaining)
          source_index <- seq.int(source_at, length.out = amount)
          output_index <- seq.int(output_at, length.out = amount)
          encoded[output_index] <- bytes[source_index]
          source_at <- source_at + amount
          output_at <- output_at + amount
          remaining <- remaining - amount
        }
        hex <- charToRaw(sprintf("%02X", as.integer(bytes[[index]])))
        encoded[seq.int(output_at, length.out = 2L)] <- hex
        output_at <- output_at + 2L
        previous <- index
      }
    }
    chunk_start <- chunk_end + 1L
  }
  trailing <- size - previous
  if (trailing > 0L) {
    header <- charToRaw(paste0(trailing, "-"))
    encoded[seq.int(output_at, length.out = length(header))] <- header
    output_at <- output_at + length(header)
    source_at <- previous + 1L
    remaining <- trailing
    while (remaining > 0L) {
      amount <- min(.DSVERT_DSI_TEXT_CHUNK_BYTES, remaining)
      source_index <- seq.int(source_at, length.out = amount)
      output_index <- seq.int(output_at, length.out = amount)
      encoded[output_index] <- bytes[source_index]
      source_at <- source_at + amount
      output_at <- output_at + amount
      remaining <- remaining - amount
    }
  }
  if (output_at != length(encoded) + 1L) {
    .dsvert_dsi_text_abort("DSI argument")
  }
  rawToChar(encoded)
}

.dsvert_dsi_text_encode_b <- function(plan) {
  payload <- gsub("[\r\n]", "", jsonlite::base64_enc(plan$bytes))
  payload <- chartr("+/", "-_", sub("=+$", "", payload, perl = TRUE))
  paste0(.DSVERT_DSI_TEXT_PREFIX_B, payload)
}

.dsvert_dsi_text_encode <- function(value, what = "DSI argument") {
  plan <- .dsvert_dsi_text_plan(value, what)
  encoded <- switch(plan$mode,
    R = paste0(.DSVERT_DSI_TEXT_PREFIX_R, plan$value),
    L = .dsvert_dsi_text_encode_l(plan),
    B = .dsvert_dsi_text_encode_b(plan))
  if (nchar(encoded, type = "bytes") != plan$encoded_bytes) {
    .dsvert_dsi_text_abort(what)
  }
  encoded
}

.dsvert_dsi_text_b64_value <- function(value) {
  if (value >= as.raw(65L) && value <= as.raw(90L)) {
    return(as.integer(value) - 65L)
  }
  if (value >= as.raw(97L) && value <= as.raw(122L)) {
    return(as.integer(value) - 71L)
  }
  if (value >= as.raw(48L) && value <= as.raw(57L)) {
    return(as.integer(value) + 4L)
  }
  if (value == as.raw(45L)) return(62L)
  if (value == as.raw(95L)) return(63L)
  NA_integer_
}

.dsvert_dsi_text_decode_l_pass <- function(
    input, maximum_bytes, what, decoded_bytes = NULL) {
  input_size <- length(input)
  if (input_size <= 6L) .dsvert_dsi_text_abort(what)
  build <- !is.null(decoded_bytes)
  decoded <- if (build) raw(decoded_bytes) else NULL
  batch_size <- .DSVERT_DSI_TEXT_L_BATCH_RUNS
  batch_copy_bytes <- .DSVERT_DSI_TEXT_CHUNK_BYTES %/% 4L
  small_run <- batch_copy_bytes %/% batch_size
  run_inputs <- if (build) integer(batch_size) else integer()
  run_outputs <- if (build) integer(batch_size) else integer()
  run_lengths <- if (build) integer(batch_size) else integer()
  unsafe_outputs <- if (build) integer(batch_size) else integer()
  unsafe_values <- if (build) integer(batch_size) else integer()
  input_at <- 7L
  output_at <- 1L
  unsafe_count <- 0L
  header_bytes <- 0
  terminal <- FALSE
  repeat {
    batch_runs <- 0L
    batch_unsafe <- 0L
    for (unused in seq_len(batch_size)) {
      digit_at <- input_at
      digit <- as.integer(input[[input_at]]) - 48L
      if (digit < 0L || digit > 9L) .dsvert_dsi_text_abort(what)
      run <- digit
      input_at <- input_at + 1L
      if (input_at <= input_size &&
          input[[input_at]] == as.raw(45L)) {
        digits <- 1L
      } else {
        if (digit == 0L) .dsvert_dsi_text_abort(what)
        while (input_at <= input_size &&
               input[[input_at]] >= as.raw(48L) &&
               input[[input_at]] <= as.raw(57L)) {
          digit <- as.integer(input[[input_at]]) - 48L
          if (run > floor((maximum_bytes - digit) / 10)) {
            .dsvert_dsi_text_abort(what)
          }
          run <- 10 * run + digit
          input_at <- input_at + 1L
        }
        digits <- input_at - digit_at
      }
      if (input_at > input_size ||
          input[[input_at]] != as.raw(45L)) {
        .dsvert_dsi_text_abort(what)
      }
      header_bytes <- header_bytes + digits + 1L
      input_at <- input_at + 1L
      decoded_so_far <- output_at - 1L
      if (run > maximum_bytes - decoded_so_far ||
          run > input_size - input_at + 1L) {
        .dsvert_dsi_text_abort(what)
      }
      # .dsvert_dsi_text_decode() has already checked every frame byte
      # against the safe wire alphabet, so declared runs need no rescan.
      if (build && run > 0L) {
        if (run <= small_run) {
          batch_runs <- batch_runs + 1L
          run_inputs[[batch_runs]] <- input_at
          run_outputs[[batch_runs]] <- output_at
          run_lengths[[batch_runs]] <- run
        } else {
          remaining <- run
          source_at <- input_at
          target_at <- output_at
          while (remaining > 0L) {
            amount <- min(.DSVERT_DSI_TEXT_CHUNK_BYTES, remaining)
            source_index <- seq.int(source_at, length.out = amount)
            output_index <- seq.int(target_at, length.out = amount)
            decoded[output_index] <- input[source_index]
            source_at <- source_at + amount
            target_at <- target_at + amount
            remaining <- remaining - amount
          }
        }
      }
      input_at <- input_at + run
      output_at <- output_at + run
      if (input_at > input_size) {
        if (run == 0L) .dsvert_dsi_text_abort(what)
        terminal <- TRUE
        break
      }
      if (input_at + 1L > input_size || output_at > maximum_bytes) {
        .dsvert_dsi_text_abort(what)
      }
      high <- .DSVERT_DSI_TEXT_HEX_VALUES[[
        as.integer(input[[input_at]]) + 1L]]
      low <- .DSVERT_DSI_TEXT_HEX_VALUES[[
        as.integer(input[[input_at + 1L]]) + 1L]]
      if (is.na(high) || is.na(low)) .dsvert_dsi_text_abort(what)
      byte <- 16L * high + low
      if ((byte >= 48L && byte <= 57L) ||
          (byte >= 65L && byte <= 90L) ||
          (byte >= 97L && byte <= 122L) ||
          byte == 45L || byte == 95L) {
        .dsvert_dsi_text_abort(what)
      }
      if (build) {
        batch_unsafe <- batch_unsafe + 1L
        unsafe_outputs[[batch_unsafe]] <- output_at
        unsafe_values[[batch_unsafe]] <- byte
      }
      output_at <- output_at + 1L
      unsafe_count <- unsafe_count + 1L
      input_at <- input_at + 2L
      if (input_at > input_size) {
        terminal <- TRUE
        break
      }
    }
    if (build && batch_runs > 0L) {
      present <- seq_len(batch_runs)
      lengths <- run_lengths[present]
      offsets <- sequence(lengths)
      source_index <- offsets +
        rep.int(run_inputs[present] - 1L, lengths)
      output_index <- offsets +
        rep.int(run_outputs[present] - 1L, lengths)
      decoded[output_index] <- input[source_index]
    }
    if (build && batch_unsafe > 0L) {
      present <- seq_len(batch_unsafe)
      decoded[unsafe_outputs[present]] <- as.raw(unsafe_values[present])
    }
    if (terminal) break
  }
  list(
    decoded = decoded, decoded_bytes = output_at - 1L,
    unsafe_count = unsafe_count, header_bytes = header_bytes)
}

.dsvert_dsi_text_decode_l <- function(value, maximum_bytes, what) {
  input <- charToRaw(value)
  plan <- .dsvert_dsi_text_decode_l_pass(input, maximum_bytes, what)
  expected_length <- 6 + plan$decoded_bytes + plan$unsafe_count +
    plan$header_bytes
  b_length <- 6 + .dsvert_dsi_text_b64_length(plan$decoded_bytes)
  if (!plan$unsafe_count || expected_length != length(input) ||
      expected_length > b_length) {
    .dsvert_dsi_text_abort(what)
  }
  built <- .dsvert_dsi_text_decode_l_pass(
    input, maximum_bytes, what, decoded_bytes = plan$decoded_bytes)
  if (built$decoded_bytes != plan$decoded_bytes ||
      built$unsafe_count != plan$unsafe_count ||
      built$header_bytes != plan$header_bytes) {
    .dsvert_dsi_text_abort(what)
  }
  built$decoded
}

.dsvert_dsi_text_decode_b <- function(body, what) {
  body_size <- nchar(body, type = "bytes")
  if (!grepl("^[A-Za-z0-9_-]*$", body, perl = TRUE, useBytes = TRUE) ||
      body_size %% 4L == 1L) {
    .dsvert_dsi_text_abort(what)
  }
  remainder <- body_size %% 4L
  if (remainder %in% c(2L, 3L)) {
    last <- charToRaw(substr(body, body_size, body_size))[[1L]]
    value <- .dsvert_dsi_text_b64_value(last)
    modulus <- if (remainder == 2L) 16L else 4L
    if (is.na(value) || value %% modulus != 0L) {
      .dsvert_dsi_text_abort(what)
    }
  }
  padding <- (4L - remainder) %% 4L
  decoded <- tryCatch(
    jsonlite::base64_dec(paste0(chartr("-_", "+/", body),
                                strrep("=", padding))),
    error = function(error) .dsvert_dsi_text_abort(what))
  plan <- .dsvert_dsi_text_raw_plan(decoded)
  if (!identical(plan$mode, "B") ||
      plan$encoded_bytes != 6 + body_size) {
    .dsvert_dsi_text_abort(what)
  }
  decoded
}

.dsvert_dsi_text_decode <- function(
    value, what = "DSI argument",
    maximum_bytes = .DSVERT_DSI_TEXT_MAX_BYTES) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !is.numeric(maximum_bytes) || length(maximum_bytes) != 1L ||
      is.na(maximum_bytes) || !is.finite(maximum_bytes) ||
      maximum_bytes != floor(maximum_bytes) || maximum_bytes < 0 ||
      maximum_bytes > .DSVERT_DSI_TEXT_MAX_BYTES) {
    .dsvert_dsi_text_abort(what)
  }
  value_size <- nchar(value, type = "bytes")
  maximum_encoded <- 6 + .dsvert_dsi_text_b64_length(maximum_bytes)
  if (value_size > maximum_encoded ||
      !grepl("^[A-Za-z0-9_-]*$", value, perl = TRUE, useBytes = TRUE)) {
    .dsvert_dsi_text_abort(what)
  }
  prefix <- substr(value, 1L, 6L)
  if (identical(prefix, .DSVERT_DSI_TEXT_PREFIX_R)) {
    body <- substr(value, 7L, value_size)
    if (nchar(body, type = "bytes") > maximum_bytes) {
      .dsvert_dsi_text_abort(what)
    }
    return(body)
  }
  decoded_raw <- if (identical(prefix, .DSVERT_DSI_TEXT_PREFIX_L)) {
    .dsvert_dsi_text_decode_l(value, maximum_bytes, what)
  } else if (identical(prefix, .DSVERT_DSI_TEXT_PREFIX_B)) {
    .dsvert_dsi_text_decode_b(substr(value, 7L, value_size), what)
  } else {
    .dsvert_dsi_text_abort(what)
  }
  if (!is.raw(decoded_raw) || length(decoded_raw) > maximum_bytes) {
    .dsvert_dsi_text_abort(what)
  }
  decoded <- tryCatch(rawToChar(decoded_raw), error = function(error) NULL)
  if (is.null(decoded) || !isTRUE(validUTF8(decoded))) {
    .dsvert_dsi_text_abort(what)
  }
  Encoding(decoded) <- "UTF-8"
  decoded
}
