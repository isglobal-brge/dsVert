.frequency_execution_pk <- function(index) {
  .dsvert_relay_b64url_encode(as.raw(rep(as.integer(index), 32L)))
}

.frequency_execution_transport_pk <- function(index) {
  gsub("[\r\n]", "", jsonlite::base64_enc(
    as.raw(rep(as.integer(index + 20L), 32L))))
}

.frequency_execution_signature <- function(message, key) {
  .dsvert_relay_b64url_encode(digest::hmac(
    key = charToRaw(key), object = message, algo = "sha512",
    serialize = FALSE, raw = TRUE))
}

.frequency_execution_verifier <- function(
    message, identity_pk, signature, peer_name = NULL) {
  identical(signature, .frequency_execution_signature(message, identity_pk))
}

.frequency_execution_snapshot <- function(data, config, peer_name, claim, ...) {
  list(
    psi_run_sha256 = claim$psi_run_sha256,
    snapshot_commitment = digest::digest(list(
      ids = as.character(data[[config$privacy_unit_column]]),
      labels = as.character(data[[config$factor_domain$variable_name]])),
      algo = "sha256", serialize = TRUE))
}

.frequency_execution_crypto <- function() {
  tag <- function(value) digest::digest(
    value, algo = "sha512", serialize = FALSE, raw = TRUE)[seq_len(60L)]
  list(
    encrypt = function(value, recipient_pk) {
      expect_true(is.raw(value))
      .dsvert_relay_b64url_encode(c(tag(value), value))
    },
    decrypt = function(value) {
      sealed <- .dsvert_relay_b64url_decode(value, "test ciphertext")
      if (length(sealed) != 1056828L) stop("test ciphertext geometry")
      frame <- sealed[-seq_len(60L)]
      if (!identical(sealed[seq_len(60L)], tag(frame))) {
        stop("test ciphertext authentication")
      }
      frame
    })
}

.frequency_execution_decode_ring128 <- function(value) {
  raw <- jsonlite::base64_dec(value)
  starts <- seq.int(1L, length(raw), by = 16L)
  vapply(starts, function(start) sum(
    as.integer(raw[start + 0:3]) * 256^(0:3)), numeric(1L))
}

.frequency_execution_encode_ring128 <- function(values) {
  raw <- raw(length(values) * 16L)
  starts <- seq.int(1L, length(raw), by = 16L)
  for (byte in 0:3) raw[starts + byte] <- as.raw(bitwAnd(
    bitwShiftR(as.integer(values), 8L * byte), 255L))
  gsub("[\r\n]", "", jsonlite::base64_enc(raw))
}

.frequency_execution_sampler <- function(counter) {
  function(command, input, expected) {
    counter$calls <- counter$calls + 1L
    counter$requests[[length(counter$requests) + 1L]] <- list(
      command = command, input = input)
    gaussian <- grepl("gaussian", command, fixed = TRUE)
    if (grepl("share", command, fixed = TRUE)) {
      values <- .frequency_execution_decode_ring128(input$source_share)
      increment <- if (grepl("source", input$peer_name, fixed = TRUE)) 1 else 2
      noised <- .frequency_execution_encode_ring128(values + increment)
      counter$shares <- c(counter$shares, noised)
      output <- list(
        version = if (gaussian) paste0(
          "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-",
          "share-v2") else paste0(
          "dsvert-joint-dp-vector-independent-full-draw-convolution-",
          "share-v3"),
        backend = expected$backend, sampler = expected$sampler,
        release_contract_hash = input$release_contract_hash,
        sampler_contract_hash = digest::digest(
          expected$plan, algo = "sha256", serialize = TRUE),
        transcript_hash = input$transcript_hash, peer_name = input$peer_name,
        seed_commitment = input$seed_commitment,
        ring_bits = 128L, frac_bits = 0L,
        total_coordinate_count = input$total_coordinate_count,
        chunk_start = input$chunk_start,
        coordinate_count = input$coordinate_count,
        noised_share = noised,
        maximum_noise_magnitude_per_peer = "10",
        maximum_noise_magnitude_two_peers = "20",
        full_capsule_parameters_per_peer = TRUE,
        epsilon_divided_by_peer_count = FALSE,
        source_values_returned = FALSE, noise_values_returned = FALSE,
        private_seed_returned = FALSE, preclamp_values_returned = FALSE,
        no_wrap_headroom_certified = TRUE,
        source_bound_precondition = paste0(
          "authenticated_semi_honest_capsule_materializer_",
          "and_source_transport"),
        nominal_variance_multiplier = 2L, plan = expected$plan)
      if (gaussian) output <- c(output, list(
        mechanism = "dyadic_discrete_gaussian_truncated_tv_bounded",
        tail_projection_applied = FALSE, tail_truncation_applied = TRUE,
        fixed_work_shape_verified = TRUE))
      return(output)
    }
    left <- .frequency_execution_decode_ring128(input$left_noised_share)
    right <- .frequency_execution_decode_ring128(input$right_noised_share)
    upper <- as.numeric(unlist(input$raw_upper_bounds, use.names = FALSE))
    output <- list(
      version = if (gaussian) paste0(
        "dsvert-joint-dp-vector-dyadic-discrete-gaussian-tv-bounded-",
        "finalizer-v2") else paste0(
        "dsvert-joint-dp-vector-independent-full-draw-finalizer-v3"),
      backend = expected$backend, sampler = expected$sampler,
      release_contract_hash = input$release_contract_hash,
      transcript_hash = input$transcript_hash,
      ring_bits = 128L, frac_bits = 0L,
      total_coordinate_count = input$total_coordinate_count,
      chunk_start = input$chunk_start,
      coordinate_count = input$coordinate_count,
      output_lattice_bits = 1L,
      clamped_scaled_values = as.list(as.character(pmin(left + right, upper))),
      preclamp_values_returned = FALSE,
      signed_decode = "canonical_Ring128_twos_complement_after_proven_no_wrap",
      clamping = "single_fixed_public_per_coordinate_interval_postprocessing",
      no_wrap_headroom_certified = TRUE, plan = expected$plan)
    if (gaussian) output$mechanism <-
      "dyadic_discrete_gaussian_truncated_tv_bounded"
    output
  }
}

.frequency_execution_fixture <- function(k = 3L, gaussian = FALSE, d = 3L) {
  peers <- paste0("site_", seq_len(k))
  pins <- stats::setNames(vapply(
    seq_len(k), .frequency_execution_pk, character(1L)), peers)
  roles <- list(
    source_owner = unname(pins[[2L]]),
    secondary_noise_authority = unname(pins[[1L]]))
  role_peers <- stats::setNames(c(peers[[2L]], peers[[1L]]), names(roles))
  primitive <- if (gaussian) paste0(
    "independent_full_global_dyadic_discrete_gaussian_",
    "tv_bounded_ring128_v2") else
      "independent_full_global_draw_convolution_ring128_v3"
  profile <- .dsvert_dp_analysis_frequency_profile_v1(primitive)
  chunk <- min(8192L, d)
  worker <- list(
    selected_primitive = primitive, selected_profile = profile,
    selected_request = if (gaussian) list(
      epsilon = "1", delta = "0.001", l2_sensitivity_steps = "1",
      total_coordinate_count = d) else list(
      epsilon = "1", delta = "0.001", sensitivity_steps = "1",
      total_coordinate_count = d),
    selected_plan = list(version = profile$plan, marker = "test-plan"),
    selected_plan_sha256 = strrep("9", 64L),
    ring_bits = 128L, frac_bits = 0L, output_lattice_bits = 1L,
    d = d, chunk_coordinates = chunk,
    chunk_count = as.integer(ceiling(d / 8192L)),
    raw_bound = list(lower = "0", upper = "64", scale = 0L),
    authority_roles = roles,
    authority_tokens = list(
      source_owner = "source_authority",
      secondary_noise_authority = "secondary_authority"),
    release_contract_hash = strrep("a", 64L),
    transcript_hash = strrep("b", 64L),
    commitment_contexts = list(
      source_owner = strrep("c", 64L),
      secondary_noise_authority = strrep("d", 64L)),
    source_share_policy = list(
      source_owner = "private_frequency_vector_ring128_v1",
      secondary_noise_authority = "zero_vector_ring128_v1"))
  claim <- list(psi_run_sha256 = strrep("e", 64L))
  config <- list(
    peer_pins = pins, privacy_unit_column = "patient_id",
    source_owner = list(peer_name = role_peers[["source_owner"]],
                        identity_pk = roles$source_owner),
    factor_domain = list(
      variable_name = "category", variable_id = "category-v1",
      levels = as.list(c("a", "b", "c")), dimension = d),
    coordinate_upper_bound = 1000000L)
  data <- data.frame(
    patient_id = paste0("p", 1:4),
    category = factor(c("a", "outside", NA_character_, "b"),
                      levels = c("a", "b", "c", "outside")),
    stringsAsFactors = FALSE)
  normalized <- data
  normalized$category <- factor(c("a", NA, NA, "b"),
                                levels = c("a", "b", "c"))
  snapshot <- .frequency_execution_snapshot(
    normalized, config, role_peers[["source_owner"]], claim)$snapshot_commitment
  contract <- list(
    artifact_key = strrep("1", 64L),
    semantic = list(
      owner_snapshots = stats::setNames(list(list(
        snapshot_commitment = snapshot)), roles$source_owner),
      privacy = list(
        adjacency = "add_remove_patient", epsilon = 1, delta = 0.01,
        mechanism = list(
          family = profile$mechanism_family, version = profile$mechanism,
          sensitivity = list(norm = profile$sensitivity_norm, value = 1),
          calibration = list(
            sampler = profile$sampler, implementation_delta = 0.001))),
      analysis = list(effective_arguments = list(
        sampler_plan = list(coordinate_order_sha256 = strrep("2", 64L))))))
  common <- list(
    version = .DSVERT_DP_FREQUENCY_AUTHORIZATION_VERSION,
    session_id = "00000000-0000-4000-8000-000000000001",
    artifact_key = contract$artifact_key, config = config,
    config_sha256 = strrep("3", 64L),
    source_claim_sha256 = .dsvert_dp_frequency_hash_v1(
      .DSVERT_DP_FREQUENCY_CLAIM_HASH_DOMAIN, claim),
    receipt_peers = as.list(peers), receipt_set_sha256 = strrep("4", 64L),
    psi_run_sha256 = claim$psi_run_sha256, contract = contract,
    contract_sha256 = strrep("5", 64L),
    analysis_binding = list(authority_roles = roles),
    analysis_binding_sha256 = strrep("6", 64L),
    worker_static = worker, worker_static_sha256 = strrep("7", 64L))
  seeds <- list(source_owner = strrep("0", 64L),
                secondary_noise_authority = strrep("f", 64L))
  authorizations <- lapply(names(roles), function(role) {
    auth <- c(common, list(local_authority = list(
      peer_name = role_peers[[role]], identity_pk = roles[[role]], role = role),
      authorization_sha256 = if (role == "source_owner") strrep("8", 64L)
      else strrep("0", 64L)))
    unsigned <- .dsvert_dp_analysis_canonical_value_v1(list(
      version = .DSVERT_DP_FREQUENCY_PUBLIC_AUTHORIZATION_VERSION,
      session_id = auth$session_id, artifact_key = auth$artifact_key,
      config_sha256 = auth$config_sha256,
      source_claim_sha256 = auth$source_claim_sha256,
      receipt_set_sha256 = auth$receipt_set_sha256,
      psi_run_sha256 = auth$psi_run_sha256,
      contract_sha256 = auth$contract_sha256,
      analysis_binding_sha256 = auth$analysis_binding_sha256,
      worker_static_sha256 = auth$worker_static_sha256,
      local_authority = auth$local_authority,
      commitment_context = worker$commitment_contexts[[role]],
      seed_commitment = .dsvert_joint_dp_vector_seed_commitment(
        worker$commitment_contexts[[role]], seeds[[role]]),
      authorization_sha256 = auth$authorization_sha256))
    public <- .dsvert_dp_analysis_canonical_value_v1(c(unsigned, list(
      signature = .frequency_execution_signature(
        .dsvert_dp_frequency_public_authorization_message_v1(unsigned),
        roles[[role]]))))
    list(auth = auth, public = public)
  })
  names(authorizations) <- names(roles)
  list(
    k = k, peers = peers, pins = pins, roles = roles,
    role_peers = role_peers, data = data, claim = claim,
    source = authorizations$source_owner$auth,
    secondary = authorizations$secondary_noise_authority$auth,
    public = lapply(authorizations, `[[`, "public"), seeds = seeds,
    transport = stats::setNames(list(
      .frequency_execution_transport_pk(2L),
      .frequency_execution_transport_pk(1L)), names(roles)))
}

.frequency_execution_state <- function(fixture, authorization) {
  ss <- new.env(parent = emptyenv())
  ss$.dp_frequency_authorization <- authorization
  local_role <- authorization$local_authority$role
  other_role <- setdiff(names(fixture$roles), local_role)
  other_peer <- fixture$role_peers[[other_role]]
  ss$.typed_blob_self_name <- authorization$local_authority$peer_name
  ss$.typed_blob_peer_identity_pks <- stats::setNames(
    list(.base64url_to_base64(fixture$roles[[other_role]])), other_peer)
  ss$.typed_blob_peer_binding_digest <- strrep("a", 64L)
  ss$.typed_blob_parent_binding_digest <- strrep("b", 64L)
  ss$.exact_gc_peer_binding_digest <- strrep("b", 64L)
  ss$peer_transport_pks <- stats::setNames(
    list(fixture$transport[[other_role]]), other_peer)
  ss
}

.frequency_execution_reserve <- function(events = NULL) {
  function(ss, session_id, artifact_key, role, dimension, window_coordinates) {
    if (!is.null(events)) events$values <- c(events$values, "reserve")
    candidate <- list(
      session_id = session_id, artifact_key = artifact_key, role = role,
      dimension = as.numeric(dimension),
      window_coordinates = as.numeric(window_coordinates), bytes = 1)
    prior <- ss$.dp_frequency_resource_reservation
    if (!is.null(prior) && !identical(prior, candidate)) stop("reserve conflict")
    ss$.dp_frequency_resource_reservation <- candidate
    invisible(candidate)
  }
}

.frequency_execution_as <- function(
    authorization, code, reserve = .frequency_execution_reserve()) {
  testthat::with_mocked_bindings(
    code(),
    .dsvert_dp_frequency_session_authorization_validate_v1 =
      function(ss, session_id, artifact_key = NULL) {
        expect_identical(ss$.dp_frequency_authorization, authorization)
        authorization
      },
    .dsvert_dp_frequency_claim_validate_v1 = function(claim, ...) claim,
    .dsvert_dp_frequency_snapshot_v1 = .frequency_execution_snapshot,
    .dsvert_dp_sticky_subseed_v1 = function(contract, lane) {
      authorization$.test_seed
    },
    .dsvert_dp_frequency_resource_reserve_v1 = reserve,
    .get_identity_keypair = function() list(
      identity_pk = authorization$local_authority$identity_pk,
      identity_sk = authorization$local_authority$identity_pk),
    .package = "dsVert")
}

.frequency_execution_counter <- function() {
  value <- new.env(parent = emptyenv())
  value$calls <- 0L; value$requests <- list(); value$shares <- character()
  value
}

.frequency_execution_transfer <- function(context, ciphertext, index = 1L) {
  list(
    ticket = paste0("ticket-", index),
    transfer_id = paste0("tb_", sprintf("%032x", index)),
    capability_id = .DSVERT_TYPED_BLOB_FREQUENCY_SOURCE_CAPABILITY,
    sender_name = context$sender, recipient_name = context$recipient,
    payload_chars = as.numeric(nchar(ciphertext, type = "bytes")),
    payload_sha256 = digest::digest(
      ciphertext, algo = "sha256", serialize = FALSE))
}

test_that("Frequency geometry is fixed for every d boundary", {
  for (d in c(1L, 8192L, 8193L, 65536L, 65537L, 1000000L)) {
    worker <- list(d = d, chunk_coordinates = min(8192L, d),
                   chunk_count = as.integer(ceiling(d / 8192L)))
    geometry <- .dsvert_dp_frequency_execution_geometry_v1(worker)
    last <- .dsvert_dp_frequency_execution_window_v1(
      geometry, geometry$window_count - 1L)
    expect_identical(last$coordinate_offset + last$coordinate_count, d)
    expect_identical(last$padded_coordinate_count, 65536L)
    expect_identical(last$plaintext_bytes, 1056768L)
    expect_identical(last$ciphertext_chars, 1409104L)
  }
})

test_that("Frequency authorization is K-generic and transport-bound", {
  for (k in c(2L, 3L, 5L)) {
    fixture <- .frequency_execution_fixture(k)
    source <- fixture$source; source$.test_seed <- fixture$seeds$source_owner
    ss <- .frequency_execution_state(fixture, source)
    set <- .frequency_execution_as(source, function() {
      .dsvert_dp_frequency_execution_authorization_set_v1(
        ss, source$session_id, fixture$public,
        .verifier = .frequency_execution_verifier)
    })
    expect_identical(names(set$values),
                     c("source_owner", "secondary_noise_authority"))
    expect_length(setdiff(fixture$peers, unname(fixture$role_peers)), k - 2L)
  }
})

test_that("Frequency histogram matches snapshot raw-code semantics", {
  fixture <- .frequency_execution_fixture()
  source <- fixture$source; source$.test_seed <- fixture$seeds$source_owner
  malformed <- fixture$data
  malformed$category <- structure(
    c(1L, 99L, NA_integer_, 2L),
    levels = c("a", "b", "c", "outside"), class = "factor")
  histogram <- .frequency_execution_as(source, function() {
    .dsvert_dp_frequency_execution_histogram_v1(
      malformed, source, fixture$claim, .frequency_execution_verifier)
  })
  expect_identical(histogram, c(1, 1, 0))
})

test_that("default Frequency transport uses canonical fixed inputs", {
  fixture <- .frequency_execution_fixture()
  ss <- new.env(parent = emptyenv())
  frame <- raw(1056768L)
  ciphertext <- .dsvert_relay_b64url_encode(c(raw(60L), frame))
  commands <- character()
  result <- testthat::with_mocked_bindings({
    sealed <- .dsvert_dp_frequency_execution_encrypt_v1(
      frame, fixture$transport$secondary_noise_authority)
    list(sealed = sealed,
         opened = .dsvert_dp_frequency_execution_decrypt_v1(ss, sealed))
  },
    .callMpcTool = function(command, input) {
      commands <<- c(commands, command)
      if (identical(command, "transport-encrypt")) {
        expect_identical(length(jsonlite::base64_dec(input$data)), 1056768L)
        expect_identical(input$recipient_pk,
                         fixture$transport$secondary_noise_authority)
        return(list(sealed = .base64url_to_base64(ciphertext)))
      }
      expect_identical(input$sealed, .base64url_to_base64(ciphertext))
      expect_identical(input$recipient_sk,
                       fixture$transport$secondary_noise_authority)
      list(data = gsub("[\r\n]", "", jsonlite::base64_enc(frame)))
    },
    .key_get = function(name, state) {
      expect_identical(name, "transport_sk")
      fixture$transport$secondary_noise_authority
    },
    .package = "dsVert")
  expect_identical(commands, c("transport-encrypt", "transport-decrypt"))
  expect_identical(result$sealed, ciphertext)
  expect_identical(result$opened, frame)
})

test_that("source gates access, derives recipient, pads fixed and retries", {
  fixture <- .frequency_execution_fixture()
  source <- fixture$source; source$.test_seed <- fixture$seeds$source_owner
  ss <- .frequency_execution_state(fixture, source)
  counter <- .frequency_execution_counter(); crypto <- .frequency_execution_crypto()
  events <- new.env(parent = emptyenv()); events$values <- character()
  delivered <- FALSE; resolved <- 0L; recipient <- NULL
  run <- function(public = fixture$public, data = fixture$data) {
    .frequency_execution_as(source, function() {
      .dsvert_dp_frequency_execution_source_window_v1(
        ss, source$session_id, "op_00000000000000000000000000000001",
        0L, public, fixture$claim,
        .source_resolver = function() {
          events$values <- c(events$values, "resolve"); resolved <<- resolved + 1L
          data
        },
        .sampler = .frequency_execution_sampler(counter),
        .encrypt = crypto$encrypt,
        .typed_mint = function(context, ciphertext, recipient_pk) {
          events$values <- c(events$values, "mint"); recipient <<- recipient_pk
          .frequency_execution_transfer(context, ciphertext)
        },
        .typed_commit = function(request, result) result,
        .delivery_status = function(transfer) delivered,
        .verifier = .frequency_execution_verifier)
    }, reserve = .frequency_execution_reserve(events))
  }
  tampered <- fixture$public; tampered[[1L]]$artifact_key <- strrep("f", 64L)
  expect_error(run(tampered), "signature|authorization")
  expect_identical(resolved, 0L); expect_length(events$values, 0L)

  first <- run(); calls <- counter$calls
  expect_identical(events$values[seq_len(2L)], c("reserve", "resolve"))
  expect_identical(recipient,
                   fixture$transport$secondary_noise_authority)
  expect_identical(nchar(first$ciphertext_chars), 1409104L)
  expect_identical(.frequency_execution_decode_ring128(
    counter$requests[[1L]]$input$source_share), c(1, 1, 0))
  expect_identical(run(), first)
  expect_identical(resolved, 1L); expect_identical(counter$calls, calls)
  delivered <- TRUE
  ack <- run()
  expect_identical(ack$state, "delivered")
  expect_false("ciphertext_chars" %in% names(ack))
  expect_null(ss$.dp_frequency_execution$windows[[1L]]$ciphertext)
  expect_type(ss$.dp_frequency_execution$values, "double")
  expect_false(grepl(paste(c(
    "histogram", "noised_share", "chunk_hash", "preclamp",
    "plaintext_sha256", "plaintext_bytes"), collapse = "|"),
    .dsvert_dp_canonical_json(first)))
})

test_that("source retry reuses a transfer when typed commit is interrupted", {
  fixture <- .frequency_execution_fixture()
  source <- fixture$source; source$.test_seed <- fixture$seeds$source_owner
  ss <- .frequency_execution_state(fixture, source)
  counter <- .frequency_execution_counter(); crypto <- .frequency_execution_crypto()
  mints <- 0L; commits <- 0L
  run <- function() .frequency_execution_as(source, function() {
    .dsvert_dp_frequency_execution_source_window_v1(
      ss, source$session_id, "op_00000000000000000000000000000005",
      0L, fixture$public, fixture$claim, function() fixture$data,
      .frequency_execution_sampler(counter), crypto$encrypt,
      function(context, ciphertext, recipient_pk) {
        mints <<- mints + 1L
        .frequency_execution_transfer(context, ciphertext)
      },
      function(request, result) {
        commits <<- commits + 1L
        if (commits == 1L) stop("typed commit interrupted", call. = FALSE)
        result
      }, function(transfer) FALSE, .frequency_execution_verifier)
  })
  expect_error(run(), "typed commit interrupted")
  expect_identical(mints, 1L)
  recovered <- run()
  expect_identical(mints, 1L)
  expect_identical(commits, 2L)
  expect_identical(recovered$state, "issued")
})

test_that("both physical profiles finalize one signed opening", {
  for (k in c(2L, 3L, 5L)) for (gaussian in c(FALSE, TRUE)) {
    fixture <- .frequency_execution_fixture(k, gaussian)
    source <- fixture$source; secondary <- fixture$secondary
    source$.test_seed <- fixture$seeds$source_owner
    secondary$.test_seed <- fixture$seeds$secondary_noise_authority
    source_ss <- .frequency_execution_state(fixture, source)
    final_ss <- .frequency_execution_state(fixture, secondary)
    counter <- .frequency_execution_counter(); crypto <- .frequency_execution_crypto()
    operation <- "op_00000000000000000000000000000002"
    sealed <- .frequency_execution_as(source, function() {
      .dsvert_dp_frequency_execution_source_window_v1(
        source_ss, source$session_id, operation, 0L, fixture$public,
        fixture$claim, function() fixture$data,
        .frequency_execution_sampler(counter), crypto$encrypt,
        function(context, ciphertext, recipient_pk)
          .frequency_execution_transfer(context, ciphertext),
        function(request, result) result, function(transfer) FALSE,
        .frequency_execution_verifier)
    })
    expect_error(.frequency_execution_as(secondary, function() {
      .dsvert_dp_frequency_execution_replay_window_v1(
        final_ss, secondary$session_id, operation, 0L)
    }), "not complete")
    fetch_events <- logical()
    fetch <- function(context, consume = FALSE) {
      fetch_events <<- c(fetch_events, consume)
      if (isTRUE(consume)) {
        expect_true(is.list(final_ss$.dp_frequency_execution$release))
      }
      sealed$ciphertext_chars
    }
    release <- .frequency_execution_as(secondary, function() {
      .dsvert_dp_frequency_execution_finalize_window_v1(
        final_ss, secondary$session_id, operation, 0L, fixture$public,
        .frequency_execution_sampler(counter), crypto$decrypt,
        fetch,
        .frequency_execution_verifier, .frequency_execution_signature)
    })
    calls <- counter$calls
    expect_identical(fetch_events, c(FALSE, TRUE))
    expect_identical(release$state, "release_committed")
    expect_equal(release$release$public_openings, 1L)
    expect_match(release$release$final_vector_root, "^[0-9a-f]{64}$")
    expect_identical(.frequency_execution_as(secondary, function() {
      .dsvert_dp_frequency_execution_finalize_window_v1(
        final_ss, secondary$session_id, operation, 0L, fixture$public,
        .frequency_execution_sampler(counter), crypto$decrypt,
        fetch,
        .frequency_execution_verifier, .frequency_execution_signature)
    }), release)
    expect_identical(counter$calls, calls)
    expect_identical(fetch_events, c(FALSE, TRUE))
    replay <- .frequency_execution_as(secondary, function() {
      .dsvert_dp_frequency_execution_replay_window_v1(
        final_ss, secondary$session_id, operation, 0L)
    })
    expect_identical(unlist(replay$window$chunks[[1L]]$values),
                     c("4", "4", "3"))
    expect_type(final_ss$.dp_frequency_execution$values, "double")
    expect_null(final_ss$.dp_frequency_execution$windows[[1L]]$ciphertext)

    chars <- strsplit(sealed$ciphertext_chars, "", fixed = TRUE)[[1L]]
    chars[[100L]] <- if (chars[[100L]] == "A") "B" else "A"
    clean <- .frequency_execution_state(fixture, secondary)
    expect_error(.frequency_execution_as(secondary, function() {
      .dsvert_dp_frequency_execution_finalize_window_v1(
        clean, secondary$session_id, operation, 0L, fixture$public,
        .frequency_execution_sampler(counter), crypto$decrypt,
        function(context, consume = FALSE) paste0(chars, collapse = ""),
        .frequency_execution_verifier, .frequency_execution_signature)
    }), "ciphertext|frame|authentication")
  }
})

test_that("multi-window source resolves once and progress is data-free", {
  fixture <- .frequency_execution_fixture(d = 65537L)
  source <- fixture$source; secondary <- fixture$secondary
  source$.test_seed <- fixture$seeds$source_owner
  secondary$.test_seed <- fixture$seeds$secondary_noise_authority
  source_ss <- .frequency_execution_state(fixture, source)
  final_ss <- .frequency_execution_state(fixture, secondary)
  counter <- .frequency_execution_counter(); crypto <- .frequency_execution_crypto()
  resolved <- 0L; delivered <- FALSE
  operation <- "op_00000000000000000000000000000003"
  source_run <- function(index) .frequency_execution_as(source, function() {
    .dsvert_dp_frequency_execution_source_window_v1(
      source_ss, source$session_id, operation, index, fixture$public,
      fixture$claim, function() { resolved <<- resolved + 1L; fixture$data },
      .frequency_execution_sampler(counter), crypto$encrypt,
      function(context, ciphertext, recipient_pk)
        .frequency_execution_transfer(context, ciphertext, index + 1L),
      function(request, result) result, function(transfer) delivered,
      .frequency_execution_verifier)
  })
  first <- source_run(0L)
  delivered <- TRUE; expect_identical(source_run(0L)$state, "delivered")
  second <- source_run(1L)
  expect_identical(resolved, 1L)
  expect_identical(nchar(c(first$ciphertext_chars, second$ciphertext_chars)),
                   c(1409104L, 1409104L))

  fetch <- function(context, consume = FALSE) {
    if (identical(context$window_index, "0")) first$ciphertext_chars
    else second$ciphertext_chars
  }
  progress <- .frequency_execution_as(secondary, function() {
    .dsvert_dp_frequency_execution_finalize_window_v1(
      final_ss, secondary$session_id, operation, 0L, fixture$public,
      .frequency_execution_sampler(counter), crypto$decrypt, fetch,
      .frequency_execution_verifier, .frequency_execution_signature)
  })
  expect_identical(progress$state, "window_committed")
  expect_false(any(c(
    "values", "ciphertext_chars", "noised_share", "chunk_hashes",
    "window_sha256") %in% names(progress)))
  expect_error(.frequency_execution_as(secondary, function() {
    .dsvert_dp_frequency_execution_replay_window_v1(
      final_ss, secondary$session_id, operation, 0L)
  }), "not complete")
  release <- .frequency_execution_as(secondary, function() {
    .dsvert_dp_frequency_execution_finalize_window_v1(
      final_ss, secondary$session_id, operation, 1L, fixture$public,
      .frequency_execution_sampler(counter), crypto$decrypt, fetch,
      .frequency_execution_verifier, .frequency_execution_signature)
  })
  expect_identical(release$state, "release_committed")
  expect_length(final_ss$.dp_frequency_execution$values, 65537L)
})

test_that("mutation fails, sticky sessions agree, delivery and cleanup close", {
  fixture <- .frequency_execution_fixture()
  source <- fixture$source; source$.test_seed <- fixture$seeds$source_owner
  make_source <- function(data, session_id) {
    auth <- source; auth$session_id <- session_id
    public <- lapply(fixture$public, function(value) {
      value$session_id <- session_id
      unsigned <- value[setdiff(names(value), "signature")]
      value$signature <- .frequency_execution_signature(
        .dsvert_dp_frequency_public_authorization_message_v1(unsigned),
        value$local_authority$identity_pk)
      .dsvert_dp_analysis_canonical_value_v1(value)
    })
    ss <- .frequency_execution_state(fixture, auth)
    counter <- .frequency_execution_counter(); crypto <- .frequency_execution_crypto()
    result <- .frequency_execution_as(auth, function() {
      .dsvert_dp_frequency_execution_source_window_v1(
        ss, session_id, "op_00000000000000000000000000000004", 0L,
        public, fixture$claim, function() data,
        .frequency_execution_sampler(counter), crypto$encrypt,
        function(context, ciphertext, recipient_pk)
          .frequency_execution_transfer(context, ciphertext),
        function(request, result) result, function(transfer) FALSE,
        .frequency_execution_verifier)
    })
    list(result = result, state = ss, requests = counter$requests,
         shares = counter$shares)
  }
  first <- make_source(fixture$data,
    "00000000-0000-4000-8000-000000000001")
  second <- make_source(fixture$data,
    "00000000-0000-4000-8000-000000000002")
  expect_identical(first$requests[[1L]]$input$private_seed,
                   second$requests[[1L]]$input$private_seed)
  expect_identical(first$shares, second$shares)
  mutated <- fixture$data; mutated$category[[1L]] <- "b"
  expect_error(make_source(mutated,
    "00000000-0000-4000-8000-000000000003"), "snapshot")

  transfer <- first$result$transfer; status_ss <- first$state
  status_ss$.typed_blob_outbound <- stats::setNames(
    list(c(transfer, list(operation_key = "key"))), transfer$transfer_id)
  expect_false(.dsvert_dp_frequency_execution_delivery_v1(status_ss, transfer))
  status_ss$.typed_blob_outbound_receipts <- stats::setNames(
    list(list(receipt_digest = "ok")), transfer$transfer_id)
  expect_true(.dsvert_dp_frequency_execution_delivery_v1(status_ss, transfer))
  expect_true(.dsvert_dp_frequency_execution_cleanup_v1(first$state))
  expect_null(first$state$.dp_frequency_execution)
  expect_false(is.null(first$state$.dp_frequency_resource_reservation))
})
