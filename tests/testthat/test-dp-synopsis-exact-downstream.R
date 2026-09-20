.synopsis_exact_downstream_helpers <- local({
  environment <- new.env(parent = asNamespace("dsVert"))
  for (expression in parse(testthat::test_path(
      "test-dp-synopsis-exact-gc.R"))) {
    if (is.call(expression) && identical(
        as.character(expression[[1L]]), "test_that")) break
    eval(expression, envir = environment)
  }
  environment
})

.synopsis_exact_downstream_setup <- function(k = 2L) {
  h <- .synopsis_exact_downstream_helpers
  fixture <- h$.synopsis_exact_fixture(k)
  h$.synopsis_exact_cleanup(fixture, envir = parent.frame())
  setup <- h$.synopsis_exact_setup(fixture)
  shares <- c(
    as.character(openssl::bignum(2) ^ 128L - 5L), "12")
  validities <- c(0L, 1L)
  results <- locals <- sessions <- list()
  for (position in seq_along(setup$authorities)) {
    peer <- setup$authorities[[position]]
    context <- h$.synopsis_exact_context(fixture, setup, peer)
    session <- h$.synopsis_exact_session(fixture, setup, peer)
    compiler <- h$.synopsis_exact_compiler(context)
    h$.synopsis_exact_start(
      fixture, setup, peer, session, compiler,
      function(ss, session_id, binding, ...) h$.synopsis_exact_started(
        binding))
    noised <- .exact_gc_decimal_residues_b64(shares[[position]], 128L)
    validity <- gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(validities[[position]])))
    noised_hash <- digest::digest(
      jsonlite::base64_dec(noised), algo = "sha256", serialize = FALSE)
    validity_hash <- digest::digest(
      jsonlite::base64_dec(validity), algo = "sha256", serialize = FALSE)
    consumer <- function(ss, binding, worker_contract, .commit) {
      internal <- list(
        noised_share_b64 = noised, validity_share_b64 = validity,
        noised_share_sha256 = noised_hash,
        validity_share_sha256 = validity_hash,
        binding_sha256 = binding$binding_sha256,
        purpose = binding$purpose, operation_id = binding$operation_id,
        backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND)
      expect_true(.commit(internal))
      list(
        version = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_COMMIT_VERSION,
        backend = .DSVERT_JOINT_DP_VECTOR_EXACT_GC_BACKEND,
        binding_sha256 = binding$binding_sha256,
        operation_id = binding$operation_id, purpose = binding$purpose,
        noised_share_sha256 = noised_hash,
        validity_share_sha256 = validity_hash, durable = TRUE,
        intermediate_payload_exposed = FALSE,
        source_share_exposed = FALSE, private_seed_exposed = FALSE,
        preclamp_values_exposed = FALSE)
    }
    results[[peer]] <- h$.synopsis_exact_result(
      fixture, setup, peer, session, compiler, consumer)
    locals[[peer]] <- .dsvert_dp_synopsis_execution_with_store_v1(
      fixture$input$policies[[peer]], fixture$input$secrets[[peer]],
      function(connection) .dsvert_dp_synopsis_execution_local_load_v1(
        connection, fixture$input$secrets[[peer]], context, NULL,
        .dsvert_dp_synopsis_execution_chunk_v1(context, 0L),
        fixture$input$policies[[peer]], fixture$input$verifier))
    sessions[[peer]] <- session
  }
  list(fixture = fixture, setup = setup, results = results,
       locals = locals, sessions = sessions)
}

.synopsis_exact_downstream_session <- function(built, peer) {
  ss <- built$setup$authorized[[peer]]$state
  exact <- built$sessions[[peer]]
  for (field in ls(exact, all.names = TRUE)) {
    ss[[field]] <- exact[[field]]
  }
  others <- setdiff(built$setup$authorities, peer)
  ss$.session_id <- built$setup$session_id
  ss$peer_transport_pks <- stats::setNames(lapply(seq_along(others),
    function(index) gsub("[\r\n]", "", jsonlite::base64_enc(
      as.raw(rep(index + 20L, 32L))))), others)
  ss$.typed_blob_self_name <- peer
  ss$.typed_blob_peer_identity_pks <- as.list(
    built$fixture$input$fixture$pins[others])
  ss$.typed_blob_peer_binding_digest <- strrep("a", 64L)
  ss
}

.synopsis_exact_downstream_reader <- function(built, local_peer) {
  function(session, typed_context, sender, public_chunk,
           expected_segments) {
    value <- built$locals[[sender]]
    descriptor <- expected_segments[[1L]]
    list(segments = list(c(descriptor[c(
      "execution_chunk_index", "coordinate_offset", "coordinate_count")],
      list(noised_share_b64 = value$noised_share_b64,
           noised_share_sha256 = value$noised_share_sha256,
           validity_share_b64 = value$validity_share_b64,
           validity_share_sha256 = value$validity_share_sha256,
           binding_sha256 = value$binding_sha256,
           chunk_commitment_sha256 =
             value$output_commitment_sha256))), encrypted = "ciphertext")
  }
}

test_that("fixed-rho GEE schedules bounded chunks without changing the full draw plan", {
  h <- .synopsis_exact_downstream_helpers
  fixture <- h$.synopsis_exact_fixture()
  h$.synopsis_exact_cleanup(fixture)
  setup <- h$.synopsis_exact_setup(fixture)
  peer <- setup$authorities[[1L]]
  original <- h$.synopsis_exact_context(fixture, setup, peer)
  authorization <- original$authorization
  authorization$artifact$semantic$release$lattice$coordinate_count <- 43L
  physical <- authorization$artifact$physical_plan
  physical$full_plan$total_coordinate_count <- 43L
  physical$full_plan$maximum_chunk_coordinates <- 36L
  physical$request$total_coordinate_count <- 43L
  physical$request$epsilon <- 8
  physical$full_plan_sha256 <- .dsvert_joint_dp_hash(physical$full_plan)
  authorization$artifact$physical_plan <- physical
  lattice <- original$vector$lattice
  lattice$raw_upper_bounds <- rep(lattice$raw_upper_bounds[[1L]], 43L)
  lattice$scale_shifts <- rep(lattice$scale_shifts[[1L]], 43L)
  validated <- .dsvert_dp_capsule_materializer_manifest(
    fixture$input$policies[[peer]],
    .dsvert_dp_capsule_source_manifest(original$manifest_json))
  validated$layout$coordinate_count <- 43L
  catalog <- function(family, composition = "staged_fixed_rho_v1") list(
    family = family, composition = composition,
    version = paste0("bounded-", gsub("_", "-", family), "-cross-grid-v1"),
    spec_version = paste0(family, "_grid_cross_v1"))
  context_for <- function(artifacts) {
    value <- authorization
    value$artifact$semantic$catalog_projection$catalog$families$
      gaussian_models$artifacts <- artifacts
    # Exercise scheduling after the authorized materialization boundary with
    # a full 43-coordinate lattice; no protected source or native sampler runs.
    testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_execution_context_from_authorization_v1(
        value, fixture$input$policies[[peer]], fixture$input$secrets[[peer]],
        fixture$input$cache_get),
      .dsvert_dp_capsule_materializer_manifest = function(...) validated,
      .dsvert_joint_dp_vector_lattice_vectors = function(...) lattice,
      .dsvert_dp_glm_grid_cross_noise_policy = function(...)
        "dsvert-lmm-grid-exact-gc-cost-policy-v1",
      .package = "dsVert")
  }
  for (family in c("binomial_gee", "poisson_gee")) {
    artifacts <- list(catalog(family))
    context <- context_for(artifacts)
    expect_equal(context$attempt$value$execution_geometry,
      list(chunk_coordinates = 16L, chunk_count = 3L), ignore_attr = TRUE)
    chunks <- lapply(0:2, function(index)
      .dsvert_dp_synopsis_execution_chunk_v1(context, index))
    expect_identical(vapply(chunks, `[[`, integer(1L), "offset"), c(0L, 16L, 32L))
    expect_identical(vapply(chunks, `[[`, integer(1L), "count"), c(16L, 16L, 11L))
    expect_identical(context$vector$plan, physical$full_plan)
    expect_identical(context$vector$plan_sha256, physical$full_plan_sha256)
    expect_equal(context$vector$release_contract$coordinate_count, 43L)
    expect_equal(context$vector$release_contract$epsilon, physical$request$epsilon)
    expect_equal(context$vector$release_contract$allocated_delta, physical$request$delta)
    expect_equal(context$vector$release_contract$sensitivity_steps,
      physical$request$sensitivity_steps)
    expect_identical(context_for(artifacts), context)
    previous <- context$attempt$value
    previous$execution_geometry <- list(chunk_coordinates = 36L, chunk_count = 2L)
    expect_false(identical(context$attempt$sha256,
      .dsvert_dp_synopsis_execution_hash_v1(
        .DSVERT_DP_SYNOPSIS_EXECUTION_ATTEMPT_DOMAIN, previous)))
  }
  for (artifacts in list(list(), list(catalog("lmm")),
      list(catalog("binomial_glmm")), list(catalog("poisson_glmm")),
      list(catalog("binomial_gee", "legacy_v1")),
      list(catalog("poisson_gee", "staged_estimated_alpha_v1")))) {
    context <- context_for(artifacts)
    expect_equal(context$attempt$value$execution_geometry,
      list(chunk_coordinates = 36L, chunk_count = 2L), ignore_attr = TRUE)
  }
  # A changed schedule is a conflicting attempt for an existing sticky identity.
  # It must never turn a failed 36-coordinate release into a fresh noise draw.
  context <- context_for(list(catalog("binomial_gee")))
  secret <- fixture$input$secrets[[peer]]
  .dsvert_dp_synopsis_execution_with_store_v1(
    fixture$input$policies[[peer]], secret, function(connection) {
      claim <- function(attempt = context$attempt$sha256, count = 3L)
        .dsvert_dp_synopsis_execution_start_claim_v1(connection,
          context$authorization$artifact_key, context$contract$sha256,
          attempt, count, 1L, secret)
      expect_identical(claim(), claim())
      previous <- context$attempt$value
      previous$execution_geometry <- list(chunk_coordinates = 36L, chunk_count = 2L)
      expect_error(claim(.dsvert_dp_synopsis_execution_hash_v1(
        .DSVERT_DP_SYNOPSIS_EXECUTION_ATTEMPT_DOMAIN, previous), 2L),
        "first claimed by a conflicting attempt")
    })
  authorization$artifact$physical_plan$full_plan$maximum_chunk_coordinates <- 12L
  authorization$artifact$physical_plan$full_plan_sha256 <- .dsvert_joint_dp_hash(
    authorization$artifact$physical_plan$full_plan)
  smaller <- context_for(list(catalog("poisson_gee")))
  expect_equal(smaller$attempt$value$execution_geometry,
    list(chunk_coordinates = 12L, chunk_count = 4L), ignore_attr = TRUE)
})

test_that("exact synopsis FINAL_SHARE authenticates all three fixed-rho GEE segments", {
  context <- list(
    authorization = list(artifact_key = strrep("a", 64L)),
    execution_id = strrep("b", 64L),
    contract = list(sha256 = strrep("c", 64L), value = list(
      authority_roles = list(role_order = list(
        "primary_noise_authority", "secondary_noise_authority")),
      authority_peers = list("site_a", "site_b"),
      geometry = list(coordinate_count = 43L,
        public_chunk_coordinates = 43L, public_chunk_count = 1L))),
    attempt = list(sha256 = strrep("d", 64L), value = list(
      execution_geometry = list(chunk_coordinates = 16L, chunk_count = 3L))),
    vector = list(profile = list(exact_gc = TRUE)))
  public <- .dsvert_dp_synopsis_execution_public_chunk_v1(context, 0L)
  expect_identical(public$execution_chunk_indices, as.list(0:2))
  expect_identical(public$segment_count, 3L)
  typed <- .dsvert_dp_synopsis_execution_final_share_context_v1(
    context, strrep("e", 64L), public, strrep("f", 64L), "site_a", "site_b")
  expect_identical(typed$execution_chunk_coordinates, "16")
  expect_identical(typed$execution_chunk_count, "3")
  hash <- function(x) digest::digest(x, algo = "sha256", serialize = FALSE)
  segments <- lapply(0:2, function(index) {
    chunk <- .dsvert_dp_synopsis_execution_chunk_v1(context, index)
    noised <- as.raw(rep(index, chunk$count * 16L))
    validity <- as.raw(index %% 2L)
    binding <- hash(charToRaw(paste0("segment-", index)))
    list(execution_chunk_index = index, coordinate_offset = chunk$offset,
      coordinate_count = chunk$count,
      noised_share_b64 = gsub("[\r\n]", "", jsonlite::base64_enc(noised)),
      noised_share_sha256 = hash(noised),
      validity_share_b64 = jsonlite::base64_enc(validity),
      validity_share_sha256 = hash(validity), binding_sha256 = binding,
      chunk_commitment_sha256 = .dsvert_dp_synopsis_execution_exact_local_commitment_v1(
        hash(noised), hash(validity), binding))
  })
  expected <- lapply(segments, function(segment) segment[c(
    "execution_chunk_index", "coordinate_offset", "coordinate_count",
    "chunk_commitment_sha256")])
  read <- function(payload_context = typed, payload_segments = segments) {
    payload <- list(version = .DSVERT_DP_SYNOPSIS_EXECUTION_FINAL_SHARE_PAYLOAD_VERSION,
      context = payload_context, segments = payload_segments)
    testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_execution_default_peer_reader_v1(
        new.env(), typed, "site_a", public, expected),
      .dsvert_typed_blob_consume = function(...) "ciphertext",
      .key_get = function(...) raw(32L),
      .callMpcTool = function(...) list(data = jsonlite::base64_enc(charToRaw(
        .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(payload))))),
      .package = "dsVert")
  }
  accepted <- read()
  expect_equal(accepted$segments, segments)
  expect_identical(vapply(accepted$segments, `[[`, integer(1L),
    "coordinate_count"), c(16L, 16L, 11L))
  expect_error(read(payload_segments = segments[1:2]), "FINAL_SHARE payload")
  altered <- segments; altered[[3L]]$coordinate_offset <- 31L
  expect_error(read(payload_segments = altered), "FINAL_SHARE segment")
  altered <- typed; altered$execution_chunk_coordinates <- "15"
  expect_silent(.dsvert_typed_blob_synopsis_context_v1(altered, "site_a"))
  expect_error(read(payload_context = altered), "FINAL_SHARE payload")
})

test_that("exact synopsis FINAL_SHARE admits capacity-bounded GEE chunks", {
  context <- list(
    authorization = list(artifact_key = strrep("a", 64L)),
    execution_id = strrep("b", 64L),
    contract = list(sha256 = strrep("c", 64L), value = list(
      authority_roles = list(role_order = list(
        "primary_noise_authority", "secondary_noise_authority")),
      authority_peers = list("site_a", "site_b"),
      geometry = list(coordinate_count = 43L, public_chunk_count = 1L))),
    attempt = list(sha256 = strrep("d", 64L), value = list(
      execution_geometry = list(chunk_coordinates = 36L, chunk_count = 2L))),
    vector = list(profile = list(exact_gc = TRUE)))
  public_chunk <- list(index = 0L, offset = 0L, count = 43L,
    first_execution_chunk_index = 0L, segment_count = 2L)
  value <- .dsvert_dp_synopsis_execution_final_share_context_v1(
    context, strrep("e", 64L), public_chunk, strrep("f", 64L),
    "site_a", "site_b")
  expect_identical(value$execution_chunk_coordinates, "36")
  expect_identical(value$execution_chunk_count, "2")
  expect_identical(value$segment_count, "2")
  for (field in c("execution_chunk_count", "segment_count")) {
    altered <- value; altered[[field]] <- "1"
    expect_error(.dsvert_typed_blob_synopsis_context_v1(
      altered, "site_a"), "geometry")
  }
  for (size in c("0", "44", "65")) {
    altered <- value; altered$execution_chunk_coordinates <- size
    expect_error(.dsvert_typed_blob_synopsis_context_v1(
      altered, "site_a"))
  }
  altered <- value; altered$recipient <- "site_c"
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    altered, "site_a"), "route")
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    value, "site_b"), "route")
  # Another internally consistent segmentation must not replace the attempt's
  # authenticated 36-coordinate plan during the encrypted share handoff.
  altered <- value; altered$execution_chunk_coordinates <- "22"
  expect_silent(.dsvert_typed_blob_synopsis_context_v1(altered, "site_a"))
  payload <- list(version = .DSVERT_DP_SYNOPSIS_EXECUTION_FINAL_SHARE_PAYLOAD_VERSION,
    context = altered, segments = list(list(), list()))
  testthat::with_mocked_bindings(
    expect_error(.dsvert_dp_synopsis_execution_default_peer_reader_v1(
      new.env(), value, "site_a", public_chunk, list(list(), list())),
      "Invalid synopsis FINAL_SHARE payload"),
    .dsvert_typed_blob_consume = function(...) "ciphertext",
    .key_get = function(...) raw(32L),
    .callMpcTool = function(...) list(data = jsonlite::base64_enc(charToRaw(
      .dsvert_dp_canonical_json(.dsvert_dp_canonical_query_value(payload))))),
    .package = "dsVert")
})

test_that("exact synopsis FINAL_SHARE transports validity and binding", {
  built <- .synopsis_exact_downstream_setup()
  peer <- built$setup$authorities[[1L]]
  recipient <- built$setup$authorities[[2L]]
  ss <- .synopsis_exact_downstream_session(built, peer)
  observed <- new.env(parent = emptyenv())
  result <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_final_share_v1(
      ss, built$setup$session_id, built$results[[1L]],
      built$results[[2L]], 0L,
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(identity_pk = unname(
        built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier,
      .encryptor = function(plaintext, recipient_pk) {
        observed$payload <- jsonlite::fromJSON(
          rawToChar(plaintext), simplifyVector = FALSE)
        jsonlite::base64_enc(raw(32L))
      }),
    .S = function(...) ss,
    .exact_gc_validate_bound_peer_context = function(ss, session_id) {
      ss$.exact_gc_peer_binding_digest
    },
    .dsvert_typed_blob_operation_replay = function(...) list(hit = FALSE),
    .dsvert_typed_blob_mint = function(...) list(transfer_id = "ok"),
    .dsvert_typed_blob_operation_commit = function(
        ss, producer, request, result) result, .package = "dsVert")
  expect_true(result$capability_available)
  expect_identical(observed$payload$context$share_format,
    "ring128-exact-gc-local-chunk-segments-v1")
  segment <- observed$payload$segments[[1L]]
  expect_named(segment, c(
    "execution_chunk_index", "coordinate_offset", "coordinate_count",
    "noised_share_b64", "noised_share_sha256", "validity_share_b64",
    "validity_share_sha256", "binding_sha256",
    "chunk_commitment_sha256"), ignore.order = TRUE)
  expect_identical(segment$binding_sha256,
                   built$locals[[peer]]$binding_sha256)
  expect_identical(recipient, result$transfer$recipient_name %||% recipient)
  context <- .synopsis_exact_downstream_helpers$.synopsis_exact_context(
    built$fixture, built$setup, peer)
  public_chunk <- .dsvert_dp_synopsis_execution_public_chunk_v1(
    context, 0L)
  expected <- list(segment[c(
    "execution_chunk_index", "coordinate_offset", "coordinate_count",
    "chunk_commitment_sha256")])
  reader <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_default_peer_reader_v1(
      ss, observed$payload$context, peer, public_chunk, expected),
    .dsvert_typed_blob_consume = function(...) "ciphertext",
    .key_get = function(...) raw(32L),
    .callMpcTool = function(command, input) {
      expect_identical(command, "transport-decrypt")
      list(data = gsub("[\r\n]", "", jsonlite::base64_enc(charToRaw(
        .dsvert_dp_canonical_json(
          .dsvert_dp_canonical_query_value(observed$payload))))))
    }, .package = "dsVert")
  expect_identical(reader$segments[[1L]]$binding_sha256,
                   built$locals[[peer]]$binding_sha256)
  altered_context <- observed$payload$context
  altered_context$execution_chunk_coordinates <- "64"
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    altered_context, peer), "geometry")
  altered_context <- observed$payload$context
  altered_context$share_format <- "ring128-local-chunk-segments-v2"
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    altered_context, peer), "binding")
  altered_context$share_format <- list(
    "ring128-exact-gc-local-chunk-segments-v1")
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    altered_context, peer), "binding")
  altered_context$share_format <- factor(
    "ring128-exact-gc-local-chunk-segments-v1")
  expect_error(.dsvert_typed_blob_synopsis_context_v1(
    altered_context, peer), "binding")
})

test_that("exact synopsis segments and final certificates fail closed", {
  built <- .synopsis_exact_downstream_setup()
  peer <- built$setup$authorities[[1L]]
  other <- built$setup$authorities[[2L]]
  context <- .synopsis_exact_downstream_helpers$.synopsis_exact_context(
    built$fixture, built$setup, peer)
  chunk <- .dsvert_dp_synopsis_execution_chunk_v1(context, 0L)
  local <- built$locals[[peer]]
  expected <- list(
    execution_chunk_index = chunk$index,
    coordinate_offset = chunk$offset,
    coordinate_count = chunk$count,
    chunk_commitment_sha256 = local$output_commitment_sha256)
  segment <- c(expected[c(
    "execution_chunk_index", "coordinate_offset", "coordinate_count")],
  list(
    noised_share_b64 = local$noised_share_b64,
    noised_share_sha256 = local$noised_share_sha256,
    validity_share_b64 = local$validity_share_b64,
    validity_share_sha256 = local$validity_share_sha256,
    binding_sha256 = local$binding_sha256,
    chunk_commitment_sha256 = local$output_commitment_sha256))
  expect_silent(
    .dsvert_dp_synopsis_execution_exact_segment_v1(segment, expected))
  altered <- segment; altered$extra <- TRUE
  expect_error(.dsvert_dp_synopsis_execution_exact_segment_v1(
    altered, expected), "segment")
  altered <- segment; altered$noised_share_sha256 <- strrep("f", 64L)
  expect_error(.dsvert_dp_synopsis_execution_exact_segment_v1(
    altered, expected), "authentication")
  altered <- segment
  altered$validity_share_b64 <- gsub(
    "[\r\n]", "", jsonlite::base64_enc(as.raw(2L)))
  expect_error(.dsvert_dp_synopsis_execution_exact_segment_v1(
    altered, expected), "validity")
  altered <- segment; altered$binding_sha256 <- strrep("f", 64L)
  expect_error(.dsvert_dp_synopsis_execution_exact_segment_v1(
    altered, expected), "authentication")

  remote <- built$locals[[other]]
  output <- .dsvert_joint_dp_vector_exact_gc_finalize(
    own = local, peer = remote, scaled_upper_bounds = "512",
    binding_sha256 = local$binding_sha256)
  expect_identical(
    .dsvert_dp_synopsis_execution_exact_final_values_v1(
      output, local$binding_sha256, "512"), list("7"))
  altered <- output; altered$validity <- FALSE
  expect_error(.dsvert_dp_synopsis_execution_exact_final_values_v1(
    altered, local$binding_sha256, "512"), "certificate")
  altered <- output; altered$clamped_scaled_values <- list("513")
  expect_error(.dsvert_dp_synopsis_execution_exact_final_values_v1(
    altered, local$binding_sha256, "512"), "certificate")
})

test_that("exact FINAL_SHARE excludes K3 and K5 witnesses", {
  for (k in c(3L, 5L)) {
    built <- .synopsis_exact_downstream_setup(k)
    peer <- built$setup$authorities[[1L]]
    recipient <- built$setup$authorities[[2L]]
    ss <- .synopsis_exact_downstream_session(built, peer)
    expect_identical(names(ss$peer_transport_pks), recipient)
    expect_identical(names(ss$.typed_blob_peer_identity_pks), recipient)
    binding_checks <- 0L
    result <- testthat::with_mocked_bindings(
      .dsvert_dp_synopsis_execution_final_share_v1(
        ss, built$setup$session_id, built$results[[1L]],
        built$results[[2L]], 0L,
        .policy = built$fixture$input$policies[[peer]],
        .secret = built$fixture$input$secrets[[peer]],
        .identity = list(identity_pk = unname(
          built$fixture$input$fixture$pins[[peer]])),
        .cache_get = built$fixture$input$cache_get,
        .verifier = built$fixture$input$verifier,
        .encryptor = function(...) jsonlite::base64_enc(raw(32L))),
      .S = function(...) ss,
      .exact_gc_validate_bound_peer_context = function(ss, session_id) {
        binding_checks <<- binding_checks + 1L
        ss$.exact_gc_peer_binding_digest
      },
      .dsvert_typed_blob_operation_replay = function(...) list(hit = FALSE),
      .dsvert_typed_blob_mint = function(...) list(transfer_id = "ok"),
      .dsvert_typed_blob_operation_commit = function(
          ss, producer, request, result) result, .package = "dsVert")
    expect_true(result$capability_available)
    expect_identical(binding_checks, 1L)
  }
})

test_that("exact synopsis RELEASE finalizes binding and validity", {
  built <- .synopsis_exact_downstream_setup()
  forged_peer <- built$setup$authorities[[1L]]
  expect_error(.dsvert_dp_synopsis_execution_release_v1(
    built$setup$authorized[[forged_peer]]$state,
    built$setup$session_id, built$results[[1L]], built$results[[2L]],
    .policy = built$fixture$input$policies[[forged_peer]],
    .secret = built$fixture$input$secrets[[forged_peer]],
    .identity = list(
      identity_pk = unname(
        built$fixture$input$fixture$pins[[forged_peer]]),
      identity_sk = unname(
        built$fixture$input$fixture$pins[[forged_peer]])),
    .cache_get = built$fixture$input$cache_get,
    .verifier = built$fixture$input$verifier,
    .signer = built$fixture$input$signer,
    .peer_share_reader = .synopsis_exact_downstream_reader(
      built, forged_peer),
    .finalizer = function(input) {
      output <- do.call(
        .dsvert_joint_dp_vector_exact_gc_finalize, input)
      output$clamped_scaled_values <- list("8")
      output
    }, .session = new.env(parent = emptyenv())), "exact result")
  connection <- DBI::dbConnect(
    RSQLite::SQLite(), .dsvert_dp_synopsis_execution_store_path_v1(
      built$fixture$input$policies[[forged_peer]]))
  expect_identical(DBI::dbGetQuery(
    connection, "SELECT COUNT(*) AS n FROM synopsis_public_chunks")$n,
    0L)
  DBI::dbDisconnect(connection)
  releases <- list()
  for (peer in built$setup$authorities) {
    releases[[peer]] <- .dsvert_dp_synopsis_execution_release_v1(
      built$setup$authorized[[peer]]$state, built$setup$session_id,
      built$results[[2L]], built$results[[1L]],
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(
        identity_pk = unname(built$fixture$input$fixture$pins[[peer]]),
        identity_sk = unname(built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier,
      .signer = built$fixture$input$signer,
      .peer_share_reader = .synopsis_exact_downstream_reader(built, peer),
      .finalizer = function(input) do.call(
        .dsvert_joint_dp_vector_exact_gc_finalize, input),
      .session = new.env(parent = emptyenv()))
  }
  expect_identical(releases[[1L]]$final_vector_root,
                   releases[[2L]]$final_vector_root)
  forbidden <- function(...) stop("private dependency reached", call. = FALSE)
  replayed <- .dsvert_dp_synopsis_execution_release_v1(
    built$setup$authorized[[forged_peer]]$state,
    built$setup$session_id, built$results[[2L]], built$results[[1L]],
    .policy = built$fixture$input$policies[[forged_peer]],
    .secret = built$fixture$input$secrets[[forged_peer]],
    .identity = list(identity_pk = unname(
      built$fixture$input$fixture$pins[[forged_peer]])),
    .cache_get = built$fixture$input$cache_get,
    .verifier = built$fixture$input$verifier,
    .peer_share_reader = forbidden, .finalizer = forbidden,
    .session = new.env(parent = emptyenv()))
  expect_identical(replayed, releases[[forged_peer]])
  for (peer in built$setup$authorities) {
    path <- .dsvert_dp_synopsis_execution_store_path_v1(
      built$fixture$input$policies[[peer]])
    connection <- DBI::dbConnect(RSQLite::SQLite(), path)
    row <- DBI::dbGetQuery(connection,
      "SELECT record_json FROM synopsis_public_chunks")
    DBI::dbDisconnect(connection)
    public <- jsonlite::fromJSON(
      row$record_json[[1L]], simplifyVector = FALSE)$public_chunk
    expect_identical(public$scaled_values, list("7"))
  }
})

test_that("exact synopsis REPLAY is public-only", {
  built <- .synopsis_exact_downstream_setup()
  releases <- lapply(built$setup$authorities, function(peer)
    .dsvert_dp_synopsis_execution_release_v1(
      built$setup$authorized[[peer]]$state, built$setup$session_id,
      built$results[[1L]], built$results[[2L]],
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(
        identity_pk = unname(built$fixture$input$fixture$pins[[peer]]),
        identity_sk = unname(built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier,
      .signer = built$fixture$input$signer,
      .peer_share_reader = .synopsis_exact_downstream_reader(built, peer),
      .finalizer = function(input) do.call(
        .dsvert_joint_dp_vector_exact_gc_finalize, input),
      .session = new.env(parent = emptyenv())))
  forbidden <- function(...) stop("private dependency reached", call. = FALSE)
  peer <- built$setup$authorities[[1L]]
  replay <- testthat::with_mocked_bindings(
    .dsvert_dp_synopsis_execution_replay_v1(
      built$setup$authorized[[peer]]$state, built$setup$session_id,
      releases[[2L]], releases[[1L]], 0L,
      .policy = built$fixture$input$policies[[peer]],
      .secret = built$fixture$input$secrets[[peer]],
      .identity = list(identity_pk = unname(
        built$fixture$input$fixture$pins[[peer]])),
      .cache_get = built$fixture$input$cache_get,
      .verifier = built$fixture$input$verifier),
    .S = forbidden, .dsvert_typed_blob_consume = forbidden,
    .dsvert_dp_sticky_subseed_material_v1 = forbidden,
    .dsvert_joint_dp_vector_exact_gc_finalize = forbidden,
    .package = "dsVert")
  expect_identical(replay$chunk$scaled_values, list("7"))
  expect_true(replay$durable_replay)
})
