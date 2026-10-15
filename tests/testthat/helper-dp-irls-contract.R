# Fully synthetic, public contract. This helper is shared with B1 state tests;
# it is not an admitted MPC profile and contains no private source material.
.irls_q <- function(n, d = "1") list(d = as.character(d), n = as.character(n))
.irls_contract_fixture <- local({
  identities <- NULL
  function() {
    if (is.null(identities)) identities <<- setNames(lapply(1:2, function(i)
      .callMpcTool("derive-identity", list(seed = jsonlite::base64_enc(
        as.raw((seq_len(32L) + 53L * i) %% 256L))))), c("peer_a", "peer_b"))
    pins <- vapply(identities, function(x) .dsvert_relay_normalize_identity_pk(x$identity_pk), character(1L))
    q <- .irls_q; zero <- paste(rep("0", 64L), collapse = "")
    hex <- function(s) digest::digest(s, algo = "sha256", serialize = FALSE)
    dependency <- function(peer, dataset) {
      epoch <- hex(paste(peer, dataset, "epoch")); source <- hex(paste(peer, dataset, "source"))
      list(source_identity = unname(pins[[peer]]), dataset = dataset,
        dependency = list(version = .DSVERT_DP_SYNOPSIS_DEPENDENCY_VERSION,
          dataset_id = dataset, dataset_version = "synthetic-v1", authorization_epoch = epoch,
          source_contract_id = source, derivation_policy_id = hex(paste(dataset, "derivation")),
          provenance_kind = "frozen_materialized_root", authorization_epochs = list(list(
            peer_identity = unname(pins[[peer]]), authorization_epoch = epoch, source_contract_id = source))))
    }
    deps <- list(dependency("peer_a", "outcomes"), dependency("peer_b", "predictors"),
                 dependency("peer_a", "membership"))
    deps <- deps[order(vapply(deps, function(z) paste(z$source_identity, z$dataset, sep = "|"), character(1L)), method = "radix")]
    source_ids <- as.list(vapply(deps, `[[`, character(1L), "dataset"))
    limits <- list(common_denominator = "1", input_bits = "64", k_max = "33", temporary_bits = "2136")
    spec <- list(mechanism = "dp_irls_v1", profile_id = "irls-synthetic-b1-p2-v1",
      estimand = list(formula = "y ~ x", coefficient_order = list("(Intercept)", "x"),
        family = "binomial", link = "logit", levels = list(), contrasts = list(),
        columns = list(list(column_id = "x", owner = "peer_b", source_id = "predictors", role = "predictor"),
                       list(column_id = "y", owner = "peer_a", source_id = "outcomes", role = "outcome")),
        offset = list(kind = "none", column_id = "none", zero_exposure = "not-applicable"),
        intercept = "1", clamped_target = "bounded-Bernoulli-equation-v1",
        model_assumptions = list("independent-Bernoulli-persons")),
      privacy_source = list(adjacency = "add-remove-person", capacity = "4", row_cap = "1",
        closure = list(version = .DSVERT_DP_SYNOPSIS_CLOSURE_VERSION, dependencies = deps), source_ids = source_ids,
        alignment_purpose = "irls-person-membership-v1", missing_rule = "masked-zero-person-v1",
        duplicate_rule = "reject-in-protected-validity-v1", ordering_rule = "frozen-public-person-slots-v1",
        x_bounds = list(list(lower = q("1"), upper = q("1")), list(lower = q("-1"), upper = q("1"))),
        y_bounds = list(lower = q("0"), upper = q("1")), offset_bounds = list(lower = q("0"), upper = q("0")),
        person_caps = list(score_abs = list(q("4"), q("4")), curvature_abs = list(q("4"), q("4"), q("4"))),
        peer_pins = as.list(pins), pinset_sha256 = .dsvert_dp_synopsis_pinset_hash_v1(pins),
        computation_peers = list("peer_a", "peer_b"), schema_sha256 = hex("synthetic-schema")),
      numeric = list(eta_bounds = list(lower = q("-2"), upper = q("2")), score_definition = "x-times-y-minus-mu-v1",
        curvature_definition = "mu-times-one-minus-mu-xx-v1", curvature_role = "derivative",
        approximation_certificate_sha256 = hex("synthetic-numeric-not-producer-admitted"),
        lattice = list(g = q("1"), H = q("1"), beta = q("1", "4")), rounding = "nearest-even-per-person-v1",
        rounding_slack = list(g = q("1"), H = q("3", "2")), ring_bits = "128", source_intermediate_bits = "192",
        layout = list("g:1", "g:2", "H:1:1", "H:1:2", "H:2:2"),
        translation = list(g = list("16", "16"), H = list("16", "16", "16")),
        person_integer_caps = list(g = list("4", "4"), H = list("4", "4", "4")),
        translation_margin = list(g = list("0", "0"), H = list("0", "0", "0")),
        upper_limits = list(g = list("32", "32"), H = list("32", "32", "32")),
        compiler_version = "synthetic-b1-compiler-v1", backend_version = "synthetic-public-payload-v1",
        sampler_version = "independent_full_global_draw_convolution_ring128_v4", certificate = limits,
        certificate_sha256 = .dsvert_dp_irls_hash("dsvert-v3-irls-numeric-certificate-v1", limits)),
      path = list(T = "2", start = list(kind = "zero", digest = zero, beta = list(q("0"), q("0")),
        epsilon = q("0"), composition_sha256 = zero), box = list(lower = list(q("-1"), q("-1")), upper = list(q("1"), q("1"))),
        floor = q("1"), floor_quantum = q("1"), ridge = q("0"), damping = list(q("1"), q("1")),
        trust = list(q("1"), q("1")), refresh_mask = list("1", "1"), terminal_audit = "1",
        update_version = "dp_irls_update_v1", tie_rule = "nearest-even-v1", root_domain = "dsvert-v3-irls-root-v1",
        stage_domain = "dsvert-v3-irls-stage-v1", lane_domain = "dsvert-v3-irls-lane-v1",
        role_domain = "dsvert-v3-irls-role-v1", pin_domain = "dsvert-v3-irls-pins-v1"),
      accounting = list(geometry = "split-block-v1", stages = list(
        list(t = "0", purpose = "optimizer", g = q("1"), H = q("1"), epsilon = q("2"), alpha_g = q("1", "8"), alpha_H = q("1", "12")),
        list(t = "1", purpose = "optimizer", g = q("1"), H = q("1"), epsilon = q("2"), alpha_g = q("1", "8"), alpha_H = q("1", "12")),
        list(t = "2", purpose = "terminal-audit", g = q("2"), H = q("2"), epsilon = q("4"), alpha_g = q("1", "4"), alpha_H = q("1", "6"))),
        sensitivity = list(g = "8", H = "12"), pilot_epsilon = q("0"), auxiliary = list(), epsilon_path = q("8"),
        delta = q("0"), rho = q("0"), noise_law = "two-independent-full-coordinate-discrete-laplace-draws-v4",
        draws_per_authority = "1", authority_count = "2", failure_semantics = "reserve-full-path-charge-observed-lanes-no-refund-no-redraw-v1"),
      inference = list(mode = "candidate", method = "whole-path-replay-plus-terminal-inverse-v1", qualification_certificate_sha256 = zero,
        replay = list(law = "two-independent-full-coordinate-discrete-laplace-draws-v4", version = "public-replay-sequential-stream-v1", seed = hex("public-replay"), replicates = "2000"),
        confidence = q("19", "20"), refusal = as.list(setNames(rep("1", 8L), c("any_shift", "any_trust", "any_projection", "any_saturation", "ridge", "positive_information", "domain_margin", "terminal_audit"))),
        thresholds = list(diagnostic_tail = q("1", "100"), curvature_error_ratio = q("1", "10"), condition_max = q("1000"), bias_sd_ratio = q("1", "10"), replay_precision = q("1", "10")),
        tolerances = list(approximation = q("1", "100"), bias = q("1", "100"), noise_tail = q("1", "1000")),
        allowed_contrasts = list(list(q("1"), q("0")), list(q("0"), q("1")))),
      operations = list(shape = list(p = "2", coordinates = "5", capacity = "4", row_cap = "1"), max_compile_bytes = "1048576",
        max_memory_bytes = "1048576", max_stage_seconds = "240", max_path_seconds = "840",
        recovery_version = "durable-single-successor-v1", retention_policy = "retain-committed-bytes-signatures-and-reservations-v1", resource_failure = "fail-closed-no-new-root-no-redraw-v1"))
    sign <- function(value) {
      value <- .dsvert_dp_irls_contract_normalize(value)
      unsigned <- list(version = .DSVERT_DP_IRLS_CONTRACT_VERSION, contract = value)
      message <- .dsvert_dp_irls_contract_message(unsigned)
      c(unsigned, list(signatures = lapply(identities, function(identity)
        .dsvert_relay_sign_message(message, identity$identity_sk))))
    }
    spec <- .dsvert_dp_irls_contract_normalize(spec)
    list(spec = spec, signed = sign(spec), pins = pins, identities = identities,
      sign = sign, payload = function(t = "0") list(g = list("16", "16"), H = list("20", "16", "20")))
  }
})
