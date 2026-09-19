# Server-local preparation only. The opaque worker input contains private
# shares, routing material and a store key and must never become a receipt.
.dsvert_dp_lmm_cross_prepare_worker <- function(policy, secret, manifest,
    source_contract, schema_manifest, ss, analysis_id,
    routing_sidecar = NULL, producer = NULL) {
  source_contract <- .dsvert_dp_capsule_source_contract_validate(source_contract)
  source_hash <- .dsvert_joint_dp_hash(source_contract)
  artifact <- manifest$workload$families$gaussian_models$artifacts[[analysis_id]]
  contract <- .dsvert_dp_lmm_cross_source_contract(
    .dsvert_dp_glm_grid_cross_embedded_contract(artifact),
    policy, schema_manifest, source_hash)
  spec <- contract$spec
  peers <- unlist(spec$computation_peers, use.names = FALSE)
  parties <- .exact_gc_vecmul_party_context(ss)
  ids <- vapply(peers, function(peer)
    .dsvert_relay_peer_id(unname(policy$peer_pinset[[peer]])), character(1L))
  names(ids) <- peers
  authorities <- sort(unname(ids), method = "radix")
  if (anyDuplicated(authorities) ||
      !identical(parties$self_name, policy$peer_name) ||
      !setequal(c(parties$self_name, parties$peer_name), peers) ||
      !identical(.dsvert_relay_peer_id(.key_get("identity_pk", ss)),
                 unname(ids[[parties$self_name]])) ||
      !identical(.dsvert_relay_peer_id(ss$.exact_gc_peer_identity_pks[[parties$peer_name]]),
                 unname(ids[[parties$peer_name]]))) .dsvert_dp_grouped_cross_fail()
  # The retained router accepts the sidecar at the actual garbler. Transport
  # assigns roles by pinned identity ID; alphabetical owner names do not do so.
  if (!identical(unname(ids[[spec$grouping$owner_peer]]), authorities[[1L]])) {
    .dsvert_dp_grouped_cross_fail()
  }
  role <- if (identical(unname(ids[[policy$peer_name]]), authorities[[1L]])) {
    "garbler"
  } else "evaluator"
  routing <- NULL
  if (role == "garbler") {
    if (!identical(producer$capsule_id,
        .dsvert_dp_capsule_source_manifest_capsule_id(source_contract)) ||
        !identical(producer$source_context_hash, source_contract$source_context_hash) ||
        !identical(producer$coordinate_order_sha256, source_contract$coordinate_order_sha256)) {
      .dsvert_dp_grouped_cross_fail()
    }
    routing <- .dsvert_dp_lmm_cross_route_handoff(routing_sidecar, policy, secret,
      manifest, source_contract, schema_manifest, analysis_id, producer)
  } else if (!is.null(routing_sidecar) || !is.null(producer)) {
    .dsvert_dp_grouped_cross_fail()
  }
  handoff <- .dsvert_dp_lmm_cross_load_handoff(policy, secret, manifest,
    source_contract, schema_manifest, ss, analysis_id)
  semantic_key <- .dsvert_dp_glm_grid_cross_key(manifest, artifact, source_contract)
  directory <- file.path(dirname(.dsvert_dp_capsule_source_store_path(policy)),
    "lmm-staged-v1", semantic_key)
  if (!dir.exists(directory) &&
      !dir.create(directory, recursive = TRUE, mode = "0700", showWarnings = FALSE)) {
    .dsvert_dp_grouped_cross_fail()
  }
  if (.dsvert_dp_path_is_link(directory) ||
      !.dsvert_dp_private_mode(directory, directory = TRUE)) .dsvert_dp_grouped_cross_fail()
  key <- .dsvert_dp_capsule_source_mac(secret, "grouped-lmm-stage-store-key-v1", semantic_key)
  result <- .callMpcTool("grouped-lmm-staged-prepare-v1", list(
    handoff = handoff, role = role, session = paste0("lmm-staged-", semantic_key),
    authorities = as.list(authorities), semantic_key = semantic_key,
    store_directory = normalizePath(directory), store_key = gsub("[\r\n]", "",
      jsonlite::base64_enc(.dsvert_dp_capsule_source_hex_raw(key, "LMM durable stage key"))),
    routing = routing), simplify_output = FALSE)
  .dsvert_dp_glm_grid_cross_fields(result, c("worker_input", "purpose", "vector_len"))
  if (!is.character(result$worker_input) || length(result$worker_input) != 1L ||
      is.na(result$worker_input) || !nzchar(result$worker_input) ||
      nchar(result$worker_input, type = "bytes") > 64 * 1024^2 ||
      !is.character(result$purpose) || length(result$purpose) != 1L ||
      is.na(result$purpose) || !grepl("^grouped-lmm-staged-v1/[0-9a-f]{64}$", result$purpose) ||
      !identical(as.numeric(result$vector_len), as.numeric(artifact$coordinate_count))) {
    .dsvert_dp_grouped_cross_fail()
  }
  list(operation = "grouped-lmm-staged-v1", purpose = result$purpose,
    vector_len = result$vector_len, grouped_lmm = result$worker_input)
}
