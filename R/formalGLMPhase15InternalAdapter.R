# Internal, data-free Phase-1.5 GLM binding for the authenticated DSI relay.
#
# There is deliberately no AggregateMethod in this file.  The contract makes
# the future R/worker boundary reviewable without exposing a route that could
# open beta before the common sticky-noise release capsule supports GLM.

.DSVERT_FORMAL_GLM_PHASE15_DSI_BINDING_VERSION <-
  "dsvert-formal-glm-phase15-dsi-binding-v1"
.DSVERT_FORMAL_GLM_PHASE15_DSI_DOMAIN <-
  "dsVert/formal-glm/phase15/dsi-binding/v1"
.DSVERT_FORMAL_GLM_PHASE15_DP_BLOCKER <-
  "formal_glm_productive_joint_dp_release_lifecycle_unavailable"

.dsvert_formal_glm_phase15_hex <- function(value, what) {
  if (!is.character(value) || length(value) != 1L || is.na(value) ||
      !grepl("^[0-9a-f]{64}$", value)) {
    stop("Invalid ", what, ".", call. = FALSE)
  }
  value
}

.dsvert_formal_glm_phase15_hash <- function(value) {
  digest::digest(
    .dsvert_dp_canonical_json(
      .dsvert_dp_canonical_query_value(value)),
    algo = "sha256", serialize = FALSE)
}

.dsvert_formal_glm_phase15_peer_ids <- function(peer_ids) {
  if (!is.character(peer_ids) || length(peer_ids) != 2L ||
      is.null(names(peer_ids)) || anyNA(peer_ids) || anyNA(names(peer_ids)) ||
      any(!nzchar(names(peer_ids))) || anyDuplicated(names(peer_ids)) ||
      anyDuplicated(peer_ids) ||
      any(!grepl("^dsv1_[0-9a-f]{64}$", peer_ids))) {
    stop("Invalid pinned formal-GLM compute-peer identities.", call. = FALSE)
  }
  peer_ids
}

.dsvert_formal_glm_phase15_dsi_binding <- function(
    plan_sha256, final_receipt_pair_sha256, execution_transcript_sha256,
    bridge_sha256, snapshot_sha256, pinset_sha256, peer_ids) {
  hashes <- list(
    plan_sha256 = .dsvert_formal_glm_phase15_hex(
      plan_sha256, "formal-GLM plan hash"),
    final_receipt_pair_sha256 = .dsvert_formal_glm_phase15_hex(
      final_receipt_pair_sha256, "formal-GLM final receipt-pair hash"),
    execution_transcript_sha256 = .dsvert_formal_glm_phase15_hex(
      execution_transcript_sha256, "formal-GLM execution transcript hash"),
    bridge_sha256 = .dsvert_formal_glm_phase15_hex(
      bridge_sha256, "formal-GLM DP bridge hash"),
    snapshot_sha256 = .dsvert_formal_glm_phase15_hex(
      snapshot_sha256, "formal-GLM snapshot hash"),
    pinset_sha256 = .dsvert_formal_glm_phase15_hex(
      pinset_sha256, "formal-GLM pinset hash"))
  peer_ids <- .dsvert_formal_glm_phase15_peer_ids(peer_ids)
  ordered_names <- names(sort(peer_ids, method = "radix"))
  roles <- list(
    garbler_peer_name = ordered_names[[1L]],
    garbler_peer_id = unname(peer_ids[[ordered_names[[1L]]]]),
    evaluator_peer_name = ordered_names[[2L]],
    evaluator_peer_id = unname(peer_ids[[ordered_names[[2L]]]]))
  identity <- c(list(
    domain = .DSVERT_FORMAL_GLM_PHASE15_DSI_DOMAIN),
    hashes, roles)
  digest <- .dsvert_formal_glm_phase15_hash(identity)
  suffix <- substr(digest, 1L, 32L)
  unsigned <- c(list(
    version = .DSVERT_FORMAL_GLM_PHASE15_DSI_BINDING_VERSION),
    identity, list(
      purpose = paste0("formal-glm/phase15-internal/", digest),
      operation_id = paste0("op_", suffix),
      source_key = paste0("exact_gc_in_", suffix),
      output_key = paste0("exact_gc_out_", suffix),
      role_selection = "lexicographic_pinned_cryptographic_peer_id_v1",
      analyst_selected_roles = FALSE,
      transport =
        "authenticated_exact_gc_segment_spool_absolute_offsets_v1",
      fan_in = "server_authoritative_k_complete_pair_commitments_v1",
      opening = "none_sealed_bridge_shares_only_v1",
      registered_remote_method = FALSE,
      production_ready = FALSE))
  c(unsigned, list(
    binding_sha256 = .dsvert_formal_glm_phase15_hash(unsigned)))
}

.dsvert_formal_glm_phase15_dsi_binding_validate <- function(binding) {
  required <- c(
    "version", "domain", "plan_sha256", "final_receipt_pair_sha256",
    "execution_transcript_sha256", "bridge_sha256", "snapshot_sha256",
    "pinset_sha256", "garbler_peer_name", "garbler_peer_id",
    "evaluator_peer_name", "evaluator_peer_id", "purpose", "operation_id",
    "source_key", "output_key", "role_selection", "analyst_selected_roles",
    "transport", "fan_in", "opening", "registered_remote_method",
    "production_ready", "binding_sha256")
  if (!is.list(binding) || !setequal(names(binding), required) ||
      !identical(binding$version,
                 .DSVERT_FORMAL_GLM_PHASE15_DSI_BINDING_VERSION) ||
      !identical(binding$domain, .DSVERT_FORMAL_GLM_PHASE15_DSI_DOMAIN) ||
      !identical(binding$role_selection,
                 "lexicographic_pinned_cryptographic_peer_id_v1") ||
      !identical(binding$analyst_selected_roles, FALSE) ||
      !identical(binding$opening, "none_sealed_bridge_shares_only_v1") ||
      !identical(binding$registered_remote_method, FALSE) ||
      !identical(binding$production_ready, FALSE) ||
      !identical(binding$binding_sha256,
        .dsvert_formal_glm_phase15_hash(
          binding[setdiff(names(binding), "binding_sha256")]))) {
    stop("The formal-GLM DSI binding was modified.", call. = FALSE)
  }
  hashes <- binding[c(
    "plan_sha256", "final_receipt_pair_sha256",
    "execution_transcript_sha256", "bridge_sha256", "snapshot_sha256",
    "pinset_sha256")]
  invisible(lapply(names(hashes), function(name)
    .dsvert_formal_glm_phase15_hex(hashes[[name]], name)))
  peer_ids <- c(
    stats::setNames(binding$garbler_peer_id, binding$garbler_peer_name),
    stats::setNames(binding$evaluator_peer_id, binding$evaluator_peer_name))
  .dsvert_formal_glm_phase15_peer_ids(peer_ids)
  if (!identical(names(sort(peer_ids, method = "radix")),
                 c(binding$garbler_peer_name,
                   binding$evaluator_peer_name))) {
    stop("The formal-GLM DSI roles are not pinned-identity derived.",
         call. = FALSE)
  }
  expected <- .dsvert_formal_glm_phase15_dsi_binding(
    plan_sha256 = binding$plan_sha256,
    final_receipt_pair_sha256 = binding$final_receipt_pair_sha256,
    execution_transcript_sha256 = binding$execution_transcript_sha256,
    bridge_sha256 = binding$bridge_sha256,
    snapshot_sha256 = binding$snapshot_sha256,
    pinset_sha256 = binding$pinset_sha256,
    peer_ids = peer_ids)
  if (!identical(
        .dsvert_dp_canonical_query_value(binding),
        .dsvert_dp_canonical_query_value(expected))) {
    stop("The formal-GLM DSI binding is not canonical.", call. = FALSE)
  }
  invisible(binding)
}

.dsvert_formal_glm_phase15_dp_release_compile <- function(binding) {
  .dsvert_formal_glm_phase15_dsi_binding_validate(binding)
  stop(structure(
    list(
      message = paste(
        "Formal GLM remains sealed: its authenticated private Phase-1.9",
        "output has no registered durable handoff to the productive common",
        "sticky joint-DP release."),
      call = NULL,
      code = .DSVERT_FORMAL_GLM_PHASE15_DP_BLOCKER,
      missing = c(
        "registered Phase-1.9 private-output handoff to the productive worker",
        paste("exactly-once final opening bound to hidden execution validity",
              "and final receipts")),
      openings_performed = 0L,
      production_ready = FALSE),
    class = c("dsvert_formal_glm_dp_release_unavailable",
              "error", "condition")))
}
