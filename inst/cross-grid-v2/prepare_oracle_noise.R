# Synthetic validation only. Obtain the production sticky noise contract without
# reading source shares or executing an MPC circuit. Nothing here is exported.
grid_oracle_noise <- function(peers, conns, bootstrap) {
  cf <- function(name) get(name, asNamespace("dsVertClient"), inherits = FALSE)
  bundle <- bootstrap$manifest_bundle
  trusted <- cf(".dsvert_dp_synopsis_client_bundle")(bundle, bootstrap$status)
  context <- trusted$context
  layout <- cf(".dsvert_dp_capsule_vector_layout")(trusted$manifest)
  built <- cf(".dsvert_dp_synopsis_runner_compile")(
    context, bundle, trusted, layout, DSI::datashield.aggregate)
  session <- cf(".dsvert_uuid4")()
  for (peer in peers) peer$worker$run(function() {
    trace(".dsvert_dp_synopsis_execution_context_v1", where = asNamespace("dsVert"),
      print = FALSE, exit = quote(assign(".grid_oracle_authority", list(
        context = returnValue(), ss = ss, policy = .policy, secret = .secret), .GlobalEnv)))
    TRUE
  })
  calls <- stats::setNames(lapply(context$designated, function(peer) call(
    "dsvertDPSynopsisPrepareDS", session_id = session,
    manifest_sha256 = bundle$manifest_sha256,
    claim_set_json = cf(".dsvert_joint_dp_client_json")(built$claim_set),
    compilation_json = cf(".dsvert_joint_dp_client_json")(built$compilation))), context$designated)
  prepares <- cf(".dsvert_dp_synopsis_runner_json_set")(
    cf(".dsvert_fanout_by_site")(context$conns, calls,
      operation = "synthetic oracle PREPARE", .aggregate = DSI::datashield.aggregate),
    context$designated, "PREPARE", cf(".DSVERT_CLIENT_SYNOPSIS_PREPARE_MAX_OBJECT_BYTES"))
  setup <- cf(".dsvert_setup_exact_gc_transport")(conns, context$servers,
    match(context$designated, context$servers), session)
  on.exit(cf(".dsvert_dp_cross_exact_cleanup")(context$conns, session, setup,
    DSI::datashield.aggregate, cf(".dsvert_setup_exact_gc_transport")), add = TRUE)
  authorities <- lapply(peers[context$designated], function(peer) peer$worker$run(
    function(session, prepares) {
      sf <- function(name) get(name, asNamespace("dsVert"), inherits = FALSE)
      captured <- get(".grid_oracle_authority", .GlobalEnv)
      untrace(".dsvert_dp_synopsis_execution_context_v1", where = asNamespace("dsVert"))
      context <- captured$context
      checked <- sf(".dsvert_dp_synopsis_execution_prepare_set_v1")(
        prepares[[1]], prepares[[2]], context, captured$policy)
      semantic <- context$authorization$artifact$semantic
      seed <- sf(".dsvert_dp_sticky_subseed_material_v1")(
        context$authorization$artifact_key, semantic$privacy$mechanism$randomness$lanes,
        semantic$noise_authority_roles$authority_ids, "final_noise",
        context$authorization$local_authority$identity_pk)
      draws <- lapply(seq_len(context$attempt$value$execution_geometry$chunk_count) - 1L,
        function(index) {
          chunk <- sf(".dsvert_dp_synopsis_execution_chunk_v1")(context, index)
          op <- sf(".dsvert_dp_synopsis_execution_exact_gc_operation_v1")(
            captured$ss, session, context, checked, chunk, captured$policy,
            captured$secret, sf(".get_identity_keypair")(), NULL)
          list(operation = op$worker$operation, purpose = op$worker$purpose,
            garbler_id = op$roles$garbler_peer_id, evaluator_id = op$roles$evaluator_peer_id,
            role = if (captured$policy$peer_name == op$roles$garbler_peer_name) "garbler" else "evaluator",
            joint_dp_vector = op$worker$worker_policy,
            private_seed = sf(".dsvert_joint_dp_vector_exact_gc_seed_b64")(seed))
        })
      list(artifact_key = context$authorization$artifact_key, draws = draws)
    }, args = list(session, prepares)))
  stopifnot(identical(authorities[[1]]$artifact_key, authorities[[2]]$artifact_key))
  list(artifact_key = authorities[[1]]$artifact_key,
    captures = unlist(lapply(authorities, `[[`, "draws"), recursive = FALSE))
}
