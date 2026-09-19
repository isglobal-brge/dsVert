# Synthetic public signed fixtures only. Also sourced by the DSLite test harness.
.nb_grid_cross_fixture <- function(package = "dsVert", capacity = 8, bits = 18,
                                  beta_grid = list(c(-1, 1, 0), c(0, 1, 0)),
                                  theta_grid = c(0.125, 2), max_outcome = 3) {
  ns <- asNamespace(package)
  fn <- function(name) get(name, envir = ns, inherits = FALSE)
  server <- identical(package, "dsVert")
  hash <- fn(if (server) ".dsvert_joint_dp_hash" else ".dsvert_dp_capsule_source_hash")
  json <- fn(if (server) ".dsvert_dp_canonical_json" else ".dsvert_joint_dp_client_json")
  prefix <- if (server) ".DSVERT_DP_" else ".DSVERT_CLIENT_DP_"
  peers <- c("peer_a", "peer_b")
  keys <- stats::setNames(lapply(peers, function(peer) openssl::ed25519_keygen()), peers)
  b64 <- function(x) sub("=+$", "", chartr("+/", "-_", gsub("[\r\n]", "", jsonlite::base64_enc(x))))
  pins <- vapply(keys, function(key) b64(tail(as.raw(as.list(key)$pubkey), 32L)), character(1L))
  policy <- list(peer_pinset = pins, peer_pinset_sha256 = hash(as.list(pins)),
                 designated_noise_peers = peers, unit_capacity = capacity,
                 numeric_grid_bits = bits, adjacency = "add_remove_patient")
  snapshot <- list(logical_snapshot_id = "nb-cohort", version = "v1",
                   alignment_protocol_version = 1)
  schema <- list(version = fn(paste0(prefix, "CAPSULE_SCHEMA_VERSION")),
    logical_snapshot = snapshot, peer_pinset_sha256 = policy$peer_pinset_sha256,
    datasets = list(cohort = list(dataset_id = "cohort", dataset_version = "v1",
      schema_version = "v1", alignment_group = "aligned",
      patient_keys = list(peer_a = "id", peer_b = "id"), columns = list(
        x = list(kind = "numeric", owner_peer = "peer_a", lower = -2, upper = 4),
        z = list(kind = "numeric", owner_peer = "peer_b", lower = 0, upper = 10),
        y = list(kind = "numeric", owner_peer = "peer_a", lower = 0, upper = max_outcome)))))
  sign_schema <- function(value) {
    value$signatures <- NULL
    message <- if (server) fn(".dsvert_dp_capsule_schema_message")(value) else {
      charToRaw(paste0(fn(paste0(prefix, "CAPSULE_SCHEMA_SIGNATURE_DOMAIN")), json(value)))
    }
    value$signatures <- lapply(keys, function(key) b64(openssl::ed25519_sign(message, key)))
    value
  }
  schema <- sign_schema(schema)
  authenticated <- if (server) {
    fn(".dsvert_dp_capsule_schema")(policy, snapshot, schema, fn(".dsvert_relay_verify_message"))
  } else fn(".dsvert_dp_glm_grid_cross_schema_validate")(
    policy, snapshot, schema, fn(".dsvert_dp_glm_grid_cross_verify"))
  raw <- list(version = "nb_grid_cross_v1", analysis_id = "nb_grid", dataset = "cohort",
    outcome = "peer_a$y", predictor_order = c("peer_a$x", "peer_b$z"),
    beta_grid = beta_grid, theta_grid = theta_grid, max_outcome = max_outcome,
    alignment = list(version = "existing_prealigned_logical_dataset_v1",
      method = "pinned_psi_ordered_manifest_v1", alignment_group = "aligned",
      public_alignment_contract_sha256 = hash(list(logical_snapshot = snapshot,
        alignment_group = "aligned", method = "pinned_psi_ordered_manifest_v1")),
      public_patient_dependent_hash = FALSE))
  order <- order(vapply(Map(function(beta, theta) list(beta = as.list(beta), theta = theta),
    beta_grid, theta_grid), json, character(1L)), method = "radix")
  raw$beta_grid <- beta_grid[order]
  raw$theta_grid <- theta_grid[order]
  registration <- fn(".dsvert_dp_nb_grid_cross_register")()
  spec <- registration$build_spec(raw, policy, authenticated)
  artifact <- registration$build_artifact(spec)
  unsigned <- list(version = fn(paste0(prefix, "GLM_GRID_CROSS_CONTRACT_VERSION")),
    spec = spec, artifact = artifact,
    source_contract = registration$build_source_contract(spec, artifact))
  sign <- function(value) {
    value$signatures <- NULL
    message <- fn(".dsvert_dp_glm_grid_cross_message")(value)
    value$signatures <- lapply(keys, function(key) b64(openssl::ed25519_sign(message, key)))
    value
  }
  list(policy = policy, schema = schema, authenticated = authenticated,
       raw = raw, unsigned = unsigned, contract = sign(unsigned), sign = sign,
       sign_schema = sign_schema, registration = registration)
}
