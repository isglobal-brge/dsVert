# Immutable, identity-bound namespace for bounded-lifetime DP accounting.
#
# The receipt is deployment state beside the identity seed, not a configurable
# ledger accessory. It binds the canonical consortium policy and this peer's
# local accountant paths before any accountant ledger, registry, alignment
# registry, or protected source is opened by a DP policy operation.

.DSVERT_PRIVACY_ACCOUNTANT_NAMESPACE_PROTOCOL <-
  "dsvert-privacy-accountant-namespace-receipt-v1"
.DSVERT_PRIVACY_ACCOUNTANT_NAMESPACE_HMAC_DOMAIN <-
  "dsVert/privacy-accountant-namespace/receipt/hmac-sha256/v1|"

.dsvert_privacy_accountant_namespace_abort <- function(message, class) {
  stop(structure(
    list(message = message, call = NULL),
    class = c(class, "error", "condition")))
}

.dsvert_privacy_accountant_namespace_receipt_path <- function() {
  paste0(
    path.expand(.dsvert_identity_seed_path()),
    ".privacy-accountant-namespace-v1")
}

.dsvert_privacy_accountant_namespace_canonical_path <- function(
    path, what) {
  if (!is.character(path) || length(path) != 1L || is.na(path) ||
      !nzchar(path)) {
    .dsvert_privacy_accountant_namespace_abort(
      paste0("The privacy-accountant ", what, " path is invalid."),
      "dsvert_privacy_accountant_namespace_mismatch")
  }
  path <- path.expand(path)
  if (!grepl("^/", path)) {
    .dsvert_privacy_accountant_namespace_abort(
      paste0("The privacy-accountant ", what, " path must be absolute."),
      "dsvert_privacy_accountant_namespace_mismatch")
  }
  parent <- tryCatch(
    normalizePath(dirname(path), winslash = "/", mustWork = TRUE),
    error = function(error) NULL)
  if (is.null(parent) || .dsvert_dp_path_is_link(dirname(path))) {
    .dsvert_privacy_accountant_namespace_abort(
      paste0("The privacy-accountant ", what,
             " directory is unavailable or linked."),
      "dsvert_privacy_accountant_namespace_mismatch")
  }
  file.path(parent, basename(path))
}

.dsvert_privacy_accountant_namespace_expected <- function(policy, context) {
  if (!is.list(policy) || !is.list(context) ||
      !is.list(context$common) ||
      !is.character(context$consortium_id) ||
      length(context$consortium_id) != 1L ||
      is.na(context$consortium_id) ||
      !grepl("^jdpc1_[0-9a-f]{64}$", context$consortium_id) ||
      !is.character(context$peer_name) ||
      length(context$peer_name) != 1L || is.na(context$peer_name) ||
      !nzchar(context$peer_name) ||
      !identical(policy$peer_name, context$peer_name)) {
    .dsvert_privacy_accountant_namespace_abort(
      "The privacy-accountant namespace context is invalid.",
      "dsvert_privacy_accountant_namespace_mismatch")
  }
  common <- .dsvert_dp_canonical_query_value(context$common)
  derived_consortium <- paste0(
    "jdpc1_", .dsvert_joint_dp_hash(common))
  if (!identical(context$consortium_id, derived_consortium)) {
    .dsvert_privacy_accountant_namespace_abort(
      "The privacy-accountant consortium binding is inconsistent.",
      "dsvert_privacy_accountant_namespace_mismatch")
  }
  ledger <- .dsvert_privacy_accountant_namespace_canonical_path(
    policy$ledger_path, "local ledger")
  joint <- .dsvert_privacy_accountant_namespace_canonical_path(
    .dsvert_joint_dp_ledger_path(policy), "joint ledger")
  registry <- .dsvert_privacy_accountant_namespace_canonical_path(
    paste0(joint, ".capsule-registry-v3.sqlite"), "capsule registry")
  vector <- .dsvert_privacy_accountant_namespace_canonical_path(
    paste0(ledger, ".joint-dp-vector-v4.sqlite"), "vector store")
  source <- .dsvert_privacy_accountant_namespace_canonical_path(
    paste0(ledger, ".capsule-source-v3.sqlite"), "source store")
  seed <- tryCatch(
    .get_identity_seed(), error = function(error) NULL)
  if (!is.character(seed) || length(seed) != 1L || is.na(seed)) {
    .dsvert_privacy_accountant_namespace_abort(
      "The privacy-accountant namespace identity is unavailable.",
      "dsvert_privacy_accountant_namespace_mismatch")
  }
  list(
    protocol = .DSVERT_PRIVACY_ACCOUNTANT_NAMESPACE_PROTOCOL,
    identity_seed_id = .dsvert_identity_seed_id(seed),
    privacy_accountant_namespace_id = context$consortium_id,
    common = common,
    peer_name = context$peer_name,
    paths = list(
      local_ledger = ledger,
      joint_ledger = joint,
      capsule_registry = registry,
      vector_store = vector,
      source_store = source))
}

.dsvert_privacy_accountant_namespace_envelope <- function(expected) {
  payload_json <- .dsvert_dp_canonical_json(expected)
  secret <- .dsvert_dp_secret()
  list(
    protocol = .DSVERT_PRIVACY_ACCOUNTANT_NAMESPACE_PROTOCOL,
    payload_json = payload_json,
    mac_sha256 = digest::hmac(
      key = secret,
      object = charToRaw(paste0(
        .DSVERT_PRIVACY_ACCOUNTANT_NAMESPACE_HMAC_DOMAIN, payload_json)),
      algo = "sha256", serialize = FALSE, raw = FALSE))
}

.dsvert_privacy_accountant_namespace_validate <- function(
    receipt_path, policy, context) {
  expected <- .dsvert_privacy_accountant_namespace_expected(policy, context)
  invalid <- function() {
    .dsvert_privacy_accountant_namespace_abort(
      "The privacy-accountant namespace receipt does not match this deployment.",
      "dsvert_privacy_accountant_namespace_mismatch")
  }
  if (.dsvert_dp_path_is_link(receipt_path) ||
      !file.exists(receipt_path) || !file_test("-f", receipt_path) ||
      !.dsvert_dp_private_mode(receipt_path, directory = FALSE)) {
    invalid()
  }
  links <- tryCatch(
    .dsvert_dp_noise_link_count(receipt_path), error = function(error) NA_real_)
  if (!identical(links, 1)) invalid()
  info <- file.info(receipt_path)
  if (nrow(info) != 1L || is.na(info$size) || info$size < 1L ||
      info$size > 65536L) {
    invalid()
  }
  before <- unname(info[c("size", "mtime", "ctime")])
  encoded <- tryCatch(
    readBin(receipt_path, what = "raw", n = info$size + 1L),
    error = function(error) raw(0L))
  after_info <- file.info(receipt_path)
  after <- unname(after_info[c("size", "mtime", "ctime")])
  if (.dsvert_dp_path_is_link(receipt_path) ||
      !file.exists(receipt_path) || !file_test("-f", receipt_path) ||
      !.dsvert_dp_private_mode(receipt_path, directory = FALSE) ||
      !identical(before, after) || length(encoded) != info$size) {
    invalid()
  }
  value <- tryCatch(
    jsonlite::fromJSON(rawToChar(encoded), simplifyVector = TRUE),
    error = function(error) NULL)
  envelope <- .dsvert_privacy_accountant_namespace_envelope(expected)
  if (!is.list(value) || is.null(names(value)) || anyNA(names(value)) ||
      anyDuplicated(names(value)) ||
      !setequal(names(value), names(envelope)) ||
      !identical(value$protocol, envelope$protocol) ||
      !identical(value$payload_json, envelope$payload_json) ||
      !identical(value$mac_sha256, envelope$mac_sha256) ||
      !identical(
        .dsvert_dp_canonical_json(value),
        .dsvert_dp_canonical_json(envelope))) {
    invalid()
  }
  expected
}

.dsvert_privacy_accountant_namespace_state_is_virgin <- function(policy) {
  bases <- .dsvert_identity_dp_state_bases(policy$ledger_path)
  suffixes <- c("", ".lock", "-wal", "-shm", "-journal")
  artifacts <- unique(unlist(lapply(
    bases, function(path) paste0(path, suffixes)), use.names = FALSE))
  !any(vapply(artifacts, function(path) {
    file.exists(path) || .dsvert_dp_path_is_link(path)
  }, logical(1L)))
}

.dsvert_privacy_accountant_namespace_commit <- function(
    receipt_path, policy, context) {
  expected <- .dsvert_privacy_accountant_namespace_expected(policy, context)
  envelope <- .dsvert_privacy_accountant_namespace_envelope(expected)
  temporary <- tempfile(
    paste0(".privacy-accountant-namespace-", Sys.getpid(), "."),
    tmpdir = dirname(receipt_path))
  on.exit(if (file.exists(temporary)) unlink(temporary, force = TRUE),
          add = TRUE)
  connection <- file(temporary, open = "wb")
  on.exit(try(if (isOpen(connection)) close(connection), silent = TRUE),
          add = TRUE)
  writeBin(charToRaw(.dsvert_dp_canonical_json(envelope)), connection)
  flush(connection)
  close(connection)
  Sys.chmod(temporary, mode = "0600")
  invisible(.dsvert_privacy_accountant_namespace_validate(
    temporary, policy, context))
  .dsvert_identity_require_sync(
    temporary, "staged privacy-accountant namespace receipt")
  if (!file.rename(temporary, receipt_path)) {
    stop("Could not atomically commit the privacy-accountant namespace receipt",
         call. = FALSE)
  }
  Sys.chmod(receipt_path, mode = "0600")
  invisible(.dsvert_privacy_accountant_namespace_validate(
    receipt_path, policy, context))
  .dsvert_identity_require_sync(
    dirname(receipt_path), "privacy-accountant namespace directory")
  expected
}

.dsvert_privacy_accountant_namespace_enforce <- function(
    policy, context, allow_virgin_bootstrap = FALSE) {
  if (!is.logical(allow_virgin_bootstrap) ||
      length(allow_virgin_bootstrap) != 1L ||
      is.na(allow_virgin_bootstrap)) {
    stop("The internal privacy-accountant bootstrap flag is invalid.",
         call. = FALSE)
  }
  receipt_path <- .dsvert_privacy_accountant_namespace_receipt_path()
  present <- file.exists(receipt_path) ||
    .dsvert_dp_path_is_link(receipt_path)
  if (isTRUE(present)) {
    return(.dsvert_privacy_accountant_namespace_validate(
      receipt_path, policy, context))
  }
  if (!isTRUE(allow_virgin_bootstrap)) {
    .dsvert_privacy_accountant_namespace_abort(
      paste0(
        "The identity exists without its privacy-accountant namespace ",
        "receipt; an explicit audited virgin-state bootstrap is required."),
      "dsvert_privacy_accountant_namespace_missing")
  }

  lock_path <- paste0(receipt_path, ".lock")
  if (.dsvert_dp_path_is_link(lock_path)) {
    .dsvert_privacy_accountant_namespace_abort(
      "The privacy-accountant namespace lock is linked.",
      "dsvert_privacy_accountant_namespace_mismatch")
  }
  previous_umask <- Sys.umask("0077")
  on.exit(try(Sys.umask(previous_umask), silent = TRUE), add = TRUE)
  lock <- filelock::lock(lock_path, timeout = 30000)
  if (is.null(lock)) {
    stop("The privacy-accountant namespace bootstrap lock is unavailable.",
         call. = FALSE)
  }
  on.exit(try(filelock::unlock(lock), silent = TRUE), add = TRUE)
  Sys.chmod(lock_path, mode = "0600")
  links <- tryCatch(
    .dsvert_dp_noise_link_count(lock_path), error = function(error) NA_real_)
  if (.dsvert_dp_path_is_link(lock_path) ||
      !.dsvert_dp_private_mode(lock_path, directory = FALSE) ||
      !identical(links, 1)) {
    .dsvert_privacy_accountant_namespace_abort(
      "The privacy-accountant namespace lock is not private.",
      "dsvert_privacy_accountant_namespace_mismatch")
  }

  if (file.exists(receipt_path) ||
      .dsvert_dp_path_is_link(receipt_path)) {
    return(.dsvert_privacy_accountant_namespace_validate(
      receipt_path, policy, context))
  }
  if (!isTRUE(.dsvert_privacy_accountant_namespace_state_is_virgin(policy))) {
    .dsvert_privacy_accountant_namespace_abort(
      paste0(
        "Privacy-accountant state is not virgin; namespace bootstrap and ",
        "migration are forbidden for non-virgin state."),
      "dsvert_privacy_accountant_namespace_bootstrap_denied")
  }
  .dsvert_privacy_accountant_namespace_commit(
    receipt_path, policy, context)
}

#' Bootstrap the Local Privacy-Accountant Namespace
#'
#' Administrative, local-only action for a fresh deployment or an audited
#' pre-receipt upgrade. It is exported for a server administrator but is not a
#' DataSHIELD aggregate or assign method. Stop the service first and verify all
#' prior ledger, joint-ledger, registry, vector-store, source-store, lock and
#' SQLite-sidecar locations, including retired backups. This action succeeds
#' only when every known configured state path is absent; it never migrates or
#' resets lifetime history.
#'
#' @param confirm_no_other_history Must be exactly `TRUE`, affirming that the
#'   custodian has stopped the service, audited every previous accountant path
#'   and backup, and confirmed that no other lifetime history exists.
#'
#' @return Invisibly, the shared privacy-accountant namespace ID and the local
#'   immutable receipt path.
#' @export
dsvertBootstrapPrivacyAccountantNamespace <- function(
    confirm_no_other_history = FALSE) {
  if (!identical(confirm_no_other_history, TRUE)) {
    stop(paste0(
      "confirm_no_other_history must be exactly TRUE after the custodian ",
      "stops the service and audits all prior accountant paths and backups."),
      call. = FALSE)
  }
  invisible(.dsvert_dp_policy_build(
    .privacy_accountant_bootstrap_empty = TRUE))
}
