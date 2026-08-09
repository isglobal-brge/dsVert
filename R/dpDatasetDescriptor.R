#' Build a custodian-owned DP dataset descriptor
#'
#' This local administrative helper accepts only an object carrying the full
#' persistent attestation produced by pinned padded PSI. It binds the private
#' snapshot and the stable semantic alignment contract while deliberately
#' excluding run-specific PSI tokens, nonces and session identifiers. It is
#' exported for trusted server provisioning but is not registered as a
#' DataSHIELD aggregate or assign method: neither private commitment may be
#' released to the analyst. Normal Rock/Opal deployments use the automatic
#' post-attestation registry populated from a custodian-owned dataset template;
#' this helper remains useful for explicit legacy-style provisioning.
#'
#' @param data Protected data frame produced by the pinned padded-PSI
#'   alignment and available only in the custodian's trusted provisioning
#'   environment.
#' @param id Stable logical dataset identifier agreed by the consortium.
#' @param version Stable logical snapshot version agreed by the consortium.
#'
#' @return A private descriptor suitable for one entry of the server-owned
#'   `dsvert.dp.datasets` option.
#' @export
dsvertDPDatasetDescriptor <- function(data, id, version) {
  if (!is.data.frame(data)) {
    stop("data must be an aligned protected data frame", call. = FALSE)
  }
  label <- function(value, what) {
    value <- .dsvert_dp_scalar_string(value, what)
    if (!grepl("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$", value)) {
      stop(what, " contains unsupported characters", call. = FALSE)
    }
    value
  }
  id <- label(id, "dataset id")
  version <- label(version, "dataset version")
  binding <- .dsvert_dp_padded_alignment_binding(data)
  if (!identical(binding$descriptor$id, id) ||
      !identical(binding$descriptor$version, version)) {
    stop("id and version must match the authenticated padded-PSI contract",
         call. = FALSE)
  }
  binding$descriptor
}
