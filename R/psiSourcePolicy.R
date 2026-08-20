#' Build a custodian-owned padded-PSI source descriptor
#'
#' This local administrative helper binds one protected data frame, its
#' privacy-unit identifier column, logical dataset identity and analysis
#' purpose to the padded PSI protocol. It is exported for server provisioning
#' but is deliberately not registered as a DataSHIELD aggregate or assign
#' method: the private snapshot digest must never be released to an analyst.
#'
#' @param data Protected data frame, available only in the custodian's trusted
#'   provisioning environment.
#' @param id_col Name of the identifier/privacy-unit column.
#' @param id Stable logical dataset identifier agreed by the consortium.
#' @param version Stable logical snapshot version agreed by the consortium.
#' @param purpose Public purpose identifier. All vertical peers must use the
#'   same value for one alignment.
#' @param privacy_unit_id Public semantic identifier for the privacy unit. Use
#'   the same value at every vertical peer even when local `id_col` aliases
#'   differ. It defaults to `id_col` for existing deployments.
#'
#' @return A descriptor suitable for one entry of the server-owned
#'   `dsvert.psi.authorized_sources` option.
#' @export
dsvertPSISourceDescriptor <- function(
    data, id_col, id, version,
    purpose = "patient-record-alignment-v1", privacy_unit_id = id_col) {
  if (!is.data.frame(data) || !is.character(id_col) ||
      length(id_col) != 1L || is.na(id_col) || !nzchar(id_col) ||
      !id_col %in% names(data)) {
    stop("data must be a data frame containing id_col", call. = FALSE)
  }
  .dsvert_canonical_label_values(
    data[[id_col]], "padded PSI identifiers", allow_na = TRUE,
    allow_blank = TRUE)
  label <- function(value, what) {
    .psi_padded_scalar(
      value, what, "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
  }
  .psi_padded_scalar(
    id_col, "authorized identifier column",
    "^[A-Za-z._][A-Za-z0-9._]{0,127}$")
  list(
    id = label(id, "dataset id"),
    version = label(version, "dataset version"),
    id_col = id_col,
    privacy_unit_id = label(privacy_unit_id, "privacy-unit identifier"),
    purpose = label(purpose, "alignment purpose"),
    snapshot_sha256 = .dsvert_dp_snapshot_digest(data))
}
