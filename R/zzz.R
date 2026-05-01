#' @title Package Load Hook
#' @description Auto-generates Ed25519 identity seed on first load if none exists.
#' @keywords internal
#' @importFrom utils head tail packageVersion
NULL

.dsvert_init_identity_seed <- function() {
  seed_path <- file.path(Sys.getenv("HOME"), ".dsvert", "identity.seed")
  if (!file.exists(seed_path)) {
    seed_dir <- dirname(seed_path)
    if (!dir.exists(seed_dir))
      dir.create(seed_dir, showWarnings = FALSE, recursive = TRUE, mode = "0700")
    # 256 bits of entropy from /dev/urandom (Unix) or R PRNG (Windows)
    seed_raw <- if (.Platform$OS.type == "unix" && file.exists("/dev/urandom")) {
      con <- file("/dev/urandom", "rb")
      on.exit(close(con), add = TRUE)
      readBin(con, "raw", 32L)
    } else {
      as.raw(sample.int(256L, 32L, replace = TRUE) - 1L)
    }
    con_out <- file(seed_path, "w")
    on.exit(close(con_out), add = TRUE)
    base::writeLines(jsonlite::base64_enc(seed_raw), con_out)
    Sys.chmod(seed_path, mode = "0600")
  }
  invisible(NULL)
}

.onLoad <- function(libname, pkgname) {
  .dsvert_init_identity_seed()
}
