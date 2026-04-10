#' @title Package Load Hook
#' @description Auto-generates Ed25519 identity seed on first load if none exists.
#' @keywords internal

.onLoad <- function(libname, pkgname) {
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
    writeLines(jsonlite::base64_enc(seed_raw), seed_path)
    Sys.chmod(seed_path, mode = "0600")
  }
}
