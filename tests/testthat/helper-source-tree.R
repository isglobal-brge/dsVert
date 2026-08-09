.dsvert_test_source_roots <- function() {
  test_root <- normalizePath(
    file.path(testthat::test_path(), "..", ".."), mustWork = FALSE)
  candidates <- unique(c(
    test_root,
    file.path(test_root, "00_pkg_src", "dsVert"),
    getwd(),
    file.path(getwd(), "00_pkg_src", "dsVert")))
  candidates <- candidates[
    file.exists(file.path(candidates, "DESCRIPTION")) &
      file.exists(file.path(candidates, "R", "zzz.R"))]
  unique(normalizePath(candidates, mustWork = TRUE))
}

.dsvert_test_package_file <- function(..., source_only = FALSE) {
  parts <- as.character(c(...))
  relative <- if (length(parts)) do.call(file.path, as.list(parts)) else ""
  roots <- .dsvert_test_source_roots()
  candidates <- if (length(roots)) file.path(roots, relative) else character()

  if (!isTRUE(source_only)) {
    installed_parts <- if (length(parts) && identical(parts[[1L]], "inst")) {
      parts[-1L]
    } else {
      parts
    }
    installed <- if (length(installed_parts)) {
      do.call(system.file, c(
        as.list(installed_parts), list(package = "dsVert")))
    } else {
      system.file(package = "dsVert")
    }
    candidates <- c(candidates, installed)
  }

  candidates <- unique(candidates[nzchar(candidates) & file.exists(candidates)])
  if (!length(candidates)) {
    kind <- if (isTRUE(source_only)) "source-only test artifact" else {
      "package test artifact"
    }
    testthat::skip(paste0(kind, " is unavailable: ", relative))
  }
  normalizePath(candidates[[1L]], mustWork = TRUE)
}

.dsvert_test_source_root <- function() {
  roots <- .dsvert_test_source_roots()
  if (!length(roots)) {
    testthat::skip("the dsVert source tree is unavailable for this static audit")
  }
  roots[[1L]]
}
