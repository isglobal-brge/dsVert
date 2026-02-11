#' @title MHE Utility Functions
#' @description Internal functions for calling the mhe-tool binary.
#' @keywords internal

#' Find the mhe-tool binary
#'
#' @return Path to the mhe-tool binary
#' @keywords internal
.findMheTool <- function() {
  # Determine platform-specific binary name
  os <- .Platform$OS.type
  if (os == "windows") {
    binary_name <- "mhe-tool.exe"
  } else {
    binary_name <- "mhe-tool"
  }

  # Check architecture for macOS (arm64 vs amd64)
  arch <- Sys.info()["machine"]
  if (Sys.info()["sysname"] == "Darwin") {
    if (arch == "arm64") {
      subdir <- "darwin-arm64"
    } else {
      subdir <- "darwin-amd64"
    }
  } else if (os == "windows") {
    subdir <- "windows-amd64"
  } else {
    subdir <- "linux-amd64"
  }

  bin_path <- ""

  # Look for binary in package installation
  tryCatch({
    bin_path <- system.file("bin", subdir, binary_name, package = "dsVert")
  }, error = function(e) {})

  # Fallback: look in development locations
  if (bin_path == "" || !file.exists(bin_path)) {
    # Try relative to this file (for development)
    dev_paths <- c(
      file.path(getwd(), "inst", "bin", subdir, binary_name),
      file.path(dirname(getwd()), "dsVert", "inst", "bin", subdir, binary_name)
    )

    for (dp in dev_paths) {
      if (file.exists(dp)) {
        bin_path <- dp
        break
      }
    }
  }

  # Additional fallback: check environment variable
  if (bin_path == "" || !file.exists(bin_path)) {
    env_path <- Sys.getenv("DSVERT_MHE_TOOL")
    if (env_path != "" && file.exists(env_path)) {
      bin_path <- env_path
    }
  }

  if (bin_path == "" || !file.exists(bin_path)) {
    stop(
      "mhe-tool binary not found. ",
      "The MHE functionality requires the compiled Go binary.\n",
      "Expected location: inst/bin/", subdir, "/", binary_name, "\n",
      "Or set DSVERT_MHE_TOOL environment variable to the binary path.",
      call. = FALSE
    )
  }

  # Ensure binary is executable (Unix only)
  if (os != "windows") {
    Sys.chmod(bin_path, mode = "0755")
  }

  return(bin_path)
}

#' Call mhe-tool with JSON input
#'
#' @param command The mhe-tool subcommand to run
#' @param input_data List that will be converted to JSON input
#' @return Parsed JSON output from mhe-tool
#' @keywords internal
.callMheTool <- function(command, input_data) {
  bin_path <- .findMheTool()

  # Convert input to JSON
  input_json <- jsonlite::toJSON(input_data, auto_unbox = TRUE)

  # Create temporary file for input
  input_file <- tempfile(fileext = ".json")

  on.exit({
    if (file.exists(input_file)) unlink(input_file)
  })

  # Write input
  writeLines(as.character(input_json), input_file)

  # Call mhe-tool and capture stdout
  result <- system2(
    command = bin_path,
    args = command,
    stdin = input_file,
    stdout = TRUE,
    stderr = TRUE
  )

  # Check for errors
  status <- attr(result, "status")
  if (!is.null(status) && status != 0) {
    stop("mhe-tool failed with status ", status, ": ",
         paste(result, collapse = "\n"), call. = FALSE)
  }

  # Parse output
  output_json <- paste(result, collapse = "\n")
  output <- jsonlite::fromJSON(output_json)

  # Check for error in output
  if (!is.null(output$error) && nchar(output$error) > 0) {
    stop("mhe-tool error: ", output$error, call. = FALSE)
  }

  return(output)
}

#' Check if MHE is available
#'
#' @return TRUE if mhe-tool binary is available, FALSE otherwise
#' @export
mheAvailable <- function() {
  tryCatch({
    bin_path <- .findMheTool()
    file.exists(bin_path)
  }, error = function(e) {
    FALSE
  })
}

#' Get MHE tool version
#'
#' @return Version string of mhe-tool
#' @export
mheVersion <- function() {
  bin_path <- .findMheTool()

  # Capture stdout directly
  result <- system2(
    command = bin_path,
    args = "version",
    stdout = TRUE,
    stderr = TRUE
  )

  output <- jsonlite::fromJSON(paste(result, collapse = "\n"))
  return(output$version)
}
