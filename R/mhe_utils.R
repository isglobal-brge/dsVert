#' @title MHE Utility Functions
#' @description Internal functions for calling the mhe-tool binary.
#' @keywords internal

#' Convert base64url to standard base64
#' @description Converts base64url encoding (URL-safe) to standard base64.
#'   This is needed because R's parser on Opal/Rock has issues with "/" and "+"
#'   characters in long strings passed as function parameters.
#' @param x Character string in base64url encoding
#' @return Character string in standard base64 encoding
#' @keywords internal
.base64url_to_base64 <- function(x) {
  # Replace URL-safe characters with standard base64
  x <- gsub("-", "+", x, fixed = TRUE)
  x <- gsub("_", "/", x, fixed = TRUE)

  # Add padding if needed
  padding_needed <- (4 - nchar(x) %% 4) %% 4
  if (padding_needed > 0) {
    x <- paste0(x, paste(rep("=", padding_needed), collapse = ""))
  }

  x
}

#' Convert standard base64 to base64url
#' @description Converts standard base64 to base64url encoding (URL-safe).
#' @param x Character string in standard base64 encoding
#' @return Character string in base64url encoding
#' @export
base64_to_base64url <- function(x) {
  # Replace standard base64 characters with URL-safe ones
  x <- gsub("+", "-", x, fixed = TRUE)
  x <- gsub("/", "_", x, fixed = TRUE)
  # Remove padding
  x <- gsub("=", "", x, fixed = TRUE)
  x
}

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

  # Look for binary in package installation (platform-specific)
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

  # Create temporary files for input and output
  input_file <- tempfile(fileext = ".json")
  output_file <- tempfile(fileext = ".json")
  stderr_file <- tempfile(fileext = ".txt")

  on.exit({
    if (file.exists(input_file)) unlink(input_file)
    if (file.exists(output_file)) unlink(output_file)
    if (file.exists(stderr_file)) unlink(stderr_file)
  })

  # Write input JSON to file (avoids large string in R memory)
  jsonlite::write_json(input_data, input_file, auto_unbox = TRUE)

  # Call mhe-tool with file-based I/O (avoids C stack overflow on large output)
  status <- system2(
    command = bin_path,
    args = command,
    stdin = input_file,
    stdout = output_file,
    stderr = stderr_file
  )

  # Check for errors
  if (status != 0) {
    err_msg <- if (file.exists(output_file)) readLines(output_file, warn = FALSE) else ""
    stderr_msg <- if (file.exists(stderr_file)) readLines(stderr_file, warn = FALSE) else ""
    stop("mhe-tool failed with status ", status, ": ",
         paste(c(err_msg, stderr_msg), collapse = "\n"), call. = FALSE)
  }

  # Parse output from file (avoids loading huge string into R)
  output <- jsonlite::read_json(output_file, simplifyVector = TRUE)

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
