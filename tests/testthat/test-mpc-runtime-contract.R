.runtime_contract_source_dir <- function() {
  candidates <- file.path(
    .dsvert_test_source_roots(), "inst", "dsvert-mpc")
  candidates <- candidates[file.exists(file.path(candidates, "main.go"))]
  if (!length(candidates)) return(NA_character_)
  normalizePath(candidates[[1L]], mustWork = TRUE)
}

test_that("mere executable presence and an old version command are rejected", {
  skip_on_os("windows")
  fake <- tempfile("dsvert-mpc-old-")
  writeLines(c(
    "#!/bin/sh",
    "if [ \"$1\" = \"version\" ]; then",
    "  printf '{\"version\":\"1.0.0\"}\\n'",
    "  exit 0",
    "fi",
    "printf '{\"error\":\"Unknown command\"}\\n'",
    "exit 1"), fake)
  Sys.chmod(fake, mode = "0700")
  on.exit(unlink(fake, force = TRUE), add = TRUE)
  withr::local_options(dsvert.mpc_binary = fake)

  expect_true(file.exists(fake))
  expect_false(mpcAvailable())
  expect_error(mpcVersion(), "Incompatible dsvert-mpc runtime")
  expect_error(
    .callMpcTool("version", list()),
    "Incompatible dsvert-mpc runtime")
})

test_that("an explicit missing runtime override never silently falls back", {
  missing <- tempfile("dsvert-mpc-does-not-exist-")
  withr::local_options(dsvert.mpc_binary = missing)
  expect_error(.findMpcBinary(), "not a regular file")
  expect_false(mpcAvailable())
})

test_that("runtime discovery never repairs unsafe executable permissions", {
  skip_on_os("windows")
  binary <- tempfile("dsvert-mpc-not-executable-")
  writeBin(charToRaw("not executable"), binary)
  Sys.chmod(binary, mode = "0600")
  on.exit(unlink(binary, force = TRUE), add = TRUE)
  withr::local_options(dsvert.mpc_binary = binary)

  expect_error(.findMpcBinary(), "not executable")
  expect_true(file.access(binary, mode = 1L) != 0L)
})

test_that("old-API, malformed or incomplete manifests fail closed", {
  old <- list(
    schema_version = 1L,
    protocol_version = "dsvert-mpc-runtime-v1",
    runtime_version = "1.1.0",
    api_version = "1.1.0",
    capabilities = list())
  expect_error(
    .dsvert_mpc_validate_runtime_manifest(old),
    "unsupported manifest schema or API version")
  expect_error(
    .dsvert_mpc_validate_runtime_manifest("not-a-manifest"),
    "unsupported manifest schema or API version")

  testthat::local_mocked_bindings(
    .callMpcTool = function(...) old,
    # A preceding exact-GC test may already have cached the packaged runtime
    # identity.  This test exercises malformed-manifest handling, so bypass
    # that valid cache explicitly instead of depending on file order.
    .dsvert_mpc_cached_manifest = function(...) NULL,
    .package = "dsVert")
  expect_false(mpcAvailable())
})

test_that("a validated manifest is cached only for one executable identity", {
  binary <- tempfile("dsvert-mpc-manifest-cache-")
  writeBin(charToRaw("runtime-v1"), binary)
  on.exit(unlink(binary, force = TRUE), add = TRUE)
  cache_key <- normalizePath(binary, mustWork = TRUE)
  on.exit(if (exists(cache_key, envir = .dsvert_mpc_compatibility_cache,
                     inherits = FALSE)) {
    rm(list = cache_key, envir = .dsvert_mpc_compatibility_cache)
  }, add = TRUE)
  probes <- 0L
  sentinel <- list(runtime_version = "sentinel")
  testthat::local_mocked_bindings(
    .findMpcBinary = function() binary,
    .callMpcTool = function(command, input_data) {
      expect_identical(command, "runtime-capabilities")
      expect_identical(input_data, list())
      probes <<- probes + 1L
      sentinel
    },
    .dsvert_mpc_validate_runtime_manifest = function(value) value,
    .package = "dsVert")

  expect_identical(.dsvert_mpc_runtime_manifest(), sentinel)
  expect_identical(.dsvert_mpc_runtime_manifest(), sentinel)
  expect_identical(
    .dsvert_mpc_require_compatible_binary(binary), sentinel)
  expect_identical(probes, 1L)

  connection <- file(binary, open = "ab")
  writeBin(as.raw(0L), connection)
  close(connection)
  expect_identical(.dsvert_mpc_runtime_manifest(), sentinel)
  expect_identical(probes, 2L)
})

test_that("packaged artifacts are checksum verified with drift invalidation", {
  root <- withr::local_tempdir(pattern = "dsvert-packaged-runtime-")
  relative_path <- "linux-amd64/dsvert-mpc"
  binary <- file.path(root, relative_path)
  dir.create(dirname(binary), recursive = TRUE)
  writeBin(charToRaw("known packaged runtime"), binary)

  hashes <- stats::setNames(
    rep(paste(rep("0", 64L), collapse = ""),
        length(.DSVERT_MPC_PACKAGED_PATHS)),
    .DSVERT_MPC_PACKAGED_PATHS)
  hashes[[relative_path]] <- digest::digest(
    file = binary, algo = "sha256", serialize = FALSE)
  writeLines(paste(hashes, names(hashes), sep = "  "),
             file.path(root, "SHA256SUMS"), useBytes = TRUE)

  expect_true(.dsvert_mpc_verify_packaged_binary(
    binary, root, relative_path))
  cache_key <- normalizePath(binary, mustWork = TRUE)
  expect_true(exists(cache_key, envir = .dsvert_mpc_integrity_cache,
                     inherits = FALSE))
  cached <- get(cache_key, envir = .dsvert_mpc_integrity_cache,
                inherits = FALSE)
  expect_true(.dsvert_mpc_verify_packaged_binary(
    binary, root, relative_path))
  expect_identical(
    get(cache_key, envir = .dsvert_mpc_integrity_cache, inherits = FALSE),
    cached)

  connection <- file(binary, open = "ab")
  writeBin(as.raw(0L), connection)
  close(connection)
  expect_error(
    .dsvert_mpc_verify_packaged_binary(binary, root, relative_path),
    "SHA-256 mismatch")
  expect_false(exists(cache_key, envir = .dsvert_mpc_integrity_cache,
                      inherits = FALSE))
})

test_that("missing or malformed packaged checksum manifests fail closed", {
  root <- withr::local_tempdir(pattern = "dsvert-bad-checksums-")
  expect_error(
    .dsvert_mpc_packaged_checksums(root),
    "missing regular SHA256SUMS")
  writeLines("not a checksum", file.path(root, "SHA256SUMS"))
  expect_error(
    .dsvert_mpc_packaged_checksums(root),
    "malformed SHA256SUMS")
})

test_that("the current compiled runtime satisfies a deterministic contract", {
  go <- Sys.which("go")
  skip_if(!nzchar(go), "Go toolchain is unavailable")
  source_dir <- .runtime_contract_source_dir()
  skip_if(is.na(source_dir), "Go runtime source tree is unavailable")

  suffix <- if (.Platform$OS.type == "windows") ".exe" else ""
  binary <- tempfile("dsvert-mpc-contract-", fileext = suffix)
  on.exit(unlink(binary, force = TRUE), add = TRUE)
  build_output <- withr::with_dir(source_dir, system2(
    go,
    c("build", "-trimpath", "-buildvcs=false", "-o", binary, "."),
    stdout = TRUE, stderr = TRUE))
  status <- attr(build_output, "status")
  if (!is.null(status) && status != 0L) {
    fail(paste(c("Go runtime build failed", build_output), collapse = "\n"))
  }
  if (.Platform$OS.type != "windows") Sys.chmod(binary, mode = "0700")
  withr::local_options(dsvert.mpc_binary = binary)

  first <- system2(binary, "runtime-capabilities", stdout = TRUE,
                   stderr = TRUE)
  second <- system2(binary, "runtime-capabilities", stdout = TRUE,
                    stderr = TRUE)
  expect_identical(first, second)
  manifest <- .dsvert_mpc_runtime_manifest()
  old_manifest <- manifest
  old_manifest$api_version <- "1.1.0"
  old_manifest$capabilities$joint_dp_frequency_backend_selection <- NULL
  expect_error(
    .dsvert_mpc_validate_runtime_manifest(old_manifest),
    "unsupported manifest schema or API version")
  expect_identical(manifest$runtime_version, "1.1.0")
  expect_identical(manifest$api_version, "1.2.0")
  expect_true(manifest$capabilities$dp_noise_int64$available)
  expect_true(manifest$capabilities$exact_gc$available)
  frequency <- manifest$capabilities$joint_dp_frequency_backend_selection
  expect_identical(frequency$available, TRUE)
  expect_identical(
    frequency$capability_id,
    "joint_dp_frequency_backend_selection_v1")
  expect_identical(
    frequency$protocol_version,
    "dsvert-joint-dp-frequency-backend-selection-v1")
  expect_identical(
    as.character(frequency$commands),
    "joint-dp-frequency-backend-select-v1")
  expect_identical(
    as.character(frequency$operations),
    "public-data-free-certified-frequency-backend-selection-v1")
  expect_identical(mpcVersion(), "1.1.0")
  expect_true(mpcAvailable())
})

test_that("release Makefile pins reproducible pure-Go flags", {
  source_dir <- .runtime_contract_source_dir()
  skip_if(is.na(source_dir), "Go runtime source tree is unavailable")
  package_description <- read.dcf(.dsvert_test_package_file(
    "DESCRIPTION", source_only = TRUE), fields = "Version")[[1L]]
  expect_identical(package_description, .DSVERT_MPC_RUNTIME_VERSION)
  makefile <- paste(readLines(file.path(source_dir, "Makefile"), warn = FALSE),
                    collapse = "\n")
  expect_match(makefile, "VERSION \\?= 1\\.1\\.0")
  expect_match(
    makefile, "override GO_VERSION_REQUIRED := go1\\.25\\.7")
  expect_match(makefile, "deps: check-go-version", fixed = TRUE)
  expect_match(makefile, "go env GOVERSION", fixed = TRUE)
  expect_match(makefile, "CGO_ENABLED=0", fixed = TRUE)
  expect_match(makefile, "-trimpath", fixed = TRUE)
  expect_match(makefile, "-buildvcs=false", fixed = TRUE)
  expect_match(makefile, "-buildid=", fixed = TRUE)
  expect_match(makefile, "main.runtimeVersion=$(VERSION)", fixed = TRUE)
  expect_match(makefile, "checksums:", fixed = TRUE)
  expect_match(makefile, "SHA256SUMS.tmp", fixed = TRUE)
  expect_match(makefile, "test -x", fixed = TRUE)
  expect_false(grepl("go mod tidy", makefile, fixed = TRUE))

  make <- Sys.which("make")
  if (nzchar(make) && .Platform$OS.type != "windows") {
    fake_bin <- withr::local_tempdir(pattern = "dsvert-fake-go-")
    fake_go <- file.path(fake_bin, "go")
    writeLines(c("#!/bin/sh", "printf 'go0.0.0\\n'"), fake_go)
    Sys.chmod(fake_go, mode = "0700")
    rejected <- withr::with_envvar(c(
      PATH = paste(fake_bin, Sys.getenv("PATH"),
                   sep = .Platform$path.sep)), suppressWarnings(
        withr::with_dir(source_dir, system2(
          make, "check-go-version", stdout = TRUE, stderr = TRUE))))
    expect_true((attr(rejected, "status") %||% 0L) != 0L)
    expect_match(paste(rejected, collapse = "\n"), "requires exactly")
  }
})
