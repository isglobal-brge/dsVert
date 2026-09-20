# This file is part of the standard testthat testing infrastructure.
# Test-only security overrides live under tests/testthat/setup-security-gate.R
# and are never installed with the package.
# testthat imports processx before the fork-based concurrency regressions run.
# Preserve processx's preceding SIGCHLD handler so base parallel can reap its
# children cleanly at interpreter shutdown on Unix.
if (.Platform$OS.type != "windows") {
  Sys.setenv(PROCESSX_NOTIFY_OLD_SIGCHLD = "true")
}
library(testthat)
library(dsVert)

# Each installed-check process owns its state; never inherit a service identity.
.dsvert_test_state_dir <- tempfile("dsvert-check-state-")
stopifnot(dir.create(.dsvert_test_state_dir, mode = "0700"))
Sys.setenv(DSVERT_STATE_DIR = .dsvert_test_state_dir)
testthat::set_max_fails(Inf)

test_check("dsVert")
