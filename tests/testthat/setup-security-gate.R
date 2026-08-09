# Historical unit tests still exercise retained implementation internals while
# their public methods are migrated. Test-only namespace replacement keeps
# those regression tests available without shipping a production bypass.
.dsvert_test_replace_binding <- function(name, value) {
  namespace <- asNamespace("dsVert")
  was_locked <- bindingIsLocked(name, namespace)
  if (was_locked) unlockBinding(name, namespace)
  assign(name, value, envir = namespace)
  if (was_locked) lockBinding(name, namespace)
  invisible(value)
}

.dsvert_test_disclosure_safe_methods <-
  dsVert:::.dsvert_disclosure_safe_remote_methods
.dsvert_test_all_remote_methods <- names(
  dsVert:::.dsvert_remote_function_registry(refresh = TRUE))
.dsvert_test_production_gate <- dsVert:::.dsvert_enforce_release_mode
.dsvert_test_compatibility_gate <- function(entry = NULL) {
  dsVert:::.dsvert_ensure_service_state()
  invisible(TRUE)
}

.dsvert_test_set_remote_gate <- function(
    profile = c("compatibility_tests", "disclosure_safe")) {
  profile <- match.arg(profile)
  value <- if (identical(profile, "disclosure_safe")) {
    .dsvert_test_disclosure_safe_methods
  } else {
    .dsvert_test_all_remote_methods
  }
  .dsvert_test_replace_binding(
    ".dsvert_disclosure_safe_remote_methods", value)
  .dsvert_test_replace_binding(
    ".dsvert_enforce_release_mode",
    if (identical(profile, "disclosure_safe")) {
      .dsvert_test_production_gate
    } else {
      .dsvert_test_compatibility_gate
    })
}

# Tests emulate multiple independently keyed peers inside one process. The
# installed package implementation is the constant FALSE; only this test
# process replaces it.
.dsvert_test_replace_binding(
  ".dsvert_identity_test_mode", function() TRUE)
.dsvert_test_set_remote_gate("compatibility_tests")
