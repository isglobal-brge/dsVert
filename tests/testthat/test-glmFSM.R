# Tests for GLM Phase-Ordering FSM Firewall

# =============================================================================
# FSM initialization
# =============================================================================

test_that("glmFSMInitDS initializes correctly", {
  sid <- "test-session-001"
  glmFSMInitDS(sid, 2, "secure_agg")
  ss <- dsVert:::.S(sid)
  expect_equal(ss$fsm_session_id, sid)
  expect_equal(ss$fsm_n_nonlabel, 2L)
  expect_equal(ss$fsm_mode, "secure_agg")
  expect_equal(ss$fsm_state, "EXPECT_ETAS")
  expect_equal(ss$fsm_iteration, 0L)
  expect_equal(length(ss$fsm_etas_received), 0)
})

test_that("glmFSMInitDS rejects invalid inputs", {
  expect_error(glmFSMInitDS("", 2, "secure_agg"), "non-empty string")
  expect_error(glmFSMInitDS("s", 0, "secure_agg"), "n_nonlabel must be >= 1")
  expect_error(glmFSMInitDS("s", 2, "invalid"), "mode must be")
})

# =============================================================================
# FSM rejects out-of-order calls
# =============================================================================

test_that("glmFSMCheckDS rejects out-of-order actions", {
  glmFSMInitDS("test-session-order", 2, "secure_agg")

  # Cannot distribute_mwv from EXPECT_ETAS
  expect_error(
    glmFSMCheckDS("test-session-order", "distribute_mwv"),
    "expected COORD_DONE"
  )

  # Cannot block_complete from EXPECT_ETAS
  expect_error(
    glmFSMCheckDS("test-session-order", "block_complete"),
    "expected BLOCKS_ACTIVE"
  )
})

# =============================================================================
# FSM rejects iteration replay
# =============================================================================

test_that("glmFSMCheckDS rejects iteration replay", {
  glmFSMInitDS("test-session-replay", 2, "secure_agg")

  # First coordinator step (iter 1) from EXPECT_ETAS is allowed
  glmFSMCheckDS("test-session-replay", "coordinator_step", iteration = 1L)
  expect_equal(dsVert:::.S("test-session-replay")$fsm_state, "COORD_DONE")

  # Advance to EXPECT_ETAS for next iteration
  glmFSMCheckDS("test-session-replay", "distribute_mwv")
  glmFSMCheckDS("test-session-replay", "block_complete")
  glmFSMCheckDS("test-session-replay", "block_complete")

  # Now at EXPECT_ETAS, receive etas
  glmFSMCheckDS("test-session-replay", "receive_eta", server_name = "s1")
  glmFSMCheckDS("test-session-replay", "receive_eta", server_name = "s2")

  # Try iter 1 again — should reject (anti-replay)
  expect_error(
    glmFSMCheckDS("test-session-replay", "coordinator_step", iteration = 1L),
    "anti-replay"
  )

  # But iter 2 should work
  glmFSMCheckDS("test-session-replay", "coordinator_step", iteration = 2L)
  expect_equal(dsVert:::.S("test-session-replay")$fsm_iteration, 2L)
})

# =============================================================================
# FSM rejects wrong session_id
# =============================================================================

test_that("glmFSMCheckDS rejects wrong session_id", {
  glmFSMInitDS("correct-session", 2, "secure_agg")

  expect_error(
    glmFSMCheckDS("wrong-session", "coordinator_step", iteration = 1L),
    "not initialized"
  )
})

# =============================================================================
# FSM accepts valid full iteration cycle
# =============================================================================

test_that("glmFSMCheckDS accepts valid full iteration cycle", {
  sid <- "test-session-full"
  glmFSMInitDS(sid, 2, "secure_agg")

  # Iter 1: first iteration, no etas to receive
  glmFSMCheckDS(sid, "coordinator_step", iteration = 1L)
  expect_equal(dsVert:::.S(sid)$fsm_state, "COORD_DONE")

  glmFSMCheckDS(sid, "distribute_mwv")
  expect_equal(dsVert:::.S(sid)$fsm_state, "BLOCKS_ACTIVE")

  glmFSMCheckDS(sid, "block_complete")
  expect_equal(dsVert:::.S(sid)$fsm_state, "BLOCKS_ACTIVE")  # still waiting for 2nd

  glmFSMCheckDS(sid, "block_complete")
  expect_equal(dsVert:::.S(sid)$fsm_state, "EXPECT_ETAS")

  # Iter 2: receive etas first
  glmFSMCheckDS(sid, "receive_eta", server_name = "serverB")
  expect_equal(dsVert:::.S(sid)$fsm_state, "EXPECT_ETAS")  # still waiting

  glmFSMCheckDS(sid, "receive_eta", server_name = "serverC")
  expect_equal(dsVert:::.S(sid)$fsm_state, "COORD_READY")

  glmFSMCheckDS(sid, "coordinator_step", iteration = 2L)
  expect_equal(dsVert:::.S(sid)$fsm_state, "COORD_DONE")
  expect_equal(dsVert:::.S(sid)$fsm_iteration, 2L)
})

# =============================================================================
# FSM rejects duplicate eta
# =============================================================================

test_that("glmFSMCheckDS rejects duplicate eta from same server", {
  glmFSMInitDS("test-session-dup", 2, "secure_agg")

  # Advance to a state where we expect etas (iter 1 with etas)
  glmFSMCheckDS("test-session-dup", "coordinator_step", iteration = 1L)
  glmFSMCheckDS("test-session-dup", "distribute_mwv")
  glmFSMCheckDS("test-session-dup", "block_complete")
  glmFSMCheckDS("test-session-dup", "block_complete")
  # Back to EXPECT_ETAS

  glmFSMCheckDS("test-session-dup", "receive_eta", server_name = "s1")
  expect_error(
    glmFSMCheckDS("test-session-dup", "receive_eta", server_name = "s1"),
    "duplicate eta"
  )
})

# =============================================================================
# FSM transitions to TERMINATED after deviance
# =============================================================================

test_that("glmFSMCheckDS transitions to TERMINATED after deviance", {
  glmFSMInitDS("test-session-term", 1, "secure_agg")

  # Quick cycle
  glmFSMCheckDS("test-session-term", "coordinator_step", iteration = 1L)
  glmFSMCheckDS("test-session-term", "distribute_mwv")
  glmFSMCheckDS("test-session-term", "block_complete")
  # Back to EXPECT_ETAS

  glmFSMCheckDS("test-session-term", "deviance")
  expect_equal(dsVert:::.S("test-session-term")$fsm_state, "TERMINATED")

  # Further calls should be rejected
  expect_error(
    glmFSMCheckDS("test-session-term", "coordinator_step", iteration = 2L),
    "already terminated"
  )
})

# =============================================================================
# FSM uninitialized check
# =============================================================================

test_that("glmFSMCheckDS rejects calls before init", {
  # Use a session_id that has never been initialized.
  # .S() creates a fresh empty environment, so fsm_session_id will be NULL.
  expect_error(
    glmFSMCheckDS("never-initialized-xyz", "coordinator_step", iteration = 1L),
    "not initialized"
  )
})
