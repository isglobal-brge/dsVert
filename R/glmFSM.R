#' @title GLM Phase-Ordering FSM Firewall
#' @description Server-side finite state machine that prevents protocol abuse
#'   in the GLM secure aggregation protocol. Each server tracks its own
#'   session state and rejects out-of-order or replayed operations.
#'
#' @details
#' The FSM enforces the following phase ordering on the coordinator:
#' \preformatted{
#' INIT -> EXPECT_ETAS -> COORD_READY -> COORD_DONE ->
#'   BLOCKS_ACTIVE -> EXPECT_ETAS (next iter) -> ... -> TERMINATED
#' }
#'
#' Key enforcement rules:
#' \itemize{
#'   \item Coordinator MUST receive exactly \code{n_nonlabel} etas before stepping
#'   \item Iteration numbers MUST be strictly increasing (anti-replay)
#'   \item Session IDs must match on every call
#' }
#'
#' @name glm-fsm
NULL

# FSM state is now stored in session-scoped storage with fsm_ prefix
# (previously used a dedicated .glm_fsm environment)

# ============================================================================
# FSM Initialization
# ============================================================================

#' Initialize GLM session FSM
#'
#' Sets up the finite state machine for a new GLM session. Must be called
#' before any \code{glmFSMCheckDS} calls.
#'
#' @param session_id Character. UUID for this GLM session.
#' @param n_nonlabel Integer. Expected number of non-label servers.
#' @param mode Character. Privacy mode: \code{"secure_agg"}, \code{"transport"},
#'   or \code{"he_link"}. Default \code{"secure_agg"}.
#'
#' @return TRUE (invisible)
#' @export
glmFSMInitDS <- function(session_id, n_nonlabel, mode = "secure_agg") {
  if (!is.character(session_id) || nchar(session_id) == 0)
    stop("session_id must be a non-empty string", call. = FALSE)
  if (!is.numeric(n_nonlabel) || n_nonlabel < 1)
    stop("n_nonlabel must be >= 1", call. = FALSE)
  if (!mode %in% c("secure_agg", "transport", "he_link"))
    stop("mode must be 'secure_agg', 'transport', or 'he_link'", call. = FALSE)

  ss <- .S(session_id)
  ss$fsm_session_id <- session_id
  ss$fsm_n_nonlabel <- as.integer(n_nonlabel)
  ss$fsm_mode <- mode
  ss$fsm_state <- "EXPECT_ETAS"
  ss$fsm_iteration <- 0L
  ss$fsm_etas_received <- character(0)
  ss$fsm_blocks_completed <- 0L

  invisible(TRUE)
}

# ============================================================================
# FSM Check / Advance
# ============================================================================

#' Check and advance GLM session FSM state
#'
#' Validates that the requested action is permitted in the current state,
#' and advances the state machine if valid. Rejects out-of-order actions,
#' iteration replays, and session mismatches.
#'
#' @param session_id Character. Must match the initialized session.
#' @param action Character. One of:
#'   \describe{
#'     \item{\code{"receive_eta"}}{Coordinator: register eta from a non-label server}
#'     \item{\code{"coordinator_step"}}{Coordinator: perform IRLS step (requires all etas)}
#'     \item{\code{"distribute_mwv"}}{Coordinator: send (mu, w, v) blobs}
#'     \item{\code{"block_complete"}}{Non-label server: finished block solve}
#'     \item{\code{"deviance"}}{Final deviance computation}
#'     \item{\code{"cleanup"}}{Terminal cleanup}
#'   }
#' @param iteration Integer or NULL. Required for \code{"coordinator_step"}.
#' @param server_name Character or NULL. Required for \code{"receive_eta"}.
#'
#' @return TRUE if the action is allowed and state was advanced.
#' @export
glmFSMCheckDS <- function(session_id, action, iteration = NULL,
                           server_name = NULL) {
  # Session binding
  ss <- .S(session_id)

  if (is.null(ss$fsm_session_id))
    stop("FSM not initialized. Call glmFSMInitDS first.", call. = FALSE)
  if (session_id != ss$fsm_session_id)
    stop("Session ID mismatch: expected '", ss$fsm_session_id,
         "', got '", session_id, "'", call. = FALSE)

  state <- ss$fsm_state

  if (state == "TERMINATED") {
    stop("GLM session already terminated", call. = FALSE)
  }

  switch(action,
    "receive_eta" = {
      if (state != "EXPECT_ETAS")
        stop("FSM: cannot receive_eta in state '", state,
             "' (expected EXPECT_ETAS)", call. = FALSE)
      if (is.null(server_name) || !is.character(server_name))
        stop("FSM: receive_eta requires server_name", call. = FALSE)
      if (server_name %in% ss$fsm_etas_received)
        stop("FSM: duplicate eta from '", server_name, "'", call. = FALSE)

      ss$fsm_etas_received <- c(ss$fsm_etas_received, server_name)

      # Transition to COORD_READY when all etas received
      if (length(ss$fsm_etas_received) == ss$fsm_n_nonlabel) {
        ss$fsm_state <- "COORD_READY"
      }
    },

    "coordinator_step" = {
      # On first iteration (iteration=0 stored), EXPECT_ETAS is OK even
      # without receiving etas (first iteration has no etas to receive)
      if (state == "EXPECT_ETAS" && ss$fsm_iteration == 0L &&
          length(ss$fsm_etas_received) == 0) {
        # Allow first coordinator step without etas
      } else if (state != "COORD_READY") {
        stop("FSM: cannot coordinator_step in state '", state,
             "' (expected COORD_READY or first iteration)", call. = FALSE)
      }

      if (is.null(iteration) || !is.numeric(iteration))
        stop("FSM: coordinator_step requires numeric iteration", call. = FALSE)

      # Anti-replay: iteration must be strictly increasing
      if (as.integer(iteration) <= ss$fsm_iteration)
        stop("FSM: iteration ", iteration, " <= last iteration ",
             ss$fsm_iteration, " (anti-replay violation)", call. = FALSE)

      ss$fsm_iteration <- as.integer(iteration)
      ss$fsm_etas_received <- character(0)  # reset for next round
      ss$fsm_state <- "COORD_DONE"
    },

    "distribute_mwv" = {
      if (state != "COORD_DONE")
        stop("FSM: cannot distribute_mwv in state '", state,
             "' (expected COORD_DONE)", call. = FALSE)
      ss$fsm_blocks_completed <- 0L
      ss$fsm_state <- "BLOCKS_ACTIVE"
    },

    "block_complete" = {
      if (state != "BLOCKS_ACTIVE")
        stop("FSM: cannot block_complete in state '", state,
             "' (expected BLOCKS_ACTIVE)", call. = FALSE)

      ss$fsm_blocks_completed <- ss$fsm_blocks_completed + 1L

      # Transition when all blocks done
      if (ss$fsm_blocks_completed == ss$fsm_n_nonlabel) {
        ss$fsm_state <- "EXPECT_ETAS"
      }
    },

    "deviance" = {
      # Allow deviance from EXPECT_ETAS or COORD_READY (after final iteration)
      if (!state %in% c("EXPECT_ETAS", "COORD_READY"))
        stop("FSM: cannot compute deviance in state '", state, "'",
             call. = FALSE)
      ss$fsm_state <- "TERMINATED"
    },

    "cleanup" = {
      ss$fsm_state <- "TERMINATED"
      ss$fsm_session_id <- NULL
    },

    stop("FSM: unknown action '", action, "'", call. = FALSE)
  )

  invisible(TRUE)
}
