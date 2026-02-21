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

# Dedicated environment for FSM state (separate from .mhe_storage)
.glm_fsm <- new.env(parent = emptyenv())

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

  .glm_fsm$session_id <- session_id
  .glm_fsm$n_nonlabel <- as.integer(n_nonlabel)
  .glm_fsm$mode <- mode
  .glm_fsm$state <- "EXPECT_ETAS"
  .glm_fsm$iteration <- 0L
  .glm_fsm$etas_received <- character(0)
  .glm_fsm$blocks_completed <- 0L

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

  if (is.null(.glm_fsm$session_id))
    stop("FSM not initialized. Call glmFSMInitDS first.", call. = FALSE)
  if (session_id != .glm_fsm$session_id)
    stop("Session ID mismatch: expected '", .glm_fsm$session_id,
         "', got '", session_id, "'", call. = FALSE)

  state <- .glm_fsm$state

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
      if (server_name %in% .glm_fsm$etas_received)
        stop("FSM: duplicate eta from '", server_name, "'", call. = FALSE)

      .glm_fsm$etas_received <- c(.glm_fsm$etas_received, server_name)

      # Transition to COORD_READY when all etas received
      if (length(.glm_fsm$etas_received) == .glm_fsm$n_nonlabel) {
        .glm_fsm$state <- "COORD_READY"
      }
    },

    "coordinator_step" = {
      # On first iteration (iteration=0 stored), EXPECT_ETAS is OK even
      # without receiving etas (first iteration has no etas to receive)
      if (state == "EXPECT_ETAS" && .glm_fsm$iteration == 0L &&
          length(.glm_fsm$etas_received) == 0) {
        # Allow first coordinator step without etas
      } else if (state != "COORD_READY") {
        stop("FSM: cannot coordinator_step in state '", state,
             "' (expected COORD_READY or first iteration)", call. = FALSE)
      }

      if (is.null(iteration) || !is.numeric(iteration))
        stop("FSM: coordinator_step requires numeric iteration", call. = FALSE)

      # Anti-replay: iteration must be strictly increasing
      if (as.integer(iteration) <= .glm_fsm$iteration)
        stop("FSM: iteration ", iteration, " <= last iteration ",
             .glm_fsm$iteration, " (anti-replay violation)", call. = FALSE)

      .glm_fsm$iteration <- as.integer(iteration)
      .glm_fsm$etas_received <- character(0)  # reset for next round
      .glm_fsm$state <- "COORD_DONE"
    },

    "distribute_mwv" = {
      if (state != "COORD_DONE")
        stop("FSM: cannot distribute_mwv in state '", state,
             "' (expected COORD_DONE)", call. = FALSE)
      .glm_fsm$blocks_completed <- 0L
      .glm_fsm$state <- "BLOCKS_ACTIVE"
    },

    "block_complete" = {
      if (state != "BLOCKS_ACTIVE")
        stop("FSM: cannot block_complete in state '", state,
             "' (expected BLOCKS_ACTIVE)", call. = FALSE)

      .glm_fsm$blocks_completed <- .glm_fsm$blocks_completed + 1L

      # Transition when all blocks done
      if (.glm_fsm$blocks_completed == .glm_fsm$n_nonlabel) {
        .glm_fsm$state <- "EXPECT_ETAS"
      }
    },

    "deviance" = {
      # Allow deviance from EXPECT_ETAS or COORD_READY (after final iteration)
      if (!state %in% c("EXPECT_ETAS", "COORD_READY"))
        stop("FSM: cannot compute deviance in state '", state, "'",
             call. = FALSE)
      .glm_fsm$state <- "TERMINATED"
    },

    "cleanup" = {
      .glm_fsm$state <- "TERMINATED"
      .glm_fsm$session_id <- NULL
    },

    stop("FSM: unknown action '", action, "'", call. = FALSE)
  )

  invisible(TRUE)
}
