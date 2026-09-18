# Synthetic harness variant using the existing connector's synchronous jobs.
# All expressions still pass through DSI and the strict DSLite allowlist.
grid_sync_connector <- function() {
  methods::setMethod("dsIsAsync", "DSVertE2EProcessConnection", function(conn) {
    list(session = NULL, aggregate = FALSE, assignTable = FALSE,
      assignExpr = TRUE, assignResource = FALSE)
  })
}
text <- readLines("inst/cross-grid-v2/validate_dslite.R")
position <- which(text == 'source(file.path(client_dir, "inst/validation/v1.2.0/worked_example_custodian.R"))')
stopifnot(length(position) == 1L)
text <- append(text, "grid_sync_connector()", after = position)
eval(parse(text = text), envir = .GlobalEnv)
