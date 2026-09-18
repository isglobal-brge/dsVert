# Synthetic diagnostic only: sample function stacks, never payloads or values.
text <- readLines("inst/cross-grid-v2/validate_dslite.R")
start <- which(text == '  cat("DSLITE_PUBLIC_ADMISSION_COMPLETE\\n")')
stopifnot(length(start) == 1L)
text <- append(text, c(
  '  for (peer in peers) peer$worker$run(function() {',
  '    assign(".grid_relay_profile", tempfile(), .GlobalEnv)',
  '    trace(".exact_gc_exchange_impl", where=asNamespace("dsVert"), print=FALSE,',
  '      tracer=quote(Rprof(get(".grid_relay_profile", .GlobalEnv), interval=0.005, append=TRUE)),',
  '      exit=quote(Rprof(NULL)))',
  '    TRUE',
  '  })'), after=start)
finish <- which(text == '  cat("DSLITE_ORACLE_BITWISE_EQUAL\\n")')
stopifnot(length(finish) == 1L)
text <- append(text, c(
  '  for (peer in peers) print(peer$worker$run(function() {',
  '    path <- get(".grid_relay_profile", .GlobalEnv)',
  '    on.exit(unlink(path))',
  '    lines <- readLines(path)',
  '    writeLines(lines[seq_along(lines) == 1L | !grepl("^sample.interval=", lines)], path)',
  '    head(summaryRprof(path)$by.self, 15L)',
  '  }))'), after=finish)
eval(parse(text=text), envir=.GlobalEnv)
