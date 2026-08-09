\name{dsvertDPSurvivalDS}
\alias{dsvertDPSurvivalDS}
\title{Differentially Private Fixed-Grid Survival Histogram}
\usage{
dsvertDPSurvivalDS(data_name, analysis_id)
}
\arguments{
  \item{data_name}{Name of a registered protected data frame.}
  \item{analysis_id}{Name of a custodian-owned survival specification.}
}
\value{
A fixed-shape, noisy histogram and its sticky-noise, accuracy, adjacency,
and composition metadata. No exact cohort size, event count, risk-set count,
or patient identifier is returned.
}
\description{
Makes one accountant-controlled vector release for Kaplan--Meier,
Nelson--Aalen, and competing-risks cumulative-incidence post-processing.
The public time grid, bounds, outcome domain, censoring level, and optional
entry-time variable are fixed by the data custodian.
}
\details{
The custodian configures \code{dsvert.dp.survival_specs} as a uniquely named
list. Each entry has exactly \code{version}, \code{dataset}, \code{time},
\code{event}, \code{censor}, \code{time_grid}, and \code{entry}; the latter is
\code{NULL} when delayed entry is absent. The last grid endpoint must equal the
configured upper numeric bound, and entry and exit variables share bounds.

Under add/remove adjacency, one unit changes at most one exit-or-quality cell
without delayed entry (L1 sensitivity one), or one entry and one exit cell with
delayed entry (L1 sensitivity two). Under replace-one fixed-cohort adjacency
the corresponding vector sensitivities are two and four. Repeated patient rows use the first event,
or the latest censoring record when no event exists, with deterministic public
tie-breaking. Invalid protected values enter a noisy quality bin instead of
changing the transcript. Missing or malformed patient identifiers and any
capacity violation fail the same custodian-owned admission contract before a
release or ledger charge.

The histogram grid and vector length do not depend on protected values. The
same canonical query, snapshot, key epoch, and policy replays the same sticky
payload without consuming another allocation.
}
\keyword{internal}
