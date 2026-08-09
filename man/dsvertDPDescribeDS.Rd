\name{dsvertDPDescribeDS}
\alias{dsvertDPDescribeDS}
\title{Differentially Private Fixed-Grid Descriptive Release}
\usage{
dsvertDPDescribeDS(data_name, analysis_id)
}
\arguments{
  \item{data_name}{Name of a registered protected data frame.}
  \item{analysis_id}{Name of a custodian-owned describe specification.}
}
\value{
A fixed-shape vector of noisy integer sufficient statistics and histograms,
with a public certificate for quantization, sensitivity, epsilon allocation,
accuracy, composition, sticky-noise epoch, and adjacency. It contains no exact
count, observed extremum, adaptive bin, raw value, or unquantized sum.
}
\description{
Internal server release used by the package's unified disclosure-safe
descriptive interface. It performs one purpose-bound sticky ledger release for
all variables in the selected public analysis specification.
}
\details{
The custodian configures \code{dsvert.dp.describe_specs} as a uniquely named
list. Each analysis entry has exactly \code{version}, \code{dataset},
\code{variables}, \code{histogram_grids}, and \code{allocation}. Variable
bounds come from the immutable DP numeric-bound policy. Every grid is strictly
increasing, uses public upper endpoints, and ends at its public upper bound.
No grid is chosen from protected data.

The allocation has positive \code{count}, \code{sum}, \code{sumsq}, and
\code{histogram} weights summing to one. With \eqn{p} variables, each family
receives its weight times the ledger epsilon divided by \eqn{p}. A complete
histogram is one vector mechanism with L1 sensitivity one under add/remove
and two under replace-one fixed-cohort adjacency, and receives
\code{epsilon_histogram / p}; epsilon is not divided again across its bins.
The four families compose sequentially across variables, and the certified
submechanism epsilons sum exactly to the single ledger allocation.
Each family is calibrated using its own sensitivity and epsilon. The reported
sum of family L1 bounds is descriptive and is not presented as one common
Laplace calibration scale.
This sensitivity and composition certificate uses the canonical patient-level
adjacency reported by the server: add/remove or replace-one fixed cohort.

Finite row values are clipped to public bounds before patient-level averaging.
The normalized value and its square are quantized independently to integers
before summation, preventing a fractional-part side channel; the certificate
reports the maximum per-unit normalized quantization error. Each unit changes
at most count sensitivity one, two moment sensitivities equal to the integer
grid scale, and one histogram cell per variable. Missing/non-finite values use
a fixed invalid histogram bin. Invalid patient identifiers form one invalid
super-unit, conservatively preserving the contribution bound while
deliberately undercounting identifier-quality defects.
}
\keyword{internal}
