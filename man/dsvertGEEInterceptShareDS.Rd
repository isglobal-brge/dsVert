% Generated manually for dsVert GEE sandwich helpers
\name{dsvertGEEInterceptShareDS}
\alias{dsvertGEEInterceptShareDS}
\title{Store a public intercept column as additive FP shares}
\usage{
dsvertGEEInterceptShareDS(
  output_key = "gee_x_col_0",
  n = NULL,
  is_party0 = FALSE,
  session_id = NULL,
  frac_bits = 20L,
  ring = 63L
)
}
\arguments{
\item{output_key}{Session slot to receive the column share.}
\item{n}{Vector length. Defaults to the active GLM session row count.}
\item{is_party0}{Logical; TRUE for the first DCF party.}
\item{session_id}{Active MPC session identifier.}
\item{frac_bits}{Fixed-point fractional bits.}
\item{ring}{Integer 63 or 127.}
}
\value{
List with \code{stored}, \code{output_key}, and \code{n}.
}
\description{
Writes an n-vector of additive shares for the public intercept column.
Party 0 receives the all-ones fixed-point vector and party 1 receives
zeros, so the reconstructed vector is exactly one while no patient-level
private value is introduced.
}
