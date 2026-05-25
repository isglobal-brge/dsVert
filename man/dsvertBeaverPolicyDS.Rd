\name{dsvertBeaverPolicyDS}
\alias{dsvertBeaverPolicyDS}
\title{Report the server-side Beaver preprocessing policy}
\usage{
dsvertBeaverPolicyDS()
}
\description{
Reports which Beaver preprocessing backends this DataSHIELD server allows.
The client uses this aggregate method during preflight negotiation so that
the effective backend is accepted by every participating server.
}
\details{
Administrators can configure the policy with ordinary R/DataSHIELD options:
\code{dsvert.beaver_preprocessing.allowed},
\code{dsvert.beaver_preprocessing.preferred}, and
\code{dsvert.beaver_preprocessing.minimum}. The corresponding
\code{default.*} option names are also honoured.

Recognised backend names are \code{"dealer"} and \code{"iknp"}; \code{"ot"}
is normalised to \code{"iknp"}. Dealer mode is the efficient profile for
governed semi-honest institutional peers. IKNP mode removes the privileged
preprocessing dealer for deployments that require stronger
inter-institutional protection.
}
\value{
A list with \code{supported}, \code{allowed}, \code{preferred},
\code{minimum}, and \code{requires_iknp}.
}
\keyword{internal}
