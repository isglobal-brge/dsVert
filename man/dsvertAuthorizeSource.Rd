\name{dsvertAuthorizeSource}
\alias{dsvertAuthorizeSource}
\alias{dsvertReauthorizeSource}
\title{Authorize a source as a durable frozen publication}
\usage{
dsvertAuthorizeSource(data, descriptor, event_id, kind = c("dataset", "psi"),
  patient_column = NULL, public = NULL, provenance = NULL)
dsvertReauthorizeSource(data, descriptor, event_id, kind = c("dataset", "psi"),
  patient_column = NULL, public = NULL, provenance = NULL)
}
\arguments{
\item{data}{Custodian-owned approved data frame.}
\item{descriptor}{Private source or dataset descriptor.}
\item{event_id}{Stable custodian event identifier, reused only for retries.}
\item{kind}{\code{dataset} for an aligned import or \code{psi} for a PSI input.}
\item{patient_column}{Local privacy-unit column for an import.}
\item{public}{Optional complete public source contract.}
\item{provenance}{Optional authenticated pre-alignment dependency provenance.}
}
\description{Allocates a random 256-bit epoch and durably captures the approved
frame. A retry of the same event returns the original authorization. These
administrative functions are not on the DataSHIELD allowlist. Legacy generic
aligned imports require one explicit authorization after upgrading to 1.4.1.}
\value{Private authorization record. Never disclose it to an analyst.}
\details{In-place replacement does not update a registered publication. Use a
new event identifier to reauthorize, even for unchanged bytes. Retain the
identity key, authorization store and stable artifacts across restarts. See
\file{PROVENANCE_EPOCHS.md} for migration, capacity and recovery instructions.}
