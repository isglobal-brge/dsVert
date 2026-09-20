\name{remote_internal_endpoints}
\alias{dsvertDPSynopsisGaussianCrossBindDS}
\alias{dsvertDPSynopsisGaussianCrossFinalizeDS}
\alias{dsvertDPSynopsisGaussianCrossEvidenceDS}
\alias{dsvertFormalGLMPublicResultDS}
\alias{dsvertFormalCoxPublicResultDS}
\alias{dsvertFormalCoxDiscretePublicResultDS}
\title{Authenticated internal remote lifecycle and publication endpoints}
\usage{
dsvertDPSynopsisGaussianCrossBindDS(manifest_sha256, claim_set_json,
  compilation_json, analysis_id, session_id)
dsvertDPSynopsisGaussianCrossFinalizeDS(manifest_sha256, claim_set_json,
  compilation_json, analysis_id, session_id)
dsvertDPSynopsisGaussianCrossEvidenceDS(manifest_sha256, claim_set_json,
  compilation_json, analysis_id)
dsvertFormalGLMPublicResultDS(analysis_id, data_name, family, formula_sha256)
dsvertFormalCoxPublicResultDS(analysis_id, data_name, formula_sha256)
dsvertFormalCoxDiscretePublicResultDS(analysis_id, data_name, source_formula_sha256)
}
\arguments{
\item{manifest_sha256}{Digest of the admitted public Synopsis manifest.}
\item{claim_set_json}{Canonical authenticated source-claim set.}
\item{compilation_json}{Canonical signed compilation and receipt bundle.}
\item{analysis_id}{Custodian-configured analysis identifier.}
\item{session_id}{Authenticated computation session identifier.}
\item{data_name}{Custodian-configured dataset selector.}
\item{family}{Family bound to the completed formal GLM publication.}
\item{formula_sha256, source_formula_sha256}{Canonical formula digest bound to
the configured publication.}
}
\description{
The Gaussian Synopsis endpoints bind authenticated source shares, finalize
private result shares, or return public completion evidence. They require the
existing signed Synopsis authority and do not release private shares.

The formal result endpoints read an already completed, signed public
publication selected by custodian policy. They do not start model computation.
Their separate authorization and promotion checks remain mandatory.
}
\value{A route-specific authenticated receipt, public evidence, or public
publication response. Invalid or unavailable bindings fail closed.}
\keyword{internal}
