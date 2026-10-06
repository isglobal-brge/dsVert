\name{dsvertListSourceAuthorizations}
\alias{dsvertListSourceAuthorizations}
\title{List source authorizations for the custodian}
\usage{dsvertListSourceAuthorizations()}
\description{Reads the authenticated authorization inventory. This administrative
function is not on the DataSHIELD allowlist.}
\value{Store UUID and private authorization metadata without frame bytes, or
\code{NULL} before initial provisioning. Never disclose descriptors to analysts.}
