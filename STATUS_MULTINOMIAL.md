# Multinomial cross-owner grid status

## Retained work and Day-1 arithmetic amendment (2026-09-18)

This work continues branch `feature/famB`, server base `4d7e6ae` and client
base `cb26ecd`. The existing family contracts, circuit sources, integer
references, tests and client frontdoors were present as uncommitted files.
They are being retained and reparametrized. No prior `STATUS_MULTINOMIAL.md`,
`DECISIONS_MULTINOMIAL.md` or `STATUS_V1.md` exists in this checkout; this is
the first available status record, not a reconstruction of unobserved tests.

The binding `../DECISION_DAY1_ARITHMETIC_ROUTE.md` supersedes the former
q64 nonlinear profile. The source feature/coefficient f50 ABI, exact f100
partial predictors, authenticated contracts, canonical candidates, private
alignment requirements and output g=8..18 remain in force.

Milestones:

1. Read the arithmetic decision, V1 decisions/certificate, design and existing
   family code; split profile/circuit, certificate/oracle, and client validation
   work without shared-file edits.
2. Retarget nonlinear evaluation to certified public piecewise polynomials;
   bind the table and certificate identities into both signed validators.
3. Validate circuit/reference/R equality, bounded sensitivity, numeric error,
   two-peer public-synthetic DSLite reference selection and both R packages.
4. Record measured cost, remaining fused-producer gates and small local commits.

The supplied `pod4_endpoint` is empty; `./pod4` reports `Bad port ''`.
Local R 4.5.2, Go 1.25.7, DSLite, nnet and MASS are available. No pod address
or readiness claim is inferred. Production release registration remains
disabled. No push or thesis edit is authorized or performed.

Test counts, commands, measurements and final commits are appended below
after execution. An incomplete milestone above is not a passing gate.
