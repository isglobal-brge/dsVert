# Third-party notices

`dsvert-mpc` links Google Differential Privacy Go v4.1.0
(`github.com/google/differential-privacy/go/v4`), Copyright Google LLC,
under the Apache License 2.0. The corresponding license text is distributed at
`third_party/google-differential-privacy.LICENSE`.

The local `dp-noise-int64` command adapts Google Differential Privacy v4.1.0's
granular integer Laplace algorithm and two-sided geometric inversion sampler.
The distribution and power-of-two granularity are retained, while dsVert
replaces the entropy source with a release-specific HMAC-SHA256/ChaCha20
stream so an authenticated ledger entry can be replayed byte-for-byte. The Go
dependency remains linked for its integer confidence-interval implementation.
The adapted implementation is in `k2_dp_noise.go` and is distributed under the
same Apache License 2.0 terms identified above.

The local `dp-gaussian-int64` command likewise adapts Google Differential
Privacy v4.1.0's analytic Gaussian calibration and symmetric-binomial secure
sampler, replacing only its entropy source with independent domain-separated
HMAC-SHA256/ChaCha20 streams. Google's
[`Secure Noise Generation`](https://github.com/google/differential-privacy/blob/main/common_docs/Secure_Noise_Generation.pdf)
report bounds the total-variation distance of the normalized binomial sampler
from its discretized Gaussian target by `2^-40` for the stated construction.
`k2_dp_gaussian.go` enforces the upstream `sqrt(n)` interval, charges that
bound conservatively as
`(1 + exp(epsilon)) * coordinate_count * 2^-40` in the release delta, and
subtracts the scalar `2^-40` slack from each coordinate's tail allocation when
reporting simultaneous accuracy. This is the required transfer from the
approximating law to the stated `(epsilon, delta)` guarantee. The adaptation is
distributed under the Apache License 2.0 terms above.

The productive `dyadic_discrete_gaussian_truncated_tv_bounded` vector
mechanism targets the exact rational law published by Thomas Steinke in IBM's
`discrete-gaussian-differential-privacy` repository, Copyright IBM Corp., under
the Apache License 2.0. The upstream implementation accompanies Canonne,
Kamath, and Steinke, *The Discrete Gaussian for Differential Privacy*
(NeurIPS 2020, arXiv:2004.00010). dsVert ports the uniform, rational Bernoulli,
Bernoulli-exp, geometric-exp, discrete-Laplace proposal, and rejection steps to
Go as a retained cross-oracle. The productive v2 sampler uses an outward-
rounded rational dyadic CDF over a certified finite support, a purpose- and
coordinate-separated HKDF-SHA256/ChaCha20 sticky stream, and separately
audited zCDP calibration, sampler/tail TV accounting, Ring128 headroom proofs,
and the two-peer convolution contract. The code is in
`k2_joint_dp_discrete_gaussian_v1.go` and
`k2_joint_dp_discrete_gaussian_fixed.go`; its cross-language oracle is in
`testdata/discrete_gaussian_ibm_oracle.py`. The corresponding Apache-2.0 text
is distributed at `third_party/ibm-discrete-gaussian.LICENSE`.

Google Differential Privacy pulls the following runtime dependencies used by
that sampler:

- `github.com/golang/glog` v1.2.5, Copyright 2023 Google Inc., Apache-2.0
  (covered by the Apache-2.0 text distributed above); and
- `gonum.org/v1/gonum` v0.16.0, Copyright 2013 The Gonum Authors, BSD-3-Clause.
  Its license is distributed at `third_party/gonum.LICENSE`.

The exact garbled-circuit runtime links these MIT-licensed modules by Markku
Rossi:

- `github.com/markkurossi/mpc`, Copyright 2019 Markku Rossi;
- `github.com/markkurossi/crypto`, Copyright 2023 Markku Rossi; and
- `github.com/markkurossi/tabulate`, Copyright 2020 Markku Rossi.

Their license texts are distributed at `third_party/markkurossi-mpc.LICENSE`,
`third_party/markkurossi-crypto.LICENSE`, and
`third_party/markkurossi-tabulate.LICENSE`.

Packaged runtimes also embed the exact AES-128, HMAC-SHA256, and SHA-256 MPCL
circuit assets required by the joint-DP prototype from the pinned
`github.com/markkurossi/mpc` revision `c911bbd029d1`. The assets are stored as
deterministic gzip files under `third_party/mpcl-runtime-c911bbd029d1/` and
remain covered by `third_party/markkurossi-mpc.LICENSE`.

The runtime also links `golang.org/x/crypto` v0.50.0 and indirectly
`golang.org/x/text` v0.36.0, Copyright 2009 The Go Authors, BSD-3-Clause. Their
common license text is distributed at `third_party/golang-x.LICENSE`.

This source tree does not vendor or link EMP-toolkit. Adding it later requires
its own dependency review and notice before a binary release.
