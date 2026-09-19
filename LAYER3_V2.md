# Layer 3: production-seeded DP selection and real API equality

Synthetic n=2000, p=6 (3/3 owners), two signed candidates per grid; delta=2^-100. Each cell uses 20 distinct signed grids. The first two instances also execute the actual two-authority DataSHIELD release. The harness compares independently planned production sticky seeds and sampler contracts, then the complete authenticated integer DP vector and selected candidate, before conversion to doubles.

| Family | Epsilon | Instances | Real API equalities | Selection agreement | Mean loss gap | Maximum loss gap |
|---|---:|---:|---:|---:|---:|---:|
| binomial | 1 | 20 | 2 | 16/20 | 2.68316 | 14.4925 |
| binomial | 4 | 20 | 2 | 20/20 | 0 | 0 |
| binomial | 8 | 20 | 2 | 20/20 | 0 | 0 |
| poisson | 1 | 20 | 2 | 11/20 | 31.2351 | 73.8808 |
| poisson | 4 | 20 | 2 | 16/20 | 14.2878 | 75.0381 |
| poisson | 8 | 20 | 2 | 19/20 | 3.52114 | 70.4227 |

PASS: 120 distinct artifact keys, 120 oracle selections and 12 real API releases with bit-for-bit equality. Loss gaps are sums on the certified loss lattice divided by 2^16; selection agreement compares DP-best against the noise-free finite-grid best, with first-in-order ties. Reported gaps inherit the harness JSON's decimal precision. These small-grid statistics do not establish continuous-MLE accuracy or utility for all admitted grids.

## Real API elapsed times

Timing wraps `ds.vertGLM()`, including authenticated materialisation, MPC, joint noise and publication. It excludes preceding PSI/signature setup and subsequent oracle/cold-lifecycle verification.

| Family | Epsilon | Instance | API seconds |
|---|---:|---:|---:|
| binomial | 1 | 1 | 2838.057 |
| binomial | 1 | 2 | 2801.709 |
| binomial | 4 | 1 | 2932.752 |
| binomial | 4 | 2 | 2767.322 |
| binomial | 8 | 1 | 3216.212 |
| binomial | 8 | 2 | 2822.927 |
| poisson | 1 | 1 | 3390.267 |
| poisson | 1 | 2 | 3247.900 |
| poisson | 4 | 1 | 3782.294 |
| poisson | 4 | 2 | 3369.260 |
| poisson | 8 | 1 | 3675.475 |
| poisson | 8 | 2 | 3195.671 |

Reproduce with `run_validation_campaign_pod.sh`, then `python3 inst/cross-grid-v2/summarize_validation.py <logs> LAYER3_V2.md`. The matrix runner checks frozen helper hashes before and after each cell.
