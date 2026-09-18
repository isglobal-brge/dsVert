# Step 2 decisions

## 2026-09-18T12:45Z — resumed

1. Preserve the committed V1 profile, references and signatures. The arithmetic
   addendum supersedes its nonlinear arithmetic, not its source f50 encoding,
   ownership, alignment, complete-case semantics or release authorization.
   A replacement profile requires its own identity, hash and error certificate;
   old signed q64 contracts must never silently select new arithmetic.
2. Measure a new Boolean-engine piecewise profile before integrating release.
   The existing ring/spline implementation is not a drop-in certified backend:
   its binomial/Poisson domains are hardcoded, its tail rules differ, and its
   coefficient generation uses ordinary floating point. Its trusted combined
   preprocessing helpers do not establish two-authority production security.
   No sealed generation-one route will be reopened.
3. Preserve all baseline files. Newly generated numerical fixtures contain only
   public coefficients and synthetic inputs. A profile cost experiment is not
   a completed kernel, release, or whole-workload benchmark.
