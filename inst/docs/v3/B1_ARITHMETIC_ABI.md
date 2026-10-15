# B1 exact public arithmetic ABI

Version `dp_irls_update_v1` (diagonal shift; not eigenvalue clipping). Input and output are UTF-8 JSON, object keys sorted lexicographically recursively, no whitespace or trailing newline, no duplicate keys or unknown fields. Strings contain ASCII integer spelling `0` or `-?[1-9][0-9]*` only. Rationals are reduced objects `{"d":"positive denominator","n":"signed numerator"}`; zero is `{"d":"1","n":"0"}`. Arrays retain their signed order.

Input keys:
`beta`, `box_lower`, `box_upper` (rational vectors of length p), `damping`, `floor`, `floor_quantum` (rationals), `g`, `g_translation` (integer-string vectors p), `g_unit` (rational), `h`, `h_translation` (integer-string upper triangles, row-major i=0..p-1,j=i..p-1), `h_unit`, `lattice` (rationals), `limits` (object), `ridge`, `trust` (rationals), `version` (the string above).

Limits keys: `common_denominator`, `input_bits`, `k_max`, `temporary_bits`, all nonnegative integer strings. Positive: denominator/input_bits/temporary_bits. The public engine envelope is p<=128, input_bits<=4096, temporary_bits<=5000000, input bytes<=4 MiB, integer strings<=1500 characters. This is an admission envelope, never an adaptive arithmetic fallback.

Translations A must be positive; finalizer bound is exactly U=2A. Payload coordinates must lie in [0,U]; decode `(payload-A)*unit`. Units, lattice, floor and floor_quantum are positive; ridge/trust nonnegative; 0<damping<=1. beta is inside the closed signed box and on its lattice; box endpoints are on that lattice. Output `saturated` is true for any input finalizer endpoint (including reused H endpoints).

## Fixed numeric certificate

Let RH be the largest row sum of the symmetric matrix whose upper triangle is `h_translation*h_unit`. Require `k_max = ceil((floor+RH)/floor_quantum)` exactly. Let D be the LCM of reduced denominators of h_unit, floor_quantum, ridge, floor, g_unit and ridge*lattice. Require common_denominator=D exactly.

Let Hmax=max(h_translation*h_unit), Gmax=max(g_translation*g_unit), Bbeta=max(abs(box_lower),abs(box_upper)), and B=max(Hmax+k_max*floor_quantum+ridge+floor,Gmax+ridge*Bbeta). Required w is the maximum bit length of: numerator (absolute) and denominator of every *static* rational input (box endpoints,damping,floor,floor_quantum,g_unit,h_unit,lattice,ridge,trust), every 2A, D, ceil(D*B), and ceil(Bbeta*lattice.denominator). Zero has bit length zero. Signed input_bits=w may exceed this minimum, allowing a fixed profile to cover all stages. Dynamic beta and payload values are bounded by the validated box/lattice/translation, not used to increase the certificate.

Compute m as the least nonnegative integer with 2^(2m)>=p^p. This is exactly ceil((p/2)*log2(p)) without floating point. Set L=p*w+m+2 and require temporary_bits=8L+16w+64 exactly. Integer matrices after clearing denominators have entries <=2^w. Bareiss minors fit L bits; multiply-before-divide fits 2L+2. PSD zero rows are skipped *without changing the previous successful positive pivot*, initially 1. Remaining rows retain their fraction-free scale.

The solve uses fraction-free forward Bareiss elimination on [A|b], fixed order, followed by integer common-determinant back substitution: det is the last diagonal; N_i=(b_i*det-sum(A_ij*N_j))/A_ii, exact division, then v_i=N_i/det. Cramer numerators and determinant fit L; partial sums fit 3L+2. This avoids growing rational back-substitution denominators. Damping rational components have at most L+w bits; trust scaling at most 2L+3w; beta addition, projection comparisons, lattice division and rounded product fit at most 2L+6w+4. The signed temporary bound covers these operations, reduction cross products, and certificate computation; no larger ceiling is selected at runtime.

## Canonical result

Output keys: `beta` (rational successor vector), `k` (nonnegative integer string), `projected` (boolean vector marking strict pre-round box clipping), `saturated` (boolean), `trust_scaled` (boolean), `version` (`dp_irls_update_v1`). Damping precedes trust; trust scale is one for a zero vector. Projection precedes one nearest-even lattice rounding, including negative ties. Terminal audit payloads may be decoded/validated but do not invoke a successor update.

The arithmetic bytes are embedded in separately domain-bound stage certificates; this function does not accept unsigned beta claims or decide release identities. A score-only caller resolves the signed prior-H reference and supplies those exact retained H bytes and translations.

CLI: `dsvert-mpc dp-irls-update` reads exactly one canonical input from stdin and writes exactly one canonical result to stdout (no newline). On rejection stderr contains a reason and exit status is nonzero. Go API: `DPIRLSCanonicalUpdate([]byte) ([]byte,error)`.
