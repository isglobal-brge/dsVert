#!/usr/bin/env python3
"""Outward-interval certificate for an unadmitted range-reduced exp profile."""
import argparse
import hashlib
import json
import random
import sys
sys.dont_write_bytecode = True
from pathlib import Path
import mpmath as mp
from generate_profile import canonical, rounded, upper_decimal, round_even, oracle

mp.mp.dps = 100
mp.iv.dps = 90
ETA_F, RED_F, COEFF_F, OUTPUT_F = 26, 24, 27, 16
LN_F, INV_F = 30, 30


def evaluate(profile, eta):
    if abs(eta) > 16 * 2**ETA_F:
        return 0, False
    k = round_even(abs(eta) * profile['inv_ln2'], 2**(ETA_F+INV_F))
    if eta < 0:
        k = -k
    r = round_even(eta * 2**(LN_F-ETA_F) - k*profile['ln2'], 2**(LN_F-RED_F))
    v = oracle(profile['coefficients'], profile['width'], r + 2**(RED_F-1))
    shift = COEFF_F-OUTPUT_F-k
    v = round_even(v, 2**shift) if shift > 0 else v * 2**(-shift)
    return v, True


def build():
    ln2 = mp.iv.log(2)
    ln_i, inv_i = rounded(ln2, 2**LN_F), rounded(1/ln2, 2**INV_F)
    # k need not equal exact round(eta/ln2) near a boundary: all selected k
    # are valid if the residual stays in the polynomial's certified interval.
    k_error = mp.iv.mpf(16)/2**(INV_F+1)
    residual = ln2*(mp.iv.mpf('0.5') + k_error) + mp.iv.mpf(23)/2**(LN_F+1) + mp.iv.mpf(1)/2**(RED_F+1)
    assert mp.mpf(residual.b) < mp.mpf('0.5')
    encoding = mp.iv.mpf(33)/2**51 + mp.iv.mpf(16)/2**102
    eta_error = encoding + mp.iv.mpf(1)/2**(ETA_F+1)
    reduction_error = mp.iv.mpf(23)/2**(LN_F+1) + mp.iv.mpf(1)/2**(RED_F+1)
    profiles = []
    for pieces in (16,32,64):
        h = mp.iv.mpf(1)/pieces
        coeff = []
        for j in range(pieces):
            x = mp.iv.mpf('-0.5') + j*h
            y0, ym, y1 = mp.iv.exp(x), mp.iv.exp(x+h/2), mp.iv.exp(x+h)
            c2 = 2*(y1 - 2*ym + y0)
            coeff.append([rounded(y0,2**COEFF_F), rounded(y1-y0-c2,2**COEFF_F), rounded(c2,2**COEFF_F)])
        # Quadratic interpolation on [-1/2,1/2], two nearest Horner products.
        polynomial = mp.iv.exp(mp.iv.mpf('0.5'))*h**3/(72*mp.iv.sqrt(3))
        arithmetic = mp.iv.mpf(5)/2**(COEFF_F+1)
        # Scale the absolute mantissa error by exp(1/2) to bound relative error.
        relative = (polynomial+arithmetic)*mp.iv.exp(mp.iv.mpf('0.5'))
        total_relative = mp.iv.exp(eta_error+reduction_error)*(1+relative)-1
        errors, caps = {}, []
        for a in (1,2,4,8,16):
            # Integer count term uses eta26; log-factorial and final shift f16.
            loss_error = mp.iv.exp(a)*total_relative + 1024*eta_error + mp.iv.mpf(1)/2**OUTPUT_F
            errors[str(a)] = upper_decimal(loss_error)
            for m in (4,1024):
                lf = sum((mp.iv.log(i) for i in range(1,m+1)), mp.iv.mpf(0))
                corners = [mp.iv.exp(sign*a)-y*sign*a+(lf if y else 0) for sign in (-1,1) for y in (0,m)]
                bound = max(mp.mpf(c.b) for c in corners)
                cap = int(mp.ceil((bound+2*mp.mpf(loss_error.b))*2**OUTPUT_F))
                caps.append(dict(a=a,max_outcome=m,per_patient_cap=cap))
        p = dict(identity=f'cross-grid-exp-reduced-k{pieces}-eta26-r24-q27-out16-v2',
                 pieces=pieces, eta_fraction_bits=ETA_F, reduced_fraction_bits=RED_F,
                 coefficient_fraction_bits=COEFF_F, output_fraction_bits=OUTPUT_F,
                 ln_fraction_bits=LN_F, inv_fraction_bits=INV_F,
                 ln2=ln_i, inv_ln2=inv_i, width=2**RED_F//pieces, coefficients=coeff,
                 max_k=23, residual_bound=upper_decimal(residual),
                 k_reciprocal_error=upper_decimal(k_error),
                 reduction_error=upper_decimal(reduction_error),
                 interpolation_error=upper_decimal(polynomial),
                 arithmetic_error=upper_decimal(arithmetic),
                 relative_exp_error=upper_decimal(total_relative),loss_errors=errors,caps=caps)
        # Signed32 polynomial words, unsigned64 exact multiplication temporaries.
        assert all(0 <= min(c) and sum(c)+2 < 2**31 for c in coeff)
        assert (16*2**ETA_F)*inv_i < 2**61
        assert 23*ln_i < 2**35
        assert max((c[1]+c[2]+1)*p['width'] for c in coeff) < 2**63
        rng = random.Random(20260918)
        points = {-16*2**ETA_F,0,16*2**ETA_F}
        for k in range(-23,24):
            for midpoint in (mp.mpf(k),mp.mpf(k)+mp.mpf('0.5')):
                x = int(mp.nint(midpoint*mp.log(2)*2**ETA_F))
                points.update(x+d for d in (-1,0,1) if abs(x+d)<=16*2**ETA_F)
        points.update(rng.randrange(-16*2**ETA_F,16*2**ETA_F+1) for _ in range(256))
        p['test_vectors'] = [[x,evaluate(p,x)[0]] for x in sorted(points)]
        profiles.append(p)
    data = dict(version='cross-grid-exp-range-reduced-candidate-v2', status='not-admitted',
                rounding='nearest-ties-to-even',profiles=profiles)
    data['sha256'] = hashlib.sha256(canonical(data).encode()).hexdigest()
    return data


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    path=Path(__file__).with_name('exp_reduced_candidate.json')
    data=json.dumps(build(),sort_keys=True,indent=2)+'\n'
    if args.check:
        assert path.read_text()==data, 'range-reduced certificate mismatch'
    else:
        path.write_text(data)
    print('range-reduced certificate reproduced')

if __name__=='__main__':
    main()
