#!/usr/bin/env python3
"""Independent integer-only synthetic fixture evaluator (test artifact only)."""
from pathlib import Path
import json
from verify_numeric_certificate import rnd, piece, exp16, log16, soft16

ROOT = Path(__file__).resolve().parent
Q64 = 1 << 64

def divround(a, b):
    q, r = divmod(abs(a), b)
    return (-1 if a < 0 else 1)*(q+int(2*r > b or (2*r == b and q % 2)))

def exp64(eta, coefficients):
    t = divround(eta, 17)
    b1 = b2 = 0
    for coefficient in coefficients[:0:-1]:
        nxt = coefficient+rnd(2*t*b1, 64)-b2
        b2, b1 = b1, nxt
    value = coefficients[0]+rnd(t*b1, 64)-b2
    value = rnd(value*value, 64)
    return rnd(value*value, 64)

def log64(value):
    exponent = value.bit_length()-65
    mantissa = rnd(value, exponent)
    z = divround((mantissa-Q64)*Q64, mantissa+Q64)
    z2 = rnd(z*z, 64)
    term = total = z
    for k in range(1, 24):
        term = rnd(term*z2, 64)
        total += divround(term, 2*k+1)
    return 2*total+exponent*12786308645202655660

def row_loss(case, row, candidate, profile, coefficients):
    beta = list(map(int, case['beta_encoded'][candidate]))
    x = list(map(int, case['features_encoded'][row]))
    y = case['outcomes'][row]
    dim = len(x)+1
    dot = lambda b: (b[0] << 50)+sum(u*v for u,v in zip(x,b[1:]))
    if case['family'] == 'multinomial':
        eta = [rnd(dot(beta[k*dim:(k+1)*dim]), 84) for k in range(case['classes']-1)]
        maximum = max([0]+eta)
        loss = maximum+log16(sum(exp16(v-maximum,profile) for v in [0]+eta),profile)
        if y:
            loss -= eta[y-1]
    else:
        eta = rnd(dot(beta),84)
        thresholds = list(map(int, case['thresholds_encoded'][candidate]))
        args = [rnd(v,34)-eta for v in thresholds]
        if y == 0:
            loss = soft16(args[0],profile)-args[0]
        elif y == case['classes']-1:
            loss = soft16(args[-1],profile)
        else:
            gap = (thresholds[y]-thresholds[y-1]) << 14
            gaplog = rnd(log64(Q64-exp64(-gap,coefficients)),48)
            loss = soft16(args[y],profile)+soft16(args[y-1],profile)-args[y]-gaplog
    if not case['valid'][row]:
        return 0
    return min(case['caps'][candidate],max(0,rnd(loss,16-case['g'])))

def generate():
    document=json.loads((ROOT/'piecewise_profile_v1.json').read_text())
    profile=document['profile']
    legacy=json.loads((ROOT.parent/'cross-grid-v1'/'numeric_profile_v1.json').read_text())
    coefficients=list(map(int,legacy['profile']['exp_quarter_coefficients_q64']))
    path=ROOT/'integer_fixtures_v1.json'
    fixture=json.loads(path.read_text())
    fixture['profile_sha256']=document['profile_sha256']
    fixture['provenance']='public synthetic inputs; independent integer Python/Go test-tag-only/R oracle equality'
    if not any(c['name']=='multinomial_q16_dot_half_ties' for c in fixture['cases']):
        fixture['cases'].append({'name':'multinomial_q16_dot_half_ties',
          'family':'multinomial','classes':2,'g':18,
          'features_encoded':[[1<<40,1],[1<<40,0]],
          'beta_encoded':[['0',str(1<<43),str(v)] for v in [-1,0,1]],
          'outcomes':[0,1],'valid':[True,True],'caps':[9000000]*3})
    for case in fixture['cases']:
        case['expected_rows']=[[row_loss(case,i,j,profile,coefficients)
            for j in range(len(case['caps']))] for i in range(len(case['features_encoded']))]
        case['expected_sums']=list(map(sum,zip(*case['expected_rows'])))
    path.write_text(json.dumps(fixture,indent=2)+'\n')
    words={}
    for name,table in profile['tables'].items():
        lower,step=table['lower_q16'],table['step_q16']
        inputs=sorted(set(v for i in range(65) for v in (lower+i*step-1,lower+i*step,lower+i*step+1)
                          if lower<=v<=lower+64*step))
        words[name]=[{'input_q16':x,'output_q16':piece(x,table)} for x in inputs]
    words['exp_kernel']=[{'input_q16':x,'output_q16':exp16(x,profile)}
                         for x in [-32*65536,-16*65536-1,-16*65536,-1,0]]
    words['log_kernel']=[{'input_q16':x,'output_q16':log16(x,profile)}
                         for x in [65536,131071,131072,131073,262143,262144,262145,524287,524288]]
    (ROOT/'piecewise_boundary_fixtures_v1.json').write_text(json.dumps({
        'profile_sha256':document['profile_sha256'],'cases':words},indent=2)+'\n')
    print('regenerated',len(fixture['cases']),'loss cases;',sum(map(len,words.values())),'kernel boundary words')

if __name__=='__main__':
    generate()
