"""Cross-language oracle for the dsVert exact discrete-Gaussian tests.

The sampling functions below are a direct Python 3 adaptation of IBM's
Apache-2.0 reference implementation:
https://github.com/IBM/discrete-gaussian-differential-privacy/blob/master/discretegauss.py

The only substitution is a documented SHA-256 counter byte reader and an
explicit byte-level rejection sampler.  This makes the random-bit law
reproducible in Go without relying on Python's version-specific randrange().
Run this file to regenerate the vectors embedded in
k2_joint_dp_discrete_gaussian_v1_test.go.
"""

from fractions import Fraction
from hashlib import sha256
from math import isqrt


class CounterStream:
    def __init__(self, seed):
        self.seed = seed
        self.counter = 0
        self.buffer = b""

    def read(self, size):
        while len(self.buffer) < size:
            self.buffer += sha256(
                self.seed + self.counter.to_bytes(8, "big")
            ).digest()
            self.counter += 1
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result


def sample_uniform(modulus, rng):
    byte_count = (modulus.bit_length() + 7) // 8
    excess = byte_count * 8 - modulus.bit_length()
    while True:
        raw = bytearray(rng.read(byte_count))
        raw[0] &= 0xFF >> excess
        value = int.from_bytes(raw, "big")
        if value < modulus:
            return value


def sample_bernoulli(probability, rng):
    return sample_uniform(probability.denominator, rng) < probability.numerator


def sample_bernoulli_exp1(value, rng):
    k = 1
    while sample_bernoulli(value / k, rng):
        k += 1
    return k % 2 == 1


def sample_bernoulli_exp(value, rng):
    while value > 1:
        if not sample_bernoulli_exp1(Fraction(1), rng):
            return False
        value -= 1
    return sample_bernoulli_exp1(value, rng)


def sample_geometric_exp_slow(value, rng):
    result = 0
    while sample_bernoulli_exp(value, rng):
        result += 1
    return result


def sample_geometric_exp_fast(value, rng):
    denominator = value.denominator
    while True:
        uniform = sample_uniform(denominator, rng)
        if sample_bernoulli_exp(Fraction(uniform, denominator), rng):
            break
    geometric = sample_geometric_exp_slow(Fraction(1), rng)
    return (geometric * denominator + uniform) // value.numerator


def sample_discrete_laplace(scale, rng):
    while True:
        sign = sample_bernoulli(Fraction(1, 2), rng)
        magnitude = sample_geometric_exp_fast(Fraction(1, scale), rng)
        if sign and magnitude == 0:
            continue
        return -magnitude if sign else magnitude


def sample_discrete_gaussian(sigma_squared, rng):
    proposal_scale = isqrt(
        sigma_squared.numerator // sigma_squared.denominator
    ) + 1
    while True:
        candidate = sample_discrete_laplace(proposal_scale, rng)
        bias = (
            (abs(candidate) - sigma_squared / proposal_scale) ** 2
            / (2 * sigma_squared)
        )
        if sample_bernoulli_exp(bias, rng):
            return candidate


if __name__ == "__main__":
    for text in ("1/2", "3/2", "17/3", "560", "1234567/89"):
        sigma_squared = Fraction(text)
        stream = CounterStream(
            b"dsVert/IBM-cross-oracle/v1/" + text.encode("ascii")
        )
        values = [
            sample_discrete_gaussian(sigma_squared, stream)
            for _ in range(24)
        ]
        print(text, values)
