# type: ignore
from random import Random

import pytest

from shamir.math import add, mul
from shamir.utils import Polynomial


def test_random() -> None:
    poly: Polynomial = Polynomial(intercept=42, degree=2, rng=Random(123))
    assert poly.coefficients[0] == 42


def test_rng_None() -> None:
    poly: Polynomial = Polynomial(intercept=42, degree=2)
    assert poly.coefficients[0] == 42


def test_evaluate() -> None:
    poly: Polynomial = Polynomial(intercept=42, degree=1, rng=Random(123))
    assert poly.evaluate(0) == 42
    out: int = poly.evaluate(1)
    exp: int = add(42, mul(1, poly.coefficients[1]))
    assert out == exp


def test_polynomial_coefficient_array_size() -> None:
    """Test that Polynomial allocates exactly degree+1 coefficients.

    Verifies memory efficiency - the coefficients array should have exactly
    enough space for the intercept (index 0) plus degree random coefficients
    (indices 1 through degree). This catches memory allocation bugs.
    """
    # Test various degrees
    for degree in [1, 2, 5, 10, 20]:
        poly: Polynomial = Polynomial(intercept=42, degree=degree, rng=Random(123))
        expected_size = degree + 1
        actual_size = len(poly.coefficients)
        assert actual_size == expected_size, (
            f"Polynomial with degree {degree} should have {expected_size} "
            f"coefficients but has {actual_size}"
        )
