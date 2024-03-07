# type: ignore
import pytest

from shamir.math import add, mul
from shamir.utils import Polynomial, interpolate


def test_invalid_rng() -> None:
    with pytest.raises(ValueError, match="RNG not initialized"):
        Polynomial(intercept=42, degree=2, rng=None)


def test_random() -> None:
    poly: Polynomial = Polynomial(intercept=42, degree=2)
    assert poly.coefficients[0] == 42


def test_evaluate() -> None:
    poly: Polynomial = Polynomial(intercept=42, degree=1)
    assert poly.evaluate(0) == 42
    out: int = poly.evaluate(1)
    exp: int = add(42, mul(1, poly.coefficients[1]))
    assert out == exp


def test_interpolate() -> None:
    for i in range(1, 256):
        poly: Polynomial = Polynomial(intercept=i, degree=2)
        x: bytearray = bytearray([1, 2, 3])
        y: bytearray = bytearray([poly.evaluate(1), poly.evaluate(2), poly.evaluate(3)])
        out: int = interpolate(x, y, 0)
        assert out == i
