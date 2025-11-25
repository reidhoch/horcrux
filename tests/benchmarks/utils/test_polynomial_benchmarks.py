from random import Random
from typing import Any

import pytest

from shamir.math import add, mul
from shamir.utils import Polynomial, interpolate


class TestPolynomialBenchmarks:
    """Benchmarks for polynomial operations."""

    @pytest.mark.benchmark
    def test_evaluate(self, benchmark: Any, rng: Random) -> None:
        """Benchmark polynomial evaluation."""
        poly: Polynomial = Polynomial(intercept=42, degree=1, rng=rng)
        assert poly.evaluate(0) == 42
        out: int = benchmark(poly.evaluate, 1)
        exp: int = add(42, mul(1, poly.coefficients[1]))
        assert out == exp

    @pytest.mark.benchmark
    def test_interpolate(self, benchmark: Any, rng: Random) -> None:
        """Benchmark Lagrange interpolation."""
        poly: Polynomial = Polynomial(intercept=123, degree=2, rng=rng)
        x: bytearray = bytearray([1, 2, 3])
        y: bytearray = bytearray([poly.evaluate(1), poly.evaluate(2), poly.evaluate(3)])
        out: int = benchmark(interpolate, x, y, 0)
        assert out == 123
