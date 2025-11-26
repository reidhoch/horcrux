from random import Random
from typing import Any

import pytest

from shamir.math import add, mul
from shamir.utils import Polynomial


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
