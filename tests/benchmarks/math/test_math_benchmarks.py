from random import Random
from typing import Any

import pytest

from shamir.math import add, div, inverse, mul


class TestMathBenchmarks:
    """Benchmarks for low-level GF(256) math operations."""

    @pytest.mark.benchmark
    def test_add(self, benchmark: Any, rng: Random) -> None:
        """Test addition is closed (in GF(2^8), 0 <= sum <= 255)."""
        a = rng.randrange(0, 256)
        b = rng.randrange(0, 256)
        sum = benchmark(lambda: add(a, b))
        assert 0 <= sum <= 255

    @pytest.mark.benchmark
    def test_div(self, benchmark: Any, rng: Random) -> None:
        """Test division is closed (in GF(2^8), 0 <= sum <= 255)."""
        a = rng.randrange(0, 256)
        b = rng.randrange(1, 256)
        quotient = benchmark(lambda: div(a, b))
        assert 0 <= quotient <= 255

    @pytest.mark.benchmark
    def test_mul(self, benchmark: Any, rng: Random) -> None:
        """Test multiplication is closed (in GF(2^8), 0 <= sum <= 255)."""
        a = rng.randrange(0, 256)
        b = rng.randrange(0, 256)
        product = benchmark(lambda: mul(a, b))
        assert 0 <= product <= 255

    @pytest.mark.benchmark
    def test_inverse(self, benchmark: Any, rng: Random) -> None:
        """Test that a * inverse(a) = 1 for all non-zero values in GF(2^8)."""
        a = rng.randrange(1, 256)
        b = benchmark(lambda: inverse(a))
        assert mul(a, b) == 1
