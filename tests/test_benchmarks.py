"""Benchmark tests for Shamir's Secret Sharing implementation.

These tests use pytest-codspeed to track performance over time.
Run with: uv run pytest tests/test_benchmarks.py --codspeed
"""

from random import Random
from typing import Any

import pytest

from shamir import combine, split
from shamir.math import add, div, inverse, mul


@pytest.fixture
def rng() -> Random:
    """Provide deterministic RNG for reproducible benchmarks."""
    return Random(42)


class TestSplitBenchmarks:
    """Benchmarks for the split() function."""

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, (16 * 16), (128 * 128)])
    def test_split(self, size: int, benchmark: Any, rng: Random) -> None:
        """Benchmark splitting a secret of various sizes."""
        secret = rng.randbytes(size)
        benchmark(lambda: split(secret, 5, 3, rng=rng))

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, (16 * 16), (128 * 128)])
    def test_split_high_threshold(self, size: int, benchmark: Any, rng: Random) -> None:
        """Benchmark splitting with high threshold (128 of 255)."""
        secret = rng.randbytes(size)
        benchmark(lambda: split(secret, 255, 128, rng=rng))

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, (16 * 16), (128 * 128)])
    def test_split_many_parts(self, size: int, benchmark: Any, rng: Random) -> None:
        """Benchmark splitting into many parts (255 parts, threshold 3)."""
        secret = rng.randbytes(size)
        benchmark(lambda: split(secret, 255, 3, rng=rng))


class TestCombineBenchmarks:
    """Benchmarks for the combine() function."""

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, (16 * 16), (128 * 128)])
    def test_combine(self, size: int, benchmark: Any, rng: Random) -> None:
        """Benchmark combining a secret of various sizes."""
        secret = rng.randbytes(size)
        parts = split(secret, 5, 3, rng=rng)
        benchmark(lambda: combine(parts[:3]))

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, (16 * 16), (128 * 128)])
    def test_combine_high_threshold(
        self, size: int, benchmark: Any, rng: Random
    ) -> None:
        """Benchmark combining with high threshold (128 of 255)."""
        secret = rng.randbytes(size)
        parts = split(secret, 255, 128, rng=rng)
        benchmark(lambda: combine(parts[:128]))

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, (16 * 16), (128 * 128)])
    def test_combine_many_parts_used(
        self, size: int, benchmark: Any, rng: Random
    ) -> None:
        """Benchmark combining using all 255 parts (threshold 3)."""
        secret = rng.randbytes(size)
        parts = split(secret, 255, 3, rng=rng)
        benchmark(lambda: combine(parts))  # Use all parts


class TestRoundtripBenchmarks:
    """Benchmarks for complete split+combine roundtrip."""

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, (16 * 16), (128 * 128)])
    def test_roundtrip(self, size: int, benchmark: Any, rng: Random) -> None:
        """Benchmark complete split+combine for a secret of various sizes."""
        secret = rng.randbytes(size)

        def roundtrip() -> bytearray:
            parts = split(secret, 5, 3, rng=rng)
            return combine(parts[:3])

        result = benchmark(roundtrip)
        assert result == secret


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
