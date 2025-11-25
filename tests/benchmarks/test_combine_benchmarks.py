from random import Random
from typing import Any

import pytest

from shamir import combine, split


@pytest.fixture
def rng() -> Random:
    """Provide deterministic RNG for reproducible benchmarks."""
    return Random(42)


class TestCombineBenchmarks:
    """Benchmarks for the combine() function."""

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, 256, (16 * 1024)])
    def test_combine(self, size: int, benchmark: Any, rng: Random) -> None:
        """Benchmark combining a secret of various sizes."""
        secret = rng.randbytes(size)
        parts = split(secret, 5, 3, rng=rng)
        benchmark(lambda: combine(parts[:3]))
