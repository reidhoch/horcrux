from random import Random
from typing import Any

import pytest

from shamir import split


class TestSplitBenchmarks:
    """Benchmarks for the split() function."""

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, 256, (16 * 1024)])
    def test_split(self, size: int, benchmark: Any, rng: Random) -> None:
        """Benchmark splitting a secret of various sizes."""
        secret = rng.randbytes(size)
        benchmark(lambda: split(secret, 5, 3, rng=rng))
