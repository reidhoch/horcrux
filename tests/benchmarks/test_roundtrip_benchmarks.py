from random import Random
from typing import Any

import pytest

from shamir import combine, split


class TestRoundtripBenchmarks:
    """Benchmarks for a split()/combine() roundtrip."""

    @pytest.mark.benchmark
    @pytest.mark.parametrize("size", [16, 256, (16 * 1024)])
    def test_roundtrip(self, size: int, benchmark: Any, rng: Random) -> None:
        """Benchmark complete split+combine for a secret of various sizes."""
        secret = rng.randbytes(size)

        def roundtrip() -> bytearray:
            parts = split(secret, 5, 3, rng=rng)
            return combine(parts[:3])

        result = benchmark(roundtrip)
        assert result == secret
