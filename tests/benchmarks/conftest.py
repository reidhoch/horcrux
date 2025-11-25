from random import Random
import pytest


@pytest.fixture
def rng() -> Random:
    """Provide deterministic RNG for reproducible benchmarks."""
    return Random(42)
