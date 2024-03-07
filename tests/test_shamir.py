# type: ignore
from itertools import permutations
from random import Random

import pytest

from shamir import combine, split


def test_combine() -> None:
    secret: bytes = b"test"
    parts: int = 5
    threshold: int = 3
    out: list[bytearray] = split(secret, parts, threshold, rng=Random(12345))
    for perm in permutations(out, threshold):
        recombined: bytearray = combine(list(perm))
        assert recombined == secret


def test_combine_invalid() -> None:
    parts: list[bytearray] = []
    with pytest.raises(
        ValueError, match="Less than two parts cannot be used to reconstruct the secret"
    ):
        combine(parts)
    parts = [bytearray("foo", "ascii"), bytearray("ba", "ascii")]
    with pytest.raises(ValueError, match="All parts must be the same length"):
        combine(parts)
    parts = [bytearray("f", "ascii"), bytearray("b", "ascii")]
    with pytest.raises(ValueError, match="Parts must be at least two bytes"):
        combine(parts)
    parts = [bytearray("foo", "ascii"), bytearray("foo", "ascii")]
    with pytest.raises(ValueError, match="Duplicate part detected"):
        combine(parts)


def test_split() -> None:
    secret: bytearray = bytearray("test", "ascii")
    out: list[bytearray] = split(secret, 5, 3, rng=Random(54321))
    assert len(out) == 5  # noqa: SCS108
    first_part_len: int = len(out[0])
    for part in out:
        assert len(part) == first_part_len  # noqa: SCS108


def test_split_invalid() -> None:
    secret: bytearray = bytearray("test", "ascii")
    with pytest.raises(ValueError, match="RNG not initialized"):
        split(secret, 5, 3, None)
    with pytest.raises(ValueError, match="Parts cannot be less than threshold"):
        split(secret, 2, 3)
    with pytest.raises(ValueError, match="Parts or Threshold cannot exceed 255"):
        split(secret, 1000, 3)
    with pytest.raises(ValueError, match="Threshold must be at least 2"):
        split(secret, 10, 1)
    with pytest.raises(ValueError, match="Parts or Threshold cannot exceed 255"):
        split(secret, 256, 256)
    with pytest.raises(ValueError, match="Cannot split an empty secret"):
        split(bytearray(), 3, 2)
