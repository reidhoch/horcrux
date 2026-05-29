from itertools import permutations
from random import Random

import pytest

from shamir import combine, split
from shamir.errors import Error


def test_combine() -> None:
    secret: bytes = b"test"
    parts: int = 5
    threshold: int = 3
    out: list[bytearray] = split(secret, parts, threshold, rng=Random(12345))
    for perm in permutations(out, threshold):
        recombined: bytearray = combine(list(perm))
        assert recombined == secret


def test_combine_shares_too_short() -> None:
    """Test combine with shares that are too short (< 2 bytes)."""
    # Create malformed shares (only 1 byte each)
    malformed_parts = [bytearray([0x42]), bytearray([0x43])]

    with pytest.raises(ValueError, match=Error.PARTS_MUST_BE_TWO_BYTES):
        combine(malformed_parts)


def test_combine_mismatched_lengths() -> None:
    """Test combine rejects shares with different lengths."""
    mismatched_parts = [
        bytearray([0x42, 0x10]),  # 2 bytes
        bytearray([0x55, 0x60, 0x20]),  # 3 bytes
    ]

    with pytest.raises(ValueError, match=Error.ALL_PARTS_MUST_BE_SAME_LENGTH):
        combine(mismatched_parts)


def test_split_secret_exceeds_max_size() -> None:
    """Test split rejects secrets larger than MAX_SECRET_SIZE (100MB)."""
    large_secret = b"a" * (100 * (2**20) + 1)  # 100MB + 1 byte
    with pytest.raises(ValueError, match=Error.SECRET_EXCEEDS_MAX_SIZE):
        split(large_secret, 5, 3)


@pytest.mark.slow
def test_split_accepts_max_secret_size() -> None:
    """Test split accepts secrets of exactly MAX_SECRET_SIZE (100MB)."""
    max_secret = b"a" * (100 * (2**20))  # Exactly 100MB
    # Should not raise - this proves the boundary condition is correct (> not >=)
    parts = split(max_secret, 5, 3, rng=Random(42))
    assert len(parts) == 5


def test_split() -> None:
    secret: bytes = b"test"
    out: list[bytearray] = split(secret, 5, 3, rng=Random(54321))
    assert len(out) == 5  # noqa: SCS108
    first_part_len: int = len(out[0])
    for part in out:
        assert len(part) == first_part_len  # noqa: SCS108


def test_split_rng_None() -> None:
    secret: bytes = b"test"
    out: list[bytearray] = split(secret, 5, 3)
    assert len(out) == 5  # noqa: SCS108
    first_part_len: int = len(out[0])
    for part in out:
        assert len(part) == first_part_len  # noqa: SCS108


def test_split_share_format() -> None:
    """Shares are [y_values..., x_coordinate] (secret_len + 1 bytes)."""
    secret = b"Hello, World!"
    parts = split(secret, 5, 3, rng=Random(123))

    assert len(parts[0]) == len(secret) + 1
    assert combine(parts[:3]) == secret


def test_single_byte_secret_roundtrip() -> None:
    """A single-byte secret produces 2-byte shares and reconstructs correctly."""
    secret = b"\x01"
    parts = split(secret, 3, 2, rng=Random(42))

    assert len(parts[0]) == 2  # [y_value, x_coord]
    assert combine(parts[:2]) == secret
