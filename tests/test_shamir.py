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


def test_combine_legacy_shares_too_short() -> None:
    """Test combine with legacy shares that are too short (< 2 bytes)."""
    # Create malformed legacy shares (only 1 byte each)
    malformed_parts = [bytearray([0x42]), bytearray([0x43])]

    with pytest.raises(ValueError, match=Error.PARTS_MUST_BE_TWO_BYTES):
        combine(malformed_parts)


def test_combine_version1_shares_too_short() -> None:
    """Test combine with version 1 shares that are too short (< 3 bytes)."""
    # Create malformed version 1 shares (only 2 bytes each)
    # First byte is 0x01 (version), but missing y-values and x-coord
    malformed_parts = [bytearray([0x01, 0x42]), bytearray([0x01, 0x43])]

    with pytest.raises(ValueError, match=Error.PARTS_MUST_BE_THREE_BYTES):
        combine(malformed_parts)


def test_detect_empty_parts_list() -> None:
    """Test version detection with empty parts list."""
    from shamir import _detect_share_version

    # Empty list should return legacy version
    version = _detect_share_version([])
    assert version == 0  # SHARE_VERSION_LEGACY


def test_combine_mixed_version_shares() -> None:
    """Test combine rejects shares with mixed versions."""
    mixed_parts = [
        bytearray([0x01, 0x42, 0x10]),  # First byte is 0x01 (version 1)
        bytearray([0x00, 0x43, 0x20]),  # First byte is NOT 0x01
    ]

    with pytest.raises(ValueError, match=Error.MIXED_SHARE_VERSIONS):
        combine(mixed_parts)


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


def test_split_with_invalid_version() -> None:
    """Test split with invalid version parameter."""
    secret = b"test"

    # Version 2 is not supported (only 0 and 1)
    with pytest.raises(ValueError, match=Error.UNSUPPORTED_SHARE_VERSION):
        split(secret, 5, 3, version=2)

    # Version 255 is not supported
    with pytest.raises(ValueError, match=Error.UNSUPPORTED_SHARE_VERSION):
        split(secret, 5, 3, version=255)

    # Negative version is not supported
    with pytest.raises(ValueError, match=Error.UNSUPPORTED_SHARE_VERSION):
        split(secret, 5, 3, version=-1)

    # Exceeds max size
    with pytest.raises(ValueError, match=Error.SECRET_EXCEEDS_MAX_SIZE):
        large_secret = b"a" * (100 * (2**21))  # > 100 MB
        split(large_secret, 5, 3)


def test_split_version_none_defaults_to_current() -> None:
    """Test split with version=None uses current default version."""
    secret = b"test"

    # version=None should default to CURRENT_SHARE_VERSION (which is 1)
    parts_none = split(secret, 5, 3, version=None, rng=Random(42))
    parts_explicit = split(secret, 5, 3, version=1, rng=Random(42))

    # Both should produce identical results
    assert len(parts_none[0]) == len(parts_explicit[0])
    assert parts_none[0][0] == 0x01  # Version byte
    assert parts_explicit[0][0] == 0x01  # Version byte

    # Should be able to reconstruct from both
    assert combine(parts_none[:3]) == secret
    assert combine(parts_explicit[:3]) == secret


def test_split_version_zero_creates_legacy_shares() -> None:
    """Test split with version=0 creates legacy format shares."""
    secret = b"test"

    parts_v0 = split(secret, 5, 3, version=0, rng=Random(42))
    parts_v1 = split(secret, 5, 3, version=1, rng=Random(42))

    # Version 0 shares should be 1 byte shorter than version 1
    assert len(parts_v0[0]) == len(secret) + 1  # No version byte
    assert len(parts_v1[0]) == len(secret) + 2  # Has version byte

    # Version 0 shares should NOT start with 0x01 (usually)
    # (though there's a 1/256 chance they might randomly)

    # Both should reconstruct correctly
    assert combine(parts_v0[:3]) == secret
    assert combine(parts_v1[:3]) == secret


def test_split_with_explicit_version_1() -> None:
    """Test split with explicit version=1 parameter."""
    secret = b"test"

    parts = split(secret, 5, 3, version=1, rng=Random(42))

    # Should create version 1 shares
    assert len(parts[0]) == len(secret) + 2
    assert parts[0][0] == 0x01  # Version byte
    assert combine(parts[:3]) == secret


def test_version_detection_consistency() -> None:
    """Test that all shares in a set are detected as same version."""
    secret = b"test"

    # Create version 0 shares
    parts_v0 = split(secret, 5, 3, version=0, rng=Random(42))
    # All should be detected as legacy
    from shamir import _detect_share_version

    assert _detect_share_version(parts_v0) == 0

    # Create version 1 shares
    parts_v1 = split(secret, 5, 3, version=1, rng=Random(42))
    # All should be detected as version 1
    assert _detect_share_version(parts_v1) == 1


def test_combine_legacy_shares_explicit() -> None:
    """Test combining legacy shares explicitly."""
    secret = b"Hello, World!"
    parts = split(secret, 5, 3, version=0, rng=Random(123))

    # Should be legacy format
    assert len(parts[0]) == len(secret) + 1

    # Should reconstruct correctly
    reconstructed = combine(parts[:3])
    assert reconstructed == secret


def test_combine_version1_shares_explicit() -> None:
    """Test combining version 1 shares explicitly."""
    secret = b"Hello, World!"
    parts = split(secret, 5, 3, version=1, rng=Random(123))

    # Should be version 1 format
    assert len(parts[0]) == len(secret) + 2
    assert parts[0][0] == 0x01

    # Should reconstruct correctly
    reconstructed = combine(parts[:3])
    assert reconstructed == secret


def test_combine_auto_detects_both_versions() -> None:
    """Test that combine auto-detects both legacy and version 1."""
    secret = b"test"

    parts_v0 = split(secret, 5, 3, version=0, rng=Random(42))
    parts_v1 = split(secret, 5, 3, version=1, rng=Random(42))

    # Both should reconstruct correctly via auto-detection
    assert combine(parts_v0[:3]) == secret
    assert combine(parts_v1[:3]) == secret


def test_combine_with_explicit_version_parameter() -> None:
    """Test combine with explicit version parameter eliminates false positives."""
    secret = b"test"

    # Create version 0 shares
    parts_v0 = split(secret, 5, 3, version=0, rng=Random(42))

    # Combine with explicit version=0 (100% reliable)
    reconstructed_v0 = combine(parts_v0[:3], version=0)
    assert reconstructed_v0 == secret

    # Create version 1 shares
    parts_v1 = split(secret, 5, 3, version=1, rng=Random(42))

    # Combine with explicit version=1 (100% reliable)
    reconstructed_v1 = combine(parts_v1[:3], version=1)
    assert reconstructed_v1 == secret


def test_combine_with_invalid_explicit_version() -> None:
    """Test combine rejects invalid explicit version parameter."""
    secret = b"test"
    parts = split(secret, 5, 3, version=1, rng=Random(42))

    # Version 2 is not supported
    with pytest.raises(ValueError, match=Error.UNSUPPORTED_SHARE_VERSION):
        combine(parts[:3], version=2)

    # Version 255 is not supported
    with pytest.raises(ValueError, match=Error.UNSUPPORTED_SHARE_VERSION):
        combine(parts[:3], version=255)

    # Negative version is not supported
    with pytest.raises(ValueError, match=Error.UNSUPPORTED_SHARE_VERSION):
        combine(parts[:3], version=-1)


def test_combine_explicit_version_overrides_autodetect() -> None:
    """Test that explicit version parameter overrides auto-detection."""
    secret = b"test"

    # Create version 1 shares
    parts_v1 = split(secret, 5, 3, version=1, rng=Random(42))

    # Even though shares are version 1, explicit version=1 should work
    reconstructed = combine(parts_v1[:3], version=1)
    assert reconstructed == secret

    # Create version 0 shares
    parts_v0 = split(secret, 5, 3, version=0, rng=Random(42))

    # Even though shares are version 0, explicit version=0 should work
    reconstructed = combine(parts_v0[:3], version=0)
    assert reconstructed == secret


def test_version_detection_majority_voting() -> None:
    """Test that version detection uses majority voting across multiple shares."""
    from shamir import _detect_share_version

    # Create 3 version 1 shares (all start with 0x01)
    parts_v1 = [
        bytearray([0x01, 0x42, 0x10]),
        bytearray([0x01, 0x43, 0x20]),
        bytearray([0x01, 0x44, 0x30]),
    ]

    # Should detect as version 1 (all agree)
    assert _detect_share_version(parts_v1) == 1

    # Create 3 legacy shares (none start with 0x01)
    parts_v0 = [
        bytearray([0x42, 0x10]),
        bytearray([0x43, 0x20]),
        bytearray([0x44, 0x30]),
    ]

    # Should detect as version 0 (legacy)
    assert _detect_share_version(parts_v0) == 0
