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
    """Test combine with version 1 shares that are too short (< 3 bytes).

    Note: 2-byte shares starting with 0x01 are now auto-detected as legacy
    format due to length-based heuristic (version 1 requires minimum 3 bytes).
    This test verifies that explicit version=1 parameter correctly rejects
    2-byte shares as too short.
    """
    # Create malformed 2-byte shares starting with 0x01
    # These will be auto-detected as legacy (not version 1) due to length
    malformed_parts = [bytearray([0x01, 0x42]), bytearray([0x01, 0x43])]

    # Auto-detection treats these as legacy (passes basic length check)
    # They will just fail to reconstruct correctly

    # But with explicit version=1, they should be rejected as too short
    with pytest.raises(ValueError, match=Error.PARTS_MUST_BE_THREE_BYTES):
        combine(malformed_parts, version=1)


def test_detect_empty_parts_list() -> None:
    """Test version detection with empty parts list."""
    from shamir import _detect_share_version

    # Empty list should return legacy version
    version = _detect_share_version([])
    assert version == 0  # SHARE_VERSION_LEGACY


def test_combine_mixed_version_shares() -> None:
    """Test combine rejects shares with different lengths (natural mixed versions).

    Natural v0/v1 shares for the same secret have different lengths (v1 is 1 byte
    longer due to version byte). The length check catches this before version detection.
    """
    # Create v1 shares for a 2-byte secret (length = 4: version + 2 y-values + x-coord)
    v1_parts = split(b"XY", 3, 2, version=1, rng=Random(42))
    # Create v0 shares for a 2-byte secret (length = 3: 2 y-values + x-coord)
    v0_parts = split(b"AB", 3, 2, version=0, rng=Random(43))

    # Mix shares with different lengths (4 vs 3)
    mixed_parts = [v1_parts[0], v0_parts[0]]

    # Different lengths are caught by the length check
    with pytest.raises(ValueError, match=Error.ALL_PARTS_MUST_BE_SAME_LENGTH):
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

    # Create 4+ byte version 1 shares (all start with 0x01, not ambiguous)
    parts_v1 = [
        bytearray([0x01, 0x42, 0x50, 0x10]),
        bytearray([0x01, 0x43, 0x60, 0x20]),
        bytearray([0x01, 0x44, 0x70, 0x30]),
    ]

    # Should detect as version 1 (all agree, not ambiguous length)
    assert _detect_share_version(parts_v1) == 1

    # Create 3 legacy shares (none start with 0x01)
    parts_v0 = [
        bytearray([0x42, 0x10]),
        bytearray([0x43, 0x20]),
        bytearray([0x44, 0x30]),
    ]

    # Should detect as version 0 (legacy)
    assert _detect_share_version(parts_v0) == 0


def test_version_detection_majority_voting_60_percent() -> None:
    """Test that >= 60% shares starting with 0x01 are detected as version 1."""
    from shamir import _detect_share_version

    # Create 5 shares where 3 start with 0x01 (60%)
    parts = [
        bytearray([0x01, 0x42, 0x10]),  # Starts with 0x01
        bytearray([0x01, 0x43, 0x20]),  # Starts with 0x01
        bytearray([0x01, 0x44, 0x30]),  # Starts with 0x01
        bytearray([0x55, 0x45, 0x40]),  # Does NOT start with 0x01
        bytearray([0x66, 0x46, 0x50]),  # Does NOT start with 0x01
    ]

    # Should detect as version 1 via majority voting (60%)
    assert _detect_share_version(parts) == 1

    # Create 10 shares where 7 start with 0x01 (70%)
    parts_70 = [
        bytearray([0x01, 0x42, 0x10]),  # Starts with 0x01
        bytearray([0x01, 0x43, 0x20]),  # Starts with 0x01
        bytearray([0x01, 0x44, 0x30]),  # Starts with 0x01
        bytearray([0x01, 0x45, 0x40]),  # Starts with 0x01
        bytearray([0x01, 0x46, 0x50]),  # Starts with 0x01
        bytearray([0x01, 0x47, 0x60]),  # Starts with 0x01
        bytearray([0x01, 0x48, 0x70]),  # Starts with 0x01
        bytearray([0x55, 0x49, 0x80]),  # Does NOT start with 0x01
        bytearray([0x66, 0x4A, 0x90]),  # Does NOT start with 0x01
        bytearray([0x77, 0x4B, 0xA0]),  # Does NOT start with 0x01
    ]

    # Should detect as version 1 via majority voting (70%)
    assert _detect_share_version(parts_70) == 1


def test_version_detection_false_positives_under_40_percent() -> None:
    """Test that < 40% shares starting with 0x01 are treated as legacy with false positives."""
    from shamir import _detect_share_version

    # Create 10 shares where 3 start with 0x01 (30%)
    # This simulates legacy shares where some randomly have 0x01 as first y-value
    parts = [
        bytearray([0x01, 0x42, 0x10]),  # False positive
        bytearray([0x01, 0x43, 0x20]),  # False positive
        bytearray([0x01, 0x44, 0x30]),  # False positive
        bytearray([0x55, 0x45, 0x40]),
        bytearray([0x66, 0x46, 0x50]),
        bytearray([0x77, 0x47, 0x60]),
        bytearray([0x88, 0x48, 0x70]),
        bytearray([0x99, 0x49, 0x80]),
        bytearray([0xAA, 0x4A, 0x90]),
        bytearray([0xBB, 0x4B, 0xA0]),
    ]

    # Should detect as version 0 (legacy) despite false positives
    assert _detect_share_version(parts) == 0

    # Create 5 shares where 1 starts with 0x01 (20%)
    parts_20 = [
        bytearray([0x01, 0x42, 0x10]),  # False positive
        bytearray([0x55, 0x43, 0x20]),
        bytearray([0x66, 0x44, 0x30]),
        bytearray([0x77, 0x45, 0x40]),
        bytearray([0x88, 0x46, 0x50]),
    ]

    # Should detect as version 0 (legacy)
    assert _detect_share_version(parts_20) == 0


def test_version_detection_intentional_mixing_40_to_60_percent() -> None:
    """Test that 40-60% range raises error for intentional mixing (3+ shares)."""
    from shamir import _detect_share_version

    # Create 5 shares where 2 start with 0x01 (40%)
    parts_40 = [
        bytearray([0x01, 0x42, 0x10]),
        bytearray([0x01, 0x43, 0x20]),
        bytearray([0x55, 0x44, 0x30]),
        bytearray([0x66, 0x45, 0x40]),
        bytearray([0x77, 0x46, 0x50]),
    ]

    # Should raise error (40% suggests intentional mixing)
    with pytest.raises(ValueError, match=Error.MIXED_SHARE_VERSIONS):
        _detect_share_version(parts_40)

    # Create 5 shares where 2.5 start with 0x01 (50%)
    parts_50 = [
        bytearray([0x01, 0x42, 0x10]),
        bytearray([0x01, 0x43, 0x20]),
        bytearray([0x55, 0x44, 0x30]),
        bytearray([0x66, 0x45, 0x40]),
        bytearray([0x77, 0x46, 0x50]),
        bytearray([0x01, 0x47, 0x60]),
    ]

    # 3 out of 6 = 50%, should raise error
    with pytest.raises(ValueError, match=Error.MIXED_SHARE_VERSIONS):
        _detect_share_version(parts_50)

    # Create 10 shares where 5 start with 0x01 (50%)
    parts_50_large = [
        bytearray([0x01, 0x42, 0x10]),
        bytearray([0x01, 0x43, 0x20]),
        bytearray([0x01, 0x44, 0x30]),
        bytearray([0x01, 0x45, 0x40]),
        bytearray([0x01, 0x46, 0x50]),
        bytearray([0x55, 0x47, 0x60]),
        bytearray([0x66, 0x48, 0x70]),
        bytearray([0x77, 0x49, 0x80]),
        bytearray([0x88, 0x4A, 0x90]),
        bytearray([0x99, 0x4B, 0xA0]),
    ]

    # Should raise error (50% suggests intentional mixing)
    with pytest.raises(ValueError, match=Error.MIXED_SHARE_VERSIONS):
        _detect_share_version(parts_50_large)


def test_version_detection_two_shares_ambiguous() -> None:
    """Test that 2 shares with 50% split are treated as legacy (ambiguous case)."""
    from shamir import _detect_share_version

    # Create 2 shares where 1 starts with 0x01 (50%)
    parts = [
        bytearray([0x01, 0x42, 0x10]),
        bytearray([0x55, 0x43, 0x20]),
    ]

    # With only 2 shares, 50% is ambiguous (could be false positive)
    # Should treat as legacy version 0
    assert _detect_share_version(parts) == 0


def test_version_detection_legacy_secret_starting_with_01() -> None:
    """Test that legacy shares are correctly detected even when secret starts with 0x01.

    This is the critical edge case: when a legacy share's first y-value is 0x01,
    it could be misdetected as version 1. The length-based heuristic prevents this.
    """
    from shamir import _detect_share_version

    # Single-byte secret 0x01 creates 2-byte legacy shares: [0x01, x_coord]
    # Both shares start with 0x01 (the y-value), but length proves they're legacy
    secret = b"\x01"
    parts = split(secret, 3, 2, version=0, rng=Random(42))

    # All shares should start with some y-value and end with x-coord
    # Some/all may start with 0x01 if that's the y-value
    assert len(parts[0]) == 2  # Legacy format: [y_value, x_coord]

    # Detection should correctly identify as legacy based on length
    assert _detect_share_version(parts) == 0

    # Should reconstruct correctly
    reconstructed = combine(parts[:2])
    assert reconstructed == secret

    # Multi-byte secret starting with 0x01
    secret2 = b"\x01\x00\xFF"
    parts2 = split(secret2, 3, 2, version=0, rng=Random(42))

    # All shares should be 4 bytes: [y0=0x01, y1, y2, x_coord]
    assert len(parts2[0]) == 4

    # Detection should correctly identify as legacy
    # (even though first byte of all shares is 0x01)
    assert _detect_share_version(parts2) == 0

    # Should reconstruct correctly
    reconstructed2 = combine(parts2[:2])
    assert reconstructed2 == secret2


def test_version_detection_ambiguous_3byte_shares() -> None:
    """Test handling of ambiguous 3-byte shares.

    3-byte shares where all start with 0x01 are fundamentally ambiguous:
    - Could be version 1 with 1-byte secret: [0x01, y0, x_coord]
    - Could be legacy with 2-byte secret starting with 0x01: [0x01, y1, x_coord]

    The detection defaults to legacy to avoid false positives for legacy shares.
    For version 1 single-byte secrets, users MUST use explicit version=1 parameter.
    """
    # Legacy 2-byte secret starting with 0x01
    secret_v0 = b"\x01\x00"
    parts_v0 = split(secret_v0, 3, 2, version=0, rng=Random(42))
    assert len(parts_v0[0]) == 3  # [y0=0x01, y1, x_coord]

    # Auto-detection defaults to legacy (conservative)
    reconstructed_v0 = combine(parts_v0[:2])
    assert reconstructed_v0 == secret_v0

    # Version 1 single-byte secret
    secret_v1 = b"\x42"
    parts_v1 = split(secret_v1, 3, 2, version=1, rng=Random(42))
    assert len(parts_v1[0]) == 3  # [version=0x01, y0, x_coord]

    # Auto-detection FAILS for 3-byte version 1 shares (ambiguous case)
    # All start with 0x01, but detection defaults to legacy
    # This is a documented limitation

    # Explicit version parameter always works (100% reliable)
    assert combine(parts_v0[:2], version=0) == secret_v0
    assert combine(parts_v1[:2], version=1) == secret_v1

    # For 2-byte secrets (4-byte shares), auto-detection works fine
    secret_v1_2byte = b"\x42\x43"
    parts_v1_2byte = split(secret_v1_2byte, 3, 2, version=1, rng=Random(42))
    assert len(parts_v1_2byte[0]) == 4  # [version=0x01, y0, y1, x_coord]

    # Auto-detection works for 4+ byte shares
    reconstructed_v1_2byte = combine(parts_v1_2byte[:2])
    assert reconstructed_v1_2byte == secret_v1_2byte
