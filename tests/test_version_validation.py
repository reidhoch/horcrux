"""Tests for version parameter validation and mixed version detection."""

from random import Random

import pytest

from shamir import combine, split
from shamir.errors import Error


class TestVersionValidation:
    """Test version parameter validation in split and combine."""

    def test_combine_with_invalid_version_parameter(self) -> None:
        """Test that combine() raises ValueError for unsupported version numbers."""
        secret = b"test_secret"
        parts = split(secret, 5, 3, rng=Random(123))

        # Test with various invalid version numbers
        invalid_versions = [2, 3, -1, 10, 255]

        for invalid_version in invalid_versions:
            with pytest.raises(
                ValueError,
                match=Error.UNSUPPORTED_SHARE_VERSION,
            ):
                combine(parts, version=invalid_version)

    def test_split_with_invalid_version_parameter(self) -> None:
        """Test that split() raises ValueError for unsupported version numbers."""
        secret = b"test_secret"

        # Test with various invalid version numbers
        invalid_versions = [2, 3, -1, 10, 255]

        for invalid_version in invalid_versions:
            with pytest.raises(
                ValueError,
                match=Error.UNSUPPORTED_SHARE_VERSION,
            ):
                split(secret, 5, 3, rng=Random(123), version=invalid_version)


class TestMixedVersionDetection:
    """Test detection of intentionally mixed share versions.

    Note: To test version detection, we craft shares with the same length
    but different version indicators. Natural v0/v1 shares have different
    lengths and would fail the length check before version detection.
    """

    def test_detect_perfectly_mixed_versions_two_shares(self) -> None:
        """Test that perfectly mixed v0/v1 shares (2 shares) raise error.

        When we have exactly 2 shares and one is v0 and one is v1,
        we have a perfect tie (v1_votes=1, legacy_votes=1), which indicates
        intentional mixing rather than corruption.
        """
        # Create v1 shares for a 2-byte secret
        secret = b"XY"
        v1_parts = split(secret, 3, 2, rng=Random(123), version=1)

        # Craft a "legacy-like" share by replacing the version byte (0x01) with
        # a different value (e.g., 0x42). This simulates a legacy share that
        # happens to have the same length as a v1 share.
        # v1 format: [0x01, y1, y2, x]
        # fake v0: [0x42, y1, y2, x] (looks like legacy because first byte != 0x01)
        fake_v0_part = bytearray(v1_parts[1])  # Copy a v1 share
        fake_v0_part[0] = 0x42  # Change version byte to simulate legacy

        # Mix: 1 real v1 share + 1 fake v0 share (50/50 split)
        mixed_parts = [v1_parts[0], fake_v0_part]

        # This SHOULD raise MIXED_SHARE_VERSIONS error
        with pytest.raises(
            ValueError,
            match=Error.MIXED_SHARE_VERSIONS,
        ):
            combine(mixed_parts)

    def test_mostly_v1_with_one_fake_v0_no_error(self) -> None:
        """Test that mostly v1 shares with one fake v0 uses majority voting.

        When we have 2v1 + 1v0 (sample_size=3), it's not a perfect tie,
        so it should use majority voting and not raise MIXED_SHARE_VERSIONS.
        """
        secret = b"XY"
        v1_parts = split(secret, 5, 3, rng=Random(123), version=1)

        # Craft a fake v0 share
        fake_v0_part = bytearray(v1_parts[2])
        fake_v0_part[0] = 0x42  # Simulate legacy share

        # Mix: 2 v1 shares + 1 fake v0 share (not a tie)
        mixed_parts = [v1_parts[0], v1_parts[1], fake_v0_part, v1_parts[3], v1_parts[4]]

        # This should NOT raise MIXED_SHARE_VERSIONS error
        # It will use majority voting (2 v1 votes vs 1 v0 vote) -> detects as v1
        # The result will be garbage because fake_v0_part is corrupted,
        # but no error should be raised about mixing
        result = combine(mixed_parts)
        assert result is not None  # Just verify it returned something

    def test_mostly_fake_v0_with_one_v1_no_error(self) -> None:
        """Test that mostly fake v0 shares with one v1 uses majority voting."""
        secret = b"XY"
        v1_parts = split(secret, 5, 3, rng=Random(123), version=1)

        # Craft fake v0 shares
        fake_v0_part1 = bytearray(v1_parts[1])
        fake_v0_part1[0] = 0x42
        fake_v0_part2 = bytearray(v1_parts[2])
        fake_v0_part2[0] = 0x43

        # Mix: 1 v1 share + 2 fake v0 shares (not a tie)
        mixed_parts = [
            v1_parts[0],
            fake_v0_part1,
            fake_v0_part2,
            v1_parts[3],
            v1_parts[4],
        ]

        # This should NOT raise MIXED_SHARE_VERSIONS error
        # It will use majority voting (1 v1 vote vs 2 v0 votes) -> detects as v0
        result = combine(mixed_parts)
        assert result is not None  # Just verify it returned something
