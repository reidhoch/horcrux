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

    def test_detect_perfectly_mixed_versions_three_shares(self) -> None:
        """Test that perfectly mixed v0/v1 shares (3+ shares) raise error.

        With 3+ shares in a ~50/50 split, we can reliably detect intentional
        mixing. With only 2 shares, a 50/50 split is ambiguous and cannot be
        distinguished from v0 shares where one y-value happens to be 0x01.
        """
        # Create v1 shares for a 2-byte secret
        secret = b"XY"
        v1_parts = split(secret, 5, 3, rng=Random(123), version=1)

        # Craft fake "legacy-like" shares by replacing the version byte (0x01)
        # v1 format: [0x01, y1, y2, x]
        # fake v0: [0x42, y1, y2, x] (looks like legacy because first byte != 0x01)
        fake_v0_part1 = bytearray(v1_parts[1])
        fake_v0_part1[0] = 0x42
        fake_v0_part2 = bytearray(v1_parts[2])
        fake_v0_part2[0] = 0x43

        # Mix: 2 v1 shares + 2 fake v0 shares = 4 shares with 50/50 split
        mixed_parts = [v1_parts[0], fake_v0_part1, fake_v0_part2, v1_parts[3]]

        # This SHOULD raise MIXED_SHARE_VERSIONS error (ratio = 2/4 = 50%)
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

    def test_two_shares_with_50_percent_ratio_no_error(self) -> None:
        """Test that 2 shares with 50% ratio does NOT raise error.

        With only 2 shares, a 50/50 split is ambiguous and cannot be reliably
        distinguished from v0 shares where one y-value happens to be 0x01.
        The mixing detection only applies to 3+ shares.
        """
        secret = b"XY"
        v1_parts = split(secret, 5, 3, rng=Random(123), version=1)

        # Craft one fake v0 share
        fake_v0_part = bytearray(v1_parts[1])
        fake_v0_part[0] = 0x42

        # Mix: 1 v1 share + 1 fake v0 share = 2 shares with 50% ratio
        mixed_parts = [v1_parts[0], fake_v0_part]

        # This should NOT raise MIXED_SHARE_VERSIONS error (only 2 shares)
        result = combine(mixed_parts)
        assert result is not None  # Just verify it returned something

    def test_ten_shares_with_50_percent_ratio_raises_error(self) -> None:
        """Test that 10 shares with 50% ratio raises MIXED_SHARE_VERSIONS error.

        With 10 shares in a perfect 50/50 split (5 v1, 5 fake v0), this clearly
        indicates intentional mixing rather than random false positives.
        """
        secret = b"XY"
        v1_parts = split(secret, 10, 3, rng=Random(123), version=1)

        # Craft 5 fake v0 shares
        fake_v0_parts = []
        for i in range(5):
            fake_v0_part = bytearray(v1_parts[i + 5])
            fake_v0_part[0] = 0x42 + i
            fake_v0_parts.append(fake_v0_part)

        # Mix: 5 v1 shares + 5 fake v0 shares = 10 shares with 50% ratio
        mixed_parts = v1_parts[:5] + fake_v0_parts

        # This SHOULD raise MIXED_SHARE_VERSIONS error (ratio = 5/10 = 50%)
        with pytest.raises(
            ValueError,
            match=Error.MIXED_SHARE_VERSIONS,
        ):
            combine(mixed_parts)

    def test_five_shares_with_40_percent_ratio_raises_error(self) -> None:
        """Test that 5 shares with 40% ratio raises MIXED_SHARE_VERSIONS error.

        With 5 shares where 2 are v1 (40%), this is at the lower boundary
        of the 40%-60% detection range and should raise an error.
        """
        secret = b"XY"
        v1_parts = split(secret, 5, 3, rng=Random(123), version=1)

        # Craft 3 fake v0 shares
        fake_v0_parts = []
        for i in range(3):
            fake_v0_part = bytearray(v1_parts[i + 2])
            fake_v0_part[0] = 0x42 + i
            fake_v0_parts.append(fake_v0_part)

        # Mix: 2 v1 shares + 3 fake v0 shares = 5 shares with 40% ratio
        mixed_parts = [v1_parts[0], v1_parts[1]] + fake_v0_parts

        # This SHOULD raise MIXED_SHARE_VERSIONS error (ratio = 2/5 = 40%)
        with pytest.raises(
            ValueError,
            match=Error.MIXED_SHARE_VERSIONS,
        ):
            combine(mixed_parts)

    def test_five_shares_with_60_percent_ratio_no_error(self) -> None:
        """Test that 5 shares with 60% ratio uses majority voting.

        With 5 shares where 3 are v1 (60%), this is at the upper boundary
        (exclusive) of the 40%-60% detection range. Since ratio >= 0.60,
        it should use majority voting for version 1 instead of raising an error.
        """
        secret = b"XY"
        v1_parts = split(secret, 5, 3, rng=Random(123), version=1)

        # Craft 2 fake v0 shares
        fake_v0_part1 = bytearray(v1_parts[3])
        fake_v0_part1[0] = 0x42
        fake_v0_part2 = bytearray(v1_parts[4])
        fake_v0_part2[0] = 0x43

        # Mix: 3 v1 shares + 2 fake v0 shares = 5 shares with 60% ratio
        mixed_parts = [
            v1_parts[0],
            v1_parts[1],
            v1_parts[2],
            fake_v0_part1,
            fake_v0_part2,
        ]

        # This should NOT raise MIXED_SHARE_VERSIONS error (ratio = 3/5 = 60%)
        # It will use majority voting for version 1
        result = combine(mixed_parts)
        assert result is not None  # Just verify it returned something

    def test_exactly_one_share_starts_with_01(self) -> None:
        """Test detection when exactly 1 out of many shares starts with 0x01.

        This tests the boundary between "none start with 0x01" and
        "some start with 0x01" logic. With only 1 out of 5 shares (20%),
        it should be detected as legacy with a false positive.
        """
        secret = b"XY"
        v1_parts = split(secret, 5, 3, rng=Random(123), version=1)

        # Craft 4 fake v0 shares (80% fake v0)
        fake_v0_parts = []
        for i in range(4):
            fake_v0_part = bytearray(v1_parts[i + 1])
            fake_v0_part[0] = 0x42 + i
            fake_v0_parts.append(fake_v0_part)

        # Mix: 1 v1 share + 4 fake v0 shares = 5 shares with 20% ratio
        mixed_parts = [v1_parts[0]] + fake_v0_parts

        # This should NOT raise MIXED_SHARE_VERSIONS error (ratio = 1/5 = 20% < 40%)
        # It will be detected as version 0 (legacy)
        result = combine(mixed_parts)
        assert result is not None  # Just verify it returned something
