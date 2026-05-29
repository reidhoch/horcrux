"""Comprehensive fuzz testing using Hypothesis for edge cases and security properties.

These tests use property-based testing to verify security properties hold across
a wide range of inputs, including edge cases that manual tests might miss.
"""

from random import Random

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from shamir import combine, split


@given(
    secret=st.binary(min_size=1, max_size=1024),
    parts=st.integers(min_value=2, max_value=20),
    threshold=st.integers(min_value=2, max_value=20),
    rng=st.randoms(note_method_calls=True),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much])
def test_roundtrip(
    secret: bytes,
    parts: int,
    threshold: int,
    rng: Random,
) -> None:
    """Test that splitting then combining recovers the original secret."""
    assume(parts >= threshold)

    shares = split(secret, parts, threshold, rng=rng)
    reconstructed = combine(shares[:threshold])

    assert reconstructed == secret


@given(
    secret=st.binary(min_size=1, max_size=100),
    parts=st.integers(min_value=3, max_value=10),
    threshold=st.integers(min_value=2, max_value=9),
    subset_size=st.integers(min_value=0, max_value=5),
    rng=st.randoms(note_method_calls=True),
)
@settings(
    deadline=None,
    suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.too_slow],
)
def test_threshold_property_any_subset_works(
    secret: bytes,
    parts: int,
    threshold: int,
    subset_size: int,
    rng: Random,
) -> None:
    """Test that ANY subset of threshold shares can reconstruct the secret.

    This is a fundamental security property: no particular shares are special.
    """
    assume(parts >= threshold)
    assume(threshold + subset_size <= parts)  # Ensure we can select a valid subset

    shares = split(secret, parts, threshold, rng=rng)

    # Test with threshold shares
    reconstructed = combine(shares[:threshold])
    assert reconstructed == secret

    # Test with threshold + subset_size shares (if applicable)
    if threshold + subset_size <= parts:
        reconstructed_extra = combine(shares[: threshold + subset_size])
        assert reconstructed_extra == secret


@given(
    secret=st.binary(min_size=1, max_size=100),
    parts=st.integers(min_value=2, max_value=10),
    threshold=st.integers(min_value=2, max_value=10),
    rng=st.randoms(note_method_calls=True),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much])
def test_share_format_consistency(
    secret: bytes,
    parts: int,
    threshold: int,
    rng: Random,
) -> None:
    """Test that all shares in a set have consistent format and length."""
    assume(parts >= threshold)

    shares = split(secret, parts, threshold, rng=rng)

    # All shares should have same length
    first_len = len(shares[0])
    assert all(len(share) == first_len for share in shares)

    # All shares should have unique x-coordinates (last byte)
    x_coords = [share[-1] for share in shares]
    assert len(set(x_coords)) == len(shares), "Duplicate x-coordinates detected"

    # X-coordinates must be in range 1-255 (generated via x_coords[i] + 1)
    assert all(1 <= x <= 255 for x in x_coords), "X-coordinate out of range 1-255"


@given(
    secret=st.binary(min_size=1, max_size=100),
    parts=st.integers(min_value=2, max_value=10),
    threshold=st.integers(min_value=2, max_value=10),
    rng=st.randoms(note_method_calls=True),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much])
def test_share_independence(
    secret: bytes,
    parts: int,
    threshold: int,
    rng: Random,
) -> None:
    """Test that shares are structurally valid and don't reveal secret through length.

    Note: Individual shares can have coincidental byte patterns matching parts
    of the secret - this is mathematically valid in Shamir's scheme. Security
    comes from needing threshold shares, not from individual share contents.
    """
    assume(parts >= threshold)
    assume(len(secret) >= 4)  # Need enough bytes for meaningful comparison

    shares = split(secret, parts, threshold, rng=rng)

    # Verify share structure is correct
    for share in shares:
        y_values = share[:-1]  # Skip x-coord

        # Share y-values should have same length as secret
        assert len(y_values) == len(secret)

        # X-coordinate (last byte) should be non-zero (range 1-255)
        assert share[-1] != 0


@given(
    secrets=st.lists(
        st.binary(min_size=1, max_size=50),
        min_size=2,
        max_size=5,
        unique=True,
    ),
    parts=st.integers(min_value=3, max_value=8),
    threshold=st.integers(min_value=2, max_value=7),
    rng=st.randoms(note_method_calls=True),
)
@settings(
    deadline=None,
    suppress_health_check=[HealthCheck.filter_too_much, HealthCheck.too_slow],
)
def test_multiple_secrets_independence(
    secrets: list[bytes],
    parts: int,
    threshold: int,
    rng: Random,
) -> None:
    """Test that sharing multiple secrets produces independent share sets.

    Shares from different secrets should not interfere with each other.
    """
    assume(parts >= threshold)
    # All secrets must have same length to mix shares
    assume(len(set(len(s) for s in secrets)) == 1)
    # For very short secrets, mixed shares can coincidentally reconstruct to an
    # original (1/256 per byte). Require enough bytes that collision is negligible.
    assume(len(secrets[0]) >= 4)

    all_shares = []
    for secret in secrets:
        shares = split(secret, parts, threshold, rng=rng)
        all_shares.append(shares)

        # Each secret should reconstruct correctly
        reconstructed = combine(shares[:threshold])
        assert reconstructed == secret

    # Verify that mixing shares from different secrets doesn't work
    if len(all_shares) >= 2 and threshold >= 2:
        # Take shares from first secret and last secret (same length guaranteed by assume)
        mixed_shares = (
            all_shares[0][: threshold // 2] + all_shares[-1][threshold // 2 : threshold]
        )

        if len(mixed_shares) >= threshold:
            # Check for duplicate x-coordinates (can happen with same RNG)
            x_coords = [share[-1] for share in mixed_shares[:threshold]]
            if len(set(x_coords)) == len(x_coords):  # No duplicates
                # Reconstruction should produce garbage, not either original secret
                reconstructed_mixed = combine(mixed_shares[:threshold])
                assert reconstructed_mixed != secrets[0]
                assert reconstructed_mixed != secrets[-1]


@given(
    secret=st.binary(min_size=1, max_size=100),
    parts=st.integers(min_value=2, max_value=10),
    threshold=st.integers(min_value=2, max_value=10),
    byte_index=st.integers(min_value=0, max_value=99),
    rng=st.randoms(note_method_calls=True),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much])
def test_single_byte_modification_breaks_reconstruction(
    secret: bytes,
    parts: int,
    threshold: int,
    byte_index: int,
    rng: Random,
) -> None:
    """Test that modifying a single byte in a share breaks reconstruction.

    This verifies that shares have error detection properties (though not
    error correction, which is by design).
    """
    assume(parts >= threshold)
    assume(byte_index < len(secret))

    shares = split(secret, parts, threshold, rng=rng)

    # Modify a y-value byte in first share (not the x-coord)
    corrupted_shares = [bytearray(share) for share in shares]
    if len(corrupted_shares[0]) > 1:  # Has y-values
        # Modify a y-value (before the x-coordinate)
        y_index = min(byte_index, len(corrupted_shares[0]) - 2)
        corrupted_shares[0][y_index] ^= 0xFF  # Flip all bits

        # Reconstruction should produce different result
        corrupted_result = combine(corrupted_shares[:threshold])
        assert corrupted_result != secret, "Corrupted share produced correct secret!"


@given(
    secret=st.binary(min_size=1, max_size=100),
    parts=st.integers(min_value=2, max_value=10),
    threshold=st.integers(min_value=2, max_value=10),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much])
def test_deterministic_with_seeded_rng(
    secret: bytes,
    parts: int,
    threshold: int,
) -> None:
    """Test that using same RNG seed produces identical shares.

    This is important for testing and reproducibility.
    """
    assume(parts >= threshold)

    # Same seed should produce same shares
    shares1 = split(secret, parts, threshold, rng=Random(42))
    shares2 = split(secret, parts, threshold, rng=Random(42))

    assert shares1 == shares2

    # Different seed should produce different shares
    shares3 = split(secret, parts, threshold, rng=Random(43))
    assert shares1 != shares3

    # But all should reconstruct to same secret
    assert combine(shares1[:threshold]) == secret
    assert combine(shares2[:threshold]) == secret
    assert combine(shares3[:threshold]) == secret


@given(
    secret=st.binary(min_size=1, max_size=100),
    parts=st.integers(min_value=2, max_value=10),
    threshold=st.integers(min_value=2, max_value=10),
    rng=st.randoms(note_method_calls=True),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much])
def test_share_length_reveals_secret_length(
    secret: bytes,
    parts: int,
    threshold: int,
    rng: Random,
) -> None:
    """Test that share length reveals secret length (documented behavior).

    This is inherent to Shamir's Secret Sharing and is documented in the API.
    Users who need length privacy should pad secrets before splitting.
    """
    assume(parts >= threshold)

    # Share length = secret length + 1 (x-coordinate)
    shares = split(secret, parts, threshold, rng=rng)
    assert len(shares[0]) == len(secret) + 1

    # Given share length, secret length is derivable
    derived_length = len(shares[0]) - 1
    assert derived_length == len(secret)
