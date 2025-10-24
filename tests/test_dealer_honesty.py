"""Dealer honesty tests for Shamir's Secret Sharing.

These tests verify that the dealer (split function) creates consistent shares
that all lie on a single polynomial of the correct degree. A dishonest dealer
could create inconsistent shares where different subsets reconstruct to different
secrets, violating the fundamental security properties of the scheme.
"""

import itertools
from random import Random

import pytest
from hypothesis import given
from hypothesis import strategies as st

from shamir import combine, split
from shamir.math import add, div, mul


class TestDealerHonesty:
    """Test that split() produces consistent, valid shares."""

    def test_all_threshold_subsets_reconstruct_same_secret(self) -> None:
        """Test that all threshold-sized subsets reconstruct the original secret.

        This is the fundamental dealer honesty property: if the dealer used a
        consistent polynomial, every threshold-sized subset must reconstruct
        the exact same secret.
        """
        secret = b"Hello, World!"
        threshold = 3
        num_parts = 5

        parts = split(secret, num_parts, threshold, rng=Random(42))

        # Get all possible threshold-sized subsets
        all_subsets = list(itertools.combinations(parts, threshold))

        # Every subset should reconstruct to the same secret
        for subset in all_subsets:
            reconstructed = combine(list(subset))
            assert reconstructed == secret, (
                f"Subset {[p[-1] for p in subset]} reconstructed to different secret"
            )

    def test_all_larger_subsets_reconstruct_same_secret(self) -> None:
        """Test that subsets larger than threshold also work consistently."""
        secret = b"Test"
        threshold = 3
        num_parts = 6

        parts = split(secret, num_parts, threshold, rng=Random(123))

        # Test threshold+1 and threshold+2 sized subsets
        for subset_size in [threshold, threshold + 1, threshold + 2, num_parts]:
            subsets = list(itertools.combinations(parts, subset_size))

            # Sample a few subsets of each size (all would be too many for large sizes)
            sample_size = min(10, len(subsets))
            sampled_subsets = Random(456).sample(subsets, sample_size)

            for subset in sampled_subsets:
                reconstructed = combine(list(subset))
                assert reconstructed == secret, (
                    f"Subset of size {subset_size} reconstructed to different secret"
                )

    @pytest.mark.parametrize(
        ("num_parts", "threshold"),
        [
            (3, 2),  # 2-of-3
            (5, 3),  # 3-of-5
            (7, 4),  # 4-of-7
            (10, 5),  # 5-of-10
        ],
    )
    def test_consistency_across_threshold_configurations(
        self, num_parts: int, threshold: int
    ) -> None:
        """Test dealer honesty for various (k,n) threshold schemes."""
        secret = b"X" * 20
        parts = split(secret, num_parts, threshold, rng=Random(789))

        # Test 5 random threshold-sized subsets
        all_subsets = list(itertools.combinations(parts, threshold))
        sampled_subsets = Random(101112).sample(
            all_subsets, min(5, len(all_subsets))
        )

        for subset in sampled_subsets:
            reconstructed = combine(list(subset))
            assert reconstructed == secret

    @given(
        secret=st.binary(min_size=1, max_size=100),
        num_parts=st.integers(min_value=3, max_value=10),
        threshold=st.integers(min_value=2, max_value=5),
    )
    def test_consistency_property_based(
        self, secret: bytes, num_parts: int, threshold: int
    ) -> None:
        """Property-based test: all threshold subsets must reconstruct same secret.

        Uses Hypothesis to test with random secrets and configurations.
        """
        # Ensure threshold <= num_parts
        if threshold > num_parts:
            threshold = num_parts

        parts = split(secret, num_parts, threshold)

        # Test 3 random threshold-sized subsets
        all_subsets = list(itertools.combinations(parts, threshold))
        num_samples = min(3, len(all_subsets))

        # Use deterministic sampling based on secret for reproducibility
        rng = Random(hash(secret) % (2**32))
        sampled_subsets = rng.sample(all_subsets, num_samples)

        for subset in sampled_subsets:
            reconstructed = combine(list(subset))
            assert reconstructed == secret

    def test_shares_lie_on_single_polynomial(self) -> None:
        """Test that all shares lie on a polynomial of degree (threshold - 1).

        For a single byte secret, verify that shares form a valid polynomial
        by checking that any threshold points uniquely define the polynomial,
        and all other shares lie on that same polynomial.
        """
        secret = b"X"  # Single byte for simplicity
        threshold = 3
        num_parts = 5

        parts = split(secret, num_parts, threshold, rng=Random(999))

        # Extract x and y coordinates for the first byte
        x_coords = [part[-1] for part in parts]
        y_coords = [part[0] for part in parts]

        # Take first threshold points to define the polynomial
        defining_x = x_coords[:threshold]
        defining_y = y_coords[:threshold]

        # Verify remaining points lie on the polynomial defined by first threshold points
        for i in range(threshold, num_parts):
            x_test = x_coords[i]
            y_test = y_coords[i]

            # Compute y_expected using Lagrange interpolation at x_test
            y_expected = 0
            for j in range(threshold):
                x_j = defining_x[j]
                y_j = defining_y[j]

                # Compute Lagrange basis polynomial L_j(x_test)
                lagrange_basis = 1
                for k in range(threshold):
                    if k != j:
                        x_k = defining_x[k]
                        numerator = add(x_test, x_k)
                        denominator = add(x_j, x_k)
                        lagrange_basis = mul(
                            lagrange_basis, div(numerator, denominator)
                        )

                y_expected = add(y_expected, mul(y_j, lagrange_basis))

            assert y_test == y_expected, (
                f"Share {i} (x={x_test}, y={y_test}) does not lie on polynomial "
                f"defined by first {threshold} shares (expected y={y_expected})"
            )

    def test_polynomial_constant_term_equals_secret(self) -> None:
        """Test that the polynomial's constant term f(0) equals the secret.

        This verifies the dealer correctly encoded the secret as the polynomial's
        constant term, which is the standard approach in Shamir's scheme.
        """
        secret = b"A"  # Single byte
        threshold = 3
        num_parts = 5

        parts = split(secret, num_parts, threshold, rng=Random(2468))

        # Extract coordinates for first byte
        x_coords = [part[-1] for part in parts]
        y_coords = [part[0] for part in parts]

        # Use first threshold shares to interpolate f(0)
        x_defining = x_coords[:threshold]
        y_defining = y_coords[:threshold]

        # Compute f(0) using Lagrange interpolation
        f_0 = 0
        for i in range(threshold):
            x_i = x_defining[i]
            y_i = y_defining[i]

            # Compute Lagrange basis L_i(0)
            lagrange_basis = 1
            for j in range(threshold):
                if i != j:
                    x_j = x_defining[j]
                    numerator = x_j  # Since we're evaluating at 0
                    denominator = add(x_i, x_j)
                    lagrange_basis = mul(lagrange_basis, div(numerator, denominator))

            f_0 = add(f_0, mul(y_i, lagrange_basis))

        assert f_0 == secret[0], (
            f"Polynomial constant term f(0)={f_0} does not equal secret byte {secret[0]}"
        )

    def test_different_subsets_have_no_bias(self) -> None:
        """Test that choice of subset doesn't bias the reconstructed secret.

        A dishonest dealer might create shares where certain subsets are more
        likely to succeed or produce specific patterns. This test verifies
        uniform behavior across subset selection.
        """
        secret = b"Sensitive data: 12345"
        threshold = 4
        num_parts = 7

        parts = split(secret, num_parts, threshold, rng=Random(13579))

        # Get all threshold-sized subsets
        all_subsets = list(itertools.combinations(parts, threshold))

        # Track unique reconstruction results
        reconstruction_results = set()

        for subset in all_subsets:
            reconstructed = combine(list(subset))
            reconstruction_results.add(bytes(reconstructed))

        # All subsets must produce the exact same result
        assert len(reconstruction_results) == 1, (
            f"Different subsets produced {len(reconstruction_results)} different "
            f"reconstruction results: {reconstruction_results}"
        )

        # And that result must be the original secret
        assert reconstruction_results.pop() == secret


class TestDishonestDealerDetection:
    """Test that combine() behaves predictably with inconsistent shares.

    These tests verify how the system handles potentially malicious or corrupted
    shares that don't lie on a consistent polynomial.
    """

    def test_inconsistent_shares_produce_wrong_result(self) -> None:
        """Test that manually constructed inconsistent shares don't reconstruct.

        This demonstrates that if someone tries to create inconsistent shares,
        the reconstruction will fail to produce the expected secret (though it
        won't necessarily raise an error, as combine() can't detect dishonesty).
        """
        secret = b"X"
        threshold = 3

        # Create legitimate shares
        parts = split(secret, 5, threshold, rng=Random(24680))

        # Corrupt one share by flipping bits in the y-coordinate
        corrupted_parts = [bytearray(p) for p in parts[:threshold]]
        corrupted_parts[0][0] ^= 0xFF  # Flip all bits in y-coordinate

        # Reconstruction will produce garbage, not the original secret
        reconstructed = combine(corrupted_parts)

        assert reconstructed != secret, (
            "Corrupted shares should not reconstruct to original secret"
        )

    def test_mixing_shares_from_different_splits(self) -> None:
        """Test that mixing shares from different splits produces wrong results.

        If an attacker mixes shares from different split operations (different
        polynomials), the reconstruction should fail to produce either secret.
        """
        secret1 = b"Secret A"
        secret2 = b"Secret B"
        threshold = 3
        num_parts = 5

        parts1 = split(secret1, num_parts, threshold, rng=Random(111))
        parts2 = split(secret2, num_parts, threshold, rng=Random(222))

        # Mix shares: 2 from first split, 1 from second split
        mixed_parts = parts1[:2] + parts2[:1]

        reconstructed = combine(mixed_parts)

        # Should not reconstruct to either original secret
        assert reconstructed != secret1
        assert reconstructed != secret2
