"""Property-based and security tests for Shamir's Secret Sharing."""

from random import Random

import pytest

from shamir import combine, split


class TestSecurityProperties:
    """Test security properties and invariants."""

    def test_information_theoretic_security(self) -> None:
        """Test that insufficient parts reveal no information about the secret.

        Key property: Given any k-1 shares, for ANY possible secret value,
        there exists a valid kth share that would reconstruct to that secret.
        This proves k-1 shares reveal zero information.

        We demonstrate this by:
        1. Taking k-1 shares from a polynomial for secret A
        2. Computing what the kth share must be to reconstruct to target secret B
        3. Verifying that reconstruction works for ANY target secret B
        """

        threshold = 3
        original_secret = b"X"  # Single byte: 0x58 (88 decimal)

        # Create shares for the original secret
        parts = split(original_secret, 5, threshold, rng=Random(12345))

        # Take k-1 shares (insufficient for unique reconstruction)
        insufficient_parts = parts[: threshold - 1]
        assert len(insufficient_parts) == 2  # For threshold=3

        # Extract x-coordinates from insufficient parts
        x_coords_insufficient = [part[-1] for part in insufficient_parts]

        # Choose an x-coordinate for our "completing" share (must be different)
        x_complete = 100
        while x_complete in x_coords_insufficient:
            x_complete = (x_complete + 1) % 256
            if x_complete == 0:
                x_complete = 1  # Skip 0, use 1-255

        # Now demonstrate: for ANY target secret, we can compute a completing share
        for target_byte in [0, 42, 88, 128, 200, 255]:
            target_secret = bytes([target_byte])

            # For each byte position in the secret, compute what y-value is needed
            # at x_complete to make interpolation give us target_secret
            #
            # Mathematical insight: Given k-1 points and a target f(0) = target,
            # we can solve for the kth point using the interpolation formula

            # We'll compute the required y-value using Lagrange interpolation
            # We want: interpolate([x1, x2, x_complete], [y1, y2, y_needed], 0) = target

            # Get the y-values from insufficient parts (for first byte of secret)
            # Share format is [y_values..., x_coord]
            y_insufficient = [part[0] for part in insufficient_parts]

            # We need to solve for y_needed such that interpolation at x=0 gives target
            # Using the property: L(0) = sum over i of (y_i * lagrange_basis_i(0))
            #
            # IMPORTANT: The Lagrange basis for point i when we have ALL k points is:
            # l_i(0) = product over all j≠i of (0 - x_j) / (x_i - x_j)
            #        = product over all j≠i of (-x_j) / (x_i - x_j)
            # This includes the completing point in the product!

            from shamir.math import add, div, mul

            # Collect all x-coordinates (including the completing one)
            all_x_coords = x_coords_insufficient + [x_complete]

            # Compute sum of y_i * l_i(0) for the insufficient parts
            # Note: l_i(0) now includes x_complete in the product
            partial_sum = 0
            for x_i, y_i in zip(x_coords_insufficient, y_insufficient):
                # Compute l_i(0) = product over ALL other x-coords (including x_complete)
                lagrange_basis = 1
                for x_j in all_x_coords:
                    if x_i != x_j:
                        # In GF(256), -x_j = x_j (since a + a = 0)
                        numerator = x_j  # This is -x_j in GF(256)
                        denominator = add(x_i, x_j)  # This is x_i - x_j in GF(256)
                        lagrange_basis = mul(
                            lagrange_basis, div(numerator, denominator)
                        )

                partial_sum = add(partial_sum, mul(y_i, lagrange_basis))

            # Now compute l_complete(0) for the completing share
            # This is the product over all OTHER x-coordinates (the insufficient ones)
            lagrange_basis_complete = 1
            for x_j in x_coords_insufficient:
                numerator = x_j  # -x_j in GF(256)
                denominator = add(x_complete, x_j)  # x_complete - x_j
                lagrange_basis_complete = mul(
                    lagrange_basis_complete, div(numerator, denominator)
                )

            # Solve for y_needed: target = partial_sum + y_needed * lagrange_basis_complete
            # => y_needed = (target - partial_sum) / lagrange_basis_complete
            target_value = target_byte
            difference = add(target_value, partial_sum)  # subtraction in GF(256)
            y_needed = div(difference, lagrange_basis_complete)

            # Construct the completing share with the computed y-value
            # Share format: [y_value, x_coord]
            completing_share = bytearray([y_needed, x_complete])

            # Verify: combining insufficient parts + completing share reconstructs target
            all_parts = insufficient_parts + [completing_share]
            reconstructed = combine(all_parts)

            assert reconstructed == target_secret, (
                f"Failed to reconstruct target {target_byte} from insufficient parts. "
                f"Got {reconstructed[0]} instead."
            )

        # Success! We've proven that the same k-1 shares can reconstruct to ANY
        # secret by choosing an appropriate kth share. Therefore, k-1 shares
        # reveal ZERO information about which secret was originally used.

    def test_randomness_quality(self) -> None:
        """Test that splits with same parameters but different RNG are different."""
        secret = b"randomness_test"

        splits = []
        for seed in range(10):
            parts = split(secret, 5, 3, rng=Random(seed))
            splits.append(parts)

        # All splits should be different
        for i, split1 in enumerate(splits):
            for j, split2 in enumerate(splits):
                if i != j:
                    assert split1 != split2, f"Splits {i} and {j} are identical"

    def test_avalanche_effect(self) -> None:
        """Test that small changes in secret produce different parts."""
        base_secret = b"avalanche_test_message"

        # Create variations with single bit flips
        variations = []
        for i in range(len(base_secret)):
            modified = bytearray(base_secret)
            modified[i] ^= 1  # Flip least significant bit
            variations.append(bytes(modified))

        # Split each variation
        base_parts = split(base_secret, 5, 3, rng=Random(123))

        for variation in variations:
            var_parts = split(variation, 5, 3, rng=Random(123))
            # Parts should be different for different secrets
            assert var_parts != base_parts
            # But each should reconstruct correctly
            assert combine(var_parts[:3]) == variation

    def test_no_information_leakage_from_part_count(self) -> None:
        """Test that the number of parts doesn't leak secret information."""
        secrets = [b"a", b"ab", b"abc", b"abcd"]

        for secret in secrets:
            parts = split(secret, 5, 3, rng=Random(456))
            assert len(parts) == 5  # Should always be the requested number
            for part in parts:
                # Part length should be secret length + 1 (y-values + x-coordinate)
                assert len(part) == len(secret) + 1


class TestErrorConditions:
    """Test comprehensive error conditions and edge cases."""

    def test_combine_error_messages(self) -> None:
        """Test that error messages are exactly as expected."""
        # Test empty parts list
        with pytest.raises(
            ValueError,
            match="At least two parts are required to reconstruct the secret",
        ):
            combine([])

        # Test single part
        with pytest.raises(
            ValueError,
            match="At least two parts are required to reconstruct the secret",
        ):
            combine([bytearray(b"single")])

        # Test parts too short
        with pytest.raises(ValueError, match="Parts must be at least two bytes"):
            combine([bytearray(b"a"), bytearray(b"b")])

        # Test mismatched lengths
        with pytest.raises(ValueError, match="All parts must be the same length"):
            combine([bytearray(b"abc"), bytearray(b"ab")])

        # Test duplicate parts (same x-coordinate)
        part1 = bytearray(b"abc")
        part2 = bytearray(b"abc")  # Same content = same x-coordinate
        with pytest.raises(ValueError, match="Duplicate part detected"):
            combine([part1, part2])

    def test_split_error_messages(self) -> None:
        """Test that split error messages are exactly as expected."""
        secret = b"test"

        # Test parts < threshold
        with pytest.raises(ValueError, match="Parts cannot be less than threshold"):
            split(secret, 2, 3)

        # Test parts > 255
        with pytest.raises(ValueError, match="Parts cannot exceed 255"):
            split(secret, 256, 3)

        # Test threshold > 255
        with pytest.raises(ValueError, match="Threshold cannot exceed 255"):
            split(secret, 254, 256)  # Both exceed 255

        # Test threshold < 2
        with pytest.raises(ValueError, match="Threshold must be at least 2"):
            split(secret, 5, 1)

        # Test empty secret
        with pytest.raises(ValueError, match="Cannot split an empty secret"):
            split(b"", 3, 2)

    def test_boundary_values(self) -> None:
        """Test boundary values for parameters."""
        secret = b"boundary_test"

        # Minimum valid values
        parts = split(secret, 2, 2, rng=Random(123))
        assert len(parts) == 2
        reconstructed = combine(parts)
        assert reconstructed == secret

        # Test with a reasonable high number (avoiding collision issues)
        parts = split(secret, 20, 20, rng=Random(456))
        assert len(parts) == 20
        reconstructed = combine(parts)
        assert reconstructed == secret

        # Maximum valid values (parts=255 and threshold=255 are both accepted)
        # Test parts=255 with lower threshold
        parts_max = split(secret, 255, 3, rng=Random(789))
        assert len(parts_max) == 255
        reconstructed_max = combine(parts_max[:3])
        assert reconstructed_max == secret

        # Test threshold=255 (must also have parts=255)
        parts_max_threshold = split(secret, 255, 255, rng=Random(999))
        assert len(parts_max_threshold) == 255
        reconstructed_max_threshold = combine(parts_max_threshold)
        assert reconstructed_max_threshold == secret
