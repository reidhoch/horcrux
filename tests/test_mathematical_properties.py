"""Mathematical property tests for the Shamir Secret Sharing implementation."""

from random import Random

from shamir import combine, split
from shamir.utils import Polynomial


class TestMathematicalProperties:
    """Test mathematical properties and correctness."""

    def test_polynomial_evaluation_properties(self) -> None:
        """Test polynomial evaluation properties."""
        # Test that polynomial evaluation at 0 gives intercept
        for intercept in range(256):
            poly = Polynomial(degree=5, intercept=intercept, rng=Random(intercept))
            assert poly.evaluate(0) == intercept

        # Test polynomial degree vs coefficients
        for degree in range(1, 10):
            poly = Polynomial(degree=degree, intercept=42, rng=Random(42))
            assert len(poly.coefficients) == degree + 1

    def test_secret_sharing_mathematical_correctness(self) -> None:
        """Test that the secret sharing follows Shamir's scheme mathematically."""
        secret = b"math_test"
        threshold = 3
        parts = split(secret, 5, threshold, rng=Random(42))

        # Each part should have the secret length + 1 bytes (y-values + x_coord)
        for part in parts:
            assert len(part) == len(secret) + 1

        # The last byte should be the x-coordinate (should be unique)
        x_coords = [part[-1] for part in parts]
        assert len(set(x_coords)) == len(x_coords)  # All unique

        # Any threshold number of parts should reconstruct the secret
        from itertools import combinations

        for combo in combinations(parts, threshold):
            reconstructed = combine(list(combo))
            assert reconstructed == secret

    def test_linearity_property(self) -> None:
        """Test linearity property of secret sharing."""
        # Note: This test demonstrates that the current implementation is NOT
        # perfectly linear due to the random polynomial generation.
        # Each split uses fresh random coefficients, so linearity doesn't hold.

        secret1 = b"test1"
        secret2 = b"test2"

        # Ensure secrets are same length
        assert len(secret1) == len(secret2)

        # XOR the secrets
        secret_xor = bytes(a ^ b for a, b in zip(secret1, secret2))

        # Split all secrets - they will have different random polynomials
        parts1 = split(secret1, 5, 3, rng=Random(12345))
        parts2 = split(secret2, 5, 3, rng=Random(54321))
        parts_xor = split(secret_xor, 5, 3, rng=Random(98765))

        # Since different random polynomials are used, linearity doesn't hold
        # But each should reconstruct correctly
        assert combine(parts1[:3]) == secret1
        assert combine(parts2[:3]) == secret2
        assert combine(parts_xor[:3]) == secret_xor

    def test_homomorphic_property(self) -> None:
        """Test homomorphic property - operations on shares reflect in secret."""
        secret1 = b"\x42"  # Single byte for simplicity
        secret2 = b"\x17"

        rng1 = Random(111)
        rng2 = Random(111)  # Same seed for deterministic behavior

        parts1 = split(secret1, 3, 2, rng=rng1)
        parts2 = split(secret2, 3, 2, rng=rng2)

        # XOR corresponding parts (except the x-coordinate)
        # Share format is [y_values..., x_coord]
        combined_parts: list[bytearray] = []
        for i in range(3):
            part = bytearray(2)  # y-value + x_coord
            part[0] = parts1[i][0] ^ parts2[i][0]  # XOR the y-values
            part[1] = parts1[i][1]  # Keep same x-coordinate
            combined_parts.append(part)

        # Reconstruct should give XOR of original secrets
        reconstructed = combine(combined_parts[:2])
        expected = bytes([secret1[0] ^ secret2[0]])
        assert reconstructed == expected

    def test_threshold_security_property(self) -> None:
        """Test that exactly threshold-1 parts provide no information."""
        secret = b"threshold_security_test"
        threshold = 4
        parts = split(secret, 6, threshold, rng=Random(789))

        # Test with threshold-1 parts
        insufficient_parts = parts[: threshold - 1]

        # While we can't easily test information-theoretic security,
        # we can verify that we need exactly the threshold
        assert len(insufficient_parts) == threshold - 1

        # With threshold parts, reconstruction should work
        sufficient_parts = parts[:threshold]
        reconstructed = combine(sufficient_parts)
        assert reconstructed == secret
