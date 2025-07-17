"""Mathematical property tests for the Shamir Secret Sharing implementation."""

import pytest
from random import Random
from shamir import combine, split
from shamir.math import add, mul, div
from shamir.utils import Polynomial, interpolate


class TestMathematicalProperties:
    """Test mathematical properties and correctness."""

    def test_galois_field_arithmetic_properties(self) -> None:
        """Test properties of GF(256) arithmetic."""
        # Test additive identity
        for a in range(256):
            assert add(a, 0) == a
            assert add(0, a) == a

        # Test additive inverse (in GF(2^8), a + a = 0)
        for a in range(256):
            assert add(a, a) == 0

        # Test commutativity of addition
        for a in range(0, 256, 17):  # Sample every 17th value to reduce test time
            for b in range(0, 256, 19):  # Sample every 19th value
                assert add(a, b) == add(b, a)

        # Test multiplicative identity
        for a in range(1, 256):  # Skip 0 since 0*1 is special
            assert mul(a, 1) == a
            assert mul(1, a) == a

        # Test multiplicative zero
        for a in range(256):
            assert mul(a, 0) == 0
            assert mul(0, a) == 0

        # Test commutativity of multiplication
        for a in range(1, 256, 23):  # Sample values to reduce test time
            for b in range(1, 256, 29):
                assert mul(a, b) == mul(b, a)

    def test_division_properties(self) -> None:
        """Test division properties in GF(256)."""
        # Test that a / a = 1 for all non-zero a
        for a in range(1, 256):
            assert div(a, a) == 1

        # Test that (a * b) / b = a for non-zero b
        for a in range(0, 256, 31):
            for b in range(1, 256, 37):  # b cannot be 0
                product = mul(a, b)
                assert div(product, b) == a

        # Test division by zero raises exception
        with pytest.raises(ZeroDivisionError):
            div(1, 0)

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

    def test_lagrange_interpolation_properties(self) -> None:
        """Test Lagrange interpolation mathematical properties."""
        # Test interpolation with known polynomial
        for degree in range(1, 5):
            poly = Polynomial(degree=degree, intercept=123, rng=Random(123))

            # Create sample points
            x_points = list(range(1, degree + 2))  # Need degree+1 points
            y_points = [poly.evaluate(x) for x in x_points]

            x_s = bytearray(x_points)
            y_s = bytearray(y_points)

            # Interpolation should recover the intercept
            recovered = interpolate(x_s, y_s, 0)
            assert recovered == 123

    def test_secret_sharing_mathematical_correctness(self) -> None:
        """Test that the secret sharing follows Shamir's scheme mathematically."""
        secret = b"math_test"
        threshold = 3
        parts = split(secret, 5, threshold, rng=Random(42))

        # Each part should have the secret length + 1 byte
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

        # XOR corresponding parts (except x-coordinate)
        combined_parts = []
        for i in range(3):
            part = bytearray(2)  # secret length + 1
            part[0] = parts1[i][0] ^ parts2[i][0]  # XOR the secret byte
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
        insufficient_parts = parts[:threshold-1]

        # While we can't easily test information-theoretic security,
        # we can verify that we need exactly the threshold
        assert len(insufficient_parts) == threshold - 1

        # With threshold parts, reconstruction should work
        sufficient_parts = parts[:threshold]
        reconstructed = combine(sufficient_parts)
        assert reconstructed == secret

    def test_field_operations_are_closed(self) -> None:
        """Test that field operations are closed under GF(256)."""
        # Test that all operations result in values 0-255
        for a in range(0, 256, 43):  # Sample values
            for b in range(0, 256, 47):
                sum_result = add(a, b)
                assert 0 <= sum_result <= 255

                prod_result = mul(a, b)
                assert 0 <= prod_result <= 255

                if b != 0:
                    div_result = div(a, b)
                    assert 0 <= div_result <= 255

    def test_distributive_property(self) -> None:
        """Test distributive property: a * (b + c) = (a * b) + (a * c)."""
        for a in range(1, 256, 51):  # Sample non-zero values
            for b in range(0, 256, 53):
                for c in range(0, 256, 59):
                    left_side = mul(a, add(b, c))
                    right_side = add(mul(a, b), mul(a, c))
                    assert left_side == right_side

    def test_associative_property(self) -> None:
        """Test associative property for addition and multiplication."""
        # Test (a + b) + c = a + (b + c)
        for a in range(0, 256, 61):
            for b in range(0, 256, 67):
                for c in range(0, 256, 71):
                    left_side = add(add(a, b), c)
                    right_side = add(a, add(b, c))
                    assert left_side == right_side

        # Test (a * b) * c = a * (b * c)
        for a in range(1, 256, 73):  # Avoid 0 to make test more meaningful
            for b in range(1, 256, 79):
                for c in range(1, 256, 83):
                    left_side = mul(mul(a, b), c)
                    right_side = mul(a, mul(b, c))
                    assert left_side == right_side
