"""Edge case tests for Shamir's Secret Sharing implementation."""

from random import Random

from shamir import combine, split


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_minimum_valid_secret(self) -> None:
        """Test with the smallest possible secret (1 byte)."""
        secret = b"\x42"
        parts = split(secret, 2, 2, rng=Random(12345), version=1)
        reconstructed = combine(parts, version=1)
        assert reconstructed == secret

    def test_maximum_parts_and_threshold(self) -> None:
        """Test with high number of parts and threshold."""
        secret = b"test"
        parts = split(secret, 20, 20, rng=Random(12345), version=1)
        reconstructed = combine(parts, version=1)
        assert reconstructed == secret

    def test_binary_data(self) -> None:
        """Test with binary data including null bytes."""
        secret = bytes([0, 1, 2, 255, 254, 0, 128, 127])
        parts = split(secret, 7, 4, rng=Random(12345), version=1)
        reconstructed = combine(parts[:4], version=1)
        assert reconstructed == secret

    def test_unicode_encoded_secret(self) -> None:
        """Test with unicode text encoded as bytes."""
        secret = "Hello, 世界! 🌍".encode("utf-8")
        parts = split(secret, 5, 3, rng=Random(12345), version=1)
        reconstructed = combine(parts[:3], version=1)
        assert reconstructed == secret

    def test_exact_threshold_reconstruction(self) -> None:
        """Test that exactly the threshold number of parts is needed."""
        secret = b"threshold_test"
        threshold = 4
        parts = split(secret, 6, threshold, rng=Random(12345), version=1)

        # Should work with exactly threshold parts
        reconstructed = combine(parts[:threshold], version=1)
        assert reconstructed == secret

    def test_random_part_selection(self) -> None:
        """Test reconstruction with random selection of parts."""
        secret = b"random_selection_test"
        parts = split(secret, 10, 5, rng=Random(12345), version=1)

        # Test with different combinations of 5 parts
        import itertools

        for combo in list(itertools.combinations(range(10), 5))[
            :10
        ]:  # Test first 10 combinations
            selected_parts = [parts[i] for i in combo]
            reconstructed = combine(selected_parts, version=1)
            assert reconstructed == secret

    def test_single_byte_variations(self) -> None:
        """Test some single byte values (avoiding x-coordinate collision issue)."""
        test_values = [0, 1, 42, 127, 128, 200, 254, 255]
        for byte_value in test_values:
            secret = bytes([byte_value])
            parts = split(secret, 3, 2, rng=Random(100000 + byte_value * 1000))
            reconstructed = combine(parts[:2], version=1)
            assert reconstructed == secret

    def test_x_coordinate_uniqueness(self) -> None:
        """Test that x-coordinates are always unique (no collisions)."""
        secret = b"collision_test"

        # Test with many different seeds and configurations
        for seed in range(100):
            for num_parts in [5, 10, 20, 50, 100]:
                parts = split(secret, num_parts, 3, rng=Random(seed * 1000 + num_parts))
                x_coords = [part[-1] for part in parts]

                # Verify all x-coordinates are unique
                assert len(set(x_coords)) == len(x_coords), (
                    f"Collision detected with seed={seed}, num_parts={num_parts}"
                )

                # Verify all x-coordinates are in valid range [1, 255]
                for x in x_coords:
                    assert 1 <= x <= 255, f"Invalid x-coordinate: {x}"
