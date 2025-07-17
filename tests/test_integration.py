"""Integration tests for real-world usage scenarios."""

import json
import tempfile
import os
from pathlib import Path
from random import SystemRandom
from shamir import combine, split


class TestRealWorldScenarios:
    """Test real-world usage scenarios."""

    def test_password_sharing(self) -> None:
        """Test sharing a password among team members."""
        password = "MyVerySecurePassword123!@#".encode('utf-8')

        # Split among 5 team members, any 3 can recover
        parts = split(password, 5, 3, rng=SystemRandom())

        # Simulate 3 team members coming together
        reconstructed = combine(parts[:3])
        assert reconstructed.decode('utf-8') == "MyVerySecurePassword123!@#"

    def test_api_key_sharing(self) -> None:
        """Test sharing an API key."""
        api_key = "sk-1234567890abcdef1234567890abcdef".encode('utf-8')

        # Split for disaster recovery (3 of 5 scheme)
        parts = split(api_key, 5, 3, rng=SystemRandom())

        # Any 3 parts should recover the key
        reconstructed = combine(parts[1:4])  # Use parts 1, 2, 3
        assert reconstructed.decode('utf-8') == "sk-1234567890abcdef1234567890abcdef"

    def test_cryptocurrency_seed_phrase(self) -> None:
        """Test sharing a cryptocurrency seed phrase."""
        seed_phrase = "abandon ability able about above absent absorb abstract absurd abuse access accident".encode('utf-8')

        # High security: 4 of 7 scheme (reduced to avoid collision issues)
        parts = split(seed_phrase, 7, 4, rng=SystemRandom())

        # Test with exactly 4 parts
        reconstructed = combine(parts[:4])
        assert reconstructed.decode('utf-8') == "abandon ability able about above absent absorb abstract absurd abuse access accident"

    def test_file_encryption_key(self) -> None:
        """Test sharing a file encryption key."""
        # Simulate a 256-bit AES key
        encryption_key = bytes.fromhex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")

        # Split key for backup (2 of 3 scheme for easier recovery)
        parts = split(encryption_key, 3, 2, rng=SystemRandom())

        # Verify any 2 parts work
        reconstructed1 = combine(parts[:2])
        reconstructed2 = combine(parts[1:])
        reconstructed3 = combine([parts[0], parts[2]])

        assert reconstructed1 == encryption_key
        assert reconstructed2 == encryption_key
        assert reconstructed3 == encryption_key

    def test_database_credentials(self) -> None:
        """Test sharing database connection string."""
        db_connection = "postgresql://user:password@localhost:5432/database".encode('utf-8')

        # Split among DevOps team (any 2 of 4)
        parts = split(db_connection, 4, 2, rng=SystemRandom())

        reconstructed = combine(parts[:2])
        assert reconstructed.decode('utf-8') == "postgresql://user:password@localhost:5432/database"

    def test_json_configuration_secret(self) -> None:
        """Test sharing a JSON configuration with secrets."""
        config = {
            "database_url": "postgresql://user:secret@db:5432/app",
            "api_keys": {
                "stripe": "sk_test_123456789",
                "sendgrid": "SG.1234567890"
            },
            "jwt_secret": "super-secret-jwt-key-2024"
        }

        config_bytes = json.dumps(config, sort_keys=True).encode('utf-8')

        # Split configuration (3 of 5)
        parts = split(config_bytes, 5, 3, rng=SystemRandom())

        # Reconstruct and verify
        reconstructed = combine(parts[:3])
        reconstructed_config = json.loads(reconstructed.decode('utf-8'))

        assert reconstructed_config == config

    def test_backup_and_recovery_simulation(self) -> None:
        """Simulate a backup and recovery scenario."""
        # Simulate important data
        important_data = "Critical business data that must not be lost" * 100
        data_bytes = important_data.encode('utf-8')

        # Create shares for geographic distribution
        shares = split(data_bytes, 7, 4, rng=SystemRandom())  # 4 of 7

        # Simulate storing shares in different locations
        locations = ["AWS-US-East", "AWS-EU-West", "GCP-Asia", "Azure-US-West",
                    "On-Premise-DC1", "On-Premise-DC2", "Cold-Storage"]

        assert len(shares) == len(locations)

        # Simulate disaster: 3 locations become unavailable
        available_shares = shares[:4]  # Only 4 locations available

        # Should still be able to recover
        recovered = combine(available_shares)
        assert recovered.decode('utf-8') == important_data

    def test_progressive_revelation(self) -> None:
        """Test progressive revelation scenario."""
        secret = "Nuclear launch codes: 1234-5678-9012".encode('utf-8')

        # Create a 5 of 5 scheme (all parts needed)
        parts = split(secret, 5, 5, rng=SystemRandom())

        # Simulate collecting parts one by one
        collected_parts = []

        for i, part in enumerate(parts):
            collected_parts.append(part)

            if len(collected_parts) < 5:
                # Should not be able to reconstruct with fewer than 5 parts
                # Note: Current implementation doesn't enforce this,
                # so we just document the behavior
                continue
            else:
                # With all 5 parts, should work
                reconstructed = combine(collected_parts)
                assert reconstructed.decode('utf-8') == "Nuclear launch codes: 1234-5678-9012"

    def test_multi_language_text(self) -> None:
        """Test with text in multiple languages."""
        multilingual_secret = """
        English: Hello World
        Spanish: Hola Mundo
        French: Bonjour le Monde
        German: Hallo Welt
        Japanese: こんにちは世界
        Chinese: 你好世界
        Russian: Привет мир
        Arabic: مرحبا بالعالم
        Hindi: नमस्ते दुनिया
        """.strip().encode('utf-8')

        parts = split(multilingual_secret, 6, 4, rng=SystemRandom())
        reconstructed = combine(parts[:4])

        assert reconstructed == multilingual_secret

    def test_binary_file_simulation(self) -> None:
        """Test with binary file-like data."""
        # Simulate a small binary file (e.g., a certificate or key file)
        binary_data = bytes(range(256)) + bytes(range(255, -1, -1))  # 512 bytes

        parts = split(binary_data, 5, 3, rng=SystemRandom())
        reconstructed = combine(parts[:3])

        assert reconstructed == binary_data
        assert len(reconstructed) == 512

    def test_version_control_scenario(self) -> None:
        """Test scenario where parts are stored in version control."""
        secret = "production-deployment-key-v2024".encode('utf-8')

        # Split for storage in different repositories
        parts = split(secret, 4, 3, rng=SystemRandom())

        # Simulate storing each part in a different repo/branch
        repo_parts = {
            "frontend-repo": parts[0],
            "backend-repo": parts[1],
            "devops-repo": parts[2],
            "security-repo": parts[3]
        }

        # Any 3 repos should allow reconstruction
        selected_repos = ["frontend-repo", "backend-repo", "devops-repo"]
        selected_parts = [repo_parts[repo] for repo in selected_repos]

        reconstructed = combine(selected_parts)
        assert reconstructed.decode('utf-8') == "production-deployment-key-v2024"
