"""Cryptocurrency wallet backup using Shamir's Secret Sharing.

This example demonstrates how to securely backup cryptocurrency wallet seed
phrases by splitting them into multiple shares. This protects against both
loss (any threshold shares can recover) and theft (insufficient shares reveal
nothing).

Use case: You have a cryptocurrency wallet with a 12 or 24 word BIP39 seed
phrase worth significant value. You want to:
1. Protect against single point of failure (lose seed = lose funds)
2. Protect against theft (finding one backup = stealing funds)
3. Enable recovery even if some backups are lost or destroyed

Solution: Split the seed phrase into N shares where any K shares can recover
the original seed. Store shares in geographically distributed locations.
"""

from base64 import b64decode, b64encode
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from shamir import Shares, combine, split


class BackupStrategy(Enum):
    """Common backup strategies for different security/convenience trade-offs."""

    # 3 of 5: Good balance - can lose 2 backups, need 3 for theft
    BALANCED = (5, 3, "Balanced: 5 shares, need 3 to recover")

    # 2 of 3: More convenient - can lose 1 backup, need 2 for theft
    CONVENIENT = (3, 2, "Convenient: 3 shares, need 2 to recover")

    # 4 of 7: More secure - can lose 3 backups, need 4 for theft
    PARANOID = (7, 4, "Paranoid: 7 shares, need 4 to recover")

    # 5 of 9: Maximum security - can lose 4 backups, need 5 for theft
    MAXIMUM = (9, 5, "Maximum: 9 shares, need 5 to recover")

    def __init__(self, total: int, threshold: int, description: str) -> None:
        self.total = total
        self.threshold = threshold
        self.description = description


class WalletBackup:
    """Manages cryptocurrency wallet seed phrase backups using secret sharing."""

    def __init__(
        self,
        seed_phrase: str,
        wallet_name: str = "Primary Wallet",
        strategy: BackupStrategy = BackupStrategy.BALANCED,
    ) -> None:
        """Initialize wallet backup.

        Args:
            seed_phrase: BIP39 seed phrase (12 or 24 words).
            wallet_name: Descriptive name for this wallet.
            strategy: Backup strategy defining share distribution.

        Raises:
            ValueError: If seed phrase format is invalid.
        """
        self.seed_phrase = seed_phrase.strip()
        self.wallet_name = wallet_name
        self.strategy = strategy
        self.created_at = datetime.now()

        # Validate seed phrase
        words = self.seed_phrase.split()
        if len(words) not in (12, 24):
            msg = f"Invalid seed phrase: expected 12 or 24 words, got {len(words)}"
            raise ValueError(msg)

        self.word_count = len(words)

    def create_shares(self) -> list[str]:
        """Create cryptographic shares of the seed phrase.

        Returns:
            List of base64-encoded shares.
        """
        # Encode seed phrase to bytes
        seed_bytes = self.seed_phrase.encode("utf-8")

        # Split into shares
        raw_shares: Shares = split(
            seed_bytes,
            parts=self.strategy.total,
            threshold=self.strategy.threshold,
        )

        # Encode to base64 for storage
        encoded_shares = [b64encode(share).decode("ascii") for share in raw_shares]

        return encoded_shares

    @staticmethod
    def recover_seed(shares: list[str]) -> str:
        """Recover seed phrase from shares.

        Args:
            shares: List of base64-encoded shares (at least threshold).

        Returns:
            The original seed phrase.

        Raises:
            ValueError: If shares are invalid or insufficient.
        """
        # Decode from base64
        decoded_shares = [b64decode(share) for share in shares]

        # Convert to bytearrays
        share_arrays: Shares = [bytearray(share) for share in decoded_shares]

        # Recover original seed
        recovered_bytes = combine(share_arrays)

        return recovered_bytes.decode("utf-8")

    def generate_backup_package(self, output_dir: Path) -> dict[str, Any]:
        """Generate complete backup package with shares and instructions.

        Args:
            output_dir: Directory where backup files will be saved.

        Returns:
            Dictionary with backup metadata and file paths.
        """
        output_dir.mkdir(parents=True, exist_ok=True)

        # Create shares
        shares = self.create_shares()

        # Define storage locations
        locations = self._get_storage_locations()

        # Generate files for each share
        share_files: list[Path] = []
        for i, (share, location) in enumerate(zip(shares, locations), 1):
            filepath = self._create_share_file(
                share_number=i,
                share=share,
                location=location,
                output_dir=output_dir,
            )
            share_files.append(filepath)

        # Create master instruction file
        instruction_file = self._create_instruction_file(
            locations=locations,
            output_dir=output_dir,
        )

        return {
            "wallet_name": self.wallet_name,
            "strategy": self.strategy.description,
            "total_shares": self.strategy.total,
            "threshold": self.strategy.threshold,
            "word_count": self.word_count,
            "created_at": self.created_at.isoformat(),
            "share_files": share_files,
            "instruction_file": instruction_file,
        }

    def _get_storage_locations(self) -> list[str]:
        """Get recommended storage locations based on strategy."""
        # Base locations (for 5 share strategy)
        base_locations = [
            "Home Safe - Primary residence",
            "Bank Safe Deposit Box - Local branch",
            "Bank Safe Deposit Box - Different city",
            "Trusted Family Member - Parent/sibling",
            "Secure Cloud Storage - Encrypted, different provider",
        ]

        # Extended locations for larger strategies
        extended_locations = [
            "Trusted Friend - Long-time friend",
            "Lawyer/Estate Executor - With estate documents",
            "Offshore Safe Deposit Box - Foreign jurisdiction",
            "Corporate Vault - Business location",
        ]

        all_locations = base_locations + extended_locations
        return all_locations[: self.strategy.total]

    def _create_share_file(
        self,
        share_number: int,
        share: str,
        location: str,
        output_dir: Path,
    ) -> Path:
        """Create a file for a single share with instructions."""
        filename = output_dir / f"share_{share_number}_of_{self.strategy.total}.txt"

        with filename.open("w") as f:
            f.write("=" * 70 + "\n")
            f.write("CRYPTOCURRENCY WALLET BACKUP SHARE\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Wallet: {self.wallet_name}\n")
            f.write(f"Share: {share_number} of {self.strategy.total}\n")
            f.write(f"Threshold: {self.strategy.threshold} shares needed to recover\n")
            f.write(f"Created: {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Recommended Storage: {location}\n\n")

            f.write("CRITICAL SECURITY INFORMATION:\n")
            f.write("-" * 70 + "\n")
            f.write(
                f"• This share alone is USELESS - need {self.strategy.threshold} total\n"
            )
            f.write("• This share reveals ZERO information about your wallet\n")
            f.write(
                f"• You can lose {self.strategy.total - self.strategy.threshold} shares and still recover\n"  # noqa: E501
            )
            f.write(
                f"• An attacker needs {self.strategy.threshold} shares to steal funds\n"
            )
            f.write("\n")

            f.write("TO RECOVER YOUR WALLET:\n")
            f.write("-" * 70 + "\n")
            f.write(f"1. Gather at least {self.strategy.threshold} shares\n")
            f.write("2. Use the recovery script (see instructions.txt)\n")
            f.write("3. Import recovered seed into your wallet software\n")
            f.write("4. Create new backup shares after recovery\n\n")

            f.write("YOUR SHARE DATA:\n")
            f.write("-" * 70 + "\n")
            f.write(f"{share}\n\n")

            f.write("=" * 70 + "\n")
            f.write("DO NOT share this file electronically unless encrypted.\n")
            f.write("Store in a secure physical location.\n")
            f.write("=" * 70 + "\n")

        return filename

    def _create_instruction_file(
        self,
        locations: list[str],
        output_dir: Path,
    ) -> Path:
        """Create master instruction file."""
        filename = output_dir / "INSTRUCTIONS.txt"

        with filename.open("w") as f:
            f.write("=" * 70 + "\n")
            f.write("CRYPTOCURRENCY WALLET BACKUP - MASTER INSTRUCTIONS\n")
            f.write("=" * 70 + "\n\n")

            f.write(f"Wallet Name: {self.wallet_name}\n")
            f.write(f"Backup Strategy: {self.strategy.description}\n")
            f.write(f"Seed Phrase Length: {self.word_count} words\n")
            f.write(f"Created: {self.created_at.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

            f.write("DISTRIBUTION PLAN:\n")
            f.write("-" * 70 + "\n")
            for i, location in enumerate(locations, 1):
                f.write(f"Share {i}: {location}\n")
            f.write("\n")

            f.write("SECURITY PROPERTIES:\n")
            f.write("-" * 70 + "\n")
            f.write(
                f"• Threshold: Need {self.strategy.threshold} shares to recover wallet\n"
            )
            f.write(
                f"• Redundancy: Can lose {self.strategy.total - self.strategy.threshold} shares safely\n"  # noqa: E501
            )
            f.write(
                f"• Security: Attacker must compromise {self.strategy.threshold} locations\n"  # noqa: E501
            )
            f.write("• Information-theoretic security: Shares reveal nothing\n\n")

            f.write("RECOVERY PROCEDURE:\n")
            f.write("-" * 70 + "\n")
            f.write(f"1. Retrieve at least {self.strategy.threshold} share files\n")
            f.write("2. Extract the base64 share data from each file\n")
            f.write("3. Use Python recovery script:\n\n")

            f.write("   from shamir import combine\n")
            f.write("   from base64 import b64decode\n\n")
            f.write("   shares = ['share1_base64', 'share2_base64', ...]\n")
            f.write("   decoded = [bytearray(b64decode(s)) for s in shares]\n")
            f.write("   seed = combine(decoded).decode('utf-8')\n")
            f.write("   print(seed)\n\n")

            f.write("4. Import seed phrase into wallet software:\n")
            f.write("   • Bitcoin Core, Electrum, Ledger Live, etc.\n")
            f.write("   • Look for 'Restore from seed' or 'Import wallet'\n\n")

            f.write("5. After recovery:\n")
            f.write("   • Generate NEW backup shares (old ones may be compromised)\n")
            f.write("   • Update distribution plan\n")
            f.write("   • Consider moving funds to new wallet for maximum security\n\n")

            f.write("EMERGENCY CONTACTS:\n")
            f.write("-" * 70 + "\n")
            f.write("Technical Support: [Your trusted tech contact]\n")
            f.write("Legal Contact: [Estate lawyer if applicable]\n\n")

            f.write("=" * 70 + "\n")
            f.write("Keep this file with one of your shares or in a secure location.\n")
            f.write("=" * 70 + "\n")

        return filename


def main() -> None:
    """Demonstrate cryptocurrency wallet backup and recovery."""
    print("Cryptocurrency Wallet Backup Example")
    print("=" * 70)
    print()

    # Example seed phrase (DO NOT use in production - for demonstration only)
    seed_phrase = (
        "witch collapse practice feed shame open despair creek road again ice least"  # noqa: E501
    )

    print("SCENARIO: Backing up a Bitcoin wallet")
    print("-" * 70)
    print(f"Seed phrase: {seed_phrase}")
    print(f"Word count: {len(seed_phrase.split())} words")
    print()

    # Create backup with balanced strategy
    print("Step 1: Creating backup with BALANCED strategy (5 shares, need 3)...")
    backup = WalletBackup(
        seed_phrase=seed_phrase,
        wallet_name="Primary Bitcoin Wallet",
        strategy=BackupStrategy.BALANCED,
    )

    # Generate shares
    shares = backup.create_shares()
    print(f"✓ Generated {len(shares)} shares")
    print()

    # Display first few characters of each share
    print("Share preview (first 40 chars):")
    for i, share in enumerate(shares, 1):
        print(f"  Share {i}: {share[:40]}...")
    print()

    # Create backup package
    print("Step 2: Creating backup package with instructions...")
    output_dir = Path("wallet_backup")
    package = backup.generate_backup_package(output_dir)

    print(f"✓ Strategy: {package['strategy']}")
    print(f"✓ Created {len(package['share_files'])} share files")
    print(f"✓ Output directory: {output_dir.absolute()}")
    print()

    # Demonstrate recovery
    print("=" * 70)
    print("RECOVERY SIMULATION")
    print("=" * 70)
    print()

    print("Scenario: You need to recover your wallet from backup")
    print(f"You have access to shares: 1, 3, and 5 (need {backup.strategy.threshold})")
    print()

    # Use shares 1, 3, and 5 for recovery
    recovery_shares = [shares[0], shares[2], shares[4]]

    print("Recovering seed phrase...")
    recovered_seed = WalletBackup.recover_seed(recovery_shares)

    print()
    if recovered_seed == seed_phrase:
        print("✓ SUCCESS! Seed phrase recovered correctly")
        print(f"  Recovered: {recovered_seed}")
    else:
        print("✗ ERROR: Recovery failed")

    print()

    # Security demonstration
    print("=" * 70)
    print("SECURITY DEMONSTRATION")
    print("=" * 70)
    print()

    print("Testing with insufficient shares (should fail):")
    print(f"  Threshold required: {backup.strategy.threshold}")
    print(f"  Shares provided: {backup.strategy.threshold - 1}")
    print()

    # Try with only 2 shares (below threshold)
    insufficient_shares = [shares[0], shares[1]]

    print("Attempting recovery with insufficient shares...")
    try:
        # This will succeed mathematically but produce wrong result
        wrong_seed = WalletBackup.recover_seed(insufficient_shares)
        print(f"  Result: {wrong_seed}")
        if wrong_seed != seed_phrase:
            print("  ✓ As expected: produces incorrect result (not your seed)")
            print("    This is information-theoretic security in action!")
    except ValueError as e:
        print(f"  ✓ Correctly rejected: {e}")

    print()

    # Storage recommendations
    print("=" * 70)
    print("STORAGE RECOMMENDATIONS")
    print("=" * 70)
    print()

    locations = backup._get_storage_locations()
    print(f"For {backup.strategy.description}:\n")
    for i, location in enumerate(locations, 1):
        print(f"  Share {i} → {location}")

    print()
    print("Key principles:")
    print("  • Geographic distribution prevents regional disasters")
    print("  • Multiple custodians prevent single point of failure")
    print("  • Physical + digital locations for redundancy")
    print(
        f"  • Can lose {backup.strategy.total - backup.strategy.threshold} shares and still recover"
    )  # noqa: E501
    print(f"  • Attacker needs {backup.strategy.threshold} shares (very difficult)")
    print()

    # Compare strategies
    print("=" * 70)
    print("STRATEGY COMPARISON")
    print("=" * 70)
    print()

    for strategy in BackupStrategy:
        print(f"{strategy.description}")
        print(f"  Redundancy: Can lose {strategy.total - strategy.threshold} shares")
        print(f"  Security: Need {strategy.threshold} shares to compromise")
        print(f"  Complexity: {strategy.total} locations to manage")
        print()

    print("=" * 70)
    print(f"Files saved to: {output_dir.absolute()}")
    print("Review INSTRUCTIONS.txt for complete recovery procedure.")
    print("=" * 70)


if __name__ == "__main__":
    main()
