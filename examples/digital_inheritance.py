"""Digital inheritance system using Shamir's Secret Sharing.

This example demonstrates how to secure digital assets for inheritance using
secret sharing. The approach allows family members to access important accounts
and information after your death, but not before.

Use case: You want your family to access your digital assets (password manager,
cryptocurrency, email accounts) after you pass away, but you don't want any
single person to have access while you're alive.

Solution: Split access credentials into shares distributed among family members
and a trusted third party (lawyer/executor). Require multiple shares to
reconstruct the original credentials.
"""

import json
from base64 import b64decode, b64encode
from datetime import datetime
from pathlib import Path
from typing import Any

from shamir import Shares, combine, split


def setup_inheritance_package(
    digital_assets: dict[str, Any],
    num_shares: int = 5,
    threshold: int = 3,
) -> dict[str, str]:
    """Create inheritance package with distributed shares.

    Args:
        digital_assets: Dictionary containing sensitive information to protect.
        num_shares: Total number of shares to create (default: 5).
        threshold: Minimum shares needed to reconstruct (default: 3).

    Returns:
        Dictionary mapping beneficiary names to their share (base64 encoded).

    Example:
        >>> assets = {
        ...     'password_manager': 'master-password-here',
        ...     'recovery_email': 'backup@example.com',
        ...     'notes': 'Safe deposit box #4523 at First National Bank'
        ... }
        >>> shares = setup_inheritance_package(assets)
    """
    # Add metadata for future reference
    package: dict[str, Any] = {
        "created": datetime.now().isoformat(),
        "version": "1.0",
        "assets": digital_assets,
    }

    # Serialize to JSON and encode to bytes
    package_json = json.dumps(package, indent=2)
    package_bytes = package_json.encode("utf-8")

    # Split into shares using Shamir's Secret Sharing
    raw_shares: Shares = split(package_bytes, parts=num_shares, threshold=threshold)

    # Encode shares to base64 for easy storage/transmission
    beneficiary_names = ["Spouse", "Child_1", "Child_2", "Executor", "Lawyer"]
    encoded_shares = {
        name: b64encode(share).decode("ascii")
        for name, share in zip(beneficiary_names[:num_shares], raw_shares)
    }

    return encoded_shares


def recover_inheritance_package(shares: dict[str, str]) -> dict[str, Any]:
    """Recover digital assets from inheritance shares.

    Args:
        shares: Dictionary mapping beneficiary names to their shares (base64).

    Returns:
        Dictionary containing the original digital assets.

    Raises:
        ValueError: If insufficient shares provided or shares are invalid.

    Example:
        >>> shares = {
        ...     'Spouse': 'base64_encoded_share_1',
        ...     'Child_1': 'base64_encoded_share_2',
        ...     'Executor': 'base64_encoded_share_3'
        ... }
        >>> assets = recover_inheritance_package(shares)
    """
    # Decode shares from base64
    decoded_shares = [b64decode(share) for share in shares.values()]

    # Convert to bytearray for combine function
    share_arrays: Shares = [bytearray(share) for share in decoded_shares]

    # Reconstruct original data
    recovered_bytes = combine(share_arrays)

    # Parse JSON
    package_json = recovered_bytes.decode("utf-8")
    package = json.loads(package_json)

    return package


def save_share_to_file(
    beneficiary_name: str,
    share: str,
    output_dir: Path,
    instructions: str = "",
) -> Path:
    """Save a share to a file with instructions for the beneficiary.

    Args:
        beneficiary_name: Name of the person receiving this share.
        share: The base64-encoded share.
        output_dir: Directory where the file should be saved.
        instructions: Additional instructions for the beneficiary.

    Returns:
        Path to the created file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    filename = output_dir / f"inheritance_share_{beneficiary_name}.txt"

    with filename.open("w") as f:
        f.write("=" * 70 + "\n")
        f.write(f"INHERITANCE SHARE FOR: {beneficiary_name}\n")
        f.write("=" * 70 + "\n\n")

        f.write("IMPORTANT INSTRUCTIONS:\n")
        f.write("-" * 70 + "\n")
        f.write("This document contains a cryptographic share of important\n")
        f.write("digital asset information. It has no value by itself.\n\n")

        f.write("To access the protected information, you must:\n")
        f.write("1. Gather shares from at least 2 other beneficiaries\n")
        f.write("2. Contact the executor to coordinate reconstruction\n")
        f.write("3. Use the recovery script provided by the executor\n\n")

        if instructions:
            f.write("ADDITIONAL NOTES:\n")
            f.write("-" * 70 + "\n")
            f.write(f"{instructions}\n\n")

        f.write("YOUR SHARE:\n")
        f.write("-" * 70 + "\n")
        f.write(f"{share}\n\n")

        f.write("=" * 70 + "\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 70 + "\n")

    return filename


def main() -> None:
    """Demonstrate digital inheritance setup and recovery."""
    print("Digital Inheritance Example")
    print("=" * 70)
    print()

    # Step 1: Define digital assets to protect
    print("Step 1: Setting up digital assets package...")
    digital_assets: dict[str, Any] = {
        "password_manager_master": "correct-horse-battery-staple-2024",
        "recovery_email": "recovery@example.com",
        "recovery_email_password": "another-secure-password",
        "bitcoin_wallet_seed": "witch collapse practice feed shame open despair creek road again ice least",  # noqa: E501
        "bank_account_info": "Account #123456789 at First National Bank",
        "safe_deposit_box": "Box #4523, Key with executor",
        "important_contacts": {
            "estate_lawyer": "Jane Smith, (555) 123-4567",
            "financial_advisor": "John Doe, (555) 987-6543",
        },
        "additional_notes": "All passwords are stored in 1Password. Master password above gives full access.",  # noqa: E501
    }

    # Step 2: Create shares
    print("Step 2: Creating 5 shares with threshold of 3...")
    shares = setup_inheritance_package(
        digital_assets,
        num_shares=5,
        threshold=3,
    )

    print(f"✓ Created {len(shares)} shares")
    print()

    # Step 3: Display distribution plan
    print("Step 3: Recommended distribution plan:")
    print("-" * 70)
    distribution_plan = {
        "Spouse": "Keep in home safe or safety deposit box",
        "Child_1": "Mail in sealed envelope with instructions",
        "Child_2": "Mail in sealed envelope with instructions",
        "Executor": "Provide during estate planning meeting",
        "Lawyer": "Store with will and other estate documents",
    }

    for beneficiary, location in distribution_plan.items():
        if beneficiary in shares:
            print(f"  {beneficiary:12} → {location}")
    print()

    # Step 4: Save shares to files (optional)
    print("Step 4: Saving shares to files...")
    output_dir = Path("inheritance_shares")

    for beneficiary, share in shares.items():
        instructions = distribution_plan.get(beneficiary, "")
        filepath = save_share_to_file(beneficiary, share, output_dir, instructions)
        print(f"  ✓ Saved share for {beneficiary}: {filepath}")
    print()

    # Step 5: Demonstrate recovery (simulating after death)
    print("=" * 70)
    print("RECOVERY SIMULATION")
    print("=" * 70)
    print()
    print("Scenario: After legal declaration of death, three beneficiaries")
    print("meet with the executor to reconstruct access credentials.")
    print()

    # Simulate three beneficiaries providing their shares
    recovery_shares = {
        "Spouse": shares["Spouse"],
        "Child_1": shares["Child_1"],
        "Executor": shares["Executor"],
    }

    print(f"Shares provided by: {', '.join(recovery_shares.keys())}")
    print("Reconstructing package...")

    # Recover the assets
    recovered_package = recover_inheritance_package(recovery_shares)

    print()
    print("✓ Successfully recovered digital assets!")
    print()
    print("Recovered information:")
    print("-" * 70)

    # Display recovered assets (in practice, these would be used, not printed)
    assets = recovered_package["assets"]
    print(f"  Password Manager Master: {assets['password_manager_master']}")
    print(f"  Recovery Email: {assets['recovery_email']}")
    print(f"  Bitcoin Wallet Seed: {assets['bitcoin_wallet_seed'][:40]}...")
    print(f"  Bank Account: {assets['bank_account_info']}")
    print(f"  Safe Deposit Box: {assets['safe_deposit_box']}")
    print()
    print(f"  Package created: {recovered_package['created']}")
    print()

    # Security notes
    print("=" * 70)
    print("SECURITY NOTES")
    print("=" * 70)
    print()
    print("✓ No single person can access the information alone")
    print("✓ Loss of up to 2 shares still allows recovery")
    print("✓ Shares can be stored in different physical locations")
    print("✓ System is information-theoretically secure")
    print("✓ Each share reveals zero information about the secret")
    print()
    print(f"Files saved to: {output_dir.absolute()}")
    print()


if __name__ == "__main__":
    main()
