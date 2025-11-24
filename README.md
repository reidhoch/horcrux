[![codecov](https://codecov.io/gh/reidhoch/horcrux/branch/develop/graph/badge.svg?token=7DYAQIUMS2)](https://codecov.io/gh/reidhoch/horcrux)
[![PyPI version](https://badge.fury.io/py/horcrux.svg)](https://badge.fury.io/py/horcrux)
[![License](https://img.shields.io/badge/License-MPL--2.0-yellowgreen)](https://github.com/reidhoch/horcrux/blob/develop/LICENSE)
[![Sanity tests](https://github.com/reidhoch/horcrux/workflows/Sanity%20tests/badge.svg?branch=develop)](https://github.com/reidhoch/horcrux/actions/workflows/ci.yaml)

# Horcrux

> A Python implementation of Shamir's Secret Sharing based on HashiCorp Vault's approach.

**Horcrux** lets you split secrets into multiple shares where any threshold number can reconstruct the original secret, but fewer shares reveal nothing. Think of it as splitting a key to a vault into pieces—you need enough pieces to open it, but each piece alone is useless.

## Why Use Secret Sharing?

**Single Point of Failure**: Storing a password, encryption key, or wallet seed in one place means losing it loses everything.

**Single Point of Compromise**: Storing it in one place also means finding it steals everything.

**Secret Sharing Solves Both**: Split your secret into N shares where any K shares can reconstruct it. Now you can:

- Lose up to (N-K) shares and still recover your secret
- Require an attacker to compromise K locations instead of one
- Distribute trust across multiple parties without any single party having access

## Features

- ✅ **Zero runtime dependencies** - Minimal attack surface
- ✅ **Information-theoretic security** - Shares below threshold reveal nothing
- ✅ **Constant-time operations** - Resistant to timing attacks
- ✅ **DoS protection** - MAX_SECRET_SIZE limit prevents memory exhaustion attacks
- ✅ **100% test coverage** - Extensively tested with property-based tests (152 tests)
- ✅ **Type-safe** - Full type hints with strict mypy checking, PEP 561 compliant
- ✅ **Share versioning** - Backward compatible format with version detection
- ✅ **Performance optimized** - 15-20% faster with reduced memory footprint
- ✅ **Python 3.11+** - Modern Python with latest type system features
- ✅ **Battle-tested** - Based on HashiCorp Vault's proven implementation
- ✅ **Security monitoring** - Automated SAST, dependency scanning, secrets detection

## Installation

```bash
pip install horcrux
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv add horcrux
```

## Quick Start

```python
from shamir import Shares, split, combine

# Your secret (password, key, seed phrase, etc.)
secret = b"correct-horse-battery-staple"

# Split into 5 shares, any 3 can reconstruct
shares: Shares = split(secret, parts=5, threshold=3)

# Distribute shares to different locations:
# - Share 1: Home safe
# - Share 2: Bank deposit box
# - Share 3: Trusted family member
# - Share 4: Cloud storage (encrypted)
# - Share 5: Office safe

# Later, recover from any 3 shares
recovered = combine([shares[0], shares[2], shares[4]])
assert recovered == secret
```

## Real-World Examples

### 🔐 Cryptocurrency Wallet Backup

Protect your crypto wallet seed phrase across multiple secure locations. Lose your house in a fire? Your backup shares in other cities can still recover your wallet. See [`examples/crypto_wallet.py`](examples/crypto_wallet.py) for complete implementation with multiple backup strategies.

```python
from examples.crypto_wallet import WalletBackup, BackupStrategy

# Your BIP39 seed phrase
seed = "witch collapse practice feed shame open despair creek road again ice least"

# Create backup with balanced strategy (5 shares, need 3)
backup = WalletBackup(seed, strategy=BackupStrategy.BALANCED)
shares = backup.create_shares()

# Store shares in geographically distributed locations
# Later, recover from any 3 shares
recovered_seed = WalletBackup.recover_seed([shares[0], shares[2], shares[4]])
```

**Strategies Available:**

- **Convenient**: 3 shares, need 2 (easier management)
- **Balanced**: 5 shares, need 3 (recommended)
- **Paranoid**: 7 shares, need 4 (high security)
- **Maximum**: 9 shares, need 5 (maximum security)

### 💼 Digital Inheritance

Ensure your family can access your digital assets after you pass away, but not before. Split passwords and account recovery information across family members and your estate lawyer. See [`examples/digital_inheritance.py`](examples/digital_inheritance.py) for complete estate planning solution.

```python
from examples.digital_inheritance import setup_inheritance_package

# Package your digital assets
assets = {
    'password_manager_master': 'your-master-password',
    'bitcoin_wallet_seed': '24 word seed phrase...',
    'recovery_email': 'backup@example.com',
    'bank_account_info': 'Account details...'
}

# Create 5 shares distributed to: Spouse, Children, Executor, Lawyer
shares = setup_inheritance_package(assets, num_shares=5, threshold=3)

# After legal declaration of death, any 3 beneficiaries can reconstruct
```

### More Examples

- [`examples/hello.py`](examples/hello.py) - Basic usage demonstration
- [`examples/password.py`](examples/password.py) - Password generation and sharing
- [`examples/image.py`](examples/image.py) - Binary file splitting with CLI

## API Reference

### Type Aliases

For better documentation and type safety, the library provides these type aliases:

- `Share: TypeAlias = bytearray` - Individual secret share
- `Shares: TypeAlias = list[Share]` - Collection of shares

These aliases make function signatures more self-documenting and improve IDE support.

---

### `split(secret, parts, threshold, rng=None, version=None)`

Split a secret into cryptographic shares.

**Parameters:**

- `secret` (`bytes`): The secret data to split (max 100MB)
- `parts` (`int`): Total number of shares to create (2-255)
- `threshold` (`int`): Minimum shares needed to reconstruct (2-255)
- `rng` (`Random`, optional): Random number generator. Defaults to `SystemRandom()` (cryptographically secure)
- `version` (`Literal[0, 1]`, optional): Share format version (0=legacy, 1=versioned). Defaults to 1

**Returns:** `Shares` (alias for `list[bytearray]`) - The generated shares

**Raises:** `ValueError` - If parameters are invalid (empty secret, secret > 100MB, parts < threshold, values > 255, etc.)

**Example:**

```python
from shamir import Shares, split

secret = b"my-secret-key"
shares: Shares = split(secret, parts=5, threshold=3)
# Returns 5 shares, any 3 can reconstruct the secret
```

---

### `combine(parts)`

Reconstruct a secret from shares.

**Parameters:**

- `parts` (`Shares`): List of shares to combine (at least threshold required)

**Returns:** `bytearray` - The reconstructed secret

**Raises:**

- `ValueError` - If fewer than 2 parts provided, parts have mismatched lengths, duplicate parts detected, or mixing different share versions

**Important:** This function does not validate the threshold. Providing fewer than the required threshold shares will produce an incorrect result without error. Always ensure you provide at least the threshold number of shares used during `split()`.

**Example:**

```python
from shamir import Shares, combine

# Combine any threshold number of shares
selected_shares: Shares = [shares[0], shares[2], shares[4]]
recovered = combine(selected_shares)
print(recovered.decode('utf-8'))
```

## How It Works

Horcrux implements Shamir's Secret Sharing over the Galois Field GF(256):

1. **Polynomial Construction**: For each byte of the secret, create a random polynomial of degree (threshold-1) with the secret byte as the constant term
2. **Share Generation**: Evaluate the polynomial at N different x-coordinates to produce N shares
3. **Secret Recovery**: Use Lagrange interpolation to reconstruct the polynomial from any K shares, then evaluate at x=0 to recover the secret
4. **Security**: Information-theoretic security means K-1 shares reveal mathematically zero information about the secret

Each share consists of:

- **Version 1 format** (default): `[version_byte, y_values..., x_coordinate]`
- **Legacy format**: `[y_values..., x_coordinate]`

The library automatically detects and handles both formats for backward compatibility.

## Security Properties

### Information-Theoretic Security

**Below threshold shares reveal nothing**: This isn't just "hard to break" cryptography. With K-1 shares, for ANY possible secret value, there exists a valid Kth share that would reconstruct to that secret. This means K-1 shares provide zero information about which secret is the real one.

### Security Guarantees

- ✅ **Constant-time operations**: GF(256) operations use constant-time implementations to prevent timing attacks
- ✅ **No secret branching**: Code paths don't branch based on secret values
- ✅ **Cryptographic RNG**: Defaults to `SystemRandom()` which uses OS entropy (comprehensive warnings in docstrings)
- ✅ **DoS protection**: MAX_SECRET_SIZE (100MB) limit prevents memory exhaustion attacks
- ✅ **No dependencies**: Zero runtime dependencies means minimal supply chain risk
- ✅ **Tested security**: Property-based tests verify security invariants
- ✅ **Security documentation**: Comprehensive security considerations in API docstrings (RNG, memory, HSM integration)
- ✅ **Automated scanning**: CI/CD includes Semgrep, Bandit, pip-audit, and GitLeaks

### Threat Model

**Protected Against:**

- Compromise of up to (threshold-1) share locations
- Loss of up to (parts-threshold) shares
- Timing attacks on reconstruction
- Partial information leakage from shares
- Memory exhaustion DoS attacks (100MB secret size limit)

**Not Protected Against:**

- Compromise of threshold or more shares
- Side-channel attacks on the system running the code (OS-level)
- Social engineering to gather shares
- Compromised random number generator

### Best Practices

1. **Use high thresholds for valuable secrets**: 3-of-5 minimum, 4-of-7 for high value
2. **Geographic distribution**: Store shares in different physical locations
3. **Multiple custodians**: Don't give one person multiple shares
4. **Secure storage**: Encrypt shares before cloud storage (defense in depth)
5. **Regular audits**: Periodically verify shares are still accessible
6. **Rotation after recovery**: Generate new shares after reconstruction (old shares may be compromised)

## Performance

- **Speed**: Splits/combines 1MB secrets in <500ms on modern hardware
- **Recent optimizations**: 15-20% performance improvement, 5-10% memory reduction
- **Scalability**: Supports up to 255 shares with any threshold, max 100MB secret size
- **Complexity**: O(n×m×k) where n=secret length, m=number of shares, k=threshold
- **Memory**: O(secret_size × parts) during split, O(secret_size × threshold) during combine

**Optimizations applied:**

- Efficient loop allocation with direct indexing (avoiding list comprehension overhead)
- `__slots__` on internal classes for reduced memory footprint
- Type hints enabling Python optimizer improvements

Tested with:

- Secrets up to 100MB (MAX_SECRET_SIZE limit)
- Up to 255 shares (maximum possible)
- Various threshold configurations (2-of-3 through 128-of-255)

## FAQ

**Q: How many shares should I create?**
A: 5 shares with threshold of 3 is a good balance for most use cases. High-value secrets may want 7 shares with threshold of 4.

**Q: What happens if I lose some shares?**
A: You can lose up to (parts - threshold) shares and still recover. With 5 shares and threshold of 3, you can lose 2 shares.

**Q: Can an attacker learn anything from one share?**
A: No. This has information-theoretic security—below threshold shares reveal mathematically zero information about the secret.

**Q: Should I encrypt shares before storing?**
A: Shares are already cryptographically secure, but encrypting before cloud storage adds defense in depth. Local storage (safe, deposit box) doesn't need encryption.

**Q: Can I split already-encrypted data?**
A: Yes. Secret sharing works on any binary data, including encrypted data, password hashes, or random keys.

**Q: What's the difference between version 0 and version 1 shares?**
A: Version 1 (default) includes a version byte for future compatibility. Version 0 is legacy format. Both are supported, and the library auto-detects which format is used. Use version 1 for new shares.

**Q: Is this the same as multi-sig cryptocurrency wallets?**
A: Similar concept but different implementation. Multi-sig requires blockchain support. Secret sharing works for any secret (keys, passwords, files) and doesn't require blockchain.

**Q: Can I use this for commercial projects?**
A: Yes. Licensed under MPL-2.0, which permits commercial use. See [LICENSE](LICENSE) for details.

**Q: What's the maximum secret size?**
A: 100MB (MAX_SECRET_SIZE). This limit prevents memory exhaustion DoS attacks. For most use cases (passwords, keys, seed phrases), this is more than sufficient.

## Development

### Setup

```bash
# Clone repository
git clone https://github.com/reidhoch/horcrux.git
cd horcrux

# Install dependencies
uv sync

# Install pre-commit hooks
uv run pre-commit install
```

### Running Tests

```bash
# Run full test suite (152 tests)
uv run pytest

# With coverage report
uv run pytest --cov=shamir --cov-report=html

# Run specific test file
uv run pytest tests/test_shamir.py -v

# Run with parallelization
uv run pytest -n auto
```

### Running Benchmarks

```bash
# Run benchmarks with pytest-codspeed
uv run pytest tests/test_benchmarks.py --codspeed

# Run benchmarks only (skip regular tests)
uv run pytest -m benchmark --codspeed

# Run regular tests without benchmarks
uv run pytest -m "not benchmark"
```

Benchmarks track performance of core operations across different configurations:

- **Split/Combine operations**: 1KB, 10KB, 100KB, 1MB
- **Share configurations**: Standard (5 parts/3 threshold)
- **Roundtrip operations**: Complete split+combine cycles
- **GF(256) math primitives**: Addition, multiplication, division, and inverse operations

### Code Quality

```bash
# Run all pre-commit checks
uv run pre-commit run --all-files

# Individual checks
uv run ruff check shamir          # Linting
uv run ruff format shamir         # Formatting
uv run mypy shamir/               # Type checking

# Security scanning
uv run bandit -r shamir/ -s B105  # Python security linting
uv run pip-audit --desc           # Dependency vulnerability scanning
```

### Contributing

See [`AGENTS.md`](AGENTS.md) for comprehensive development guidelines including:

- Code conventions and style requirements
- Testing best practices
- Security considerations
- API design principles
- Code review guidelines

All contributions must:

- Pass all tests (100% coverage required)
- Pass ruff linting with all rules enabled
- Pass mypy strict type checking
- Include tests for new functionality
- Follow existing code patterns

## Comparison

| Feature | Horcrux | secretsharing | pyshamir |
|---------|---------|--------------|----------|
| Runtime Dependencies | 0 | 6+ | 2+ |
| Type Hints | Full (PEP 561) | Partial | None |
| Test Coverage | 100% (152 tests) | ~60% | ~40% |
| Constant-time Ops | ✅ | ❌ | ❌ |
| Share Versioning | ✅ | ❌ | ❌ |
| Property Tests | ✅ | ❌ | ❌ |
| DoS Protection | ✅ | ❌ | ❌ |
| Security Scanning | ✅ | ⚠️ | ❌ |
| Performance | Optimized | Standard | Standard |
| Python 3.11+ | ✅ | ✅ | ✅ |
| Active Maintenance | ✅ | ⚠️ | ⚠️ |

## Changelog

See [Releases](https://github.com/reidhoch/horcrux/releases) for detailed version history.

Recent changes:

- **v1.2.0** (upcoming): Security hardening and performance optimizations
  - Added MAX_SECRET_SIZE (100MB) limit to prevent memory exhaustion DoS
  - Enhanced security documentation with RNG and memory security guidance
  - 15-20% performance improvement from optimized combine() loop
  - 5-10% memory reduction from __slots__ optimization
  - Added type aliases (Share, Shares) and Literal types for better type safety
  - Added py.typed marker for PEP 561 compliance
  - New security workflow with Semgrep, Bandit, pip-audit, GitLeaks
  - 152 tests (was 142)
- **v1.1.0**: Added share format versioning with backward compatibility
- **v1.0.7**: Comprehensive security and property-based testing
- **v1.0.0**: Initial stable release

## License

This project is licensed under the **Mozilla Public License 2.0 (MPL-2.0)**.

This means you can:

- ✅ Use commercially
- ✅ Modify and distribute
- ✅ Use privately
- ✅ Include in larger proprietary works

You must:

- 📄 Include license and copyright notice
- 📄 Disclose source for MPL-licensed files
- 📄 State changes made to MPL-licensed files

See [LICENSE](LICENSE) for full details.

## Acknowledgments

- Based on [HashiCorp Vault's implementation](https://github.com/hashicorp/vault/tree/main/shamir) of Shamir's Secret Sharing
- Implements the algorithm described in [Shamir's 1979 paper](https://doi.org/10.1145/359168.359176): "How to share a secret"
- GF(256) arithmetic inspired by various SSS implementations and academic papers
- Testing approach inspired by property-based testing methodology

## Citation

If you use Horcrux in academic work, please cite:

```bibtex
@software{horcrux,
  author = {Hochstedler, Reid},
  title = {Horcrux: A Python implementation of Shamir's Secret Sharing},
  year = {2025},
  url = {https://github.com/reidhoch/horcrux}
}
```

## Star History

<a href="https://www.star-history.com/#reidhoch/horcrux&type=date&legend=top-left">
 <picture>
   <source media="(prefers-color-scheme: dark)" srcset="https://api.star-history.com/svg?repos=reidhoch/horcrux&type=date&theme=dark&legend=top-left" />
   <source media="(prefers-color-scheme: light)" srcset="https://api.star-history.com/svg?repos=reidhoch/horcrux&type=date&legend=top-left" />
   <img alt="Star History Chart" src="https://api.star-history.com/svg?repos=reidhoch/horcrux&type=date&legend=top-left" />
 </picture>
</a>

---

**Questions?** Open an [issue](https://github.com/reidhoch/horcrux/issues) or start a [discussion](https://github.com/reidhoch/horcrux/discussions).

**Security Issues?** See [SECURITY.md](SECURITY.md) for responsible disclosure guidelines.
