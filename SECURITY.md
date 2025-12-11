# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a Vulnerability

If you discover a security vulnerability:

1. **Do NOT open a public issue**
2. **Email**: Contact maintainers privately at [security contact - to be added]
3. **Provide details**: Describe the vulnerability, impact, and reproduction steps
4. **Allow time**: Give maintainers reasonable time to address before disclosure

---

# Security Guidelines

This document covers security standards, cryptographic requirements, and threat model considerations for the Horcrux library.

## Overview

Horcrux is a **security-focused cryptographic library** implementing Shamir's Secret Sharing. All code must maintain security properties outlined in this document.

## Core Security Requirements

### 1. Constant-Time Operations

Avoid timing side channels in all cryptographic operations:

- **No branching on secret data**: Use bitwise operations and masking instead
- **Constant-time comparison**: Use constant-time comparison for sensitive values
- **Python limitations**: Be aware of Python's optimizations (string interning, etc.)

**Example Pattern:**

```python
# Bad: Branches on secret value
if secret_byte == 0x00:
    result = process_zero()
else:
    result = process_nonzero(secret_byte)

# Good: Constant-time using masking
is_zero = (secret_byte == 0)
mask = -int(is_zero)  # -1 if zero, 0 if nonzero
result = (mask & zero_value) | (~mask & nonzero_value)
```

### 2. No Secret Leakage

Secrets must never appear in observable outputs:

- **Error messages**: Never include secret data in exceptions
- **Logging**: Secrets should not appear in logs (even debug logs)
- **String representations**: Avoid `__repr__` or `__str__` methods on secret-containing objects
- **Memory clearing**: Clear sensitive data when possible (though Python GC complicates this)

**Example:**

```python
# Bad: Leaks secret length in error
raise ValueError(f"Secret of length {len(secret)} is too long")

# Good: Uses predefined error from enum
raise ValueError(Error.SECRET_TOO_LARGE.value)
```

### 3. Cryptographic RNG

Use cryptographically secure random number generation:

- **Default**: Use `random.SystemRandom()` which uses OS cryptographic RNG
- **Testing**: Only accept `random.Random` interface for testing/reproducibility
- **Documentation**: Clearly document when deterministic RNG is acceptable (tests only)

**Example:**

```python
def split(
    secret: bytearray,
    parts: int,
    threshold: int,
    rng: random.Random | None = None,  # Only for testing
) -> Shares:
    if rng is None:
        rng = random.SystemRandom()  # Cryptographic RNG
    # ... use rng for coefficient generation
```

### 4. Input Validation

Validate all inputs before processing:

- **Fail fast**: Check all constraints immediately
- **Specific errors**: Use error messages from `Error` enum
- **Validation order**: Consistent order for predictable error reporting
- **Range checks**: Verify all numeric inputs are in valid ranges

**Example:**

```python
def split(secret: bytearray, parts: int, threshold: int, ...) -> Shares:
    # Validation order matters for consistent error messages
    if len(secret) == 0:
        raise ValueError(Error.SECRET_EMPTY.value)
    if len(secret) > MAX_SECRET_SIZE:
        raise ValueError(Error.SECRET_TOO_LARGE.value)
    if parts < 2:
        raise ValueError(Error.PARTS_TOO_SMALL.value)
    if parts > 255:
        raise ValueError(Error.PARTS_TOO_LARGE.value)
    if threshold < 2:
        raise ValueError(Error.THRESHOLD_TOO_SMALL.value)
    if threshold > parts:
        raise ValueError(Error.THRESHOLD_EXCEEDS_PARTS.value)
    # ... proceed with validated inputs
```

### 5. Resource Limits

Enforce limits to prevent denial-of-service attacks:

- **MAX_SECRET_SIZE**: 100MB limit prevents memory exhaustion
- **Parts limit**: 255 parts maximum (GF(256) constraint)
- **Validate before allocation**: Check limits before allocating large buffers

**Rationale:**

- 100MB secret limit: Prevents memory exhaustion DoS attacks
- 255 parts limit: Mathematical constraint of GF(256)
- Early validation: Fail fast before consuming resources

## Cryptographic Standards

### Galois Field GF(256)

All arithmetic operations must use proper GF(256) mathematics:

- **Never use Python operators**: `+`, `*`, `/` give wrong results
- **Always use `shamir.math` functions**: `add()`, `mul()`, `div()`
- **Check for zero**: Division by zero is undefined in GF(256)

### Polynomial Construction

Secret sharing uses random polynomials over GF(256):

- **Degree**: `threshold - 1` (e.g., 3-of-5 uses degree-2 polynomial)
- **Coefficients**: Generated using cryptographic RNG
- **Per-byte polynomials**: Each secret byte has its own polynomial
- **X-coordinates**: Shuffled list of 256 values to prevent predictable shares

### Interpolation

Lagrange interpolation reconstructs the secret:

- **Constant-time**: No branching on secret values during interpolation
- **Field operations**: All operations use GF(256) arithmetic
- **Error handling**: Invalid shares detected by incorrect reconstruction

## When Adding Security-Sensitive Code

Before adding or modifying security-sensitive code:

### 1. Consider Side Channels

- **Timing attacks**: Does execution time depend on secret values?
- **Memory access patterns**: Are memory accesses constant-time?
- **Exceptions**: Do exceptions leak information about secret values?
- **Cache timing**: Consider CPU cache effects (though Python abstracts this)

### 2. Review Crypto Primitives

- **Correct usage**: Verify proper use of GF(256) operations
- **Mathematical correctness**: Ensure algorithms match specifications
- **Edge cases**: Test boundary conditions (zero values, maximum values)

### 3. Add Property-Based Tests

Use Hypothesis to test cryptographic properties:

- **Roundtrip property**: `combine(split(secret, n, k)) == secret`
- **Threshold property**: Any k shares work, k-1 shares don't
- **Invariants**: Mathematical properties hold for all inputs
- **Version consistency**: All share formats reconstruct correctly

### 4. Document Security Properties

Explain what security guarantees the code provides:

- **What is protected**: Which values are kept secret
- **Threat model**: What attacks are mitigated
- **Limitations**: What attacks are not prevented
- **Assumptions**: What properties must hold for security

### 5. Get Review

Security-sensitive changes require thorough review:

- **Multiple reviewers**: At least two reviewers for crypto code
- **Testing**: Demonstrate tests cover security properties
- **Documentation**: Explain security rationale in comments

## Threat Model

### In Scope

Horcrux protects against:

1. **Information leakage**: Fewer than threshold shares reveal nothing about the secret
2. **Timing attacks**: Constant-time operations prevent timing side channels
3. **Resource exhaustion**: Size limits prevent memory exhaustion DoS
4. **Invalid inputs**: Comprehensive validation prevents malformed inputs

### Out of Scope

Horcrux does **not** protect against:

1. **Physical attacks**: No protection against hardware attacks (cold boot, DMA)
2. **Side-channel attacks**: Python's runtime has inherent timing variations
3. **Malicious shares**: Shares are assumed to be authentic (no authentication)
4. **Dealer honesty**: The party splitting the secret is trusted
5. **Secure storage**: How shares are stored is user responsibility
6. **Network security**: How shares are transmitted is user responsibility
7. **Memory forensics**: Python GC makes memory clearing difficult

### Assumptions

The security model assumes:

1. **Trusted dealer**: The party running `split()` is honest
2. **Authentic shares**: Shares provided to `combine()` are not forged
3. **No side-channel observation**: Attacker cannot observe execution (though we minimize leakage)
4. **OS RNG security**: `random.SystemRandom()` provides cryptographic randomness
5. **Python runtime integrity**: CPython is not compromised

## Security Testing

### Automated Security Scanning

The project includes comprehensive security scanning:

- **Semgrep SAST**: Advanced static analysis with OWASP Top 10, secrets, and security-audit rulesets
- **Bandit**: Python-specific security linting configured in `pyproject.toml`
- **pip-audit**: Dependency vulnerability scanning (fails on critical/high severity)
- **GitLeaks**: Secrets detection across full git history
- **Schedule**: Runs on push/PR, plus weekly Monday 00:00 UTC scans
- **Results**: SARIF uploaded to GitHub Security tab

### Manual Security Review

For security-critical changes:

1. **Code review**: At least two reviewers familiar with cryptography
2. **Testing**: Property-based tests demonstrate security properties
3. **Documentation**: Security rationale explained in comments
4. **Threat modeling**: Consider attack vectors and mitigations

### Constant-Time Verification

See TESTING.md for detailed constant-time testing procedures:

- Basic timing tests catch obvious leaks
- Enhanced statistical tests provide rigor
- Python limitations mean true constant-time is impossible
- Tests verify practical exploitation thresholds not exceeded

## Security Best Practices for Users

When using Horcrux in your application:

### 1. Protect Shares at Rest

- **Encryption**: Encrypt shares before storing
- **Access control**: Restrict who can read shares
- **Separate storage**: Store shares in different locations

### 2. Protect Shares in Transit

- **TLS**: Use TLS 1.3+ for network transmission
- **Authentication**: Verify share authenticity
- **Avoid logging**: Never log share contents

### 3. Handle Secrets Securely

- **Clear memory**: Zero secret data after use (best effort in Python)
- **Minimize lifetime**: Reconstruct secret only when needed
- **Avoid disk**: Don't write secrets to disk if possible

### 4. Validate Reconstruction

- **Checksum**: Use checksums or MACs to detect tampered shares
- **Threshold**: Use appropriate threshold for your threat model
- **Share count**: Generate sufficient shares for your use case

### 5. Use Explicit Versioning

- **Specify version**: Pass explicit `version` parameter to `combine()` for 100% reliability
- **Don't mix versions**: Never mix v0 and v1 shares
- **Version tracking**: Store version metadata with shares

## Constant-Time Implementation Notes

### Why Constant-Time Matters

Timing attacks can leak secret information:

- **Different execution paths**: Branches on secret values create timing differences
- **Cache effects**: Memory access patterns affect timing
- **Early termination**: Loops that exit based on secret values leak information

### Python Limitations

Python's CPython runtime makes true constant-time impossible:

1. **Baseline variability**: ~35-37% coefficient of variation in basic operations
2. **Garbage collection**: Unpredictable pauses (can reach 400%+ CV)
3. **Dynamic typing**: Variable overhead for type checking and allocation
4. **OS scheduling**: Jitter from operating system

### What We Do

Despite limitations, we implement constant-time patterns:

- **Bit masking**: Use bitwise operations instead of branches
- **No secret-dependent branches**: Avoid `if` statements on secret values
- **Constant-time comparison**: Use timing-safe comparison functions
- **Loop invariants**: Loops run for fixed iterations, not dependent on secrets

### Practical Security

Our constant-time implementation provides:

- **Below exploitation threshold**: Timing variations < 1.2x (20% difference)
- **Best effort**: Maximum protection within Python's constraints
- **No obvious leaks**: Statistical tests verify no secret-dependent timing

**For stronger guarantees**: Use compiled languages with explicit constant-time libraries (libsodium, BearSSL).

## References

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE: Common Weakness Enumeration](https://cwe.mitre.org/)
- [Timing Attacks on RSA](https://www.iacr.org/cryptodb/archive/2003/CHES/1965/1965.pdf)
- [Shamir's Secret Sharing (Original Paper)](https://dl.acm.org/doi/10.1145/359168.359176)
- [HashiCorp Vault Shamir Implementation](https://github.com/hashicorp/vault)
