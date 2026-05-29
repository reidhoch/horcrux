"""Python implementation of Shamir's Secret Sharing."""

from random import Random, SystemRandom
from typing import Final, TypeAlias

from shamir.math import add, div, mul
from shamir.utils import Polynomial

from .errors import Error

__all__: list[str] = ["__version__", "combine", "split"]

try:
    from shamir._version import __version__
except ImportError:  # pragma: no cover
    # Version file is generated during build
    try:
        from importlib.metadata import PackageNotFoundError, version

        __version__ = version("horcrux")
    except PackageNotFoundError:
        __version__ = "unknown"

MIN_PARTS: Final[int] = 2
MIN_THRESHOLD: Final[int] = 2
MIN_PART_LENGTH: Final[int] = 2
MAX_PARTS: Final[int] = 255
MAX_THRESHOLD: Final[int] = 255
MAX_SECRET_SIZE: Final[int] = (
    100 * 1024 * 1024
)  # 100MB - prevents memory exhaustion DoS

# Type aliases for better documentation
# NOTE: `Share` is a mutable type (bytearray) for performance reasons.
#       Do not modify shares after creation, as this may lead to unexpected behavior.
Share: TypeAlias = bytearray
Shares: TypeAlias = list[Share]


def combine(parts: Shares) -> bytearray:
    r"""Combine is used to reconstruct a secret once a threshold is reached.

    Args:
        parts: List of secret parts to combine. Must all be the same length
              and include the x-coordinate in the last byte.

    Returns:
        The reconstructed secret as a bytearray.

    Raises:
        ValueError: If parts list has fewer than 2 elements, if parts have
                   mismatched lengths, if parts are too short, or if duplicate
                   parts are detected.

    Examples:
        >>> secret = combine(shares)

    Security Considerations:
        Python Constant-Time Limitations:
            This library implements constant-time algorithms for GF(256) operations
            to mitigate timing side-channels. However, CPython has inherent limitations:

            1. INTEGER CACHING: CPython caches integers in range [-5, 256], causing
               different memory access patterns for cached vs. non-cached values.
               This creates potential cache timing side-channels.

            2. INTERPRETER OVERHEAD: The GIL, reference counting, and bytecode
               interpretation add timing noise that may obscure or reveal patterns.

            3. MEMORY ALLOCATOR: Python's memory manager behavior is not constant-time.

            For applications requiring defense against sophisticated timing attacks
            (nation-state adversaries, side-channel experts):
            - Use native extension module (Rust/C with formal verification)
            - Deploy in secure enclaves (Intel SGX, ARM TrustZone)
            - Integrate with HSM for critical operations
            - Consider vetted libraries like libsodium via ctypes

            This implementation provides best-effort constant-time operations suitable
            for most applications, but cannot guarantee protection against all
            side-channel attacks in pure Python.

        Memory Security:
            Python's garbage collector may leave secret copies in memory.
            The reconstructed secret may persist until GC runs.

            For highly sensitive secrets:
            - Disable core dumps: ulimit -c 0 or setrlimit(RLIMIT_CORE, 0)
            - Use encrypted swap/pagefile
            - Clear returned bytearray after use: secret[:] = b'\x00' * len(secret)
            - Run in memory-locked processes (mlock/VirtualLock)

    WARNING: This function does not validate the threshold. Ensure you
    provide at least the threshold number of parts used during split().
    Fewer parts will produce an incorrect result without error.

    WARNING: Shares created by versions 1.1.0-1.3.0 used a ``0x01`` version
    prefix. Those shares are no longer supported: feeding one here treats the
    prefix as a y-value and silently reconstructs an incorrect secret with no
    error. Re-split any secrets that were shared under those versions.
    """
    if len(parts) < MIN_PARTS:
        raise ValueError(Error.LESS_THAN_TWO_PARTS)
    first_part_len: int = len(parts[0])
    if first_part_len < MIN_PART_LENGTH:
        raise ValueError(Error.PARTS_MUST_BE_TWO_BYTES)
    if not all(len(part) == first_part_len for part in parts):
        raise ValueError(Error.ALL_PARTS_MUST_BE_SAME_LENGTH)

    # Share format: [y_values..., x_coordinate]
    secret_len = first_part_len - 1

    secret: bytearray = bytearray(secret_len)
    num_parts: int = len(parts)
    x_samples: bytearray = bytearray(num_parts)
    # Bitset for O(1) duplicate detection (256 bytes vs set overhead)
    seen: bytearray = bytearray(256)

    for i in range(num_parts):
        sample: int = parts[i][first_part_len - 1]
        if seen[sample]:
            raise ValueError(Error.DUPLICATE_PART)
        seen[sample] = 1
        x_samples[i] = sample

    # Pre-compute Lagrange basis functions for x=0 (optimization)
    # Since we always interpolate at x=0 and x_samples are the same for all
    # secret bytes, we can compute the basis values once and reuse them.
    # This eliminates O(k²) redundant GF(256) operations per byte.
    basis_values = _compute_lagrange_basis(x_samples)

    # Reconstruct each secret byte using pre-computed basis values
    # secret[idx] = ∑[i] y_samples[i] * basis_values[i]
    # Cache num_parts and use direct indexing for better performance
    for idx in range(len(secret)):
        result: int = 0
        for i in range(num_parts):
            y_value: int = parts[i][idx]
            result = add(result, mul(y_value, basis_values[i]))
        secret[idx] = result

    return secret


def _compute_lagrange_basis(x_samples: bytearray) -> bytearray:
    """Pre-compute Lagrange basis functions for interpolation at x=0.

    For Lagrange interpolation at x=0, the basis functions only depend on the
    x-coordinates and can be computed once for all secret bytes. This optimization
    eliminates O(k²) redundant GF(256) operations per byte.

    For x=0, the Lagrange basis formula simplifies:
    L_i(0) = ∏[j≠i] (0 - x_j) / (x_i - x_j) = ∏[j≠i] x_j / (x_i - x_j)

    In GF(256) with addition being XOR:
    L_i(0) = ∏[j≠i] x_j / (x_i ⊕ x_j)

    Args:
        x_samples: X-coordinates of the shares (public data).

    Returns:
        Pre-computed Lagrange basis values for each share.
    """
    basis_values: bytearray = bytearray(len(x_samples))
    for i in range(len(x_samples)):
        basis: int = 1
        for j in range(len(x_samples)):
            if i == j:
                continue
            # For x=0: numerator = 0 ⊕ x_samples[j] = x_samples[j]
            numerator: int = x_samples[j]
            # Denominator = x_samples[i] ⊕ x_samples[j]
            denominator: int = add(x_samples[i], x_samples[j])
            term: int = div(numerator, denominator)
            basis = mul(basis, term)
        basis_values[i] = basis
    return basis_values


def _validate_split_params(
    secret: bytes,
    parts: int,
    threshold: int,
) -> None:
    """Validate parameters for split operation.

    Args:
        secret: The secret to validate.
        parts: Number of parts to create.
        threshold: Minimum parts needed to reconstruct.

    Raises:
        ValueError: If any parameter is invalid.
    """
    if parts > MAX_PARTS:
        raise ValueError(Error.PARTS_CANNOT_EXCEED_255)
    if threshold > MAX_THRESHOLD:
        raise ValueError(Error.THRESHOLD_CANNOT_EXCEED_255)
    if threshold < MIN_THRESHOLD:
        raise ValueError(Error.THRESHOLD_MUST_BE_AT_LEAST_2)
    if parts < threshold:
        raise ValueError(Error.PARTS_CANNOT_BE_LESS_THAN_THRESHOLD)
    if not secret:
        raise ValueError(Error.CANNOT_SPLIT_EMPTY_SECRET)
    if len(secret) > MAX_SECRET_SIZE:
        raise ValueError(Error.SECRET_EXCEEDS_MAX_SIZE)


def _generate_x_coordinates(rng: Random) -> list[int]:
    """Generate unique x-coordinates for shares using Fisher-Yates shuffle.

    Args:
        rng: Random number generator.

    Returns:
        List of unique x-coordinates in range [1..255].
    """
    # Generate unique values [0..254] and shuffle
    x_coords: list[int] = list(range(MAX_PARTS))
    rng.shuffle(x_coords)
    return x_coords


def _allocate_shares(
    parts: int,
    secret_len: int,
    x_coords: list[int],
) -> Shares:
    """Allocate and initialize share arrays.

    Args:
        parts: Number of shares to create.
        secret_len: Length of the secret in bytes.
        x_coords: Pre-generated x-coordinates for shares.

    Returns:
        Output shares in the format [y_bytes..., x].
    """
    output: Shares = [bytearray(secret_len + 1) for _ in range(parts)]

    # Set x-coordinates (last byte of each part, add 1 to get range [1..255])
    for idx, part in enumerate(output):
        part[len(part) - 1] = x_coords[idx] + 1

    return output


def split(
    secret: bytes,
    parts: int,
    threshold: int,
    rng: Random | None = None,
) -> Shares:
    r"""Split an arbitrarily long secret into a number of parts.

    A threshold of which are required to reconstruct the secret.

    Args:
        secret: The secret data to split into shares (max 100MB).
        parts: The number of shares to create (2-255).
        threshold: The minimum number of shares required to reconstruct (2-255).
        rng: Optional random number generator. Defaults to SystemRandom().

    Returns:
        List of shares as bytearrays. Each share is [y_values..., x_coordinate].

    Raises:
        ValueError: If parameters are invalid or out of allowed ranges.

    Security Considerations:
        Random Number Generator (Critical):
            The RNG is critical for security. The default SystemRandom() uses
            OS-level cryptographic RNG (/dev/urandom on Unix, CryptGenRandom
            on Windows) and provides information-theoretic security.

            WARNING: Only provide a custom RNG for testing/reproducibility.
            Using a weak or predictable RNG (e.g., Random(seed)) completely
            breaks information-theoretic security. Attackers could predict
            polynomial coefficients and forge arbitrary shares.

            For production: ALWAYS use the default SystemRandom().
            For HSM integration: Implement Random interface with HSM calls.

        Memory Security:
            Python's garbage collector may leave secret copies in memory.
            Secrets and polynomial coefficients may persist until GC runs.

            For highly sensitive secrets:
            - Disable core dumps: ulimit -c 0 or setrlimit(RLIMIT_CORE, 0)
            - Use encrypted swap/pagefile
            - Clear returned bytearrays after use: part[:] = b'\x00' * len(part)
            - Run in memory-locked processes (mlock/VirtualLock)
            - Consider secure enclaves (Intel SGX, ARM TrustZone) for
              ultra-high-security scenarios

        Python Constant-Time Limitations:
            This library implements constant-time algorithms for GF(256) operations
            to mitigate timing side-channels. However, CPython has inherent limitations:

            1. INTEGER CACHING: CPython caches integers in range [-5, 256], causing
               different memory access patterns for cached vs. non-cached values.
               This creates potential cache timing side-channels.

            2. INTERPRETER OVERHEAD: The GIL, reference counting, and bytecode
               interpretation add timing noise that may obscure or reveal patterns.

            3. MEMORY ALLOCATOR: Python's memory manager behavior is not constant-time.

            For applications requiring defense against sophisticated timing attacks
            (nation-state adversaries, side-channel experts):
            - Use native extension module (Rust/C with formal verification)
            - Deploy in secure enclaves (Intel SGX, ARM TrustZone)
            - Integrate with HSM for critical operations
            - Consider vetted libraries like libsodium via ctypes

            This implementation provides best-effort constant-time operations suitable
            for most applications, but cannot guarantee protection against all
            side-channel attacks in pure Python.

        Information Disclosure:
            Share size reveals secret length (inherent to Shamir's Secret Sharing).
            Information-theoretic security applies to secret CONTENT, not metadata.

            If secret length must be hidden:
            - Pad secret to fixed size before splitting
            - Use format-preserving encryption as wrapper
            - Combine with steganography for distribution

        Performance:
            Memory usage: O(secret_length * parts)
            CPU time: O(secret_length * parts * threshold)
            Maximum secret size: 100MB (configurable via MAX_SECRET_SIZE)
    """
    # Validate all parameters
    _validate_split_params(secret, parts, threshold)

    # Set defaults
    if rng is None:
        rng = SystemRandom()

    # Generate unique x-coordinates for all shares
    x_coords = _generate_x_coordinates(rng)

    # Allocate output shares
    output = _allocate_shares(parts, len(secret), x_coords)

    # Optimization: Pre-compute x-coordinate offsets (x_coords[i] + 1)
    # This eliminates O(secret_length * parts) redundant additions
    x_values: bytearray = bytearray(x_coords[i] + 1 for i in range(parts))

    # Optimization: Batch generate all random coefficients in single syscall
    # This reduces O(secret_length) syscalls to O(1) syscall to OS RNG
    degree = threshold - 1
    # Pre-generate all random coefficients for all polynomials at once
    all_random_coeffs = bytearray(rng.randbytes(len(secret) * degree))

    # Generate polynomial shares for each byte of the secret
    for idx, val in enumerate(secret):
        # Construct a random polynomial for each byte of the secret.
        # Since we're using a field size of 256 we can only represent
        # a single byte as the intercept of the polynomial, so we have
        # to use a new polynomial for each byte.
        # Extract pre-generated random coefficients for this byte's polynomial
        coeff_start = idx * degree
        coeff_end = coeff_start + degree
        coeffs = all_random_coeffs[coeff_start:coeff_end]
        poly: Polynomial = Polynomial._from_coefficients(val, coeffs)  # noqa: SLF001

        # Evaluate polynomial at each x-coordinate and store y-values
        for i in range(parts):
            output[i][idx] = poly.evaluate(x_values[i])

    return output
