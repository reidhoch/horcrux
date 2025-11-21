"""Python implementation of Shamir's Secret Sharing."""

from random import Random, SystemRandom
from typing import Final, TypeAlias

from shamir.utils import Polynomial, interpolate

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
MIN_PART_LENGTH_VERSIONED: Final[int] = 3
MAX_PARTS: Final[int] = 255
MAX_THRESHOLD: Final[int] = 255
MAX_SECRET_SIZE: Final[int] = (
    100 * 1024 * 1024
)  # 100MB - prevents memory exhaustion DoS

# Share format versions
SHARE_VERSION_LEGACY: Final[int] = 0  # No version byte (backward compatibility)
SHARE_VERSION_1: Final[int] = 1  # Version byte + y-values + x-coordinate
CURRENT_SHARE_VERSION: Final[int] = SHARE_VERSION_1

# Type aliases for better documentation
# NOTE: `Share` is a mutable type (bytearray) for performance reasons.
#       Do not modify shares after creation, as this may lead to unexpected behavior.
Share: TypeAlias = bytearray
Shares: TypeAlias = list[Share]


def combine(parts: Shares) -> bytearray:
    """Combine is used to reconstruct a secret once a threshold is reached.

    Args:
        parts: List of secret parts to combine. Must all be the same length
              and include the x-coordinate in the last byte. Supports both
              legacy (unversioned) and versioned share formats.

    Returns:
        The reconstructed secret as a bytearray.

    Raises:
        ValueError: If parts list has fewer than 2 elements, if parts have
                   mismatched lengths, if parts are too short, if duplicate
                   parts are detected, if shares have unsupported versions,
                   or if mixing different share versions.

    WARNING: This function does not validate the threshold. Ensure you
    provide at least the threshold number of parts used during split().
    Fewer parts will produce an incorrect result without error.
    """
    if len(parts) < MIN_PARTS:
        raise ValueError(Error.LESS_THAN_TWO_PARTS)
    first_part_len: int = len(parts[0])
    if first_part_len < MIN_PART_LENGTH:
        raise ValueError(Error.PARTS_MUST_BE_TWO_BYTES)
    if not all(len(part) == first_part_len for part in parts):
        raise ValueError(Error.ALL_PARTS_MUST_BE_SAME_LENGTH)

    # Detect share version by checking first byte
    # Version byte is 0x00 (legacy) or 0x01+ (versioned)
    # Legacy shares: [y_0, y_1, ..., y_n, x]
    # Versioned shares: [version, y_0, y_1, ..., y_n, x]
    share_version = _detect_share_version(parts)

    if share_version == SHARE_VERSION_LEGACY:
        # Legacy format: no version byte
        # Note: MIN_PART_LENGTH already checked at line 60
        secret_len = first_part_len - 1
        y_offset = 0
    else:  # share_version == SHARE_VERSION_1
        # Version 1 format: [version, y_bytes..., x]
        if first_part_len < MIN_PART_LENGTH_VERSIONED:
            raise ValueError(Error.PARTS_MUST_BE_THREE_BYTES)
        secret_len = first_part_len - 2  # Subtract version byte and x-coordinate
        y_offset = 1  # Skip version byte when reading y-values

    secret: bytearray = bytearray(secret_len)
    x_samples: bytearray = bytearray(len(parts))
    y_samples: bytearray = bytearray(len(parts))
    seen_samples: set[int] = set()

    for i, part in enumerate(parts):
        sample: int = part[first_part_len - 1]
        if sample in seen_samples:
            raise ValueError(Error.DUPLICATE_PART)
        seen_samples.add(sample)
        x_samples[i] = sample

    for idx in range(len(secret)):
        # Direct indexing avoids list comprehension allocation overhead
        for i, part in enumerate(parts):
            y_samples[i] = part[idx + y_offset]
        secret[idx] = interpolate(x_samples, y_samples, 0)

    return secret


def _detect_share_version(parts: Shares) -> int:
    """Detect the version of shares by examining the first byte.

    Args:
        parts: List of shares to examine.

    Returns:
        The detected share version (SHARE_VERSION_LEGACY or SHARE_VERSION_1).

    Raises:
        ValueError: If shares have mixed versions or unsupported version.
    """
    if not parts:
        return SHARE_VERSION_LEGACY

    # Check first byte of first share
    first_byte = parts[0][0]

    # Version detection heuristic:
    # - If first byte is 0x01, likely version 1
    # - Otherwise, assume legacy format
    # This works because:
    # 1. Version 1 shares always start with 0x01
    # 2. Legacy shares start with y-value, which is random (0-255)
    # 3. Only 1/256 chance of false positive (y-value happens to be 0x01)
    # 4. All shares in a set will have same format, so if first is version 1, all are

    if first_byte == SHARE_VERSION_1:
        # Verify all shares have same version
        for part in parts:
            if part[0] != SHARE_VERSION_1:
                raise ValueError(Error.MIXED_SHARE_VERSIONS)
        return SHARE_VERSION_1

    # Assume legacy format (no version byte)
    # Note: There's a 1/256 chance of false positive if legacy share
    # happens to start with 0x01, but this is acceptable trade-off
    return SHARE_VERSION_LEGACY


def _validate_split_params(
    secret: bytes,
    parts: int,
    threshold: int,
    version: int | None,
) -> None:
    """Validate parameters for split operation.

    Args:
        secret: The secret to validate.
        parts: Number of parts to create.
        threshold: Minimum parts needed to reconstruct.
        version: Share format version.

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
    if version is not None and version not in (SHARE_VERSION_LEGACY, SHARE_VERSION_1):
        raise ValueError(Error.UNSUPPORTED_SHARE_VERSION)


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
    version: int,
    x_coords: list[int],
) -> tuple[Shares, int]:
    """Allocate and initialize share arrays.

    Args:
        parts: Number of shares to create.
        secret_len: Length of the secret in bytes.
        version: Share format version (0 for legacy, 1 for version 1).
        x_coords: Pre-generated x-coordinates for shares.

    Returns:
        Tuple of (output shares, y_offset for writing y-values).
    """
    if version == SHARE_VERSION_LEGACY:
        # Legacy format: [y_bytes..., x]
        output: Shares = [bytearray(secret_len + 1) for _ in range(parts)]
        y_offset = 0
    else:  # version == SHARE_VERSION_1
        # Version 1 format: [version, y_bytes..., x]
        output = [bytearray(secret_len + 2) for _ in range(parts)]
        y_offset = 1
        # Set version byte
        for part in output:
            part[0] = version

    # Set x-coordinates (last byte of each part, add 1 to get range [1..255])
    for idx, part in enumerate(output):
        part[len(part) - 1] = x_coords[idx] + 1

    return output, y_offset


def split(
    secret: bytes,
    parts: int,
    threshold: int,
    rng: Random | None = None,
    version: int | None = None,
) -> Shares:
    r"""Split an arbitrarily long secret into a number of parts.

    A threshold of which are required to reconstruct the secret.

    Args:
        secret: The secret data to split into shares (max 100MB).
        parts: The number of shares to create (2-255).
        threshold: The minimum number of shares required to reconstruct (2-255).
        rng: Optional random number generator. Defaults to SystemRandom().
        version: Share format version. 0 for legacy (no version byte),
                1 for version 1 (includes version byte). Defaults to version 1
                for new shares.

    Returns:
        List of shares as bytearrays. Each share includes:
        - Version 1: [0x01, y_values..., x_coordinate]
        - Legacy: [y_values..., x_coordinate]

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

        Performance:
            Memory usage: O(secret_length * parts)
            CPU time: O(secret_length * parts * threshold)
            Maximum secret size: 100MB (configurable via MAX_SECRET_SIZE)
    """
    # Validate all parameters
    _validate_split_params(secret, parts, threshold, version)

    # Set defaults
    if rng is None:
        rng = SystemRandom()
    if version is None:
        version = CURRENT_SHARE_VERSION

    # Generate unique x-coordinates for all shares
    x_coords = _generate_x_coordinates(rng)

    # Allocate output shares and determine y-value offset
    output, y_offset = _allocate_shares(parts, len(secret), version, x_coords)

    # Generate polynomial shares for each byte of the secret
    for idx, val in enumerate(secret):
        # Construct a random polynomial for each byte of the secret.
        # Since we're using a field size of 256 we can only represent
        # a single byte as the intercept of the polynomial, so we have
        # to use a new polynomial for each byte.
        poly: Polynomial = Polynomial(degree=threshold - 1, intercept=val, rng=rng)

        # Evaluate polynomial at each x-coordinate and store y-values
        for i in range(parts):
            output[i][idx + y_offset] = poly.evaluate(x_coords[i] + 1)

    return output
