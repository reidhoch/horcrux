"""Python implementation of Shamir's Secret Sharing."""

from random import Random, SystemRandom
from typing import Final

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
MAX_PARTS: Final[int] = 255
MAX_THRESHOLD: Final[int] = 255


def combine(parts: list[bytearray]) -> bytearray:
    """Combine is used to reconstruct a secret once a threshold is reached.

    Args:
        parts: List of secret parts to combine. Must all be the same length
              and include the x-coordinate in the last byte.

    Returns:
        The reconstructed secret as a bytearray.

    Raises:
        ValueError: If parts list has fewer than 2 elements, if parts have
                   mismatched lengths, if parts are too short, or if duplicate
                   parts are detected.

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

    secret: bytearray = bytearray(first_part_len - 1)
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
        y_samples[:] = [part[idx] for part in parts]
        secret[idx] = interpolate(x_samples, y_samples, 0)

    return secret


def split(
    secret: bytes,
    parts: int,
    threshold: int,
    rng: Random | None = None,
) -> list[bytearray]:
    """Split an arbitrarily long secret into a number of parts.

    A threshold of which are required to reconstruct the secret.
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
    if rng is None:
        rng = SystemRandom()

    # Generate a random list of unique x coordinates using Fisher-Yates shuffle.
    # This ensures no collisions by starting with unique values [0..254].
    # We add 1 when storing to get final x-coordinates in [1..255].
    x_coords: list[int] = list(range(MAX_PARTS))
    rng.shuffle(x_coords)

    # Allocate output array
    secret_len = len(secret)
    output: list[bytearray] = [bytearray(secret_len + 1) for _ in range(parts)]
    for idx, part in enumerate(output):
        part[secret_len] = x_coords[idx] + 1

    for idx, val in enumerate(secret):
        # Construct a random polynomial for each byte of the secret.
        # Since we're using a field size of 256 we can only represent
        # a single byte as the intercept of the polynomial, so we have
        # to use a new polynomial for each byte.
        poly: Polynomial = Polynomial(degree=threshold - 1, intercept=val, rng=rng)

        # Generate (x, y) pairs
        for i in range(parts):
            output[i][idx] = poly.evaluate(x_coords[i] + 1)
    return output
