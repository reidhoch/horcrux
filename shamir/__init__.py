"""Python implementation of Shamir's Secret Sharing."""

from random import Random, SystemRandom
from typing import Final

from shamir.utils import Polynomial, interpolate

from .errors import Error

__all__: list[str] = ["__version__", "combine", "split"]

try:
    from shamir._version import __version__
except ImportError:
    # Version file is generated during build
    try:
        from importlib.metadata import PackageNotFoundError, version

        __version__ = version("horcrux")
    except PackageNotFoundError:
        __version__ = "unknown"

TWO: Final[int] = 2
MAX_PARTS: Final[int] = 255
MAX_THRESHOLD: Final[int] = 255


def combine(parts: list[bytearray]) -> bytearray:
    """Combine is used to reconstruct a secret once a threshold is reached."""
    if len(parts) < TWO:
        raise ValueError(Error.LESS_THAN_TWO_PARTS)
    first_part_len: int = len(parts[0])
    if first_part_len < TWO:
        raise ValueError(Error.PARTS_MUST_BE_TWO_BYTES)
    for part in parts:
        if len(part) != first_part_len:
            raise ValueError(Error.ALL_PARTS_MUST_BE_SAME_LENGTH)

    secret: bytearray = bytearray(first_part_len - 1)
    x_s: bytearray = bytearray(len(parts))
    y_s: bytearray = bytearray(len(parts))
    check_map: dict[int, bool] = {}

    for i, part in enumerate(parts):
        sample: int = part[first_part_len - 1]
        if sample in check_map:
            raise ValueError(Error.DUPLICATE_PART)
        check_map[sample] = True
        x_s[i] = sample

    for idx, _ in enumerate(secret):
        for i, part in enumerate(parts):
            y_s[i] = part[idx]
        val: int = interpolate(x_s, y_s, 0)
        secret[idx] = val

    return secret


def split(
    secret: bytes,
    parts: int,
    threshold: int,
    rng: Random = SystemRandom(),  # noqa: B008
) -> list[bytearray]:
    """Split an arbitrarily long secret into a number of parts.

    A threshold of which are required to reconstruct the secret.
    """
    if parts < threshold:
        raise ValueError(Error.PARTS_CANNOT_BE_LESS_THAN_THRESHOLD)
    if parts > MAX_PARTS or threshold > MAX_THRESHOLD:
        raise ValueError(Error.PARTS_OR_THRESHOLD_CANNOT_EXCEED_255)
    if threshold < TWO:
        raise ValueError(Error.THRESHOLD_MUST_BE_AT_LEAST_2)
    if len(secret) == 0:
        raise ValueError(Error.CANNOT_SPLIT_EMPTY_SECRET)
    if not rng:
        raise ValueError(Error.UNINITIALIZED_RNG)

    # Generate a random list of x coordinates.
    x_coords: list[int] = [rng.randrange(0, 255) for _ in range(1, 256)]

    # Allocate output array
    output: list[bytearray] = [bytearray() for _ in range(parts)]
    for idx in range(len(output)):
        output[idx] = bytearray(len(secret) + 1)
        output[idx][len(secret)] = x_coords[idx] + 1

    for idx, val in enumerate(secret):
        # Construct a random polynomial for each byte of the secret.
        # Since we're using a field size of 256 we can only represent
        # a single byte as the intercept of the polynomial, so we have
        # to use a new polynomial for each byte.
        poly: Polynomial = Polynomial(degree=(threshold - 1), intercept=val, rng=rng)

        # Generate (x, y) pairs
        for i in range(parts):
            x: int = x_coords[i] + 1
            y: int = poly.evaluate(x)
            output[i][idx] = y
    return output
