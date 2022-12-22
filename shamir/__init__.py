"""Python implementation of Shamir's Secret Sharing."""
from random import Random, SystemRandom

from shamir.utils import Polynomial, interpolate

__all__: list[str] = ["combine", "split"]


def combine(parts: list[bytearray]) -> bytearray:
    """Combine is used to reconstruct a secret once a threshold is reached."""
    if len(parts) < 2:
        raise ValueError("Less than two parts cannot be used to reconstruct the secret")
    first_part_len: int = len(parts[0])
    if first_part_len < 2:
        raise ValueError("Parts must be at least two bytes")
    for part in parts:
        if len(part) != first_part_len:
            raise ValueError("All parts must be the same length")

    secret: bytearray = bytearray(first_part_len - 1)
    x_s: bytearray = bytearray(len(parts))
    y_s: bytearray = bytearray(len(parts))
    check_map: dict[int, bool] = {}

    for i, part in enumerate(parts):
        sample: int = part[first_part_len - 1]
        if sample in check_map:
            raise ValueError("Duplicate part detected")
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
    """
    Split an arbitrarily long secret into a number of parts.

    A threshold of which are required to reconstruct the secret.
    """
    if parts < threshold:
        raise ValueError("Parts cannot be less than threshold")
    if parts > 255 or threshold > 255:
        raise ValueError("Parts or Threshold cannot exceed 255")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if len(secret) == 0:
        raise ValueError("Cannot split an empty secret")
    if not rng:
        raise ValueError("RNG not initialized")

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
