from secrets import randbelow
from typing import List

from shamir.utils import Polynomial, interpolate

__all__ = ["combine", "split"]


def combine(parts: List[bytearray]) -> bytearray:
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
        samp = part[first_part_len - 1]
        if samp in check_map:
            raise ValueError("Duplicate part detected")
        check_map[samp] = True
        x_s[i] = samp

    for idx, _ in enumerate(secret):
        for i, part in enumerate(parts):
            y_s[i] = part[idx]
        val: int = interpolate(x_s, y_s, 0)
        secret[idx] = val

    return secret


def split(secret: bytes, parts: int, threshold: int) -> List[bytearray]:
    """
    Split an arbitrarily long secret into a number of parts, a threshold of which
    are required to reconstruct the secret.
    """
    if parts < threshold:
        raise ValueError("Parts cannot be less than threshold")
    if parts > 255 or threshold > 255:
        raise ValueError("Parts or Threshold cannot exceed 255")
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if len(secret) == 0:
        raise ValueError("Cannot split an empty secret")

    x_coords: List[int] = [randbelow(255) for _ in range(1, 256)]

    output: List[bytearray] = [bytearray() for _ in range(parts)]
    for i in range(len(output)):
        output[i] = bytearray(len(secret) + 1)
        output[i][len(secret)] = x_coords[i] + 1

    for i, val in enumerate(secret):
        poly: Polynomial = Polynomial(degree=(threshold - 1), intercept=val)
        for j in range(parts):
            x: int = x_coords[j] + 1
            y: int = poly.evaluate(x)
            output[j][i] = y
    return output
