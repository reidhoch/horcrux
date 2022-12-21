"""Math utility functions in GF(2^8)."""
from sys import byteorder
from typing import Final

from cryptography.hazmat.primitives import constant_time

from .tables import EXP_TABLE, LOG_TABLE

__all__: list[str] = ["add", "div", "mul", "EXP_TABLE", "LOG_TABLE"]
ZERO: Final[bytes] = b"\x00"


def add(a: int, b: int) -> int:
    """Combine two numbers in GF(2^8)."""
    return a ^ b


def div(a: int, b: int) -> int:
    """Divides two numbers in GF(2^8)."""
    # Ensure that we return zero if a is zero, but don't leak timing info.
    if constant_time.bytes_eq(a.to_bytes(1, byteorder), ZERO):
        return 0
    if constant_time.bytes_eq(b.to_bytes(1, byteorder), ZERO):
        raise ZeroDivisionError

    log_a: int = LOG_TABLE[a]
    log_b: int = LOG_TABLE[b]
    diff: int = ((log_a - log_b) + 255) % 255

    return EXP_TABLE[diff]


def mul(a: int, b: int) -> int:
    """Multiply two numbers in GF(2^8)."""
    # Ensure that we return zero if a or b is zero, but don't leak timing info.
    if constant_time.bytes_eq(a.to_bytes(1, byteorder), ZERO) or constant_time.bytes_eq(
        b.to_bytes(1, byteorder),
        ZERO,
    ):
        return 0
    log_a: int = LOG_TABLE[a]
    log_b: int = LOG_TABLE[b]
    _sum: int = (log_a + log_b) % 255

    return EXP_TABLE[_sum]
