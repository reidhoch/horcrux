"""Math utility functions in GF(2^8)."""

import hmac
from sys import byteorder
from typing import Final

__all__: list[str] = ["add", "div", "inverse", "mul"]
ZERO: Final[bytes] = b"\x00"


def bytes_eq(a: bytes, b: bytes) -> bool:
    """Test byte equality in constant-time."""
    return hmac.compare_digest(a, b)


def add(a: int, b: int) -> int:
    """Combine two numbers in GF(2^8)."""
    return a ^ b


def div(a: int, b: int) -> int:
    """Divides two numbers in GF(2^8)."""
    # Ensure that we return zero if a is zero, but don't leak timing info.
    if bytes_eq(b.to_bytes(1, byteorder), ZERO):
        raise ZeroDivisionError

    result = mul(a, inverse(b))
    # Mask result to 0 if a is 0, without branching on secrets
    a_is_zero = int(bytes_eq(a.to_bytes(1, byteorder), ZERO))
    return result * (1 - a_is_zero)


def inverse(a: int) -> int:
    """Calculate the inverse of a number in GF(2^8)."""
    b = mul(a, a)
    c = mul(a, b)
    b = mul(c, c)
    b = mul(b, b)
    c = mul(b, c)
    b = mul(b, b)
    b = mul(b, b)
    b = mul(b, c)
    b = mul(b, b)
    b = mul(a, b)

    return mul(b, b)


def mul(a: int, b: int) -> int:
    """Multiply two numbers in GF(2^8) using shift-and-add method."""
    result: int = 0

    # Process each bit of b from MSB to LSB
    for i in range(7, -1, -1):
        # Double the current result (left shift)
        result = result << 1

        # If the result overflowed, reduce modulo the polynomial
        # XOR with 0x1B (the lower 8 bits of 0x11B)
        if result & 0x100:  # Check if bit 8 is set
            result ^= 0x11B

        # If bit i of b is set, add a to the result (XOR in GF(2))
        if (b >> i) & 1:
            result ^= a

    return result
