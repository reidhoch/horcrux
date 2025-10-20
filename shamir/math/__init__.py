"""Math utility functions in GF(2^8)."""

import hmac
from sys import byteorder
from typing import Final

__all__: list[str] = ["add", "div", "inverse", "mul"]
ZERO: Final[bytes] = b"\x00"


def bytes_eq(a: bytes, b: bytes) -> bool:
    """Test byte equality in constant-time.

    Uses hmac.compare_digest to prevent timing attacks.
    """
    return hmac.compare_digest(a, b)


def add(a: int, b: int) -> int:
    """Combine two numbers in GF(2^8)."""
    return a ^ b


def div(a: int, b: int) -> int:
    """Divides two numbers in GF(2^8).

    Returns 0 when a=0 (regardless of b).
    Raises ZeroDivisionError when b=0.
    """
    # Ensure that we return zero if a is zero, but don't leak timing info.
    if bytes_eq(b.to_bytes(1, byteorder), ZERO):
        raise ZeroDivisionError

    result = mul(a, inverse(b))
    # Mask result to 0 if a is 0, without branching on secrets
    a_is_zero = int(bytes_eq(a.to_bytes(1, byteorder), ZERO))
    return result * (1 - a_is_zero)


def inverse(a: int) -> int:
    """Calculate the multiplicative inverse of a number in GF(2^8).

    Uses Fermat's Little Theorem (constant-time exponentiation by squaring).
    """
    # Ensure that we return zero if a is zero, but don't leak timing info.
    if bytes_eq(a.to_bytes(1, byteorder), ZERO):
        errmsg = "No inverse for zero."
        raise ArithmeticError(errmsg)
    # b = a^2  # noqa: ERA001
    b = mul(a, a)
    # c = (a^3)  # noqa: ERA001
    c = mul(a, b)
    # b = (a^3)^2 = a^6
    b = mul(c, c)
    # b = (a^6)^2 = a^12
    b = mul(b, b)
    # c = a^12 * a^3 = a^15
    c = mul(b, c)
    # b = (a^12)^2 = a^24
    b = mul(b, b)
    # b = (a^24)^2 = a^48
    b = mul(b, b)
    # b = a^48 * a^15 = a^63
    b = mul(b, c)
    # b = (a^63)^2 = a^126
    b = mul(b, b)
    # b = a^126 * a = a^127
    b = mul(a, b)
    # b = (a^127)^2 = a^254
    return mul(b, b)


def mul(a: int, b: int) -> int:
    """Multiply two numbers in GF(2^8) using constant-time shift-and-add method."""
    result: int = 0

    # Process each bit of b from MSB to LSB
    for i in reversed(range(8)):
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
