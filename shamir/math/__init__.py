"""Math utility functions in GF(2^8)."""

__all__: list[str] = ["add", "div", "inverse", "mul"]


def add(a: int, b: int) -> int:
    """Combine two numbers in GF(2^8)."""
    return a ^ b


def div(a: int, b: int) -> int:
    """Divide two numbers in GF(2^8) using constant-time operations.

    Args:
        a: Dividend (0-255)
        b: Divisor (1-255, must not be zero)

    Returns:
        Quotient a/b in GF(256), or 0 if a==0

    Raises:
        ZeroDivisionError: If b == 0 (validated before constant-time path)
    """
    # Validate b != 0 BEFORE entering constant-time code path
    # This check is on public/validated data, branching is acceptable
    if b == 0:
        raise ZeroDivisionError

    # Now in constant-time path: a/b = a * b^(-1)
    result = mul(a, inverse(b))  # Both must be constant-time

    # Mask result to 0 if a == 0 (constant-time)
    # Create mask: 0xFF if a != 0, 0x00 if a == 0
    a_nonzero_mask = (a | -a) >> (8 * (a.bit_length() // 8 or 1) - 1)
    return result & a_nonzero_mask


def inverse(a: int) -> int:
    """Calculate the multiplicative inverse of a number in GF(2^8).

    Uses Fermat's Little Theorem (constant-time exponentiation by squaring).
    """
    if a == 0:
        errmsg = "No multiplicative inverse for zero in GF(256)"
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
    """Constant-time multiplication using bit-masking."""
    result: int = 0

    for i in reversed(range(8)):
        result = result << 1
        overflow_mask = -((result >> 8) & 1)  # All 1s if overflow, else 0s
        result ^= 0x11B & overflow_mask
        result &= 0xFF

        bit_mask = -((b >> i) & 1)  # All 1s if bit set, else 0s
        result ^= a & bit_mask  # No conditional branching

    return result & 0xFF
