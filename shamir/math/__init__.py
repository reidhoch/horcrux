"""Math utility functions in GF(2^8)."""

from .tables import INVERSE_TABLE

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
    # Uses constant-time operations: (a | -a) propagates any set bit to sign position,
    # right shift by 7 extracts to bit 0, mask to isolate, negate to get 0xFF or 0x00
    a_nonzero_mask = -(((a | -a) >> 7) & 1) & 0xFF
    return result & a_nonzero_mask


def inverse(a: int) -> int:
    """Calculate the multiplicative inverse of a number in GF(2^8).

    Uses pre-computed lookup table for O(1) performance. This is safe because
    inverse() only operates on PUBLIC x-coordinates (x-coordinate differences
    in Lagrange interpolation), never on private y-values. Cache timing attacks
    on this table are not a concern as they only reveal public data.

    Args:
        a: Value to invert (1-255). Must not be zero.

    Returns:
        The multiplicative inverse such that mul(a, inverse(a)) = 1.

    Raises:
        ArithmeticError: If a == 0 (zero has no multiplicative inverse).
    """
    if a == 0:
        errmsg = "No multiplicative inverse for zero in GF(256)"
        raise ArithmeticError(errmsg)

    return INVERSE_TABLE[a]


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

    return result
