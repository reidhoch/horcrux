import pytest

from shamir.math import add, div, inverse, mul


def test_add() -> None:
    assert add(16, 16) == 0
    assert add(3, 4) == 7


def test_div() -> None:
    assert div(0, 7) == 0
    assert div(3, 3) == 1
    assert div(6, 3) == 2


def test_div_zero() -> None:
    with pytest.raises(ZeroDivisionError):
        assert div(7, 0) == 0


def test_div_zero_numerator() -> None:
    """Test that div(0, b) always returns 0 for any non-zero b.

    This verifies the constant-time zero-masking logic in div() that ensures
    0/b = 0 without branching on secret data. Critical for timing attack resistance.
    """
    for b in range(1, 256):
        assert div(0, b) == 0


def test_inverse_zero() -> None:
    with pytest.raises(ArithmeticError):
        assert inverse(0)


def test_mul() -> None:
    assert mul(3, 7) == 9
    assert mul(3, 0) == 0
    assert mul(0, 3) == 0
