import pytest

from shamir.math import add, div, mul


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


def test_mul() -> None:
    assert mul(3, 7) == 9
    assert mul(3, 0) == 0
    assert mul(0, 3) == 0
