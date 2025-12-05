from hypothesis import given
from hypothesis import strategies as st

from shamir.math import add, div, inverse, mul


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
)
def test_add_is_closed(a: int, b: int) -> None:
    """Test addition is closed (in GF(2^8), 0 <= sum <= 255)."""
    sum = add(a, b)
    assert 0 <= sum <= 255


@given(a=st.integers(min_value=0, max_value=255))
def test_additive_identity(a: int) -> None:
    """Test additive identity (in GF(2^8), a + 0 = a)."""
    assert add(a, 0) == a


@given(a=st.integers(min_value=0, max_value=255))
def test_additive_inverse(a: int) -> None:
    """Test additive inverse (in GF(2^8), a + a = 0)."""
    assert add(a, a) == 0


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
    c=st.integers(min_value=0, max_value=255),
)
def test_add_is_associative(a: int, b: int, c: int) -> None:
    """Test add is associative (in GF(2^8), (a + b) + c = a + (b + c)."""
    assert add(add(a, b), c) == add(a, add(b, c))


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
)
def test_add_is_commutative(a: int, b: int) -> None:
    """Test add is commutative (in GF(2^8), a + b = b + a)."""
    assert add(a, b) == add(b, a)


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=1, max_value=255),
)
def test_div_is_closed(a: int, b: int) -> None:
    """Test division is closed (in GF(2^8), 0 <= result <= 255)."""
    result = div(a, b)
    assert 0 <= result <= 255


@given(a=st.integers(min_value=1, max_value=255))
def test_div_by_self_is_one(a: int) -> None:
    """Test that a / a = 1 for all non-zero a."""
    assert div(a, a) == 1


@given(
    a=st.integers(min_value=1, max_value=255),
    b=st.integers(min_value=1, max_value=255),
)
def test_div_and_mul(a: int, b: int) -> None:
    assert div(mul(a, b), a) == b


@given(a=st.integers(min_value=1, max_value=255))
def test_inverse(a: int) -> None:
    """Test that a * inverse(a) = 1 for all non-zero values in GF(2^8)."""
    assert mul(a, inverse(a)) == 1


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
)
def test_mul_is_closed(a: int, b: int) -> None:
    """Test multiplication is closed (in GF(2^8), 0 <= product <= 255)."""
    product = mul(a, b)
    assert 0 <= product <= 255


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
    c=st.integers(min_value=0, max_value=255),
)
def test_mul_is_associative(a: int, b: int, c: int) -> None:
    """Test mul is associative (in GF(2^8), (a * b) * c = a * (b * c))."""
    assert mul(mul(a, b), c) == mul(a, mul(b, c))


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
)
def test_mul_is_commutative(a: int, b: int) -> None:
    """Test mul is commutative (in GF(2^8), (a * b) = (b * a)."""
    assert mul(a, b) == mul(b, a)


@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
    c=st.integers(min_value=0, max_value=255),
)
def test_mul_is_distributive(a: int, b: int, c: int) -> None:
    """Test mul is distributive (in GF(2^8), a * (b + c) = (a * b) + (a * c)."""
    assert mul(a, add(b, c)) == add(mul(a, b), mul(a, c))


@given(a=st.integers(min_value=0, max_value=255))
def test_multiplicative_identity(a: int) -> None:
    """Test multiplicative identity (in GF(2^8), a * 1 = a)."""
    assert mul(a, 1) == a
    assert mul(1, a) == a


@given(a=st.integers(min_value=0, max_value=255))
def test_multiplicative_zero(a: int) -> None:
    """Test multiplicative zero (in GF(2^8), a * 0 = 0)."""
    assert mul(a, 0) == 0
    assert mul(0, a) == 0


# Exhaustive Field Coverage Tests
@given(
    a=st.integers(min_value=0, max_value=255),
    b=st.integers(min_value=0, max_value=255),
)
def test_frobenius_endomorphism_squaring(a: int, b: int) -> None:
    """Test Frobenius: (a + b)^2 = a^2 + b^2 in characteristic 2 fields."""
    # In GF(2^8), squaring is a field automorphism
    left_side = mul(add(a, b), add(a, b))  # (a + b)^2
    right_side = add(mul(a, a), mul(b, b))  # a^2 + b^2
    assert left_side == right_side


@given(a=st.integers(min_value=0, max_value=255))
def test_frobenius_endomorphism_repeated_squaring(a: int) -> None:
    """Test that repeated squaring 8 times returns to original (Frobenius)."""
    # In GF(2^8), x^(2^8) = x for all x
    result = a
    for _ in range(8):
        result = mul(result, result)
    assert result == a


@given(a=st.integers(min_value=1, max_value=255))
def test_element_order_divides_255(a: int) -> None:
    """Test that multiplicative order of non-zero elements divides 255."""
    # The multiplicative group of GF(2^8) has order 255 = 3 * 5 * 17
    # By Lagrange's theorem, a^255 = 1 for all non-zero a
    result = a
    for _ in range(254):  # Multiply a by itself 254 more times (total 255)
        result = mul(result, a)
    assert result == 1


@given(a=st.integers(min_value=0, max_value=255))
def test_fermat_little_theorem_gf256(a: int) -> None:
    """Test that a^256 = a for all a in GF(2^8) (Fermat's Little Theorem variant)."""
    # This is a consequence of a^(2^8) = a (Frobenius)
    # For non-zero: a^256 = a * a^255 = a * 1 = a
    # For zero: 0^256 = 0
    result = a
    for _ in range(255):
        result = mul(result, a)
    assert result == a


@given(a=st.integers(min_value=1, max_value=255))
def test_inverse_involution(a: int) -> None:
    """Test that inverse(inverse(a)) = a (inverse is an involution on non-zero elements)."""
    assert inverse(inverse(a)) == a


@given(
    a=st.integers(min_value=1, max_value=255),
    b=st.integers(min_value=1, max_value=255),
)
def test_inverse_of_product(a: int, b: int) -> None:
    """Test that inverse(a * b) = inverse(a) * inverse(b)."""
    product = mul(a, b)
    inv_product = inverse(product)
    inv_a_times_inv_b = mul(inverse(a), inverse(b))
    assert inv_product == inv_a_times_inv_b
