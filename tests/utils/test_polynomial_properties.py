"""Exhaustive property tests for Polynomial and interpolation over GF(2^8)."""

from random import Random

from hypothesis import given
from hypothesis import strategies as st

from shamir.math import add, mul
from shamir.utils import Polynomial

# Polynomial Evaluation Properties


@given(
    intercept=st.integers(min_value=0, max_value=255),
    degree=st.integers(min_value=0, max_value=10),
    rng=st.randoms(note_method_calls=True),
)
def test_polynomial_evaluation_at_zero_returns_intercept(
    intercept: int, degree: int, rng: Random
) -> None:
    """Test that evaluating any polynomial at x=0 always returns the intercept."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)
    assert poly.evaluate(0) == intercept


@given(
    degree=st.integers(min_value=1, max_value=254),
    intercept=st.integers(min_value=0, max_value=255),
    x=st.integers(min_value=1, max_value=255),
)
def test_polynomial_evaluation_is_deterministic(
    degree: int, intercept: int, x: int
) -> None:
    """Test that polynomial evaluation is deterministic for same inputs."""
    poly1 = Polynomial(degree=degree, intercept=intercept, rng=Random(123))
    poly2 = Polynomial(degree=degree, intercept=intercept, rng=Random(123))

    # Same seed produces same polynomial
    assert poly1.coefficients == poly2.coefficients

    # Evaluation is deterministic
    result1 = poly1.evaluate(x)
    result2 = poly2.evaluate(x)
    assert result1 == result2


@given(
    degree=st.integers(min_value=0, max_value=10),
    intercept=st.integers(min_value=0, max_value=255),
    x=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_polynomial_evaluation_result_in_field(
    degree: int,
    intercept: int,
    x: int,
    rng: Random,
) -> None:
    """Test that polynomial evaluation always produces values in GF(2^8)."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)
    result = poly.evaluate(x)
    assert 0 <= result <= 255


@given(
    degree=st.integers(min_value=0, max_value=10),
    intercept=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_polynomial_coefficients_count(
    degree: int, intercept: int, rng: Random
) -> None:
    """Test that polynomial has exactly degree+1 coefficients."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)
    assert len(poly.coefficients) == degree + 1
    assert poly.coefficients[0] == intercept


def test_constant_polynomial() -> None:
    """Test degree-0 (constant) polynomials."""
    for intercept in range(0, 256, 17):  # Sample values
        poly = Polynomial(degree=0, intercept=intercept, rng=Random(42))
        # Constant polynomial should return intercept for all x
        for x in range(0, 256, 19):
            assert poly.evaluate(x) == intercept


def test_linear_polynomial() -> None:
    """Test degree-1 (linear) polynomials."""
    # f(x) = a0 + a1*x
    poly = Polynomial(degree=1, intercept=42, rng=Random(123))
    a0 = poly.coefficients[0]
    a1 = poly.coefficients[1]

    assert a0 == 42

    # Verify evaluation matches manual calculation
    for x in [1, 2, 5, 10, 100, 255]:
        expected = add(a0, mul(a1, x))
        assert poly.evaluate(x) == expected


def test_quadratic_polynomial() -> None:
    """Test degree-2 (quadratic) polynomials."""
    # f(x) = a0 + a1*x + a2*x^2
    poly = Polynomial(degree=2, intercept=123, rng=Random(456))
    a0 = poly.coefficients[0]
    a1 = poly.coefficients[1]
    a2 = poly.coefficients[2]

    assert a0 == 123

    # Verify evaluation at specific points
    x = 7
    # Calculate manually: a0 + a1*x + a2*x^2
    term1 = mul(a1, x)
    x_squared = mul(x, x)
    term2 = mul(a2, x_squared)
    expected = add(add(a0, term1), term2)
    assert poly.evaluate(x) == expected


@given(
    degree=st.integers(min_value=1, max_value=10),
    intercept=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_polynomial_evaluation_consistency_across_field(
    degree: int,
    intercept: int,
    rng: Random,
) -> None:
    """Test polynomial can be evaluated at all field elements."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)

    # Should be able to evaluate at every field element
    results: list[int] = []
    for x in range(256):
        result = poly.evaluate(x)
        assert 0 <= result <= 255
        results.append(result)

    # Results list should have 256 entries
    assert len(results) == 256


# Polynomial Degree Properties


def test_maximum_degree_polynomial() -> None:
    """Test that maximum practical degree polynomials work correctly."""
    # In GF(2^8), we can have high-degree polynomials
    max_degree = 254  # Maximum meaningful degree in GF(256)

    poly = Polynomial(degree=max_degree, intercept=99, rng=Random(888))

    assert len(poly.coefficients) == max_degree + 1
    assert poly.evaluate(0) == 99

    # Should be able to evaluate at any point
    assert 0 <= poly.evaluate(1) <= 255
    assert 0 <= poly.evaluate(255) <= 255


# Coefficient Properties


@given(
    degree=st.integers(min_value=1, max_value=10),
    intercept=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_all_coefficients_in_field_range(
    degree: int,
    intercept: int,
    rng: Random,
) -> None:
    """Test that all polynomial coefficients are valid GF(2^8) elements."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)

    for coefficient in poly.coefficients:
        assert 0 <= coefficient <= 255


@given(
    degree=st.integers(min_value=1, max_value=10),
    intercept=st.integers(min_value=0, max_value=255),
)
def test_coefficient_randomness_quality(degree: int, intercept: int) -> None:
    """Test that random coefficients (except intercept) differ across instances."""
    poly1 = Polynomial(degree=degree, intercept=intercept, rng=Random(1111))
    poly2 = Polynomial(degree=degree, intercept=intercept, rng=Random(2222))

    # First coefficient (intercept) should be same
    assert poly1.coefficients[0] == poly2.coefficients[0] == intercept

    # For degree >= 1, at least some other coefficients should differ
    if degree >= 1:
        different = False
        for i in range(1, degree + 1):
            if poly1.coefficients[i] != poly2.coefficients[i]:
                different = True
                break
        # With different seeds, should get different random coefficients
        assert different


# Edge Cases and Special Values


@given(
    degree=st.integers(min_value=1, max_value=10),
    intercept=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_polynomial_evaluation_with_repeated_x(
    degree: int,
    intercept: int,
    rng: Random,
) -> None:
    """Test that evaluating polynomial multiple times at same x gives same result."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)

    x = 42
    result1 = poly.evaluate(x)
    result2 = poly.evaluate(x)
    result3 = poly.evaluate(x)

    assert result1 == result2 == result3
