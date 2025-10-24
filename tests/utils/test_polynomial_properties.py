"""Exhaustive property tests for Polynomial and interpolation over GF(2^8)."""

from random import Random

from hypothesis import given
from hypothesis import strategies as st

from shamir.math import add, mul
from shamir.utils import Polynomial, interpolate

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


# Lagrange Interpolation Properties


@given(
    degree=st.integers(min_value=1, max_value=10),
    intercept=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_interpolation_recovers_polynomial_at_all_points(
    degree: int,
    intercept: int,
    rng: Random,
) -> None:
    """Test that interpolation recovers original polynomial at all evaluated points."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)

    # Sample exactly degree+1 points (minimum needed)
    sample_points = list(range(1, degree + 2))
    x_samples = bytearray(sample_points)
    y_samples = bytearray([poly.evaluate(x) for x in sample_points])

    # Interpolation should recover polynomial at any x
    test_points = [0, 5, 10, 50, 100, 200, 255]
    for x in test_points:
        if x < 256:  # Ensure in field
            interpolated = interpolate(x_samples, y_samples, x)
            expected = poly.evaluate(x)
            assert interpolated == expected


@given(
    degree=st.integers(min_value=1, max_value=10),
    intercept=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_interpolation_recovers_intercept(
    degree: int,
    intercept: int,
    rng: Random,
) -> None:
    """Test that interpolation always correctly recovers the intercept at x=0."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)

    # Use exactly degree+1 sample points
    sample_points = list(range(1, degree + 2))
    x_samples = bytearray(sample_points)
    y_samples = bytearray([poly.evaluate(x) for x in sample_points])

    # Interpolate at x=0 should give intercept
    recovered = interpolate(x_samples, y_samples, 0)
    assert recovered == intercept


def test_interpolation_with_excess_points() -> None:
    """Test interpolation behavior with more than degree+1 points."""
    # Degree-2 polynomial needs 3 points, but provide 5
    poly = Polynomial(degree=2, intercept=42, rng=Random(333))

    # Use 5 points (more than needed)
    sample_points = [1, 2, 3, 4, 5]

    # Taking any 3 consecutive points should recover the same values
    for start in range(3):
        x_subset = bytearray(sample_points[start : start + 3])
        y_subset = bytearray(
            [poly.evaluate(x) for x in sample_points[start : start + 3]]
        )

        # All subsets should give same interpolation
        recovered = interpolate(x_subset, y_subset, 0)
        assert recovered == 42


@given(
    degree=st.integers(min_value=2, max_value=10),
    intercept=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_interpolation_uniqueness(
    degree: int,
    intercept: int,
    rng: Random,
) -> None:
    """Test that degree+1 points uniquely determine a degree-n polynomial."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)

    # Two different sets of degree+1 points from same polynomial
    points1 = list(range(1, degree + 2))
    points2 = list(range(10, 10 + degree + 1))

    x1 = bytearray(points1)
    y1 = bytearray([poly.evaluate(x) for x in points1])

    x2 = bytearray(points2)
    y2 = bytearray([poly.evaluate(x) for x in points2])

    # Both should interpolate to same values at test points
    test_x = 0
    result1 = interpolate(x1, y1, test_x)
    result2 = interpolate(x2, y2, test_x)
    assert result1 == result2 == intercept


def test_interpolation_consistency_at_sample_points() -> None:
    """Test that interpolation returns original y values at sample x points."""
    poly = Polynomial(degree=3, intercept=77, rng=Random(555))

    sample_points = [5, 10, 15, 20]  # 4 points for degree-3
    x_samples = bytearray(sample_points)
    y_samples = bytearray([poly.evaluate(x) for x in sample_points])

    # Interpolating at each sample point should return the sample y value
    for i, x in enumerate(sample_points):
        result = interpolate(x_samples, y_samples, x)
        assert result == y_samples[i]


@given(
    intercept=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_interpolation_constant_polynomial(intercept: int, rng: Random) -> None:
    """Test interpolation works for degree-0 (constant) polynomials."""
    poly = Polynomial(degree=0, intercept=intercept, rng=rng)

    # Even single point determines constant polynomial
    x_samples = bytearray([1])
    y_samples = bytearray([poly.evaluate(1)])

    # Should interpolate to intercept at x=0
    result = interpolate(x_samples, y_samples, 0)
    # For constant polynomial: f(0) = f(1) = intercept
    assert result == intercept


def test_interpolation_linear_polynomial() -> None:
    """Test interpolation works correctly for degree-1 (linear) polynomials."""
    # f(x) = a0 + a1*x
    poly = Polynomial(degree=1, intercept=50, rng=Random(777))

    # Need exactly 2 points for degree-1
    x_samples = bytearray([1, 2])
    y_samples = bytearray([poly.evaluate(1), poly.evaluate(2)])

    # Test interpolation at various points
    for test_x in [0, 3, 10, 100, 255]:
        interpolated = interpolate(x_samples, y_samples, test_x)
        expected = poly.evaluate(test_x)
        assert interpolated == expected


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


@given(
    degree=st.integers(min_value=1, max_value=20),
    intercept=st.integers(min_value=0, max_value=255),
    rng=st.randoms(note_method_calls=True),
)
def test_minimum_points_theorem(degree: int, intercept: int, rng: Random) -> None:
    """Test that exactly degree+1 points are needed to determine polynomial."""
    poly = Polynomial(degree=degree, intercept=intercept, rng=rng)

    # Use exactly degree+1 points
    points = list(range(1, degree + 2))
    x_samples = bytearray(points)
    y_samples = bytearray([poly.evaluate(x) for x in points])

    # Should successfully recover polynomial
    assert len(x_samples) == degree + 1
    recovered_intercept = interpolate(x_samples, y_samples, 0)
    assert recovered_intercept == intercept


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


def test_interpolation_with_zero_x_coordinates() -> None:
    """Test interpolation behavior when x=0 is in sample points."""
    # This is special because we usually evaluate at x=0 to get secret
    poly = Polynomial(degree=2, intercept=88, rng=Random(1212))

    # Include x=0 in samples
    x_samples = bytearray([0, 1, 2])
    y_samples = bytearray([poly.evaluate(x) for x in [0, 1, 2]])

    # The y-value at x=0 should be the intercept
    assert y_samples[0] == 88

    # Interpolating at x=0 should return intercept
    result = interpolate(x_samples, y_samples, 0)
    assert result == 88


def test_interpolation_with_boundary_values() -> None:
    """Test interpolation with x-coordinates at field boundaries."""
    poly = Polynomial(degree=3, intercept=200, rng=Random(1313))

    # Use boundary values including 1 and 255
    x_samples = bytearray([1, 2, 254, 255])
    y_samples = bytearray([poly.evaluate(x) for x in [1, 2, 254, 255]])

    # Should recover polynomial correctly
    recovered = interpolate(x_samples, y_samples, 0)
    assert recovered == 200


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


# Integration with Shamir's Secret Sharing Properties


def test_polynomial_supports_shamir_threshold_property() -> None:
    """Test that polynomial properties support Shamir's threshold scheme."""
    # In a (k, n) threshold scheme, we need degree k-1 polynomial
    threshold = 3
    num_parts = 5
    degree = threshold - 1  # degree 2

    secret = 142
    poly = Polynomial(degree=degree, intercept=secret, rng=Random(1515))

    # Generate n=5 parts
    x_coords = list(range(1, num_parts + 1))
    parts = [poly.evaluate(x) for x in x_coords]

    # Any k=3 parts should recover secret
    x_subset = bytearray([1, 2, 3])
    y_subset = bytearray([parts[0], parts[1], parts[2]])
    recovered = interpolate(x_subset, y_subset, 0)
    assert recovered == secret

    # Different k=3 subset should also work
    x_subset2 = bytearray([2, 4, 5])
    y_subset2 = bytearray([parts[1], parts[3], parts[4]])
    recovered2 = interpolate(x_subset2, y_subset2, 0)
    assert recovered2 == secret
