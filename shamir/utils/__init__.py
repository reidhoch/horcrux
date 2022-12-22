"""Utilities."""
from random import Random, SystemRandom

from shamir.math import add, div, mul

__all__: list[str] = ["Polynomial", "interpolate"]


class Polynomial:
    """A Polynomial of arbitrary degree."""

    def __init__(
        self,
        degree: int,
        intercept: int,
        rng: Random = SystemRandom(),  # noqa: B008
    ) -> None:
        """Random polynomial of given degree with the provided intercept value."""
        if not rng:
            raise ValueError("RNG not initialized")
        self.coefficients: bytearray = bytearray(degree + 1)
        # Ensure the intercept is set
        self.coefficients[0] = intercept
        # Assign random coefficients to the polynomial.
        self.coefficients[1:] = rng.randbytes(degree)

    def evaluate(self, x: int) -> int:
        """Return the value of the polynomial for the given x."""
        if x == 0:
            return self.coefficients[0]
        # Compute the polynomial using Horner's method.
        degree: int = len(self.coefficients) - 1
        out: int = self.coefficients[degree]
        for i in range(degree - 1, -1, -1):
            coeff: int = self.coefficients[i]
            out = add(mul(out, x), coeff)
        return out


def interpolate(x_s: bytearray, y_s: bytearray, x: int) -> int:
    """Take N sample points and return the value of a given x using Lagrange interpolation."""  # noqa: E501
    limit: int = len(x_s)
    result: int = 0
    for i in range(limit):
        basis: int = 1
        for j in range(limit):
            if i == j:
                continue
            num: int = add(x, x_s[j])
            den: int = add(x_s[i], x_s[j])
            term: int = div(num, den)
            basis = mul(basis, term)
        group: int = mul(y_s[i], basis)
        result = add(result, group)
    return result
