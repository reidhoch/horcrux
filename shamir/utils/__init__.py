# Copyright (c) 2022 Reid Hochstedler
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
"""Utilities."""

from random import Random, SystemRandom

from shamir.math import add, mul

__all__: list[str] = ["Polynomial"]


class Polynomial:
    """A Polynomial of arbitrary degree."""

    __slots__ = ("coefficients",)

    def __init__(
        self,
        degree: int,
        intercept: int,
        rng: Random | None = None,
    ) -> None:
        """Random polynomial of given degree with the provided intercept value."""
        if rng is None:
            rng = SystemRandom()
        self.coefficients: bytearray = bytearray(degree + 1)
        # Ensure the intercept is set
        self.coefficients[0] = intercept
        # Assign random coefficients to the polynomial.
        self.coefficients[1:] = rng.randbytes(degree)

    @classmethod
    def _from_coefficients(
        cls,
        intercept: int,
        random_coeffs: bytearray,
    ) -> "Polynomial":
        """Create polynomial from pre-generated coefficients (optimization).

        This classmethod allows creating polynomials from a batch of pre-generated
        random coefficients, avoiding repeated syscalls to the OS RNG.

        Args:
            intercept: The y-intercept (secret byte value).
            random_coeffs: Pre-generated random coefficients for the polynomial.

        Returns:
            A new Polynomial instance with the specified coefficients.
        """
        poly = cls.__new__(cls)
        poly.coefficients = bytearray(len(random_coeffs) + 1)
        poly.coefficients[0] = intercept
        poly.coefficients[1:] = random_coeffs
        return poly

    def evaluate(self, x: int) -> int:
        """Return the value of the polynomial for the given x."""
        # Compute the polynomial using Horner's method.
        degree: int = len(self.coefficients) - 1
        out: int = self.coefficients[degree]
        for i in range(degree - 1, -1, -1):
            coefficient: int = self.coefficients[i]
            out = add(mul(out, x), coefficient)
        return out
