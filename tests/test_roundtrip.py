from random import Random

from hypothesis import assume, given, settings
from hypothesis import strategies as st
from hypothesis import HealthCheck
import shamir


@given(  # type: ignore[misc]
    parts=st.integers(max_value=255),
    rng=st.randoms(note_method_calls=True),
    secret=st.binary(min_size=1),
    threshold=st.integers(min_value=2, max_value=255),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much])  # type: ignore[misc]
def test_roundtrip_split_combine(
    parts: int,
    rng: Random,
    secret: bytes,
    threshold: int,
) -> None:
    assume(parts > threshold)
    out = shamir.split(secret=secret, parts=parts, threshold=threshold, rng=rng)
    recombined = shamir.combine(parts=out)
    assert secret == recombined, (secret, recombined)
