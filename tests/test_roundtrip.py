from random import Random

from hypothesis import HealthCheck, assume, given, settings
from hypothesis import strategies as st

from shamir import combine, split


@given(
    parts=st.integers(min_value=2, max_value=255),
    rng=st.randoms(note_method_calls=True),
    secret=st.binary(min_size=1),
    threshold=st.integers(min_value=2, max_value=255),
    version=st.sampled_from([0, 1]),
)
@settings(deadline=None, suppress_health_check=[HealthCheck.filter_too_much])
def test_roundtrip_split_combine(
    parts: int,
    rng: Random,
    secret: bytes,
    threshold: int,
    version: int,
) -> None:
    """Roundtrip test with explicit version for reliability."""
    assume(parts >= threshold)
    out = split(secret=secret, parts=parts, threshold=threshold, rng=rng, version=version)
    recombined = combine(parts=out, version=version)
    assert secret == recombined, (secret, recombined)
