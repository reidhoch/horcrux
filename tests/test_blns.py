# type: ignore

from base64 import b64decode
from itertools import permutations
from json import loads
from random import Random
from typing import Final
from urllib.request import Request, urlopen

from shamir import combine, split

BLNS: Final[str] = (
    "https://raw.githubusercontent.com/minimaxir/big-list-of-naughty-strings/master/blns.base64.json"
)
RNG: Final[Random] = Random(12345)


def test_blns() -> None:
    """Test against the Big List of Naughty Strings."""
    parts: int = 5
    threshold: int = 3
    req: Request = Request(BLNS)
    with urlopen(req) as response:
        blns: list[bytes] = loads(response.read())
        for secret in blns:
            if len(secret) == 0:
                continue
            decoded_secret: bytes = b64decode(secret)
            out: list[bytearray] = split(decoded_secret, parts, threshold, rng=RNG)
            shares: set[bytes] = {bytes(share) for share in out}
            for perm in permutations(shares, threshold):
                recombined: bytearray = combine(list(perm))
                assert recombined == decoded_secret
