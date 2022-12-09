from base64 import b64decode, b64encode
from typing import List

from shamir import combine, split


def hello() -> None:
    hw: bytes = b64encode("Hello, World!".encode("utf-8"))
    parts: List[bytearray] = split(hw, 64, 4)
    p = [parts[2], parts[7], parts[54], parts[44]]
    rt = combine(p)
    print(b64decode(rt).decode("utf-8"))


if __name__ == "__main__":
    hello()
