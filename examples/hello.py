import rich

from shamir import combine, split


def hello() -> None:
    """Split a byte-string and recombine its parts."""
    hw: bytes = b"Hello, World!"
    parts: list[bytearray] = split(hw, 64, 4)
    p: list[bytearray] = [parts[2], parts[7], parts[54], parts[44]]
    rt: bytearray = combine(p)
    rich.print(rt.decode("utf-8"))


if __name__ == "__main__":
    hello()
