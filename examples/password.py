import secrets
import string
from base64 import b64encode
from random import shuffle

from shamir import combine, split


def password() -> None:
    alphabet: str = string.ascii_letters + string.digits
    password: str = ""
    while True:
        password = "".join(secrets.choice(alphabet) for _ in range(16))
        if (
            any(c.islower() for c in password)
            and any(c.isupper() for c in password)  # noqa: W503
            and sum(c.isdigit() for c in password) >= 3  # noqa: W503
        ):
            break
    print(f"Generated password: {password}")  # noqa: T201
    parts: list[bytearray] = split(password.encode("ascii"), 5, 3)
    print("Generating base64 encoded shares.")  # noqa: T201
    for idx, part in enumerate(parts):
        print(f"{idx}:\t{b64encode(part).decode('ascii')}")  # noqa: T201
    shuffle(parts)
    print("Using the following shares")  # noqa: T201
    for share in range(3):
        print(f"\t{b64encode(parts[share]).decode('ascii')}")  # noqa: T201
    recovered: bytearray = combine(parts[2:])
    print(f"Recovered password: {recovered.decode('ascii')}")  # noqa: T201


if __name__ == "__main__":
    password()
