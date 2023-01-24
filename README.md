# Horcrux
A Python implementation of Shamir's Secret Sharing, based of Hashicorp's implementation for Vault.

## Shamir's Secret Sharing
Shamir's Secret Sharing in an efficient algorithm for distributing private information. A secret is transformed into _shares_ from which the secret can be reassembled once a _threshold_ number are combined.

## Example
```python
from shamir import combine, split


def hello() -> None:
    """Split a byte-string and recombine its parts."""
    secret: bytes = b"Hello, World!"
    shares: int = 5
    threshold: int = 3

    parts: list[bytearray] = split(secret, shares, threshold)
    combined: bytearray = combine(parts[:3])
    print(combined.decode("utf-8"))


if __name__ == "__main__":
    hello()
```
