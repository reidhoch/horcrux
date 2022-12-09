# flake8: noqa
from shamir.math import EXP_TABLE, LOG_TABLE


def test_tables() -> None:
    for i in range(1, 256):
        log = LOG_TABLE[i]
        exp = EXP_TABLE[log]
        assert exp == i
