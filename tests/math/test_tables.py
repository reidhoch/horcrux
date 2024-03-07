from shamir.math import EXP_TABLE, LOG_TABLE


def test_tables() -> None:
    for i in range(1, 256):
        log: int = LOG_TABLE[i]
        exp: int = EXP_TABLE[log]
        assert exp == i
