"""Benchmark tests for Shamir's Secret Sharing.

Sizes selected for balance between CI performance and coverage:
- 16B: Minimal overhead (1 block)
- 256B: Field boundary (GF(256))
- 16KB: Realistic secret size

Larger sizes (1MB+) tested in property tests. MAX_SECRET_SIZE=100MB
enforced in production code.
"""
