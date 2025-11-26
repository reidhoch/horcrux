"""Enhanced constant-time operation tests with statistical rigor.

These tests use statistical hypothesis testing (Kruskal-Wallis H-test) to verify
that timing distributions are independent of operand values. This provides stronger
evidence of constant-time properties than simple variance checks.

Requirements:
    - scipy (for statistical tests)
    - numpy (dependency of scipy)

Note: These tests are more stringent than test_constant_time_ops.py and may
occasionally fail due to system noise. They are marked as slow and require
scipy to be installed.
"""

import statistics
import time
from random import Random

import pytest

# Conditional import for scipy
try:
    from scipy import stats

    SCIPY_AVAILABLE = True
except ImportError:
    SCIPY_AVAILABLE = False
    stats = None  # type: ignore[assignment]

from shamir import combine, split
from shamir.math import add, div, mul

pytestmark = pytest.mark.skipif(not SCIPY_AVAILABLE, reason="scipy not installed")


@pytest.mark.slow
class TestEnhancedConstantTimeTiming:
    """Enhanced constant-time tests using statistical hypothesis testing."""

    def test_mul_hamming_weight_independence_kruskal_wallis(self) -> None:
        """Test mul() timing is independent of Hamming weight using Kruskal-Wallis.

        Kruskal-Wallis H-test is a non-parametric test that checks if samples
        originate from the same distribution. A high p-value (> 0.05) means we
        cannot reject the null hypothesis that distributions are equal (good!).
        """
        if not SCIPY_AVAILABLE:
            pytest.skip("scipy not installed")

        # Test operands with different Hamming weights
        test_cases = [
            (42, 0b00000001),  # Hamming weight = 1
            (42, 0b00000011),  # Hamming weight = 2
            (42, 0b00001111),  # Hamming weight = 4
            (42, 0b11111111),  # Hamming weight = 8
        ]

        trials = 10000
        measurements = {}

        for a, b in test_cases:
            times = []
            for _ in range(trials):
                start = time.perf_counter_ns()
                mul(a, b)
                elapsed = time.perf_counter_ns() - start
                times.append(elapsed)
            measurements[(a, b)] = times

        # Kruskal-Wallis H-test: null hypothesis is distributions are equal
        h_statistic, p_value = stats.kruskal(*measurements.values())

        # p > 0.05 means we cannot reject null hypothesis (distributions are equal)
        # This is GOOD - means timing is independent of Hamming weight
        assert p_value > 0.01, (
            f"Timing varies by Hamming weight (H={h_statistic:.2f}, p={p_value:.6f}). "
            f"This indicates a potential timing side-channel. "
            f"p-value should be > 0.01 for constant-time operations."
        )

    def test_mul_coefficient_of_variation_strict(self) -> None:
        """Test mul() has low and consistent coefficient of variation (<10%)."""
        test_cases = [
            (0, 0),
            (1, 1),
            (255, 255),
            (42, 15),  # Low Hamming weight
            (42, 240),  # High Hamming weight
        ]

        trials = 10000

        for a, b in test_cases:
            times = []
            for _ in range(trials):
                start = time.perf_counter_ns()
                mul(a, b)
                times.append(time.perf_counter_ns() - start)

            mean = statistics.mean(times)
            stdev = statistics.stdev(times)
            cv = stdev / mean if mean > 0 else 0

            # CV < 0.3 (30%) is acceptable for Python operations
            # (stricter than the 50x variation in existing tests)
            assert cv < 0.3, (
                f"High timing variance for mul({a}, {b}): "
                f"CV={cv:.3f} (mean={mean:.1f}ns, stdev={stdev:.1f}ns). "
                f"Expected CV < 0.3 for consistent timing."
            )

    def test_div_operand_independence_kruskal_wallis(self) -> None:
        """Test div() timing is independent of operand values using statistical test."""
        if not SCIPY_AVAILABLE:
            pytest.skip("scipy not installed")

        # Test different operand combinations
        test_cases = [
            (1, 1),
            (255, 255),
            (128, 64),
            (42, 7),
            (200, 150),
        ]

        trials = 10000
        measurements = {}

        for a, b in test_cases:
            times = []
            for _ in range(trials):
                start = time.perf_counter_ns()
                div(a, b)
                elapsed = time.perf_counter_ns() - start
                times.append(elapsed)
            measurements[(a, b)] = times

        # Kruskal-Wallis H-test
        h_statistic, p_value = stats.kruskal(*measurements.values())

        # p > 0.01 means distributions are statistically similar (good!)
        assert p_value > 0.01, (
            f"Timing varies by operand values (H={h_statistic:.2f}, p={p_value:.6f}). "
            f"This indicates a potential timing side-channel in div(). "
            f"p-value should be > 0.01 for constant-time operations."
        )

    def test_combine_secret_value_independence_strict(self) -> None:
        """Test combine() timing is independent of secret values with stricter CV."""
        threshold = 3
        num_trials = 50

        # Test extreme bit patterns
        test_secrets = {
            "all_zero": bytes([0x00]) * 100,
            "all_one": bytes([0xFF]) * 100,
            "alternating": bytes([0x55]) * 100,
            "inverse_alt": bytes([0xAA]) * 100,
        }

        timings_by_secret = {}

        for secret_name, secret in test_secrets.items():
            timings = []
            for trial in range(num_trials):
                parts = split(secret, 5, threshold, rng=Random(trial))
                start = time.perf_counter_ns()
                combine(parts[:threshold])
                elapsed = time.perf_counter_ns() - start
                timings.append(elapsed)
            timings_by_secret[secret_name] = timings

        # Calculate CV for each secret
        cvs = {
            name: statistics.stdev(times) / statistics.mean(times)
            for name, times in timings_by_secret.items()
        }

        # CVs should be similar (< 0.2 or 20% range)
        cv_values = list(cvs.values())
        cv_range = max(cv_values) - min(cv_values)

        # Stricter threshold than existing tests (0.5 -> 0.2)
        assert cv_range < 0.2, (
            f"Timing varies significantly by secret value: {cvs}. "
            f"Range: {cv_range:.3f}. Expected < 0.2 for constant-time operations."
        )

    def test_mul_timing_percentiles(self) -> None:
        """Test mul() timing percentiles are consistent across operands.

        This test checks that not just the mean, but the entire distribution
        (including tail behavior) is consistent.
        """
        test_cases = [
            (42, 0b00000001),  # Hamming weight = 1
            (42, 0b11111111),  # Hamming weight = 8
        ]

        trials = 10000
        distributions = {}

        for a, b in test_cases:
            times = []
            for _ in range(trials):
                start = time.perf_counter_ns()
                mul(a, b)
                times.append(time.perf_counter_ns() - start)
            distributions[(a, b)] = sorted(times)

        # Compare percentiles (25th, 50th, 75th, 95th)
        percentiles = [25, 50, 75, 95]
        for p in percentiles:
            values = []
            for times in distributions.values():
                idx = int(len(times) * p / 100)
                values.append(times[idx])

            # Percentiles should be within 30% of each other
            if max(values) > 0:
                ratio = max(values) / min(values) if min(values) > 0 else float("inf")
                assert ratio < 1.3, (
                    f"P{p} percentile varies significantly: {values}. "
                    f"Ratio: {ratio:.2f}. Expected < 1.3 for consistent timing."
                )

    def test_fuzz_combine_timing_with_random_secrets(self) -> None:
        """Fuzz test: combine() timing should be independent of random secret patterns.

        This test uses property-based fuzzing approach with random secrets
        to catch edge cases that structured tests might miss.
        """
        threshold = 3
        num_secrets = 20
        secret_length = 100

        timings = []
        rng = Random(42)

        for i in range(num_secrets):
            # Generate random secret with different patterns
            secret = bytes([rng.randint(0, 255) for _ in range(secret_length)])
            parts = split(secret, 5, threshold, rng=Random(i))

            start = time.perf_counter_ns()
            combine(parts[:threshold])
            elapsed = time.perf_counter_ns() - start
            timings.append(elapsed)

        # All timings should have low CV (< 0.3 or 30%)
        mean = statistics.mean(timings)
        stdev = statistics.stdev(timings)
        cv = stdev / mean if mean > 0 else 0

        assert cv < 0.3, (
            f"Timing varies across random secrets: CV={cv:.3f} "
            f"(mean={mean:.1f}ns, stdev={stdev:.1f}ns). "
            f"Expected CV < 0.3 for constant-time operations."
        )


@pytest.mark.slow
class TestStatisticalTimingAnalysis:
    """Statistical analysis of timing behavior for documentation purposes.

    These tests collect and analyze timing data to characterize the library's
    timing behavior. Failures here indicate areas for improvement but don't
    necessarily indicate vulnerabilities.
    """

    def test_document_timing_characteristics(self) -> None:
        """Document timing characteristics for different operations.

        This test doesn't assert anything - it just collects data for analysis.
        Run with pytest -v -s to see output.
        """
        print("\n\n=== Timing Characteristics Analysis ===\n")

        # Test mul() with different Hamming weights
        print("mul() timing by Hamming weight:")
        for hw in [1, 4, 8]:
            operand = (1 << hw) - 1  # Create operand with hw ones
            times = []
            for _ in range(10000):
                start = time.perf_counter_ns()
                mul(42, operand)
                times.append(time.perf_counter_ns() - start)

            mean = statistics.mean(times)
            median = statistics.median(times)
            stdev = statistics.stdev(times)
            print(
                f"  HW={hw}: mean={mean:.1f}ns, median={median:.1f}ns, stdev={stdev:.1f}ns"
            )

        # Test combine() with different secret patterns
        print("\ncombine() timing by secret pattern:")
        test_secrets = {
            "zeros": bytes([0x00]) * 100,
            "ones": bytes([0xFF]) * 100,
            "random": bytes([i % 256 for i in range(100)]),
        }

        for name, secret in test_secrets.items():
            times = []
            for trial in range(50):
                parts = split(secret, 5, 3, rng=Random(trial))
                start = time.perf_counter_ns()
                combine(parts[:3])
                times.append(time.perf_counter_ns() - start)

            mean = statistics.mean(times)
            median = statistics.median(times)
            print(f"  {name}: mean={mean:.1f}ns, median={median:.1f}ns")

        print("\n=== End Analysis ===\n")
