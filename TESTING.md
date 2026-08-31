# Testing Guide

This document covers testing standards, organization, and specialized testing for the Horcrux library.

## Testing Standards

- **Atomic tests**: Every test is self-contained and tests a single functionality
- **Parameterization**: Use `@pytest.mark.parametrize` for multiple examples of the same functionality
- **Separation**: Use separate test functions for different functionality pieces
- **Imports**: ALWAYS put imports at the top of the file, never in the test body
- **Run pytest**: ALWAYS run pytest after significant changes
- **Explicit byte literals**: Use `b"Hello, World!"` not string encodings
- **Unicode testing**: Use actual multi-language strings in tests
- **Threshold variations**: Test 2-of-3, 3-of-5, 4-of-7, etc.
- **Part selection**: Test exact threshold, threshold+1, random subsets

## Running Tests

### During Development (Fast Feedback)

```bash
# Single file
uv run pytest -n auto tests/test_specific.py -v

# Single test
uv run pytest -n auto tests/test_specific.py::test_fn -v

# Match by name
uv run pytest -n auto -k "keyword" -v
```

### Before Committing (Full Validation)

```bash
# Sequential, full suite
uv run pytest -n auto
```

### CI Runs (What GitHub Actions Does)

```bash
# With coverage, skip slow tests
uv run pytest --cov=shamir --cov-branch --cov-report=xml -n auto -m "not slow"
```

### Slow Tests (Timing/Performance)

```bash
# Run basic timing tests
uv run pytest tests/test_constant_time_ops.py -v

# Run statistical timing tests
uv run pytest tests/test_enhanced_timing.py -v

# Run all slow tests
uv run pytest -m slow -v

# Skip slow tests (CI default)
uv run pytest -m "not slow"
```

### Fuzz Tests (Property-Based with Hypothesis)

```bash
# Run comprehensive fuzz tests
uv run pytest tests/test_fuzz_comprehensive.py -v
```

### Benchmarks (Performance Tracking with pytest-codspeed)

```bash
# Run benchmarks
uv run pytest tests/test_benchmarks.py --codspeed

# Run all benchmark tests
uv run pytest -m benchmark --codspeed

# Skip benchmark tests
uv run pytest -m "not benchmark"
```

## Test Markers

### `@pytest.mark.slow`

Marks tests as slow (typically timing-based tests):

- These tests are skipped in CI to avoid flakiness
- Run them locally to verify constant-time properties
- Located in `tests/test_constant_time_ops.py` and `tests/test_enhanced_timing.py`
- Enhanced timing tests use statistical hypothesis testing (Kruskal-Wallis H-test)

### `@pytest.mark.benchmark`

Marks tests as benchmarks (performance tracking):

- Use pytest-codspeed to track performance over time
- Benchmarks cover split/combine/roundtrip operations across multiple sizes (16 B, 256 B, 16 KB)
- Also benchmarks low-level GF(256) math operations (add, mul, div, inverse)
- Located in `tests/benchmarks`
- 15 total benchmark tests

## Test Files

- **`tests/test_shamir.py`**: Core split/combine functionality and version detection (19 tests)
- **`tests/test_dealer_honesty.py`**: Dealer honesty verification (shares lie on same polynomial)
- **`tests/test_constant_time_ops.py`**: Basic constant-time operation tests
- **`tests/test_enhanced_timing.py`**: Statistical timing tests with scipy
  - Kruskal-Wallis H-test for timing distribution independence
  - Coefficient of variation (CV) analysis
  - Percentile distribution consistency tests
  - Requires scipy for statistical analysis (marked `@pytest.mark.slow`)
- **`tests/test_fuzz_comprehensive.py`**: Property-based fuzz tests with Hypothesis (9 tests)
  - Roundtrip testing with explicit version parameter
  - Version detection consistency across v0/v1 formats
  - Threshold property verification (any k shares work)
  - Share format consistency validation
  - Multiple secrets independence testing
  - Single-byte modification error detection
  - Deterministic RNG behavior verification
- **`tests/test_security_properties.py`**: Security invariant tests
- **`tests/benchmarks/`**: Performance benchmarking suite

## Property-Based Testing

Use Hypothesis for testing mathematical properties:

- **Roundtrip property**: `combine(split(secret, n, k)) == secret`
- **Threshold property**: Any k parts reconstruct, k-1 parts don't
- **Invariants**: Result length matches input length
- **Version consistency**: Both v0 and v1 shares reconstruct correctly
- **Format validation**: All shares have consistent structure
- **Independence**: Mixing shares from different secrets produces garbage
- **Error detection**: Modifying any share byte breaks reconstruction

See `tests/test_shamir.py` for basic examples and `tests/test_fuzz_comprehensive.py` for comprehensive property-based tests.

## Constant-Time Testing

The library includes two levels of constant-time testing to detect timing side-channels:

### Basic Tests (`tests/test_constant_time_ops.py`)

- **Purpose**: Catch obvious timing leaks with lenient thresholds
- **Marked**: `@pytest.mark.slow` (skipped in CI to avoid flakiness)
- **Approach**: Coefficient of variation (CV) analysis with wide tolerances
- **Use case**: Primary guard against egregious timing leaks

### Enhanced Tests (`tests/test_enhanced_timing.py`)

- **Purpose**: Statistical rigor with Kruskal-Wallis hypothesis testing
- **Requires**: scipy for statistical analysis
- **Marked**: `@pytest.mark.slow` (skipped in CI)
- **Approach**:
  - Kruskal-Wallis H-test (non-parametric distribution comparison)
  - Coefficient of variation analysis
  - Percentile distribution consistency checks

### Test Thresholds (Calibrated for Python)

| Test Type | Threshold | Rationale |
|-----------|-----------|-----------|
| Kruskal-Wallis p-value | > 0.001 | 99.9% confidence, accounts for 10K sample sensitivity |
| CV (individual ops) | < 0.5 (50%) | Python baseline is ~35%, allows GC pauses |
| CV range (combine) | < 0.3 (30%) | Permits trial-to-trial variation, catches secret-dependent patterns |
| Mean timing ratio | < 1.2x | Practical exploitation threshold (20% difference) |

### Python Constant-Time Limitations

Python's CPython runtime makes true constant-time operations impossible:

1. **Baseline variability**: Basic operations have ~35-37% CV
2. **Garbage collection**: Causes unpredictable timing spikes (can reach 400%+ CV)
3. **Dynamic typing**: Memory allocation and type checking add variable overhead
4. **OS scheduling**: Introduces timing jitter beyond application control

This library implements constant-time patterns (bit-masking, no branching on secrets) to minimize timing leaks. However, **measurable timing variations (10-15%) remain** due to CPython's inherent characteristics. These variations are **below practical exploitation thresholds** (1.2x) for most threat models.

**For stronger constant-time guarantees**: Use compiled languages with explicit constant-time libraries (e.g., libsodium, BearSSL).

### Running Constant-Time Tests

```bash
# Run all constant-time tests (may take several minutes)
uv run pytest tests/test_constant_time_ops.py tests/test_enhanced_timing.py -v

# Run with coverage
uv run pytest tests/test_constant_time_ops.py tests/test_enhanced_timing.py -v --cov=shamir --cov-branch

# Run enhanced tests only (requires scipy)
uv run pytest tests/test_enhanced_timing.py -v
```

### Interpreting Failures

- **CV > 0.5**: Operation has excessive variance, investigate
- **CV range > 0.3**: Secret-dependent timing detected
- **p-value < 0.001**: Statistically significant timing differences
- **Mean ratio > 1.2x**: Potentially exploitable timing leak

**Note**: Occasional failures due to system noise (GC, OS scheduling) are expected. Run tests multiple times to confirm consistent failures before investigating.

## When Tests Fail

1. **Read the error**: Pytest output shows exact line and assertion
2. **Reproduce locally**: Run single test with `-v` flag
3. **Check assumptions**: Verify test data matches expected behavior
4. **Use debugger**: `pytest --pdb` drops into debugger on failure
5. **Check CI logs**: GitHub Actions shows full output

## Coverage

- **100% coverage required**: All code paths must be tested
- **Branch coverage**: Use `--cov-branch` to ensure all branches tested
- **Report formats**:
  - JSON: `--cov-report=json` (for tooling)
  - XML: `--cov-report=xml` (for codecov)
  - Terminal: Default output shows coverage summary

## Test Organization Best Practices

### File Naming

- Test files should match source files: `test_<module>.py`
- Special test files use descriptive names: `test_fuzz_comprehensive.py`, `test_enhanced_timing.py`

### Test Function Naming

- Use descriptive names: `test_split_basic_functionality`
- Include edge case description: `test_split_with_zero_threshold_raises`
- Avoid generic names: `test_1`, `test_basic`

### Test Structure

Follow the Arrange-Act-Assert pattern:

```python
def test_split_basic_functionality():
    # Arrange
    secret = b"test secret"
    parts_count = 5
    threshold = 3

    # Act
    parts = split(secret, parts_count, threshold)

    # Assert
    assert len(parts) == parts_count
    assert all(len(part) == len(secret) + 2 for part in parts)
```

### Fixtures

- Use fixtures for common test data
- Keep fixtures in `conftest.py`
- Use parametrized fixtures for variations

### Parameterization

Use `@pytest.mark.parametrize` for testing multiple inputs:

```python
@pytest.mark.parametrize(
    "parts,threshold",
    [
        (3, 2),
        (5, 3),
        (7, 4),
    ],
)
def test_split_various_thresholds(parts, threshold):
    secret = b"test"
    result = split(secret, parts, threshold)
    assert len(result) == parts
```
