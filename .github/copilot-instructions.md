# Horcrux - AI Coding Agent Instructions

## Project Overview
Horcrux is a Python implementation of Shamir's Secret Sharing based on HashiCorp Vault's approach. The library splits secrets into multiple parts where a threshold number of parts can reconstruct the original secret, using Galois Field GF(256) mathematics.

## Architecture

### Core Components
- **`shamir/__init__.py`**: Public API with `split()` and `combine()` functions
- **`shamir/math/`**: Galois Field GF(256) operations (`add`, `mul`, `div`) using pre-computed log/exp tables
- **`shamir/utils/`**: Polynomial class for Lagrange interpolation
- **`shamir/errors.py`**: Error enum with exact, user-facing error messages

### Mathematical Foundation
- **Field**: GF(256) - all operations use lookup tables in `shamir/math/tables.py`
- **Polynomial Construction**: Each byte of the secret gets its own random polynomial with degree = threshold - 1
- **Interpolation**: Lagrange interpolation over GF(256) to reconstruct secrets
- **Security**: Information-theoretic security - fewer than threshold parts reveal nothing

### Critical Implementation Details
1. **X-coordinate generation**: Random list of 256 values, indexed by part number (x = x_coords[i] + 1)
2. **Byte-by-byte processing**: Each secret byte has a separate polynomial (field limitation)
3. **Constant-time operations**: `div` and `mul` use `hmac.compare_digest` to prevent timing attacks
4. **Part format**: `[secret_byte_0, secret_byte_1, ..., secret_byte_n, x_coordinate]` - last byte is the x-value

## Development Workflow

### Setup
```bash
# Install dependencies (creates virtual environment automatically)
uv sync --group dev

# Or use uv run to auto-install dependencies on first run
uv run pytest
```

### Testing
```bash
# Run full test suite (72 tests, 100% coverage)
uv run pytest

# Run with coverage report
uv run pytest --cov=shamir --cov-branch --cov-report=xml

# Run tests in parallel
uv run pytest -n auto

# Run specific test category
uv run pytest tests/test_mathematical_properties.py
```

### Linting and Formatting
```bash
# Format code (must pass in CI)
uv run ruff format shamir

# Check formatting without modifying
uv run ruff format --check shamir

# Run linter (ALL rules enabled)
uv run ruff check shamir

# Auto-fix issues
uv run ruff check --fix shamir

# Type checking
uv run mypy shamir
```

### Multi-Version Testing
```bash
# Test across Python 3.11, 3.12, 3.13
tox
```

### Build System
- **Uses Hatch** for build backend (PEP 621 compliant)
- **Uses uv** for dependency management (replaces Poetry/pip)
- Dependencies in `[dependency-groups]` section of `pyproject.toml`
- Package building: `uv build`
- Publishing: `uv publish`

## Code Conventions

### Type Annotations
- **Strict typing required**: `tool.mypy.strict = true` with all strict flags enabled
- Use `bytearray` for mutable byte sequences, `bytes` for immutable
- All functions must have complete type hints including return types
- Exception: Test files have `disallow_untyped_defs = false` override

### Error Handling
- **Use exact error messages**: All errors defined in `Error` enum in `shamir/errors.py`
- Never create ad-hoc error messages - add to enum if needed
- Validation order matters for consistent error reporting (see existing functions)

### Ruff Configuration
- **All rules enabled**: `select = ["ALL"]` with minimal ignores
- **Special ignore**: `A005` (shadowing builtin) allowed in `shamir/math/__init__.py` for `add`, `mul`, `div`
- **Line length**: 88 characters (Black-compatible)
- **Docstring style**: Google format (`tool.ruff.lint.pydocstyle.convention = "google"`)
- **Import sorting**: `shamir` is marked as first-party

### Docstrings
- Use Google-style docstrings for all public functions
- See examples in `shamir/__init__.py` and `shamir/utils/__init__.py`
- Private/internal functions may have brief descriptions

### Random Number Generation
- Default: `SystemRandom()` for cryptographic security
- Tests use `Random(seed)` for determinism
- **Important**: RNG parameter uses mutable default (`B008` violation accepted for API design)

## Testing Practices

### Test Structure (see `TEST_SUITE_DOCUMENTATION.md`)
1. **`test_shamir.py`**: Basic API validation
2. **`test_edge_cases.py`**: Boundary conditions (1 byte to 1MB secrets)
3. **`test_security_properties.py`**: Cryptographic properties, avalanche effect
4. **`test_mathematical_properties.py`**: GF(256) field properties, Lagrange interpolation
5. **`test_integration.py`**: Real-world scenarios (password sharing, API keys, etc.)
6. **`test_stress.py`**: Performance and large-scale testing

### Test Data Patterns
- Use explicit byte literals: `b"Hello, World!"` not string encodings
- Test Unicode: Use actual multi-language strings (see `test_multi_language_text`)
- Threshold variations: Test 2-of-3, 3-of-5, 4-of-7, etc.
- Part selection: Test exact threshold, threshold+1, random subsets

### Performance Expectations
- 1MB secrets should split/combine in <500ms
- 255 parts (max) with threshold 128 should work reliably

## Dependencies

### Production
- **None** - Zero runtime dependencies for library code

### Development
- `pytest`, `pytest-cov`, `pytest-xdist`: Testing framework
- `ruff`: Linting and formatting (replaces flake8, black, isort)
- `mypy`: Type checking with strict mode
- `tox`: Multi-version testing
- `typer`: CLI utilities (examples only)
- `pre-commit`: Git hooks

**Package Manager**: `uv` - Fast Python package installer and resolver
- Install with: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Auto-creates virtual environments
- Commands: `uv sync`, `uv run`, `uv add`, `uv build`, `uv publish`

## Common Patterns

### Splitting Secrets
```python
from shamir import split
from random import Random

# Production: cryptographically secure
parts = split(b"secret", shares=5, threshold=3)

# Testing: deterministic
parts = split(b"secret", shares=5, threshold=3, rng=Random(42))
```

### Combining Parts
```python
from shamir import combine

# Any threshold number of parts works
secret = combine(parts[:3])  # exactly threshold
secret = combine(parts[:4])  # more than threshold
```

### Field Operations (internal)
```python
from shamir.math import add, mul, div

# XOR addition in GF(256)
result = add(a, b)

# Logarithm-based multiplication
result = mul(a, b)

# Division with zero-handling
result = div(a, b)  # raises ZeroDivisionError if b == 0
```

## CI/CD Notes
- Tests run on Python 3.11, 3.12, 3.13 via GitHub Actions
- Coverage uploaded to codecov (100% required)
- Ruff format check must pass (blocking)
- All Ruff lint rules must pass (blocking)
- Uses Hatch for build backend (PEP 621 compliant)
- Uses `uv` for dependency management and publishing
- Security scanning via CodeQL and Scorecards

## Troubleshooting Common Issues

### X-Coordinate Collisions
**Problem**: `ValueError: Duplicate part detected` during combine or split operations

**Cause**: The RNG generates duplicate x-coordinates in the random list (probability increases with more parts)

**Solutions**:
```python
# In tests: Try different RNG seeds
for seed_offset in range(0, 10000, 1000):
    try:
        parts = split(secret, shares=10, threshold=5, rng=Random(seed + seed_offset))
        break
    except ValueError as e:
        if "Duplicate part detected" not in str(e):
            raise
```

**Test Pattern**: See `test_x_coordinate_collision_handling()` and `test_large_parts_stress()` for handling strategies

### Type Mismatches
**Problem**: `TypeError` when passing strings instead of bytes

**Cause**: API expects `bytes` for secrets, not `str`

**Solution**:
```python
# Wrong
secret = "password"
parts = split(secret, 5, 3)  # TypeError!

# Correct
secret = b"password"  # or "password".encode("utf-8")
parts = split(secret, 5, 3)
```

### Validation Errors (ValueError)
All validation errors use exact messages from `shamir.errors.Error` enum:

- `"Less than two parts cannot be used to reconstruct the secret"` - Need ≥2 parts for combine()
- `"Parts must be at least two bytes"` - Each part needs secret bytes + x-coordinate
- `"All parts must be the same length"` - Mismatched parts from different secrets
- `"Duplicate part detected"` - X-coordinate collision (see above)
- `"Parts cannot be less than threshold"` - Invalid split() parameters
- `"Parts or Threshold cannot exceed 255"` - GF(256) limitation
- `"Threshold must be at least 2"` - Need ≥2 for meaningful secret sharing
- `"Cannot split an empty secret"` - Secret must have ≥1 byte
- `"RNG not initialized"` - Passed `None` or invalid RNG

**Solution**: Check error message against `shamir/errors.py` enum for exact cause

### Mypy Strict Mode Errors
**Problem**: Type errors in new code despite having type hints

**Common Issues**:
```python
# Missing return type
def my_function(x: int):  # Error: missing return type
    return x * 2

# Should be
def my_function(x: int) -> int:
    return x * 2

# Implicit Any type
data = []  # Error: need explicit type
data: list[bytearray] = []  # Correct
```

**Solution**: Use `uv run mypy shamir` to check; all strict flags are enabled

### Ruff Linting Failures
**Problem**: CI fails on Ruff checks but local `ruff check` passes

**Cause**: Cached results - CI uses `--no-cache` flag

**Solution**:
```bash
# Match CI behavior
uv run ruff format --no-cache --check shamir
uv run ruff check --no-cache shamir

# Clear cache and re-run
rm -rf .ruff_cache
uv run ruff check shamir
```

### Test Failures Due to Non-Determinism
**Problem**: Tests fail intermittently with "Duplicate part detected"

**Cause**: Using `SystemRandom()` (cryptographic RNG) in tests instead of seeded `Random()`

**Solution**:
```python
# Wrong - non-deterministic
parts = split(secret, 10, 5)  # Uses SystemRandom() by default

# Correct - deterministic for tests
parts = split(secret, 10, 5, rng=Random(42))
```

**Pattern**: See any test file - all use `rng=Random(seed)` for reproducibility

### Coverage Below 100%
**Problem**: Coverage report shows missing lines

**Cause**: This project requires 100% coverage - no untested code paths

**Solution**:
```bash
# Generate HTML coverage report
uv run pytest --cov=shamir --cov-branch --cov-report=html

# Open htmlcov/index.html to see missing lines
open htmlcov/index.html  # macOS
xdg-open htmlcov/index.html  # Linux
```

**Pattern**: Add tests for every error condition, edge case, and code path

### Tox Environment Issues
**Problem**: `tox` fails to find Python versions

**Solution**:
```bash
# Check available Python versions
which python3.11 python3.12 python3.13

# Install missing versions (macOS with Homebrew)
brew install python@3.11 python@3.12 python@3.13

# Or use pyenv
pyenv install 3.11.x 3.12.x 3.13.x
pyenv global 3.11.x 3.12.x 3.13.x
```

### Performance Issues
**Problem**: Split/combine operations too slow for large secrets

**Expectations**:
- 1MB secrets: <500ms for split or combine
- 255 parts with threshold 128: should complete reliably

**Check**:
```python
import time
start = time.time()
parts = split(large_secret, 100, 50)
print(f"Split took: {time.time() - start:.2f}s")
```

**Pattern**: See `test_stress.py` for performance benchmarks
