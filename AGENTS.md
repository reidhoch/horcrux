# Horcrux Development Guidelines

> **Audience**: LLM-driven engineering agents and human developers

Horcrux is a Python implementation of Shamir's Secret Sharing based on HashiCorp Vault's approach. The library splits secrets into multiple parts where a threshold number of parts can reconstruct the original secret, using Galois Field GF(256) mathematics.

## Required Development Workflow

**CRITICAL**: Always run these commands in sequence before committing:

```bash
uv sync                              # Install dependencies
uv run prek run --all-files          # Ruff + mypy + gitleaks
uv run pytest -n auto                # Run full test suite
```

**All three must pass** - this is enforced by CI

## Repository Structure

| Path               | Purpose                                                    |
| ------------------ | ---------------------------------------------------------- |
| `shamir/`          | Library source (Python ≥ 3.11), public API in `__init__.py` |
| `├─math/`          | Galois Field GF(256) operations (add, mul, div, inverse)   |
| `├─utils/`         | Polynomial class for Lagrange interpolation                |
| `├─errors.py`      | Error message enum - all validation errors defined here    |
| `tests/`           | Comprehensive pytest suite with markers (see TESTING.md)   |
| `examples/`        | Demonstration projects                                     |

## Core API

**Public Exports** (from `shamir/__init__.py`):

- `split(secret, parts, threshold, rng=None, version=None) -> Shares` - Split secret (max 100MB)
- `combine(parts: Shares, version=None) -> bytearray` - Reconstruct secret (auto-detects version)
- `__version__` - Package version string

**Type Aliases**: `Share: TypeAlias = bytearray`, `Shares: TypeAlias = list[Share]`

**Design Principles**:

- Minimal surface area - only essential functions exported
- Simple signatures - standard Python types only
- Explicit over implicit - all parameters required (except optional `rng`)
- Fail fast - validation errors raise `ValueError` with messages from `Error` enum

## Mathematical Foundation

- **Field**: GF(256) - all operations use `shamir.math.{add,mul,div}()` (NOT Python `+`, `*`, `/`)
- **Polynomial Construction**: Each secret byte gets its own random polynomial (degree = threshold - 1)
- **Interpolation**: Lagrange interpolation over GF(256) to reconstruct secrets
- **Security**: Information-theoretic security - fewer than threshold parts reveal nothing

## Share Format

**Version 1** (current default): `[0x01, y_values..., x_coordinate]` (secret_length + 2 bytes)
**Version 0** (legacy): `[y_values..., x_coordinate]` (secret_length + 1 bytes)

- X-coordinate stored as 1-255 (last byte of share)
- Y-values start at index 1 for v1, index 0 for v0
- `combine()` auto-detects version (99.6% reliable) or pass explicit `version=0|1` (100% reliable)
- See `shamir/__init__.py` for usage examples

## Code Conventions

### Type Annotations

- **Strict typing required**: Complete type hints, `bytearray` for mutable bytes, `bytes` for immutable
- **No `Any` types**: Use `object` or proper type unions
- **Literal types**: For constrained values (e.g., `version: Literal[0, 1]`)
- Exception: Test files have `disallow_untyped_defs = false` override

### Error Handling

- **Use exact error messages**: All errors defined in `Error` enum in `shamir/errors.py`
- Never create ad-hoc error messages - add to enum if needed
- Always raise `ValueError` for validation errors

### Ruff Configuration

- **All rules enabled**: `select = ["ALL"]` with minimal ignores
- **Line length**: 88 characters (Black-compatible)
- **Docstring style**: Google format for all public functions

### Performance Patterns

- **Use `__slots__`**: Reduce memory footprint (see `Polynomial` class)
- **Avoid list comprehensions in hot loops**: Use direct indexing
- **Type hints improve performance**: Enables better optimizations

## Security Guidelines

This is a **security-focused library**. All code must maintain:

1. **Constant-time operations**: No branching on secret data, use constant-time comparison
2. **No secret leakage**: Secrets never appear in logs or error messages
3. **Cryptographic RNG**: Default to `SystemRandom()`, only accept `Random` for testing
4. **Input validation**: Validate all inputs before processing, fail fast
5. **Resource limits**: Enforce `MAX_SECRET_SIZE` (100MB) to prevent DoS attacks

**See SECURITY.md for detailed cryptographic standards and threat model considerations**

## Common Pitfalls

### Galois Field Gotchas

1. **No standard operators**: Cannot use `+`, `*`, `/` on GF(256) elements
   - Use `shamir.math.add()`, `shamir.math.mul()`, `shamir.math.div()`
   - Standard Python operators give wrong results (modulo 256 ≠ GF(256))

2. **Zero handling**: Division by zero is undefined in GF(256)
   - Check for zero denominators before calling `div()`

3. **Field size limitation**: GF(256) only represents 0-255
   - Each byte needs separate polynomial

### Threshold vs Degree Confusion

- **Threshold**: Minimum parts needed to reconstruct
- **Polynomial degree**: `threshold - 1`
- Example: 3-of-5 sharing uses degree-2 polynomial

### Off-by-One Errors

- **X-coordinates**: Stored as 1-255 (not 0-254), generated via `x_coords[i] + 1`
- **Array indexing**:
  - Version 1 parts: `secret_length + 2` (version + y-values + x-coordinate)
  - Version 0 parts: `secret_length + 1` (y-values + x-coordinate)
  - X-coordinate is always last byte: `part[-1]`

## Writing Style

Be brief and to the point. Do not regurgitate information easily gleaned from code, except to guide the reader to where the code is located.

**NEVER** use "This isn't..." or "not just..." constructions. State what something IS directly:

- ❌ "This isn't X, it's Y" or "Not just X, but Y"
- ✅ "This is Y"

## Testing

**Quick Commands:**

- Single test: `uv run pytest -n auto tests/test_specific.py::test_fn -v`
- Full suite: `uv run pytest -n auto`
- With coverage: `uv run pytest -n auto --cov=shamir --cov-branch`

**Standards:**

- Every test: atomic, self-contained, single functionality
- Use parameterization for multiple examples
- Imports at top of file (never in test body)
- Explicit byte literals: `b"Hello"` not string encodings

**See TESTING.md for detailed test organization, markers, and constant-time testing**

## Key Commands

### Validation

- **Linting**: `uv run ruff check` (or `--fix`)
- **Formatting**: `uv run ruff format`
- **Type Checking**: `uv run mypy`
- **All Checks**: `uv run prek run --all-files`

### Security Scans

- **Secrets**: `uv run prek run gitleaks --all-files`
- **Python Security**: `uv run bandit -r shamir/ -s B105`
- **Dependencies**: `uv run pip-audit --desc`

### Development

- **Sync dependencies**: `uv sync`
- **Update lock**: `uv lock --upgrade`
- **Run example**: `uv run python examples/hello.py`

## Critical Patterns

### Build Issues

1. **Dependencies**: Always `uv sync` first
2. **Pre-commit fails**: Run `uv run prek run --all-files` to see failures
3. **Type errors**: Use `uv run mypy` directly, check `pyproject.toml` config
4. **Coverage failures**: Add tests for uncovered branches

### When Tests Fail

1. Read pytest output - shows exact line and assertion
2. Reproduce locally with `-v` flag
3. Use `pytest --pdb` to drop into debugger on failure

### When Pre-commit Fails

1. **Ruff formatting**: `uv run ruff format` then re-stage
2. **Ruff linting**: `uv run ruff check --fix`
3. **Mypy errors**: Add type hints or fix mismatches
4. **Gitleaks**: Remove secrets, never commit credentials

## Dependency Management

- **Philosophy**: Zero runtime dependencies (current state)
- **Justify additions**: Strong rationale required, evaluate 2-3 alternatives
- **Security first**: All dependencies reviewed for CVEs, Scorecard rating
- **See CONTRIBUTING.md for detailed dependency and versioning guidelines**

## CI/CD

- Tests run on Python 3.11, 3.12, 3.13, 3.14 via GitHub Actions
- Coverage uploaded to codecov (100% required)
- Ruff format/lint checks must pass (blocking)
- Security scanning via CodeQL, Semgrep, Bandit, pip-audit, Scorecards
- Uses Hatch for build backend, `uv` for dependency management

## Code Review

**Focus on:**

- Does this advance the codebase in the intended direction?
- API design and naming clarity
- Security implications (timing side channels, secret leakage)
- Specific, actionable feedback (not generic "add more tests")

**See CONTRIBUTING.md for detailed code review guidelines, examples, and checklist**
