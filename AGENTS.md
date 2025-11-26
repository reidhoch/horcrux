# Horcrux Development Guidelines

> **Audience**: LLM-driven engineering agents and human developers

Horcrux is a Python implementation of Shamir's Secret Sharing based on HashiCorp Vault's approach. The library splits secrets into multiple parts where a threshold number of parts can reconstruct the original secret, using Galois Field GF(256) mathematics.

## Required Development Workflow

**CRITICAL**: Always run these commands in sequence before committing:

```bash
uv sync                              # Install dependencies
uv run pre-commit run --all-files    # Ruff + mypy + gitleaks
uv run pytest -n auto                # Run full test suite
```

**All three must pass** - this is enforced by CI

**Tests must pass and lint/typing must be clean before committing.**

## Repository Structure

| Path               | Purpose                                                    |
| ------------------ | ---------------------------------------------------------- |
| `shamir/`          | Library source code (Python ≥ 3.11)                        |
| `├─math/`          | Galois Field GF(256) operations (add, mul, div, inverse)   |
| `├─utils/`         | Polynomial class for Lagrange interpolation                |
| `├─errors.py`      | Error message enum - all validation errors defined here    |
| `├─py.typed`       | PEP 561 marker for type checking (enables downstream mypy) |
| `tests/`           | Comprehensive pytest suite with markers                    |
| `examples/`        | Simple demonstration projects                              |

## Core API

### Public Exports

The public API (from `shamir/__init__.py`) exports:

- `split(secret, parts, threshold, rng=None, version=None) -> Shares` - Split secret into parts (max 100MB)
- `combine(parts: Shares, version=None) -> bytearray` - Reconstruct secret from parts (auto-detects version or use explicit version for 100% reliability)
- `__version__` - Package version string

**Type Aliases** (for documentation):

- `Share: TypeAlias = bytearray` - Individual share
- `Shares: TypeAlias = list[Share]` - Collection of shares

### Design Principles

- **Minimal surface area**: Only essential functions are exported
- **Simple signatures**: Functions use standard Python types (no custom types in public API)
- **Explicit over implicit**: All parameters except optional `rng` are required
- **Fail fast**: Validation errors raise `ValueError` with specific messages from `Error` enum

### Adding to Public API

Before adding new public functions:

1. **Question necessity**: Can this be achieved with existing API?
2. **Consider ergonomics**: Will this be intuitive to users?
3. **Check consistency**: Does it match existing naming/signature patterns?
4. **Document thoroughly**: Google-style docstrings with examples
5. **Add to `__all__`**: Explicitly export in `shamir/__init__.py`

## Mathematical Foundation

- **Field**: GF(256)
- **Polynomial Construction**: Each byte of the secret gets its own random polynomial with degree = threshold - 1
- **Interpolation**: Lagrange interpolation over GF(256) to reconstruct secrets
- **Security**: Information-theoretic security - fewer than threshold parts reveal nothing

## Critical Implementation Details

- **X-coordinate generation**: Shuffled list of 256 values, indexed by part number (x = x_coords[i] + 1)
- **Byte-by-byte processing**: Each secret byte has a separate polynomial (field limitation)
- **Constant-time operations**: Used to prevent timing attacks
- **No branching on secrets**: Avoid conditional logic based on secret values

## Share Format Versioning

### Version 1 (Current Default)

**Format**: `[version_byte, y_values..., x_coordinate]`

- **Version byte**: `0x01` (first byte)
- **Y-values**: Secret share data (one byte per secret byte)
- **X-coordinate**: Share identifier (last byte, range 1-255)
- **Length**: `secret_length + 2` bytes

### Version 0 (Legacy)

**Format**: `[y_values..., x_coordinate]`

- **No version byte**: Maintains backward compatibility
- **Y-values**: Secret share data (one byte per secret byte)
- **X-coordinate**: Share identifier (last byte, range 1-255)
- **Length**: `secret_length + 1` bytes

### Version Detection

The `combine()` function can auto-detect share version or use an explicit version parameter:

**Auto-Detection** (default behavior):

1. Samples up to 3 shares for version detection (majority voting)
2. **Version 1 detection**: If first byte is `0x01`, counts as v1 vote
3. **Legacy detection**: Otherwise, counts as legacy vote
4. **Majority wins**: Uses majority vote across sampled shares
5. **Mixed version detection**: Raises error if votes are evenly split (indicates intentional mixing)

**Explicit Version** (100% reliable):

- Pass `version=0` for legacy shares or `version=1` for version 1 shares
- Eliminates false positive rate entirely
- Recommended when you know the share format

**False Positive Rate**:

- **Auto-detection alone**: 1/256 (0.39%) chance of false positive for legacy shares
- **Majority voting (3 shares)**: ~1/65536 (0.0015%) false positive rate
- **Explicit version**: 0% false positive rate (100% reliable)

### Creating Versioned Shares

```python
# Default: Create version 1 shares (recommended)
parts = split(secret, 5, 3)  # version defaults to 1

# Legacy: Create version 0 shares (backward compatibility)
parts_legacy = split(secret, 5, 3, version=0)

# Reconstruction with auto-detection
combine(parts)         # Auto-detects version 1 (99.6% reliable)
combine(parts_legacy)  # Auto-detects version 0 (99.6% reliable)

# Reconstruction with explicit version (100% reliable, recommended)
combine(parts, version=1)         # Explicit version 1
combine(parts_legacy, version=0)  # Explicit version 0
```

### When to Use Version 0

- **Interoperability**: When working with systems that expect legacy format
- **Storage constraints**: When the extra byte per share matters
- **Testing**: When verifying backward compatibility

### Future Versions

Version 2+ may include:

- Share metadata (threshold, part index)
- Checksums for error detection
- Additional security features

To add a new version:

1. Define `SHARE_VERSION_X` constant
2. Update `_detect_share_version()` logic
3. Add format handling in `split()` and `combine()`
4. Update `CURRENT_SHARE_VERSION` constant
5. Add comprehensive tests

## Code Conventions

### Type Annotations

- **Strict typing required**:
  - Use `bytearray` for mutable byte sequences, `bytes` for immutable
  - All functions must have complete type hints including return types
  - Exception: Test files have `disallow_untyped_defs = false` override
- **No `Any` types**: Prefer `object` or proper type unions
- **Explicit optionals**: Use `Type | None` not implicit optionals
- **Type aliases**: Use `TypeAlias` for better API documentation (e.g., `Share`, `Shares`)
- **Literal types**: Use `Literal` for constrained values (e.g., `version: Literal[0, 1]`)
- **PEP 561 compliance**: The `shamir/py.typed` marker file enables downstream type checking

### Error Handling

- **Use exact error messages**: All errors defined in `Error` enum in `shamir/errors.py`
- Never create ad-hoc error messages - add to enum if needed
- Validation order matters for consistent error reporting (see existing functions)
- Always raise `ValueError` for validation errors (consistency)

### Ruff Configuration

- **All rules enabled**: `select = ["ALL"]` with minimal ignores
- **Special ignore**: `A005` (shadowing builtin) allowed in `shamir/math/__init__.py` for `add`, `mul`, `div`
- **Line length**: 88 characters (Black-compatible)
- **Docstring style**: Google format (`tool.ruff.lint.pydocstyle.convention = "google"`)
- **Import sorting**: `shamir` is marked as first-party

### Docstrings

- Use Google-style docstrings for all public functions
- See examples in `shamir/__init__.py:30-48` (combine) and `shamir/__init__.py:76-84` (split)
- Private/internal functions may have brief descriptions
- Include Args, Returns, Raises sections for public functions

### Performance Patterns

- **Use `__slots__`**: Add `__slots__` to classes to reduce memory footprint (see the `Polynomial` class in `shamir/utils/__init__.py`)
- **Avoid list comprehensions in hot loops**: Use direct indexing for better performance (see optimized loop in the `combine()` function in `shamir/__init__.py`)
- **Type hints improve performance**: Well-typed code enables better optimizations

## Security Guidelines

### Cryptographic Standards

This is a **security-focused library**. All code must maintain:

1. **Constant-time operations**: Avoid timing side channels
   - No branching on secret data
   - Use constant-time comparison for sensitive values
   - Be aware of Python's optimizations (string interning, etc.)

2. **No secret leakage**:
   - Secrets should not appear in logs or error messages
   - Avoid string representations of secret data
   - Clear sensitive data when possible (though Python GC complicates this)

3. **Cryptographic RNG**:
   - Default to `SystemRandom()` which uses OS cryptographic RNG
   - Only accept `Random` interface for testing/reproducibility
   - Document when deterministic RNG is acceptable

4. **Input validation**:
   - Validate all inputs before processing
   - Fail fast on invalid input
   - Use specific error messages (from Error enum)

5. **Resource limits**:
   - Enforce `MAX_SECRET_SIZE` (100MB) to prevent memory exhaustion DoS attacks
   - Validate against all size/count limits before allocation
   - See comprehensive security documentation in `split()` function docstring in `shamir/__init__.py`

### When Adding Security-Sensitive Code

1. **Consider side channels**: Timing, memory access patterns, exceptions
2. **Review crypto primitives**: Ensure correct usage of GF(256) operations
3. **Add property-based tests**: Use Hypothesis to test invariants
4. **Document security properties**: Explain what guarantees the code provides
5. **Get review**: Security-sensitive changes require thorough review

## Dependency Management

### Philosophy

- **Minimal dependencies**: Zero runtime dependencies (current state)
- **Justify additions**: New dependencies must have strong rationale
- **Security first**: All dependencies reviewed for security advisories

### Adding Dependencies

Before adding a dependency:

1. **Question necessity**: Can we implement this ourselves?
2. **Evaluate alternatives**: Compare 2-3 options if available
3. **Check maintenance**: Is the package actively maintained?
4. **Review security**: Check for known CVEs, Scorecard rating
5. **Consider size**: Keep installation footprint minimal

### Dependency Updates

- **Security updates**: Apply immediately when CVEs are disclosed
- **Minor updates**: Update during normal maintenance
- **Major updates**: Evaluate breaking changes, update when stable
- **Lock file**: Commit `uv.lock` changes with dependency updates

## API Stability & Versioning

### Semantic Versioning

- **MAJOR.MINOR.PATCH** format (auto-generated via `hatch-vcs`)
- **MAJOR**: Breaking changes to public API
- **MINOR**: New features, backward-compatible
- **PATCH**: Bug fixes, no API changes

### Backward Compatibility

- **Public API is sacred**: Breaking changes require major version bump
- **Internal APIs can change**: Anything not in `__all__` is internal
- **Deprecation process**:
  1. Add deprecation warning (use `warnings.warn`)
  2. Document in CHANGELOG
  3. Wait minimum 1 major version
  4. Remove in subsequent major version

### What Constitutes Breaking Changes

- Removing or renaming public functions
- Changing function signatures (parameters, return types)
- Changing error types or messages users may depend on
- Modifying behavior of existing functionality (even bug fixes sometimes)

## Writing Style

- Be brief and to the point. Do not regurgitate information that can easily be gleaned from the code, except to guide the reader to where the code is located.
- **NEVER** use "This isn't..." or "not just..." constructions. State what something IS directly. Avoid defensive writing patterns like:
  - "This isn't X, it's Y" or "Not just X, but Y" → Just say "This is Y"
  - "Not just about X" → State the actual purpose
  - "We're not doing X, we're doing Y" → Just explain what you're doing
  - Any variation of explaining what something isn't before what it is

## Testing Best Practices

### Testing Standards

- Every test: atomic, self-contained, single functionality
- Use parameterization for multiple examples of same functionality
- Use separate tests for different functionality pieces
- **ALWAYS** Put imports at the top of the file, not in the test body
- **ALWAYS** run pytest after significant changes
- Use explicit byte literals: `b"Hello, World!"` not string encodings
- Test Unicode: Use actual multi-language strings
- Threshold variations: Test 2-of-3, 3-of-5, 4-of-7, etc.
- Part selection: Test exact threshold, threshold+1, random subsets

### Running Tests

**During development** (fast feedback):

```bash
uv run pytest -n auto tests/test_specific.py -v        # Single file
uv run pytest -n auto tests/test_specific.py::test_fn  # Single test
uv run pytest -n auto -k "keyword" -v                  # Match by name
```

**Before committing** (full validation):

```bash
uv run pytest -n auto                                  # Sequential, full suite
```

**CI runs** (what GitHub Actions does):

```bash
uv run pytest --cov=shamir --cov-branch --cov-report=xml -n auto -m "not slow"    # With coverage, skip slow tests
```

**Slow tests** (timing/performance tests that may be flaky):

```bash
uv run pytest tests/test_constant_time_ops.py -v      # Run basic timing tests
uv run pytest tests/test_enhanced_timing.py -v        # Run statistical timing tests
uv run pytest -m slow -v                              # Run all slow tests
uv run pytest -m "not slow"                           # Skip slow tests (CI default)
```

**Fuzz tests** (property-based tests with Hypothesis):

```bash
uv run pytest tests/test_fuzz_comprehensive.py -v     # Run comprehensive fuzz tests
```

**Benchmarks** (performance tracking with pytest-codspeed):

```bash
uv run pytest tests/test_benchmarks.py --codspeed   # Run benchmarks
uv run pytest -m benchmark --codspeed               # Run all benchmark tests
uv run pytest -m "not benchmark"                    # Skip benchmark tests
```

### Test Markers

- **`@pytest.mark.slow`**: Marks tests as slow (typically timing-based tests)
  - These tests are skipped in CI to avoid flakiness
  - Run them locally to verify constant-time properties
  - Located in `tests/test_constant_time_ops.py` and `tests/test_enhanced_timing.py`
  - Enhanced timing tests use statistical hypothesis testing (Kruskal-Wallis H-test)

- **`@pytest.mark.benchmark`**: Marks tests as benchmarks (performance tracking)
  - Use pytest-codspeed to track performance over time
  - Benchmarks cover split/combine/roundtrip operations across multiple sizes (16 B, 256 B, 16 KB)
  - Also benchmarks low-level GF(256) math operations (add, mul, div, inverse)
  - Located in `tests/benchmarks`
  - 15 total benchmark tests

### Test Files

- **`tests/test_shamir.py`**: Core split/combine functionality and version detection (19 tests)
- **`tests/test_dealer_honesty.py`**: Dealer honesty verification (shares lie on same polynomial)
- **`tests/test_constant_time_ops.py`**: Basic constant-time operation tests
- **`tests/test_enhanced_timing.py`** (NEW): Statistical timing tests with scipy
  - Kruskal-Wallis H-test for timing distribution independence
  - Coefficient of variation (CV) analysis
  - Percentile distribution consistency tests
  - Requires scipy for statistical analysis (marked `@pytest.mark.slow`)
- **`tests/test_fuzz_comprehensive.py`** (NEW): Property-based fuzz tests with Hypothesis (9 tests)
  - Roundtrip testing with explicit version parameter
  - Version detection consistency across v0/v1 formats
  - Threshold property verification (any k shares work)
  - Share format consistency validation
  - Multiple secrets independence testing
  - Single-byte modification error detection
  - Deterministic RNG behavior verification
- **`tests/test_security_properties.py`**: Security invariant tests
- **`tests/benchmarks/`**: Performance benchmarking suite

### Property-Based Testing

Use Hypothesis for testing mathematical properties:

- Roundtrip property: `combine(split(secret, n, k)) == secret`
- Threshold property: Any k parts reconstruct, k-1 parts don't
- Invariants: Result length matches input length
- Version consistency: Both v0 and v1 shares reconstruct correctly
- Format validation: All shares have consistent structure
- Independence: Mixing shares from different secrets produces garbage
- Error detection: Modifying any share byte breaks reconstruction
- See `tests/test_shamir.py` for basic examples
- See `tests/test_fuzz_comprehensive.py` for comprehensive property-based tests

### Constant-Time Testing

The library includes two levels of constant-time testing to detect timing side-channels:

#### Basic Tests (`tests/test_constant_time_ops.py`)

- **Purpose**: Catch obvious timing leaks with lenient thresholds
- **Marked**: `@pytest.mark.slow` (skipped in CI to avoid flakiness)
- **Approach**: Coefficient of variation (CV) analysis with wide tolerances
- **Use case**: Primary guard against egregious timing leaks

#### Enhanced Tests (`tests/test_enhanced_timing.py`)

- **Purpose**: Statistical rigor with Kruskal-Wallis hypothesis testing
- **Requires**: scipy for statistical analysis
- **Marked**: `@pytest.mark.slow` (skipped in CI)
- **Approach**:
  - Kruskal-Wallis H-test (non-parametric distribution comparison)
  - Coefficient of variation analysis
  - Percentile distribution consistency checks

**Test Thresholds (calibrated for Python):**

| Test Type | Threshold | Rationale |
|-----------|-----------|-----------|
| Kruskal-Wallis p-value | > 0.001 | 99.9% confidence, accounts for 10K sample sensitivity |
| CV (individual ops) | < 0.5 (50%) | Python baseline is ~35%, allows GC pauses |
| CV range (combine) | < 0.3 (30%) | Permits trial-to-trial variation, catches secret-dependent patterns |
| Mean timing ratio | < 1.2x | Practical exploitation threshold (20% difference) |

**Python Constant-Time Limitations:**

Python's CPython runtime makes true constant-time operations impossible:

1. **Baseline variability**: Basic operations have ~35-37% CV
2. **Garbage collection**: Causes unpredictable timing spikes (can reach 400%+ CV)
3. **Dynamic typing**: Memory allocation and type checking add variable overhead
4. **OS scheduling**: Introduces timing jitter beyond application control

This library implements constant-time patterns (bit-masking, no branching on secrets) to minimize timing leaks. However, **measurable timing variations (10-15%) remain** due to CPython's inherent characteristics. These variations are **below practical exploitation thresholds** (1.2x) for most threat models.

**For stronger constant-time guarantees**: Use compiled languages with explicit constant-time libraries (e.g., libsodium, BearSSL).

**Running constant-time tests:**

```bash
# Run all constant-time tests (may take several minutes)
uv run pytest tests/test_constant_time_ops.py tests/test_enhanced_timing.py -v

# Run with coverage
uv run pytest tests/test_constant_time_ops.py tests/test_enhanced_timing.py -v --cov=shamir --cov-branch

# Run enhanced tests only (requires scipy)
uv run pytest tests/test_enhanced_timing.py -v
```

**Interpreting failures:**

- **CV > 0.5**: Operation has excessive variance, investigate
- **CV range > 0.3**: Secret-dependent timing detected
- **p-value < 0.001**: Statistically significant timing differences
- **Mean ratio > 1.2x**: Potentially exploitable timing leak

**Note**: Occasional failures due to system noise (GC, OS scheduling) are expected. Run tests multiple times to confirm consistent failures before investigating.

## Common Pitfalls

### Galois Field Gotchas

1. **No standard operators**: Cannot use `+`, `*`, `/` on GF(256) elements
   - Use `shamir.math.add()`, `shamir.math.mul()`, `shamir.math.div()`
   - Standard Python operators give wrong results (modulo 256 != GF(256))

2. **Zero handling**: Division by zero is undefined in GF(256)
   - Check for zero denominators before calling `div()`
   - Interpolation handles this by avoiding zero differences

3. **Field size limitation**: GF(256) only represents 0-255
   - Cannot directly work with larger numbers
   - Each byte needs separate polynomial (current approach)

### Threshold vs Degree Confusion

- **Threshold**: Minimum parts needed to reconstruct
- **Polynomial degree**: `threshold - 1`
- Example: 3-of-5 sharing uses degree-2 polynomial (3 coefficients)

### Off-by-One Errors

- **X-coordinates**: Stored as 1-255 (not 0-254)
  - `x_coords[i] + 1` when storing
  - Used directly when retrieving (already offset)
- **Array indexing**: Secret length vs part length differ by 1 or 2
  - Version 1 parts: `secret_length + 2` (version + y-values + x-coordinate)
  - Version 0 parts: `secret_length + 1` (y-values + x-coordinate)
  - X-coordinate is always last byte: `part[len(part) - 1]`
  - Y-values start at index 1 for version 1, index 0 for version 0

### Byte Order

- **Version 1 format**: `[version=0x01, y_0, y_1, ..., y_n, x_coord]`
  - First byte is version identifier
  - Y-values follow in order (first secret byte → first y-value)
  - X-coordinate is last byte
- **Version 0 format**: `[y_0, y_1, ..., y_n, x_coord]`
  - No version byte
  - Y-values start at index 0
  - X-coordinate is last byte
- **No padding**: Secret length preserved exactly (unlike some implementations)
- **Big-endian by default**: First byte of secret maps to first y-value

## Examples Directory

### Purpose

Examples demonstrate real-world usage patterns for users. They should be:

- **Simple**: Focus on one use case
- **Complete**: Runnable without modification
- **Practical**: Solve actual problems users might have

### Current Examples

- `hello.py` - Basic string splitting/combining (`shamir/__init__.py:10`)
- `password.py` - Secure password sharing
- `image.py` - Binary data handling

### Adding New Examples

Consider adding examples for:

1. **Common use cases**: If users frequently ask about it
2. **Non-obvious patterns**: Integration with specific frameworks
3. **Best practices**: Demonstrate secure usage patterns

Each example should:

- Have descriptive filename (verb_noun.py pattern)
- Include docstring explaining purpose
- Show imports explicitly
- Use realistic data/scenarios
- Add to examples group in pyproject.toml if new deps needed

## Performance Expectations

Tested on an Apple M1 Max

- 1MB secrets should split/combine in <30s
- 255 parts (max) with threshold 128 should work reliably
- Memory usage should be O(secret_size * parts)

## CI/CD Notes

- Tests run on Python 3.11, 3.12, 3.13, 3.14 via GitHub Actions
- Coverage uploaded to codecov (100% required)
- Ruff format check must pass (blocking)
- All Ruff lint rules must pass (blocking)
- Uses Hatch for build backend (PEP 621 compliant)
- Uses `uv` for dependency management and publishing
- Security scanning via CodeQL and Scorecards

### Security Workflows

The project includes comprehensive security scanning via `.github/workflows/security.yaml`:

- **Semgrep SAST**: Advanced static analysis with OWASP Top 10, secrets, and security-audit rulesets
- **Bandit**: Python-specific security linting configured in `pyproject.toml`
- **pip-audit**: Dependency vulnerability scanning (fails on critical/high severity)
- **GitLeaks**: Secrets detection across full git history
- **Schedule**: Runs on push/PR, plus weekly Monday 00:00 UTC scans
- **Results**: SARIF uploaded to GitHub Security tab

## Code Review Guidelines

### Philosophy

Code review is about maintaining a healthy codebase while helping contributors succeed. The burden of proof is on the PR to demonstrate it adds value in the intended way. Your job is to help it get there through actionable feedback.

**Critical**: This is a security-focused library. A perfectly written PR that adds unwanted functionality must still be rejected. The code must advance the codebase in the intended direction, not just be well-written. When rejecting, provide clear guidance on how to align with project goals.

Be friendly and welcoming while maintaining high standards. Call out what works well - this reinforces good patterns. When code needs improvement, be specific about why and how to fix it. Remember that PRs serve as documentation for future developers.

### Focus On

- **Does this advance the codebase in the intended direction?** (Even perfect code for unwanted features should be rejected)
- **API design and naming clarity** - Identify confusing patterns (e.g., parameter values that contradict defaults) or non-idiomatic code (mutable defaults, etc.). Contributed code will need to be maintained indefinitely, and by someone other than the author (unless the author is a maintainer).
- **Security implications** - Does this introduce timing side channels? Expose secrets in errors?
- **Suggest specific improvements**, not generic "add more tests" comments
- **Think about API ergonomics and learning curve** from a user perspective

### For Agent Reviewers

- **Read the full context**: Always examine related files, tests, and documentation before reviewing
- **Check against established patterns**: Look for consistency with existing codebase conventions
- **Verify functionality claims**: Don't just read code - understand what it actually does
- **Consider edge cases**: Think through error conditions and boundary scenarios
- **Test the PR**: Check out the branch and run tests locally if possible

### Avoid

- Generic feedback without specifics
- Hypothetical problems unlikely to occur
- Nitpicking organizational choices without strong reason
- Summarizing what the PR already describes
- Star ratings or excessive emojis
- Bikeshedding style preferences when functionality is correct
- Requesting changes without suggesting solutions
- Focusing on personal coding style over project conventions

### Tone

- Acknowledge good decisions ("This API design is clean")
- Be direct but respectful
- Explain impact ("This will confuse users because...")
- Remember: Someone else maintains this code forever

### Decision Framework

Before approving, ask yourself:

1. Does this PR achieve its stated purpose?
2. Is that purpose aligned with where the codebase should go?
3. Would I be comfortable maintaining this code?
4. Have I actually understood what it does, not just what it claims?
5. Does this change introduce technical debt?
6. Are there security implications I need to consider?

If something needs work, your review should help it get there through specific, actionable feedback. If it's solving the wrong problem, say so clearly.

### Review Comment Examples

**Good Review Comments:**

❌ "Add more tests"
✅ "The `div` method needs tests for the edge case where a=0 (`shamir/math/__init__.py:42`)"

❌ "This API is confusing"
✅ "The parameter name `data` is ambiguous - consider `secret` to match the `split()` function signature (`shamir/__init_.py:77`)"

❌ "This could be better"
✅ "This approach works but creates a circular dependency. Consider moving the validation to `shamir/errors.py`"

❌ "Security concerns"
✅ "This branches on secret byte values which could leak timing information. Use constant-time comparison (see `shamir/utils/__init__.py:15` for pattern)"

### Review Checklist

Before approving, verify:

- [ ] All required development workflow steps completed (uv sync, pre-commit, pytest)
- [ ] Changes align with repository patterns and conventions
- [ ] API changes are documented and backwards-compatible where possible
- [ ] Error handling follows project patterns (specific exception types from Error enum)
- [ ] Tests cover new functionality and edge cases
- [ ] No security implications (timing attacks, secret leakage, etc.)
- [ ] Dependencies justified if any added
- [ ] Type hints complete and mypy passes

## Key Tools & Commands

### Validation Commands (Run Frequently)

- **Linting**: `uv run ruff check` (or with `--fix`)
- **Formatting**: `uv run ruff format`
- **Type Checking**: `uv run mypy`
- **Security Scans**:
  - `uv run pre-commit run gitleaks --all-files` (secrets detection)
  - `uv run bandit -r shamir/ -s B105` (Python security linting)
  - `uv run pip-audit --desc` (dependency vulnerability scanning)
- **All Checks**: `uv run pre-commit run --all-files`

### Testing

- **Full suite**: `uv run pytest -n auto`
- **With coverage**: `uv run pytest -n auto --cov=shamir --cov-branch --cov-report=json`
- **Specific file**: `uv run pytest tests/test_shamir.py -v`

### Development

- **Sync dependencies**: `uv sync`
- **Update lock file**: `uv lock --upgrade`
- **Run example**: `uv run python examples/hello.py`
- **Install pre-commit hooks**: `uv run pre-commit install`

## Critical Patterns

### Build Issues (Common Solutions)

1. **Dependencies**: Always `uv sync` first
2. **Pre-commit fails**: Run `uv run pre-commit run --all-files` to see failures
3. **Type errors**: Use `uv run mypy` directly, check `pyproject.toml` config
4. **Import errors**: Ensure `pythonpath = ["."]` in pytest config (already set)
5. **Coverage failures**: Add tests for uncovered branches, check with `--cov-branch --cov-report=json`

### When Tests Fail

1. **Read the error**: Pytest output shows exact line and assertion
2. **Reproduce locally**: Run single test with `-v` flag
3. **Check assumptions**: Verify test data matches expected behavior
4. **Use debugger**: `pytest --pdb` drops into debugger on failure
5. **Check CI logs**: GitHub Actions shows full output

### When Pre-commit Fails

1. **Ruff formatting**: Run `uv run ruff format` then re-stage
2. **Ruff linting**: Run `uv run ruff check --fix` to auto-fix
3. **Mypy errors**: Add type hints or fix type mismatches
4. **Gitleaks**: Remove secrets, never commit credentials
5. **Re-run**: `uv run pre-commit run --all-files` to verify
