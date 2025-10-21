# Horcrux Development Guidelines

> **Audience**: LLM-driven engineering agents and human developers

Horcrux is a Python implementation of Shamir's Secret Sharing based on HashiCorp Vault's approach. The library splits secrets into multiple parts where a threshold number of parts can reconstruct the original secret, using Galois Field GF(256) mathematics.

## Required Development Workflow

**CRITICAL**: Always run these commands in sequence before committing:

```bash
uv sync                              # Install dependencies
uv run pre-commit run --all-files    # Ruff + mypy + gitleaks
uv run pytest                        # Run full test suite
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
| `tests/`           | Comprehensive pytest suite with markers                    |
| `examples/`        | Simple demonstration projects                              |

## Core API

### Public Exports

The public API (from `shamir/__init__.py`) exports:

- `split(secret, parts, threshold, rng=None) -> list[bytearray]` - Split secret into parts
- `combine(parts) -> bytearray` - Reconstruct secret from parts
- `__version__` - Package version string

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

## Code Conventions

### Type Annotations

- **Strict typing required**:
  - Use `bytearray` for mutable byte sequences, `bytes` for immutable
  - All functions must have complete type hints including return types
  - Exception: Test files have `disallow_untyped_defs = false` override
- **No `Any` types**: Prefer `object` or proper type unions
- **Explicit optionals**: Use `Type | None` not implicit optionals

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
uv run pytest tests/test_specific.py -v        # Single file
uv run pytest tests/test_specific.py::test_fn  # Single test
uv run pytest -k "keyword" -v                  # Match by name
```

**Before committing** (full validation):

```bash
uv run pytest                                  # Sequential, full suite
uv run pytest -n auto                          # Parallel, faster
```

**CI runs** (what GitHub Actions does):

```bash
uv run pytest --cov=shamir --cov-report=xml    # With coverage
```

### Property-Based Testing

Use Hypothesis for testing mathematical properties:

- Roundtrip property: `combine(split(secret, n, k)) == secret`
- Threshold property: Any k parts reconstruct, k-1 parts don't
- Invariants: Result length matches input length
- See `tests/test_shamir.py` for examples

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
- **Array indexing**: Secret length vs part length differ by 1
  - Parts have extra byte for x-coordinate
  - `part[len(part) - 1]` is x-coordinate

### Byte Order

- **Big-endian by default**: First byte of secret is first byte of parts
- **No padding**: Secret length preserved exactly (unlike some implementations)
- **X-coordinate position**: Always last byte of each part

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

- 1MB secrets should split/combine in <500ms
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
- **Security Scan**: `uv run pre-commit run gitleaks --all-files`
- **All Checks**: `uv run pre-commit run --all-files`

### Testing

- **Full suite**: `uv run pytest`
- **Parallel**: `uv run pytest -n auto`
- **With coverage**: `uv run pytest --cov=shamir --cov-report=html`
- **Specific file**: `uv run pytest tests/test_shamir.py -v`
- **Watch mode**: `uv run pytest-watch` (if installed)

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
5. **Coverage failures**: Add tests for uncovered lines, check with `--cov-report=html`

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
