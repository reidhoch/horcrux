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
| `tests/`           | Comprehensive pytest suite with markers                    |
| `examples/`        | Simple demonstration projects                              |

## Core Components

## Mathematical Foundation

- Field: GF(256)
- Polynomial Construction: Each byte of the secret gets its own random polynomial with degree = threshold - 1
- Interpolation: Lagrange interpolation over GF(256) to reconstruct secrets
- Security: Information-theoretic security - fewer than threshold parts reveal nothing

## Critical Implementation Details

- X-coordinate generation: Shuffled list of 256 values, indexed by part number (x = x_coords[i] + 1)
- Byte-by-byte processing: Each secret byte has a separate polynomial (field limitation)
- Constant-time operations: Used to prevent timing attacks

## Code Conventions

## Type Annotations

- **Strict typing required**:
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

## Performance Expectations

- 1MB secrets should split/combine in <500ms
- 255 parts (max) with threshold 128 should work reliably

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

**Critical**: This is a security focused library, keep that in mind when reviewing. A perfectly written PR that adds unwanted functionality must still be rejected. The code must advance the codebase in the intended direction, not just be well-written. When rejecting, provide clear guidance on how to align with project goals.

Be friendly and welcoming while maintaining high standards. Call out what works well - this reinforces good patterns. When code needs improvement, be specific about why and how to fix it. Remember that PRs serve as documentation for future developers.

### Focus On

- **Does this advance the codebase in the intended direction?** (Even perfect code for unwanted features should be rejected)
- **API design and naming clarity** - Identify confusing patterns (e.g., parameter values that contradict defaults) or non-idiomatic code (mutable defaults, etc.). Contributed code will need to be maintained indefinitely, and by someone other than the author (unless the author is a maintainer).
- **Suggest specific improvements**, not generic "add more tests" comments
- **Think about API ergonomics and learning curve** from a user perspective

### For Agent Reviewers

- **Read the full context**: Always examine related files, tests, and documentation before reviewing
- **Check against established patterns**: Look for consistency with existing codebase conventions
- **Verify functionality claims**: Don't just read code - understand what it actually does
- **Consider edge cases**: Think through error conditions and boundary scenarios

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

If something needs work, your review should help it get there through specific, actionable feedback. If it's solving the wrong problem, say so clearly.

### Review Comment Examples

**Good Review Comments:**

❌ "Add more tests"
✅ "The `div` method needs tests for the edge case where a=0"

❌ "This API is confusing"
✅ "The parameter name `data` is ambiguous - consider `message_content` to consistently match other methods"

❌ "This could be better"
✅ "This approach works but creates a circular dependency. Consider moving the validation to `utils/foo.py`"

### Review Checklist

Before approving, verify:

- [ ] All required development workflow steps completed (uv sync, pre-commit, pytest)
- [ ] Changes align with repository patterns and conventions
- [ ] API changes are documented and backwards-compatible where possible
- [ ] Error handling follows project patterns (specific exception types)
- [ ] Tests cover new functionality and edge cases

## Key Tools & Commands

### Validation Commands (Run Frequently)

- **Linting**: `uv run ruff check` (or with `--fix`)
- **Type Checking**: `uv run mypy`
- **All Checks**: `uv run pre-commit run --all-files`

### Testing

- **Standard**: `uv run pytest`

## Critical Patterns

### Build Issues (Common Solutions)

1. **Dependencies**: Always `uv sync` first
2. **Pre-commit fails**: Run `uv run pre-commit run --all-files` to see failures
3. **Type errors**: Use `uv run mypy` directly, check `pyproject.toml` config
