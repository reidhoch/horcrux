# Contributing to Horcrux

Thank you for your interest in contributing to Horcrux! This document provides guidelines for code review, dependency management, versioning, and other contribution practices.

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
✅ "The parameter name `data` is ambiguous - consider `secret` to match the `split()` function signature (`shamir/__init__.py:77`)"

❌ "This could be better"
✅ "This approach works but creates a circular dependency. Consider moving the validation to `shamir/errors.py`"

❌ "Security concerns"
✅ "This branches on secret byte values which could leak timing information. Use constant-time comparison (see `shamir/utils/__init__.py:15` for pattern)"

### Review Checklist

Before approving, verify:

- [ ] All required development workflow steps completed (uv sync, prek, pytest)
- [ ] Changes align with repository patterns and conventions
- [ ] API changes are documented and backwards-compatible where possible
- [ ] Error handling follows project patterns (specific exception types from Error enum)
- [ ] Tests cover new functionality and edge cases
- [ ] No security implications (timing attacks, secret leakage, etc.)
- [ ] Dependencies justified if any added
- [ ] Type hints complete and mypy passes

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

## Examples Directory

### Purpose

Examples demonstrate real-world usage patterns for users. They should be:

- **Simple**: Focus on one use case
- **Complete**: Runnable without modification
- **Practical**: Solve actual problems users might have

### Current Examples

- `hello.py` - Basic string splitting/combining
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

Tested on an Apple M1 Max:

- 1MB secrets should split/combine in <30s
- 255 parts (max) with threshold 128 should work reliably
- Memory usage should be O(secret_size * parts)

When optimizing:

- Profile first - use `cProfile` or `py-spy`
- Focus on hot paths - optimize what matters
- Maintain security properties - constant-time operations
- Benchmark changes - use pytest-codspeed benchmarks

## CI/CD

### Continuous Integration

- **Python versions**: Tests run on Python 3.11, 3.12, 3.13, 3.14 via GitHub Actions
- **Coverage**: Uploaded to codecov (100% required)
- **Formatting**: Ruff format check must pass (blocking)
- **Linting**: All Ruff lint rules must pass (blocking)
- **Type checking**: Mypy must pass with strict settings

### Build System

- **Build backend**: Hatch (PEP 621 compliant)
- **Dependency management**: `uv` for fast, reliable dependency resolution
- **Publishing**: Automated via `uv` to PyPI

### Security Workflows

The project includes comprehensive security scanning via `.github/workflows/security.yaml`:

- **Semgrep SAST**: Advanced static analysis with OWASP Top 10, secrets, and security-audit rulesets
- **Bandit**: Python-specific security linting configured in `pyproject.toml`
- **pip-audit**: Dependency vulnerability scanning (fails on critical/high severity)
- **GitLeaks**: Secrets detection across full git history
- **Schedule**: Runs on push/PR, plus weekly Monday 00:00 UTC scans
- **Results**: SARIF uploaded to GitHub Security tab

### Pre-commit Hooks

The project uses pre-commit hooks (run via [prek](https://github.com/j178/prek), a Rust reimplementation of pre-commit) to ensure code quality:

```bash
# Install hooks
uv run prek install

# Run all hooks
uv run prek run --all-files

# Run specific hook
uv run prek run ruff-format --all-files
```

**Configured hooks:**

- Ruff format (auto-formatting)
- Ruff lint (code quality)
- Mypy (type checking)
- GitLeaks (secrets detection)

## Development Workflow

### Setting Up

```bash
# Clone repository
git clone https://github.com/rhochstedler/horcrux.git
cd horcrux

# Install dependencies
uv sync

# Install pre-commit hooks
uv run prek install
```

### Making Changes

1. **Create branch**: `git checkout -b feature/your-feature`
2. **Make changes**: Edit code, add tests, update docs
3. **Run tests**: `uv run pytest -n auto`
4. **Run checks**: `uv run prek run --all-files`
5. **Commit**: `git commit -m "Description of changes"`
6. **Push**: `git push origin feature/your-feature`
7. **Open PR**: Create pull request on GitHub

### Before Committing

**CRITICAL**: Always run these commands in sequence:

```bash
uv sync                              # Install dependencies
uv run prek run --all-files          # Ruff + mypy + gitleaks
uv run pytest -n auto                # Run full test suite
```

**All three must pass** - this is enforced by CI

## Adding to Public API

Before adding new public functions:

1. **Question necessity**: Can this be achieved with existing API?
2. **Consider ergonomics**: Will this be intuitive to users?
3. **Check consistency**: Does it match existing naming/signature patterns?
4. **Document thoroughly**: Google-style docstrings with examples
5. **Add to `__all__`**: Explicitly export in `shamir/__init__.py`

The public API (defined in `__all__`) is sacred - any changes require careful consideration:

- Adding functions: Ensure they solve real user problems
- Changing signatures: Requires major version bump
- Removing functions: Follow deprecation process (see API Stability & Versioning)

## Pull Request Guidelines

### PR Title

Use conventional commit format:

- `feat: Add new feature`
- `fix: Fix bug in combine()`
- `docs: Update README`
- `test: Add tests for edge case`
- `refactor: Simplify polynomial evaluation`
- `perf: Optimize GF(256) operations`
- `chore: Update dependencies`

### PR Description

Include:

1. **What**: What does this PR do?
2. **Why**: Why is this change needed?
3. **How**: How does it work (if non-obvious)?
4. **Testing**: How was this tested?
5. **Breaking changes**: List any breaking changes (if MAJOR version bump)

### PR Checklist

- [ ] Tests pass locally (`uv run pytest -n auto`)
- [ ] Pre-commit checks pass (`uv run prek run --all-files`)
- [ ] New functionality has tests
- [ ] Documentation updated (if needed)
- [ ] CHANGELOG.md updated (if user-facing change)
- [ ] Follows coding conventions (see AGENTS.md)
- [ ] No security implications (see SECURITY.md)

## Release Process

Releases are automated via GitHub Actions:

1. **Version bump**: Update version in appropriate commits
2. **Create tag**: `git tag v1.2.3`
3. **Push tag**: `git push origin v1.2.3`
4. **GitHub Actions**: Automatically builds and publishes to PyPI
5. **Create release**: Draft release notes on GitHub

Version is auto-generated via `hatch-vcs` based on git tags.

## Getting Help

- **Questions**: Open a discussion on GitHub
- **Bugs**: Open an issue with reproduction steps
- **Security**: See SECURITY.md for reporting vulnerabilities
- **Feature requests**: Open an issue describing use case

## License

By contributing, you agree that your contributions will be licensed under the project's license.
