# Contributing to Ab0t Auth

Thank you for your interest in contributing to Ab0t Auth! This document provides guidelines and instructions for contributing.

## Development Setup

### Prerequisites

- Python 3.11+
- Git

### Installation

```bash
# Clone the repository
git clone https://github.com/ab0t-com/auth_wrapper.git
cd auth_wrapper

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate     # Windows

# Install with dev dependencies
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
python scripts/test.py

# Run with verbose output
python scripts/test.py -v

# Run with coverage
python scripts/test.py --cov

# Run specific tests
python scripts/test.py -k tenant
python scripts/test.py -k "jwt or token"
```

### Linting and Formatting

```bash
# Check all (no changes)
python scripts/lint.py

# Auto-fix issues
python scripts/lint.py --fix

# Format only
python scripts/lint.py --format

# Run specific linters
python scripts/lint.py --ruff
python scripts/lint.py --mypy
```

## Code Style

### General Guidelines

1. **Pure Functions First** - Prefer pure functions over classes for business logic
2. **Immutable Data** - Use frozen dataclasses for data structures
3. **Type Hints** - All functions must have complete type hints
4. **Async by Default** - All I/O operations should be async

### Formatting

- Line length: 100 characters
- Use `black` for code formatting
- Use `isort` for import sorting
- Follow PEP 8 guidelines

### Example Code Style

```python
from dataclasses import dataclass, field
from typing import Sequence

@dataclass(frozen=True, slots=True)
class UserPermission:
    """Immutable permission data."""

    permission: str
    resource_id: str | None = None
    metadata: dict[str, str] = field(default_factory=dict)


def check_permission(
    user_permissions: Sequence[str],
    required: str,
) -> bool:
    """
    Check if user has required permission.

    Pure function - no side effects.
    """
    return required in user_permissions
```

## Pull Request Process

### Before Submitting

1. **Create a branch** from `main`:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following the code style guidelines

3. **Add tests** for new functionality

4. **Run the test suite**:
   ```bash
   python scripts/test.py
   ```

5. **Run linting**:
   ```bash
   python scripts/lint.py --fix
   ```

6. **Update documentation** if needed

### Submitting

1. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Create a Pull Request with:
   - Clear title describing the change
   - Description of what and why
   - Link to any related issues

3. Wait for review and address feedback

### PR Title Format

Use conventional commit format:

- `feat: Add new permission pattern matching`
- `fix: Handle expired tokens correctly`
- `docs: Update README with Flask examples`
- `refactor: Simplify JWT validation logic`
- `test: Add tenant isolation tests`
- `chore: Update dependencies`

## Project Structure

```
auth_wrapper/
├── src/ab0t_auth/
│   ├── __init__.py       # Public API exports
│   ├── core.py           # Immutable types (AuthenticatedUser, etc.)
│   ├── guard.py          # Main AuthGuard coordinator
│   ├── jwt.py            # JWT validation functions
│   ├── permissions.py    # Permission checking functions
│   ├── tenant.py         # Multi-tenancy support
│   ├── client.py         # Async HTTP client
│   ├── cache.py          # Token/permission caching
│   ├── dependencies.py   # FastAPI dependencies
│   ├── middleware.py     # ASGI middleware
│   ├── decorators.py     # FastAPI route decorators
│   ├── flask.py          # Flask extension
│   ├── config.py         # Configuration management
│   ├── errors.py         # Error types
│   └── logging.py        # Structured logging
├── tests/
│   ├── conftest.py       # Shared fixtures
│   ├── test_core.py
│   ├── test_jwt.py
│   ├── test_permissions.py
│   ├── test_tenant.py
│   └── test_flask.py
├── scripts/
│   ├── test.py           # Test runner
│   └── lint.py           # Linting script
└── demo/
    ├── fastapi_server.py
    └── flask_server.py
```

## Adding New Features

### Adding a New Dependency Type

1. Create the dependency function in `dependencies.py`:
   ```python
   def require_feature(
       guard: AuthGuard,
       feature: str,
   ) -> Callable[..., Awaitable[AuthenticatedUser]]:
       """Require user has access to feature."""
       async def dependency(request: Request) -> AuthenticatedUser:
           user = await _authenticate(guard, request)
           if not user.has_feature(feature):
               raise FeatureAccessDeniedError(feature)
           return user
       return dependency
   ```

2. Export from `__init__.py`

3. Add tests in `tests/test_dependencies.py`

4. Update README with usage examples

### Adding Flask Support for a Feature

1. Add decorator in `flask.py`:
   ```python
   def feature_required(feature: str):
       """Require feature access."""
       def decorator(f):
           @functools.wraps(f)
           def wrapper(*args, **kwargs):
               user = get_current_user()
               if not user or not user.has_feature(feature):
                   raise FeatureAccessDeniedError(feature)
               return f(*args, **kwargs)
           return wrapper
       return decorator
   ```

2. Add tests in `tests/test_flask.py`

## Reporting Issues

### Bug Reports

Include:
- Python version
- Package version
- Minimal reproduction code
- Expected vs actual behavior
- Full error traceback

### Feature Requests

Include:
- Use case description
- Proposed API design
- Any alternative approaches considered

## Questions?

- Open a GitHub issue for questions
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
