# Contributing

Contributions are welcome via GitHub pull requests. This guide covers the
expectations for working on this package.

## Requirements

- PHP 8.3+
- Composer 2

## Getting Started

```bash
git clone git@github.com:sinemacula/laravel-authentication.git
cd laravel-authentication
composer install
```

## Development Workflow

### Branching

Branch from `master` using the appropriate prefix:

| Prefix      | Purpose                          |
|-------------|----------------------------------|
| `feature/`  | New functionality                |
| `bugfix/`   | Bug fixes                        |
| `hotfix/`   | Urgent production fixes          |
| `refactor/` | Refactoring without new features |
| `chore/`    | Tooling, CI, dependencies        |

### Commits

This project uses [Conventional Commits](https://www.conventionalcommits.org/).
Prefix your commit messages accordingly:

```text
feat: add tenant-aware principal resolution
fix: preserve principal context during refresh
test: add query budget tests for 3D bearer path
chore: update qlty configuration
```

### Code Quality

All code must pass static analysis before submission:

```bash
composer check                            # PHPStan level 8, PHP-CS-Fixer, CodeSniffer
composer check -- --all --no-cache --fix  # With auto-fix
composer format                           # Format code
```

### Testing

Run the full test suite before submitting:

```bash
composer test             # All suites in parallel (Paratest)
composer test-coverage    # With clover coverage report
```

Individual suites:

```bash
composer test:unit          # Unit tests
composer test:feature       # Feature tests
composer test:integration   # Integration tests
composer test:performance   # Performance budget tests
```

Single test file or method:

```bash
vendor/bin/phpunit tests/Unit/SomeTest.php
vendor/bin/phpunit --filter testMethodName tests/Unit/SomeTest.php
```

### Standards

- PHP strict types (`declare(strict_types = 1)`) in every file
- PHPStan level 8 compliance
- Full type hints on all public method parameters and return types
- PHPDoc on all methods and classes
- 100% line coverage is expected for new code

## Pull Requests

- Keep changes minimal and scoped to a single concern
- Do not change static analysis or formatting configuration without prior
  discussion
- Include tests for new or changed behaviour
- Ensure `composer check` and `composer test` pass

## Security

If you discover a security vulnerability, please report it directly to
Sine Macula rather than opening a public issue. See [SECURITY.md](SECURITY.md)
for details.

## License

By contributing, you agree that your contributions will be licensed under
the [Apache License 2.0](LICENSE).
