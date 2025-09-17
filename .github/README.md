# GitHub Actions CI/CD Setup

This repository includes comprehensive GitHub Actions workflows for continuous integration, security scanning, and automated releases.

## Workflows

### 🔄 CI Workflow (`.github/workflows/ci.yml`)

**Triggers:** Push or Pull Request to `main` or `develop` branches

**What it does:**
- Sets up PostgreSQL 15 database service
- Installs Elixir 1.15.7 with OTP 26.1
- Caches dependencies for faster builds
- Runs code formatting checks
- Performs static analysis with Credo
- Compiles with warnings treated as errors
- Executes tests with coverage reporting
- Runs quality checks using `mix quality`

### 🚀 Release Workflow (`.github/workflows/release.yml`)

**Triggers:** Git tags starting with `v*` (e.g., `v1.0.0`)

**What it does:**
- Builds production release
- Generates documentation
- Creates GitHub release with auto-generated notes
- Optionally publishes to Hex.pm (requires `HEX_API_KEY` secret)

### 🔒 Security Workflow (`.github/workflows/security.yml`)

**Triggers:** 
- Push or Pull Request to `main`
- Weekly schedule (Mondays at 10:00 UTC)

**What it does:**
- Scans for security vulnerabilities using Trivy
- Uploads results to GitHub Security tab
- Runs automatically on a weekly basis

### 🧪 Matrix Testing (`.github/workflows/matrix.yml`)

**Triggers:**
- Push or Pull Request to `main`
- Weekly schedule (Sundays at 6:00 UTC)

**What it does:**
- Tests across multiple Elixir/OTP version combinations
- Ensures compatibility with minimum and latest supported versions
- Includes Elixir 1.15.0-1.16.0 with OTP 26.0-26.2

## Configuration

### Required Secrets

For full functionality, add these secrets to your repository:

- `HEX_API_KEY` - Required for automatic Hex.pm publishing on releases
- `GITHUB_TOKEN` - Automatically provided by GitHub Actions

### Database Setup

All workflows use PostgreSQL with these credentials (matching `config/test.exs`):
- **Username:** `postgres`
- **Password:** `postgres`  
- **Database:** `postgres`
- **Port:** `5432`

### Coverage Reporting

The CI workflow generates coverage reports using ExCoveralls and uploads them to GitHub. The project requires a minimum of 85% test coverage as configured in `.coveralls.exs`.

## Status Badges

Add these badges to your README.md:

```markdown
[![CI](https://github.com/agoodway/tango/actions/workflows/ci.yml/badge.svg)](https://github.com/agoodway/tango/actions/workflows/ci.yml)
[![Security](https://github.com/agoodway/tango/actions/workflows/security.yml/badge.svg)](https://github.com/agoodway/tango/actions/workflows/security.yml)
```

## Local Development

To run the same checks locally:

```bash
# Install dependencies
mix deps.get

# Run formatting check
mix format --check-formatted

# Run static analysis
mix credo --strict

# Run tests with coverage
mix coveralls

# Run all quality checks
mix quality
```

## Troubleshooting

### Common Issues

1. **Database Connection Errors**: Ensure PostgreSQL is running locally with the credentials in `config/test.exs`
2. **Coverage Failures**: Check that tests meet the 85% minimum coverage requirement
3. **Formatting Errors**: Run `mix format` to auto-fix formatting issues
4. **Credo Warnings**: Address static analysis issues highlighted by Credo

### Workflow Debugging

- Check the Actions tab for detailed logs
- Failed steps will show specific error messages
- Use the re-run feature to retry failed workflows
- Check the matrix workflow for compatibility issues across Elixir versions