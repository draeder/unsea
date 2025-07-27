# CI/CD Pipeline

## Overview

Comprehensive CI/CD pipeline with security scanning, multi-platform testing, and automated deployment.

## Setup

1. **For Contributors**:
   ```bash
   git clone https://github.com/draeder/unsea.git
   cd unsea
   npm run ci:setup
   ```

2. **For Maintainers**:
   - Add `NPM_TOKEN` and `SEMGREP_APP_TOKEN` secrets
   - Run `./.github/scripts/configure-repo.sh`

## Pipeline Components

- **Security**: npm audit (high), Semgrep, CodeQL
- **Testing**: Multi-platform (Linux/Windows/macOS),   ✅ Multi-version testing (Node.js 20, 22)
- **Quality**: Pre-commit hooks, required reviews, browser testing
- **Deployment**: Automated npm publishing on version changes

## Key Features

- High-level security audits appropriate for crypto libraries
- Scans distribution files (`dist/`) that users actually consume
- Pre-commit hooks prevent vulnerable code from being committed
- Required status checks and code reviews before merging

---

For issues, use the provided templates. For security vulnerabilities, use private disclosure.
