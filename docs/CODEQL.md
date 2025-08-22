# CodeQL Security Analysis

This repository is configured with CodeQL for automated security analysis. CodeQL can be run both in CI/CD and locally before committing.

## Setup

### 1. Install CodeQL CLI

#### macOS (Homebrew)
```bash
brew install codeql
```

#### Manual Installation
1. Download CodeQL CLI from [GitHub Releases](https://github.com/github/codeql-cli-binaries/releases)
2. Extract and add to your PATH

### 2. Setup CodeQL for this project
```bash
npm run codeql:setup
```

This will:
- Verify CodeQL CLI is installed
- Download JavaScript/TypeScript query packages
- Create necessary directories

## Local Usage

### Quick Security Check (Recommended for Pre-commit)
```bash
npm run codeql:quick
```
- Fast analysis (~30 seconds)
- Focuses on critical security issues
- Suitable for pre-commit hooks

### Full Security Analysis
```bash
npm run codeql:full
```
- Complete analysis with all query suites
- Takes longer (~2-3 minutes)
- Generates detailed SARIF and CSV reports
- Use for thorough security review

### Complete Security Suite
```bash
npm run security:full
```
- Runs npm audit + full CodeQL analysis
- Comprehensive security check

## Automated Integration

### Pre-commit Hook
CodeQL quick analysis runs automatically before each commit. To bypass:
```bash
git commit --no-verify
```

### CI/CD
Full CodeQL analysis runs on:
- Push to `main` or `develop` branches
- Pull requests to `main`
- Weekly schedule (Mondays at 2 AM UTC)

## Configuration

- **CodeQL Config**: `.github/codeql/codeql-config.yml`
- **Query Suites**: `security-and-quality`, `security-extended`
- **Scanned Paths**: `src/`, `test/`, `example/`, `dist/`

## Understanding Results

### Exit Codes
- `0`: No security issues found ✅
- `1`: Security issues detected ❌

### Report Formats
- **CSV**: Human-readable results in `.codeql-analysis/results.csv`
- **SARIF**: Machine-readable format for IDE integration

### Common Issues
- **js/incomplete-sanitization**: Input validation concerns
- **js/code-injection**: Potential code injection vulnerabilities
- **js/path-injection**: File system path manipulation risks

## VS Code Integration

Install the SARIF extension to view results directly in VS Code:
```bash
code --install-extension ms-sarif.sarif-viewer
```

Then open `.codeql-analysis/results.sarif` files for detailed issue analysis.

## Troubleshooting

### "codeql not found"
Ensure CodeQL is installed and in your PATH:
```bash
which codeql
codeql version
```

### Database Creation Fails
Ensure dependencies are installed:
```bash
npm ci
```

### False Positives
Edit `.github/codeql/codeql-config.yml` to exclude specific rules:
```yaml
query-filters:
  - exclude:
      id: js/rule-id-to-exclude
```
