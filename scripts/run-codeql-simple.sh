#!/bin/bash

# Simplified CodeQL Security Check
# Basic security analysis without complex database creation

set -e

# Check if CodeQL is available
if ! command -v codeql &> /dev/null; then
    echo "❌ CodeQL CLI not found! Please install it first:"
    echo "  macOS: brew install codeql"
    echo "  Other: https://github.com/github/codeql-cli-binaries/releases"
    exit 1
fi

# Check if query packages are available
if ! codeql resolve packs | grep -q "codeql/javascript-queries"; then
    echo "❌ CodeQL JavaScript packages not found! Please run setup first:"
    echo "  npm run codeql:setup"
    exit 1
fi

echo "🔍 Running CodeQL security analysis..."

# Clean up any existing analysis
rm -rf .codeql-analysis-simple

# Create database
echo "📊 Creating CodeQL database..."
codeql database create .codeql-analysis-simple \
  --language=javascript \
  --source-root=. \
  --overwrite

# Run analysis
echo "🔬 Analyzing code..."
codeql database analyze .codeql-analysis-simple \
  "/Users/danraeder/.codeql/packages/codeql/javascript-queries/2.0.1/codeql-suites/javascript-security-and-quality.qls" \
  --format=csv \
  --output=.codeql-analysis-simple/results.csv

# Check results
if [ -f ".codeql-analysis-simple/results.csv" ]; then
  RESULT_COUNT=$(tail -n +2 ".codeql-analysis-simple/results.csv" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$RESULT_COUNT" -gt 0 ]; then
    echo "❌ Found $RESULT_COUNT potential security issues:"
    head -10 ".codeql-analysis-simple/results.csv"
    echo ""
    echo "Full results in: .codeql-analysis-simple/results.csv"
    exit 1
  else
    echo "✅ No security issues found!"
  fi
else
  echo "⚠️  No results file generated"
fi

# Cleanup
rm -rf .codeql-analysis-simple
echo "✅ CodeQL analysis complete"
