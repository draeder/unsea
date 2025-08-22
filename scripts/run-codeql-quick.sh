#!/bin/bash

# Quick database creation (no build step for faster execution)
codeql database create "$TEMP_DB" \
  --language=javascript \
  --source-root=. \
  --overwrite \
  --quiet \
  --no-run-unnecessary-builds || {k CodeQL Pre-commit Check
# This runs a faster analysis suitable for pre-commit hooks

set -e

echo "🔍 Running quick CodeQL security check..."

# Create temp database with unique name
TEMP_DB=".codeql-temp-$(date +%s)"
rm -rf "$TEMP_DB"

# Quick database creation (no build step for faster execution)
codeql database create "$TEMP_DB" 
  --language=javascript 
  --source-root=. 
  --overwrite 
  --quiet || {
    echo "❌ Failed to create CodeQL database"
    rm -rf "$TEMP_DB"
    exit 1
  }

# Run only critical security queries for speed
codeql database analyze "$TEMP_DB" 
  codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls 
  --format=csv 
  --output="$TEMP_DB/quick-results.csv" 
  --quiet 
  --ram=512 || {
    echo "❌ Failed to run CodeQL analysis"
    rm -rf "$TEMP_DB"
    exit 1
  }

# Check results
if [ -f "$TEMP_DB/quick-results.csv" ]; then
  RESULT_COUNT=$(tail -n +2 "$TEMP_DB/quick-results.csv" 2>/dev/null | wc -l | tr -d ' ')
  if [ "$RESULT_COUNT" -gt 0 ]; then
    echo "❌ CodeQL found $RESULT_COUNT potential security issues:"
    head -10 "$TEMP_DB/quick-results.csv"
    echo ""
    echo "Run 'npm run codeql:full' for detailed analysis"
    rm -rf "$TEMP_DB"
    exit 1
  fi
fi

echo "✅ Quick CodeQL check passed"
rm -rf "$TEMP_DB"