#!/bin/bash

# Local CodeQL Analysis Script for Unsea
# This script runs the same CodeQL analysis locally that runs in CI/CD

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if CodeQL is available
if ! command -v codeql &> /dev/null; then
    echo -e "${RED}❌ CodeQL CLI not found! Please install it first:${NC}"
    echo "  macOS: brew install codeql"
    echo "  Other: https://github.com/github/codeql-cli-binaries/releases"
    exit 1
fi

# Check if query packages are available
if ! codeql resolve packs | grep -q "codeql/javascript-queries"; then
    echo -e "${RED}❌ CodeQL JavaScript packages not found! Please run setup first:${NC}"
    echo "  npm run codeql:setup"
    exit 1
fi

echo -e "${YELLOW}🔍 Starting local CodeQL analysis for Unsea...${NC}"

# Create analysis directory
ANALYSIS_DIR=".codeql-analysis"
rm -rf "$ANALYSIS_DIR"
mkdir -p "$ANALYSIS_DIR"

# Step 1: Create CodeQL database
echo -e "${YELLOW}📊 Creating CodeQL database...${NC}"
codeql database create "$ANALYSIS_DIR/unsea-db" \
  --language=javascript \
  --source-root=. \
  --command="npm ci && npm run build" \
  --overwrite

# Step 2: Run analysis with security queries
echo -e "${YELLOW}🔬 Running CodeQL analysis...${NC}"
codeql database analyze "$ANALYSIS_DIR/unsea-db" \
  codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls \
  --format=sarif-latest \
  --output="$ANALYSIS_DIR/results.sarif" \
  --sarif-category=javascript

# Step 3: Generate human-readable report
echo -e "${YELLOW}📋 Generating human-readable report...${NC}"
codeql database analyze "$ANALYSIS_DIR/unsea-db" \
  codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls \
  --format=csv \
  --output="$ANALYSIS_DIR/results.csv"

# Step 4: Show results summary
echo -e "${GREEN}✅ CodeQL analysis complete!${NC}"
echo ""
echo "Results saved to:"
echo "  - SARIF format: $ANALYSIS_DIR/results.sarif"
echo "  - CSV format:   $ANALYSIS_DIR/results.csv"
echo ""

# Check if there are any results
if [ -f "$ANALYSIS_DIR/results.csv" ]; then
  RESULT_COUNT=$(tail -n +2 "$ANALYSIS_DIR/results.csv" | wc -l | tr -d ' ')
  if [ "$RESULT_COUNT" -gt 0 ]; then
    echo -e "${RED}⚠️  Found $RESULT_COUNT potential security issues:${NC}"
    echo ""
    # Show first few results
    head -20 "$ANALYSIS_DIR/results.csv"
    if [ "$RESULT_COUNT" -gt 18 ]; then
      echo "... and $(($RESULT_COUNT - 18)) more results in $ANALYSIS_DIR/results.csv"
    fi
    exit 1
  else
    echo -e "${GREEN}🎉 No security issues found!${NC}"
  fi
fi

echo ""
echo "To view detailed results:"
echo "  cat $ANALYSIS_DIR/results.csv"
echo "  # or open $ANALYSIS_DIR/results.sarif in VS Code with SARIF extension"
