#!/bin/bash
# Setup script for CodeQL local analysis

set -e

echo "🔧 Setting up CodeQL for local security analysis..."

# Check if CodeQL CLI is installed
if ! command -v codeql &> /dev/null; then
    echo "❌ CodeQL CLI not found!"
    echo "Please install CodeQL CLI first:"
    echo "  macOS: brew install codeql"
    echo "  Other: https://github.com/github/codeql-cli-binaries/releases"
    exit 1
fi

echo "✅ CodeQL CLI found: $(codeql version --format=text)"

# Create .codeql directory if it doesn't exist
if [ ! -d ".codeql" ]; then
    mkdir -p .codeql
    echo "📁 Created .codeql directory"
fi

# Download JavaScript/TypeScript query packages
echo "📦 Downloading CodeQL JavaScript query packages..."
codeql pack download codeql/javascript-queries

echo "🎉 CodeQL setup complete!"
echo ""
echo "You can now run security analysis with:"
echo "  npm run codeql:quick    # Quick analysis"
echo "  npm run codeql:full     # Comprehensive analysis"
echo ""
echo "Or integrate with git hooks:"
echo "  npm run codeql:install-hooks"
