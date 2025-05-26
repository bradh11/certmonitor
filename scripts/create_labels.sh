#!/bin/bash
# Script to create GitHub labels for the certmonitor project
# Run this once to set up the labels used by the auto-labeler

# Colors for labels (hex codes without #)
PYTHON_COLOR="3776ab"      # Python blue
RUST_COLOR="000000"        # Rust black
TESTS_COLOR="28a745"       # Green
DOCS_COLOR="0366d6"        # Blue
CI_COLOR="6f42c1"          # Purple
DEPS_COLOR="e99695"        # Light red
CORE_COLOR="d73a4a"        # Red
VALIDATORS_COLOR="f9d0c4"  # Light orange
PROTOCOLS_COLOR="c5def5"   # Light blue
SECURITY_COLOR="b60205"    # Dark red

# Function to create a label (requires gh CLI)
create_label() {
    local name="$1"
    local description="$2"
    local color="$3"
    
    echo "Creating label: $name"
    gh label create "$name" --description "$description" --color "$color" 2>/dev/null || \
    gh label edit "$name" --description "$description" --color "$color" 2>/dev/null || \
    echo "  ⚠️  Failed to create/update label: $name"
}

# Check if gh CLI is available
if ! command -v gh &> /dev/null; then
    echo "❌ GitHub CLI (gh) is not installed. Please install it first:"
    echo "   brew install gh"
    echo "   Then run: gh auth login"
    exit 1
fi

# Check if authenticated
if ! gh auth status &> /dev/null; then
    echo "❌ Not authenticated with GitHub. Please run: gh auth login"
    exit 1
fi

echo "🏷️  Creating GitHub labels for certmonitor..."

# Create all the labels
create_label "python" "Python source code changes" "$PYTHON_COLOR"
create_label "rust" "Rust source code changes" "$RUST_COLOR"
create_label "tests" "Test changes" "$TESTS_COLOR"
create_label "documentation" "Documentation changes" "$DOCS_COLOR"
create_label "ci" "CI/CD changes" "$CI_COLOR"
create_label "dependencies" "Dependency changes" "$DEPS_COLOR"
create_label "core" "Core functionality changes" "$CORE_COLOR"
create_label "validators" "Validator changes" "$VALIDATORS_COLOR"
create_label "protocols" "Protocol handler changes" "$PROTOCOLS_COLOR"
create_label "security" "Security-related changes" "$SECURITY_COLOR"

echo "✅ Label creation complete!"
echo ""
echo "💡 You can now run the labeler action, or create a PR to test auto-labeling."
