#!/bin/bash

# Test script for bc-components
# Runs tests with different feature flag combinations
#
# Note: Tests requiring a real SSH agent are marked with #[ignore]
# To run them manually, ensure you have an SSH agent running with an Ed25519 key
# and run: cargo test --features ssh-agent-tests -- --ignored

set -e

TERM_PURPLE='\033[0;35m'
TERM_BOLD='\033[1m'
TERM_RESET='\033[0m'

section() {
    echo -e "${TERM_PURPLE}${TERM_BOLD}=== $1 ===${TERM_RESET}"
}

# argument: "feature1,feature2,..."
test_only_features() {
    local features="$1"
    section "no default + $features"
    cargo test --lib --bins --tests --benches --no-default-features --features "$features" > /dev/null
}

test_additional_features() {
    local features="$1"
    section "default + $features"
    cargo test --lib --bins --tests --benches --features "$features" > /dev/null
}

section "All Default Features"
cargo test --all-targets > /dev/null

section "No Default Features"
# Skip doctests as they require at least one signing scheme
cargo test --lib --bins --tests --benches --no-default-features > /dev/null

test_only_features "pqcrypto"
test_only_features "secp256k1"
test_only_features "ed25519"
test_only_features "ssh"

test_only_features "ssh,ed25519"
test_only_features "secp256k1,ed25519,pqcrypto"
test_only_features "secp256k1,pqcrypto,ssh"

test_additional_features "ssh-agent"
test_additional_features "ssh-agent-tests"

section "Doc Tests"
cargo test --doc > /dev/null

echo -e "${TERM_PURPLE}${TERM_BOLD}✓ All test configurations passed${TERM_RESET}"
