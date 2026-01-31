#!/bin/bash

# Simple test suite for noexec detectors

echo "======================================"
echo "noexec Detector Test Suite"
echo "======================================"
echo ""

# Test 1: Credential leak
echo "Test 1: Credential Leak Detection"
echo '{"command": "echo $AWS_SECRET_ACCESS_KEY"}' | node dist/cli.js analyze --hook PreToolUse 2>&1
echo ""

# Test 2: Destructive command
echo "Test 2: Destructive Command Detection (rm -rf /)"
echo '{"command": "rm -rf /"}' | node dist/cli.js analyze --hook PreToolUse 2>&1
echo ""

# Test 3: Git force push
echo "Test 3: Git Force Push Detection"
echo '{"command": "git push --force origin main"}' | node dist/cli.js analyze --hook PreToolUse 2>&1
echo ""

# Test 4: Environment variable leak
echo "Test 4: Environment Variable Leak Detection"
echo '{"command": "echo $API_KEY"}' | node dist/cli.js analyze --hook PreToolUse 2>&1
echo ""

# Test 5: Safe command (should pass)
echo "Test 5: Safe Command (should allow)"
echo '{"command": "ls -la"}' | node dist/cli.js analyze --hook PreToolUse 2>&1
if [ $? -eq 0 ]; then
  echo "✓ Safe command allowed"
else
  echo "✗ Safe command was blocked (unexpected)"
fi
echo ""

echo "======================================"
echo "Manual Test Complete"
echo "Check output above for blocked commands"
echo "======================================"
