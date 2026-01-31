#!/bin/bash
# Example test script for noexec

echo "Testing noexec CLI..."
echo ""

# Test 1: Clean command (should pass)
echo "Test 1: Clean command"
echo '{"tool": "Bash", "command": "echo hello"}' | node dist/cli.js analyze
if [ $? -eq 0 ]; then
    echo "✅ PASSED: Clean command allowed"
else
    echo "❌ FAILED: Clean command was blocked"
fi
echo ""

# Test 2: Magic string detection (should block)
echo "Test 2: Magic string 'test_me'"
echo '{"tool": "Bash", "command": "echo test_me"}' | node dist/cli.js analyze
if [ $? -eq 2 ]; then
    echo "✅ PASSED: Magic string blocked"
else
    echo "❌ FAILED: Magic string not detected"
fi
echo ""

# Test 3: Credential leak detection (should block)
echo "Test 3: API key leak"
echo '{"command": "export API_KEY=sk-abcdefghijklmnopqrstuvwxyz1234567890123456"}' | node dist/cli.js analyze
if [ $? -eq 2 ]; then
    echo "✅ PASSED: Credential leak blocked"
else
    echo "❌ FAILED: Credential leak not detected"
fi
echo ""

echo "All tests completed!"
