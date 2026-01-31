#!/bin/bash

# Test suite for noexec detectors
# This demonstrates all security detectors in action

set -e

echo "======================================"
echo "noexec Detector Test Suite"
echo "======================================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

test_count=0
pass_count=0
fail_count=0

# Test function
test_detector() {
  local test_name="$1"
  local command="$2"
  local should_block="$3"

  test_count=$((test_count + 1))

  echo "Test $test_count: $test_name"
  echo "  Command: $command"

  # Create test payload - escape the command properly for JSON
  local escaped_command=$(echo "$command" | sed 's/\\/\\\\/g' | sed 's/"/\\"/g')
  local payload="{\"command\": \"$escaped_command\"}"

  # Run detector
  echo "$payload" | node dist/cli.js analyze --hook PreToolUse >/dev/null 2>&1
  exit_code=$?

  if [ "$should_block" = "true" ]; then
    if [ $exit_code -eq 2 ]; then
      echo -e "  ${GREEN}✓ PASS${NC} - Correctly blocked"
      pass_count=$((pass_count + 1))
    else
      echo -e "  ${RED}✗ FAIL${NC} - Should have blocked but didn't (exit code: $exit_code)"
      fail_count=$((fail_count + 1))
    fi
  else
    if [ $exit_code -eq 0 ]; then
      echo -e "  ${GREEN}✓ PASS${NC} - Correctly allowed"
      pass_count=$((pass_count + 1))
    else
      echo -e "  ${RED}✗ FAIL${NC} - Should have allowed but didn't (exit code: $exit_code)"
      fail_count=$((fail_count + 1))
    fi
  fi

  echo ""
}

echo "========================================="
echo "1. Credential Leak Detection"
echo "========================================="

test_detector "AWS credentials" "echo \$AWS_SECRET_ACCESS_KEY" true
test_detector "GitHub token" "curl -H 'Authorization: token ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'" true
test_detector "API key in variable" "api_key=sk-abcdefghijklmnopqrstuvwxyz1234567890123456" true
test_detector "Safe command" "echo 'Hello World'" false

echo "========================================="
echo "2. Destructive Command Detection"
echo "========================================="

test_detector "rm -rf root" "rm -rf /" true
test_detector "rm -rf home" "rm -rf ~" true
test_detector "dd to device" "dd if=/dev/zero of=/dev/sda" true
test_detector "mkfs format" "mkfs.ext4 /dev/sdb1" true
test_detector "fork bomb" ":(){ :|:& };:" true
test_detector "Safe rm" "rm old_file.txt" false
test_detector "Safe dd" "dd if=input.bin of=output.bin" false

echo "========================================="
echo "3. Git Force Operation Detection"
echo "========================================="

test_detector "Force push" "git push --force origin main" true
test_detector "Force push shorthand" "git push -f origin feature" true
test_detector "Hard reset" "git reset --hard HEAD~1" true
test_detector "Force clean" "git clean -fdx" true
test_detector "Force branch delete" "git branch -D old-branch" true
test_detector "Safe push" "git push origin main" false
test_detector "Safe reset" "git reset --soft HEAD~1" false
test_detector "Force with lease" "git push --force-with-lease origin main" false

echo "========================================="
echo "4. Environment Variable Leak Detection"
echo "========================================="

test_detector "Echo AWS key" "echo \$AWS_SECRET_ACCESS_KEY" true
test_detector "Echo API key" "echo \$API_KEY" true
test_detector "Curl with token" "curl https://api.example.com -H 'Token: '\$GITHUB_TOKEN" true
test_detector "Export secret" "export SECRET_KEY=mysecret" true
test_detector "Safe echo" "echo \$PATH" false
test_detector "Safe export" "export NODE_ENV=production" false

echo ""
echo "======================================"
echo "Test Results Summary"
echo "======================================"
echo "Total tests: $test_count"
echo -e "${GREEN}Passed: $pass_count${NC}"
echo -e "${RED}Failed: $fail_count${NC}"
echo ""

if [ $fail_count -eq 0 ]; then
  echo -e "${GREEN}All tests passed!${NC}"
  exit 0
else
  echo -e "${RED}Some tests failed!${NC}"
  exit 1
fi
