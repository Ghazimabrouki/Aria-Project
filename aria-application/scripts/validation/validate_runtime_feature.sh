#!/usr/bin/env bash
# Runtime Feature Validation Script
# Runs backend compile checks, tests, frontend lint/build, and Playwright E2E.
# Exit 0 if all pass, exit 1 if any fail.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0

log_pass() {
    echo -e "${GREEN}✅ PASS${NC}: $1"
    ((PASS+=1)) || true
}

log_fail() {
    echo -e "${RED}❌ FAIL${NC}: $1"
    ((FAIL+=1)) || true
}

log_info() {
    echo -e "${YELLOW}ℹ️ INFO${NC}: $1"
}

# ---------------------------------------------------------------------------
# 1. Backend compile checks
# ---------------------------------------------------------------------------
log_info "Checking backend Python file compilation..."
BACKEND_FILES=(
    "api/routes/runtime.py"
    "pipeline/datausage/runtime_orchestrator.py"
    "response/runtime_ai_engine/remediation_planner.py"
    "response/ansible_exec.py"
    "response/fix_verifier.py"
    "response/models.py"
    "main.py"
    "scripts/validation/runtime_qa_watchdog.py"
)

COMPILE_OK=true
for f in "${BACKEND_FILES[@]}"; do
    if python3 -m py_compile "$f" 2>/dev/null; then
        :
    else
        log_fail "Python compile: $f"
        COMPILE_OK=false
    fi
done

if $COMPILE_OK; then
    log_pass "Backend Python compilation"
fi

# ---------------------------------------------------------------------------
# 2. Backend tests
# ---------------------------------------------------------------------------
log_info "Running backend unit tests..."

if python3 -m pytest tests/test_manual_workflow.py -q --tb=short 2>/dev/null; then
    log_pass "test_manual_workflow.py"
else
    log_fail "test_manual_workflow.py"
fi

if python3 -m pytest tests/test_forwarder.py -q --tb=short 2>/dev/null; then
    log_pass "test_forwarder.py"
else
    log_fail "test_forwarder.py"
fi

# ---------------------------------------------------------------------------
# 3. Runtime QA Watchdog (lightweight check)
# ---------------------------------------------------------------------------
log_info "Running runtime QA watchdog (lightweight)..."

if python3 scripts/validation/runtime_qa_watchdog.py --ci --silent 2>/dev/null; then
    log_pass "Runtime QA watchdog (no critical issues)"
else
    log_fail "Runtime QA watchdog (critical issues detected)"
fi

# ---------------------------------------------------------------------------
# 4. Frontend lint
# ---------------------------------------------------------------------------
log_info "Running frontend lint..."

if (cd frontend && pnpm lint 2>/dev/null); then
    log_pass "Frontend lint"
else
    log_fail "Frontend lint"
fi

# ---------------------------------------------------------------------------
# 5. Frontend build
# ---------------------------------------------------------------------------
log_info "Running frontend build..."

if (cd frontend && pnpm build 2>/dev/null); then
    log_pass "Frontend build"
else
    log_fail "Frontend build"
fi

# ---------------------------------------------------------------------------
# 6. Playwright E2E tests
# ---------------------------------------------------------------------------
log_info "Running Playwright E2E tests..."

if (cd frontend && pnpm exec playwright test e2e/runtime-investigations.spec.ts --reporter=list 2>/dev/null); then
    log_pass "Playwright E2E runtime-investigations"
else
    log_fail "Playwright E2E runtime-investigations"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "========================================"
echo "  Runtime Feature Validation Summary"
echo "========================================"
echo -e "  Passed: ${GREEN}${PASS}${NC}"
echo -e "  Failed: ${RED}${FAIL}${NC}"
echo ""

if [ "$FAIL" -eq 0 ]; then
    echo -e "${GREEN}🟢 ALL CHECKS PASSED${NC}"
    exit 0
else
    echo -e "${RED}🔴 SOME CHECKS FAILED${NC}"
    exit 1
fi
