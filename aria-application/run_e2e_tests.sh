#!/bin/bash
# Run E2E tests for the OpenSOAR backend.
#
# Usage:
#   ./run_e2e_tests.sh              # run all E2E tests
#   ./run_e2e_tests.sh connectivity # run only connectivity tests
#   ./run_e2e_tests.sh elastic      # run only ES tests
#   ./run_e2e_tests.sh opensoar     # run only OpenSOAR API tests
#   ./run_e2e_tests.sh pipeline     # run only pipeline tests
#   ./run_e2e_tests.sh response     # run only response layer tests
#   ./run_e2e_tests.sh assistant    # run only AI assistant tests
#   ./run_e2e_tests.sh full         # run full end-to-end flow test
#   ./run_e2e_tests.sh fast         # skip slow AI/flow tests

set -e
cd "$(dirname "$0")"

echo ""
echo "══════════════════════════════════════════════════════════"
echo "  OpenSOAR Backend — End-to-End Test Suite"
echo "══════════════════════════════════════════════════════════"
echo ""
echo "  Services expected:"
echo "    Elasticsearch : https://193.95.30.97:9200"
echo "    OpenSOAR      : http://193.95.30.97:8000"
echo "    Ollama        : http://193.95.30.97:11434"
echo "    Backend API   : http://localhost:8001  (start with: python3 main.py)"
echo ""

SUITE="${1:-all}"

case "$SUITE" in
    connectivity)
        echo "Running: Connectivity tests only"
        python3 -m pytest tests/e2e/test_01_connectivity.py -v
        ;;
    elastic)
        echo "Running: Elasticsearch tests"
        python3 -m pytest tests/e2e/test_02_elasticsearch.py -v
        ;;
    opensoar)
        echo "Running: OpenSOAR API tests"
        python3 -m pytest tests/e2e/test_03_opensoar_api.py -v
        ;;
    pipeline)
        echo "Running: Pipeline cycle tests"
        python3 -m pytest tests/e2e/test_04_pipeline_cycle.py -v
        ;;
    response)
        echo "Running: Response intelligence layer tests"
        python3 -m pytest tests/e2e/test_05_response_layer.py -v
        ;;
    assistant)
        echo "Running: AI assistant tests"
        python3 -m pytest tests/e2e/test_06_ai_assistant.py -v
        ;;
    full)
        echo "Running: Full end-to-end flow test"
        python3 -m pytest tests/e2e/test_07_full_flow.py -v
        ;;
    fast)
        echo "Running: Fast tests (skip slow AI + full flow)"
        python3 -m pytest \
            tests/e2e/test_01_connectivity.py \
            tests/e2e/test_02_elasticsearch.py \
            tests/e2e/test_03_opensoar_api.py \
            tests/e2e/test_04_pipeline_cycle.py \
            -v
        ;;
    all|*)
        echo "Running: All E2E tests (this may take 5-10 minutes)"
        python3 -m pytest tests/e2e/ -v
        ;;
esac
