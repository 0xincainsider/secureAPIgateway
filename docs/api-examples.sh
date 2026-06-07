#!/bin/bash
# =============================================================================
# Secure API Gateway - API Usage Examples
# =============================================================================
# This script demonstrates common API operations using curl.
# Assumes the gateway is running at http://localhost:8000
# =============================================================================

BASE_URL="http://localhost:8000/api/v1"
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Secure API Gateway - API Examples${NC}"
echo -e "${BLUE}============================================${NC}"
echo ""

# =============================================================================
# 1. Health Check
# =============================================================================
echo -e "${GREEN}1. Health Check${NC}"
echo "GET /health"
curl -s "${BASE_URL/\/api\/v1}/health" | python3 -m json.tool
echo ""

# =============================================================================
# 2. Register a new user
# =============================================================================
echo -e "${GREEN}2. Register a new user${NC}"
echo "POST /api/v1/auth/register"
curl -s -X POST "${BASE_URL}/auth/register" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john.doe@example.com",
    "username": "johndoe",
    "password": "SecurePass123!",
    "display_name": "John Doe"
  }' | python3 -m json.tool
echo ""

# =============================================================================
# 3. Login (form-encoded - OAuth2 compatible)
# =============================================================================
echo -e "${GREEN}3. Login (OAuth2 Password Flow)${NC}"
echo "POST /api/v1/auth/login"
LOGIN_RESPONSE=$(curl -s -X POST "${BASE_URL}/auth/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=johndoe&password=SecurePass123!")

echo "$LOGIN_RESPONSE" | python3 -m json.tool

# Extract tokens for subsequent requests
ACCESS_TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
REFRESH_TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))" 2>/dev/null)
echo ""

# =============================================================================
# 4. Get current user profile
# =============================================================================
if [ -n "$ACCESS_TOKEN" ]; then
    echo -e "${GREEN}4. Get current user profile${NC}"
    echo "GET /api/v1/auth/me"
    curl -s -X GET "${BASE_URL}/auth/me" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" | python3 -m json.tool
    echo ""
fi

# =============================================================================
# 5. Refresh tokens
# =============================================================================
if [ -n "$REFRESH_TOKEN" ]; then
    echo -e "${GREEN}5. Refresh tokens${NC}"
    echo "POST /api/v1/auth/refresh"
    REFRESH_RESPONSE=$(curl -s -X POST "${BASE_URL}/auth/refresh" \
      -H "Content-Type: application/json" \
      -d "{\"refresh_token\": \"${REFRESH_TOKEN}\"}")
    echo "$REFRESH_RESPONSE" | python3 -m json.tool

    NEW_ACCESS_TOKEN=$(echo "$REFRESH_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token',''))" 2>/dev/null)
    NEW_REFRESH_TOKEN=$(echo "$REFRESH_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('refresh_token',''))" 2>/dev/null)
    echo ""
fi

# =============================================================================
# 6. Logout (revoke current refresh token)
# =============================================================================
if [ -n "$ACCESS_TOKEN" ] && [ -n "$REFRESH_TOKEN" ]; then
    echo -e "${GREEN}6. Logout${NC}"
    echo "POST /api/v1/auth/logout"
    curl -s -X POST "${BASE_URL}/auth/logout" \
      -H "Authorization: Bearer ${ACCESS_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "{\"refresh_token\": \"${REFRESH_TOKEN}\"}" | python3 -m json.tool
    echo ""
fi

# =============================================================================
# 7. Test rate limiting (trigger 429)
# =============================================================================
echo -e "${GREEN}7. Quick sequential requests${NC}"
echo "Making 5 quick requests to demonstrate rate limiting..."
for i in {1..5}; do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" -X POST "${BASE_URL}/auth/login" \
      -d "username=test&password=test")
    echo "  Request $i: HTTP $STATUS"
done
echo ""

# =============================================================================
# 8. Prometheus metrics
# =============================================================================
echo -e "${GREEN}8. Prometheus Metrics${NC}"
echo "GET /metrics"
curl -s "${BASE_URL/\/api\/v1}/metrics" | head -30
echo ""

# =============================================================================
# 9. Access protected endpoint without token (should fail)
# =============================================================================
echo -e "${GREEN}9. Access without token (expected: 401)${NC}"
echo "GET /api/v1/auth/me (no token)"
curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" -X GET "${BASE_URL}/auth/me"
echo ""

# =============================================================================
# 10. API Documentation
# =============================================================================
echo -e "${GREEN}10. API Documentation${NC}"
echo "Swagger UI:  ${BASE_URL}/docs"
echo "ReDoc:       ${BASE_URL}/redoc"
echo "OpenAPI:     ${BASE_URL}/openapi.json"
echo ""

echo -e "${BLUE}============================================${NC}"
echo -e "${BLUE}  Examples Complete${NC}"
echo -e "${BLUE}============================================${NC}"
