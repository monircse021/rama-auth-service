# auth-service (Rama 1.1.0, JDK 17)

JWT authentication with access/refresh tokens: **register, login, refresh, update user, logout**.  
Runs on Rama **InProcessCluster** for easy local dev.

---

## Features
- HS256 JWT access tokens (default **10 min**) + refresh tokens (default **7 days**)
- Enforces unique `email` and `username`
- SHA‑256 password hashing
- Refresh token persistence with expiry & revocation (survives restarts)

---

## Prerequisites
- JDK 17+
- Maven 3.8+

## Configuration (environment variables)
```bash
export JWT_SECRET='super_secret_change_me'    # REQUIRED (use a long, random string in prod)
export ACCESS_TTL_MIN=10                      # optional (default: 10 minutes)
export REFRESH_TTL_DAYS=7                     # optional (default: 7 days)
export PORT=8080                              # optional (default: 8080)
```

## Build & Run
```bash
mvn -DskipTests clean package
java -jar target/auth-service-jar-with-dependencies.jar
# Server: http://localhost:${PORT:-8080}
```

---

## Quick Test (end‑to‑end with token capture)

> Uses `jq` if available (recommended). A minimal `sed` fallback is shown after this block.

```bash
BASE_URL="http://localhost:${PORT:-8080}"

# 1) Register
REGISTER_RES=$(curl -sS -X POST "$BASE_URL/api/register" \
  -H "Content-Type: application/json" \
  -d '{
    "fullName":"Monirul Islam",
    "email":"monir@example.com",
    "username":"monir",
    "mobileNumber":"01700000000",
    "password":"secret123"
  }')
echo "$REGISTER_RES"

# Extract values (jq)
if command -v jq >/dev/null 2>&1; then
  USER_ID=$(echo "$REGISTER_RES" | jq -r .userId)
  ACCESS_TOKEN=$(echo "$REGISTER_RES" | jq -r .accessToken)
  REFRESH_TOKEN=$(echo "$REGISTER_RES" | jq -r .refreshToken)
else
  # sed fallback (very naive)
  USER_ID=$(echo "$REGISTER_RES" | sed -n 's/.*"userId":"\([^"]*\)".*/\1/p')
  ACCESS_TOKEN=$(echo "$REGISTER_RES" | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p')
  REFRESH_TOKEN=$(echo "$REGISTER_RES" | sed -n 's/.*"refreshToken":"\([^"]*\)".*/\1/p')
fi

# 2) Login (optional — shows fresh token issuance)
LOGIN_RES=$(curl -sS -X POST "$BASE_URL/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"monir","password":"secret123"}')
echo "$LOGIN_RES"

if command -v jq >/dev/null 2>&1; then
  USER_ID=$(echo "$LOGIN_RES" | jq -r .userId)
  ACCESS_TOKEN=$(echo "$LOGIN_RES" | jq -r .accessToken)
  REFRESH_TOKEN=$(echo "$LOGIN_RES" | jq -r .refreshToken)
else
  USER_ID=$(echo "$LOGIN_RES" | sed -n 's/.*"userId":"\([^"]*\)".*/\1/p')
  ACCESS_TOKEN=$(echo "$LOGIN_RES" | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p')
  REFRESH_TOKEN=$(echo "$LOGIN_RES" | sed -n 's/.*"refreshToken":"\([^"]*\)".*/\1/p')
fi

# 3) Refresh access/refresh tokens
REFRESH_RES=$(curl -sS -X POST "$BASE_URL/api/token/refresh" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}")
echo "$REFRESH_RES"

if command -v jq >/dev/null 2>&1; then
  ACCESS_TOKEN=$(echo "$REFRESH_RES" | jq -r .accessToken)
  REFRESH_TOKEN=$(echo "$REFRESH_RES" | jq -r .refreshToken)
else
  ACCESS_TOKEN=$(echo "$REFRESH_RES" | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p')
  REFRESH_TOKEN=$(echo "$REFRESH_RES" | sed -n 's/.*"refreshToken":"\([^"]*\)".*/\1/p')
fi

# 4) Update user (requires Bearer access token)
UPDATE_RES=$(curl -sS -X POST "$BASE_URL/api/user/update" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d "{
    \"userId\":\"$USER_ID\",
    \"fullName\":\"New Name\",
    \"email\":\"new@example.com\",
    \"mobileNumber\":\"01800000000\"
  }")
echo "$UPDATE_RES"

# 5) Logout (revokes refresh token)
LOGOUT_RES=$(curl -sS -X POST "$BASE_URL/api/logout" \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH_TOKEN\"}")
echo "$LOGOUT_RES"
```

**Minimal sed-only extraction (if you don’t have jq):**
```bash
USER_ID=$(echo "$REGISTER_RES" | sed -n 's/.*"userId":"\([^"]*\)".*/\1/p')
ACCESS_TOKEN=$(echo "$REGISTER_RES" | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p')
REFRESH_TOKEN=$(echo "$REGISTER_RES" | sed -n 's/.*"refreshToken":"\([^"]*\)".*/\1/p')
```

---

## REST API

### 1) Register
`POST /api/register`

**Request body**
```json
{
  "fullName": "Monirul Islam",
  "email": "monir@example.com",
  "username": "monir",
  "mobileNumber": "017XXXXXXXX",
  "password": "secret123"
}
```
- Required: `email`, `username`, `password`
- Password stored as **SHA‑256** hash
- Ensures unique `email` and `username`

**cURL**
```bash
curl -X POST "http://localhost:${PORT:-8080}/api/register" \
  -H "Content-Type: application/json" \
  -d '{
    "fullName":"Monirul Islam",
    "email":"monir@example.com",
    "username":"monir",
    "mobileNumber":"01700000000",
    "password":"secret123"
  }'
```

**Response (200/201)**
```json
{
  "status": "created",
  "userId": "uuid",
  "username": "monir",
  "accessToken": "...",
  "refreshToken": "..."
}
```

---

### 2) Login
`POST /api/login`

**Request body**
```json
{"username":"monir","password":"secret123"}
```

**cURL**
```bash
curl -X POST "http://localhost:${PORT:-8080}/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"monir","password":"secret123"}'
```

**Response (200)**
```json
{
  "status":"ok",
  "userId":"uuid",
  "username":"monir",
  "accessToken":"...",
  "refreshToken":"..."
}
```
Access token expires in **ACCESS_TTL_MIN** minutes (default 10).

---

### 3) Refresh
`POST /api/token/refresh`

**Request body**
```json
{"refreshToken":"..."}
```

**cURL**
```bash
curl -X POST "http://localhost:${PORT:-8080}/api/token/refresh" \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"REPLACE_WITH_REFRESH"}'
```

**Response (200)**
```json
{
  "status":"ok",
  "userId":"uuid",
  "username":"monir",
  "accessToken":"newAccess",
  "refreshToken":"newRefresh"
}
```

---

### 4) Update user
`POST /api/user/update`

**Request body**
```json
{
  "userId":"uuid",
  "fullName":"New Name",
  "email":"new@example.com",
  "mobileNumber":"018XXXXXXXX"
}
```

**cURL (requires Bearer access token)**
```bash
ACCESS_TOKEN="REPLACE_WITH_ACCESS"
curl -X POST "http://localhost:${PORT:-8080}/api/user/update" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -d '{
    "userId":"REPLACE_USER_ID",
    "fullName":"New Name",
    "email":"new@example.com",
    "mobileNumber":"01800000000"
  }'
```

**Response (200)**
```json
{"status":"updated"}
```

> Changing `email` enforces uniqueness.

---

### 5) Logout
`POST /api/logout`

**Request body**
```json
{"refreshToken":"..."}
```

**cURL**
```bash
curl -X POST "http://localhost:${PORT:-8080}/api/logout" \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"REPLACE_WITH_REFRESH"}'
```

**Response (200)**
```json
{"status":"logged_out"}
```
Revokes the refresh token immediately.

---

## Notes & Security
- All tokens are **HS256** JWT signed with `JWT_SECRET`.
- Use a **strong random** `JWT_SECRET` and **HTTPS** in production.
- Consider small clock‑skew tolerance on token validation if clients’ clocks vary.
- Refresh tokens are persisted in Rama state with expiry and revocation and **survive restarts**.
- This sample is for local dev (InProcessCluster). For production, run a proper Rama cluster and back durable storage per your deployment model.