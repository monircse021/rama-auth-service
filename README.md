# Rama Auth Service (Rama 1.1.0, JDK 17)

Minimal JWT-based auth service built on **Rama 1.1.0** using the Java API.

- Register (fullName, email, username, mobile, password) → **201** `{status,userId,fullName}`
- Login (username, password) → **200** `{status, userId, username, accessToken, refreshToken}`
- Refresh → **200** `{status, userId, username, accessToken, refreshToken}`
- Update user (email/fullName/mobile) → **200** `{status: "updated"}`
- Logout → **200** `{status: "logged_out"}`

It supports:
- ✅ User Registration
- ✅ Login (with JWT access/refresh tokens)
- ✅ Token Refresh
- ✅ User Update
- ✅ Logout
- ✅ Get Current User (via access token)

---

## 🚀 Build

```bash
mvn -DskipTests clean package
```

---

## ▶️ Run

```bash
export JWT_SECRET="dhjvbfhjdbvjfdhbjgrjbgmonirdsbvjdfvfd021djhbhjhfbgnvndf001ndjdg"
export ACCESS_TTL_MIN=10
export REFRESH_TTL_DAYS=7
export PORT=8080

java -jar target/auth-service-jar-with-dependencies.jar
```

Server starts at:
```
http://localhost:8080
```

---

## 📌 API Endpoints

> Unless otherwise shown, all requests and responses are JSON.  
> For protected endpoints, include `Authorization: Bearer <ACCESS_TOKEN>`.

### 1) Register
**POST** `/api/register`

```bash
curl -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{
    "fullName":"Md Manirul Islam",
    "email":"monircse021@gmail.com",
    "username":"monircse021",
    "mobileNumber":"+8801XXXXXXXXX",
    "password":"secret"
  }'
```

**✅ Success (200)**
```json
{
  "status": "created",
  "userId": "...",
  "fullName": "Md Manirul Islam"
}
```

**❌ Conflict (409)**
```json
{"error":"Email or username already taken"}
```

**❌ Bad Request (400)** – missing fields
```json
{"error":"email is required"}
```

---

### 2) Login
**POST** `/api/login`

```bash
curl -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{
    "username":"monircse021",
    "password":"secret"
  }'
```

**✅ Success (200)**
```json
{
  "status": "ok",
  "userId": "...",
  "username": "monircse021",
  "accessToken": "<JWT_ACCESS>",
  "refreshToken": "<JWT_REFRESH>"
}
```

**❌ Unauthorized (401)**
```json
{"error":"Invalid username or password"}
```

---

### 3) Refresh Token
**POST** `/api/token/refresh`

```bash
curl -X POST http://localhost:8080/api/token/refresh \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken":"<JWT_REFRESH>",
    "username":"monircse021"
  }'
```

**✅ Success (200)**
```json
{
  "status": "ok",
  "userId": "...",
  "username": "monircse021",
  "accessToken": "<NEW_JWT_ACCESS>",
  "refreshToken": "<NEW_JWT_REFRESH>"
}
```

**❌ Unauthorized (401)**
```json
{"error":"Invalid or expired refresh token"}
```

---

### 4) Update User
**POST** `/api/user/update`

```bash
curl -X POST http://localhost:8080/api/user/update \
  -H "Content-Type: application/json" \
  -d '{
    "userId":"<USER_ID>",
    "fullName":"Md M. Islam",
    "email":"monircse021@gmail.com",
    "mobileNumber":"+8801YYYYYYYY"
  }'
```

**✅ Success (200)**
```json
{"status":"updated"}
```

**❌ Conflict (409)**
```json
{"error":"Email already in use"}
```

**❌ Bad Request (400)**
```json
{"error":"userId is required"}
```

---

### 5) Logout
**POST** `/api/logout`

```bash
curl -X POST http://localhost:8080/api/logout \
  -H "Content-Type: application/json" \
  -d '{
    "refreshToken":"<JWT_REFRESH>"
  }'
```

**✅ Success (200)**
```json
{"status":"logged_out"}
```

**❌ Bad Request (400)**
```json
{"error":"refreshToken is required"}
```

---

### 6) Get Current User (Protected)
**GET** `/api/me`

```bash
curl -X GET http://localhost:8080/api/me \
  -H "Authorization: Bearer <JWT_ACCESS>" \
  -H "Content-Type: application/json"
```

**✅ Success (200)**
```json
{
  "status": "ok",
  "user": {
    "userId": "...",
    "username": "monircse021",
    "email": "monircse021@gmail.com",
    "fullName": "Md Manirul Islam",
    "mobileNumber": "+8801XXXXXXXXX",
    "status": "active",
    "createdAt": 1723900000000,
    "updatedAt": 1723900000000
  }
}
```

**❌ Unauthorized (401)** – missing/invalid/expired access token
```json
{"error":"Invalid token"}
```

**❌ Not Found (404)** – user not found
```json
{"error":"User not found"}
```

---

## ⚡ Quick End-to-End Test

```bash
# 1) Register
curl -s -X POST http://localhost:8080/api/register \
  -H "Content-Type: application/json" \
  -d '{"fullName":"Alice","email":"alice@example.com","username":"alice","mobileNumber":"+88017777777","password":"secret"}'

# 2) Login (capture tokens)
LOGIN_JSON=$(curl -s -X POST http://localhost:8080/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"secret"}')

ACCESS=$(echo "$LOGIN_JSON" | python - <<'PY'
import sys, json
print(json.load(sys.stdin).get("accessToken",""))
PY
)

REFRESH=$(echo "$LOGIN_JSON" | python - <<'PY'
import sys, json
print(json.load(sys.stdin).get("refreshToken",""))
PY
)

echo "ACCESS=$ACCESS"
echo "REFRESH=$REFRESH"

# 3) Hit protected endpoint /api/me
curl -s -X GET http://localhost:8080/api/me \
  -H "Authorization: Bearer $ACCESS" \
  -H "Content-Type: application/json"

# 4) Refresh tokens
curl -s -X POST http://localhost:8080/api/token/refresh \
  -H "Content-Type: application/json" \
  -d "{\"refreshToken\":\"$REFRESH\",\"username\":\"alice\"}"
```

---

## 🛠️ Troubleshooting

- **409 Conflict on Register/Update**  
  Email or username already exists in the system.

- **401 Unauthorized on Login**  
  Username not found or password hash mismatch.

- **401 on /api/me**  
  Access token missing/invalid/expired. Log in again or refresh the token.

- **404 on /api/me**  
  Token is valid but user record not found (unlikely unless data was pruned).

---

## 📎 Notes
- The service uses **Rama InProcessCluster** for quick local runs.
