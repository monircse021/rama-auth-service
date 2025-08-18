# Rama Auth Service (Rama 1.1.0, JDK 17)

Minimal authentication service using Red Planet Labs **Rama 1.1.0** with:
- Register (normalize + SHA-256)
- Login (JWT access + refresh)
- Refresh token rotation
- Update user
- Logout (refresh revoke)
- `/api/me` (reads Bearer access token)

## Build & Run

```bash
export JWT_SECRET=bfhfhjmanha021wheffhjermonir
export ACCESS_TTL_MIN=10
export REFRESH_TTL_DAYS=7
export PORT=8080

mvn -q -DskipTests package
java -jar target/rama-auth-service-1.0.0-SNAPSHOT-shaded.jar
```

## API

- `POST /api/register` → `201 created` or `202 accepted` or `409 conflict`
- `POST /api/login` → `200 ok` with tokens
- `POST /api/token/refresh` → `200 ok` with rotated tokens
- `POST /api/user/update` → `200 updated` or `409 conflict`
- `POST /api/logout` → `204 no content`
- `GET /api/me` (Authorization: Bearer) → `200 ok` user json

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

## Notes

- Uses `InProcessCluster` for dev. Swap to your cluster when ready.
- PStates use `PState.mapSchema` only (Rama 1.1.0 compatible).
- Returns real HTTP codes to simplify frontend error handling.
