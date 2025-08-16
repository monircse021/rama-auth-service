# auth-service (Rama 1.1.0, JDK 17)

Minimal Rama module for auth:
- Register with `fullName`, `email`, `username`, `mobileNumber`, `password` (SHA-256)
- JWT access (10 minutes) + refresh
- Login, update user, logout
- Refresh endpoint
- Env vars for secrets/TTL/port

## Build
```bash
mvn -DskipTests clean package
```

## Run
```bash
export JWT_SECRET="dhjvbfhjdbvjfdhbjgrjbgmonirdsbvjdfvfd021djhbhjhfbgnvndf001ndjdg"
export ACCESS_TTL_MIN=10
export REFRESH_TTL_DAYS=7
export PORT=8080

java -jar target/auth-service-jar-with-dependencies.jar
```

## API

### Register
POST `/api/register`
```json
{
  "fullName":"Alice Smith",
  "email":"alice@example.com",
  "username":"alice",
  "mobileNumber":"+8801XXXXXXXXX",
  "password":"secret"
}
```
Response (on success):
```json
{
  "status":"created",
  "userId":"...",
  "username":"alice",
  "accessToken":"...",
  "refreshToken":"..."
}
```

### Login
POST `/api/login`
```json
{"username":"alice","password":"secret"}
```
Response:
```json
{"status":"ok","userId":"...","username":"alice","accessToken":"...","refreshToken":"..."}
```

### Refresh
POST `/api/token/refresh`
```json
{"refreshToken":"<token>","username":"alice"}
```
Response:
```json
{"status":"ok","userId":"...","username":"alice","accessToken":"...","refreshToken":"..."}
```

### Update user
POST `/api/user/update`
```json
{"userId":"...","fullName":"Alice B. Smith","email":"alice2@example.com","mobileNumber":"+8801YYYYYYYY"}
```
Response:
```json
{"status":"updated"}
```

### Logout
POST `/api/logout`
```json
{"refreshToken":"<token>"}
```
Response:
```json
{"status":"logged_out"}
```
