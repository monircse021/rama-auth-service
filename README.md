# auth-service (Rama 1.1.0, JDK 17)

Minimal Rama module showing registration + login + logout.

## Build

```bash
mvn -DskipTests clean package
```

This produces `target/auth-service-jar-with-dependencies.jar`.

## Run (local dev)

```bash
java -jar target/auth-service-jar-with-dependencies.jar
```

You should see the module start and a sample `RegisterRequested` appended.
Logs are configured with `src/main/resources/log4j2.properties`.


## API Endpoints & Quick Test (cURL)

### 1️⃣ Register
```bash
curl -X POST http://localhost:8080/api/register   -H "Content-Type: application/json"   -d '{"email":"monircse021@gmail.com","name":"Monir"}'
```

### 2️⃣ Check if can register
```bash
curl -X GET "http://localhost:8080/api/can-register?email=monircse021@gmail.com"
```

### 3️⃣ Get user ID
```bash
curl -X GET "http://localhost:8080/api/user-id?email=monircse021@gmail.com"
```

### 4️⃣ Verify email
```bash
curl -X POST http://localhost:8080/api/verify-email   -H "Content-Type: application/json"   -d '{"userId":"<USER_ID_FROM_PREV_STEP>"}'
```

### 5️⃣ Set password
```bash
curl -X POST http://localhost:8080/api/password   -H "Content-Type: application/json"   -d '{
        "userId":"<USER_ID>",
        "hash":"<your-hash>",
        "algo":"argon2id",
        "salt":"<optional>",
        "params":{"m":65536,"t":3,"p":1}
      }'
```

### 6️⃣ Create session
```bash
curl -X POST http://localhost:8080/api/session   -H "Content-Type: application/json"   -d '{
        "userId":"<USER_ID>",
        "device":"iPhone",
        "ip":"203.0.113.5"
      }'
```

### 7️⃣ Get session
```bash
curl -X GET "http://localhost:8080/api/session/get?sessionId=<SESSION_ID>"
```

### 8️⃣ Logout
```bash
curl -X POST http://localhost:8080/api/logout   -H "Content-Type: application/json"   -d '{"sessionId":"<SESSION_ID>"}'
```
