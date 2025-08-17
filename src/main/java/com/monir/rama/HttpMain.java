package com.monir.rama;

import com.monir.rama.util.AuthFns;
import com.monir.rama.util.Json;
import com.monir.rama.util.Jwt;
import com.rpl.rama.Depot;
import com.rpl.rama.QueryTopologyClient;
import com.rpl.rama.test.InProcessCluster;
import com.rpl.rama.test.LaunchConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.*;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

public class HttpMain {

    public static void main(String[] args) throws Exception {
        // ====== Load Environment Variables ======
        String secret = System.getenv("JWT_SECRET");
        if (secret == null || secret.isBlank()) {
            System.err.println("ERROR: JWT_SECRET env var is required.");
            System.exit(2);
        }
        int accessTtlMin = parseIntEnv("ACCESS_TTL_MIN", 10);  // default: 10 minutes
        int refreshTtlDays = parseIntEnv("REFRESH_TTL_DAYS", 7); // default: 7 days
        int port = parseIntEnv("PORT", 8080); // default: 8080

        long ACCESS_TTL_MS = Duration.ofMinutes(accessTtlMin).toMillis();
        long REFRESH_TTL_MS = Duration.ofDays(refreshTtlDays).toMillis();

        try (InProcessCluster cluster = InProcessCluster.create()) {
            cluster.launchModule(new AuthModule(), new LaunchConfig(1, 1));
            System.out.println("AuthModule launched on InProcessCluster.");

            Depot reg  = cluster.clusterDepot(AuthModule.class.getName(), "*registration_cmds");
            Depot auth = cluster.clusterDepot(AuthModule.class.getName(), "*auth_events");

            QueryTopologyClient<Object> qCanRegister   = cluster.clusterQuery(AuthModule.class.getName(), "canRegister");
            QueryTopologyClient<Object> qUidByEmail    = cluster.clusterQuery(AuthModule.class.getName(), "getUserIdByEmail");
            QueryTopologyClient<Object> qUidByUsername = cluster.clusterQuery(AuthModule.class.getName(), "getUserIdByUsername");
            QueryTopologyClient<Object> qCredForUser   = cluster.clusterQuery(AuthModule.class.getName(), "getCredForUser");
            QueryTopologyClient<Object> qValidateRef   = cluster.clusterQuery(AuthModule.class.getName(), "validateRefresh");

            HttpServer http = HttpServer.create(new InetSocketAddress(port), 0);
            http.setExecutor(Executors.newCachedThreadPool());

            // --------------------------
            // Register
            // --------------------------
            http.createContext("/api/register", ex -> handlePost(ex, in -> {
                String fullName = str(in.get("fullName"));
                String email    = str(in.get("email"));
                String username = str(in.get("username"));
                String mobile   = str(in.get("mobileNumber"));
                String password = str(in.get("password"));

                require(nonEmpty(email), "email is required");
                require(nonEmpty(username), "username is required");
                require(nonEmpty(password), "password is required");

                String emailLower = AuthFns.lowerTrim(email);
                String userLower  = AuthFns.lowerTrim(username);

                Boolean ok = (Boolean) qCanRegister.invoke(emailLower, userLower);
                if (ok == null || !ok) {
                    return Map.of("status", "conflict", "error", "Email or username already taken");
                }

                String pwdHash = AuthFns.sha256Hex(password);

                Map<String,Object> evt = new HashMap<>();
                evt.put("type","RegisterRequested");
                evt.put("fullName", fullName);
                evt.put("email", email);
                evt.put("emailLower", emailLower);
                evt.put("username", username);
                evt.put("usernameLower", userLower);
                evt.put("mobileNumber", mobile);
                evt.put("pwdHash", pwdHash);
                reg.append(evt);

                Object userId = waitFor(Duration.ofSeconds(5),
                        () -> qUidByUsername.invoke(userLower));

                if (userId == null) {
                    return Map.of("status","accepted");
                }

                return Map.of("status","created","userId", userId,"fullName", fullName);
            }));

            // --------------------------
            // Login
            // --------------------------
            http.createContext("/api/login", ex -> handlePost(ex, in -> {
                String username = str(in.get("username"));
                String password = str(in.get("password"));
                require(nonEmpty(username), "username is required");
                require(nonEmpty(password), "password is required");

                String userLower  = AuthFns.lowerTrim(username);
                Object userId = qUidByUsername.invoke(userLower);
                if (userId == null) return unauthorized("Invalid username or password");

                Map cred = (Map) qCredForUser.invoke(userId);
                if (cred == null) return unauthorized("Invalid username or password");

                String stored = String.valueOf(cred.get("hash"));
                String cand   = AuthFns.sha256Hex(password);
                if (!Objects.equals(stored, cand)) return unauthorized("Invalid username or password");

                String access = createAccessToken(secret, (String)userId, username, ACCESS_TTL_MS);
                String refresh = createRefreshToken(secret, (String)userId, username, REFRESH_TTL_MS);

                long expMillis = System.currentTimeMillis() + REFRESH_TTL_MS;
                Map<String,Object> tokEvt = new HashMap<>();
                tokEvt.put("type","RefreshTokenUpsert");
                tokEvt.put("token", refresh);
                tokEvt.put("userId", userId);
                tokEvt.put("expMillis", expMillis);
                auth.append(tokEvt);

                return Map.of(
                        "status","ok",
                        "userId", userId,
                        "username", username,
                        "accessToken", access,
                        "refreshToken", refresh
                );
            }));

            // --------------------------
            // Refresh Token
            // --------------------------
            http.createContext("/api/token/refresh", ex -> handlePost(ex, in -> {
                String refresh = str(in.get("refreshToken"));
                require(nonEmpty(refresh), "refreshToken is required");

                Object userId = qValidateRef.invoke(refresh);
                if (userId == null) return unauthorized("Invalid or expired refresh token");

                String username = str(in.get("username"));
                if (username == null) username = "user";

                Map<String,Object> revoke = new HashMap<>();
                revoke.put("type","RefreshTokenRevoke");
                revoke.put("token", refresh);
                auth.append(revoke);

                String newRefresh = createRefreshToken(secret, (String)userId, username, REFRESH_TTL_MS);
                long expMillis = System.currentTimeMillis() + REFRESH_TTL_MS;

                Map<String,Object> upsert = new HashMap<>();
                upsert.put("type","RefreshTokenUpsert");
                upsert.put("token", newRefresh);
                upsert.put("userId", userId);
                upsert.put("expMillis", expMillis);
                auth.append(upsert);

                String access = createAccessToken(secret, (String)userId, username, ACCESS_TTL_MS);

                return Map.of(
                        "status","ok",
                        "userId", userId,
                        "username", username,
                        "accessToken", access,
                        "refreshToken", newRefresh
                );
            }));

            // --------------------------
            // Update User
            // --------------------------
            http.createContext("/api/user/update", ex -> handlePost(ex, in -> {
                String uid      = str(in.get("userId"));
                String fullName = str(in.getOrDefault("fullName", null));
                String email    = str(in.getOrDefault("email", null));
                String mobile   = str(in.getOrDefault("mobileNumber", null));
                require(nonEmpty(uid), "userId is required");

                if (email != null) {
                    String emailLower = AuthFns.lowerTrim(email);
                    Object existing = qUidByEmail.invoke(emailLower);
                    if (existing != null && !Objects.equals(existing, uid)) {
                        return Map.of("status","conflict","error","Email already in use");
                    }
                }

                Map<String,Object> evt = new HashMap<>();
                evt.put("type","UserUpdated");
                evt.put("userId", uid);
                if (fullName != null) evt.put("fullName", fullName);
                if (mobile != null) evt.put("mobileNumber", mobile);
                if (email != null) evt.put("emailLower", AuthFns.lowerTrim(email));
                reg.append(evt);

                return Map.of("status","updated");
            }));

            // --------------------------
            // Logout
            // --------------------------
            http.createContext("/api/logout", ex -> handlePost(ex, in -> {
                String refresh = str(in.get("refreshToken"));
                require(nonEmpty(refresh), "refreshToken is required");

                Map<String,Object> revoke = new HashMap<>();
                revoke.put("type","RefreshTokenRevoke");
                revoke.put("token", refresh);
                auth.append(revoke);

                return Map.of("status","logged_out");
            }));

            http.start();
            System.out.println("HTTP listening on http://localhost:" + port + "  (Ctrl+C to stop)");
            new CountDownLatch(1).await();
        }
    }

    // ======================================================================
    // Helpers
    // ======================================================================

    private static int parseIntEnv(String k, int def){
        try {
            String v = System.getenv(k);
            return v == null ? def : Integer.parseInt(v.trim());
        } catch(Exception e){ return def; }
    }

    private static String str(Object o) { return o == null ? null : String.valueOf(o); }
    private static boolean nonEmpty(String s) { return s != null && !s.isBlank(); }

    @FunctionalInterface
    interface BodyHandler { Map<String,Object> handle(Map<String,Object> in) throws Exception; }

    /** Handles POST/OPTIONS safely with CORS */
    private static void handlePost(HttpExchange ex, BodyHandler fn) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
            handleOptions(ex);
            return;
        }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { methodNotAllowed(ex, "POST"); return; }
        try {
            Map<String,Object> in = Json.readMap(ex.getRequestBody());
            Map<String,Object> out = fn.handle(in);
            respond(ex, 200, out);
        } catch (BadReq br) {
            respond(ex, 400, Map.of("error", br.getMessage()));
        } catch (Unauthorized u) {
            respond(ex, 401, Map.of("error", u.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            respond(ex, 500, Map.of("error", e.toString()));
        }
    }

    /** Preflight CORS response */
    private static void handleOptions(HttpExchange ex) throws IOException {
        addCors(ex);
        ex.sendResponseHeaders(204, -1); // No body
        ex.close();
    }

    /** JSON + CORS */
    private static void respond(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes;
        try { bytes = Json.M.writeValueAsBytes(body); }
        catch (Exception e) { bytes = ("{\"error\":\"" + e.getMessage() + "\"}").getBytes(StandardCharsets.UTF_8); status = 500; }
        ex.getResponseHeaders().set("Content-Type", "application/json");
        addCors(ex);
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    /** Add common CORS headers */
    private static void addCors(HttpExchange ex) {
        ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        ex.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }

    private static void methodNotAllowed(HttpExchange ex, String expected) throws IOException {
        respond(ex, 405, Map.of("error","Use " + expected));
    }

    private static Object waitFor(Duration timeout, SupplierThrowing<Object> sup) {
        long deadline = System.nanoTime() + timeout.toNanos();
        Object v = sup.get();
        while (v == null && System.nanoTime() < deadline) {
            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            v = sup.get();
        }
        return v;
    }
    @FunctionalInterface interface SupplierThrowing<T> { T get(); }

    private static String createAccessToken(String secret, String userId, String username, long ttlMs){
        long now = System.currentTimeMillis();
        long exp = now + ttlMs;
        Map<String,Object> payload = new LinkedHashMap<>();
        payload.put("sub", userId);
        payload.put("username", username);
        payload.put("type", "access");
        payload.put("iat", now/1000);
        payload.put("exp", exp/1000);
        return Jwt.signHS256(payload, secret);
    }
    private static String createRefreshToken(String secret, String userId, String username, long ttlMs){
        long now = System.currentTimeMillis();
        long exp = now + ttlMs;
        Map<String,Object> payload = new LinkedHashMap<>();
        payload.put("sub", userId);
        payload.put("username", username);
        payload.put("type", "refresh");
        payload.put("jti", UUID.randomUUID().toString().replace("-", ""));
        payload.put("iat", now/1000);
        payload.put("exp", exp/1000);
        return Jwt.signHS256(payload, secret);
    }

    private static Map<String,Object> unauthorized(String msg){
        return Map.of("status","unauthorized","error", msg);
    }

    private static class BadReq extends RuntimeException { BadReq(String m) { super(m); } }
    private static class Unauthorized extends RuntimeException { Unauthorized(String m) { super(m); } }
    private static void require(boolean ok, String msg) { if (!ok) throw new BadReq(msg); }
}