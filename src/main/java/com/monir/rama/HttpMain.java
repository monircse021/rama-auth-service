package com.monir.rama;

import com.monir.rama.util.Json;
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
        try (InProcessCluster cluster = InProcessCluster.create()) {
            cluster.launchModule(new AuthModule(), new LaunchConfig(1, 1));
            System.out.println("AuthModule launched on InProcessCluster.");

            // Depots
            Depot reg  = cluster.clusterDepot(AuthModule.class.getName(), "*registration_cmds");
            Depot auth = cluster.clusterDepot(AuthModule.class.getName(), "*auth_events");

            // Query clients (reuse these)
            QueryTopologyClient<Object> qCanRegister   =
                    cluster.clusterQuery(AuthModule.class.getName(), "canRegister");
            QueryTopologyClient<Object> qUserIdByEmail =
                    cluster.clusterQuery(AuthModule.class.getName(), "getUserIdByEmail");
            QueryTopologyClient<Object> qCheckOtp      =
                    cluster.clusterQuery(AuthModule.class.getName(), "checkOtp");
            QueryTopologyClient<Object> qCheckSession  =
                    cluster.clusterQuery(AuthModule.class.getName(), "checkSession");

            HttpServer http = HttpServer.create(new InetSocketAddress(8080), 0);
            http.setExecutor(Executors.newCachedThreadPool());

            // -------- Commands --------

            // POST /api/register  {email, name}
            http.createContext("/api/register", ex -> handlePost(ex, in -> {
                String email = norm(str(in.get("email")));
                String name  = str(in.get("name"));
                require(nonEmpty(email), "email is required");
                require(nonEmpty(name),  "name is required");

                Map<String,Object> evt = new HashMap<>();
                evt.put("type","RegisterRequested");
                evt.put("requestId", UUID.randomUUID().toString());
                evt.put("email", email);
                evt.put("name",  name);
                reg.append(evt); // HashMap avoids JDK MapN serialization issues

                // Poll for userId briefly so client can get it back if ready
                Object userId = waitFor(Duration.ofSeconds(3),
                        () -> qUserIdByEmail.invoke(email));

                if (userId != null) return Map.of("status","created","userId",userId);
                return Map.of("status","accepted");
            }));

            // POST /api/verify-email  {userId}
            http.createContext("/api/verify-email", ex -> handlePost(ex, in -> {
                String uid = str(in.get("userId"));
                require(nonEmpty(uid), "userId is required");
                Map<String,Object> evt = new HashMap<>();
                evt.put("type","EmailVerified");
                evt.put("userId", uid);
                reg.append(evt);
                return Map.of("status","accepted");
            }));

            // POST /api/password  {userId, hash, algo, salt?, params?}
            http.createContext("/api/password", ex -> handlePost(ex, in -> {
                String uid  = str(in.get("userId"));
                require(nonEmpty(uid), "userId is required");
                require(in.containsKey("hash"), "hash is required");
                require(in.containsKey("algo"), "algo is required");

                Map<String,Object> evt = new HashMap<>();
                evt.put("type","SetPasswordHash");
                evt.put("userId", uid);
                evt.put("hash", in.get("hash"));
                evt.put("algo", in.get("algo"));
                evt.put("salt", in.get("salt"));
                evt.put("params", in.get("params"));
                reg.append(evt);
                return Map.of("status","accepted");
            }));

            // POST /api/login-failed  {principal, ip}
            http.createContext("/api/login-failed", ex -> handlePost(ex, in -> {
                String principal = str(in.get("principal"));
                String ip        = str(in.get("ip"));
                require(nonEmpty(principal), "principal is required");
                require(nonEmpty(ip),        "ip is required");

                Map<String,Object> evt = new HashMap<>();
                evt.put("type","LoginFailed");
                evt.put("principal", principal);
                evt.put("ip", ip);
                auth.append(evt);
                return Map.of("status","accepted");
            }));

            // POST /api/session  {userId, device, ip}
            http.createContext("/api/session", ex -> handlePost(ex, in -> {
                String uid = str(in.get("userId"));
                String dev = str(in.get("device"));
                String ip  = str(in.get("ip"));
                require(nonEmpty(uid), "userId is required");
                require(nonEmpty(dev), "device is required");
                require(nonEmpty(ip),  "ip is required");

                Map<String,Object> evt = new HashMap<>();
                evt.put("type","SessionRequested");
                evt.put("userId", uid);
                evt.put("device", dev);
                evt.put("ip", ip);
                auth.append(evt);
                return Map.of("status","accepted");
            }));

            // POST /api/logout  {sessionId}
            http.createContext("/api/logout", ex -> handlePost(ex, in -> {
                String sid = str(in.get("sessionId"));
                require(nonEmpty(sid), "sessionId is required");

                Map<String,Object> evt = new HashMap<>();
                evt.put("type","LogoutRequested");
                evt.put("sessionId", sid);
                auth.append(evt);
                return Map.of("status","accepted");
            }));

            // -------- Queries --------

            // GET /api/can-register?email=...
            http.createContext("/api/can-register", ex -> handleGet(ex, params -> {
                String email = norm(params.getOrDefault("email",""));
                require(nonEmpty(email), "email is required");
                Boolean ok = (Boolean) qCanRegister.invoke(email);
                return Map.of("ok", ok);
            }));

            // GET /api/user-id?email=...
            http.createContext("/api/user-id", ex -> handleGet(ex, params -> {
                String email = norm(params.getOrDefault("email",""));
                require(nonEmpty(email), "email is required");
                Object userId = qUserIdByEmail.invoke(email);
                return Map.of("userId", userId);
            }));

            // POST /api/otp/check  {userId, otp}
            http.createContext("/api/otp/check", ex -> handlePost(ex, in -> {
                String uid = str(in.get("userId"));
                String otp = str(in.get("otp"));
                require(nonEmpty(uid), "userId is required");
                require(nonEmpty(otp), "otp is required");
                Boolean ok = (Boolean) qCheckOtp.invoke(uid, otp);
                return Map.of("ok", ok);
            }));

            // GET /api/session/get?sessionId=...
            http.createContext("/api/session/get", ex -> handleGet(ex, params -> {
                String sid = params.getOrDefault("sessionId", "");
                require(nonEmpty(sid), "sessionId is required");
                Object sess = qCheckSession.invoke(sid);
                return Map.of("session", sess);
            }));

            http.start();
            System.out.println("HTTP listening on http://localhost:8080  (Ctrl+C to stop)");
            new CountDownLatch(1).await();
        }
    }

    // ---------- helpers ----------
    private static String str(Object o) { return o == null ? null : String.valueOf(o); }
    private static boolean nonEmpty(String s) { return s != null && !s.isBlank(); }
    private static String norm(String s) { return s == null ? null : s.trim().toLowerCase(Locale.ROOT); }

    @FunctionalInterface interface BodyHandler { Map<String,Object> handle(Map<String,Object> in) throws Exception; }
    @FunctionalInterface interface QueryHandler { Map<String,Object> handle(Map<String,String> params) throws Exception; }

    private static void handlePost(HttpExchange ex, BodyHandler fn) throws IOException {
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) { methodNotAllowed(ex, "POST"); return; }
        try {
            Map<String,Object> in = Json.readMap(ex.getRequestBody());
            Map<String,Object> out = fn.handle(in);
            respond(ex, 200, out);
        } catch (BadReq br) {
            respond(ex, 400, Map.of("error", br.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            respond(ex, 500, Map.of("error", e.toString()));
        }
    }

    private static void handleGet(HttpExchange ex, QueryHandler fn) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) { methodNotAllowed(ex, "GET"); return; }
        try {
            Map<String,String> q = parseQuery(ex.getRequestURI().getQuery());
            Map<String,Object> out = fn.handle(q);
            respond(ex, 200, out);
        } catch (BadReq br) {
            respond(ex, 400, Map.of("error", br.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            respond(ex, 500, Map.of("error", e.toString()));
        }
    }

    private static void respond(HttpExchange ex, int status, Object body) throws IOException {
        byte[] bytes;
        try { bytes = Json.M.writeValueAsBytes(body); }
        catch (Exception e) { bytes = ("{\"error\":\"" + e.getMessage() + "\"}").getBytes(StandardCharsets.UTF_8); status = 500; }
        ex.getResponseHeaders().set("Content-Type", "application/json");
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    private static void methodNotAllowed(HttpExchange ex, String expected) throws IOException {
        respond(ex, 405, Map.of("error","Use " + expected));
    }

    private static Map<String,String> parseQuery(String q) {
        Map<String,String> out = new HashMap<>();
        if (q == null || q.isBlank()) return out;
        for (String p : q.split("&")) {
            int i = p.indexOf('=');
            if (i > 0) out.put(urlDecode(p.substring(0,i)), urlDecode(p.substring(i+1)));
        }
        return out;
    }

    private static String urlDecode(String s) {
        return java.net.URLDecoder.decode(s, StandardCharsets.UTF_8);
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

    private static class BadReq extends RuntimeException { BadReq(String m) { super(m); } }
    private static void require(boolean ok, String msg) { if (!ok) throw new BadReq(msg); }
}