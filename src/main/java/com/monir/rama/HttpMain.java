package com.monir.rama;

import com.monir.rama.handler.LoginHandler;
import com.monir.rama.handler.RegisterHandler;
import com.monir.rama.handler.TokenHandler;
import com.monir.rama.handler.UserHandler;
import com.monir.rama.util.ResponseUtil;
import com.rpl.rama.Depot;
import com.rpl.rama.QueryTopologyClient;
import com.rpl.rama.test.InProcessCluster;
import com.rpl.rama.test.LaunchConfig;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class HttpMain {
    private static final Logger log = LoggerFactory.getLogger(HttpMain.class);

    public static void main(String[] args) throws Exception {
        // --- env ---
        String secret = System.getenv("JWT_SECRET");
        if (secret == null || secret.isBlank()) {
            System.err.println("ERROR: JWT_SECRET env var is required.");
            System.exit(2);
        }
        int accessTtlMin   = parseIntEnv("ACCESS_TTL_MIN", 10);
        int refreshTtlDays = parseIntEnv("REFRESH_TTL_DAYS", 7);
        int port           = parseIntEnv("PORT", 8080);

        long ACCESS_TTL_MS  = Duration.ofMinutes(accessTtlMin).toMillis();
        long REFRESH_TTL_MS = Duration.ofDays(refreshTtlDays).toMillis();

        log.info("Starting rama-auth-service...");
        log.info("HTTP port={}  ACCESS_TTL_MIN={}  REFRESH_TTL_DAYS={}", port, accessTtlMin, refreshTtlDays);

        try (InProcessCluster cluster = InProcessCluster.create()) {
            log.info("Launching Rama module: {}", AuthModule.class.getName());
            long t0 = System.nanoTime();
            cluster.launchModule(new AuthModule(), new LaunchConfig(1, 1));
            log.info("AuthModule launched in {} ms",
                    TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0));

            // Depots
            Depot reg  = cluster.clusterDepot(AuthModule.class.getName(), "*registration_cmds");
            Depot auth = cluster.clusterDepot(AuthModule.class.getName(), "*auth_events");
            log.debug("Depots ready: registration_cmds={}, auth_events={}", reg, auth);

            // Queries
            QueryTopologyClient<Object> qCanRegister   = cluster.clusterQuery(AuthModule.class.getName(), "canRegister");
            QueryTopologyClient<Object> qUidByEmail    = cluster.clusterQuery(AuthModule.class.getName(), "getUserIdByEmail");
            QueryTopologyClient<Object> qUidByUsername = cluster.clusterQuery(AuthModule.class.getName(), "getUserIdByUsername");
            QueryTopologyClient<Object> qCredForUser   = cluster.clusterQuery(AuthModule.class.getName(), "getCredForUser");
            QueryTopologyClient<Object> qValidateRef   = cluster.clusterQuery(AuthModule.class.getName(), "validateRefresh");
            QueryTopologyClient<Object> qUserById      = cluster.clusterQuery(AuthModule.class.getName(), "getUserById");
            log.debug("Queries ready: canRegister/getUserIdByEmail/getUserIdByUsername/getCredForUser/validateRefresh/getUserById");

            // Handlers
            RegisterHandler register = new RegisterHandler(reg, qCanRegister, qUidByUsername);
            LoginHandler    login    = new LoginHandler(secret, auth, qUidByUsername, qCredForUser, ACCESS_TTL_MS, REFRESH_TTL_MS);
            TokenHandler    token    = new TokenHandler(secret, auth, qValidateRef, ACCESS_TTL_MS, REFRESH_TTL_MS);
            UserHandler     user     = new UserHandler(reg, qUidByEmail, qUserById, secret);
            log.info("Handlers constructed.");

            // HTTP server / routes
            HttpServer http = HttpServer.create(new InetSocketAddress(port), 0);
            http.setExecutor(Executors.newCachedThreadPool());
            log.info("HttpServer created and executor set.");

            // Preflight + catch-all under /api/
            http.createContext("/api/", withLogging("/api/*", ex -> {
                if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                    log.debug("Preflight OPTIONS for {}", ex.getRequestURI());
                    ResponseUtil.handleOptions(ex);
                } else {
                    log.warn("No route matched: {} {}", ex.getRequestMethod(), ex.getRequestURI());
                    ResponseUtil.respond(ex, 404, Map.of("error", "Not Found"));
                }
            }));

            // Routes
            http.createContext("/api/register",
                    withLogging("POST /api/register", ex -> ResponseUtil.handlePost(ex, register::handle)));

            http.createContext("/api/login",
                    withLogging("POST /api/login", ex -> ResponseUtil.handlePost(ex, login::handle)));

            http.createContext("/api/token/refresh",
                    withLogging("POST /api/token/refresh", ex -> ResponseUtil.handlePost(ex, token::refresh)));

            http.createContext("/api/logout",
                    withLogging("POST /api/logout", ex -> ResponseUtil.handlePost(ex, token::logout)));

            http.createContext("/api/user/update",
                    withLogging("POST /api/user/update", ex -> ResponseUtil.handlePost(ex, user::update)));

            // GET + Bearer
            http.createContext("/api/me",
                    withLogging("GET /api/me", user::me));

            // Start
            http.start();
            log.info("HTTP listening on http://localhost:{}  (Ctrl+C to stop)", port);
            new CountDownLatch(1).await();
        } catch (Throwable t) {
            log.error("Fatal error in HttpMain: {}", t.toString(), t);
            throw t;
        }
    }

    /**
     * Wrap an HttpHandler with rich request logging:
     * - Generates request id (rid) and adds to MDC
     * - Logs method, path, remote, start/end, duration
     * - Catches unexpected errors and returns 500 if needed
     */
    private static HttpHandler withLogging(String routeName, HttpHandler inner) {
        return ex -> {
            String rid = UUID.randomUUID().toString().substring(0, 8);
            MDC.put("rid", rid);
            String method = safe(() -> ex.getRequestMethod(), "?");
            String path   = safe(() -> ex.getRequestURI().toString(), "?");
            String remote = safe(() -> String.valueOf(ex.getRemoteAddress()), "?");

            long t0 = System.nanoTime();
            log.info("→ {} | {} {} | from={}", routeName, method, path, remote);
            log.debug("Headers (masked): {}", maskAuthHeader(ex));
            try {
                inner.handle(ex);
                long ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
                log.info("← {} | {} {} | took={}ms", routeName, method, path, ms);
            } catch (Exception e) {
                long ms = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - t0);
                log.error("✖ {} | {} {} | took={}ms | error={}", routeName, method, path, ms, e.toString(), e);
                // Best-effort send 500 if handler didn’t already write a response
                try { ResponseUtil.respond(ex, 500, Map.of("error", "internal")); } catch (Exception ignore) {}
            } finally {
                MDC.clear();
            }
        };
    }

    // Mask Authorization header in logs
    private static String maskAuthHeader(HttpExchange ex) {
        try {
            var h = ex.getRequestHeaders();
            if (h == null) return "{}";
            var copy = new java.util.TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            h.forEach((k, v) -> {
                if ("Authorization".equalsIgnoreCase(k)) copy.put(k, java.util.List.of("***"));
                else copy.put(k, v);
            });
            return copy.toString();
        } catch (Exception ignore) {
            return "{}";
        }
    }

    private static <T> T safe(java.util.concurrent.Callable<T> c, T def){
        try { return c.call(); } catch (Exception e) { return def; }
    }

    private static int parseIntEnv(String k, int def){
        try{
            String v = System.getenv(k);
            int val = (v==null? def : Integer.parseInt(v.trim()));
            log.debug("ENV {}={}", k, (k.contains("SECRET") ? "***" : val));
            return val;
        }catch(Exception e){
            log.warn("ENV {} parse failed ({}). Using default={}", k, e.toString(), def);
            return def;
        }
    }
}