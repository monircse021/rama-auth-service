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
import com.sun.net.httpserver.HttpServer;

import java.net.InetSocketAddress;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;

public class HttpMain {

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

        try (InProcessCluster cluster = InProcessCluster.create()) {
            cluster.launchModule(new AuthModule(), new LaunchConfig(1, 1));
            System.out.println("AuthModule launched.");

            // Depots
            Depot reg  = cluster.clusterDepot(AuthModule.class.getName(), "*registration_cmds");
            Depot auth = cluster.clusterDepot(AuthModule.class.getName(), "*auth_events");

            // Queries
            QueryTopologyClient<Object> qCanRegister   = cluster.clusterQuery(AuthModule.class.getName(), "canRegister");
            QueryTopologyClient<Object> qUidByEmail    = cluster.clusterQuery(AuthModule.class.getName(), "getUserIdByEmail");
            QueryTopologyClient<Object> qUidByUsername = cluster.clusterQuery(AuthModule.class.getName(), "getUserIdByUsername");
            QueryTopologyClient<Object> qCredForUser   = cluster.clusterQuery(AuthModule.class.getName(), "getCredForUser");
            QueryTopologyClient<Object> qValidateRef   = cluster.clusterQuery(AuthModule.class.getName(), "validateRefresh");
            QueryTopologyClient<Object> qUserById      = cluster.clusterQuery(AuthModule.class.getName(), "getUserById");

            // Handlers
            RegisterHandler register = new RegisterHandler(reg, qCanRegister, qUidByUsername);
            LoginHandler    login    = new LoginHandler(secret, auth, qUidByUsername, qCredForUser, ACCESS_TTL_MS, REFRESH_TTL_MS);
            TokenHandler    token    = new TokenHandler(secret, auth, qValidateRef, ACCESS_TTL_MS, REFRESH_TTL_MS);
            UserHandler     user     = new UserHandler(reg, qUidByEmail, qUserById, secret);

            // HTTP server / routes
            HttpServer http = HttpServer.create(new InetSocketAddress(port), 0);
            http.setExecutor(Executors.newCachedThreadPool());

            // Preflight
            http.createContext("/api/", ex -> {
                if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
                    ResponseUtil.handleOptions(ex);
                } else {
                    ResponseUtil.respond(ex, 404, Map.of("error", "Not Found"));
                }
            });

            http.createContext("/api/register", ex -> ResponseUtil.handlePost(ex, in -> register.handle(in)));
            http.createContext("/api/login",    ex -> ResponseUtil.handlePost(ex, in -> login.handle(in)));
            http.createContext("/api/token/refresh", ex -> ResponseUtil.handlePost(ex, in -> token.refresh(in)));
            http.createContext("/api/logout",   ex -> ResponseUtil.handlePost(ex, in -> token.logout(in)));
            http.createContext("/api/user/update", ex -> ResponseUtil.handlePost(ex, in -> user.update(in)));
            http.createContext("/api/me", user::me); // GET + Bearer

            http.start();
            System.out.println("HTTP listening on http://localhost:" + port + "  (Ctrl+C to stop)");
            new CountDownLatch(1).await();
        }
    }

    private static int parseIntEnv(String k, int def){
        try{
            String v = System.getenv(k);
            return v==null? def : Integer.parseInt(v.trim());
        }catch(Exception e){
            return def;
        }
    }
}
