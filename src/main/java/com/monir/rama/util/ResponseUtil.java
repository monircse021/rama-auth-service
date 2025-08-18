package com.monir.rama.util;

import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.function.Supplier;

public final class ResponseUtil {
    private ResponseUtil(){}

    // Exceptions mapped to HTTP codes
    public static class BadReq extends RuntimeException { public BadReq(String m){ super(m);} }
    public static class Unauthorized extends RuntimeException { public Unauthorized(String m){ super(m);} }
    public static class Conflict extends RuntimeException { public Conflict(String m){ super(m);} }

    public static void handleOptions(HttpExchange ex) throws IOException {
        addCors(ex);
        ex.sendResponseHeaders(204, -1);
        ex.close();
    }

    @FunctionalInterface public interface BodyHandler { Map<String,Object> handle(Map<String,Object> in) throws Exception; }

    public static void handlePost(HttpExchange ex, BodyHandler fn) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
            handleOptions(ex);
            return;
        }
        if (!"POST".equalsIgnoreCase(ex.getRequestMethod())) {
            methodNotAllowed(ex, "POST"); return;
        }
        try {
            Map<String,Object> in = Json.readMap(ex.getRequestBody());
            Map<String,Object> out = fn.handle(in);
            respond(ex, 200, out);
        } catch (BadReq br) {
            respond(ex, 400, Map.of("error", br.getMessage()));
        } catch (Unauthorized u) {
            respond(ex, 401, Map.of("error", u.getMessage()));
        } catch (Conflict c) {
            respond(ex, 409, Map.of("error", c.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            respond(ex, 500, Map.of("error", e.toString()));
        }
    }

    public static void respond(HttpExchange ex, int status, Object body) throws IOException {
        addCors(ex);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        if (status == 204 || body == null) {
            ex.sendResponseHeaders(status, -1);
            ex.close();
            return;
        }
        byte[] bytes = Json.toBytes(body);
        ex.sendResponseHeaders(status, bytes.length);
        ex.getResponseBody().write(bytes);
        ex.close();
    }

    public static void methodNotAllowed(HttpExchange ex, String expected) throws IOException {
        respond(ex, 405, Map.of("error","Use " + expected));
    }

    public static void addCors(HttpExchange ex){
        ex.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        ex.getResponseHeaders().add("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
        ex.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type, Authorization");
    }

    public static String str(Object o){ return o==null? null : String.valueOf(o); }
    public static void require(boolean ok, String msg){ if(!ok) throw new BadReq(msg); }

    public static <T> T waitFor(java.time.Duration timeout, Supplier<T> sup){
        long deadline = System.nanoTime() + timeout.toNanos();
        T v = sup.get();
        while (v == null && System.nanoTime() < deadline) {
            try { Thread.sleep(100); } catch (InterruptedException ignored) {}
            v = sup.get();
        }
        return v;
    }

    public static String getBearerToken(HttpExchange ex) {
        String h = ex.getRequestHeaders().getFirst("Authorization");
        if (h == null || !h.startsWith("Bearer ")) throw new Unauthorized("Missing Bearer token");
        String tok = h.substring(7).trim();
        if (tok.isEmpty()) throw new Unauthorized("Empty Bearer token");
        return tok;
    }

    @SuppressWarnings("unchecked")
    public static Map<String,Object> verifyAccessToken(String token, String secret) {
        Map<String,Object> claims = JwtUtil.verifyHS256(token, secret);
        if (claims == null) throw new Unauthorized("Invalid token");
        Object type = claims.get("type");
        if (!"access".equals(type)) throw new Unauthorized("Token is not an access token");
        Object exp = claims.get("exp");
        long nowSec = System.currentTimeMillis() / 1000L;
        long expSec = (exp instanceof Number) ? ((Number) exp).longValue() : Long.parseLong(String.valueOf(exp));
        if (nowSec >= expSec) throw new Unauthorized("Token expired");
        return claims;
    }
}
