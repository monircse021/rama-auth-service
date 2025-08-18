package com.monir.rama.util;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

public final class JwtUtil {
    private JwtUtil(){}
    private static final ObjectMapper M = new ObjectMapper();

    public static String createAccessToken(String secret, String userId, String username, long ttlMs){
        long now = System.currentTimeMillis();
        long exp = now + ttlMs;
        Map<String,Object> payload = new LinkedHashMap<>();
        payload.put("sub", userId);
        payload.put("username", username);
        payload.put("type", "access");
        payload.put("iat", now/1000);
        payload.put("exp", exp/1000);
        return signHS256(payload, secret);
    }

    public static String createRefreshToken(String secret, String userId, String username, long ttlMs){
        long now = System.currentTimeMillis();
        long exp = now + ttlMs;
        Map<String,Object> payload = new LinkedHashMap<>();
        payload.put("sub", userId);
        payload.put("username", username);
        payload.put("type", "refresh");
        payload.put("jti", UUID.randomUUID().toString().replace("-", ""));
        payload.put("iat", now/1000);
        payload.put("exp", exp/1000);
        return signHS256(payload, secret);
    }

    public static String signHS256(Map<String,Object> payload, String secret){
        try{
            String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            String headerB64  = b64url(headerJson.getBytes(StandardCharsets.UTF_8));
            String payloadB64 = b64url(M.writeValueAsBytes(payload));
            String msg = headerB64 + "." + payloadB64;
            String sig = sign(msg, secret);
            return msg + "." + sig;
        }catch(Exception e){
            throw new RuntimeException(e);
        }
    }

    public static Map<String,Object> verifyHS256(String token, String secret){
        try{
            String[] parts = token.split("\\.");
            if (parts.length != 3) return null;
            String msg = parts[0] + "." + parts[1];
            String expect = sign(msg, secret);
            if (!constantTimeEq(expect, parts[2])) return null;
            byte[] payload = Base64.getUrlDecoder().decode(parts[1]);
            @SuppressWarnings("unchecked")
            Map<String,Object> claims = M.readValue(payload, Map.class);
            Object exp = claims.get("exp");
            if (exp instanceof Number) {
                long now = System.currentTimeMillis()/1000L;
                if (now >= ((Number)exp).longValue()) return null;
            }
            return claims;
        }catch(Exception e){
            return null;
        }
    }

    private static String sign(String msg, String secret) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return b64url(mac.doFinal(msg.getBytes(StandardCharsets.UTF_8)));
    }
    private static String b64url(byte[] b){
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
    private static boolean constantTimeEq(String a, String b){
        if (a.length()!=b.length()) return false;
        int r=0;
        for (int i=0;i<a.length();i++) r |= a.charAt(i) ^ b.charAt(i);
        return r==0;
    }
}
