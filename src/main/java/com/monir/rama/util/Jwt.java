package com.monir.rama.util;

import com.fasterxml.jackson.databind.ObjectMapper;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

public final class Jwt {
    private Jwt() {}
    private static final ObjectMapper M = new ObjectMapper();

    // ---- Base64 URL helpers ----
    private static String b64url(byte[] b) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }
    private static byte[] b64urlDecode(String s) {
        // Pad if necessary so length % 4 == 0
        int pad = (4 - (s.length() % 4)) % 4;
        StringBuilder sb = new StringBuilder(s);
        for (int i = 0; i < pad; i++) sb.append('=');
        return Base64.getUrlDecoder().decode(sb.toString());
    }

    // ---- Sign ----
    public static String signHS256(Map<String, Object> payload, String secret) {
        try {
            String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            String payloadJson = M.writeValueAsString(payload);

            String h = b64url(headerJson.getBytes(StandardCharsets.UTF_8));
            String p = b64url(payloadJson.getBytes(StandardCharsets.UTF_8));
            String data = h + "." + p;

            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] sig = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));

            return data + "." + b64url(sig);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ---- Verify (signature) + return claims ----
    @SuppressWarnings("unchecked")
    public static Map<String, Object> verifyHS256(String token, String secret) {
        try {
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                throw new SecurityException("Invalid JWT format");
            }
            String hB64 = parts[0];
            String pB64 = parts[1];
            String sB64 = parts[2];

            // Verify header.alg == HS256
            Map<String, Object> header =
                    M.readValue(b64urlDecode(hB64), Map.class);
            Object alg = header.get("alg");
            if (!"HS256".equals(alg)) {
                throw new SecurityException("Unsupported alg: " + alg);
            }

            // Compute expected signature
            String data = hB64 + "." + pB64;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            byte[] actual = b64urlDecode(sB64);

            if (!constantTimeEquals(expected, actual)) {
                throw new SecurityException("Invalid signature");
            }

            // Return payload claims (no exp/type checks here)
            return M.readValue(b64urlDecode(pB64), Map.class);
        } catch (SecurityException se) {
            throw se;
        } catch (Exception e) {
            throw new RuntimeException("JWT verification failed", e);
        }
    }

    // Constant-time comparison to avoid timing attacks
    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        if (a == null || b == null || a.length != b.length) return false;
        int result = 0;
        for (int i = 0; i < a.length; i++) result |= a[i] ^ b[i];
        return result == 0;
    }
}