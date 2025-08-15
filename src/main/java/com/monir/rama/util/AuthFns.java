
package com.monir.rama.util;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

public final class AuthFns {
    private AuthFns(){}

    public static String lowerTrim(String s) {
        return s == null ? null : s.trim().toLowerCase();
    }

    public static String newId() {
        return UUID.randomUUID().toString().replace("-", "");
    }

    public static Map<String,Object> buildUser(String userId, String emailLower, String name, long now) {
        Map<String,Object> m = new HashMap<>();
        m.put("userId", userId);
        m.put("email", emailLower);
        m.put("name", name);
        m.put("verified", Boolean.FALSE);
        m.put("createdAt", now);
        return m;
    }

    public static Map<String,Object> markVerified(Map<String,Object> user) {
        if (user == null) return null;
        user.put("verified", Boolean.TRUE);
        return user;
    }

    // PBKDF2 helpers
    private static String b64(byte[] b){ return Base64.getEncoder().encodeToString(b); }
    private static byte[] pbkdf2Bytes(char[] password, byte[] salt, int iterations, int dkLen) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, dkLen*8);
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }
    private static boolean constEq(String a, String b) {
        if (a == null || b == null) return a == b;
        if (a.length() != b.length()) return false;
        int r = 0;
        for (int i=0;i<a.length();i++) r |= a.charAt(i) ^ b.charAt(i);
        return r == 0;
    }

    // OTP as Map to avoid Nippy custom serializer
    public static Map<String,Object> newOtpMap(int digits, Duration ttl) {
        // generate numeric code
        SecureRandom rng = new SecureRandom();
        StringBuilder code = new StringBuilder(digits);
        for (int i=0;i<digits;i++) code.append(rng.nextInt(10));
        byte[] salt = new byte[16];
        rng.nextBytes(salt);
        String saltB64 = b64(salt);
        String hashB64 = b64(pbkdf2Bytes(code.toString().toCharArray(), salt, 30_000, 32));
        long expiresAt = System.currentTimeMillis() + ttl.toMillis();
        Map<String,Object> m = new HashMap<>();
        m.put("hashB64", hashB64);
        m.put("saltB64", saltB64);
        m.put("expiresAtMillis", expiresAt);
        m.put("attempts", 0);
        // DO NOT store plaintext; you could send it out-of-band (mail/SMS). Here we only return masked for demo.
        return m;
    }

    public static Map<String,Object> emailOtpRequested(String userId, String email, Map<String,Object> otp) {
        Map<String,Object> m = new HashMap<>();
        m.put("type", "EmailOtpRequested");
        m.put("userId", userId);
        m.put("email", email);
        m.put("maskedOtp", "******");
        return m;
    }

    public static Map<String,Object> buildCred(String hash, String algo, String salt, Object params, long ts) {
        Map<String,Object> m = new HashMap<>();
        m.put("hash", hash);
        m.put("algo", algo);
        m.put("salt", salt);
        m.put("params", params);
        m.put("ts", ts);
        return m;
    }

    public static String key(String principal, String ip) {
        return principal + "|" + ip;
    }

    public static Long bump(Long cur) {
        return cur == null ? 1L : cur + 1L;
    }

    public static Map<String,Object> buildSession(String sid, String uid, String device, String ip, long now) {
        Map<String,Object> m = new HashMap<>();
        m.put("sessionId", sid);
        m.put("userId", uid);
        m.put("device", device);
        m.put("ip", ip);
        m.put("revoked", Boolean.FALSE);
        m.put("createdAt", now);
        return m;
    }

    public static Map<String,Object> revoke(Map<String,Object> sess) {
        if (sess == null) return null;
        sess.put("revoked", Boolean.TRUE);
        return sess;
    }

    public static boolean checkOtp(Map<String,Object> otp, String plain) {
        if (otp == null) return false;
        long expires = ((Number)otp.get("expiresAtMillis")).longValue();
        if (System.currentTimeMillis() > expires) return false;
        String saltB64 = (String) otp.get("saltB64");
        String targetHash = (String) otp.get("hashB64");
        byte[] salt = Base64.getDecoder().decode(saltB64);
        String candHash = b64(pbkdf2Bytes(plain.toCharArray(), salt, 30_000, 32));
        return constEq(targetHash, candHash);
    }
}
