package com.monir.rama.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class AuthFns {
    private AuthFns(){}

    public static String lowerTrim(String s) {
        return s == null ? null : s.trim().toLowerCase();
    }

    public static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length*2);
            for (byte b : out) {
                String hx = Integer.toHexString((b & 0xff) | 0x100).substring(1);
                sb.append(hx);
            }
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
