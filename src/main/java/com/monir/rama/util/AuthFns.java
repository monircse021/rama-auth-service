package com.monir.rama.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

public final class AuthFns {
    private AuthFns(){}

    public static String lowerTrim(String s){
        return s==null? null : s.trim().toLowerCase();
    }

    public static String sha256Hex(String s){
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] b = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(b.length*2);
            for(byte x: b) sb.append(String.format("%02x", x));
            return sb.toString();
        }catch(Exception e){
            throw new RuntimeException(e);
        }
    }
}
