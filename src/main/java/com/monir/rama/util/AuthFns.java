package com.monir.rama.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;

public final class AuthFns {
    private AuthFns(){}

    public static String lowerTrim(String s) {
        return s == null ? null : s.trim().toLowerCase(Locale.ROOT);
    }

    public static String sha256Hex(String s){
        try{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length*2);
            for(byte b: out){
                sb.append(Character.forDigit((b>>4)&0xF,16));
                sb.append(Character.forDigit((b)&0xF,16));
            }
            return sb.toString();
        }catch(Exception e){
            throw new RuntimeException(e);
        }
    }

    public static Map<String,Object> mapOf(Object... kv){
        HashMap<String,Object> m = new HashMap<>();
        for (int i=0; i<kv.length; i+=2){
            m.put((String)kv[i], kv[i+1]);
        }
        return m;
    }
}
