package com.monir.rama.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;
import java.util.Map;

public final class Jwt {
    private Jwt(){}
    private static final ObjectMapper M = new ObjectMapper();

    private static String b64url(byte[] b){
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    public static String signHS256(Map<String,Object> payload, String secret){
        try{
            String headerJson = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}";
            String payloadJson = M.writeValueAsString(payload);
            String h = b64url(headerJson.getBytes(StandardCharsets.UTF_8));
            String p = b64url(payloadJson.getBytes(StandardCharsets.UTF_8));
            String data = h + "." + p;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] sig = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
            String s = b64url(sig);
            return data + "." + s;
        }catch(Exception e){
            throw new RuntimeException(e);
        }
    }
}
