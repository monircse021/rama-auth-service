package com.monir.rama.util;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public final class Jwt {
    private Jwt(){}

    private static final Base64.Encoder B64_URL_ENC = Base64.getUrlEncoder().withoutPadding();

    private static byte[] hmacSha256(byte[] key, String data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static String b64url(byte[] b) {
        return B64_URL_ENC.encodeToString(b);
    }

    private static String toJson(Map<String,Object> m){
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        boolean first=true;
        for (Map.Entry<String,Object> e : m.entrySet()){
            if(!first) sb.append(",");
            first=false;
            sb.append("\"").append(e.getKey()).append("\":");
            Object v=e.getValue();
            if (v instanceof Number || v instanceof Boolean) {
                sb.append(v.toString());
            } else {
                sb.append("\"").append(v.toString().replace("\"","\\\"")).append("\"");
            }
        }
        sb.append("}");
        return sb.toString();
    }

    public static String signHS256(Map<String,Object> payload, String secret){
        Map<String,Object> header = new HashMap<>();
        header.put("alg","HS256");
        header.put("typ","JWT");
        String header64 = b64url(toJson(header).getBytes(StandardCharsets.UTF_8));
        String payload64 = b64url(toJson(payload).getBytes(StandardCharsets.UTF_8));
        String signingInput = header64 + "." + payload64;
        String sig64 = b64url(hmacSha256(secret.getBytes(StandardCharsets.UTF_8), signingInput));
        return signingInput + "." + sig64;
    }
}
