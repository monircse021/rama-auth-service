package com.monir.rama.handler;

import com.monir.rama.util.JwtUtil;
import com.monir.rama.util.RequestValidator;
import com.monir.rama.util.ResponseUtil;
import com.rpl.rama.Depot;
import com.rpl.rama.QueryTopologyClient;

import java.util.HashMap;
import java.util.Map;

public class TokenHandler {
    private final String secret;
    private final Depot auth;
    private final QueryTopologyClient<Object> qValidateRef;
    private final long accessTtlMs;
    private final long refreshTtlMs;

    public TokenHandler(String secret, Depot auth,
                        QueryTopologyClient<Object> qValidateRef,
                        long accessTtlMs, long refreshTtlMs) {
        this.secret = secret;
        this.auth = auth;
        this.qValidateRef = qValidateRef;
        this.accessTtlMs = accessTtlMs;
        this.refreshTtlMs = refreshTtlMs;
    }

    public Map<String,Object> refresh(Map<String,Object> in) {
        String refresh = ResponseUtil.str(in.get("refreshToken"));
        RequestValidator.requireNonEmpty(refresh, "refreshToken is required");

        Object userId = qValidateRef.invoke(refresh);
        if (userId == null) throw new ResponseUtil.Unauthorized("Invalid or expired refresh token");

        String username = ResponseUtil.str(in.get("username"));
        if (username == null) username = "user";

        Map<String,Object> revoke = new HashMap<>();
        revoke.put("type","RefreshTokenRevoke");
        revoke.put("token", refresh);
        auth.append(revoke);

        String newRefresh = JwtUtil.createRefreshToken(secret, (String)userId, username, refreshTtlMs);
        Map<String,Object> upsert = new HashMap<>();
        upsert.put("type","RefreshTokenUpsert");
        upsert.put("token", newRefresh);
        upsert.put("userId", userId);
        upsert.put("expMillis", System.currentTimeMillis() + refreshTtlMs);
        auth.append(upsert);

        String access = JwtUtil.createAccessToken(secret, (String)userId, username, accessTtlMs);

        return Map.of(
                "status","ok",
                "userId", userId,
                "username", username,
                "accessToken", access,
                "refreshToken", newRefresh
        );
    }

    public Map<String,Object> logout(Map<String,Object> in) {
        String refresh = ResponseUtil.str(in.get("refreshToken"));
        RequestValidator.requireNonEmpty(refresh, "refreshToken is required");
        Map<String,Object> revoke = new HashMap<>();
        revoke.put("type","RefreshTokenRevoke");
        revoke.put("token", refresh);
        auth.append(revoke);
        // Return 204 from caller by throwing special signal or returning null; here we return a body and the router will send 200.
        // The main uses ResponseUtil to map routes, so let's return a simple status and the client can ignore body.
        return Map.of("status","logged_out");
    }
}
