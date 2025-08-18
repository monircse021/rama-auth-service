package com.monir.rama.handler;

import com.monir.rama.util.AuthFns;
import com.monir.rama.util.JwtUtil;
import com.monir.rama.util.RequestValidator;
import com.monir.rama.util.ResponseUtil;
import com.rpl.rama.Depot;
import com.rpl.rama.QueryTopologyClient;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class LoginHandler {
    private final String secret;
    private final Depot auth;
    private final QueryTopologyClient<Object> qUidByUsername;
    private final QueryTopologyClient<Object> qCredForUser;
    private final long accessTtlMs;
    private final long refreshTtlMs;

    public LoginHandler(String secret,
                        Depot auth,
                        QueryTopologyClient<Object> qUidByUsername,
                        QueryTopologyClient<Object> qCredForUser,
                        long accessTtlMs,
                        long refreshTtlMs) {
        this.secret = secret;
        this.auth = auth;
        this.qUidByUsername = qUidByUsername;
        this.qCredForUser = qCredForUser;
        this.accessTtlMs = accessTtlMs;
        this.refreshTtlMs = refreshTtlMs;
    }

    public Map<String,Object> handle(Map<String,Object> in) {
        String username = ResponseUtil.str(in.get("username"));
        String password = ResponseUtil.str(in.get("password"));
        RequestValidator.requireNonEmpty(username, "username is required");
        RequestValidator.requireNonEmpty(password, "password is required");

        String userLower = AuthFns.lowerTrim(username);
        Object userId = qUidByUsername.invoke(userLower);
        if (userId == null) throw new ResponseUtil.Unauthorized("Invalid username or password");

        Map cred = (Map) qCredForUser.invoke(userId);
        if (cred == null) throw new ResponseUtil.Unauthorized("Invalid username or password");

        String stored = String.valueOf(cred.get("hash"));
        String cand   = AuthFns.sha256Hex(password);
        if (!Objects.equals(stored, cand)) throw new ResponseUtil.Unauthorized("Invalid username or password");

        String access  = JwtUtil.createAccessToken(secret, (String)userId, username, accessTtlMs);
        String refresh = JwtUtil.createRefreshToken(secret, (String)userId, username, refreshTtlMs);

        Map<String,Object> tokEvt = new HashMap<>();
        tokEvt.put("type","RefreshTokenUpsert");
        tokEvt.put("token", refresh);
        tokEvt.put("userId", userId);
        tokEvt.put("expMillis", System.currentTimeMillis() + refreshTtlMs);
        auth.append(tokEvt);

        return Map.of(
                "status","ok",
                "userId", userId,
                "username", username,
                "accessToken", access,
                "refreshToken", refresh
        );
    }
}
