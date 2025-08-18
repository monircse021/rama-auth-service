package com.monir.rama.handler;

import com.monir.rama.util.AuthFns;
import com.monir.rama.util.ResponseUtil;
import com.rpl.rama.Depot;
import com.rpl.rama.QueryTopologyClient;
import com.sun.net.httpserver.HttpExchange;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public class UserHandler {
    private final Depot reg;
    private final QueryTopologyClient<Object> qUidByEmail;
    private final QueryTopologyClient<Object> qUserById;
    private final String secret;

    public UserHandler(Depot reg,
                       QueryTopologyClient<Object> qUidByEmail,
                       QueryTopologyClient<Object> qUserById,
                       String secret) {
        this.reg = reg;
        this.qUidByEmail = qUidByEmail;
        this.qUserById = qUserById;
        this.secret = secret;
    }

    public Map<String,Object> update(Map<String,Object> in) {
        String uid      = ResponseUtil.str(in.get("userId"));
        String fullName = ResponseUtil.str(in.get("fullName"));
        String email    = ResponseUtil.str(in.get("email"));
        String mobile   = ResponseUtil.str(in.get("mobileNumber"));
        ResponseUtil.require(uid != null && !uid.isBlank(), "userId is required");

        if (email != null) {
            String emailLower = AuthFns.lowerTrim(email);
            Object existing = qUidByEmail.invoke(emailLower);
            if (existing != null && !Objects.equals(existing, uid)) {
                throw new ResponseUtil.Conflict("Email already in use");
            }
        }

        Map<String,Object> evt = new HashMap<>();
        evt.put("type","UserUpdated");
        evt.put("userId", uid);
        if (fullName != null) evt.put("fullName", fullName);
        if (mobile   != null) evt.put("mobileNumber", mobile);
        if (email    != null) evt.put("emailLower", AuthFns.lowerTrim(email));
        reg.append(evt);

        return Map.of("status","updated");
    }

    /** GET /api/me */
    public void me(HttpExchange ex) throws IOException {
        if ("OPTIONS".equalsIgnoreCase(ex.getRequestMethod())) {
            ResponseUtil.handleOptions(ex);
            return;
        }
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            ResponseUtil.methodNotAllowed(ex, "GET");
            return;
        }
        try {
            String token = ResponseUtil.getBearerToken(ex);
            Map<String,Object> claims = ResponseUtil.verifyAccessToken(token, secret);
            String userId = String.valueOf(claims.get("sub"));
            Map user = (Map) qUserById.invoke(userId);
            if (user == null) {
                ResponseUtil.respond(ex, 404, Map.of("error", "User not found"));
                return;
            }
            ResponseUtil.respond(ex, 200, Map.of("status","ok","user",user));
        } catch (ResponseUtil.Unauthorized u) {
            ResponseUtil.respond(ex, 401, Map.of("error", u.getMessage()));
        } catch (Exception e) {
            e.printStackTrace();
            ResponseUtil.respond(ex, 500, Map.of("error", e.toString()));
        }
    }
}
