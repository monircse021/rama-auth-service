package com.monir.rama.handler;

import com.monir.rama.util.AuthFns;
import com.monir.rama.util.RequestValidator;
import com.monir.rama.util.EventBuilder;
import com.monir.rama.util.ResponseUtil;
import com.rpl.rama.Depot;
import com.rpl.rama.QueryTopologyClient;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public class RegisterHandler {
    private final Depot reg;
    private final QueryTopologyClient<Object> qCanRegister;
    private final QueryTopologyClient<Object> qUidByUsername;

    public RegisterHandler(Depot reg,
                           QueryTopologyClient<Object> qCanRegister,
                           QueryTopologyClient<Object> qUidByUsername) {
        this.reg = reg;
        this.qCanRegister = qCanRegister;
        this.qUidByUsername = qUidByUsername;
    }

    public Map<String,Object> handle(Map<String,Object> in) {
        String fullName = ResponseUtil.str(in.get("fullName"));
        String email    = ResponseUtil.str(in.get("email"));
        String username = ResponseUtil.str(in.get("username"));
        String mobile   = ResponseUtil.str(in.get("mobileNumber"));
        String password = ResponseUtil.str(in.get("password"));

        RequestValidator.requireNonEmpty(email, "email is required");
        RequestValidator.requireNonEmpty(username, "username is required");
        RequestValidator.requireNonEmpty(password, "password is required");

        String emailLower = AuthFns.lowerTrim(email);
        String userLower  = AuthFns.lowerTrim(username);

        Boolean okReg = (Boolean) qCanRegister.invoke(emailLower, userLower);
        if (okReg == null || !okReg) {
            throw new ResponseUtil.Conflict("Email or username already taken");
        }

        String pwdHash = AuthFns.sha256Hex(password);

        Map<String,Object> evt = new HashMap<>();
        evt.put("type","RegisterRequested");
        evt.put("fullName", fullName);
        evt.put("emailLower", emailLower);
        evt.put("usernameLower", userLower);
        evt.put("mobileNumber", mobile);
        evt.put("pwdHash", pwdHash);
        reg.append(evt);

        Object userId = ResponseUtil.waitFor(Duration.ofSeconds(5),
                () -> qUidByUsername.invoke(userLower));

        if (userId == null) {
            return Map.of("status","accepted");
        }
        return Map.of("status","created","userId", userId,"fullName", fullName);
    }
}
