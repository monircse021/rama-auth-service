package com.monir.rama;

import com.rpl.rama.*;
import com.rpl.rama.module.StreamTopology;
import com.rpl.rama.ops.Ops;

import java.util.HashMap;
import java.util.Map;

public class AuthModule implements RamaModule {

    @Override
    public void define(Setup setup, Topologies topologies) {
        setup.declareDepot("*registration_cmds", Depot.random());
        setup.declareDepot("*auth_events", Depot.random());

        // ===== Users (registration) =====
        StreamTopology reg = topologies.stream("registration");

        reg.pstate("$$usersById",     PState.mapSchema(String.class, java.util.Map.class));
        reg.pstate("$$emailIndex",    PState.mapSchema(String.class, String.class));
        reg.pstate("$$usernameIndex", PState.mapSchema(String.class, String.class));
        reg.pstate("$$credsByUser",   PState.mapSchema(String.class, java.util.Map.class));

        reg.source("*registration_cmds").out("*e")
            .each(Ops.GET, "*e", "type").out("*type")

            // RegisterRequested
            .ifTrue(new Expr(Ops.EQUAL, "*type", "RegisterRequested"),
                Block
                    .each(Ops.GET, "*e", "emailLower").out("*emailLower")
                    .each(Ops.GET, "*e", "usernameLower").out("*usernameLower")
                    .each(Ops.GET, "*e", "fullName").out("*fullName")
                    .each(Ops.GET, "*e", "mobileNumber").out("*mobile")
                    .each(Ops.GET, "*e", "pwdHash").out("*hash")

                    .hashPartition("*emailLower")
                    .localSelect("$$emailIndex", Path.key("*emailLower")).out("*uidEmail")
                    .hashPartition("*usernameLower")
                    .localSelect("$$usernameIndex", Path.key("*usernameLower")).out("*uidUser")
                    .each((String a) -> Boolean.valueOf(a != null), "*uidEmail").out("*emailTaken")
                    .each((String a) -> Boolean.valueOf(a != null), "*uidUser").out("*userTaken")
                    .each((Boolean eTaken, Boolean uTaken) -> Boolean.valueOf(!eTaken && !uTaken), "*emailTaken","*userTaken").out("*ok")

                    .ifTrue(new Expr(Ops.EQUAL, "*ok", true),
                        Block
                            .each(() -> java.util.UUID.randomUUID().toString().replace("-", "")).out("*userId")
                            .each(System::currentTimeMillis).out("*now")
                            .each((String id, String un, String em, String fn, String mob, Long now) -> {
                                Map<String,Object> u = new HashMap<>();
                                u.put("userId", id);
                                u.put("username", un);
                                u.put("email", em);
                                u.put("fullName", fn);
                                u.put("mobileNumber", mob);
                                u.put("status", "active");
                                u.put("createdAt", now);
                                u.put("updatedAt", now);
                                return u;
                            }, "*userId","*usernameLower","*emailLower","*fullName","*mobile","*now").out("*userObj")
                            .hashPartition("*userId")
                            .localTransform("$$usersById", Path.key("*userId").termVal("*userObj"))
                            .hashPartition("*emailLower")
                            .localTransform("$$emailIndex", Path.key("*emailLower").termVal("*userId"))
                            .hashPartition("*usernameLower")
                            .localTransform("$$usernameIndex", Path.key("*usernameLower").termVal("*userId"))
                            .hashPartition("*userId")
                            .each((String hash, Long ts) -> {
                                Map<String,Object> c = new HashMap<>();
                                c.put("algo", "sha256");
                                c.put("hash", hash);
                                c.put("ts", ts);
                                return c;
                            }, "*hash","*now").out("*cred")
                            .localTransform("$$credsByUser", Path.key("*userId").termVal("*cred"))
                    )
            )

            // UserUpdated
            .ifTrue(new Expr(Ops.EQUAL, "*type", "UserUpdated"),
                Block
                    .each(Ops.GET, "*e", "userId").out("*uid")
                    .each(Ops.GET, "*e", "emailLower").out("*emailLower")
                    .each(Ops.GET, "*e", "fullName").out("*fullName")
                    .each(Ops.GET, "*e", "mobileNumber").out("*mobile")

                    .hashPartition("*uid")
                    .localSelect("$$usersById", Path.key("*uid")).out("*u")
                    .ifTrue(new Expr(Ops.IS_NOT_NULL, "*u"),
                        Block
                            .each(System::currentTimeMillis).out("*now2")
                            .each((Map u, String fn, String mob, String em, Long now) -> {
                                if (u == null) return null;
                                if (fn != null) u.put("fullName", fn);
                                if (mob != null) u.put("mobileNumber", mob);
                                if (em != null) u.put("email", em);
                                u.put("updatedAt", now);
                                return u;
                            }, "*u","*fullName","*mobile","*emailLower","*now2").out("*u2")
                            .localTransform("$$usersById", Path.key("*uid").termVal("*u2"))
                            .ifTrue(new Expr(Ops.IS_NOT_NULL, "*emailLower"),
                                Block.localTransform("$$emailIndex", Path.key("*emailLower").termVal("*uid"))
                            )
                    )
            );

        // ===== Auth / Refresh tokens =====
        StreamTopology auth = topologies.stream("auth");
        auth.pstate("$$refreshTokens", PState.mapSchema(String.class, java.util.Map.class));

        auth.source("*auth_events").out("*e")
            .each(Ops.GET, "*e", "type").out("*type")

            // Upsert refresh
            .ifTrue(new Expr(Ops.EQUAL, "*type", "RefreshTokenUpsert"),
                Block
                    .each(Ops.GET, "*e", "token").out("*tok")
                    .each(Ops.GET, "*e", "userId").out("*uid")
                    .each(Ops.GET, "*e", "expMillis").out("*exp")
                    .each(() -> Boolean.FALSE).out("*rev")
                    .each((String tok, String uid, Long exp, Boolean rev) -> {
                        Map<String,Object> m = new HashMap<>();
                        m.put("userId", uid);
                        m.put("expMillis", exp);
                        m.put("revoked", rev);
                        return m;
                    }, "*tok","*uid","*exp","*rev").out("*val")
                    .hashPartition("*tok")
                    .localTransform("$$refreshTokens", Path.key("*tok").termVal("*val"))
            )

            // Revoke refresh
            .ifTrue(new Expr(Ops.EQUAL, "*type", "RefreshTokenRevoke"),
                Block
                    .each(Ops.GET, "*e", "token").out("*tok")
                    .hashPartition("*tok")
                    .localSelect("$$refreshTokens", Path.key("*tok")).out("*rt")
                    .ifTrue(new Expr(Ops.IS_NOT_NULL, "*rt"),
                        Block.each((Map rt) -> { rt.put("revoked", Boolean.TRUE); return rt; }, "*rt").out("*rt2")
                             .localTransform("$$refreshTokens", Path.key("*tok").termVal("*rt2"))
                    )
            );

        // ===== Queries =====
        topologies.query("canRegister", "*emailLower", "*usernameLower").out("*ok")
            .hashPartition("*emailLower")
            .localSelect("$$emailIndex", Path.key("*emailLower")).out("*uidE")
            .hashPartition("*usernameLower")
            .localSelect("$$usernameIndex", Path.key("*usernameLower")).out("*uidU")
            .each((String a) -> Boolean.valueOf(a == null), "*uidE").out("*emailFree")
            .each((String a) -> Boolean.valueOf(a == null), "*uidU").out("*userFree")
            .each((Boolean ef, Boolean uf) -> Boolean.valueOf(ef && uf), "*emailFree","*userFree").out("*ok")
            .originPartition();

        topologies.query("getUserIdByEmail", "*emailLower").out("*uid")
            .hashPartition("*emailLower")
            .localSelect("$$emailIndex", Path.key("*emailLower")).out("*uid")
            .originPartition();

        topologies.query("getUserIdByUsername", "*usernameLower").out("*uid")
            .hashPartition("*usernameLower")
            .localSelect("$$usernameIndex", Path.key("*usernameLower")).out("*uid")
            .originPartition();

        topologies.query("getCredForUser", "*userId").out("*cred")
            .hashPartition("*userId")
            .localSelect("$$credsByUser", Path.key("*userId")).out("*cred")
            .originPartition();

        topologies.query("getUserById", "*userId").out("*user")
            .hashPartition("*userId")
            .localSelect("$$usersById", Path.key("*userId")).out("*user")
            .originPartition();

        topologies.query("validateRefresh", "*token").out("*uid")
            .hashPartition("*token")
            .localSelect("$$refreshTokens", Path.key("*token")).out("*r")
            .each(System::currentTimeMillis).out("*now")
            .each((Map r, Long now) -> {
                if (r == null) return null;
                Object exp = r.get("expMillis");
                Object rev = r.get("revoked");
                long expMs = exp instanceof Number ? ((Number)exp).longValue() : -1L;
                boolean ok = Boolean.FALSE.equals(rev) && now < expMs;
                return ok ? r.get("userId") : null;
            }, "*r","*now").out("*uid")
            .originPartition();
    }
}
