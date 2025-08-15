
package com.monir.rama;

import com.monir.rama.util.AuthFns;
import com.rpl.rama.*;
import com.rpl.rama.module.StreamTopology;
import com.rpl.rama.ops.Ops;

import java.time.Duration;

public class AuthModule implements RamaModule {

    @Override
    public void define(Setup setup, Topologies topologies) {
        // Depots
        setup.declareDepot("*registration_cmds", Depot.random());
        setup.declareDepot("*auth_events",       Depot.random());
        setup.declareDepot("*out_email",         Depot.random());

        // ---------------- Registration stream ----------------
        StreamTopology reg = topologies.stream("registration");

        // PStates (declare inside topology for Rama 1.1.x)
        reg.pstate("$$usersById",   PState.mapSchema(String.class, java.util.Map.class));
        reg.pstate("$$emailIndex",  PState.mapSchema(String.class, String.class));
        reg.pstate("$$otpByUser",   PState.mapSchema(String.class, java.util.Map.class));
        reg.pstate("$$credsByUser", PState.mapSchema(String.class, java.util.Map.class));

        reg.source("*registration_cmds").out("*e")
                .each(Ops.GET, "*e", "type").out("*type")

                // RegisterRequested
                .ifTrue(new Expr(Ops.EQUAL, "*type", "RegisterRequested"),
                        Block
                                .each(Ops.GET, "*e", "email").out("*emailRaw")
                                .each((String s) -> AuthFns.lowerTrim(s), "*emailRaw").out("*emailLower")
                                .hashPartition("*emailLower")
                                .localSelect("$$emailIndex", Path.key("*emailLower")).out("*existing")
                                .ifTrue(new Expr(Ops.IS_NULL, "*existing"),
                                        Block
                                                .each(() -> AuthFns.newId()).out("*userId")
                                                .each(Ops.GET, "*e", "name").out("*name")
                                                .each(System::currentTimeMillis).out("*now")
                                                // build user map
                                                .each((String id, String email, String name, Long now) -> AuthFns.buildUser(id,email,name,now),
                                                        "*userId","*emailLower","*name","*now").out("*userObj")
                                                .localTransform("$$usersById",  Path.key("*userId").termVal("*userObj"))
                                                .localTransform("$$emailIndex", Path.key("*emailLower").termVal("*userId"))
                                                // OTP
                                                .each(() -> AuthFns.newOtpMap(6, Duration.ofMinutes(15))).out("*otp")
                                                .localTransform("$$otpByUser", Path.key("*userId").termVal("*otp"))
                                                // mail message
                                                .each((String uid, String emailRaw, java.util.Map otp) -> AuthFns.emailOtpRequested(uid,emailRaw,otp),
                                                        "*userId","*emailRaw","*otp").out("*msg")
                                                .depotPartitionAppend("*out_email", "*msg")
                                )
                )

                // EmailVerified
                .ifTrue(new Expr(Ops.EQUAL, "*type", "EmailVerified"),
                        Block
                                .each(Ops.GET, "*e", "userId").out("*uid")
                                .hashPartition("*uid")
                                .localSelect("$$usersById", Path.key("*uid")).out("*u")
                                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*u"),
                                        Block.each((java.util.Map u) -> AuthFns.markVerified(u), "*u").out("*u2")
                                                .localTransform("$$usersById", Path.key("*uid").termVal("*u2"))
                                )
                )

                // SetPasswordHash
                .ifTrue(new Expr(Ops.EQUAL, "*type", "SetPasswordHash"),
                        Block
                                .each(Ops.GET, "*e", "userId").out("*uid")
                                .each(Ops.GET, "*e", "hash").out("*hash")
                                .each(Ops.GET, "*e", "algo").out("*algo")
                                .each(Ops.GET, "*e", "salt").out("*salt")
                                .each(Ops.GET, "*e", "params").out("*params")
                                .each(System::currentTimeMillis).out("*ts")
                                .each((String h, String a, String s, Object p, Long ts) -> AuthFns.buildCred(h,a,s,p,ts),
                                        "*hash","*algo","*salt","*params","*ts").out("*cred")
                                .hashPartition("*uid")
                                .localTransform("$$credsByUser", Path.key("*uid").termVal("*cred"))
                );

        // ---------------- Auth stream ----------------
        StreamTopology auth = topologies.stream("auth");
        auth.pstate("$$loginFailures", PState.mapSchema(String.class, Long.class));
        auth.pstate("$$sessionsById",  PState.mapSchema(String.class, java.util.Map.class));

        auth.source("*auth_events").out("*e")
                .each(Ops.GET, "*e", "type").out("*type")

                // LoginFailed → bump counter
                .ifTrue(new Expr(Ops.EQUAL, "*type", "LoginFailed"),
                        Block
                                .each(Ops.GET, "*e", "principal").out("*principal")
                                .each(Ops.GET, "*e", "ip").out("*ip")
                                .each((String p, String ip) -> AuthFns.key(p,ip), "*principal","*ip").out("*key")
                                .hashPartition("*key")
                                .localSelect("$$loginFailures", Path.key("*key")).out("*cur")
                                .each((Long c) -> AuthFns.bump(c), "*cur").out("*next")
                                .localTransform("$$loginFailures", Path.key("*key").termVal("*next"))
                )

                // SessionRequested → create session
                .ifTrue(new Expr(Ops.EQUAL, "*type", "SessionRequested"),
                        Block
                                .each(Ops.GET, "*e", "userId").out("*uid")
                                .each(() -> AuthFns.newId()).out("*sid")
                                .each(Ops.GET, "*e", "device").out("*device")
                                .each(Ops.GET, "*e", "ip").out("*ip")
                                .each(System::currentTimeMillis).out("*now")
                                .each((String sid, String uid, String dev, String ip, Long now) -> AuthFns.buildSession(sid,uid,dev,ip,now),
                                        "*sid","*uid","*device","*ip","*now").out("*sess")
                                .hashPartition("*sid")
                                .localTransform("$$sessionsById", Path.key("*sid").termVal("*sess"))
                )

                // LogoutRequested → revoke
                .ifTrue(new Expr(Ops.EQUAL, "*type", "LogoutRequested"),
                        Block
                                .each(Ops.GET, "*e", "sessionId").out("*sid")
                                .hashPartition("*sid")
                                .localSelect("$$sessionsById", Path.key("*sid")).out("*s")
                                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*s"),
                                        Block.each((java.util.Map s) -> AuthFns.revoke(s), "*s").out("*s2")
                                                .localTransform("$$sessionsById", Path.key("*sid").termVal("*s2"))
                                )
                );

        // ---------------- Queries ----------------

        topologies.query("canRegister", "*emailLower").out("*ok")
                .hashPartition("*emailLower")
                .localSelect("$$emailIndex", Path.key("*emailLower")).out("*existing")
                .each(Ops.IS_NULL, "*existing").out("*ok")
                .originPartition();

        topologies.query("getUserIdByEmail", "*emailLower").out("*userId")
                .hashPartition("*emailLower")
                .localSelect("$$emailIndex", Path.key("*emailLower")).out("*userId")
                .originPartition();

        topologies.query("getCredForUser", "*userId").out("*cred")
                .hashPartition("*userId")
                .localSelect("$$credsByUser", Path.key("*userId")).out("*cred")
                .originPartition();

        topologies.query("checkOtp", "*userId", "*otpPlain").out("*ok")
                .hashPartition("*userId")
                .localSelect("$$otpByUser", Path.key("*userId")).out("*otp")
                .each((java.util.Map otp, String plain) -> AuthFns.checkOtp(otp, plain), "*otp","*otpPlain").out("*ok")
                .originPartition();

        topologies.query("checkSession", "*sessionId").out("*sess")
                .hashPartition("*sessionId")
                .localSelect("$$sessionsById", Path.key("*sessionId")).out("*sess")
                .originPartition();
    }
}
