package com.monir.rama;

import com.rpl.rama.*;
import com.rpl.rama.module.StreamTopology;
import com.rpl.rama.ops.Ops;

import java.util.HashMap;
import java.util.Map;

/**
 * AuthModule — Rama 1.1.0
 *
 * Depots (commands):
 *   *registration_cmds:
 *     - RegisterRequested {email, username, fullName, mobile, passwordSha256}
 *     - UpdateUserRequested {userId, fullName?, email?, mobile?}
 *
 *   *auth_events:
 *     - CreateSession {sessionId, userId, refreshId, expiresAtMs?, refreshExpiresAtMs?}
 *     - LogoutRequested {sessionId}
 *
 * PStates:
 *   $$usersById            : userId -> Map user
 *   $$emailIndex           : emailLower -> userId   (stale-safe; see canRegister)
 *   $$usernameIndex        : usernameLower -> userId
 *   $$credsByUser          : userId -> Map {algo:"sha256", hash:String, ts:long}
 *   $$sessionsById         : sessionId -> Map session {revoked, expiresAtMs,...}
 *   $$refreshById          : refreshId -> Map refresh  {revoked, expiresAtMs,...}
 *   $$refreshIdBySessionId : sessionId -> refreshId
 *
 * Queries you can call from HTTP:
 *   - canRegister(emailLower, usernameLower) -> Boolean
 *   - getUserIdByUsername(usernameLower) -> String userId or null
 *   - getUserSlimByUsername(usernameLower) -> Map {userId, username, status} or null
 *   - getUserById(userId) -> Map full user or null
 *   - authenticate(usernameLower, passwordSha256) -> String userId or null
 *   - checkSession(sessionId) -> Map session or null (null if expired/revoked)
 *   - validateRefresh(refreshId) -> Map refresh or null (null if expired/revoked)
 */
public class AuthModule implements RamaModule {

    // Defaults used if CreateSession doesn’t provide explicit expiries
    private static final long ACCESS_TTL_MS  = 10 * 60 * 1000L;       // 10 minutes
    private static final long REFRESH_TTL_MS = 7L * 24 * 60 * 60 * 1000L; // 7 days

    @Override
    public void define(Setup setup, Topologies topologies) {
        // -------- Depots --------
        setup.declareDepot("*registration_cmds", Depot.random());
        setup.declareDepot("*auth_events",       Depot.random());

        // ===================== Users / Registration stream =====================
        StreamTopology reg = topologies.stream("users");

        // PStates for user/account data
        reg.pstate("$$usersById",            PState.mapSchema(String.class, java.util.Map.class));
        reg.pstate("$$emailIndex",           PState.mapSchema(String.class, String.class));
        reg.pstate("$$usernameIndex",        PState.mapSchema(String.class, String.class));
        reg.pstate("$$credsByUser",          PState.mapSchema(String.class, java.util.Map.class));

        reg.source("*registration_cmds").out("*e")
                .each(Ops.GET, "*e", "type").out("*type")

                // ---------------- RegisterRequested ----------------
                .ifTrue(new Expr(Ops.EQUAL, "*type", "RegisterRequested"),
                        Block
                                .each(Ops.GET, "*e", "email").out("*emailRaw")
                                .each(Ops.GET, "*e", "username").out("*usernameRaw")
                                .each(Ops.GET, "*e", "fullName").out("*fullName")
                                .each(Ops.GET, "*e", "mobile").out("*mobile")
                                .each(Ops.GET, "*e", "passwordSha256").out("*passSha256")

                                // normalize email/username (lower/trim)
                                .each((String s) -> s == null ? null : s.trim().toLowerCase(), "*emailRaw").out("*emailLower")
                                .each((String s) -> s == null ? null : s.trim().toLowerCase(), "*usernameRaw").out("*usernameLower")

                                // Look up existing email owner (index may be stale; we’ll check actual user below)
                                .hashPartition("*emailLower")
                                .localSelect("$$emailIndex", Path.key("*emailLower")).out("*uidByEmailIdx")

                                // Username is unique and never changed – index is authoritative
                                .hashPartition("*usernameLower")
                                .localSelect("$$usernameIndex", Path.key("*usernameLower")).out("*uidByUsernameIdx")

                                // Determine if email is actually taken (handle possible stale index)
                                // Default: email is free
                                .each(() -> Boolean.FALSE).out("*emailTaken")
                                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*uidByEmailIdx"),
                                        Block
                                                .hashPartition("*uidByEmailIdx")
                                                .localSelect("$$usersById", Path.key("*uidByEmailIdx")).out("*userAtEmail")
                                                .each(Ops.GET, "*userAtEmail", "email").out("*emailOnUser")
                                                .each((String cur, String target) -> Boolean.valueOf(cur != null && cur.equals(target)),
                                                        "*emailOnUser", "*emailLower").out("*emailTaken")
                                )

                                // Username taken?
                                .each((String v) -> Boolean.valueOf(v != null), "*uidByUsernameIdx").out("*usernameTaken")

                                // ok = !emailTaken && !usernameTaken
                                .each((Boolean eTaken, Boolean uTaken) -> Boolean.valueOf(!eTaken && !uTaken),
                                        "*emailTaken","*usernameTaken").out("*ok")

                                .ifTrue(new Expr(Ops.EQUAL, "*ok", true),
                                        Block
                                                // Create user, indices, and creds
                                                .each(() -> java.util.UUID.randomUUID().toString().replace("-", "")).out("*userId")
                                                .each(System::currentTimeMillis).out("*now")
                                                .each((String id, String un, String em, String fn, String mob, Long now) -> {
                                                    Map<String,Object> u = new HashMap<>();
                                                    u.put("userId", id);
                                                    u.put("username", un);
                                                    u.put("email", em);
                                                    u.put("fullName", fn);
                                                    u.put("mobile", mob);
                                                    u.put("status", "active");
                                                    u.put("createdAt", now);
                                                    u.put("updatedAt", now);
                                                    return u;
                                                }, "*userId","*usernameLower","*emailLower","*fullName","*mobile","*now").out("*userObj")
                                                .localTransform("$$usersById",     Path.key("*userId").termVal("*userObj"))
                                                .localTransform("$$emailIndex",    Path.key("*emailLower").termVal("*userId"))
                                                .localTransform("$$usernameIndex", Path.key("*usernameLower").termVal("*userId"))

                                                // creds: store SHA-256 hash string and algo label
                                                .each((String hash, Long ts) -> {
                                                    Map<String,Object> c = new HashMap<>();
                                                    c.put("algo","sha256");
                                                    c.put("hash", hash);
                                                    c.put("ts", ts);
                                                    return c;
                                                }, "*passSha256","*now").out("*cred")
                                                .localTransform("$$credsByUser", Path.key("*userId").termVal("*cred"))
                                )
                )

                // ---------------- UpdateUserRequested ----------------
                .ifTrue(new Expr(Ops.EQUAL, "*type", "UpdateUserRequested"),
                        Block
                                .each(Ops.GET, "*e", "userId").out("*uid")
                                .each(Ops.GET, "*e", "email").out("*emailRaw")
                                .each(Ops.GET, "*e", "fullName").out("*newFullName")
                                .each(Ops.GET, "*e", "mobile").out("*newMobile")
                                .each((String s) -> s == null ? null : s.trim().toLowerCase(), "*emailRaw").out("*newEmailLower")

                                // Check email uniqueness only if provided
                                .each(() -> Boolean.TRUE).out("*emailOk")
                                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*newEmailLower"),
                                        Block
                                                .hashPartition("*newEmailLower")
                                                .localSelect("$$emailIndex", Path.key("*newEmailLower")).out("*uidByNewEmail")
                                                // Assume OK by default
                                                .each(() -> Boolean.TRUE).out("*tmpEmailOk")
                                                // If some uid holds that email, ensure it's either the same user or stale
                                                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*uidByNewEmail"),
                                                        Block
                                                                .hashPartition("*uidByNewEmail")
                                                                .localSelect("$$usersById", Path.key("*uidByNewEmail")).out("*uAtEmail")
                                                                .each(Ops.GET, "*uAtEmail", "email").out("*curEmailOnOwner")
                                                                .each((String ownerUid, String curEmail, String targetEmail, String thisUid) ->
                                                                                Boolean.valueOf(ownerUid.equals(thisUid) || (curEmail == null || !curEmail.equals(targetEmail))),
                                                                        "*uidByNewEmail","*curEmailOnOwner","*newEmailLower","*uid").out("*tmpEmailOk")
                                                )
                                                .each(Ops.IDENTITY, "*tmpEmailOk").out("*emailOk")
                                )

                                // Apply update if user exists and email OK
                                .hashPartition("*uid")
                                .localSelect("$$usersById", Path.key("*uid")).out("*u")
                                .ifTrue(
                                        new Expr(Ops.AND,
                                                new Expr(Ops.IS_NOT_NULL, "*u"),
                                                new Expr(Ops.EQUAL, "*emailOk", true)
                                        ),
                                        Block
                                                .each(System::currentTimeMillis).out("*now2")
                                                .each((Map u, String nf, String nm, String ne, Long now) -> {
                                                    if (u == null) return null;
                                                    if (nf != null) u.put("fullName", nf);
                                                    if (nm != null) u.put("mobile", nm);
                                                    if (ne != null) u.put("email", ne); // write normalized (lower)
                                                    u.put("updatedAt", now);
                                                    return u;
                                                }, "*u","*newFullName","*newMobile","*newEmailLower","*now2").out("*u2")
                                                .localTransform("$$usersById", Path.key("*uid").termVal("*u2"))
                                                // update new email index if provided
                                                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*newEmailLower"),
                                                        Block.localTransform("$$emailIndex", Path.key("*newEmailLower").termVal("*uid"))
                                                )
                                )
                );

        // ===================== Auth / Sessions stream =====================
        StreamTopology auth = topologies.stream("auth");

        auth.pstate("$$sessionsById",          PState.mapSchema(String.class, java.util.Map.class));
        auth.pstate("$$refreshById",           PState.mapSchema(String.class, java.util.Map.class));
        auth.pstate("$$refreshIdBySessionId",  PState.mapSchema(String.class, String.class));

        auth.source("*auth_events").out("*e")
                .each(Ops.GET, "*e", "type").out("*type")

                // ---------------- CreateSession ----------------
                .ifTrue(new Expr(Ops.EQUAL, "*type", "CreateSession"),
                        Block
                                .each(Ops.GET, "*e", "sessionId").out("*sid")
                                .each(Ops.GET, "*e", "userId").out("*uid")
                                .each(Ops.GET, "*e", "refreshId").out("*rid")
                                .each(Ops.GET, "*e", "expiresAtMs").out("*exp")
                                .each(Ops.GET, "*e", "refreshExpiresAtMs").out("*rexp")
                                .each(System::currentTimeMillis).out("*now")

                                // Fill default expiries if not provided
                                .each((Long exp, Long now) -> Long.valueOf(exp != null ? exp : now + ACCESS_TTL_MS), "*exp","*now").out("*sessExp")
                                .each((Long re, Long now) -> Long.valueOf(re != null ? re : now + REFRESH_TTL_MS), "*rexp","*now").out("*refExp")

                                .each((String sid, String uid, Long now, Long exp) -> {
                                    Map<String,Object> s = new HashMap<>();
                                    s.put("sessionId", sid);
                                    s.put("userId", uid);
                                    s.put("createdAt", now);
                                    s.put("expiresAtMs", exp);
                                    s.put("revoked", Boolean.FALSE);
                                    return s;
                                }, "*sid","*uid","*now","*sessExp").out("*sessObj")
                                .localTransform("$$sessionsById", Path.key("*sid").termVal("*sessObj"))

                                .each((String rid, String sid, String uid, Long now, Long exp) -> {
                                    Map<String,Object> r = new HashMap<>();
                                    r.put("refreshId", rid);
                                    r.put("sessionId", sid);
                                    r.put("userId", uid);
                                    r.put("createdAt", now);
                                    r.put("expiresAtMs", exp);
                                    r.put("revoked", Boolean.FALSE);
                                    return r;
                                }, "*rid","*sid","*uid","*now","*refExp").out("*refObj")
                                .localTransform("$$refreshById", Path.key("*rid").termVal("*refObj"))
                                .localTransform("$$refreshIdBySessionId", Path.key("*sid").termVal("*rid"))
                )

                // ---------------- LogoutRequested ----------------
                .ifTrue(new Expr(Ops.EQUAL, "*type", "LogoutRequested"),
                        Block
                                .each(Ops.GET, "*e", "sessionId").out("*sid")
                                .hashPartition("*sid")
                                .localSelect("$$sessionsById", Path.key("*sid")).out("*s")
                                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*s"),
                                        Block
                                                // Mark session revoked
                                                .each((Map s) -> { s.put("revoked", Boolean.TRUE); return s; }, "*s").out("*s2")
                                                .localTransform("$$sessionsById", Path.key("*sid").termVal("*s2"))
                                                // Also revoke its refresh token if we have it
                                                .localSelect("$$refreshIdBySessionId", Path.key("*sid")).out("*rid")
                                                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*rid"),
                                                        Block
                                                                .localSelect("$$refreshById", Path.key("*rid")).out("*r")
                                                                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*r"),
                                                                        Block.each((Map r) -> { r.put("revoked", Boolean.TRUE); return r; }, "*r").out("*r2")
                                                                                .localTransform("$$refreshById", Path.key("*rid").termVal("*r2"))
                                                                )
                                                )
                                )
                );

        // ===================== Queries =====================

        // 1) canRegister(emailLower, usernameLower) -> boolean
        topologies.query("canRegister", "*emailLower", "*usernameLower").out("*ok")
                // email check (stale-safe)
                .hashPartition("*emailLower")
                .localSelect("$$emailIndex", Path.key("*emailLower")).out("*uidByEmailIdx")
                .each(() -> Boolean.FALSE).out("*emailTaken")
                .ifTrue(new Expr(Ops.IS_NOT_NULL, "*uidByEmailIdx"),
                        Block
                                .hashPartition("*uidByEmailIdx")
                                .localSelect("$$usersById", Path.key("*uidByEmailIdx")).out("*uEmail")
                                .each(Ops.GET, "*uEmail", "email").out("*emailOnUser")
                                .each((String cur, String want) -> Boolean.valueOf(cur != null && cur.equals(want)),
                                        "*emailOnUser", "*emailLower").out("*emailTaken")
                )
                // username check (authoritative index)
                .hashPartition("*usernameLower")
                .localSelect("$$usernameIndex", Path.key("*usernameLower")).out("*uidByUsernameIdx")
                .each((String v) -> Boolean.valueOf(v != null), "*uidByUsernameIdx").out("*usernameTaken")
                // ok = !emailTaken && !usernameTaken
                .each((Boolean eTaken, Boolean uTaken) -> Boolean.valueOf(!eTaken && !uTaken),
                        "*emailTaken","*usernameTaken").out("*ok")
                .originPartition();

        // 2) getUserIdByUsername(usernameLower) -> userId or null
        topologies.query("getUserIdByUsername", "*usernameLower").out("*userId")
                .hashPartition("*usernameLower")
                .localSelect("$$usernameIndex", Path.key("*usernameLower")).out("*userId")
                .originPartition();

        // 3) getUserSlimByUsername(usernameLower) -> {userId, username, status} or null
        topologies.query("getUserSlimByUsername", "*usernameLower").out("*out")
                .hashPartition("*usernameLower")
                .localSelect("$$usernameIndex", Path.key("*usernameLower")).out("*uid")
                .ifTrue(new Expr(Ops.IS_NULL, "*uid"),
                        Block.each(() -> null).out("*out"),
                        Block
                                .hashPartition("*uid")
                                .localSelect("$$usersById", Path.key("*uid")).out("*u")
                                .each((Map u) -> {
                                    if (u == null) return null;
                                    Map<String,Object> m = new HashMap<>();
                                    m.put("userId",   u.get("userId"));
                                    m.put("username", u.get("username"));
                                    Object st = u.get("status");
                                    m.put("status", st == null ? "active" : st);
                                    return m;
                                }, "*u").out("*out")
                )
                .originPartition();

        // 4) getUserById(userId) -> full user or null
        topologies.query("getUserById", "*userId").out("*u")
                .hashPartition("*userId")
                .localSelect("$$usersById", Path.key("*userId")).out("*u")
                .originPartition();

        // 5) authenticate(usernameLower, passwordSha256) -> userId or null
        topologies.query("authenticate", "*usernameLower", "*passwordSha256").out("*userId")
                .hashPartition("*usernameLower")
                .localSelect("$$usernameIndex", Path.key("*usernameLower")).out("*uid")
                .ifTrue(new Expr(Ops.IS_NULL, "*uid"),
                        Block.each(() -> null).out("*userId"),
                        Block
                                .hashPartition("*uid")
                                .localSelect("$$credsByUser", Path.key("*uid")).out("*cred")
                                .each((Map cred, String provided) -> {
                                    if (cred == null) return null;
                                    Object algo = cred.get("algo");
                                    Object hash = cred.get("hash");
                                    boolean ok = "sha256".equals(algo) && hash != null && hash.equals(provided);
                                    return ok ? cred.getOrDefault("userId", null) : null; // may not have userId in cred map
                                }, "*cred", "*passwordSha256").out("*tmpUserId")
                                // If cred map didn’t carry userId, return *uid when ok
                                .each((String tmp, String uid) -> tmp != null ? tmp : uid, "*tmpUserId","*uid").out("*userId")
                )
                .originPartition();

        // 6) checkSession(sessionId) -> session map or null (enforces expiry/revocation)
        topologies.query("checkSession", "*sessionId").out("*sessOut")
                .hashPartition("*sessionId")
                .localSelect("$$sessionsById", Path.key("*sessionId")).out("*s")
                .each(System::currentTimeMillis).out("*now")
                .each((Map s, Long now) -> {
                    if (s == null) return null;
                    Object revoked = s.get("revoked");
                    Object exp     = s.get("expiresAtMs");
                    long expMs = (exp instanceof Number) ? ((Number)exp).longValue() : Long.MIN_VALUE;
                    boolean ok = Boolean.FALSE.equals(revoked) && now < expMs;
                    return ok ? s : null;
                }, "*s","*now").out("*sessOut")
                .originPartition();

        // 7) validateRefresh(refreshId) -> refresh map or null
        topologies.query("validateRefresh", "*refreshId").out("*refreshOut")
                .hashPartition("*refreshId")
                .localSelect("$$refreshById", Path.key("*refreshId")).out("*r")
                .each(System::currentTimeMillis).out("*now")
                .each((Map r, Long now) -> {
                    if (r == null) return null;
                    Object revoked = r.get("revoked");
                    Object exp     = r.get("expiresAtMs");
                    long expMs = (exp instanceof Number) ? ((Number)exp).longValue() : Long.MIN_VALUE;
                    boolean ok = Boolean.FALSE.equals(revoked) && now < expMs;
                    return ok ? r : null;
                }, "*r","*now").out("*refreshOut")
                .originPartition();
    }
}