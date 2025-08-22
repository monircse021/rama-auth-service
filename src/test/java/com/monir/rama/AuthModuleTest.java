package com.monir.rama;

import com.rpl.rama.Depot;
import com.rpl.rama.QueryTopologyClient;
import com.rpl.rama.test.InProcessCluster;
import com.rpl.rama.test.LaunchConfig;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;

import static org.junit.jupiter.api.Assertions.*;

public class AuthModuleTest {

    private Map<String, Object> registerEvt(String emailLower, String usernameLower, String fullName, String mobile, String pwdHash) {
        Map<String, Object> m = new HashMap<>();
        m.put("type", "RegisterRequested");
        m.put("emailLower", emailLower);
        m.put("usernameLower", usernameLower);
        m.put("fullName", fullName);
        m.put("mobileNumber", mobile);
        m.put("pwdHash", pwdHash);
        return m;
    }

    private Map<String, Object> userUpdatedEvt(String uid, String newEmailLower, String fullName, String mobile) {
        Map<String, Object> m = new HashMap<>();
        m.put("type", "UserUpdated");
        m.put("userId", uid);
        if (newEmailLower != null) m.put("emailLower", newEmailLower);
        if (fullName != null) m.put("fullName", fullName);
        if (mobile != null) m.put("mobileNumber", mobile);
        return m;
    }

    @Test
    public void registration_idempotent_and_email_index_cleanup_works() throws Exception {
        try (InProcessCluster cluster = InProcessCluster.create()) {
            cluster.launchModule(new AuthModule(), new LaunchConfig(1, 1));

            String module = AuthModule.class.getName();

            Depot regDepot = cluster.clusterDepot(module, "*registration_cmds");
            QueryTopologyClient byEmail = cluster.clusterQuery(module, "getUserIdByEmail");

            // Register Alice
            regDepot.append(registerEvt("alice@example.com", "alice", "Alice A.", "+8801000000000", "sha256:aaa"));
            spinUntilTrue(15000, () -> byEmail.invoke("alice@example.com") != null);

            String uidByEmail = (String) byEmail.invoke("alice@example.com");
            assertNotNull(uidByEmail);

            // Update Alice's email
            regDepot.append(userUpdatedEvt(uidByEmail, "alice2@example.com", null, null));
            System.out.println("Before waiting: " + byEmail.invoke("alice@example.com")); // Debug log

            // Wait for the old email index to be cleared
            spinUntilEquals(20000, () -> byEmail.invoke("alice@example.com"), null);

            System.out.println("After waiting: " + byEmail.invoke("alice@example.com")); // Debug log

            // Verify the new email index
            spinUntilTrue(15000, () -> byEmail.invoke("alice2@example.com") != null);
            String uidNew = (String) byEmail.invoke("alice2@example.com");
            assertEquals(uidByEmail, uidNew);
        }
    }

    // -------- Polling helpers (runtime-agnostic) --------
    private static void spinUntilTrue(long timeoutMs, Callable<Boolean> cond) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            Boolean v = cond.call();
            if (Boolean.TRUE.equals(v)) return;
            Thread.sleep(50);
        }
        fail("Timed out waiting for condition to become true");
    }

    private static void spinUntilEquals(long timeoutMs, Callable<Object> actual, Object expected) throws Exception {
        long deadline = System.currentTimeMillis() + timeoutMs;
        while (System.currentTimeMillis() < deadline) {
            Object v = actual.call();
            if ((expected == null && v == null) || (expected != null && expected.equals(v))) return;
            Thread.sleep(50);
        }
        fail("Timed out waiting for equality. expected=" + expected);
    }
}