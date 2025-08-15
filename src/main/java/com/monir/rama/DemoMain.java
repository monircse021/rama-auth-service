//package com.monir.rama;
//
//import com.rpl.rama.Depot;
//import com.rpl.rama.test.InProcessCluster;
//import com.rpl.rama.test.LaunchConfig;
//
//import java.util.HashMap;
//import java.util.Map;
//import java.util.UUID;
//
//public class DemoMain {
//    public static void main(String[] args) throws Exception {
//        try (InProcessCluster cluster = InProcessCluster.create()) {
//            cluster.launchModule(new AuthModule(), new LaunchConfig(1, 1));
//            System.out.println("AuthModule launched on InProcessCluster.");
//
//            Depot reg = cluster.clusterDepot(AuthModule.class.getName(), "*registration_cmds");
//
//            Map<String, Object> evt = new HashMap<>();
//            evt.put("type", "RegisterRequested");
//            evt.put("requestId", UUID.randomUUID().toString());
//            evt.put("email", "monircse021@gmail.com");
//            evt.put("name", "Manirul");
//
//            reg.append(evt);
//
//            Thread.sleep(1500L);
//            System.out.println("Sample event appended.");
//        }
//    }
//}