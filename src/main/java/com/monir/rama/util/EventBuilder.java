package com.monir.rama.util;

import java.util.HashMap;
import java.util.Map;

public final class EventBuilder {
    private EventBuilder(){}
    public static Map<String,Object> of(Object... kv){
        Map<String,Object> m = new HashMap<>();
        for (int i=0;i+1<kv.length;i+=2) {
            m.put(String.valueOf(kv[i]), kv[i+1]);
        }
        return m;
    }
}
