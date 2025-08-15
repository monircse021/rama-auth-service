package com.monir.rama.util;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Map;

public final class Json {
    private Json() {}
    public static final ObjectMapper M = new ObjectMapper();
    public static Map<String,Object> readMap(InputStream is) throws Exception {
        return M.readValue(is, new TypeReference<Map<String,Object>>() {});
    }
    public static void write(OutputStream os, Object body) throws Exception {
        M.writeValue(os, body);
    }
}
