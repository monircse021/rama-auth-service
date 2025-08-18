package com.monir.rama.util;

public final class RequestValidator {
    private RequestValidator(){}
    public static void requireNonEmpty(String s, String msg){
        if (s==null || s.isBlank()) throw new com.monir.rama.util.ResponseUtil.BadReq(msg);
    }
}
