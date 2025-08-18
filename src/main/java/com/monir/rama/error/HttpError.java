package com.monir.rama.error;

public class HttpError extends RuntimeException {
    public final int status;
    public HttpError(int status, String msg){ super(msg); this.status = status; }
}
