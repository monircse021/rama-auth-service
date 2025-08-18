package com.monir.rama.error;

public class BadRequest extends HttpError {
    public BadRequest(String msg){ super(400, msg); }
}
