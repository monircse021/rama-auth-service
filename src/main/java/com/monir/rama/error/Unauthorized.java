package com.monir.rama.error;

public class Unauthorized extends HttpError {
    public Unauthorized(String msg){ super(401, msg); }
}
