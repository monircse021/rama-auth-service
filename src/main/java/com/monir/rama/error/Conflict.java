package com.monir.rama.error;

public class Conflict extends HttpError {
    public Conflict(String msg){ super(409, msg); }
}
