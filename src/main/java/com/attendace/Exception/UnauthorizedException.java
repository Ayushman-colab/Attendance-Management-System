package com.attendace.Exception;

import org.springframework.http.HttpStatus;


public class UnauthorizedException extends ApiException {
    public UnauthorizedException(String message) {
        super(message, HttpStatus.UNAUTHORIZED);
    }
}