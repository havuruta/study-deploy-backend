package com.ssafy.demo.exception.auth;

import org.springframework.security.core.AuthenticationException;

import com.ssafy.demo.exception.ErrorMessage;

public class InvalidTokenException extends AuthenticationException {
    public InvalidTokenException() {
        super(ErrorMessage.INVALID_TOKEN_EXCEPTION);
    }
}
