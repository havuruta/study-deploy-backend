package com.ssafy.demo.security.jwt;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class CookieFactory {

    private static final String SAME_SITE_ATTRIBUTE = "SameSite";
    private static final String SAME_SITE_VALUE = "None";
    private static final String PATH_VALUE = "/";

    public void addAccessCookie(HttpServletResponse response, String token) {
        ResponseCookie cookie = ResponseCookie.from(TokenProvider.ACCESS_TOKEN_COOKIE_NAME, token)
                .httpOnly(true)
                .secure(true)
                .path(PATH_VALUE)
                .sameSite(SAME_SITE_VALUE)
                .maxAge(TokenProvider.ACCESS_TOKEN_EXPIRE_TIME / 1000)
                .build();
        
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void addRefreshCookie(HttpServletResponse response, String token) {
        ResponseCookie cookie = ResponseCookie.from(TokenProvider.REFRESH_TOKEN_COOKIE_NAME, token)
                .httpOnly(true)
                .secure(true)
                .path(PATH_VALUE)
                .sameSite(SAME_SITE_VALUE)
                .maxAge(TokenProvider.REFRESH_TOKEN_EXPIRE_TIME / 1000)
                .build();
        
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    public void clearCookies(HttpServletResponse response) {
        ResponseCookie accessCookie = ResponseCookie.from(TokenProvider.ACCESS_TOKEN_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .path(PATH_VALUE)
                .sameSite(SAME_SITE_VALUE)
                .maxAge(0)
                .build();
        
        ResponseCookie refreshCookie = ResponseCookie.from(TokenProvider.REFRESH_TOKEN_COOKIE_NAME, "")
                .httpOnly(true)
                .secure(true)
                .path(PATH_VALUE)
                .sameSite(SAME_SITE_VALUE)
                .maxAge(0)
                .build();
        
        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
    }

    /**
     * 쿠키를 만료시키는 메서드
     * @param response HTTP 응답 객체
     * @param cookieName 만료시킬 쿠키 이름
     */
    public void expireCookie(HttpServletResponse response, String cookieName) {
        ResponseCookie cookie = ResponseCookie.from(cookieName, "")
                .path("/")
                .maxAge(0)
                .httpOnly(true)
                .secure(true)
                .sameSite("None")
                .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }

    /**
     * 모든 인증 관련 쿠키를 만료시키는 메서드
     * @param response HTTP 응답 객체
     */
    public void expireAllCookies(HttpServletResponse response) {
        expireCookie(response, TokenProvider.ACCESS_TOKEN_COOKIE_NAME);
        expireCookie(response, TokenProvider.REFRESH_TOKEN_COOKIE_NAME);
    }
} 