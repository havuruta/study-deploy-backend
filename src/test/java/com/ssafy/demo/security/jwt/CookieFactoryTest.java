package com.ssafy.demo.security.jwt;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class CookieFactoryTest {

    private CookieFactory cookieFactory;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        cookieFactory = new CookieFactory();
        response = new MockHttpServletResponse();
    }

    @Test
    @DisplayName("액세스 토큰 쿠키 생성 속성 검증")
    void createAccessCookie() {
        String token = "access-token-value";
        cookieFactory.addAccessCookie(response, token);
        String cookieHeader = response.getHeader(HttpHeaders.SET_COOKIE);
        assertThat(cookieHeader).contains(TokenProvider.ACCESS_TOKEN_COOKIE_NAME);
        assertThat(cookieHeader).contains(token);
        assertThat(cookieHeader).contains("HttpOnly");
        assertThat(cookieHeader).contains("Secure");
        assertThat(cookieHeader).contains("Path=/");
        assertThat(cookieHeader).contains("SameSite=None");
        assertThat(cookieHeader).contains("Max-Age=");
    }

    @Test
    @DisplayName("리프레시 토큰 쿠키 생성 속성 검증")
    void createRefreshCookie() {
        String token = "refresh-token-value";
        cookieFactory.addRefreshCookie(response, token);
        String cookieHeader = response.getHeader(HttpHeaders.SET_COOKIE);
        assertThat(cookieHeader).contains(TokenProvider.REFRESH_TOKEN_COOKIE_NAME);
        assertThat(cookieHeader).contains(token);
        assertThat(cookieHeader).contains("HttpOnly");
        assertThat(cookieHeader).contains("Secure");
        assertThat(cookieHeader).contains("Path=/");
        assertThat(cookieHeader).contains("SameSite=None");
        assertThat(cookieHeader).contains("Max-Age=");
    }

    @Test
    @DisplayName("쿠키 만료(삭제) 속성 검증")
    void expireCookie() {
        cookieFactory.expireAllCookies(response);
        // 두 개의 만료 쿠키가 추가되어야 함
        var cookies = response.getHeaders(HttpHeaders.SET_COOKIE);
        assertThat(cookies).hasSize(2);
        boolean accessExpired = cookies.stream().anyMatch(c -> c.contains(TokenProvider.ACCESS_TOKEN_COOKIE_NAME) && c.contains("Max-Age=0"));
        boolean refreshExpired = cookies.stream().anyMatch(c -> c.contains(TokenProvider.REFRESH_TOKEN_COOKIE_NAME) && c.contains("Max-Age=0"));
        assertThat(accessExpired).isTrue();
        assertThat(refreshExpired).isTrue();
    }
} 