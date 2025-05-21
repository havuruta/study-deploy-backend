package com.ssafy.demo.security.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class TokenValidationUtilTest {

    private final TokenValidationUtil tokenValidationUtil = new TokenValidationUtil();

    @Test
    @DisplayName("유효한 JWT 형식의 토큰은 true를 반환해야 함")
    void shouldReturnTrueForValidJwtFormat() {
        String validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assertThat(tokenValidationUtil.isValidTokenFormat(validToken)).isTrue();
    }

    @Test
    @DisplayName("잘못된 형식의 토큰은 false를 반환해야 함")
    void shouldReturnFalseForInvalidTokenFormat() {
        String[] invalidTokens = {
            null,
            "",
            "invalid.token",
            "header.payload",
            "header.payload.signature.extra",
            "not.a.jwt.token"
        };

        for (String token : invalidTokens) {
            assertThat(tokenValidationUtil.isValidTokenFormat(token)).isFalse();
        }
    }

    @Test
    @DisplayName("유효한 길이의 토큰은 true를 반환해야 함")
    void shouldReturnTrueForValidTokenLength() {
        String validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assertThat(tokenValidationUtil.isValidTokenLength(validToken)).isTrue();
    }

    @Test
    @DisplayName("잘못된 길이의 토큰은 false를 반환해야 함")
    void shouldReturnFalseForInvalidTokenLength() {
        String[] invalidTokens = {
            "too.short",
            "header.payload.signature".repeat(10) // 너무 긴 토큰
        };

        for (String token : invalidTokens) {
            assertThat(tokenValidationUtil.isValidTokenLength(token)).isFalse();
        }
    }

    @Test
    @DisplayName("유효한 구조의 토큰은 true를 반환해야 함")
    void shouldReturnTrueForValidTokenStructure() {
        String validToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        assertThat(tokenValidationUtil.hasValidTokenStructure(validToken)).isTrue();
    }

    @Test
    @DisplayName("잘못된 구조의 토큰은 false를 반환해야 함")
    void shouldReturnFalseForInvalidTokenStructure() {
        String[] invalidTokens = {
            "header.payload", // 서명이 없음
            "header..signature", // 페이로드가 없음
            ".payload.signature", // 헤더가 없음
            "header.payload.", // 서명이 비어있음
            "header..", // 페이로드와 서명이 비어있음
            "..signature" // 헤더와 페이로드가 비어있음
        };

        for (String token : invalidTokens) {
            assertThat(tokenValidationUtil.hasValidTokenStructure(token)).isFalse();
        }
    }

    @Test
    @DisplayName("만료된 토큰은 true를 반환해야 함")
    void shouldReturnTrueForExpiredToken() {
        long expiredTime = System.currentTimeMillis() / 1000 - 3600; // 1시간 전
        assertThat(tokenValidationUtil.isTokenExpired(expiredTime)).isTrue();
    }

    @Test
    @DisplayName("만료되지 않은 토큰은 false를 반환해야 함")
    void shouldReturnFalseForNonExpiredToken() {
        long futureTime = System.currentTimeMillis() / 1000 + 3600; // 1시간 후
        assertThat(tokenValidationUtil.isTokenExpired(futureTime)).isFalse();
    }

    @Test
    @DisplayName("미래에 발급된 토큰은 true를 반환해야 함")
    void shouldReturnTrueForFutureIssuedToken() {
        long futureTime = System.currentTimeMillis() / 1000 + 3600; // 1시간 후
        assertThat(tokenValidationUtil.isTokenIssuedInFuture(futureTime)).isTrue();
    }

    @Test
    @DisplayName("과거에 발급된 토큰은 false를 반환해야 함")
    void shouldReturnFalseForPastIssuedToken() {
        long pastTime = System.currentTimeMillis() / 1000 - 3600; // 1시간 전
        assertThat(tokenValidationUtil.isTokenIssuedInFuture(pastTime)).isFalse();
    }

    @Test
    @DisplayName("갱신 가능한 토큰은 true를 반환해야 함")
    void shouldReturnTrueForRefreshableToken() {
        long expiryTime = System.currentTimeMillis() / 1000 + 300; // 5분 후
        assertThat(tokenValidationUtil.isTokenRefreshable(expiryTime)).isTrue();
    }

    @Test
    @DisplayName("갱신 불가능한 토큰은 false를 반환해야 함")
    void shouldReturnFalseForNonRefreshableToken() {
        long[] nonRefreshableTimes = {
            System.currentTimeMillis() / 1000 - 3600, // 1시간 전
            System.currentTimeMillis() / 1000 + 600, // 10분 후
            System.currentTimeMillis() / 1000 + 3600 // 1시간 후
        };

        for (long time : nonRefreshableTimes) {
            assertThat(tokenValidationUtil.isTokenRefreshable(time)).isFalse();
        }
    }
} 