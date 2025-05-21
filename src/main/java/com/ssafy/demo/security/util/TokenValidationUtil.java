package com.ssafy.demo.security.util;

import org.springframework.stereotype.Component;
import java.util.regex.Pattern;
import java.util.Base64;

@Component
public class TokenValidationUtil {
    // 1. 토큰 형식 검증을 위한 정규식
    private static final Pattern JWT_PATTERN = Pattern.compile("^[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+\\.[A-Za-z0-9-_=]+$");
    private static final int MIN_TOKEN_LENGTH = 100;
    private static final int MAX_TOKEN_LENGTH = 1000;
    private static final long REFRESH_THRESHOLD = 300; // 5분
    private static final long MAX_FUTURE_ISSUE_TIME = 60; // 1분

    // 2. 토큰 형식 검증
    public boolean isValidTokenFormat(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        // 기본 JWT 형식 검사
        if (!JWT_PATTERN.matcher(token).matches()) {
            return false;
        }

        // Base64 디코딩 가능 여부 검사
        String[] parts = token.split("\\.");
        try {
            Base64.getUrlDecoder().decode(parts[0]); // header
            Base64.getUrlDecoder().decode(parts[1]); // payload
            Base64.getUrlDecoder().decode(parts[2]); // signature
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    // 3. 토큰 길이 검증
    public boolean isValidTokenLength(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        // 전체 토큰 길이 검사
        int totalLength = token.length();
        if (totalLength < MIN_TOKEN_LENGTH || totalLength > MAX_TOKEN_LENGTH) {
            return false;
        }

        // 각 부분의 길이 검사
        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }

        // 각 부분의 최소/최대 길이 검사
        for (String part : parts) {
            if (part.length() < 10 || part.length() > 500) { // 각 부분의 적절한 길이 범위
                return false;
            }
        }

        return true;
    }

    // 4. 토큰 구조 검증
    public boolean hasValidTokenStructure(String token) {
        if (token == null || token.isEmpty()) {
            return false;
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            return false;
        }

        // 각 부분이 비어있지 않은지 확인
        return !parts[0].isEmpty() && !parts[1].isEmpty() && !parts[2].isEmpty();
    }

    // 5. 토큰 만료 시간 검증
    public boolean isTokenExpired(long expiryTime) {
        long currentTime = System.currentTimeMillis() / 1000;
        return currentTime > expiryTime;
    }

    // 6. 토큰 발급 시간 검증
    public boolean isTokenIssuedInFuture(long issuedAt) {
        long currentTime = System.currentTimeMillis() / 1000;
        return issuedAt > currentTime + MAX_FUTURE_ISSUE_TIME;
    }

    // 7. 토큰 갱신 가능 여부 검증
    public boolean isTokenRefreshable(long expiryTime) {
        long currentTime = System.currentTimeMillis() / 1000;
        long timeUntilExpiry = expiryTime - currentTime;
        return timeUntilExpiry > 0 && timeUntilExpiry <= REFRESH_THRESHOLD;
    }
} 