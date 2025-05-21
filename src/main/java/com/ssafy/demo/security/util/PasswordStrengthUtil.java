package com.ssafy.demo.security.util;

import org.springframework.stereotype.Component;

@Component
public class PasswordStrengthUtil {
    // 1. 비밀번호 강도 레벨 정의
    public enum PasswordStrength {
        WEAK(1, "약함"),
        MEDIUM(2, "보통"),
        STRONG(3, "강함"),
        VERY_STRONG(4, "매우 강함");

        private final int level;
        private final String description;

        PasswordStrength(int level, String description) {
            this.level = level;
            this.description = description;
        }

        public int getLevel() {
            return level;
        }

        public String getDescription() {
            return description;
        }
    }

    // 2. 비밀번호 강도 계산
    public PasswordStrength calculatePasswordStrength(String password) {
        if (password == null || password.isEmpty()) {
            return PasswordStrength.WEAK;
        }

        int score = 0;

        // 길이 점수
        if (password.length() >= 12) score += 2;
        else if (password.length() >= 8) score += 1;

        // 문자 종류 점수
        if (password.matches(".*[A-Z].*")) score += 1;  // 대문자
        if (password.matches(".*[a-z].*")) score += 1;  // 소문자
        if (password.matches(".*\\d.*")) score += 1;    // 숫자
        if (password.matches(".*[@$!%*#?&].*")) score += 1;  // 특수문자

        // 연속된 문자 체크 (점수 감소)
        if (hasConsecutiveChars(password)) score -= 1;

        // 반복된 문자 체크 (점수 감소)
        if (hasRepeatedChars(password)) score -= 1;

        // 최종 강도 결정
        if (score >= 5) return PasswordStrength.VERY_STRONG;
        if (score >= 4) return PasswordStrength.STRONG;
        if (score >= 3) return PasswordStrength.MEDIUM;
        return PasswordStrength.WEAK;
    }

    // 3. 연속된 문자 체크
    private boolean hasConsecutiveChars(String password) {
        for (int i = 0; i < password.length() - 2; i++) {
            if (isConsecutive(password.charAt(i), password.charAt(i + 1), password.charAt(i + 2))) {
                return true;
            }
        }
        return false;
    }

    private boolean isConsecutive(char a, char b, char c) {
        return (a + 1 == b && b + 1 == c) || (a - 1 == b && b - 1 == c);
    }

    // 4. 반복된 문자 체크
    private boolean hasRepeatedChars(String password) {
        for (int i = 0; i < password.length() - 2; i++) {
            if (password.charAt(i) == password.charAt(i + 1) && 
                password.charAt(i + 1) == password.charAt(i + 2)) {
                return true;
            }
        }
        return false;
    }

    // 5. 비밀번호 강도 검증
    public boolean isPasswordStrongEnough(String password) {
        return calculatePasswordStrength(password).getLevel() >= PasswordStrength.STRONG.getLevel();
    }
} 