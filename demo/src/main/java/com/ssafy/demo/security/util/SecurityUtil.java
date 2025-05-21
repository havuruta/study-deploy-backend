package com.ssafy.demo.security.util;

import java.util.regex.Pattern;
import org.springframework.stereotype.Component;

@Component
public class SecurityUtil {
    // 1. 정규식 패턴 정의
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
        "^[A-Za-z0-9+_.-]+@([A-Za-z0-9-]+\\.)+[A-Za-z]{2,}$"
    );
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[A-Za-z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!%*#?&]{8,20}$");

    // 2. 이메일 검증
    public static boolean isValidEmail(String email) {
        if (email == null || email.isEmpty()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email).matches();
    }

    // 3. 비밀번호 검증
    public static boolean isValidPassword(String password) {
        if (password == null || password.isEmpty()) {
            return false;
        }
        return password.matches(PASSWORD_PATTERN.pattern());
    }

    // 4. 비밀번호 복잡도 검증
    public static boolean hasRequiredPasswordComplexity(String password) {
        if (password == null) return false;
        
        boolean hasLetter = false;
        boolean hasDigit = false;
        boolean hasSpecial = false;
        
        for (char c : password.toCharArray()) {
            if (Character.isLetter(c)) hasLetter = true;
            else if (Character.isDigit(c)) hasDigit = true;
            else if ("@$!%*#?&".indexOf(c) >= 0) hasSpecial = true;
        }
        
        return hasLetter && hasDigit && hasSpecial;
    }

    // 5. 비밀번호 길이 검증
    public static boolean isValidPasswordLength(String password) {
        return password != null && password.length() >= 8 && password.length() <= 20;
    }

    public String maskEmail(String email) {
        if (email == null || email.isEmpty()) {
            return email;
        }

        int atIndex = email.indexOf('@');
        if (atIndex <= 1) {
            return email;
        }

        String name = email.substring(0, atIndex);
        String domain = email.substring(atIndex);
        
        if (name.length() <= 1) {
            return name + domain;
        }

        return name.charAt(0) + "*".repeat(name.length() - 1) + domain;
    }

    public String extractEmailDomain(String email) {
        if (email == null || email.isEmpty()) {
            return null;
        }

        int atIndex = email.indexOf('@');
        if (atIndex == -1 || atIndex == email.length() - 1) {
            return null;
        }

        return email.substring(atIndex + 1);
    }
} 