package com.ssafy.demo.security.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class SecurityUtilTest {

    private final SecurityUtil securityUtil = new SecurityUtil();

    @Test
    @DisplayName("null이나 빈 문자열은 false를 반환해야 함")
    void shouldReturnFalseForNullOrEmptyString() {
        assertThat(securityUtil.isValidEmail(null)).isFalse();
        assertThat(securityUtil.isValidEmail("")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "test@example.com",
        "user.name@domain.co.kr",
        "user+tag@example.com",
        "user@sub.domain.com"
    })
    @DisplayName("유효한 이메일 형식은 true를 반환해야 함")
    void shouldReturnTrueForValidEmail(String email) {
        assertThat(securityUtil.isValidEmail(email)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "invalid.email",
        "user@",
        "@domain.com",
        "user@.com",
        "user@domain.",
        "user name@domain.com",
        "user@domain com"
    })
    @DisplayName("잘못된 이메일 형식은 false를 반환해야 함")
    void shouldReturnFalseForInvalidEmail(String email) {
        assertThat(securityUtil.isValidEmail(email)).isFalse();
    }

    @Test
    @DisplayName("null이나 빈 문자열은 false를 반환해야 함")
    void shouldReturnFalseForNullOrEmptyPassword() {
        assertThat(securityUtil.isValidPassword(null)).isFalse();
        assertThat(securityUtil.isValidPassword("")).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "Password123!",
        "Complex1Pass!",
        "Str0ng!Pass",
        "P@ssw0rd"
    })
    @DisplayName("유효한 비밀번호 형식은 true를 반환해야 함")
    void shouldReturnTrueForValidPassword(String password) {
        assertThat(securityUtil.isValidPassword(password)).isTrue();
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "short",
        "no-upper-1!",
        "NO-LOWER-1!",
        "NoSpecialChar1",
        "NoNumber!",
        "too long password that exceeds maximum length"
    })
    @DisplayName("잘못된 비밀번호 형식은 false를 반환해야 함")
    void shouldReturnFalseForInvalidPassword(String password) {
        assertThat(securityUtil.isValidPassword(password)).isFalse();
    }

    @Test
    @DisplayName("이메일 마스킹이 올바르게 적용되어야 함")
    void shouldMaskEmailCorrectly() {
        assertThat(securityUtil.maskEmail("test@example.com")).isEqualTo("t***@example.com");
        assertThat(securityUtil.maskEmail("user.name@domain.co.kr")).isEqualTo("u********@domain.co.kr");
        assertThat(securityUtil.maskEmail("a@b.com")).isEqualTo("a@b.com");
    }

    @Test
    @DisplayName("null이나 빈 문자열은 그대로 반환해야 함")
    void shouldReturnSameForNullOrEmptyEmail() {
        assertThat(securityUtil.maskEmail(null)).isNull();
        assertThat(securityUtil.maskEmail("")).isEqualTo("");
    }

    @Test
    @DisplayName("이메일 도메인 추출이 올바르게 동작해야 함")
    void shouldExtractEmailDomainCorrectly() {
        assertThat(securityUtil.extractEmailDomain("test@example.com")).isEqualTo("example.com");
        assertThat(securityUtil.extractEmailDomain("user.name@domain.co.kr")).isEqualTo("domain.co.kr");
        assertThat(securityUtil.extractEmailDomain("invalid.email")).isNull();
    }

    @Test
    @DisplayName("null이나 빈 문자열은 null을 반환해야 함")
    void shouldReturnNullForNullOrEmptyEmailDomain() {
        assertThat(securityUtil.extractEmailDomain(null)).isNull();
        assertThat(securityUtil.extractEmailDomain("")).isNull();
    }
} 