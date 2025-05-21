package com.ssafy.demo.security.util;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import static org.assertj.core.api.Assertions.assertThat;

class PasswordStrengthUtilTest {

    private final PasswordStrengthUtil passwordStrengthUtil = new PasswordStrengthUtil();

    @Test
    @DisplayName("null 또는 빈 문자열은 WEAK 레벨을 반환해야 함")
    void shouldReturnWeakForNullOrEmpty() {
        assertThat(passwordStrengthUtil.calculatePasswordStrength(null))
            .isEqualTo(PasswordStrengthUtil.PasswordStrength.WEAK);
        assertThat(passwordStrengthUtil.calculatePasswordStrength(""))
            .isEqualTo(PasswordStrengthUtil.PasswordStrength.WEAK);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "abc123",           // 너무 짧음
        "password",         // 문자만 있음
        "12345678",         // 숫자만 있음
        "!@#$%^&*"         // 특수문자만 있음
    })
    @DisplayName("약한 비밀번호는 WEAK 레벨을 반환해야 함")
    void shouldReturnWeakForWeakPasswords(String password) {
        assertThat(passwordStrengthUtil.calculatePasswordStrength(password))
            .isEqualTo(PasswordStrengthUtil.PasswordStrength.WEAK);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "Password123",      // 대문자, 소문자, 숫자
        "pass123!@#",      // 소문자, 숫자, 특수문자
        "PASS123!@#"       // 대문자, 숫자, 특수문자
    })
    @DisplayName("보통 비밀번호는 MEDIUM 레벨을 반환해야 함")
    void shouldReturnMediumForMediumPasswords(String password) {
        assertThat(passwordStrengthUtil.calculatePasswordStrength(password))
            .isEqualTo(PasswordStrengthUtil.PasswordStrength.MEDIUM);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "Password123!@#",   // 대문자, 소문자, 숫자, 특수문자
        "P@ssw0rd123",     // 대문자, 소문자, 숫자, 특수문자
        "Str0ng!P@ss"      // 대문자, 소문자, 숫자, 특수문자
    })
    @DisplayName("강한 비밀번호는 STRONG 레벨을 반환해야 함")
    void shouldReturnStrongForStrongPasswords(String password) {
        assertThat(passwordStrengthUtil.calculatePasswordStrength(password))
            .isEqualTo(PasswordStrengthUtil.PasswordStrength.STRONG);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "VeryStr0ng!P@ssw0rd123",  // 20자 이상, 모든 문자 종류 포함
        "P@ssw0rd!2024#Secure",    // 20자 이상, 모든 문자 종류 포함
        "S3cur3!P@ssw0rd2024"      // 20자 이상, 모든 문자 종류 포함
    })
    @DisplayName("매우 강한 비밀번호는 VERY_STRONG 레벨을 반환해야 함")
    void shouldReturnVeryStrongForVeryStrongPasswords(String password) {
        assertThat(passwordStrengthUtil.calculatePasswordStrength(password))
            .isEqualTo(PasswordStrengthUtil.PasswordStrength.VERY_STRONG);
    }

    @Test
    @DisplayName("연속된 문자를 포함한 비밀번호는 점수가 감소해야 함")
    void shouldDecreaseScoreForConsecutiveChars() {
        String password = "abc123!@#";  // 연속된 문자 'abc' 포함
        assertThat(passwordStrengthUtil.calculatePasswordStrength(password))
            .isEqualTo(PasswordStrengthUtil.PasswordStrength.MEDIUM);
    }

    @Test
    @DisplayName("반복된 문자를 포함한 비밀번호는 점수가 감소해야 함")
    void shouldDecreaseScoreForRepeatedChars() {
        String password = "aaa123!@#";  // 반복된 문자 'aaa' 포함
        assertThat(passwordStrengthUtil.calculatePasswordStrength(password))
            .isEqualTo(PasswordStrengthUtil.PasswordStrength.WEAK);
    }

    @Test
    @DisplayName("isPasswordStrongEnough는 STRONG 이상의 레벨에서 true를 반환해야 함")
    void shouldReturnTrueForStrongOrHigherPasswords() {
        assertThat(passwordStrengthUtil.isPasswordStrongEnough("Password123!@#")).isTrue();
        assertThat(passwordStrengthUtil.isPasswordStrongEnough("VeryStr0ng!P@ssw0rd123")).isTrue();
        assertThat(passwordStrengthUtil.isPasswordStrongEnough("weak123")).isFalse();
    }
} 