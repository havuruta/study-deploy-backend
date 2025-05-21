package com.ssafy.demo.security.util;

import com.ssafy.demo.exception.auth.AccountLockedException;
import com.ssafy.demo.exception.auth.TooManyLoginAttemptsException;
import com.ssafy.demo.user.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class AccountLockUtilTest {

    private AccountLockUtil accountLockUtil;
    private User user;

    @BeforeEach
    void setUp() {
        accountLockUtil = new AccountLockUtil();
        user = User.builder()
                .email("test@example.com")
                .password("password")
                .loginAttempts(0)
                .build();
    }

    @Test
    @DisplayName("로그인 시도 횟수가 최대값 미만이면 예외가 발생하지 않아야 함")
    void shouldNotThrowExceptionWhenLoginAttemptsBelowMax() {
        user.setLoginAttempts(4);
        accountLockUtil.checkLoginAttempts(user);
        assertThat(user.getLoginAttempts()).isEqualTo(4);
    }

    @Test
    @DisplayName("로그인 시도 횟수가 최대값이고 잠금 시간이 만료되지 않았으면 AccountLockedException이 발생해야 함")
    void shouldThrowAccountLockedExceptionWhenMaxAttemptsAndNotExpired() {
        user.setLoginAttempts(5);
        user.setLastLoginAttempt(LocalDateTime.now());
        
        assertThatThrownBy(() -> accountLockUtil.checkLoginAttempts(user))
            .isInstanceOf(AccountLockedException.class);
    }

    @Test
    @DisplayName("로그인 시도 횟수가 최대값이고 잠금 시간이 만료되었으면 로그인 시도 횟수가 초기화되어야 함")
    void shouldResetLoginAttemptsWhenMaxAttemptsAndExpired() {
        user.setLoginAttempts(5);
        user.setLastLoginAttempt(LocalDateTime.now().minusMinutes(31));
        
        accountLockUtil.checkLoginAttempts(user);
        assertThat(user.getLoginAttempts()).isZero();
    }

    @Test
    @DisplayName("로그인 실패 시 로그인 시도 횟수가 증가해야 함")
    void shouldIncrementLoginAttemptsOnFailure() {
        accountLockUtil.handleLoginFailure(user);
        assertThat(user.getLoginAttempts()).isEqualTo(1);
    }

    @Test
    @DisplayName("로그인 실패 시 마지막 로그인 시도 시간이 업데이트되어야 함")
    void shouldUpdateLastLoginAttemptOnFailure() {
        LocalDateTime before = LocalDateTime.now().minusSeconds(1);
        accountLockUtil.handleLoginFailure(user);
        assertThat(user.getLastLoginAttempt()).isAfter(before);
    }

    @Test
    @DisplayName("로그인 시도 횟수가 최대값에 도달하면 TooManyLoginAttemptsException이 발생해야 함")
    void shouldThrowTooManyLoginAttemptsExceptionWhenMaxAttemptsReached() {
        user.setLoginAttempts(4);
        
        assertThatThrownBy(() -> accountLockUtil.handleLoginFailure(user))
            .isInstanceOf(TooManyLoginAttemptsException.class);
    }

    @Test
    @DisplayName("로그인 성공 시 로그인 시도 횟수가 초기화되어야 함")
    void shouldResetLoginAttemptsOnSuccess() {
        user.setLoginAttempts(3);
        user.setLastLoginAttempt(LocalDateTime.now());
        
        accountLockUtil.handleLoginSuccess(user);
        assertThat(user.getLoginAttempts()).isZero();
        assertThat(user.getLastLoginAttempt()).isNull();
    }

    @Test
    @DisplayName("계정 잠금 해제 시 로그인 시도 횟수가 초기화되어야 함")
    void shouldResetLoginAttemptsOnUnlock() {
        user.setLoginAttempts(5);
        user.setLastLoginAttempt(LocalDateTime.now());
        
        accountLockUtil.unlockAccount(user);
        assertThat(user.getLoginAttempts()).isZero();
        assertThat(user.getLastLoginAttempt()).isNull();
    }

    @Test
    @DisplayName("계정이 잠겨있지 않으면 남은 잠금 시간이 0이어야 함")
    void shouldReturnZeroRemainingTimeWhenNotLocked() {
        user.setLoginAttempts(4);
        assertThat(accountLockUtil.getRemainingLockTime(user)).isZero();
    }

    @Test
    @DisplayName("계정이 잠겨있으면 남은 잠금 시간이 계산되어야 함")
    void shouldCalculateRemainingLockTimeWhenLocked() {
        user.setLoginAttempts(5);
        user.setLastLoginAttempt(LocalDateTime.now().minusMinutes(10));
        
        long remainingTime = accountLockUtil.getRemainingLockTime(user);
        assertThat(remainingTime).isBetween(19L, 21L); // 30분 - 10분 = 약 20분
    }
} 