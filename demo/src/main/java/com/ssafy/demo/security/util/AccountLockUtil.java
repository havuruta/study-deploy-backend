package com.ssafy.demo.security.util;

import java.time.LocalDateTime;
import org.springframework.stereotype.Component;

import com.ssafy.demo.exception.ErrorMessage;
import com.ssafy.demo.exception.auth.AccountLockedException;
import com.ssafy.demo.exception.auth.TooManyLoginAttemptsException;
import com.ssafy.demo.user.entity.User;

@Component
public class AccountLockUtil {
    // 1. 상수 정의
    private static final int MAX_LOGIN_ATTEMPTS = 5;
    private static final int LOCK_DURATION_MINUTES = 30;

    // 2. 로그인 시도 체크
    public void checkLoginAttempts(User user) {
        if (user.getLoginAttempts() >= MAX_LOGIN_ATTEMPTS) {
            if (isLockExpired(user.getLastLoginAttempt())) {
                // 잠금 시간이 만료되었다면 로그인 시도 횟수 초기화
                resetLoginAttempts(user);
            } else {
                throw new AccountLockedException(ErrorMessage.ACCOUNT_LOCKED);
            }
        }
    }

    // 3. 로그인 실패 처리
    public void handleLoginFailure(User user) {
        int attempts = user.getLoginAttempts() + 1;
        user.setLoginAttempts(attempts);
        user.setLastLoginAttempt(LocalDateTime.now());

        if (attempts >= MAX_LOGIN_ATTEMPTS) {
            throw new TooManyLoginAttemptsException(ErrorMessage.TOO_MANY_LOGIN_ATTEMPTS);
        }
    }

    // 4. 로그인 성공 처리
    public void handleLoginSuccess(User user) {
        resetLoginAttempts(user);
    }

    // 5. 로그인 시도 횟수 초기화
    private void resetLoginAttempts(User user) {
        user.setLoginAttempts(0);
        user.setLastLoginAttempt(null);
    }

    // 6. 잠금 만료 체크
    private boolean isLockExpired(LocalDateTime lastAttempt) {
        if (lastAttempt == null) return true;
        return LocalDateTime.now().isAfter(lastAttempt.plusMinutes(LOCK_DURATION_MINUTES));
    }

    // 7. 계정 잠금 해제
    public void unlockAccount(User user) {
        resetLoginAttempts(user);
    }

    // 8. 계정 잠금 상태 확인
    public boolean isAccountLocked(User user) {
        return user.getLoginAttempts() >= MAX_LOGIN_ATTEMPTS && 
               !isLockExpired(user.getLastLoginAttempt());
    }

    // 9. 남은 잠금 시간 계산
    public long getRemainingLockTime(User user) {
        if (!isAccountLocked(user)) return 0;
        
        LocalDateTime lockExpiryTime = user.getLastLoginAttempt().plusMinutes(LOCK_DURATION_MINUTES);
        return java.time.Duration.between(LocalDateTime.now(), lockExpiryTime).toMinutes();
    }
} 