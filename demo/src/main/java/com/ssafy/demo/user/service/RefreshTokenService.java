package com.ssafy.demo.user.service;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.NoSuchElementException;

import com.ssafy.demo.exception.ErrorMessage;
import com.ssafy.demo.exception.auth.InvalidTokenException;
import com.ssafy.demo.security.dto.TokenDto;
import com.ssafy.demo.user.entity.RefreshToken;
import com.ssafy.demo.user.repository.RefreshTokenRepository;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    public void verifyAndDeleteRefreshToken(String key, TokenDto.Request tokenRequest) {
        // 저장소에서 Member ID 를 기반으로 Refresh Token 값 가져옴
        RefreshToken refreshToken = refreshTokenRepository.findByKey(key)
                .orElseThrow(() -> new NoSuchElementException(ErrorMessage.USER_ALREADY_LOGOUT));

        // Refresh Token 일치하는지 검사
        if (!refreshToken.getValue().equals(tokenRequest.getRefreshToken())) {
            throw new InvalidTokenException();
        }

        // 토큰 삭제 로직 (필요에 따라 구현)
        refreshTokenRepository.delete(refreshToken);
    }

}
