package com.ssafy.demo.security.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import com.ssafy.demo.security.dto.TokenDto;

@Component
@RequiredArgsConstructor
public class JwtAuthSuccessHandler implements AuthenticationSuccessHandler {
    // 1. 필요한 의존성 주입
    private final TokenProvider tokenProvider;
    private final CookieFactory cookieFactory;

    // 2. 인증 성공 시 호출되는 메서드
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                      HttpServletResponse response,
                                      Authentication authentication) {
        // 2-1. 토큰 생성
        TokenDto.Response tokenResponse = tokenProvider.generateToken(authentication);
        
        // 2-2. 쿠키 설정
        cookieFactory.addAccessCookie(response, tokenResponse.getAccessToken());
        cookieFactory.addRefreshCookie(response, tokenResponse.getRefreshToken());
        
        // 2-3. 응답 상태 설정
        response.setStatus(HttpServletResponse.SC_OK);
    }
} 