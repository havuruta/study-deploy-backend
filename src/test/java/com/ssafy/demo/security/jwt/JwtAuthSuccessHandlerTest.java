package com.ssafy.demo.security.jwt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import com.ssafy.demo.security.UserPrincipal;
import com.ssafy.demo.security.dto.TokenDto;

import java.util.Collections;

@ExtendWith(MockitoExtension.class)
class JwtAuthSuccessHandlerTest {

    @InjectMocks
    private JwtAuthSuccessHandler jwtAuthSuccessHandler;

    @Mock
    private TokenProvider tokenProvider;

    @Mock
    private CookieFactory cookieFactory;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private Authentication authentication;
    private TokenDto.Response tokenResponse;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        
        UserPrincipal userPrincipal = new UserPrincipal(1L, "test@test.com", "password", 
            Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));
        authentication = new org.springframework.security.authentication.UsernamePasswordAuthenticationToken(
            userPrincipal, null, userPrincipal.getAuthorities());
        
        tokenResponse = new TokenDto.Response("Bearer", "accessToken", "refreshToken", 3600L);
    }

    @Test
    @DisplayName("인증 성공 시 토큰 생성 및 쿠키 설정")
    void onAuthenticationSuccess() {
        // given
        when(tokenProvider.generateToken(authentication)).thenReturn(tokenResponse);

        // when
        jwtAuthSuccessHandler.onAuthenticationSuccess(request, response, authentication);

        // then
        // 1. 토큰 생성 검증
        verify(tokenProvider).generateToken(authentication);
        
        // 2. 쿠키 설정 검증
        verify(cookieFactory).addAccessCookie(response, tokenResponse.getAccessToken());
        verify(cookieFactory).addRefreshCookie(response, tokenResponse.getRefreshToken());
        
        // 3. 응답 상태 검증
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_OK);
    }
} 