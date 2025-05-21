package com.ssafy.demo.security.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger log = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    // 1. 쿠키 이름 상수 정의
    public static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";
    public static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";

    private final TokenProvider tokenProvider;

    // 2. 모든 요청에 대해 실행되는 필터 메서드
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        log.debug("JwtAuthenticationFilter 시작 - 요청 URI: {}", request.getRequestURI());

        try {
            // 3. 쿠키에서 JWT 토큰 추출
            String jwt = getJwtFromRequest(request);
            log.debug("추출된 JWT 토큰: {}", jwt);

            // 4. 토큰이 존재하고 유효한 경우 인증 처리
            if (StringUtils.hasText(jwt)) {
                log.debug("토큰 검증 시작");
                if (tokenProvider.validateToken(jwt)) {
                    log.debug("토큰 검증 성공");
                    // 5. 토큰으로부터 인증 정보 생성
                    Authentication authentication = tokenProvider.getAuthentication(jwt, request);
                    log.debug("생성된 Authentication: {}", authentication);
                    // 6. SecurityContext에 인증 정보 저장
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    log.debug("토큰 검증 실패");
                }
            } else {
                log.debug("요청에 토큰이 없습니다");
            }
        } catch (Exception e){
            log.error("Could not set user authentication in security context", e);
        }

        filterChain.doFilter(request, response);
    }

    // 7. 쿠키에서 JWT 토큰을 추출하는 메서드
    private String getJwtFromRequest(HttpServletRequest request) {
        jakarta.servlet.http.Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (jakarta.servlet.http.Cookie cookie : cookies) {
                if (ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;
    }
}
