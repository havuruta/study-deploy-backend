package com.ssafy.demo.security.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.stream.Collectors;

import com.ssafy.demo.exception.auth.InvalidTokenException;
import com.ssafy.demo.security.UserPrincipal;
import com.ssafy.demo.security.dto.TokenDto;

@Component
public class TokenProvider {
    private static final Logger log = LoggerFactory.getLogger(TokenProvider.class);

    // 1. JWT 관련 상수 정의
    public static final String AUTHORITIES_KEY = "auth";
    public static final String USER_ID = "id";
    public static final String USER_EMAIL = "email";
    public static final String BEARER_TYPE = "Bearer";
    public static final String ACCESS_TOKEN_COOKIE_NAME = "access_token";
    public static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";
    public static final long ACCESS_TOKEN_EXPIRE_TIME = 1000 * 60 * 30;            // 30분
    public static final long REFRESH_TOKEN_EXPIRE_TIME = 1000 * 60 * 60 * 24 * 7;  // 7일

    private final Key key;
    private final TokenBlacklist tokenBlacklist;
    private final long accessTokenValidityInMilliseconds;
    private final long refreshTokenValidityInMilliseconds;

    // 2. JWT 서명 키 초기화
    public TokenProvider(
            @Value("${jwt.secret}") String secretKey,
            @Value("${jwt.access-token-validity-in-seconds}") long accessTokenValidityInMilliseconds,
            @Value("${jwt.refresh-token-validity-in-seconds}") long refreshTokenValidityInMilliseconds,
            TokenBlacklist tokenBlacklist) {
        this.key = Keys.hmacShaKeyFor(secretKey.getBytes());
        this.accessTokenValidityInMilliseconds = accessTokenValidityInMilliseconds;
        this.refreshTokenValidityInMilliseconds = refreshTokenValidityInMilliseconds;
        this.tokenBlacklist = tokenBlacklist;
    }

    // 3. 토큰 생성 메서드
    public TokenDto.Response generateToken(Authentication authentication) {
        log.debug("토큰 생성 시작 - Authentication: {}", authentication);
        log.debug("Principal: {}", authentication.getPrincipal());
        log.debug("Authorities: {}", authentication.getAuthorities());

        // 3-1. 권한 정보 추출
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));
        log.debug("권한 문자열: {}", authorities);

        long now = (new Date()).getTime();
        log.debug("현재 시간: {}", now);

        // 3-2. 액세스 토큰 생성
        Date accessTokenExpiresIn = new Date(now + ACCESS_TOKEN_EXPIRE_TIME);
        log.debug("Access Token 만료 시간: {}", accessTokenExpiresIn);

        UserPrincipal userPrincipal = (UserPrincipal)authentication.getPrincipal();
        log.debug("UserPrincipal 정보 - ID: {}, Email: {}", userPrincipal.getId(), userPrincipal.getEmail());

        // 3-3. JWT 클레임 설정
        Claims claims = Jwts.claims();
        log.debug("새로운 Claims 객체 생성");

        claims.put(AUTHORITIES_KEY, authorities);
        claims.put(USER_ID, userPrincipal.getId());
        claims.put(USER_EMAIL, userPrincipal.getEmail());
        claims.setSubject(userPrincipal.getEmail());
        log.debug("Claims 설정 완료: {}", claims);

        // 3-4. 액세스 토큰 서명
        String accessToken = Jwts.builder()
            .setClaims(claims)
            .setExpiration(accessTokenExpiresIn)
            .signWith(key, SignatureAlgorithm.HS512)
            .compact();

        log.debug("생성된 Access Token: {}", accessToken);
        log.debug("Access Token 길이: {}", accessToken.length());
        log.debug("Access Token 만료 시간: {}", accessTokenExpiresIn);

        // 3-5. 리프레시 토큰 생성
        Date refreshTokenExpiresIn = new Date(now + REFRESH_TOKEN_EXPIRE_TIME);
        log.debug("Refresh Token 만료 시간: {}", refreshTokenExpiresIn);

        String refreshToken = Jwts.builder()
            .setExpiration(refreshTokenExpiresIn)
            .signWith(key, SignatureAlgorithm.HS512)
            .compact();

        log.debug("생성된 Refresh Token: {}", refreshToken);
        log.debug("Refresh Token 길이: {}", refreshToken.length());
        log.debug("Refresh Token 만료 시간: {}", refreshTokenExpiresIn);

        // 3-6. 토큰 응답 객체 생성
        TokenDto.Response response = TokenDto.Response.builder()
            .grantType(BEARER_TYPE)
            .accessToken(accessToken)
            .accessTokenExpiresIn(accessTokenExpiresIn.getTime())
            .refreshToken(refreshToken)
            .build();

        log.debug("생성된 TokenDto.Response: {}", response);
        return response;
    }

    // 4. 토큰으로부터 인증 정보를 추출하는 메서드
    public Authentication getAuthentication(String accessToken, HttpServletRequest request) {
        log.debug("토큰 인증 시작 - Access Token: {}", accessToken);
        
        // 4-1. 토큰 복호화
        Claims claims = parseClaims(accessToken);
        log.debug("복호화된 Claims: {}", claims);

        if (claims.get(AUTHORITIES_KEY) == null) {
            log.error("권한 정보가 없는 토큰입니다.");
            throw new InvalidTokenException();
        }

        // 4-2. 권한 정보 추출
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .toList();
        log.debug("추출된 권한: {}", authorities);

        // 4-3. UserPrincipal 객체 생성
        UserPrincipal principal = new UserPrincipal(
                Long.parseLong(claims.get(USER_ID).toString()),
                claims.get(USER_EMAIL).toString(),
                "",
                authorities
        );
        log.debug("생성된 UserPrincipal: {}", principal);

        // 4-4. Authentication 객체 생성 및 반환
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(principal, "", authorities);
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        return authentication;
    }

    // 5. 토큰 유효성 검증 메서드
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token);
            
            // 블랙리스트 체크
            if (tokenBlacklist.isBlacklisted(token)) {
                return false;
            }
            
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    // 6. 토큰 클레임 파싱 메서드
    private Claims parseClaims(String accessToken) {
        log.debug("토큰 파싱 시작 - Access Token: {}", accessToken);
        try {
            Claims claims = Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(accessToken).getBody();
            log.debug("파싱된 Claims: {}", claims);
            return claims;
        } catch (ExpiredJwtException e) {
            log.error("만료된 토큰 파싱 - Claims: {}", e.getClaims());
            return e.getClaims();
        }
    }

    /**
     * 액세스 토큰 만료 시간을 초 단위로 반환
     * @return 액세스 토큰 만료 시간(초)
     */
    public long getAccessTokenExpirationTime() {
        return accessTokenValidityInMilliseconds / 1000;
    }

    /**
     * 리프레시 토큰 만료 시간을 초 단위로 반환
     * @return 리프레시 토큰 만료 시간(초)
     */
    public long getRefreshTokenExpirationTime() {
        return refreshTokenValidityInMilliseconds / 1000;
    }
}
