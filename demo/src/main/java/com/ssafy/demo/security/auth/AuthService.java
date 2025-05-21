package com.ssafy.demo.security.auth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.NoSuchElementException;

import com.ssafy.demo.exception.ErrorMessage;
import com.ssafy.demo.exception.auth.InvalidTokenException;
import com.ssafy.demo.exception.auth.UserAlreadyExistsException;
import com.ssafy.demo.security.UserPrincipal;
import com.ssafy.demo.security.dto.AuthDto;
import com.ssafy.demo.security.dto.TokenDto;
import com.ssafy.demo.security.jwt.CookieFactory;
import com.ssafy.demo.security.jwt.TokenProvider;
import com.ssafy.demo.security.jwt.RedisRefreshTokenRepository;
import com.ssafy.demo.security.util.AccountLockUtil;
import com.ssafy.demo.security.util.SecurityUtil;
import com.ssafy.demo.user.entity.User;
import com.ssafy.demo.user.entity.RefreshToken;
import com.ssafy.demo.user.repository.UserRepository;
import com.ssafy.demo.user.service.UserService;
import com.ssafy.demo.security.jwt.TokenBlacklist;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final TokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManagerBuilder authenticationManagerBuilder;
    private final RedisRefreshTokenRepository refreshTokenRepository;
    private final CookieFactory cookieFactory;
    private final SecurityUtil securityUtil;
    private final AccountLockUtil accountLockUtil;
    private final TokenBlacklist tokenBlacklist;

    @Transactional
    public AuthDto.DefaultRequest signup(AuthDto.DefaultRequest defaultRequest) {
        // 1. 이메일 중복 체크
        if (userService.existsByEmail(defaultRequest.getEmail())) {
            throw new UserAlreadyExistsException(ErrorMessage.USER_ALREADY_EXIST);
        }

        // 2. 이메일 형식 검증
        if (!securityUtil.isValidEmail(defaultRequest.getEmail())) {
            throw new IllegalArgumentException(ErrorMessage.INVALID_EMAIL_FORMAT);
        }

        // 3. 비밀번호 유효성 검사
        if (!securityUtil.isValidPassword(defaultRequest.getPassword())) {
            throw new IllegalArgumentException(ErrorMessage.INVALID_PASSWORD_FORMAT);
        }

        User user = defaultRequest.toEntity(passwordEncoder);
        UserPrincipal.create(user);
        return AuthDto.DefaultRequest.toDto(userRepository.save(user));
    }

    @Transactional
    public TokenDto.Response login(AuthDto.DefaultRequest defaultRequest, HttpServletResponse response) {
        User user = userRepository.findByEmail(defaultRequest.getEmail())
                .orElseThrow(() -> new BadCredentialsException(ErrorMessage.USER_NOT_FOUND));

        try {
            // 1. 계정 잠금 상태 체크
            accountLockUtil.checkLoginAttempts(user);

            // 2. 인증 시도
            UsernamePasswordAuthenticationToken authenticationToken = defaultRequest.toAuthentication();
            Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

            // 3. 로그인 성공 처리
            accountLockUtil.handleLoginSuccess(user);
            userRepository.save(user);

            // 4. UserPrincipal 생성
            UserPrincipal userPrincipal = UserPrincipal.create(user);
            authentication = new UsernamePasswordAuthenticationToken(userPrincipal, null, userPrincipal.getAuthorities());

            // 5. 토큰 생성
            TokenDto.Response tokenResDto = tokenProvider.generateToken(authentication);

            // 6. 기존 리프레시 토큰 삭제
            refreshTokenRepository.deleteByKey(authentication.getName());

            // 7. 새로운 리프레시 토큰 저장
            refreshTokenRepository.save(
                authentication.getName(),
                tokenResDto.getRefreshToken(),
                tokenProvider.getRefreshTokenExpirationTime()
            );

            // 8. 쿠키에 토큰 설정
            cookieFactory.addAccessCookie(response, tokenResDto.getAccessToken());
            cookieFactory.addRefreshCookie(response, tokenResDto.getRefreshToken());

            return tokenResDto;

        } catch (AuthenticationException e) {
            // 9. 로그인 실패 처리
            accountLockUtil.handleLoginFailure(user);
            userRepository.save(user);
            throw new BadCredentialsException(ErrorMessage.INVALID_PASSWORD_FORMAT);
        }
    }

    /**
     * 로그아웃 처리
     * @param request HTTP 요청 객체
     * @param response HTTP 응답 객체
     */
    @Transactional
    public void logout(HttpServletRequest request, HttpServletResponse response) {
        // 1. 쿠키에서 토큰 추출
        String accessToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (TokenProvider.ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    accessToken = cookie.getValue();
                    break;
                }
            }
        }

        if (accessToken != null) {
            // 2. 액세스 토큰으로부터 인증 정보 추출
            Authentication authentication = tokenProvider.getAuthentication(accessToken, request);
            
            // 3. 리프레시 토큰 삭제
            refreshTokenRepository.deleteByKey(authentication.getName());
            
            // 4. 액세스 토큰을 블랙리스트에 추가
            tokenBlacklist.addToBlacklist(accessToken, tokenProvider.getAccessTokenExpirationTime());
        }
        
        // 5. 쿠키 만료 처리
        cookieFactory.expireAllCookies(response);
    }

    @Transactional
    public TokenDto.Response reissue(HttpServletRequest request, HttpServletResponse response) {
        // 1. 쿠키에서 토큰 추출
        String accessToken = null;
        String refreshToken = null;
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (TokenProvider.ACCESS_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    accessToken = cookie.getValue();
                }
                if (TokenProvider.REFRESH_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                    refreshToken = cookie.getValue();
                }
            }
        }

        if (accessToken == null || refreshToken == null) {
            throw new InvalidTokenException();
        }

        // 2. 리프레시 토큰 유효성 검증
        validateRefreshToken(refreshToken);

        // 3. 인증 정보 조회
        Authentication authentication = tokenProvider.getAuthentication(accessToken, request);
        
        // 4. 저장된 리프레시 토큰 조회
        String storedRefreshToken = getRefreshToken(authentication.getName());
        
        // 5. 토큰 일치 여부 검증
        validateTokenMatch(storedRefreshToken, refreshToken);

        // 6. 새로운 토큰 생성
        TokenDto.Response tokenResponse = tokenProvider.generateToken(authentication);
        
        // 7. 리프레시 토큰 업데이트
        refreshTokenRepository.save(
            authentication.getName(),
            tokenResponse.getRefreshToken(),
            tokenProvider.getRefreshTokenExpirationTime()
        );

        // 8. 새로운 쿠키 설정
        cookieFactory.addAccessCookie(response, tokenResponse.getAccessToken());
        cookieFactory.addRefreshCookie(response, tokenResponse.getRefreshToken());

        return tokenResponse;
    }

    private void validateRefreshToken(String refreshToken) {
        if (!tokenProvider.validateToken(refreshToken)) {
            throw new InvalidTokenException();
        }
    }

    private String getRefreshToken(String memberId) {
        return refreshTokenRepository.findByKey(memberId)
                .map(RefreshToken::getValue)
                .orElseThrow(() -> new NoSuchElementException(ErrorMessage.USER_ALREADY_LOGOUT));
    }

    private void validateTokenMatch(String storedToken, String providedToken) {
        if (!storedToken.equals(providedToken)) {
            throw new InvalidTokenException();
        }
    }
}
