package com.ssafy.demo.security.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import jakarta.servlet.http.Cookie;

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
import com.ssafy.demo.user.entity.RefreshToken;
import com.ssafy.demo.user.entity.User;
import com.ssafy.demo.user.repository.UserRepository;
import com.ssafy.demo.user.service.UserService;
import com.ssafy.demo.security.jwt.TokenBlacklist;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @InjectMocks
    private AuthService authService;

    @Mock
    private TokenProvider tokenProvider;
    @Mock
    private UserRepository userRepository;
    @Mock
    private UserService userService;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private AuthenticationManagerBuilder authenticationManagerBuilder;
    @Mock
    private RedisRefreshTokenRepository refreshTokenRepository;
    @Mock
    private CookieFactory cookieFactory;
    @Mock
    private SecurityUtil securityUtil;
    @Mock
    private AccountLockUtil accountLockUtil;
    @Mock
    private TokenBlacklist tokenBlacklist;

    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private AuthDto.DefaultRequest defaultRequest;
    private User user;
    private TokenDto.Response tokenResponse;
    private Authentication authentication;
    private RefreshToken refreshToken;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        defaultRequest = new AuthDto.DefaultRequest("test@test.com", "password123!", null, null);
        user = User.builder()
                .email("test@test.com")
                .password("encodedPassword")
                .loginAttempts(0)
                .build();
        tokenResponse = new TokenDto.Response("Bearer", "accessToken", "refreshToken", 3600L);
        authentication = new UsernamePasswordAuthenticationToken(
                UserPrincipal.create(user), null, UserPrincipal.create(user).getAuthorities());
        refreshToken = RefreshToken.create("test@test.com", "refreshToken");
    }

    @Nested
    @DisplayName("회원가입 테스트")
    class SignupTest {

        /**
         * 정상적인 회원가입 테스트
         * - 목적: 유효한 이메일, 비밀번호, 중복 없는 경우 회원가입 성공 검증
         * - 종류: 정상 케이스(Positive Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("정상적인 회원가입")
        void signupSuccess() {
            // given
            when(userService.existsByEmail(defaultRequest.getEmail())).thenReturn(false);
            when(passwordEncoder.encode(defaultRequest.getPassword())).thenReturn("encodedPassword");
            when(userRepository.save(any(User.class))).thenReturn(user);

            // when
            AuthDto.DefaultRequest result = authService.signup(defaultRequest);

            // then
            assertThat(result.getEmail()).isEqualTo(defaultRequest.getEmail());
            verify(userService).existsByEmail(defaultRequest.getEmail());
            verify(userRepository).save(any(User.class));
        }

        /**
         * 이미 존재하는 이메일로 회원가입 시도 테스트
         * - 목적: 중복 이메일로 회원가입 시도 시 예외 발생 검증
         * - 종류: 예외 케이스(Negative Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("이미 존재하는 이메일로 회원가입 시도")
        void signupWithExistingEmail() {
            // given
            when(userService.existsByEmail(defaultRequest.getEmail())).thenReturn(true);

            // when & then
            assertThatThrownBy(() -> authService.signup(defaultRequest))
                    .isInstanceOf(UserAlreadyExistsException.class)
                    .hasMessageContaining(ErrorMessage.USER_ALREADY_EXIST);
        }

        /**
         * 잘못된 이메일 형식으로 회원가입 시도 테스트
         * - 목적: 잘못된 이메일 형식으로 회원가입 시도 시 예외 발생 검증
         * - 종류: 예외 케이스(Negative Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("잘못된 이메일 형식으로 회원가입 시도")
        void signupWithInvalidEmail() {
            // given
            AuthDto.DefaultRequest invalidEmailRequest = new AuthDto.DefaultRequest("invalid.email", "password123!", null, null);
            when(userService.existsByEmail(invalidEmailRequest.getEmail())).thenReturn(false);

            // when & then
            assertThatThrownBy(() -> authService.signup(invalidEmailRequest))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(ErrorMessage.INVALID_EMAIL_FORMAT);
        }

        /**
         * 잘못된 비밀번호 형식으로 회원가입 시도 테스트
         * - 목적: 잘못된 비밀번호 형식으로 회원가입 시도 시 예외 발생 검증
         * - 종류: 예외 케이스(Negative Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("잘못된 비밀번호 형식으로 회원가입 시도")
        void signupWithInvalidPassword() {
            // given
            AuthDto.DefaultRequest invalidPasswordRequest = new AuthDto.DefaultRequest("test@test.com", "short", null, null);
            when(userService.existsByEmail(invalidPasswordRequest.getEmail())).thenReturn(false);

            // when & then
            assertThatThrownBy(() -> authService.signup(invalidPasswordRequest))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining(ErrorMessage.INVALID_PASSWORD_FORMAT);
        }
    }

    @Nested
    @DisplayName("로그인 테스트")
    class LoginTest {

        /**
         * 정상적인 로그인 테스트
         * - 목적: 유효한 이메일, 비밀번호로 로그인 성공 및 토큰/쿠키 발급, 계정 잠금 해제 등 부수효과 검증
         * - 종류: 정상 케이스(Positive Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("정상적인 로그인")
        void loginSuccess() {
            // given
            when(userRepository.findByEmail(defaultRequest.getEmail())).thenReturn(Optional.of(user));
            when(authenticationManagerBuilder.getObject()).thenReturn(authentication -> authentication);
            when(tokenProvider.generateToken(any(Authentication.class))).thenReturn(tokenResponse);
            when(tokenProvider.getRefreshTokenExpirationTime()).thenReturn(3600L);

            // when
            TokenDto.Response result = authService.login(defaultRequest, response);

            // then
            assertThat(result).isNotNull();
            assertThat(result.getAccessToken()).isEqualTo(tokenResponse.getAccessToken());
            assertThat(result.getRefreshToken()).isEqualTo(tokenResponse.getRefreshToken());
            verify(accountLockUtil).checkLoginAttempts(user);
            verify(accountLockUtil).handleLoginSuccess(user);
            verify(refreshTokenRepository).deleteByKey(any());
            verify(refreshTokenRepository).save(
                anyString(),
                anyString(),
                anyLong()
            );
            verify(cookieFactory).addAccessCookie(response, tokenResponse.getAccessToken());
            verify(cookieFactory).addRefreshCookie(response, tokenResponse.getRefreshToken());
        }

        /**
         * 존재하지 않는 이메일로 로그인 시도 테스트
         * - 목적: 존재하지 않는 이메일로 로그인 시도 시 예외 발생 검증
         * - 종류: 예외 케이스(Negative Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("존재하지 않는 이메일로 로그인 시도")
        void loginWithNonExistentEmail() {
            // given
            when(userRepository.findByEmail(defaultRequest.getEmail())).thenReturn(Optional.empty());

            // when & then
            assertThatThrownBy(() -> authService.login(defaultRequest, response))
                    .isInstanceOf(BadCredentialsException.class)
                    .hasMessageContaining(ErrorMessage.USER_NOT_FOUND);
        }

        /**
         * 잘못된 비밀번호로 로그인 시도 테스트
         * - 목적: 잘못된 비밀번호로 로그인 시도 시 예외 발생 및 로그인 실패 처리 검증
         * - 종류: 예외 케이스(Negative Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("잘못된 비밀번호로 로그인 시도")
        void loginWithInvalidPassword() {
            // given
            when(userRepository.findByEmail(defaultRequest.getEmail())).thenReturn(Optional.of(user));
            when(authenticationManagerBuilder.getObject()).thenThrow(new BadCredentialsException("Invalid password"));

            // when & then
            assertThatThrownBy(() -> authService.login(defaultRequest, response))
                    .isInstanceOf(BadCredentialsException.class)
                    .hasMessageContaining(ErrorMessage.INVALID_PASSWORD_FORMAT);
            verify(accountLockUtil).handleLoginFailure(user);
        }
    }

    @Nested
    @DisplayName("로그아웃 테스트")
    class LogoutTest {

        /**
         * 정상적인 로그아웃 테스트
         * - 목적: 정상적인 로그아웃 요청 시 리프레시 토큰 삭제 및 쿠키 만료 처리 검증
         * - 종류: 정상 케이스(Positive Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("정상적인 로그아웃")
        void logoutSuccess() {
            // given
            TokenDto.Request tokenRequest = new TokenDto.Request("accessToken", "refreshToken");
            when(tokenProvider.getAuthentication(tokenRequest.getAccessToken(), request)).thenReturn(authentication);
            when(tokenProvider.getAccessTokenExpirationTime()).thenReturn(3600L);

            // 스텁 처리: expireAllCookies가 호출되면 직접 만료 쿠키 헤더를 추가
            doAnswer(invocation -> {
                MockHttpServletResponse resp = invocation.getArgument(0);
                resp.addHeader(HttpHeaders.SET_COOKIE, TokenProvider.ACCESS_TOKEN_COOKIE_NAME + "=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None");
                resp.addHeader(HttpHeaders.SET_COOKIE, TokenProvider.REFRESH_TOKEN_COOKIE_NAME + "=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=None");
                return null;
            }).when(cookieFactory).expireAllCookies(response);

            // when
            authService.logout(tokenRequest, request, response);

            // then
            verify(refreshTokenRepository).deleteByKey(any());
            verify(tokenBlacklist).addToBlacklist(tokenRequest.getAccessToken(), tokenProvider.getAccessTokenExpirationTime());
            verify(cookieFactory).expireAllCookies(response);
            
            // 쿠키가 만료되었는지 확인 (순서 무관)
            List<Object> cookies = response.getHeaderValues(HttpHeaders.SET_COOKIE);
            System.out.println("[로그아웃 쿠키 헤더] " + cookies);
            assertThat(cookies).hasSize(2);

            boolean accessCookieFound = cookies.stream().anyMatch(c -> c.toString().contains(TokenProvider.ACCESS_TOKEN_COOKIE_NAME) && c.toString().contains("Max-Age=0"));
            boolean refreshCookieFound = cookies.stream().anyMatch(c -> c.toString().contains(TokenProvider.REFRESH_TOKEN_COOKIE_NAME) && c.toString().contains("Max-Age=0"));

            assertThat(accessCookieFound).isTrue();
            assertThat(refreshCookieFound).isTrue();
        }
    }

    @Nested
    @DisplayName("토큰 재발급 테스트")
    class ReissueTest {

        /**
         * 정상적인 토큰 재발급 테스트
         * - 목적: 정상적인 토큰 재발급 요청 시 새로운 토큰 발급 및 쿠키 설정 검증
         * - 종류: 정상 케이스(Positive Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("정상적인 토큰 재발급")
        void reissueSuccess() {
            // given
            TokenDto.Request tokenRequest = new TokenDto.Request("accessToken", "refreshToken");

            when(tokenProvider.validateToken(tokenRequest.getRefreshToken())).thenReturn(true);
            when(tokenProvider.getAuthentication(tokenRequest.getAccessToken(), request)).thenReturn(authentication);
            when(refreshTokenRepository.findByKey(authentication.getName())).thenReturn(Optional.of(refreshToken));
            when(tokenProvider.generateToken(authentication)).thenReturn(tokenResponse);
            when(tokenProvider.getRefreshTokenExpirationTime()).thenReturn(3600L);

            // when
            TokenDto.Response result = authService.reissue(tokenRequest, request, response);

            // then
            assertThat(result).isNotNull();
            assertThat(result.getAccessToken()).isEqualTo(tokenResponse.getAccessToken());
            assertThat(result.getRefreshToken()).isEqualTo(tokenResponse.getRefreshToken());
            verify(refreshTokenRepository).save(
                authentication.getName(),
                tokenResponse.getRefreshToken(),
                tokenProvider.getRefreshTokenExpirationTime()
            );
            verify(cookieFactory).addAccessCookie(response, tokenResponse.getAccessToken());
            verify(cookieFactory).addRefreshCookie(response, tokenResponse.getRefreshToken());
        }

        /**
         * 유효하지 않은 리프레시 토큰으로 재발급 시도 테스트
         * - 목적: 유효하지 않은 리프레시 토큰으로 재발급 시도 시 예외 발생 검증
         * - 종류: 예외 케이스(Negative Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("유효하지 않은 리프레시 토큰으로 재발급 시도")
        void reissueWithInvalidRefreshToken() {
            // given
            TokenDto.Request tokenRequest = new TokenDto.Request("accessToken", "refreshToken");
            when(tokenProvider.validateToken(tokenRequest.getRefreshToken())).thenReturn(false);

            // when & then
            assertThatThrownBy(() -> authService.reissue(tokenRequest, request, response))
                    .isInstanceOf(InvalidTokenException.class);
        }

        /**
         * 저장된 리프레시 토큰과 일치하지 않는 토큰으로 재발급 시도 테스트
         * - 목적: 저장된 리프레시 토큰과 일치하지 않는 토큰으로 재발급 시도 시 예외 발생 검증
         * - 종류: 예외 케이스(Negative Test)
         * - 테스트 유형: 단위 테스트(Unit Test)
         */
        @Test
        @DisplayName("저장된 리프레시 토큰과 일치하지 않는 토큰으로 재발급 시도")
        void reissueWithMismatchedRefreshToken() {
            // given
            TokenDto.Request tokenRequest = new TokenDto.Request("accessToken", "refreshToken");
            RefreshToken differentToken = RefreshToken.create("test@test.com", "differentToken");

            when(tokenProvider.validateToken(tokenRequest.getRefreshToken())).thenReturn(true);
            when(tokenProvider.getAuthentication(tokenRequest.getAccessToken(), request)).thenReturn(authentication);
            when(refreshTokenRepository.findByKey(authentication.getName())).thenReturn(Optional.of(differentToken));

            // when & then
            assertThatThrownBy(() -> authService.reissue(tokenRequest, request, response))
                    .isInstanceOf(InvalidTokenException.class);
        }
    }
} 