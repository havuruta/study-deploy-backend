package com.ssafy.demo.security.auth;

import com.ssafy.demo.security.dto.AuthDto;
import com.ssafy.demo.security.dto.TokenDto;
import com.ssafy.demo.utils.ApiUtils;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Tag(name = "Auth", description = "인증 관련 API")
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    // 1. 회원가입 API
    @Operation(summary = "회원가입", description = "사용자가 회원가입을 진행합니다.")
    @PostMapping("/signup")
    public ResponseEntity<?> signup(@RequestBody AuthDto.DefaultRequest defaultRequest, HttpServletResponse response) {
        // 1-1. 회원가입 처리
        authService.signup(defaultRequest);
        // 1-2. 회원가입 후 자동 로그인 처리
        authService.login(defaultRequest, response);
        return ResponseEntity.ok(ApiUtils.success("회원가입이 완료되었습니다."));
    }

    // 2. 로그인 API
    @Operation(summary = "로그인", description = "사용자가 로그인하여 토큰을 발급받습니다.")
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody AuthDto.DefaultRequest defaultRequest, HttpServletResponse response) {
        // 2-1. 로그인 처리 및 토큰 발급
        authService.login(defaultRequest, response);
        return ResponseEntity.ok(ApiUtils.success("로그인이 완료되었습니다."));
    }

    // 3. 로그아웃 API
    @Operation(summary = "로그아웃", description = "사용자가 로그아웃하여 토큰을 무효화합니다.")
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        // 3-1. 로그아웃 처리
        authService.logout(request, response);
        return ResponseEntity.ok(ApiUtils.success("로그아웃 완료"));
    }

    // 4. 토큰 재발급 API
    @Operation(summary = "토큰 재발급", description = "만료된 토큰을 재발급받습니다.")
    @PostMapping("/reissue")
    public ResponseEntity<?> reissue(HttpServletRequest request, HttpServletResponse response) {
        // 4-1. 토큰 재발급 처리
        return ResponseEntity.ok(ApiUtils.success(authService.reissue(request, response)));
    }
}
