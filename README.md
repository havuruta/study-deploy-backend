## `study-deploy-backend` – JWT 기반 인증 백엔드

### 개요
Spring Boot 기반 백엔드 애플리케이션.  
JWT 토큰 기반 로그인 및 인증 플로우를 구현하여 사용자 보호가 필요한 API 접근 제어를 수행합니다.

### 주요 기능
- `회원가입 / 로그인 API` (JWT Access + Refresh 토큰 발급)
- `JwtAuthenticationFilter` 를 통한 인증 필터 적용
- `TokenProvider` 내에서 토큰 생성/검증/Claims 추출 처리
- 토큰 만료 및 검증 실패에 대한 명확한 예외 처리
- Spring Security 기반 인가 처리 (`ROLE_USER` 등)

### 인증 시스템 상세
1. **토큰 관리**
   - Access Token: 30분 유효
   - Refresh Token: 7일 유효
   - httpOnly 쿠키를 통한 안전한 토큰 저장
   - Redis를 통한 Refresh Token 관리

2. **인증 프로세스**
   - 로그인: Access Token + Refresh Token 발급 (쿠키 저장)
   - 토큰 갱신: Refresh Token 검증 후 새로운 토큰 발급
   - 로그아웃: 토큰 무효화 및 쿠키 삭제

3. **보안 기능**
   - XSS 방지를 위한 httpOnly 쿠키 사용
   - CSRF 방지를 위한 SameSite 쿠키 설정
   - Redis를 통한 토큰 블랙리스트 관리
   - 계정 잠금 기능 (로그인 실패 제한)

### 기술 스택
- Spring Boot 3.4.x
- Spring Security 6.x
- JPA + H2/MySQL
- JWT (JJWT 0.11.5)
- Redis (토큰 관리)
- Gradle, Java 17

### API 엔드포인트
1. **인증 관련**
   - POST `/auth/signup`: 회원가입
   - POST `/auth/login`: 로그인
   - POST `/auth/logout`: 로그아웃
   - POST `/auth/reissue`: 토큰 갱신

2. **사용자 관련**
   - GET `/users/info`: 사용자 정보 조회

### Redis 설정
- Redis를 통한 Refresh Token 관리
- 토큰 저장/조회/삭제 작업 로깅
- 토큰 만료 시간 자동 관리

### 보안 설정
- 모든 API는 HTTPS 통신 필요
- 쿠키는 Secure 플래그 설정
- SameSite=None 설정으로 크로스 사이트 요청 허용
- httpOnly 플래그로 JavaScript 접근 차단
