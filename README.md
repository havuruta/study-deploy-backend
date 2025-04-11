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

### 기술 스택
- Spring Boot 3.4.x
- Spring Security 6.x
- JPA + H2/MySQL
- JWT (JJWT 0.11.5)
- Gradle, Java 17
