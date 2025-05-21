# 테스트 가이드

## 테스트 구조

### 1. 단위 테스트 (Unit Tests)
- `src/test/java/com/ssafy/demo/security/auth/AuthServiceTest.java`
  - 회원가입 테스트
    - 정상적인 회원가입
    - 이미 존재하는 이메일로 회원가입 시도
    - 잘못된 이메일 형식으로 회원가입 시도
    - 잘못된 비밀번호 형식으로 회원가입 시도
  - 로그인 테스트
    - 정상적인 로그인
    - 존재하지 않는 이메일로 로그인 시도
    - 잘못된 비밀번호로 로그인 시도
  - 로그아웃 테스트
    - 정상적인 로그아웃
  - 토큰 재발급 테스트
    - 정상적인 토큰 재발급
    - 유효하지 않은 리프레시 토큰으로 재발급 시도
    - 저장된 리프레시 토큰과 일치하지 않는 토큰으로 재발급 시도

### 2. 통합 테스트 (Integration Tests)
- `src/test/java/com/ssafy/demo/security/jwt/JwtAuthenticationFilterTest.java`
  - JWT 토큰 검증
  - 인증되지 않은 요청 처리
  - 만료된 토큰 처리
  - 잘못된 형식의 토큰 처리

- `src/test/java/com/ssafy/demo/security/config/SecurityConfigTest.java`
  - 보안 설정 검증
  - 인증/인가 규칙 검증
  - CORS 설정 검증

### 3. Rate Limiting 테스트
- `src/test/java/com/ssafy/demo/security/interceptor/RateLimitInterceptorTest.java`
  - 요청 제한 동작 검증
  - 제한 초과 시 응답 검증
  - 제한 초기화 검증

## 테스트 실행 방법

### 1. 전체 테스트 실행
```bash
./gradlew test
```

### 2. 특정 테스트 클래스 실행
```bash
./gradlew test --tests "com.ssafy.demo.security.auth.AuthServiceTest"
```

### 3. 특정 테스트 메소드 실행
```bash
./gradlew test --tests "com.ssafy.demo.security.auth.AuthServiceTest.loginSuccess"
```

## 테스트 환경 설정

### 1. 테스트용 데이터베이스
```yaml
# src/test/resources/application.yml
spring:
  datasource:
    url: jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1
    username: sa
    password:
    driver-class-name: org.h2.Driver
```

### 2. 테스트용 Redis
```yaml
spring:
  data:
    redis:
      host: localhost
      port: 6379
```

## 테스트 커버리지

### 1. JaCoCo 리포트 생성
```bash
./gradlew jacocoTestReport
```

### 2. 커버리지 기준
- 라인 커버리지: 80% 이상
- 브랜치 커버리지: 70% 이상
- 메소드 커버리지: 90% 이상

## 테스트 작성 가이드라인

### 1. 테스트 메소드 명명 규칙
- `[테스트대상]_[시나리오]_[예상결과]`
- 예: `loginWithInvalidPassword_ShouldThrowBadCredentialsException`

### 2. 테스트 구조
```java
@Test
@DisplayName("테스트 설명")
void testMethod() {
    // given: 테스트 준비
    // when: 테스트 실행
    // then: 결과 검증
}
```

### 3. Mock 객체 사용
- `@Mock`: 테스트 대상의 의존성을 모의 객체로 생성
- `@InjectMocks`: 모의 객체를 주입받는 테스트 대상 객체 생성
- `when().thenReturn()`: 모의 객체의 동작 정의

### 4. 검증 방법
- `assertThat()`: 결과 검증
- `verify()`: 메소드 호출 검증
- `assertThrows()`: 예외 발생 검증

## 테스트 데이터

### 1. 테스트 데이터 생성
- `@BeforeEach`: 각 테스트 전에 실행되는 설정
- `TestDataBuilder`: 테스트 데이터 생성 헬퍼 클래스

### 2. 테스트 데이터 정리
- `@AfterEach`: 각 테스트 후에 실행되는 정리
- `@Transactional`: 테스트 후 롤백

## 테스트 시 주의사항

1. 테스트 격리
   - 각 테스트는 독립적으로 실행되어야 함
   - 테스트 간 상태 공유 금지

2. 테스트 실행 시간
   - 단위 테스트: 1초 이내
   - 통합 테스트: 5초 이내

3. 테스트 데이터
   - 실제 데이터베이스 사용 금지
   - 테스트용 데이터베이스 사용

4. 외부 의존성
   - 외부 서비스는 Mock으로 대체
   - Redis는 테스트용 인스턴스 사용 