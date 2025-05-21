package com.ssafy.demo.exception;

public class ErrorMessage {

    // Common
    public static final String INTERNAL_SERVER_ERROR = "내부 서버 에러가 발생했습니다.";

    // Api
    public static final String API_CONTENT_NOT_FOUND = "응답을 생성하는데 실패했습니다.";
    public static final String API_REQUEST_TIMEOUT = "API 호출 시간이 초과됐습니다.";
    public static final String API_UNKNOWN_FINISH_REASON = "알 수 없는 이유로 응답을 불러올 수 없습니다.";

    // Auth
    public static final String INVALID_TOKEN_EXCEPTION = "유효하지 않은 토큰입니다.";
    public static final String UNAUTHORIZED_EXCEPTION = "유효한 인증이 필요합니다.";
    public static final String LOGOUT_USER_NOT_FOUND = "로그아웃 된 사용자입니다.";
    public static final String TOKEN_MISMATCH_EXCEPTION = "토큰의 유저 정보가 일치하지 않습니다.";
    public static final String INVALID_EMAIL_FORMAT = "유효하지 않은 이메일 형식입니다.";
    public static final String INVALID_PASSWORD_FORMAT = "비밀번호는 8~20자의 영문, 숫자, 특수문자를 포함해야 합니다.";
    public static final String ACCOUNT_LOCKED = "계정이 잠겨있습니다. 관리자에게 문의하세요.";
    public static final String TOO_MANY_LOGIN_ATTEMPTS = "로그인 시도 횟수가 초과되었습니다. 잠시 후 다시 시도해주세요.";

    // User
    public static final String USER_ALREADY_LOGOUT = "이미 로그아웃 된 사용자입니다.";
    public static final String USER_ALREADY_EXIST = "이미 존재하는 아이디입니다.";
    public static final String USER_NOT_FOUND = "존재하지 않는 사용자입니다.";
    public static final String USER_ACCOUNT_DISABLED = "비활성화된 계정입니다.";
    public static final String USER_CREDENTIALS_EXPIRED = "비밀번호가 만료되었습니다.";

}
