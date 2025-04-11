package com.ssafy.demo.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Optional;

import com.ssafy.demo.user.entity.User;

public class UserDto {

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class Request {
        private String nickname;
        private String gender;
        private int age;
        private String locale;
    }
    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class ImageRequest {
        private String email;
        private String presignedUrl;
    }

    @Getter
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class Response {
        private String email;
        private String nickname;
        private String profileImageUrl;
        private String gender;
        public static Response toDto(User user){
            return new Response(
                    user.getEmail(),
                    user.getName(),
                    user.getProfileImageUrl(),
                    Optional.ofNullable(user.getGender()).map(Enum::toString).orElse(null)
            );
        }

    }


}
