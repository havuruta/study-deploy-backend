package com.ssafy.demo.user.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import java.time.LocalDateTime;

@Entity
@Builder
@Data
@NoArgsConstructor
@AllArgsConstructor
@Table(name = "user_tb")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = true)
    private String name; //닉네임

    @Column(nullable = false)
    private String email; //아이디

    @Column(nullable = false)
    private String password;

    @Column(nullable = true)
    private String profileImageUrl;

    @Column(nullable = true)
    @Enumerated(EnumType.STRING)
    private Gender gender;

    // 로그인 시도 관련 필드
    @Column(nullable = false)
    private int loginAttempts;

    @Column(nullable = true)
    private LocalDateTime lastLoginAttempt;

    @Column(nullable = true)
    private LocalDateTime passwordExpiryDate;
}
