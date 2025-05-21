package com.ssafy.demo.user.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.ssafy.demo.user.entity.RefreshToken;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {
    Optional<RefreshToken> findByKey(String key);
    void deleteByKey(String key);
} 