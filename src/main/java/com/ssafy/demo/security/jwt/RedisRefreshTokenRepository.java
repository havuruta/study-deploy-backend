package com.ssafy.demo.security.jwt;

import java.util.Optional;
import java.util.concurrent.TimeUnit;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Repository;
import lombok.RequiredArgsConstructor;
import com.ssafy.demo.user.entity.RefreshToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Repository
@RequiredArgsConstructor
public class RedisRefreshTokenRepository {
    private static final Logger log = LoggerFactory.getLogger(RedisRefreshTokenRepository.class);
    private final RedisTemplate<String, String> redisTemplate;
    private static final String KEY_PREFIX = "refresh_token:";

    public void save(String key, String value, long expirationTime) {
        String redisKey = KEY_PREFIX + key;
        log.info("Redis 토큰 저장 시도 - Key: {}, Value: {}, 만료시간: {}초", redisKey, value, expirationTime);
        try {
            redisTemplate.opsForValue().set(redisKey, value, expirationTime, TimeUnit.SECONDS);
            log.info("Redis 토큰 저장 성공 - Key: {}", redisKey);
        } catch (Exception e) {
            log.error("Redis 토큰 저장 실패 - Key: {}, Error: {}", redisKey, e.getMessage());
            throw e;
        }
    }

    public Optional<RefreshToken> findByKey(String key) {
        String redisKey = KEY_PREFIX + key;
        log.info("Redis 토큰 조회 시도 - Key: {}", redisKey);
        try {
            String value = redisTemplate.opsForValue().get(redisKey);
            log.info("Redis 토큰 조회 결과 - Key: {}, Value 존재: {}", redisKey, value != null);
            return Optional.ofNullable(value)
                    .map(token -> RefreshToken.create(key, token));
        } catch (Exception e) {
            log.error("Redis 토큰 조회 실패 - Key: {}, Error: {}", redisKey, e.getMessage());
            throw e;
        }
    }

    public void deleteByKey(String key) {
        String redisKey = KEY_PREFIX + key;
        log.info("Redis 토큰 삭제 시도 - Key: {}", redisKey);
        try {
            redisTemplate.delete(redisKey);
            log.info("Redis 토큰 삭제 성공 - Key: {}", redisKey);
        } catch (Exception e) {
            log.error("Redis 토큰 삭제 실패 - Key: {}, Error: {}", redisKey, e.getMessage());
            throw e;
        }
    }
} 