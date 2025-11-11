package com.attendace.auth_module.service.impl;

import com.attendace.auth_module.service.inter.TokenRedisService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
public class TokenRedisServiceImpl implements TokenRedisService {

    @Autowired
    private StringRedisTemplate redisTemplate;

    public void saveTokens(String userId, String accessToken, String refreshToken) {
        redisTemplate.opsForValue().set("access:" + userId, accessToken, 2, TimeUnit.SECONDS);
        redisTemplate.opsForValue().set("refresh:" + userId, refreshToken, 7, TimeUnit.DAYS);
    }

    public String getAccessToken(String userId) {
        return redisTemplate.opsForValue().get("access:" + userId);
    }

    public String getRefreshToken(String userId) {
        return redisTemplate.opsForValue().get("refresh:" + userId);
    }

    public void deleteTokens(String userId) {
        redisTemplate.delete("access:" + userId);
        redisTemplate.delete("refresh:" + userId);
    }
}
