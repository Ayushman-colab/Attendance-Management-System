package com.attendace.auth_module.service.inter;

public interface TokenRedisService {
    public void saveTokens(String userId, String accessToken, String refreshToken);
    public String getAccessToken(String userId);
    public String getRefreshToken(String userId);
    public void deleteTokens(String userId);
}
