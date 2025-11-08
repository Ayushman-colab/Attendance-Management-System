package com.attendace.auth_module.security;

import com.attendace.auth_module.entities.Role;
import com.attendace.auth_module.entities.User;
import com.attendace.auth_module.repository.UserRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.SignatureException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Component
@Slf4j
public class JwtTokenProvider {
    @Value("${jwt.secret}")
    private String jwtSecret;

    @Value("${jwt.expiration}")
    private long jwtExpirationInMs;

    @Value("${jwt.refresh-expiration}")
    private long refreshTokenExpirationInMs;

    @Autowired
    private RedisTemplate<String, Object> redisTemplate;

    @Autowired
    private UserRepository userRepository;

    public String generateAccessToken(User user) {
        Map<String, Object> claims = new HashMap<>();

        Role role = user.getRole();

        // Add minimal claims - only user ID, role info
        claims.put("userId", user.getUserId());
        claims.put("roleId", role.getRoleId());
        claims.put("roleCode", role.getRoleCode());
        claims.put("isSuperAdmin", role.getIsSuperAdmin());

        // Add user metadata (optional)
        claims.put("email", user.getEmail());
        claims.put("firstName", user.getFirstName());
        claims.put("lastName", user.getLastName());

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(user.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationInMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
        }

    public String generateRefreshToken(String username) {
        String refreshToken = Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenExpirationInMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();

        // Store refresh token in Redis with expiration
        String redisKey = "refresh_token:" + username;
        redisTemplate.opsForValue().set(
                redisKey,
                refreshToken,
                refreshTokenExpirationInMs,
                TimeUnit.MILLISECONDS
        );

        log.info("Refresh token generated and stored for user: {}", username);
        return refreshToken;
    }

    public String getUsernameFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return claims.getSubject();
    }

    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return Long.valueOf(claims.get("userId").toString());
    }

    public Long getRoleIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return Long.valueOf(claims.get("roleId").toString());
    }

    public String getRoleCodeFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return claims.get("roleCode").toString();
    }

    public Boolean isSuperAdminFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return Boolean.valueOf(claims.get("isSuperAdmin").toString());
    }

    public Map<String, Object> getAllClaimsFromToken(String token) {
        Claims claims = Jwts.parser()
                .setSigningKey(jwtSecret)
                .parseClaimsJws(token)
                .getBody();
        return new HashMap<>(claims);
    }

    public boolean validateToken(String token) {
        try {
            // ✅ STEP 1: Parse token and get claims (parse only ONCE)
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .parseClaimsJws(token)
                    .getBody();

            // ✅ STEP 2: Get username from already-parsed claims (no re-parsing)
            String username = claims.getSubject();

            // ✅ STEP 3: Check if token is blacklisted
            String blacklistKey = "blacklist_token:" + username + ":" + token;
            Boolean isBlacklisted = redisTemplate.hasKey(blacklistKey);

            if (Boolean.TRUE.equals(isBlacklisted)) {
                log.warn("Token is blacklisted for user: {}", username);
                return false;
            }

            log.debug("Token validation successful for user: {}", username);
            return true;

        } catch (SignatureException ex) {
            log.error("Invalid JWT signature: {}", ex.getMessage());
        } catch (MalformedJwtException ex) {
            log.error("Invalid JWT token: {}", ex.getMessage());
        } catch (ExpiredJwtException ex) {
            log.error("Expired JWT token: {}", ex.getMessage());
        } catch (UnsupportedJwtException ex) {
            log.error("Unsupported JWT token: {}", ex.getMessage());
        } catch (IllegalArgumentException ex) {
            log.error("JWT claims string is empty: {}", ex.getMessage());
        } catch (Exception ex) {
            log.error("Token validation failed: {}", ex.getMessage());
        }
        return false;
    }
    public boolean isTokenBlacklisted(String token) {
        try {
            String username = getUsernameFromToken(token);
            String blacklistKey = "blacklist_token:" + username + ":" + token;
            return Boolean.TRUE.equals(redisTemplate.hasKey(blacklistKey));
        } catch (Exception e) {
            log.error("Error checking token blacklist: {}", e.getMessage());
            return false;
        }
    }

    public boolean validateRefreshToken(String refreshToken) {
        try {
            String username = getUsernameFromToken(refreshToken);
            String redisKey = "refresh_token:" + username;
            String storedToken = (String) redisTemplate.opsForValue().get(redisKey);

            if (storedToken == null || !storedToken.equals(refreshToken)) {
                log.warn("Refresh token not found or doesn't match for user: {}", username);
                return false;
            }

            Jwts.parser().setSigningKey(jwtSecret).parseClaimsJws(refreshToken);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            log.error("Invalid refresh token: {}", e.getMessage());
            return false;
        }
    }

    public void blacklistToken(String token) {
        try {
            String username = getUsernameFromToken(token);
            String blacklistKey = "blacklist_token:" + username + ":" + token;

            // Get token expiration time
            Claims claims = Jwts.parser()
                    .setSigningKey(jwtSecret)
                    .parseClaimsJws(token)
                    .getBody();

            Date expiration = claims.getExpiration();
            long ttl = expiration.getTime() - System.currentTimeMillis();

            if (ttl > 0) {
                redisTemplate.opsForValue().set(blacklistKey, "true", ttl, TimeUnit.MILLISECONDS);
                log.info("Token blacklisted for user: {}", username);
            }
        } catch (JwtException e) {
            log.error("Error blacklisting token: {}", e.getMessage());
        }
    }

    public void revokeRefreshToken(String username) {
        String redisKey = "refresh_token:" + username;
        redisTemplate.delete(redisKey);
        log.info("Refresh token revoked for user: {}", username);
    }
}
