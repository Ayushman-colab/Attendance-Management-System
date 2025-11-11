package com.attendace.auth_module.config;

import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@EnableCaching
public class CacheConfig {

    /**
     * Option 1: Use Redis Cache (if Redis is available)
     */
//     @Bean
//     public CacheManager cacheManager(RedisConnectionFactory connectionFactory) {
//         RedisCacheConfiguration config = RedisCacheConfiguration.defaultCacheConfig()
//                 .entryTtl(Duration.ofMinutes(30)) // Cache for 30 minutes
//                 .serializeKeysWith(RedisSerializationContext.SerializationPair
//                         .fromSerializer(new StringRedisSerializer()))
//                 .serializeValuesWith(RedisSerializationContext.SerializationPair
//                         .fromSerializer(new GenericJackson2JsonRedisSerializer()))
//                 .disableCachingNullValues();
//
//         return RedisCacheManager.builder(connectionFactory)
//                 .cacheDefaults(config)
//                 .build();
//     }

    /**
     * Option 2: Use Simple In-Memory Cache (for development/testing)
     */
    @Bean
    public CacheManager cacheManager() {
        return new ConcurrentMapCacheManager("role_permissions");
    }
}
