package com.attendace.auth_module.service.impl;

import com.attendace.auth_module.entities.Role;
import com.attendace.auth_module.repository.RoleRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@Slf4j
public class CachedRolePermissionService {

    @Autowired
    private RoleRepository roleRepository;

    /**
     * Get role with permissions from cache or database
     * Cache key: "role_permissions::roleId"
     */
    @Cacheable(value = "role_permissions", key = "#roleId", unless = "#result == null || !#result.isPresent()")
    public Optional<Role> getRoleWithPermissions(Long roleId) {
        log.debug("Fetching role with permissions from database for roleId: {}", roleId);
        return roleRepository.findByIdWithPermissions(roleId);
    }

    /**
     * Evict cache when role is updated
     */
    @CacheEvict(value = "role_permissions", key = "#roleId")
    public void evictRoleCache(Long roleId) {
        log.info("Evicted cache for roleId: {}", roleId);
    }

    /**
     * Clear all role permission cache
     */
    @CacheEvict(value = "role_permissions", allEntries = true)
    public void evictAllRoleCache() {
        log.info("Evicted all role permission cache");
    }

}
