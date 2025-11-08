package com.attendace.auth_module.security;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Collection;

@Component("customPermissionEvaluator")
@Slf4j
public class CustomPermissionEvaluator implements PermissionEvaluator {
    @Override
    public boolean hasPermission(Authentication authentication, Object targetDomainObject, Object permission) {
        if(authentication==null || authentication.isAuthenticated()){
            log.error("Authentication is null or not authenticated");
            return false;
        }
        Collection <? extends GrantedAuthority> authorities = authentication.getAuthorities();
        boolean isSuperAdmin = authorities.stream()
                .anyMatch(auth -> "*".equals(auth.getAuthority()) ||
                        "SUPER_ADMIN".equals(auth.getAuthority()));
        if(isSuperAdmin){
            log.debug("User {} has super admin access", authentication.getName() );
            return true;
        }
        String requiredPermission = permission.toString();
        boolean hasPermission = authorities.stream()
                .anyMatch((auth-> requiredPermission.equals(auth.getAuthority())));
        log.debug("Permission check for user {}: required={}, granted={}",
                authentication.getName(), requiredPermission, hasPermission);
        return hasPermission;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType, Object permission) {
        return hasPermission(authentication, (Object) targetId, permission);
    }

    /**
     * Check if user has any of the specified permissions
     */
    public boolean hasAnyPermission(Authentication authentication, String... permissions) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        // Check for super admin
        boolean isSuperAdmin = authorities.stream()
                .anyMatch(auth -> "*".equals(auth.getAuthority()) ||
                        "ROLE_SUPER_ADMIN".equals(auth.getAuthority()));

        if (isSuperAdmin) {
            return true;
        }

        // Check if user has any of the required permissions
        for (String permission : permissions) {
            boolean hasPermission = authorities.stream()
                    .anyMatch(auth -> permission.equals(auth.getAuthority()));
            if (hasPermission) {
                return true;
            }
        }

        return false;
    }

    /**
     * Check if user has all of the specified permissions
     */
    public boolean hasAllPermissions(Authentication authentication, String... permissions) {
        if (authentication == null || !authentication.isAuthenticated()) {
            return false;
        }

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        // Check for super admin
        boolean isSuperAdmin = authorities.stream()
                .anyMatch(auth -> "*".equals(auth.getAuthority()) ||
                        "ROLE_SUPER_ADMIN".equals(auth.getAuthority()));

        if (isSuperAdmin) {
            return true;
        }

        // Check if user has all required permissions
        for (String permission : permissions) {
            boolean hasPermission = authorities.stream()
                    .anyMatch(auth -> permission.equals(auth.getAuthority()));
            if (!hasPermission) {
                return false;
            }
        }

        return true;
    }
}
