package com.attendace.auth_module.security;

import com.attendace.auth_module.config.SecurityConfig;
import com.attendace.auth_module.entities.Role;
import com.attendace.auth_module.repository.RoleRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Value("${jwt.secret}")
    private String jwtSecret;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private RoleRepository roleRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        String requestURI = request.getRequestURI();

        //  1 Skip JWT validation for public endpoints
        if (isPublicEndpoint(requestURI)) {
            log.debug("Skipping token validation for public endpoint: {}", requestURI);
            filterChain.doFilter(request, response);
            return;
        }

        //  2 Check Authorization header
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            log.debug("No Bearer token found in Authorization header");
            filterChain.doFilter(request, response);
            return;
        }
        log.debug("Processing request to: {}", requestURI);

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            log.debug("Token extracted from Authorization header");

            try {
                if (jwtTokenProvider.isTokenBlacklisted(token)) {
                    log.warn("Blocked access with blacklisted token");
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\": \"Token has been revoked. Please login again.\"}");
                    return;
                }
                // Parse token
                Claims claims = Jwts.parser()
                        .setSigningKey(jwtSecret)
                        .parseClaimsJws(token)
                        .getBody();

                String username = claims.getSubject();
                Long roleId = Long.valueOf(claims.get("roleId").toString());
                Boolean isSuperAdmin = claims.get("isSuperAdmin", Boolean.class);

                log.info("JWT parsed successfully for user: {}, roleId: {}, isSuperAdmin: {}",
                        username, roleId, isSuperAdmin);

                if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                    List<GrantedAuthority> authorities = new ArrayList<>();

                    // If super admin, grant all permissions
                    if (Boolean.TRUE.equals(isSuperAdmin)) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_SUPER_ADMIN"));
                        authorities.add(new SimpleGrantedAuthority("*")); // Wildcard for all permissions
                        log.info("Super Admin authority granted with wildcard permissions");
                    } else {
                        // Fetch permissions dynamically from database based on roleId
                        // Option 1: Direct database query
                        Optional<Role> roleOpt = roleRepository.findByIdWithPermissions(roleId);

                        // Option 2: Use cached service (uncomment if using cache)
                        // Optional<Role> roleOpt = cachedRoleService.getRoleWithPermissions(roleId);

                        if (roleOpt.isPresent()) {
                            Role role = roleOpt.get();

                            // Check if role is active
                            if (Boolean.FALSE.equals(role.getIsActive())) {
                                log.warn("User {} has inactive role: {}", username, role.getRoleCode());
                                // Continue without setting authentication
                                filterChain.doFilter(request, response);
                                return;
                            }

                            // Add role as authority
                            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.getRoleCode()));

                            // Add all permissions from the role
                            List<GrantedAuthority> permissions = role.getPermissions().stream()
                                    .filter(permission -> Boolean.TRUE.equals(permission.getIsActive()))
                                    .map(permission -> new SimpleGrantedAuthority(permission.getPermissionCode()))
                                    .collect(Collectors.toList());

                            authorities.addAll(permissions);

                            log.info("Loaded {} permissions for user {} from role {}",
                                    permissions.size(), username, role.getRoleCode());
                            log.debug("Permissions: {}", permissions);
                        } else {
                            log.warn("Role not found for roleId: {}", roleId);
                            // Continue without setting authentication
                            filterChain.doFilter(request, response);
                            return;
                        }
                    }

                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(username, null, authorities);
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    SecurityContextHolder.getContext().setAuthentication(authToken);

                    log.info("JWT authenticated user: {} with {} authorities", username, authorities.size());
                    log.debug("Authorities: {}", authorities);
                } else {
                    log.warn("Username is null or authentication already exists");
                }
            } catch (io.jsonwebtoken.ExpiredJwtException e) {
                log.error("JWT token has expired: {}", e.getMessage());
            } catch (io.jsonwebtoken.MalformedJwtException e) {
                log.error("Invalid JWT token format: {}", e.getMessage());
            } catch (io.jsonwebtoken.security.SignatureException e) {
                log.error("JWT signature validation failed: {}", e.getMessage());
            } catch (io.jsonwebtoken.UnsupportedJwtException e) {
                log.error("Unsupported JWT token: {}", e.getMessage());
            } catch (IllegalArgumentException e) {
                log.error("JWT claims string is empty: {}", e.getMessage());
            } catch (Exception e) {
                log.error("JWT validation failed: {} - {}", e.getClass().getSimpleName(), e.getMessage());
            }
        } else {
            log.debug("No Bearer token found in Authorization header");
        }

        filterChain.doFilter(request, response);
    }
    private boolean isPublicEndpoint(String path) {
        return Arrays.stream(SecurityConfig.publicEndpoint).toList().stream().anyMatch(path::startsWith);
    }
}
