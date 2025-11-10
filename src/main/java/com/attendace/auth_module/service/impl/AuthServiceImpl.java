package com.attendace.auth_module.service.impl;

import com.attendace.auth_module.dto.Common.UserDTO;      
import com.attendace.auth_module.dto.Request.LoginRequest;
import com.attendace.auth_module.dto.Request.RefreshTokenRequest;
import com.attendace.auth_module.dto.Request.RegisterRequest;
import com.attendace.auth_module.dto.Response.LoginResponse;
import com.attendace.auth_module.dto.Response.TokenResponse;
import com.attendace.auth_module.dto.Response.ValidateTokenResponse;
import com.attendace.auth_module.entities.Permission;
import com.attendace.auth_module.entities.Role;
import com.attendace.auth_module.entities.User;
import com.attendace.auth_module.exception.BadRequestException;
import com.attendace.auth_module.exception.ResourceNotFoundException;
import com.attendace.auth_module.exception.UnauthorizedException;
import com.attendace.auth_module.repository.RoleRepository;
import com.attendace.auth_module.repository.UserRepository;
import com.attendace.auth_module.security.JwtTokenProvider;
import com.attendace.auth_module.service.inter.AuthService;
import com.attendace.auth_module.service.inter.EmailService;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
public class AuthServiceImpl implements AuthService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private EmailService emailService;

    @Value("${jwt.expiration}")
    private long jwtExpirationInMs;

    @Transactional
    public LoginResponse login(LoginRequest request) {
        // Find user by username or email
        User user = userRepository.findByUsernameOrEmail(
                request.getUsernameOrEmail(),
                request.getUsernameOrEmail()
        ).orElseThrow(() -> new UnauthorizedException("Invalid credentials"));

        // Check if user is active
        if (!user.getIsActive()) {
            throw new UnauthorizedException("Account is inactive. Please contact administrator.");
        }

        // Verify password
        if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
            throw new UnauthorizedException("Invalid credentials");
        }

        // Update last login
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        // Generate tokens (no permissions stored in JWT anymore)
        String accessToken = jwtTokenProvider.generateAccessToken(user);
        String refreshToken = jwtTokenProvider.generateRefreshToken(user.getUsername());

        // Build user DTO with current permissions from database
        UserDTO userDTO = buildUserDTO(user);

        log.info("User logged in successfully: {}", user.getUsername());

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtExpirationInMs / 1000)
                .user(userDTO)
                .build();
    }

    @Transactional
    public UserDTO register(RegisterRequest request) {
        // Check if username exists
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new BadRequestException("Username is already taken");
        }

        // Check if email exists
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new BadRequestException("Email is already registered");
        }

        // Get role with permissions
        Role role = roleRepository.findByIdWithPermissions(
                roleRepository.findByRoleCode(request.getRoleCode())
                        .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + request.getRoleCode()))
                        .getRoleId()
        ).orElseThrow(() -> new ResourceNotFoundException("Role not found: " + request.getRoleCode()));

        // Create user
        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(passwordEncoder.encode(request.getPassword()))
                .firstName(request.getFirstName())
                .lastName(request.getLastName())
                .phone(request.getPhone())
                .role(role)
                .isActive(true)
                .build();

        user = userRepository.save(user);
        log.info("User registered successfully: {}", user.getUsername());

        return buildUserDTO(user);
    }

    public String forgotPassword(String email) {
        if (email == null || email.trim().isEmpty()) {
            throw new ResourceNotFoundException("Email is required");
        }

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));

        // Generate a 6-digit random OTP
        SecureRandom random = new SecureRandom();
        int otp = 100000 + random.nextInt(900000);

        // Save encoded OTP and expiry time
        user.setOtp(passwordEncoder.encode(String.valueOf(otp)));
        user.setExpiryDate(LocalDateTime.now().plusMinutes(5));

        userRepository.save(user);

        // Send OTP via email
        emailService.sendOtpEmail(email, String.valueOf(otp));

        return "OTP sent successfully to " + email;
    }

    @Transactional
    public TokenResponse refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        // Validate refresh token
        if (!jwtTokenProvider.validateRefreshToken(refreshToken)) {
            throw new UnauthorizedException("Invalid or expired refresh token");
        }

        // Get username from refresh token
        String username = jwtTokenProvider.getUsernameFromToken(refreshToken);

        // Get user
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Check if user is active
        if (!user.getIsActive()) {
            throw new UnauthorizedException("Account is inactive");
        }

        // Generate new access token (no permissions in JWT)
        String newAccessToken = jwtTokenProvider.generateAccessToken(user);

        log.info("Access token refreshed for user: {}", username);

        return TokenResponse.builder()
                .accessToken(newAccessToken)
                .refreshToken(refreshToken)
                .tokenType("Bearer")
                .expiresIn(jwtExpirationInMs / 1000)
                .build();
    }

    @Transactional
    public void logout(String token) {
        try {
            String username = jwtTokenProvider.getUsernameFromToken(token);

            // Blacklist the access token
            jwtTokenProvider.blacklistToken(token);

            // Revoke refresh token
            jwtTokenProvider.revokeRefreshToken(username);

            log.info("User logged out successfully: {}", username);
            SecurityContextHolder.clearContext();
        } catch (Exception e) {
            log.error("Error during logout: {}", e.getMessage());
            throw new BadRequestException("Invalid token");
        }
    }

    /**
     * Validates token and returns current role/permission info from database
     * This ensures validation reflects the latest permission changes
     */
    public ValidateTokenResponse validateToken(String token) {
        try {
            // Validate token structure and expiration
            if (!jwtTokenProvider.validateToken(token)) {
                return ValidateTokenResponse.builder()
                        .valid(false)
                        .message("Invalid or expired token")
                        .build();
            }

            // Extract basic information from token
            Long userId = jwtTokenProvider.getUserIdFromToken(token);
            String username = jwtTokenProvider.getUsernameFromToken(token);
            Long roleId = jwtTokenProvider.getRoleIdFromToken(token);
            String roleCode = jwtTokenProvider.getRoleCodeFromToken(token);
            Boolean isSuperAdmin = jwtTokenProvider.isSuperAdminFromToken(token);

            // Get email from token claims
            var claims = jwtTokenProvider.getAllClaimsFromToken(token);
            String email = claims.get("email").toString();

            // Fetch current permissions from database (not from token!)
            Role role = roleRepository.findByIdWithPermissions(roleId)
                    .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

            // Check if role is still active
            if (Boolean.FALSE.equals(role.getIsActive())) {
                return ValidateTokenResponse.builder()
                        .valid(false)
                        .message("User role is inactive")
                        .build();
            }

            // Get current permissions
            List<String> permissions;
            if (Boolean.TRUE.equals(isSuperAdmin)) {
                permissions = List.of("*"); // Super admin has all permissions
            } else {
                permissions = role.getPermissions().stream()
                        .filter(p -> Boolean.TRUE.equals(p.getIsActive()))
                        .map(Permission::getPermissionCode)
                        .collect(Collectors.toList());
            }

            log.debug("Token validated for user: {} with {} permissions", username, permissions.size());

            return ValidateTokenResponse.builder()
                    .valid(true)
                    .userId(userId)
                    .username(username)
                    .email(email)
                    .roleCode(roleCode)
                    .isSuperAdmin(isSuperAdmin)
                    .permissions(permissions) // Current permissions from database
                    .message("Token is valid")
                    .build();
        } catch (Exception e) {
            log.error("Error validating token: {}", e.getMessage());
            return ValidateTokenResponse.builder()
                    .valid(false)
                    .message("Token validation failed: " + e.getMessage())
                    .build();
        }
    }

    /**
     * Gets current user with latest permissions from database
     */
    public UserDTO getCurrentUser(String token) {
        Long userId = jwtTokenProvider.getUserIdFromToken(token);

        // Fetch user with role and permissions
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found"));

        // Ensure role permissions are loaded
        Role role = roleRepository.findByIdWithPermissions(user.getRole().getRoleId())
                .orElseThrow(() -> new ResourceNotFoundException("User role not found"));

        user.setRole(role);

        return buildUserDTO(user);
    }

    /**
     * Builds UserDTO with current permissions from database
     * This ensures the response always has the latest permission information
     */
    private UserDTO buildUserDTO(User user) {
        Role role = user.getRole();

        // Get current active permissions from the role
        List<String> permissions;
        if (Boolean.TRUE.equals(role.getIsSuperAdmin())) {
            permissions = List.of("*"); // Wildcard for all permissions
        } else {
            permissions = role.getPermissions().stream()
                    .filter(p -> Boolean.TRUE.equals(p.getIsActive())) // Only active permissions
                    .map(Permission::getPermissionCode)
                    .collect(Collectors.toList());
        }

        return UserDTO.builder()
                .userId(user.getUserId())
                .username(user.getUsername())
                .email(user.getEmail())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .phone(user.getPhone())
                .roleName(role.getRoleName())
                .roleCode(role.getRoleCode())
                .isSuperAdmin(role.getIsSuperAdmin())
                .permissions(permissions) // Current permissions from database, not from JWT
                .isActive(user.getIsActive())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .build();
    }

}
