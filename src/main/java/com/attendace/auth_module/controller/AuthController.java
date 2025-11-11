package com.attendace.auth_module.controller;

import com.attendace.auth_module.dto.Common.PermissionDTO;
import com.attendace.auth_module.dto.Common.RoleDTO;
import com.attendace.auth_module.dto.Common.UserDTO;
import com.attendace.auth_module.dto.Request.LoginRequest;
import com.attendace.auth_module.dto.Request.RefreshTokenRequest;
import com.attendace.auth_module.dto.Request.RegisterRequest;
import com.attendace.auth_module.dto.Request.ValidateTokenRequest;
import com.attendace.auth_module.dto.Response.LoginResponse;
import com.attendace.auth_module.dto.Response.TokenResponse;
import com.attendace.auth_module.dto.Response.ValidateTokenResponse;
import com.attendace.auth_module.service.inter.AuthService;
import com.attendace.auth_module.service.inter.PermissionService;
import com.attendace.auth_module.service.inter.RoleService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Slf4j
@Tag(name = "Authentication & Authorization", description = "APIs for authentication, user management, roles, and permissions")
public class AuthController {

    @Autowired
    private AuthService authService;

    @Autowired
    private RoleService roleService;

    @Autowired
    private PermissionService permissionService;

    // ==================== Authentication Endpoints ====================

    @PostMapping("/login")
    @Operation(
            summary = "User Login",
            description = "Authenticate user with username/email and password. Returns access token and refresh token."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login successful",
                    content = @Content(schema = @Schema(implementation = LoginResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid credentials or inactive account",
                    content = @Content),
            @ApiResponse(responseCode = "400", description = "Invalid request body",
                    content = @Content)
    })
    public ResponseEntity<LoginResponse> login(@Valid @RequestBody LoginRequest request) {
        log.info("Login request for user: {}", request.getUsernameOrEmail());
        LoginResponse response = authService.login(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    @Operation(
            summary = "Register New User",
            description = "Create a new user account with specified role"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User registered successfully",
                    content = @Content(schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "400", description = "Username or email already exists",
                    content = @Content),
            @ApiResponse(responseCode = "404", description = "Role not found",
                    content = @Content)
    })
    public ResponseEntity<UserDTO> register(@Valid @RequestBody RegisterRequest request) {
        log.info("Registration request for username: {}", request.getUsername());
        UserDTO user = authService.register(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PostMapping("/registers")
    @Operation(
            summary = "Register New User",
            description = "Create a new user account with specified role"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "User registered successfully",
                    content = @Content(schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "400", description = "Username or email already exists",
                    content = @Content),
            @ApiResponse(responseCode = "404", description = "Role not found",
                    content = @Content)
    })
    public ResponseEntity<List<UserDTO>> registerMultipleUsers(@Valid @RequestBody List<RegisterRequest> requests) {
        log.info("Bulk registration request for {} users", requests.size());

        List<UserDTO> registeredUsers = new ArrayList<>();

        for (RegisterRequest request : requests) {
            try {
                UserDTO user = authService.register(request);
                registeredUsers.add(user);
            } catch (Exception e) {
                log.error("Failed to register user: {} -> {}", request.getUsername(), e.getMessage());
                // continue registering next users even if one fails
            }
        }

        if (registeredUsers.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        }

        return ResponseEntity.status(HttpStatus.CREATED).body(registeredUsers);
    }

    @GetMapping("/forgot-password")
    public ResponseEntity<String> forgotPassword(@RequestParam String email) {
        return ResponseEntity.ok(authService.forgotPassword(email));
    }

    @PostMapping("/verify-otp")
    public ResponseEntity<Map<String, String>> verifyOtp(@RequestParam String email, @RequestParam String otp) {
        return ResponseEntity.ok(authService.verifyOtp(email, otp));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<String> resetPassword(@RequestParam String resetToken, @RequestParam String newPassword) {
        return ResponseEntity.ok(authService.resetPassword(resetToken, newPassword));
    }

    @PostMapping("/refresh")
    @Operation(
            summary = "Refresh Access Token",
            description = "Generate a new access token using a valid refresh token"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token refreshed successfully",
                    content = @Content(schema = @Schema(implementation = TokenResponse.class))),
            @ApiResponse(responseCode = "401", description = "Invalid or expired refresh token",
                    content = @Content)
    })
    public ResponseEntity<TokenResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        log.info("Token refresh request");
        TokenResponse response = authService.refreshToken(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/logout")
    @Operation(
            summary = "User Logout",
            description = "Invalidate access token and revoke refresh token"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Logout successful"),
            @ApiResponse(responseCode = "400", description = "Invalid token",
                    content = @Content)
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<Void> logout(
            @Parameter(description = "Bearer token in format: Bearer {token}", required = true)
            @RequestHeader("Authorization") String authHeader) {
        log.info("Logout request");
        String token = extractToken(authHeader);
        authService.logout(token);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/validate")
    @Operation(
            summary = "Validate Token",
            description = "Validate JWT token and return user information with current permissions from database"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token validation result",
                    content = @Content(schema = @Schema(implementation = ValidateTokenResponse.class)))
    })
    public ResponseEntity<ValidateTokenResponse> validateToken(@Valid @RequestBody ValidateTokenRequest request) {
        ValidateTokenResponse response = authService.validateToken(request.getToken());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/me")
    @Operation(
            summary = "Get Current User",
            description = "Retrieve current authenticated user's information with latest permissions"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "User information retrieved",
                    content = @Content(schema = @Schema(implementation = UserDTO.class))),
            @ApiResponse(responseCode = "401", description = "Unauthorized - Invalid token",
                    content = @Content),
            @ApiResponse(responseCode = "404", description = "User not found",
                    content = @Content)
    })
    @SecurityRequirement(name = "Bearer Authentication")
    public ResponseEntity<UserDTO> getCurrentUser(
            @Parameter(description = "Bearer token in format: Bearer {token}", required = true)
            @RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        UserDTO user = authService.getCurrentUser(token);
        return ResponseEntity.ok(user);
    }

    // ==================== Role Management Endpoints ====================

    @GetMapping("/roles")
    @Operation(
            summary = "Get All Roles",
            description = "Retrieve all roles in the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Roles retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Access denied - Missing required permissions")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'ROLE_READ','ROLE_MANAGE','ADMIN')")
    public ResponseEntity<List<RoleDTO>> getAllRoles() {
        List<RoleDTO> roles = roleService.getAllRoles();
        return ResponseEntity.ok(roles);
    }

    @GetMapping("/roles/active")
    @Operation(
            summary = "Get Active Roles",
            description = "Retrieve only active roles"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Active roles retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'ROLE_READ','ROLE_MANAGE','ADMIN')")
    public ResponseEntity<List<RoleDTO>> getActiveRoles() {
        List<RoleDTO> roles = roleService.getActiveRoles();
        return ResponseEntity.ok(roles);
    }

    @GetMapping("/roles/{roleId}")
    @Operation(
            summary = "Get Role by ID",
            description = "Retrieve a specific role by its ID"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role found"),
            @ApiResponse(responseCode = "404", description = "Role not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'ROLE_READ','ROLE_MANAGE','ADMIN')")
    public ResponseEntity<RoleDTO> getRoleById(@PathVariable Long roleId) {
        RoleDTO role = roleService.getRoleById(roleId);
        return ResponseEntity.ok(role);
    }

    @GetMapping("/roles/code/{roleCode}")
    @Operation(
            summary = "Get Role by Code",
            description = "Retrieve a specific role by its unique code"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role found"),
            @ApiResponse(responseCode = "404", description = "Role not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'ROLE_READ','ROLE_MANAGE','ADMIN')")
    public ResponseEntity<RoleDTO> getRoleByCode(@PathVariable String roleCode) {
        RoleDTO role = roleService.getRoleByCode(roleCode);
        return ResponseEntity.ok(role);
    }

    @PostMapping("/roles")
    @Operation(
            summary = "Create New Role",
            description = "Create a new role with specified permissions"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Role created successfully"),
            @ApiResponse(responseCode = "400", description = "Role code already exists"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'ROLE_CREATE','ROLE_MANAGE','ADMIN')")
    public ResponseEntity<RoleDTO> createRole(@Valid @RequestBody RoleDTO roleDTO) {
        log.info("Creating role: {}", roleDTO.getRoleCode());
        RoleDTO role = roleService.createRole(roleDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(role);
    }

    @PutMapping("/roles/{roleId}")
    @Operation(
            summary = "Update Role",
            description = "Update an existing role's information"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Role updated successfully"),
            @ApiResponse(responseCode = "404", description = "Role not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(authentication, 'ROLE_UPDATE', 'ROLE_MANAGE','ADMIN')")
    public ResponseEntity<RoleDTO> updateRole(
            @PathVariable Long roleId,
            @Valid @RequestBody RoleDTO roleDTO) {
        log.info("Updating role: {}", roleId);
        RoleDTO role = roleService.updateRole(roleId, roleDTO);
        return ResponseEntity.ok(role);
    }

    @DeleteMapping("/roles/{roleId}")
    @Operation(
            summary = "Delete Role",
            description = "Delete a role from the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Role deleted successfully"),
            @ApiResponse(responseCode = "404", description = "Role not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(authentication, 'ROLE_DELETE','ADMIN')")
    public ResponseEntity<Void> deleteRole(@PathVariable Long roleId) {
        log.info("Deleting role: {}", roleId);
        roleService.deleteRole(roleId);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/roles/{roleId}/permissions")
    @Operation(
            summary = "Assign Permissions to Role",
            description = "Add permissions to a specific role. Changes take effect immediately for all users with this role."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permissions assigned successfully"),
            @ApiResponse(responseCode = "404", description = "Role or permissions not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'ROLE_UPDATE','ROLE_MANAGE','ADMIN')")
    public ResponseEntity<RoleDTO> assignPermissions(
            @PathVariable Long roleId,
            @RequestBody List<Long> permissionIds) {
        log.info("Assigning permissions to role: {}", roleId);
        RoleDTO role = roleService.assignPermissions(roleId, permissionIds);
        return ResponseEntity.ok(role);
    }

    @DeleteMapping("/roles/{roleId}/permissions")
    @Operation(
            summary = "Remove Permissions from Role",
            description = "Remove permissions from a specific role. Changes take effect immediately."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permissions removed successfully"),
            @ApiResponse(responseCode = "404", description = "Role or permissions not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'ROLE_UPDATE','ROLE_MANAGE','ADMIN')")
    public ResponseEntity<RoleDTO> removePermissions(
            @PathVariable Long roleId,
            @RequestBody List<Long> permissionIds) {
        log.info("Removing permissions from role: {}", roleId);
        RoleDTO role = roleService.removePermissions(roleId, permissionIds);
        return ResponseEntity.ok(role);
    }

    // ==================== Permission Management Endpoints ====================

    @GetMapping("/permissions")
    @Operation(
            summary = "Get All Permissions",
            description = "Retrieve all permissions in the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permissions retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'PERMISSION_READ','PERMISSION_MANAGE','ADMIN')")
    public ResponseEntity<List<PermissionDTO>> getAllPermissions() {
        List<PermissionDTO> permissions = permissionService.getAllPermissions();
        return ResponseEntity.ok(permissions);
    }

    @GetMapping("/permissions/active")
    @Operation(
            summary = "Get Active Permissions",
            description = "Retrieve only active permissions"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Active permissions retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'PERMISSION_READ','PERMISSION_MANAGE','ADMIN')")
    public ResponseEntity<List<PermissionDTO>> getActivePermissions() {
        List<PermissionDTO> permissions = permissionService.getActivePermissions();
        return ResponseEntity.ok(permissions);
    }

    @GetMapping("/permissions/{permissionId}")
    @Operation(
            summary = "Get Permission by ID",
            description = "Retrieve a specific permission by its ID"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permission found"),
            @ApiResponse(responseCode = "404", description = "Permission not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'PERMISSION_READ','PERMISSION_MANAGE','ADMIN')")
    public ResponseEntity<PermissionDTO> getPermissionById(@PathVariable Long permissionId) {
        PermissionDTO permission = permissionService.getPermissionById(permissionId);
        return ResponseEntity.ok(permission);
    }

    @GetMapping("/permissions/code/{permissionCode}")
    @Operation(
            summary = "Get Permission by Code",
            description = "Retrieve a specific permission by its unique code"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permission found"),
            @ApiResponse(responseCode = "404", description = "Permission not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'PERMISSION_READ','PERMISSION_MANAGE','ADMIN')")
    public ResponseEntity<PermissionDTO> getPermissionByCode(@PathVariable String permissionCode) {
        PermissionDTO permission = permissionService.getPermissionByCode(permissionCode);
        return ResponseEntity.ok(permission);
    }

    @GetMapping("/permissions/module/{module}")
    @Operation(
            summary = "Get Permissions by Module",
            description = "Retrieve all permissions for a specific module (e.g., MEMBER, SUBSCRIPTION, PAYMENT)"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permissions retrieved successfully"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'PERMISSION_READ','PERMISSION_MANAGE','ADMIN')")
    public ResponseEntity<List<PermissionDTO>> getPermissionsByModule(@PathVariable String module) {
        List<PermissionDTO> permissions = permissionService.getPermissionsByModule(module);
        return ResponseEntity.ok(permissions);
    }

    @PostMapping("/permissions")
    @Operation(
            summary = "Create New Permission",
            description = "Create a new permission in the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "201", description = "Permission created successfully"),
            @ApiResponse(responseCode = "400", description = "Permission code already exists"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'PERMISSION_CREATE','PERMISSION_MANAGE','ADMIN')")
    public ResponseEntity<PermissionDTO> createPermission(@Valid @RequestBody PermissionDTO permissionDTO) {
        log.info("Creating permission: {}", permissionDTO.getPermissionCode());
        PermissionDTO permission = permissionService.createPermission(permissionDTO);
        return ResponseEntity.status(HttpStatus.CREATED).body(permission);
    }

    @PutMapping("/permissions/{permissionId}")
    @Operation(
            summary = "Update Permission",
            description = "Update an existing permission's information"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Permission updated successfully"),
            @ApiResponse(responseCode = "404", description = "Permission not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'PERMISSION_UPDATE','PERMISSION_MANAGE','ADMIN')")
    public ResponseEntity<PermissionDTO> updatePermission(
            @PathVariable Long permissionId,
            @Valid @RequestBody PermissionDTO permissionDTO) {
        log.info("Updating permission: {}", permissionId);
        PermissionDTO permission = permissionService.updatePermission(permissionId, permissionDTO);
        return ResponseEntity.ok(permission);
    }

    @DeleteMapping("/permissions/{permissionId}")
    @Operation(
            summary = "Delete Permission",
            description = "Delete a permission from the system"
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "204", description = "Permission deleted successfully"),
            @ApiResponse(responseCode = "404", description = "Permission not found"),
            @ApiResponse(responseCode = "403", description = "Access denied")
    })
    @SecurityRequirement(name = "Bearer Authentication")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'PERMISSION_DELETE','ADMIN')")
    public ResponseEntity<Void> deletePermission(@PathVariable Long permissionId) {
        log.info("Deleting permission: {}", permissionId);
        permissionService.deletePermission(permissionId);
        return ResponseEntity.noContent().build();
    }
    // ==================== Helper Methods ====================

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Invalid Authorization header");
    }
}
