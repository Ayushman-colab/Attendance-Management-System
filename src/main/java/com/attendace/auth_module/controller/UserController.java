package com.attendace.auth_module.controller;

import com.attendace.auth_module.dto.Common.UserDTO;
import com.attendace.auth_module.dto.Request.UpdateUserRequest;
import com.attendace.auth_module.dto.Request.UpdateUserRoleRequest;
import com.attendace.auth_module.service.inter.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import jakarta.validation.Valid;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@Slf4j
public class UserController {


    private final UserService userService;

    @Autowired
    public UserController(UserService userService) {
        this.userService = userService;
    }

    // ==================== User List & Search ====================

    @Operation(summary = "Get all users", description = "Fetch paginated list of all users.")
    @ApiResponse(responseCode = "200", description = "Successfully retrieved user list")
    @GetMapping
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<Page<UserDTO>> getAllUsers(
            @Parameter(description = "Pagination and sorting details")
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        log.info("Fetching all users with pagination");
        return ResponseEntity.ok(userService.getAllUsers(pageable));
    }

    @Operation(summary = "Get all active users", description = "Fetch paginated list of active users.")
    @GetMapping("/active")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<Page<UserDTO>> getActiveUsers(
            @Parameter(description = "Pagination and sorting details")
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return ResponseEntity.ok(userService.getActiveUsers(pageable));
    }

    @Operation(summary = "Get all inactive users", description = "Fetch paginated list of inactive users.")
    @GetMapping("/inactive")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<Page<UserDTO>> getInactiveUsers(
            @Parameter(description = "Pagination and sorting details")
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return ResponseEntity.ok(userService.getInactiveUsers(pageable));
    }

    @Operation(summary = "Get users by role", description = "Fetch paginated list of users having a specific role.")
    @GetMapping("/role/{roleCode}")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<Page<UserDTO>> getUsersByRole(
            @Parameter(description = "Role code of the users to fetch") @PathVariable String roleCode,
            @Parameter(description = "Pagination and sorting details")
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return ResponseEntity.ok(userService.getUsersByRole(roleCode, pageable));
    }

    @Operation(summary = "Search users", description = "Search users by name, email, or username keyword.")
    @GetMapping("/search")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<Page<UserDTO>> searchUsers(
            @Parameter(description = "Keyword to search users") @RequestParam(required = false) String keyword,
            @Parameter(description = "Pagination and sorting details")
            @PageableDefault(size = 20, sort = "createdAt", direction = Sort.Direction.DESC) Pageable pageable) {
        return ResponseEntity.ok(userService.searchUsers(keyword, pageable));
    }

    // ==================== User Details ====================

    @Operation(summary = "Get user by ID", description = "Fetch user details using the user ID.")
    @GetMapping("/{userId}")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<UserDTO> getUserById(
            @Parameter(description = "ID of the user") @PathVariable Long userId) {
        return ResponseEntity.ok(userService.getUserById(userId));
    }

    @Operation(summary = "Get user by username", description = "Fetch user details using the username.")
    @GetMapping("/username/{username}")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<UserDTO> getUserByUsername(
            @Parameter(description = "Username of the user") @PathVariable String username) {
        return ResponseEntity.ok(userService.getUserByUsername(username));
    }

    @Operation(summary = "Get user by email", description = "Fetch user details using the email address.")
    @GetMapping("/email/{email}")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<UserDTO> getUserByEmail(
            @Parameter(description = "Email address of the user") @PathVariable String email) {
        return ResponseEntity.ok(userService.getUserByEmail(email));
    }

    // ==================== User Update ====================

    @Operation(summary = "Update user details", description = "Update user profile information.")
    @PutMapping("/{userId}")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_UPDATE','USER_MANAGE')")
    public ResponseEntity<UserDTO> updateUser(
            @Parameter(description = "User ID to update") @PathVariable Long userId,
            @Valid @RequestBody UpdateUserRequest request) {
        return ResponseEntity.ok(userService.updateUser(userId, request));
    }

    @Operation(summary = "Update user role", description = "Update the role of a user by user ID.")
    @PatchMapping("/{userId}/role")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_UPDATE','USER_MANAGE')")
    public ResponseEntity<UserDTO> updateUserRole(
            @Parameter(description = "User ID to update role for") @PathVariable Long userId,
            @Valid @RequestBody UpdateUserRoleRequest request) {
        return ResponseEntity.ok(userService.updateUserRole(userId, request.getRoleCode()));
    }

    @Operation(summary = "Activate user", description = "Activate a deactivated user account.")
    @PatchMapping("/{userId}/activate")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_UPDATE','USER_MANAGE')")
    public ResponseEntity<UserDTO> activateUser(
            @Parameter(description = "User ID to activate") @PathVariable Long userId) {
        return ResponseEntity.ok(userService.activateUser(userId));
    }

    @Operation(summary = "Deactivate user", description = "Deactivate an active user account.")
    @PatchMapping("/{userId}/deactivate")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_UPDATE','USER_MANAGE')")
    public ResponseEntity<UserDTO> deactivateUser(
            @Parameter(description = "User ID to deactivate") @PathVariable Long userId) {
        return ResponseEntity.ok(userService.deactivateUser(userId));
    }

    // ==================== User Deletion ====================

    @Operation(summary = "Delete user", description = "Delete a user by ID from the system.")
    @DeleteMapping("/{userId}")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_DELETE')")
    public ResponseEntity<Void> deleteUser(
            @Parameter(description = "User ID to delete") @PathVariable Long userId) {
        userService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }

    // ==================== Statistics ====================

    @Operation(summary = "Get total user count", description = "Fetch the total number of registered users.")
    @GetMapping("/stats/count")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<Long> getTotalUserCount() {
        return ResponseEntity.ok(userService.getTotalUserCount());
    }

    @Operation(summary = "Get active user count", description = "Fetch total count of active users.")
    @GetMapping("/stats/active-count")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<Long> getActiveUserCount() {
        return ResponseEntity.ok(userService.getActiveUserCount());
    }

    @Operation(summary = "Get inactive user count", description = "Fetch total count of inactive users.")
    @GetMapping("/stats/inactive-count")
    @PreAuthorize("@customPermissionEvaluator.hasAnyPermission(Authentication, 'USER_READ','USER_MANAGE')")
    public ResponseEntity<Long> getInactiveUserCount() {
        return ResponseEntity.ok(userService.getInactiveUserCount());
    }

}
