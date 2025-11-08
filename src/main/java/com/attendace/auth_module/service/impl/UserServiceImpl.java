package com.attendace.auth_module.service.impl;

import com.attendace.auth_module.dto.Common.UserDTO;
import com.attendace.auth_module.dto.Mapper.UserMapper;
import com.attendace.auth_module.dto.Request.UpdateUserRequest;
import com.attendace.auth_module.entities.Role;
import com.attendace.auth_module.entities.User;   
import com.attendace.auth_module.exception.BadRequestException;
import com.attendace.auth_module.exception.ResourceNotFoundException;
import com.attendace.auth_module.repository.RoleRepository;
import com.attendace.auth_module.repository.UserRepository;
import com.attendace.auth_module.service.inter.UserService;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UserServiceImpl implements UserService {


    @Autowired
    UserRepository userRepository;

    @Autowired
    RoleRepository roleRepository;

    @Autowired
    UserMapper userMapper;

    @Override
    public Page<UserDTO> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable)
                .map(user-> userMapper.mapToDTO(user));
    }

    @Override
    public Page<UserDTO> getActiveUsers(Pageable pageable) {
        return userRepository.findByIsActiveTrue(pageable)
                .map(user-> userMapper.mapToDTO(user));
    }

    @Override
    public Page<UserDTO> getInactiveUsers(Pageable pageable) {
        return userRepository.findByIsActiveFalse(pageable)
                .map(user-> userMapper.mapToDTO(user));
    }

    @Override
    public Page<UserDTO> getUsersByRole(String roleCode, Pageable pageable) {
        return userRepository.findByRoleCode(roleCode, pageable)
                .map(user-> userMapper.mapToDTO(user));
    }

    @Override
    public Page<UserDTO> searchUsers(String keyword, Pageable pageable) {
        if (keyword == null || keyword.trim().isEmpty()) {
            return getAllUsers(pageable);
        }
        return userRepository.searchUsers(keyword, pageable)
                .map(user-> userMapper.mapToDTO(user));
    }

    // ==================== Get User Details ====================

    @Override
    public UserDTO getUserById(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));
        return userMapper.mapToDTO(user);
    }

    @Override
    public UserDTO getUserByUsername(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with username: " + username));
        return userMapper.mapToDTO(user);
    }

    @Override
    public UserDTO getUserByEmail(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with email: " + email));
        return userMapper.mapToDTO(user);
    }

    // ==================== Update User ====================

    @Override
    @Transactional
    public UserDTO updateUser(Long userId, UpdateUserRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        // Check if email is being changed and if it's already taken
        if (request.getEmail() != null && !request.getEmail().equals(user.getEmail())) {
            if (userRepository.existsByEmail(request.getEmail())) {
                throw new BadRequestException("Email is already registered: " + request.getEmail());
            }
            user.setEmail(request.getEmail());
        }

        // Update fields
        if (request.getFirstName() != null) {
            user.setFirstName(request.getFirstName());
        }
        if (request.getLastName() != null) {
            user.setLastName(request.getLastName());
        }
        if (request.getPhone() != null) {
            user.setPhone(request.getPhone());
        }

        user = userRepository.save(user);
        log.info("User updated: {}", user.getUsername());
        return userMapper.mapToDTO(user);
    }

    @Override
    @Transactional
    public UserDTO updateUserRole(Long userId, String roleCode) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        // Cannot change super admin role
        if (user.getRole().getIsSuperAdmin()) {
            throw new BadRequestException("Cannot change role of super admin");
        }

        Role newRole = roleRepository.findByRoleCode(roleCode)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleCode));

        // Cannot assign super admin role via API
        if (newRole.getIsSuperAdmin()) {
            throw new BadRequestException("Cannot assign super admin role via API");
        }

        user.setRole(newRole);
        user = userRepository.save(user);
        log.info("User role updated: {} -> {}", user.getUsername(), roleCode);
        return userMapper.mapToDTO(user);
    }

    @Override
    @Transactional
    public UserDTO activateUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        if (user.getIsActive()) {
            throw new BadRequestException("User is already active");
        }

        user.setIsActive(true);
        user = userRepository.save(user);
        log.info("User activated: {}", user.getUsername());
        return userMapper.mapToDTO(user);
    }

    @Override
    @Transactional
    public UserDTO deactivateUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        // Cannot deactivate super admin
        if (user.getRole().getIsSuperAdmin()) {
            throw new BadRequestException("Cannot deactivate super admin");
        }

        if (!user.getIsActive()) {
            throw new BadRequestException("User is already inactive");
        }

        user.setIsActive(false);
        user = userRepository.save(user);
        log.info("User deactivated: {}", user.getUsername());
        return userMapper.mapToDTO(user);
    }

    // ==================== Delete User ====================

    @Override
    @Transactional
    public void deleteUser(Long userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new ResourceNotFoundException("User not found with ID: " + userId));

        // Cannot delete super admin
        if (user.getRole().getIsSuperAdmin()) {
            throw new BadRequestException("Cannot delete super admin");
        }

        userRepository.delete(user);
        log.info("User deleted: {}", user.getUsername());
    }

    // ==================== Statistics ====================

    @Override
    public Long getTotalUserCount() {
        return userRepository.count();
    }

    @Override
    public Long getActiveUserCount() {
        return userRepository.countByIsActiveTrue();
    }

    @Override
    public Long getInactiveUserCount() {
        return userRepository.countByIsActiveFalse();
    }

}
