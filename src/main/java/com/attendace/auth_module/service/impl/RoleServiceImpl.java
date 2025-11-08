package com.attendace.auth_module.service.impl;

import com.attendace.auth_module.dto.Common.PermissionDTO;
import com.attendace.auth_module.dto.Common.RoleDTO;
import com.attendace.auth_module.entities.Permission;
import com.attendace.auth_module.entities.Role;
import com.attendace.auth_module.exception.BadRequestException;
import com.attendace.auth_module.exception.ResourceNotFoundException;
import com.attendace.auth_module.repository.PermissionRepository;
import com.attendace.auth_module.repository.RoleRepository;
import com.attendace.auth_module.service.inter.RoleService;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Service
@Slf4j
public class RoleServiceImpl implements RoleService {

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PermissionRepository permissionRepository;

    @Autowired
    private CachedRolePermissionService cachedRoleService;

    public List<RoleDTO> getAllRoles() {
        return roleRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    public List<RoleDTO> getActiveRoles() {
        return roleRepository.findByIsActiveTrue().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    public RoleDTO getRoleById(Long roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));
        return mapToDTO(role);
    }

    public RoleDTO getRoleByCode(String roleCode) {
        Role role = roleRepository.findByRoleCode(roleCode)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found: " + roleCode));
        return mapToDTO(role);
    }

    @Transactional
    public RoleDTO createRole(RoleDTO roleDTO) {
        // Check if role code already exists
        if (roleRepository.existsByRoleCode(roleDTO.getRoleCode())) {
            throw new BadRequestException("Role code already exists: " + roleDTO.getRoleCode());
        }

        Role role = Role.builder()
                .roleName(roleDTO.getRoleName())
                .roleCode(roleDTO.getRoleCode())
                .description(roleDTO.getDescription())
                .isActive(roleDTO.getIsActive() != null ? roleDTO.getIsActive() : true)
                .isSuperAdmin(false) // Cannot create super admin via API
                .permissions(new HashSet<>()) // Initialize empty set
                .build();

        // Add permissions if provided
        if (roleDTO.getPermissions() != null && !roleDTO.getPermissions().isEmpty()) {
            Set<Permission> permissions = roleDTO.getPermissions().stream()
                    .map(p -> permissionRepository.findById(p.getPermissionId())
                            .orElseThrow(() -> new ResourceNotFoundException("Permission not found: " + p.getPermissionId())))
                    .collect(Collectors.toSet());
            role.setPermissions(permissions);
        }

        role = roleRepository.save(role);
        log.info("Role created: {}", role.getRoleCode());
        return mapToDTO(role);
    }

    @Transactional
    public RoleDTO updateRole(Long roleId, RoleDTO roleDTO) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        // Cannot modify super admin role
        if (role.getIsSuperAdmin()) {
            throw new BadRequestException("Cannot modify super admin role");
        }

        role.setRoleName(roleDTO.getRoleName());
        role.setDescription(roleDTO.getDescription());
        role.setIsActive(roleDTO.getIsActive());

        role = roleRepository.save(role);
        // Clear cache after update
        cachedRoleService.evictRoleCache(roleId);
        log.info("Role updated: {}", role.getRoleCode());
        return mapToDTO(role);
    }

    @Transactional
    public void deleteRole(Long roleId) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        // Cannot delete super admin role
        if (role.getIsSuperAdmin()) {
            throw new BadRequestException("Cannot delete super admin role");
        }

        roleRepository.delete(role);
        log.info("Role deleted: {}", role.getRoleCode());
    }

    @Transactional
    public RoleDTO assignPermissions(Long roleId, List<Long> permissionIds) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        // Super admin already has all permissions
        if (role.getIsSuperAdmin()) {
            throw new BadRequestException("Super admin already has all permissions");
        }

        Set<Permission> permissions = permissionIds.stream()
                .map(id -> permissionRepository.findById(id)
                        .orElseThrow(() -> new ResourceNotFoundException("Permission not found: " + id)))
                .collect(Collectors.toSet());

        role.setPermissions(permissions);
        role = roleRepository.save(role);
        // Clear cache after permission change
        cachedRoleService.evictRoleCache(roleId);
        log.info("Permissions assigned to role: {}", role.getRoleCode());
        return mapToDTO(role);
    }

    @Transactional
    public RoleDTO removePermissions(Long roleId, List<Long> permissionIds) {
        Role role = roleRepository.findById(roleId)
                .orElseThrow(() -> new ResourceNotFoundException("Role not found"));

        if (role.getIsSuperAdmin()) {
            throw new BadRequestException("Cannot remove permissions from super admin");
        }

        permissionIds.forEach(id ->
                role.getPermissions().removeIf(p -> p.getPermissionId().equals(id))
        );

        Role updatedRole = roleRepository.save(role);
        log.info("Permissions removed from role: {}", updatedRole.getRoleCode());
        return mapToDTO(role);
    }

    // Convert Map Role to RoleDTO
    private RoleDTO mapToDTO(Role role) {
        // Handle null permissions - return empty list instead of causing NPE
        List<PermissionDTO> permissionDTOs = (role.getPermissions() != null && !role.getPermissions().isEmpty())
                ? role.getPermissions().stream()
                .map(this::mapPermissionToDTO)
                .collect(Collectors.toList())
                : new ArrayList<>();

        return RoleDTO.builder()
                .roleId(role.getRoleId())
                .roleName(role.getRoleName())
                .roleCode(role.getRoleCode())
                .description(role.getDescription())
                .isActive(role.getIsActive())
                .isSuperAdmin(role.getIsSuperAdmin())
                .permissions(permissionDTOs)
                .build();
    }

    // Convert Map Permission to PermissionDTO
    private PermissionDTO mapPermissionToDTO(Permission permission) {
        return PermissionDTO.builder()
                .permissionId(permission.getPermissionId())
                .permissionName(permission.getPermissionName())
                .permissionCode(permission.getPermissionCode())
                .module(permission.getModule())
                .permissionType(permission.getPermissionType())
                .description(permission.getDescription())
                .isActive(permission.getIsActive())
                .build();
    }
}
