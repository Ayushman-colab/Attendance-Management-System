package com.attendace.auth_module.service.impl;

import com.attendace.auth_module.Enums.PermissionType;
import com.attendace.auth_module.dto.Common.PermissionDTO;
import com.attendace.auth_module.entities.Permission;
import com.attendace.auth_module.exception.BadRequestException;
import com.attendace.auth_module.exception.ResourceNotFoundException;
import com.attendace.auth_module.repository.PermissionRepository;
import com.attendace.auth_module.service.inter.PermissionService;
import jakarta.transaction.Transactional;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.stream.Collectors;

@Service
@Slf4j
public class PermissionServiceImpl implements PermissionService {

    @Autowired
    private PermissionRepository permissionRepository;

    public List<PermissionDTO> getAllPermissions() {
        return permissionRepository.findAll().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    public List<PermissionDTO> getActivePermissions() {
        return permissionRepository.findByIsActiveTrue().stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    public PermissionDTO getPermissionById(Long permissionId) {
        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found"));
        return mapToDTO(permission);
    }

    public PermissionDTO getPermissionByCode(String permissionCode) {
        Permission permission = permissionRepository.findByPermissionCode(permissionCode)
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found: " + permissionCode));
        return mapToDTO(permission);
    }

    public List<PermissionDTO> getPermissionsByModule(String module) {
        return permissionRepository.findByModule(module).stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    public List<PermissionDTO> getPermissionsByType(PermissionType permissionType) {
        return permissionRepository.findByPermissionType(permissionType).stream()
                .map(this::mapToDTO)
                .collect(Collectors.toList());
    }

    @Transactional
    public PermissionDTO createPermission(PermissionDTO permissionDTO) {
        // Check if permission code already exists
        if (permissionRepository.existsByPermissionCode(permissionDTO.getPermissionCode())) {
            throw new BadRequestException("Permission code already exists: " + permissionDTO.getPermissionCode());
        }

        Permission permission = Permission.builder()
                .permissionName(permissionDTO.getPermissionName())
                .permissionCode(permissionDTO.getPermissionCode())
                .module(permissionDTO.getModule())
                .permissionType(permissionDTO.getPermissionType())
                .description(permissionDTO.getDescription())
                .isActive(permissionDTO.getIsActive() != null ? permissionDTO.getIsActive() : true)
                .build();

        permission = permissionRepository.save(permission);
        log.info("Permission created: {}", permission.getPermissionCode());
        return mapToDTO(permission);
    }

    @Transactional
    public PermissionDTO updatePermission(Long permissionId, PermissionDTO permissionDTO) {
        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found"));

        permission.setPermissionName(permissionDTO.getPermissionName());
        permission.setModule(permissionDTO.getModule());
        permission.setPermissionType(permissionDTO.getPermissionType());
        permission.setDescription(permissionDTO.getDescription());
        permission.setIsActive(permissionDTO.getIsActive());

        permission = permissionRepository.save(permission);
        log.info("Permission updated: {}", permission.getPermissionCode());
        return mapToDTO(permission);
    }

    @Transactional
    public void deletePermission(Long permissionId) {
        Permission permission = permissionRepository.findById(permissionId)
                .orElseThrow(() -> new ResourceNotFoundException("Permission not found"));

        permissionRepository.delete(permission);
        log.info("Permission deleted: {}", permission.getPermissionCode());
    }

    @Transactional
    public void initializeDefaultPermissions() {
        // Only initialize if no permissions exist
        if (permissionRepository.count() > 0) {
            log.info("Permissions already initialized");
            return;
        }

        log.info("Initializing default permissions...");

        // Member permissions
        createDefaultPermission("MEMBER_CREATE", "Create Member", "MEMBER", PermissionType.CREATE);
        createDefaultPermission("MEMBER_READ", "Read Member", "MEMBER", PermissionType.READ);
        createDefaultPermission("MEMBER_UPDATE", "Update Member", "MEMBER", PermissionType.UPDATE);
        createDefaultPermission("MEMBER_DELETE", "Delete Member", "MEMBER", PermissionType.DELETE);
        createDefaultPermission("MEMBER_EXPORT", "Export Members", "MEMBER", PermissionType.EXPORT);

        // Subscription permissions
        createDefaultPermission("SUBSCRIPTION_CREATE", "Create Subscription", "SUBSCRIPTION", PermissionType.CREATE);
        createDefaultPermission("SUBSCRIPTION_READ", "Read Subscription", "SUBSCRIPTION", PermissionType.READ);
        createDefaultPermission("SUBSCRIPTION_UPDATE", "Update Subscription", "SUBSCRIPTION", PermissionType.UPDATE);
        createDefaultPermission("SUBSCRIPTION_DELETE", "Delete Subscription", "SUBSCRIPTION", PermissionType.DELETE);
        createDefaultPermission("SUBSCRIPTION_APPROVE", "Approve Subscription", "SUBSCRIPTION", PermissionType.APPROVE);

        // Payment permissions
        createDefaultPermission("PAYMENT_CREATE", "Create Payment", "PAYMENT", PermissionType.CREATE);
        createDefaultPermission("PAYMENT_READ", "Read Payment", "PAYMENT", PermissionType.READ);
        createDefaultPermission("PAYMENT_UPDATE", "Update Payment", "PAYMENT", PermissionType.UPDATE);
        createDefaultPermission("PAYMENT_DELETE", "Delete Payment", "PAYMENT", PermissionType.DELETE);
        createDefaultPermission("PAYMENT_APPROVE", "Approve Payment", "PAYMENT", PermissionType.APPROVE);

        // Trainer permissions
        createDefaultPermission("TRAINER_CREATE", "Create Trainer", "TRAINER", PermissionType.CREATE);
        createDefaultPermission("TRAINER_READ", "Read Trainer", "TRAINER", PermissionType.READ);
        createDefaultPermission("TRAINER_UPDATE", "Update Trainer", "TRAINER", PermissionType.UPDATE);
        createDefaultPermission("TRAINER_DELETE", "Delete Trainer", "TRAINER", PermissionType.DELETE);

        // Attendance permissions
        createDefaultPermission("ATTENDANCE_CREATE", "Create Attendance", "ATTENDANCE", PermissionType.CREATE);
        createDefaultPermission("ATTENDANCE_READ", "Read Attendance", "ATTENDANCE", PermissionType.READ);
        createDefaultPermission("ATTENDANCE_UPDATE", "Update Attendance", "ATTENDANCE", PermissionType.UPDATE);
        createDefaultPermission("ATTENDANCE_DELETE", "Delete Attendance", "ATTENDANCE", PermissionType.DELETE);

        // Inventory permissions
        createDefaultPermission("INVENTORY_CREATE", "Create Inventory", "INVENTORY", PermissionType.CREATE);
        createDefaultPermission("INVENTORY_READ", "Read Inventory", "INVENTORY", PermissionType.READ);
        createDefaultPermission("INVENTORY_UPDATE", "Update Inventory", "INVENTORY", PermissionType.UPDATE);
        createDefaultPermission("INVENTORY_DELETE", "Delete Inventory", "INVENTORY", PermissionType.DELETE);

        // Report permissions
        createDefaultPermission("REPORT_VIEW", "View Reports", "REPORT", PermissionType.READ);
        createDefaultPermission("REPORT_EXPORT", "Export Reports", "REPORT", PermissionType.EXPORT);

        // User management permissions
        createDefaultPermission("USER_MANAGE", "Manage Users", "USER", PermissionType.MANAGE);
        createDefaultPermission("ROLE_MANAGE", "Manage Roles", "ROLE", PermissionType.MANAGE);
        createDefaultPermission("PERMISSION_MANAGE", "Manage Permissions", "PERMISSION", PermissionType.MANAGE);

        log.info("Default permissions initialized successfully");
    }

    private void createDefaultPermission(String code, String name, String module, PermissionType type) {
        Permission permission = Permission.builder()
                .permissionCode(code)
                .permissionName(name)
                .module(module)
                .permissionType(type)
                .description("Default " + name + " permission")
                .isActive(true)
                .build();
        permissionRepository.save(permission);
    }

    private PermissionDTO mapToDTO(Permission permission) {
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
