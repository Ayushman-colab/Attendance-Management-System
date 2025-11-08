//package com.attendace.auth_module.config;
//
//import com.attendace.auth_module.entities.Permission;
//import com.attendace.auth_module.entities.Role;
//import com.attendace.auth_module.entities.User;
//import com.attendace.auth_module.repository.PermissionRepository;
//import com.attendace.auth_module.repository.RoleRepository;
//import com.attendace.auth_module.repository.UserRepository;
//import com.attendace.auth_module.service.inter.PermissionService;
//import lombok.extern.slf4j.Slf4j;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.stereotype.Component;
//
//import java.util.HashSet;
//
//@Component
//@Slf4j
//public class DataInitializer implements CommandLineRunner {
//
//    @Autowired
//    private PermissionRepository permissionRepository;
//
//    @Autowired
//    private RoleRepository roleRepository;
//
//    @Autowired
//    private UserRepository userRepository;
//
//    @Autowired
//    private PasswordEncoder passwordEncoder;
//
//    @Autowired
//    private PermissionService permissionService;
//
//    @Override
//    public void run(String... args) {
//        log.info("Starting data initialization...");
//
//        // Step 1: Initialize permissions
//        permissionService.initializeDefaultPermissions();
//
//        // Step 2: Create Super Admin role
//        createSuperAdminRole();
//
//        // Step 3: Create default roles
//        createDefaultRoles();
//
//        // Step 4: Create super admin user
//        createSuperAdminUser();
//
//        log.info("Data initialization completed");
//    }
//
//    private void createSuperAdminRole() {
//        if (roleRepository.findSuperAdminRole().isPresent()) {
//            log.info("Super Admin role already exists");
//            return;
//        }
//
//        Role superAdminRole = Role.builder()
//                .roleName("Super Administrator")
//                .roleCode("SUPER_ADMIN")
//                .description("Super Administrator with all permissions")
//                .isActive(true)
//                .isSuperAdmin(true)
//                .permissions(new HashSet<>()) // Super admin doesn't need explicit permissions
//                .build();
//
//        roleRepository.save(superAdminRole);
//        log.info("Super Admin role created successfully");
//    }
//
//    private void createDefaultRoles() {
//        // Admin Role
//        createRoleIfNotExists(
//                "Administrator",
//                "ADMIN",
//                "System Administrator with management permissions",
//                new String[]{
//                        "USER_MANAGE", "ROLE_MANAGE", "PERMISSION_MANAGE",
//                        "MEMBER_CREATE", "MEMBER_READ", "MEMBER_UPDATE", "MEMBER_DELETE", "MEMBER_EXPORT",
//                        "SUBSCRIPTION_CREATE", "SUBSCRIPTION_READ", "SUBSCRIPTION_UPDATE", "SUBSCRIPTION_DELETE", "SUBSCRIPTION_APPROVE",
//                        "PAYMENT_CREATE", "PAYMENT_READ", "PAYMENT_UPDATE", "PAYMENT_DELETE", "PAYMENT_APPROVE",
//                        "TRAINER_CREATE", "TRAINER_READ", "TRAINER_UPDATE", "TRAINER_DELETE",
//                        "ATTENDANCE_CREATE", "ATTENDANCE_READ", "ATTENDANCE_UPDATE", "ATTENDANCE_DELETE",
//                        "INVENTORY_CREATE", "INVENTORY_READ", "INVENTORY_UPDATE", "INVENTORY_DELETE",
//                        "REPORT_VIEW", "REPORT_EXPORT"
//                }
//        );
//
//        // Manager Role
//        createRoleIfNotExists(
//                "Manager",
//                "MANAGER",
//                "Gym Manager with operational permissions",
//                new String[]{
//                        "MEMBER_CREATE", "MEMBER_READ", "MEMBER_UPDATE", "MEMBER_EXPORT",
//                        "SUBSCRIPTION_CREATE", "SUBSCRIPTION_READ", "SUBSCRIPTION_UPDATE", "SUBSCRIPTION_APPROVE",
//                        "PAYMENT_CREATE", "PAYMENT_READ", "PAYMENT_UPDATE",
//                        "TRAINER_READ", "TRAINER_UPDATE",
//                        "ATTENDANCE_CREATE", "ATTENDANCE_READ", "ATTENDANCE_UPDATE",
//                        "INVENTORY_READ", "INVENTORY_UPDATE",
//                        "REPORT_VIEW", "REPORT_EXPORT"
//                }
//        );
//
//        // Receptionist Role
//        createRoleIfNotExists(
//                "Receptionist",
//                "RECEPTIONIST",
//                "Front desk receptionist",
//                new String[]{
//                        "MEMBER_READ", "MEMBER_CREATE",
//                        "SUBSCRIPTION_READ",
//                        "PAYMENT_READ", "PAYMENT_CREATE",
//                        "ATTENDANCE_CREATE", "ATTENDANCE_READ"
//                }
//        );
//
//        // Trainer Role
//        createRoleIfNotExists(
//                "Trainer",
//                "TRAINER",
//                "Gym Trainer",
//                new String[]{
//                        "MEMBER_READ",
//                        "ATTENDANCE_READ", "ATTENDANCE_CREATE",
//                        "TRAINER_READ"
//                }
//        );
//
//        // Member Role
//        createRoleIfNotExists(
//                "Member",
//                "MEMBER",
//                "Gym Member",
//                new String[]{
//                        "MEMBER_READ",
//                        "SUBSCRIPTION_READ",
//                        "PAYMENT_READ",
//                        "ATTENDANCE_READ"
//                }
//        );
//    }
//
//    private void createRoleIfNotExists(String roleName, String roleCode, String description, String[] permissionCodes) {
//        if (roleRepository.findByRoleCode(roleCode).isPresent()) {
//            log.info("Role '{}' already exists", roleCode);
//            return;
//        }
//
//        // Get permissions
//        HashSet<Permission> permissions = new HashSet<>();
//        for (String permissionCode : permissionCodes) {
//            permissionRepository.findByPermissionCode(permissionCode)
//                    .ifPresent(permissions::add);
//        }
//
//        Role role = Role.builder()
//                .roleName(roleName)
//                .roleCode(roleCode)
//                .description(description)
//                .isActive(true)
//                .isSuperAdmin(false)
//                .permissions(permissions)
//                .build();
//
//        roleRepository.save(role);
//        log.info("Role '{}' created with {} permissions", roleCode, permissions.size());
//    }
//
//    private void createSuperAdminUser() {
//        if (userRepository.findByUsername("superadmin").isPresent()) {
//            log.info("Super Admin user already exists");
//            return;
//        }
//
//        Role superAdminRole = roleRepository.findSuperAdminRole()
//                .orElseThrow(() -> new RuntimeException("Super Admin role not found"));
//
//        User superAdmin = User.builder()
//                .username("?")
//                .email("?@gym.com")
//                .passwordHash(passwordEncoder.encode("?"))
//                .firstName("Super")
//                .lastName("Admin")
//                .phone("9999999999")
//                .role(superAdminRole)
//                .isActive(true)
//                .build();
//
//        userRepository.save(superAdmin);
//        log.info("Super Admin user created successfully");
//        log.info("Login Credentials - Username: superadmin, Password: Admin@123");
//        log.warn("IMPORTANT: Please change the default password after first login!");
//    }
//}
