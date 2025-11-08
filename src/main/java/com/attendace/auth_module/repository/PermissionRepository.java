package com.attendace.auth_module.repository;

import com.attendace.auth_module.Enums.PermissionType;
import com.attendace.auth_module.entities.Permission;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PermissionRepository extends JpaRepository<Permission, Long> {
    Optional<Permission> findByPermissionCode(String permissionCode);
    List<Permission> findByModule(String module);
    List<Permission> findByPermissionType(PermissionType permissionType);
    List<Permission> findByModuleAndPermissionType(String module, PermissionType permissionType);
    Boolean existsByPermissionCode(String permissionCode);
    List<Permission> findByIsActiveTrue();
}
