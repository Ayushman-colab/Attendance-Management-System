package com.attendace.auth_module.repository;

import com.attendace.auth_module.entities.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {

    Optional<Role> findByRoleName(String roleName);
    Optional<Role> findByRoleCode(String roleCode);
    Boolean existsByRoleName(String roleName);
    Boolean existsByRoleCode(String roleCode);
    List<Role> findByIsActiveTrue();

    @Query("SELECT r FROM Role r WHERE r.isSuperAdmin = true")
    Optional<Role> findSuperAdminRole();

    @Query("SELECT r FROM Role r LEFT JOIN FETCH r.permissions WHERE r.roleId = :roleId")
    Optional<Role> findByIdWithPermissions(Long roleId);
}
