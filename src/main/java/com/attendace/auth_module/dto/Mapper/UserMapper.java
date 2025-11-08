package com.attendace.auth_module.dto.Mapper;

import com.attendace.auth_module.dto.Common.UserDTO;
import com.attendace.auth_module.entities.Permission;
import com.attendace.auth_module.entities.Role;
import com.attendace.auth_module.entities.User;
import org.springframework.context.annotation.Configuration;

import java.util.List;
import java.util.stream.Collectors;

@Configuration
public class UserMapper {

    public UserDTO mapToDTO(User user) {
        Role role = user.getRole();

        List<String> permissions;
        if (role.getIsSuperAdmin()) {
            permissions = List.of("*");
        } else {
            permissions = role.getPermissions() != null
                    ? role.getPermissions().stream()
                    .map(Permission::getPermissionCode)
                    .collect(Collectors.toList())
                    : List.of();
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
                .permissions(permissions)
                .isActive(user.getIsActive())
                .lastLoginAt(user.getLastLoginAt())
                .createdAt(user.getCreatedAt())
                .build();
    }
}
