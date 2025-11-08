package com.attendace.auth_module.dto.Common;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RoleDTO {

    private Long roleId;
    private String roleName;
    private String roleCode;
    private String description;
    private Boolean isActive;
    private Boolean isSuperAdmin;
    private List<PermissionDTO> permissions;
}
