package com.attendace.auth_module.dto.Common;

import com.attendace.auth_module.Enums.PermissionType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class PermissionDTO {

    private Long permissionId;
    private String permissionName;
    private String permissionCode;
    private String module;
    private PermissionType permissionType;
    private String description;
    private Boolean isActive;
}
