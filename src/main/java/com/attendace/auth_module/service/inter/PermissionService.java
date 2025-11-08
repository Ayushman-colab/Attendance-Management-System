package com.attendace.auth_module.service.inter;

import com.attendace.auth_module.Enums.PermissionType;
import com.attendace.auth_module.dto.Common.PermissionDTO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface PermissionService {

    public List<PermissionDTO> getAllPermissions();

    public List<PermissionDTO> getActivePermissions();

    public PermissionDTO getPermissionById(Long permissionId);

    public PermissionDTO getPermissionByCode(String permissionCode);

    public List<PermissionDTO> getPermissionsByModule(String module);

    public List<PermissionDTO> getPermissionsByType(PermissionType permissionType);

    public PermissionDTO createPermission(PermissionDTO permissionDTO);

    public PermissionDTO updatePermission(Long permissionId, PermissionDTO permissionDTO);

    public void deletePermission(Long permissionId);

    public void initializeDefaultPermissions();


}
