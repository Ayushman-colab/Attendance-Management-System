package com.attendace.auth_module.service.inter;

import com.attendace.auth_module.dto.Common.RoleDTO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public interface RoleService {

    public List<RoleDTO> getAllRoles();

    public List<RoleDTO> getActiveRoles();

    public RoleDTO getRoleById(Long id);

    public RoleDTO getRoleByCode(String roleCode);

    public RoleDTO createRole(RoleDTO roleDTO);

    public RoleDTO updateRole(Long roleId, RoleDTO roleDTO);

    public void deleteRole(Long id);

    public RoleDTO assignPermissions(Long roleId, List<Long> permissionIds);

    public RoleDTO removePermissions(Long roleId, List<Long> permissionIds);
}
