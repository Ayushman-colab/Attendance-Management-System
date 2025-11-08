package com.attendace.auth_module.service.inter;

import com.attendace.auth_module.dto.Common.UserDTO;
import com.attendace.auth_module.dto.Request.UpdateUserRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public interface UserService {

    // List & Search
    Page<UserDTO> getAllUsers(Pageable pageable);

    Page<UserDTO> getActiveUsers(Pageable pageable);

    Page<UserDTO> getInactiveUsers(Pageable pageable);

    Page<UserDTO> getUsersByRole(String roleCode, Pageable pageable);

    Page<UserDTO> searchUsers(String keyword, Pageable pageable);

    // Get User Details
    UserDTO getUserById(Long userId);
    UserDTO getUserByUsername(String username);
    UserDTO getUserByEmail(String email);

    UserDTO updateUser(Long userId, @Valid UpdateUserRequest request);

    UserDTO updateUserRole(Long userId, @NotBlank(message = "Role code is required") String roleCode);

    UserDTO activateUser(Long userId);

    UserDTO deactivateUser(Long userId);

    void deleteUser(Long userId);

    Long getTotalUserCount();

    Long getActiveUserCount();

    Long getInactiveUserCount();
}
