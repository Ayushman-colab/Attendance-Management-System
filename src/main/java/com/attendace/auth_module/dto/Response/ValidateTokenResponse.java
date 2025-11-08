package com.attendace.auth_module.dto.Response;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ValidateTokenResponse {

    private Boolean valid;
    private Long userId;
    private String username;
    private String email;
    private String roleCode;
    private Boolean isSuperAdmin;
    private List<String> permissions;
    private String message;
}
