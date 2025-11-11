package com.attendace.auth_module.service.inter;

import com.attendace.auth_module.dto.Common.UserDTO;
import com.attendace.auth_module.dto.Request.LoginRequest;
import com.attendace.auth_module.dto.Request.RefreshTokenRequest;
import com.attendace.auth_module.dto.Request.RegisterRequest;
import com.attendace.auth_module.dto.Response.LoginResponse;
import com.attendace.auth_module.dto.Response.TokenResponse;
import com.attendace.auth_module.dto.Response.ValidateTokenResponse;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
public interface AuthService {

    public LoginResponse login(LoginRequest request);

    public UserDTO register(RegisterRequest request);

    public TokenResponse refreshToken(RefreshTokenRequest request);

    public void logout(String token);

    public ValidateTokenResponse validateToken(String token);

    public UserDTO getCurrentUser(String token);


    public String forgotPassword(String email);

    public Map<String, String> verifyOtp(String email, String otp);

    public String resetPassword(String resetToken, String newPassword);
}
