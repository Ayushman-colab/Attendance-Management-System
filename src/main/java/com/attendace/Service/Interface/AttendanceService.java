package com.attendace.Service.Interface;

import com.attendace.dto.request.AttendanceRequestDTO;
import org.springframework.security.core.Authentication;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

public interface AttendanceService {
    Map<String, Object> attendanceInOrOut(
            Authentication authentication,
            MultipartFile image,
            AttendanceRequestDTO attendanceRequestDTO
    ) throws IOException;
}
