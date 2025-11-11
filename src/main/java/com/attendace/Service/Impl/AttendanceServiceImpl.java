package com.attendace.Service.Impl;

import com.attendace.Service.Interface.AttendanceService;
import com.attendace.auth_module.entities.User;
import com.attendace.auth_module.repository.UserRepository;
import com.attendace.dto.request.AttendanceRequestDTO;
import com.attendace.dto.response.AttendanceResponseDTO;
import com.attendace.entities.Attendance;
import com.attendace.enums.AttendanceType;
import com.attendace.mapper.AttendanceMapper;
import com.attendace.repository.AttendanceRepository;
import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class AttendanceServiceImpl implements AttendanceService {

    private final UserRepository userRepository;
    private final AttendanceRepository attendanceRepository;
    private final AttendanceMapper attendanceMapper;
    private final Cloudinary cloudinary;

    public AttendanceServiceImpl(UserRepository userRepository, AttendanceRepository attendanceRepository, AttendanceMapper attendanceMapper, Cloudinary cloudinary) {
        this.userRepository = userRepository;
        this.attendanceRepository = attendanceRepository;
        this.attendanceMapper = attendanceMapper;
        this.cloudinary = cloudinary;
    }

    @Override
    public Map<String, Object> attendanceInOrOut(Authentication authentication, MultipartFile image, AttendanceRequestDTO attendanceRequestDTO) throws IOException {
        Map<String, Object> response = new HashMap<>();

        System.out.println("attendanceRequestDTO"+attendanceRequestDTO);

        //  Get logged-in user
//        User user = userRepository.findByUsername(authentication.getName())
//                .orElseThrow(() -> new RuntimeException("User not found"));

        User user = userRepository.findById(attendanceRequestDTO.getUserId()).get();

        // 🗓 Get today’s date
        LocalDate today = LocalDate.now();

        //  Check if user has already marked attendance today
        List<Attendance> userAttendance = attendanceRepository.findByUserIdAndDate(user.getUserId(), today);

        AttendanceType attendanceType;
        String message;

        //  Upload attendance image
        Map uploadResult = cloudinary.uploader().upload(
                image.getBytes(),
                ObjectUtils.asMap(
                        "folder", "attendance_app/attendance_images/" + user.getUserId(),
                        "resource_type", "image",
                        "quality", "auto:good",
                        "format", "jpg",
                        "overwrite", true
                )
        );
        String imageUrl = (String) uploadResult.get("secure_url");

        Attendance attendance;

        //  Determine attendance type
        if (userAttendance == null || userAttendance.isEmpty()) {
            // First attendance of the day → IN
            attendanceType = AttendanceType.IN_TIME;
            message = "Check-in marked successfully.";
        } else {
            // Already checked in → mark OUT
            attendanceType = AttendanceType.OUT_TIME;
            message = "Check-out marked successfully.";
        }

        //  Build Attendance entity from DTO and save
        attendance = attendanceMapper.toEntity(attendanceRequestDTO, imageUrl, user, attendanceType);
        attendance.setAttTime(LocalDateTime.now());

        attendanceRepository.save(attendance);

        //  Convert to Response DTO
        AttendanceResponseDTO responseDTO = attendanceMapper.toResponseDTO(attendance);

        //  Build response
        response.put("status", "success");
        response.put("message", message);
        response.put("data", responseDTO);

        return response;
    }
}
