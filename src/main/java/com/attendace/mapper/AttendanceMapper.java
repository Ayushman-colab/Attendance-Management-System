package com.attendace.mapper;

import com.attendace.auth_module.entities.User;
import com.attendace.dto.request.AttendanceRequestDTO;
import com.attendace.dto.response.AttendanceResponseDTO;
import com.attendace.entities.Attendance;
import com.attendace.enums.AttendanceType;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

@Component
public class AttendanceMapper {

    public Attendance toEntity(AttendanceRequestDTO dto, String imageUrl, User user, AttendanceType type) {
        return Attendance.builder()
                .imageUrl(imageUrl)
                .longitude(dto.getLongitude())
                .latitude(dto.getLatitude())
                .ipAddress(dto.getIpAddress())
                .attType(type)
                .user(user)
                .build();
    }

    // 🔹 Convert Entity → Response DTO
    public AttendanceResponseDTO toResponseDTO(Attendance entity) {
        return AttendanceResponseDTO.builder()
                .attendanceId(entity.getAttId())
                .attTime(entity.getAttTime())
                .attType(entity.getAttType())
                .imageUrl(entity.getImageUrl())
                .longitude(entity.getLongitude())
                .latitude(entity.getLatitude())
                .ipAddress(entity.getIpAddress())
                .userId(entity.getUser().getUserId())
                .username(entity.getUser().getUsername())
                .email(entity.getUser().getEmail())
                .build();
    }
}
