package com.attendace.dto.response;

import com.attendace.enums.AttendanceType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
public class AttendanceResponseDTO {
    Long attendanceId;
    LocalDateTime attTime;
    AttendanceType attType;
    String imageUrl;
    Double longitude;
    Double latitude;
    String ipAddress;

    Long userId;
    String username;
    String email;
}
