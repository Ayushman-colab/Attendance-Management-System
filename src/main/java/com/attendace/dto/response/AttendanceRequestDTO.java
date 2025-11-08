package com.attendace.dto.response;

import com.attendace.enums.AttendanceType;
import lombok.*;
import lombok.experimental.FieldDefaults;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@FieldDefaults(level = AccessLevel.PRIVATE)
public class AttendanceRequestDTO {
    LocalDateTime attTime;
    AttendanceType attType;
    MultipartFile imageFile;
    Double longitude;
    Double latitude;
    String ipAddress;
    Long userId;
}
