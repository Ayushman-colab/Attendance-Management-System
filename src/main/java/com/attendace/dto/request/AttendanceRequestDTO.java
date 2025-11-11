package com.attendace.dto.request;

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
    Long userId;
    MultipartFile imageFile;
    Double longitude;
    Double latitude;
    String ipAddress;
}
