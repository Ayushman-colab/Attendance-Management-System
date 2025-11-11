package com.attendace.Controller;


import com.attendace.Service.Interface.AttendanceService;
import com.attendace.Service.Interface.FileUploadService;
import com.attendace.dto.request.AttendanceRequestDTO;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import org.springframework.mock.web.MockMultipartFile;
import java.util.HashMap;
import java.util.Map;
import java.util.Random;

@RestController
@RequestMapping("/api/users")
public class UserImageController {

    private final FileUploadService fileUploadService;
    private final AttendanceService attendanceService;

    public UserImageController(FileUploadService fileUploadService, AttendanceService attendanceService) {
        this.fileUploadService = fileUploadService;
        this.attendanceService = attendanceService;
    }


    @PostMapping(
            value = "/profile-image",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,   // This ensures backend accepts multipart/form-data
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> uploadOrUpdateProfileImage(
            Authentication authentication,
            @RequestParam("profileImage") MultipartFile profileImage
    ) throws IOException {
        return ResponseEntity.ok(fileUploadService.uploadOrUpdateProfileImage(authentication , profileImage));
    }

    @PostMapping(
            value = "/Attandance",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> attendacneInOrOut(
            Authentication authentication,
            @ModelAttribute AttendanceRequestDTO attendanceRequestDTO
    ) throws IOException {

        MultipartFile image = attendanceRequestDTO.getImageFile();

        return ResponseEntity.ok(
                attendanceService.attendanceInOrOut(authentication, image, attendanceRequestDTO)
        );
    }

    // 🖼️ Path to your image on Desktop (Update this path if needed)
    private static final String IMAGE_PATH = "C:\\Users\\rites\\Downloads\\full-shot-ninja-wearing-equipment.jpg";

    @PostMapping(value = "/generate-attendance", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> generateAttendanceData(Authentication authentication,
            @RequestParam(defaultValue = "5000") int count
    ) throws IOException {

        int success = 0;
        int failed = 0;
        Random random = new Random();

        // Load image from Desktop once
        File file = new File(IMAGE_PATH);
        if (!file.exists()) {
            throw new IOException("Image not found at: " + IMAGE_PATH);
        }

        FileInputStream fis = new FileInputStream(file);
        MultipartFile imageFile = new MockMultipartFile("imageFile", file.getName(), "image/jpeg", fis);

        for (long userId = 1; userId <= count; userId++) {
            try {
                AttendanceRequestDTO dto = AttendanceRequestDTO.builder()
                        .userId(userId)
                        .imageFile(imageFile)
                        .longitude(77.0 + random.nextDouble())
                        .latitude(13.0 + random.nextDouble())
                        .ipAddress("192.168.1." + (userId % 255))
                        .build();

                attendanceService.attendanceInOrOut(authentication,imageFile, dto);
                success++;

                if (userId % 500 == 0)
                    System.out.println("Generated attendance for user ID: " + userId);

            } catch (Exception e) {
                failed++;
                System.err.println("Failed for user ID " + userId + ": " + e.getMessage());
            }
        }

        Map<String, Object> result = new HashMap<>();
        result.put("requestedCount", count);
        result.put("successCount", success);
        result.put("failedCount", failed);
        result.put("imageUsed", file.getAbsolutePath());
        result.put("message", "Attendance generated for users 1 to " + count);

        return ResponseEntity.ok(result);
    }
}
