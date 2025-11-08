package com.attendace.Controller;

import com.attendace.Entity.Image;
import com.attendace.Repository.ImageRepository;
import com.attendace.Service.FileUploadService;
import jakarta.validation.constraints.NotNull;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/api/image")
public class UserImageController {

    private final FileUploadService fileUploadService;
    private final ImageRepository imageRepository;

    public UserImageController(FileUploadService fileUploadService, ImageRepository imageRepository) {
        this.fileUploadService = fileUploadService;
        this.imageRepository = imageRepository;
    }




    @PostMapping("/{userId}/profile-image")
    public ResponseEntity<Map<String, Object>> uploadOrUpdateProfileImage(
            @PathVariable Long userId,
            @RequestParam("file") @NotNull MultipartFile file
    ) throws IOException {

        Image user = imageRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found with id " + userId));

        String folder = "attendance_system/profile_images";

        Map uploadResult;

        if (user.getProfileImagePublicId() != null) {

            uploadResult = fileUploadService.updateImage(user.getProfileImagePublicId(), file, folder);
        } else {
            // New image upload
            uploadResult = fileUploadService.uploadImage(file, folder);
        }

        user.setProfileImageUrl((String) uploadResult.get("secure_url"));
        user.setProfileImagePublicId((String) uploadResult.get("public_id"));
        user.setProfileImageUpdatedAt(LocalDateTime.now());

        imageRepository.save(user);


        uploadResult.put("updatedAt", user.getProfileImageUpdatedAt().toString());

        return ResponseEntity.ok(uploadResult);
    }
}
