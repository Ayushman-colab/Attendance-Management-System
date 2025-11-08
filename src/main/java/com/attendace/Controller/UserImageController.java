package com.attendace.Controller;


import com.attendace.Service.Interface.FileUploadService;
import com.attendace.auth_module.entities.User;
import com.attendace.auth_module.repository.UserRepository;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserImageController {

    private final UserRepository userRepository;
    private final FileUploadService fileUploadService;

    public UserImageController(UserRepository userRepository, FileUploadService fileUploadService) {
        this.userRepository = userRepository;
        this.fileUploadService = fileUploadService;
    }


    @PostMapping(
            value = "/{id}/profile-image",
            consumes = MediaType.MULTIPART_FORM_DATA_VALUE,   // 👈 This ensures backend accepts multipart/form-data
            produces = MediaType.APPLICATION_JSON_VALUE
    )
    public ResponseEntity<Map<String, Object>> uploadOrUpdateProfileImage(
            @PathVariable Long id,
            @RequestParam("profileImage") MultipartFile profileImage
    ) throws IOException {


        User user = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with id " + id));


        if (profileImage == null || profileImage.isEmpty()) {
            throw new RuntimeException("Please upload a valid image file");
        }


        String folder = "attendance_app/profile_pictures";
        Map uploadResult;


        if (user.getProfileImagePublicId() != null) {
            uploadResult = fileUploadService.updateImage(
                    user.getProfileImagePublicId(),
                    profileImage,
                    folder
            );
        } else {
            uploadResult = fileUploadService.uploadImage(profileImage, folder);
        }


        user.setProfilePictureUrl((String) uploadResult.get("secure_url"));
        user.setProfileImagePublicId((String) uploadResult.get("public_id"));
        user.setProfileImageUpdatedAt(LocalDateTime.now());
        userRepository.save(user);


        uploadResult.put("updatedAt", user.getProfileImageUpdatedAt().toString());

        return ResponseEntity.ok(uploadResult);
    }
}
