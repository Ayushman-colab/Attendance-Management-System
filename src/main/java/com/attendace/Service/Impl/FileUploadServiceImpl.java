package com.attendace.Service.Impl;

import com.attendace.Service.Interface.FileUploadService;
import com.attendace.auth_module.entities.User;
import com.attendace.auth_module.repository.UserRepository;
import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Map;

@Service
public class FileUploadServiceImpl implements FileUploadService {

    private final Cloudinary cloudinary;
    private final UserRepository userRepository;

    public FileUploadServiceImpl(Cloudinary cloudinary, UserRepository userRepository) {
        this.cloudinary = cloudinary;
        this.userRepository = userRepository;
    }


    @Override
    public Map uploadImage(MultipartFile file, String folder) throws IOException {
        return cloudinary.uploader().upload(file.getBytes(), ObjectUtils.asMap(
                "folder", folder,
                "resource_type", "image",
                "quality", "auto:good",
                "format", "jpg",
                "overwrite", true
        ));
    }




    @Override
    public Map updateImage(String oldPublicId, MultipartFile file, String folder) throws IOException {
        if (oldPublicId != null && !oldPublicId.isEmpty()) {
            cloudinary.uploader().destroy(oldPublicId, ObjectUtils.emptyMap());
        }


        return uploadImage(file, folder);
    }

    @Override
    public void deleteImage(String publicId) throws IOException {
        if (publicId != null && !publicId.isEmpty()) {
            cloudinary.uploader().destroy(publicId, ObjectUtils.emptyMap());
        }
    }

    @Override
    public Map<String, Object> uploadOrUpdateProfileImage(Authentication authentication, MultipartFile profileImage) throws IOException {
        User user = userRepository.findByUsername(authentication.getName())
                .orElseThrow(() -> new RuntimeException("User not found"));

        if(user.getProfileImagePublicId() != null){
            cloudinary.uploader().destroy(user.getProfileImagePublicId(), ObjectUtils.emptyMap());
        }

        if (profileImage == null || profileImage.isEmpty()) {
            throw new RuntimeException("Please upload a valid image file");
        }


        String folder = "attendance_app/profile_pictures";
        Map uploadResult;


        if (user.getProfileImagePublicId() != null) {
            uploadResult = updateImage(
                    user.getProfileImagePublicId(),
                    profileImage,
                    folder
            );
        } else {
            uploadResult = uploadImage(profileImage, folder);
        }


        user.setProfilePictureUrl((String) uploadResult.get("secure_url"));
        user.setProfileImagePublicId((String) uploadResult.get("public_id"));
        user.setProfileImageUpdatedAt(LocalDateTime.now());
        userRepository.save(user);


        uploadResult.put("updatedAt", user.getProfileImageUpdatedAt().toString());

        return uploadResult;

    }
}