package com.attendace.Service.Impl;

import com.attendace.Service.Interface.FileUploadService;
import com.cloudinary.Cloudinary;
import com.cloudinary.utils.ObjectUtils;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.Map;

@Service
public class FileUploadServiceImpl implements FileUploadService {

    private final Cloudinary cloudinary;

    public FileUploadServiceImpl(Cloudinary cloudinary) {
        this.cloudinary = cloudinary;
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
}