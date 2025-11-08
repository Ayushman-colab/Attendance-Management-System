package com.attendace.Service.Interface;


import org.springframework.web.multipart.MultipartFile;
import java.io.IOException;
import java.util.Map;

public interface FileUploadService {
    Map uploadImage(MultipartFile file, String folder) throws IOException;
    Map updateImage(String oldPublicId, MultipartFile file, String folder) throws IOException;
    void deleteImage(String publicId) throws IOException;
}
