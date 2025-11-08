package com.attendace.Entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.*;

import java.time.LocalDateTime;
@Entity
@Table(name = "Image_info")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder

public class Image {
    @Column(name = "profile_image_url")
    private String profileImageUrl;

    @Column(name = "profile_image_public_id")
    private String profileImagePublicId;

    @Column(name = "profile_image_updated_at")
    private LocalDateTime profileImageUpdatedAt;
}
