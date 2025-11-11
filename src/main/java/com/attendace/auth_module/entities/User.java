package com.attendace.auth_module.entities;

import com.attendace.entities.Attendance;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.annotation.CreatedBy;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedBy;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "users")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
@EntityListeners(AuditingEntityListener.class)
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    Long userId;

    @Column(unique = true, nullable = false)
    String username;

    @Column(unique = true, nullable = false)
    String email;

    @Column(nullable = false)
    String passwordHash;

    String firstName;
    String lastName;
    String phone;

    @ManyToOne(fetch = FetchType.EAGER)
    @JoinColumn(name = "role_id", nullable = false)
    Role role;

    @Column(nullable = false)
    Boolean isActive = true;
    LocalDateTime lastLoginAt;

    @Column(name = "password_reset_token")
    private String passwordResetToken;

    @Column(name = "password_reset_expiry")
    private LocalDateTime passwordResetExpiry;

    @CreatedDate
    LocalDateTime createdAt;

    @CreatedBy
    Long createdBy;

    @LastModifiedDate
    LocalDateTime updatedAt;

    @LastModifiedBy
    Long updatedBy;

    @Column(name="profile_url")
    String profilePictureUrl;

    @Column(name = "profile_image_public_id")
    String profileImagePublicId;

    @Column(name = "profile_image_updated_at")
    LocalDateTime profileImageUpdatedAt;

    @OneToMany(mappedBy = "user", cascade = CascadeType.ALL, orphanRemoval = true)
    @JsonIgnore
    private List<Attendance> attendanceList = new ArrayList<>();

    @Column(name = "otp")
    private String otp;

    private LocalDateTime expiryDate;

    private String resetToken;

    private boolean isUsed;
}
