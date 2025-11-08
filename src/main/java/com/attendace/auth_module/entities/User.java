package com.attendace.auth_module.entities;

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
}
