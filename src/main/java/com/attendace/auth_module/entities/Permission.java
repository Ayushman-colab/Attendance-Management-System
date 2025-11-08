package com.attendace.auth_module.entities;

import com.attendace.auth_module.Enums.PermissionType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.time.LocalDateTime;

@Entity
@Table(name = "permissions")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
@EntityListeners(AuditingEntityListener.class)
public class Permission {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long permissionId;

    @Column(unique = true, nullable = false, length = 100)
    private String permissionName;

    @Column(unique = true, nullable = false, length = 100)
    private String permissionCode;

    @Column(length = 50)
    private String module; // MEMBER, SUBSCRIPTION, PAYMENT, TRAINER, INVENTORY

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private PermissionType permissionType; // CREATE, READ, UPDATE, DELETE

    @Column(length = 255)
    private String description;

    @Column(nullable = false)
    private Boolean isActive = true;

    @CreatedDate
    @Column(nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    private LocalDateTime updatedAt;
}
