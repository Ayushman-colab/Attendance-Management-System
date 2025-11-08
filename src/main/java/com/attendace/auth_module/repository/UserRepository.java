package com.attendace.auth_module.repository;

import com.attendace.auth_module.entities.User;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

//    Optional<User> findByUsername(String username);
//    Optional<User> findByEmail(String email);
//    Optional<User> findByUsernameOrEmail(String username, String email);
//    Boolean existsByUsername(String username);
//    Boolean existsByEmail(String email);
//    Optional<User> findByPasswordResetToken(String token);
//
//    @Query("SELECT u FROM User u WHERE u.email = :email AND u.isActive = true")
//    Optional<User> findActiveUserByEmail(String email);


    Optional<User> findByUsername(String username);
    Optional<User> findByEmail(String email);
    Optional<User> findByUsernameOrEmail(String username, String email);
    Boolean existsByUsername(String username);
    Boolean existsByEmail(String email);
    Optional<User> findByPasswordResetToken(String token);

    @Query("SELECT u FROM User u WHERE u.email = :email AND u.isActive = true")
    Optional<User> findActiveUserByEmail(String email);

    // Pagination queries
    Page<User> findAll(Pageable pageable);

    Page<User> findByIsActiveTrue(Pageable pageable);

    Page<User> findByIsActiveFalse(Pageable pageable);

    @Query("SELECT u FROM User u WHERE u.role.roleCode = :roleCode")
    Page<User> findByRoleCode(@Param("roleCode") String roleCode, Pageable pageable);

    @Query("SELECT u FROM User u WHERE " +
            "LOWER(u.username) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.email) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.firstName) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.lastName) LIKE LOWER(CONCAT('%', :keyword, '%')) OR " +
            "LOWER(u.phone) LIKE LOWER(CONCAT('%', :keyword, '%'))")
    Page<User> searchUsers(@Param("keyword") String keyword, Pageable pageable);

    // Count queries
    Long countByIsActiveTrue();
    Long countByIsActiveFalse();
}
