package com.attendace.Repository;


import com.attendace.Entity.Image;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ImageRepository extends JpaRepository<Image, Long> {
    Optional<Image> findByEmail(String email);
    boolean existsByEmail(String email);
}
