package com.attendace.repository;

import com.attendace.entities.Attendance;
import io.lettuce.core.dynamic.annotation.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDate;
import java.util.List;

@Repository
public interface AttendanceRepository extends JpaRepository<Attendance, Integer> {

    @Query(value = "SELECT * FROM attendance WHERE CAST(att_time AS DATE) = :date AND user_id = :userId", nativeQuery = true)
    List<Attendance> findByUserIdAndDate(@Param("userId") Long userId, @Param("date") LocalDate date);
}
