package com.attendace.auth_module.service.impl;

import com.attendace.auth_module.service.inter.EmailService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailServiceImpl implements EmailService{

    @Autowired
    private JavaMailSender mailSender;

    public void sendOtpEmail(String toEmail, String otp) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(toEmail);
        message.setSubject("Your OTP Code");
        message.setText("Hello,\n\nYour OTP code is: " + otp + "\nIt will expire in 5 minutes.\n\n- Attendance-Management-System");
        mailSender.send(message);
    }
}
