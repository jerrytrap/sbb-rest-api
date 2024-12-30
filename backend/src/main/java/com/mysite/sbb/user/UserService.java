package com.mysite.sbb.user;

import com.mysite.sbb.util.DataNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.util.InputMismatchException;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JavaMailSender mailSender;

    private static final String CHARACTERS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    private static int PASSWORD_LENGTH = 8;

    public SiteUser create(String username, String email, String password) {
        SiteUser user = new SiteUser();
        user.setUsername(username);
        user.setEmail(email);

        user.setPassword(passwordEncoder.encode(password));
        userRepository.save(user);
        return user;
    }

    public SiteUser getUser(String username) {
        Optional<SiteUser> siteUser = userRepository.findByUsername(username);
        if (siteUser.isPresent()) {
            return siteUser.get();
        } else {
            throw new DataNotFoundException("user not found");
        }
    }

    public SiteUser getUserByEmail(String email) {
        Optional<SiteUser> siteUser = userRepository.findByEmail(email);
        if (siteUser.isPresent()) {
            return siteUser.get();
        } else {
            throw new DataNotFoundException("user not found");
        }
    }

    public void sendTemporaryPassword(SiteUser siteUser) {
        SimpleMailMessage message = new SimpleMailMessage();
        String randomPassword = getRandomPassword();
        message.setTo(siteUser.getEmail());
        message.setSubject("임시 비밀번호 발송");
        message.setText("""
                임시 비밀번호입니다. 로그인 후 즉시 비밀번호를 변경해주세요.
                %s
                """.formatted(randomPassword)
        );
        setTemporaryPassword(siteUser, randomPassword);
        mailSender.send(message);
    }

    public void changePassword(SiteUser siteUser, String oldPassword, String newPassword) {
        if (checkPassword(siteUser, oldPassword)) {
            siteUser.setPassword(passwordEncoder.encode(newPassword));
            userRepository.save(siteUser);
        } else {
            throw new InputMismatchException();
        }
    }

    private void setTemporaryPassword(SiteUser siteUser, String temporaryPassword) {
        siteUser.setPassword(passwordEncoder.encode(temporaryPassword));
        userRepository.save(siteUser);
    }

    private boolean checkPassword(SiteUser siteUser, String oldPassword) {
        String currentPassword = siteUser.getPassword();
        return passwordEncoder.matches(oldPassword, currentPassword);
    }

    private String getRandomPassword() {
        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();

        for (int i = 0; i < PASSWORD_LENGTH; i++) {
            int index = random.nextInt(CHARACTERS.length());
            password.append(CHARACTERS.charAt(index));
        }

        return password.toString();
    }
}
