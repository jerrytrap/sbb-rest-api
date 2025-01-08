package com.mysite.sbb.user;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.googleapis.javanet.GoogleNetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import jakarta.servlet.http.HttpSession;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @PostMapping("/google")
    public ResponseEntity<?> googleLogin(@RequestBody GoogleTokenRequest googleTokenRequest, HttpSession session) {
        try {
            String googleToken = googleTokenRequest.getToken();
            GoogleIdToken idToken = verifyGoogleToken(googleToken);

            if (idToken == null) {
                return ResponseEntity.status(400).body("Invalid Google token.");
            }

            GoogleIdToken.Payload payload = idToken.getPayload();

            OAuth2AuthenticationToken authenticationToken = getOAuth2AuthenticationToken(payload);
            SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
            securityContext.setAuthentication(authenticationToken);
            SecurityContextHolder.setContext(securityContext);
            session.setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, securityContext);

            OAuth2User oAuth2User = (OAuth2User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
            System.out.println(oAuth2User);
            return ResponseEntity.ok("Successfully logged in.");
        } catch (Exception e) {
            return ResponseEntity.status(400).body("Google authentication failed: " + e.getMessage());
        }
    }

    private static OAuth2AuthenticationToken getOAuth2AuthenticationToken(GoogleIdToken.Payload payload) {
        OAuth2User oAuth2User = new DefaultOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                payload,
                "sub"
        );

        OAuth2AuthenticationToken authenticationToken = new OAuth2AuthenticationToken(
                oAuth2User,  // 인증된 사용자
                Collections.singleton(new SimpleGrantedAuthority("ROLE_USER")),
                "google"
        );
        return authenticationToken;
    }

    private GoogleIdToken verifyGoogleToken(String token) {
        GoogleIdToken idToken = null;
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(GoogleNetHttpTransport.newTrustedTransport(), new GsonFactory())
                    .setAudience(Collections.singletonList(googleClientId))
                    .build();
            idToken = verifier.verify(token);
        } catch (GeneralSecurityException | IOException e) {
            throw new RuntimeException("Error verifying Google token", e);
        }
        return idToken;
    }
}
