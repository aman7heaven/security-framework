package com.portfolio.service;

import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;

import java.time.*;
import java.util.*;

@Service
public class JwtService {

    private final JwtEncoder jwtEncoder;

    public JwtService(JwtEncoder jwtEncoder) {
        this.jwtEncoder = jwtEncoder;
    }

    public String generateToken(String email, List<String> roles) {
        Instant now = Instant.now();
        Instant expiry = now.plusSeconds(3600); // Token valid for 1 hour

        // Custom claims
        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);

        JwtClaimsSet claimsSet = JwtClaimsSet.builder()
                .issuer("solopilot.com") // who issued the token
                .issuedAt(now)
                .expiresAt(expiry)
                .subject(email) // who the token is for
                .claims(c -> c.putAll(claims))
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claimsSet)).getTokenValue();
    }
}
