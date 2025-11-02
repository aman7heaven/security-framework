package com.portfolio.config;

import com.autopilot.config.exception.ApplicationException;
import com.autopilot.config.exception.ApplicationExceptionTypes;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Handles JWT and access-related security exceptions.
 */
@Component
public class SecurityExceptionHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        Throwable cause = authException.getCause();

        if (cause instanceof JwtException jwtEx) {
            String message = jwtEx.getMessage().toLowerCase();

            if (message.contains("expired")) {
                throw new ApplicationException(ApplicationExceptionTypes.EXPIRED_AUTH_TOKEN);
            } else if (message.contains("signature")) {
                throw new ApplicationException(ApplicationExceptionTypes.JWT_SIGNATURE_VERIFICATION_FAILED);
            } else if (message.contains("malformed") || message.contains("invalid")) {
                throw new ApplicationException(ApplicationExceptionTypes.INVALID_AUTH_TOKEN);
            } else {
                // Using the generic validation failure type here
                throw new ApplicationException(ApplicationExceptionTypes.JWT_VALIDATION_FAILED);
            }
        } else {
            throw new ApplicationException(ApplicationExceptionTypes.MISSING_AUTH_TOKEN);
        }
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {
        throw new ApplicationException(ApplicationExceptionTypes.ACCESS_DENIED);
    }
}
