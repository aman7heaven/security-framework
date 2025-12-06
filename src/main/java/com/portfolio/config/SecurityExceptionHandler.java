package com.portfolio.config;

import com.autopilot.config.exception.ApplicationException;
import com.autopilot.config.exception.ApplicationExceptionTypes;
import com.autopilot.config.logging.AppLogger;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
public class SecurityExceptionHandler implements AuthenticationEntryPoint, AccessDeniedHandler {

    private final ObjectMapper mapper = new ObjectMapper();

    private final AppLogger log = new AppLogger(LoggerFactory.getLogger(SecurityExceptionHandler.class));

    private void writeError(HttpServletResponse response, ApplicationException ex) throws IOException {
        // avoid writing twice
        if (response.isCommitted()) {
            log.warn("Response already committed, cannot write security error for code {}", ex.getCode());
            return;
        }

        response.setStatus(ex.getStatus().value());
        response.setContentType("application/json");

        // Use a mutable map that permits null values (Map.of does not)
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("code", ex.getCode());
        body.put("message", ex.getMessage());
        // put details even if null — JSON serializer will show null
        body.put("details", ex.getDetails());

        String json = mapper.writeValueAsString(body);
        response.getWriter().write(json);
        response.getWriter().flush();
    }

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException {

        Throwable cause = authException.getCause();
        ApplicationException ex;

        if (cause instanceof ApplicationException appEx) {
            writeError(response, appEx);
            return;
        }

        if (cause instanceof JwtException jwtEx) {
            String message = jwtEx.getMessage().toLowerCase();

            if (message.contains("expired")) {
                ex = new ApplicationException(ApplicationExceptionTypes.EXPIRED_AUTH_TOKEN);
            } else if (message.contains("signature")) {
                ex = new ApplicationException(ApplicationExceptionTypes.JWT_SIGNATURE_VERIFICATION_FAILED);
            } else if (message.contains("malformed") || message.contains("invalid")) {
                ex = new ApplicationException(ApplicationExceptionTypes.INVALID_AUTH_TOKEN);
            } else {
                ex = new ApplicationException(ApplicationExceptionTypes.JWT_VALIDATION_FAILED);
            }

        } else {
            ex = new ApplicationException(ApplicationExceptionTypes.MISSING_AUTH_TOKEN);
        }

        writeError(response, ex);  // ← write JSON output
    }

    @Override
    public void handle(HttpServletRequest request,
                       HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException {

        ApplicationException ex =
                new ApplicationException(ApplicationExceptionTypes.ACCESS_DENIED);

        writeError(response, ex);   // ← write JSON output
    }
}
