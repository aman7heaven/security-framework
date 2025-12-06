package com.portfolio.config;

import com.autopilot.config.exception.ApplicationException;
import com.autopilot.config.exception.ApplicationExceptionTypes;
import com.autopilot.config.logging.AppLogger;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.portfolio.entity.AdminToken;
import com.portfolio.repository.IAdminTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.util.LinkedHashMap;
import java.util.Map;

@Component
@RequiredArgsConstructor
public class TokenValidationFilter extends OncePerRequestFilter {

    private final AppLogger log = new AppLogger(LoggerFactory.getLogger(TokenValidationFilter.class));

    private final IAdminTokenRepository adminTokenRepository;
    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        // No token → continue normally
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String token = authHeader.substring(7);
        var adminTokenOptional = adminTokenRepository.findByToken(token);

        // Token not in DB → Let JWT decoder handle it
        if (adminTokenOptional.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        AdminToken adminToken = adminTokenOptional.get();

        // Expired or revoked → Write error and STOP filter chain
        if (OffsetDateTime.now().isAfter(adminToken.getExpiresAt()) || adminToken.isRevoked()) {

            if (response.isCommitted()) {
                log.warn("Response already committed — cannot write custom token error.");
                return;
            }

            ApplicationException ex = new ApplicationException(ApplicationExceptionTypes.EXPIRED_AUTH_TOKEN);

            // Prepare JSON body
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("code", ex.getCode());
            body.put("message", ex.getMessage());
            body.put("details", ex.getDetails());

            // Write the JSON response
            response.setStatus(ex.getStatus().value());
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");

            response.getWriter().write(mapper.writeValueAsString(body));
            response.getWriter().flush();

            return; // STOP here (do NOT throw exception)
        }

        // Token valid → Continue
        filterChain.doFilter(request, response);
    }
}
