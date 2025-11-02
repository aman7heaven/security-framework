package com.portfolio.entity;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.OffsetDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
@Entity
@Table(
        name = "tbl_admin_tokens",
        indexes = {
                @Index(name = "idx_admin_token_token", columnList = "token"),
                @Index(name = "idx_admin_token_admin_id", columnList = "admin_id")
        }
)
public class AdminToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // Each token belongs to one admin
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "fk_admin_uuid", referencedColumnName = "uuid", nullable = false)
    private Admin admin;

    @Column(name = "token", nullable = false, unique = true, length = 1000)
    private String token;

    @Column(name = "is_revoked", nullable = false)
    private boolean revoked;

    @Column(name = "dt_created_at", nullable = false)
    private OffsetDateTime createdAt;

    @Column(name = "dt_expires_at", nullable = false)
    private OffsetDateTime expiresAt;
}
