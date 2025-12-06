package com.portfolio.repository;

import com.portfolio.entity.AdminToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface IAdminTokenRepository extends JpaRepository<AdminToken, Long> {

    Optional<AdminToken> findByToken(String token);

}
