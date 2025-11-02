package com.portfolio.repository;



import main.java.com.portfolio.entity.AdminToken;

import java.util.Optional;

@Repository
public interface IAdminTokenRepository extends JpaRepository<AdminToken, Long> {

    Optional<AdminToken> findByToken(String token);

}
