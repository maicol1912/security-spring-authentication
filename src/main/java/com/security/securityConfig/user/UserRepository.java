package com.security.securityConfig.user;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {

    //* query para obtener por medio del email
    Optional<User> findByEmail(String email);
}
