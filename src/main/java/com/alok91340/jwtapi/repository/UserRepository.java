package com.alok91340.jwtapi.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.alok91340.jwtapi.entities.User;
import java.util.Optional;

public interface UserRepository extends JpaRepository<User,Integer> {

    Optional<User> findByEmail(String email);
    
}
