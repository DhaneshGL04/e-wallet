package com.github.Dhanesh.repository;

import com.github.Dhanesh.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);

    boolean existsByUsernameIgnoreCase(String name);

    boolean existsByEmailIgnoreCase(String email);
}
