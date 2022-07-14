package com.hunseong.jwtkakao.repository;

import com.hunseong.jwtkakao.domain.Role;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByName(String name);
    boolean existsByName(String roleName);
}
