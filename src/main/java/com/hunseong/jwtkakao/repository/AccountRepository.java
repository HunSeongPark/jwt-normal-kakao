package com.hunseong.jwtkakao.repository;

import com.hunseong.jwtkakao.domain.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
public interface AccountRepository extends JpaRepository<Account, Long> {
    Optional<Account> findByUsername(String username);

    boolean existsByUsername(String username);
}
