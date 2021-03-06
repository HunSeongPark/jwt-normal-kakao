package com.hunseong.jwtkakao.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.hunseong.jwtkakao.domain.Account;
import com.hunseong.jwtkakao.domain.KakaoUserInfo;
import com.hunseong.jwtkakao.domain.Role;
import com.hunseong.jwtkakao.domain.dto.AccountRequestDto;
import com.hunseong.jwtkakao.domain.dto.RoleToUserRequestDto;
import com.hunseong.jwtkakao.repository.AccountRepository;
import com.hunseong.jwtkakao.repository.RoleRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;
import java.util.stream.Collectors;

import static com.hunseong.jwtkakao.security.JwtConstants.*;


/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@Slf4j
@Transactional
@RequiredArgsConstructor
@Service
public class AccountServiceImpl implements AccountService {

    private final AccountRepository accountRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final KakaoOAuth2 kakaoOAuth2;
    private final AuthenticationManager authenticationManager;

    @Override
    public Long saveAccount(AccountRequestDto dto) {
        validateDuplicateUsername(dto);
        dto.encodePassword(passwordEncoder.encode(dto.getPassword()));
        return accountRepository.save(dto.toEntity()).getId();
    }

    private void validateDuplicateUsername(AccountRequestDto dto) {
        if (accountRepository.existsByUsername(dto.getUsername())) {
            throw new RuntimeException("?????? ???????????? ID?????????.");
        }
    }

    @Override
    public Long saveRole(String roleName) {
        validateDuplicateRoleName(roleName);
        return roleRepository.save(new Role(roleName)).getId();
    }

    private void validateDuplicateRoleName(String roleName) {
        if (roleRepository.existsByName(roleName)) {
            throw new RuntimeException("?????? ???????????? Role?????????.");
        }
    }

    @Override
    public Long addRoleToUser(RoleToUserRequestDto dto) {
        Account account = accountRepository.findByUsername(dto.getUsername()).orElseThrow(() -> new RuntimeException("???????????? ?????? ??? ????????????."));
        Role role = roleRepository.findByName(dto.getRoleName()).orElseThrow(() -> new RuntimeException("ROLE??? ?????? ??? ????????????."));
        account.getRoles().add(role);
        return account.getId();
    }

    // =============== TOKEN ============ //

    @Override
    public void updateRefreshToken(String username, String refreshToken) {
        Account account = accountRepository.findByUsername(username).orElseThrow(() -> new RuntimeException("???????????? ?????? ??? ????????????."));
        account.updateRefreshToken(refreshToken);
    }

    @Override
    public Map<String, String> refresh(String refreshToken) {

        // === Refresh Token ????????? ?????? === //
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(JWT_SECRET)).build();
        DecodedJWT decodedJWT = verifier.verify(refreshToken);

        // === Access Token ????????? === //
        long now = System.currentTimeMillis();
        String username = decodedJWT.getSubject();
        Account account = accountRepository.findByUsername(username)
                .orElseThrow(() -> new UsernameNotFoundException("???????????? ?????? ??? ????????????."));
        if (!account.getRefreshToken().equals(refreshToken)) {
            throw new JWTVerificationException("???????????? ?????? Refresh Token ?????????.");
        }
        String accessToken = JWT.create()
                .withSubject(account.getUsername())
                .withExpiresAt(new Date(now + AT_EXP_TIME))
                .withClaim("roles", account.getRoles().stream().map(Role::getName)
                        .collect(Collectors.toList()))
                .sign(Algorithm.HMAC256(JWT_SECRET));
        Map<String, String> accessTokenResponseMap = new HashMap<>();

        // === ??????????????? Refresh Token ??????????????? ?????? ?????? ???????????? ?????? === //
        // === Refresh Token ???????????? ????????? 1?????? ????????? ??? refresh token??? ?????? === //
        long refreshExpireTime = decodedJWT.getClaim("exp").asLong() * 1000;
        long diffDays = (refreshExpireTime - now) / 1000 / (24 * 3600);
        long diffMin = (refreshExpireTime - now) / 1000 / 60;
        if (diffMin < 5) {
            String newRefreshToken = JWT.create()
                    .withSubject(account.getUsername())
                    .withExpiresAt(new Date(now + RT_EXP_TIME))
                    .sign(Algorithm.HMAC256(JWT_SECRET));
            accessTokenResponseMap.put(RT_HEADER, newRefreshToken);
            account.updateRefreshToken(newRefreshToken);
        }

        accessTokenResponseMap.put(AT_HEADER, accessToken);
        return accessTokenResponseMap;
    }

    @Override
    public void kakaoLogin(String authorizedCode) throws JsonProcessingException {

        KakaoUserInfo userInfo = kakaoOAuth2.getUserInfo(authorizedCode);
        Long oAuthId = userInfo.getOid();
        String email = userInfo.getEmail();

        String password = oAuthId.toString();

        Account kakaoAccount = accountRepository.findByOid(oAuthId).orElse(null);

        if (kakaoAccount == null) {
            Role role = roleRepository.findByName("ROLE_USER").get();
            Account account = Account.builder()
                    .oid(oAuthId)
                    .email(email)
                    .username(email)
                    .password(passwordEncoder.encode(password))
                    .roles(Collections.singletonList(role))
                    .build();
            accountRepository.save(account);
        }

        Authentication authToken = new UsernamePasswordAuthenticationToken(email, password);
        authenticationManager.authenticate(authToken);
    }
}
