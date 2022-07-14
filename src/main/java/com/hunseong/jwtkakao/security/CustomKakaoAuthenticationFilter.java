package com.hunseong.jwtkakao.security;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.hunseong.jwtkakao.domain.Account;
import com.hunseong.jwtkakao.domain.KakaoUserInfo;
import com.hunseong.jwtkakao.domain.Role;
import com.hunseong.jwtkakao.repository.AccountRepository;
import com.hunseong.jwtkakao.repository.RoleRepository;
import com.hunseong.jwtkakao.service.KakaoOAuth2;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Collections;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
@RequiredArgsConstructor
@Slf4j
public class CustomKakaoAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final KakaoOAuth2 kakaoOAuth2;
    private final AccountRepository accountRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String authorizedCode = request.getParameter("code");
        KakaoUserInfo userInfo = null;
        try {
            userInfo = kakaoOAuth2.getUserInfo(authorizedCode);
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        Long oAuthId = userInfo.getId();
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
        return authenticationManager.authenticate(authToken);
    }
}
