package com.hunseong.jwtkakao.service;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.hunseong.jwtkakao.domain.dto.AccountRequestDto;
import com.hunseong.jwtkakao.domain.dto.RoleToUserRequestDto;

import java.util.Map;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-04
 */
public interface AccountService {
    Long saveAccount(AccountRequestDto dto);
    Long saveRole(String roleName);
    Long addRoleToUser(RoleToUserRequestDto dto);

    void updateRefreshToken(String username, String refreshToken);

    Map<String, String> refresh(String refreshToken);

    void kakaoLogin(String authorizedCode) throws JsonProcessingException;
}
