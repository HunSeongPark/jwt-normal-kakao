package com.hunseong.jwtkakao.domain;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

/**
 * @author : Hunseong-Park
 * @date : 2022-07-14
 */
@Getter
@RequiredArgsConstructor
public class KakaoUserInfo {

    private final Long id;
    private final String email;
}
